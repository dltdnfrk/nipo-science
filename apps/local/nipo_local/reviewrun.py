"""Persist one trace-only Review over a Run's already-pinned evidence.

`reviewer.py` decides; `store.py` remembers; neither knows about the other.
This module is the only place they meet, and it is deliberately the thinnest
possible join:

    evidence = store.pinned_run_evidence(...)   # inert values leave the store
    outcome  = Reviewer(evidence).review()      # no store, no service, no callable
    store.submit_review_findings(...)           # the store writes, not the Reviewer

The `Reviewer` is constructed from the snapshot alone. It is never handed the
store, so the capability to commit a Version or start an execution stays
absent from its object graph exactly as SPEC-v0.5 section 8 requires --
keeping the join here rather than inside `Reviewer` is what preserves that.

Deduplication is by pinned evidence, not by request
---------------------------------------------------
A Review is identified by the canonical digest of what it pins, which the
store derives itself. Asking twice for a Review of the same Run therefore
returns the same Review rather than evaluating the rules again: a
`ReviewOutcome` is a function of the pinned bytes, so a second Review over
identical evidence could differ only if the Reviewer were non-deterministic,
and two stored Reviews would then contradict each other with no way to tell
which was true.

The lookup is attempted before the insert *and* again after an
`ASSOCIATION_EXISTS`, because between those two moments another caller may
have opened it. The store's `UNIQUE (org_id, project_id,
pinned_input_sha256)` is the authority; this module only reads its answer.

Failure is recorded, not swallowed
-----------------------------------
A Review that is opened and then cannot be completed is closed `failed` with a
non-secret reason, so it never sits `running` forever. `inconclusive` never
travels this path: it is an ordinary verdict on a finding of a *completed*
Review, and treating unreachable evidence as a Review failure is precisely the
mistake SPEC-v0.5 section 8 forbids.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import TYPE_CHECKING, final

from services.api.artifacts.store_contract import ArtifactStoreError, StoreOutcome

from .reviewer import Reviewer, findings_submission
from .store import LocalArtifactStore, ReviewRecord, ReviewState

if TYPE_CHECKING:
    from collections.abc import Sequence
    from uuid import UUID

    from services.api.artifacts.models import ArtifactScope, Clock, IdFactory

    from .reviewer import IdentifierResolver
    from .store import PinnedRunEvidence, ReviewFindingRecord

__all__ = [
    "PersistedReview",
    "ReviewJob",
    "ReviewRejection",
    "ReviewRejectionError",
    "persisted_review",
    "review_run",
]


class ReviewRejection(StrEnum):
    """Closed reasons one Review could not be opened or completed."""

    RUN_NOT_FOUND = "run_not_found"
    PROJECT_ARCHIVED = "project_archived"
    NO_PINNED_EVIDENCE = "no_pinned_evidence"
    STORE_UNAVAILABLE = "store_unavailable"


@final
class ReviewRejectionError(ValueError):
    """Refuse one Review with a closed reason and no caller input."""

    __slots__ = ("reason",)

    reason: ReviewRejection

    def __init__(self, reason: ReviewRejection) -> None:
        """Record the closed refusal reason."""
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True, slots=True)
class PersistedReview:
    """One stored Review together with the findings it recorded."""

    review: ReviewRecord
    findings: tuple[ReviewFindingRecord, ...]


@dataclass(frozen=True, slots=True)
class ReviewJob:
    """Everything one Review needs, and deliberately nothing more.

    `ids` and `clock` arrive from the caller because minting an identity and
    reading a clock are not Reviewer capabilities. `resolver` defaults to the
    offline one, which answers every identifier `UNREACHABLE` and yields
    `inconclusive` for RV02 -- a correct outcome on a machine with no network,
    not a degraded one.
    """

    store: LocalArtifactStore
    scope: ArtifactScope
    ids: IdFactory
    clock: Clock
    resolver: IdentifierResolver | None = None


def persisted_review(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    run_id: UUID,
) -> PersistedReview | None:
    """Read the Review already covering one Run's pinned evidence, if any.

    Idempotent and side-effect free: it opens nothing, starts nothing, and
    evaluates no rule. The pins are recomputed from the Run's current evidence
    so this lookup asks the same question the writer asked, rather than
    trusting a Review identifier a caller supplied.
    """
    digest = _pinned_digest(store, scope, run_id)
    if digest is None:
        return None
    review = store.review_for_pinned_inputs(scope, digest)
    if review is None:
        return None
    return _with_findings(store, scope, review)


def review_run(job: ReviewJob, run_id: UUID) -> PersistedReview:
    """Open, evaluate, and complete one Review of a Run's pinned evidence.

    Args:
        job: The store, scope, identity factory, clock, and resolver this
            Review runs against.
        run_id: The Run whose committed outputs are being reviewed.

    Returns:
        The completed Review and its findings, or the Review that already
        covers exactly this evidence.

    Raises:
        ReviewRejectionError: The Run does not exist, committed nothing to
            pin, its Project is archived, or the store is unreadable.
    """
    try:
        return _review(job, run_id)
    except ArtifactStoreError as error:
        raise ReviewRejectionError(ReviewRejection.STORE_UNAVAILABLE) from error


def _review(job: ReviewJob, run_id: UUID) -> PersistedReview:
    """Run the open-evaluate-submit sequence over one snapshot of evidence."""
    evidence = _evidence(job, run_id)
    versions = _sorted_unique(evidence.artifact_version_ids)
    executions = _sorted_unique(evidence.execution_ids)
    if not versions and not executions:
        raise ReviewRejectionError(ReviewRejection.NO_PINNED_EVIDENCE)
    digest = LocalArtifactStore.pinned_input_digest(
        job.scope,
        run_id,
        versions,
        executions,
    )
    existing = job.store.review_for_pinned_inputs(job.scope, digest)
    if existing is not None:
        return _with_findings(job.store, job.scope, existing)
    opened_at = job.clock.now()
    review = ReviewRecord(
        id=job.ids.new_uuid7(),
        org_id=job.scope.org_id,
        project_id=job.scope.project_id,
        source_run_id=run_id,
        state=ReviewState.QUEUED,
        pinned_input_sha256=digest,
        pinned_artifact_version_ids=versions,
        pinned_execution_ids=executions,
        created_at=opened_at,
        updated_at=opened_at,
    )
    outcome = job.store.open_review(job.scope, review)
    if outcome is not StoreOutcome.CREATED:
        return _refused(job, digest, outcome)
    return _complete(job, review)


def _complete(job: ReviewJob, review: ReviewRecord) -> PersistedReview:
    """Evaluate the rules and record the findings, or close the Review failed.

    The evidence snapshot is captured a second time, after the Review row
    exists, so what the rules read is what the Review pins rather than what
    happened to be readable a moment before the pins were fixed.
    """
    _ = job.store.start_review(job.scope, review.id, job.clock.now())
    try:
        evidence = _evidence(job, review.source_run_id)
        outcome = Reviewer(evidence, job.resolver).review()
        submitted_at = job.clock.now()
        submission = findings_submission(
            review,
            outcome,
            [job.ids.new_uuid7() for _ in outcome.findings],
            submitted_at,
        )
        _ = job.store.submit_review_findings(job.scope, submission)
    except BaseException as error:
        _fail(job, review, error)
        raise
    return _read_back(job, review)


def _evidence(job: ReviewJob, run_id: UUID) -> PinnedRunEvidence:
    """Capture one Run's pinned evidence, refusing when the Run is absent."""
    evidence = job.store.pinned_run_evidence(job.scope, run_id)
    if evidence is None:
        raise ReviewRejectionError(ReviewRejection.RUN_NOT_FOUND)
    return evidence


def _fail(job: ReviewJob, review: ReviewRecord, error: BaseException) -> None:
    """Close an unfinished Review with a non-secret reason.

    The store's own failure is suppressed: replacing the real cause with a
    bookkeeping error would hide why the Review could not complete, and the
    Review stays visible as unfinished either way.
    """
    code = error.reason.value if isinstance(error, ReviewRejectionError) else None
    try:
        _ = job.store.fail_review(
            job.scope,
            review.id,
            job.clock.now(),
            type(error).__name__,
            code,
        )
    except ArtifactStoreError:
        return


def _refused(job: ReviewJob, digest: str, outcome: StoreOutcome) -> PersistedReview:
    """Translate a refused `open_review` into an answer or a closed reason.

    `ASSOCIATION_EXISTS` means another caller opened this exact evidence
    between the lookup and the insert, so the answer is that Review rather
    than an error. Every other outcome is a refusal with no Review to return.
    """
    if outcome is StoreOutcome.ASSOCIATION_EXISTS:
        existing = job.store.review_for_pinned_inputs(job.scope, digest)
        if existing is not None:
            return _with_findings(job.store, job.scope, existing)
    if outcome is StoreOutcome.ARCHIVED:
        raise ReviewRejectionError(ReviewRejection.PROJECT_ARCHIVED)
    raise ReviewRejectionError(ReviewRejection.RUN_NOT_FOUND)


def _read_back(job: ReviewJob, review: ReviewRecord) -> PersistedReview:
    """Return the Review as the store now holds it, not as it was built."""
    stored = job.store.review(job.scope, review.id)
    if stored is None:
        raise ReviewRejectionError(ReviewRejection.STORE_UNAVAILABLE)
    return _with_findings(job.store, job.scope, stored)


def _with_findings(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    review: ReviewRecord,
) -> PersistedReview:
    """Pair one stored Review with the findings recorded against it."""
    return PersistedReview(
        review=review,
        findings=store.review_findings(scope, review.id),
    )


def _pinned_digest(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    run_id: UUID,
) -> str | None:
    """Derive the canonical pinned-input digest of one Run's evidence."""
    evidence = store.pinned_run_evidence(scope, run_id)
    if evidence is None:
        return None
    versions = _sorted_unique(evidence.artifact_version_ids)
    executions = _sorted_unique(evidence.execution_ids)
    if not versions and not executions:
        return None
    return LocalArtifactStore.pinned_input_digest(scope, run_id, versions, executions)


def _sorted_unique(values: Sequence[UUID]) -> tuple[UUID, ...]:
    """Return identifiers in the sorted, duplicate-free order the store wants.

    `PinnedRunEvidence` reports Versions in publication order, which is what a
    reader wants; `open_review` requires pins already sorted and unique so no
    caller can reorder the same evidence into a second digest. The sort is on
    the rendered form because that is what the digest is taken over.
    """
    return tuple(sorted(set(values), key=str))
