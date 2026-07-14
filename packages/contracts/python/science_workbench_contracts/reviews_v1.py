import hashlib
import json
from collections.abc import Iterable
from threading import Lock
from typing import (
    Annotated,
    Literal,
    LiteralString,
    Never,
    Protocol,
    Self,
    final,
    override,
)

from pydantic import Field, model_validator
from pydantic_core import PydanticCustomError

from .common import NonEmptyText, Revision, Sha256, UtcTimestamp, Uuid7
from .task6_common import Task6ContractModel

type ReviewValidationError = tuple[LiteralString, LiteralString]

FINDING_EVIDENCE_REQUIRED: ReviewValidationError = (
    "finding_evidence_required",
    "finding requires Artifact Version or Execution evidence",
)
FINDING_EVIDENCE_UNIQUE: ReviewValidationError = (
    "finding_evidence_unique",
    "finding Artifact Version and Execution references must be unique",
)
FINDING_DISPOSITION_AUDIT: ReviewValidationError = (
    "finding_disposition_audit",
    "disposition actor and reason exist only for rebutted or accepted risk",
)
RESOLUTION_CORRECTION_LINKAGE: ReviewValidationError = (
    "resolution_correction_linkage",
    (
        "correction requires distinct old and new Artifact Version IDs and "
        "successor checksum"
    ),
)
RESOLUTION_VERSION_LINKAGE: ReviewValidationError = (
    "resolution_version_linkage",
    "rebuttal and accepted risk prohibit Artifact Version linkage",
)
RESOLUTION_EVENT_CHECKSUM: ReviewValidationError = (
    "resolution_event_checksum",
    "resolution event canonical checksum mismatch",
)
MISSING_REVIEW_PINS: ReviewValidationError = (
    "missing_review_pins",
    "Review requires Artifact Version or Execution pins",
)
REVIEW_PIN_UNIQUE: ReviewValidationError = (
    "review_pin_unique",
    "Review evidence pins must be unique",
)
MISSING_FINDINGS_SUBMISSION: ReviewValidationError = (
    "missing_findings_submission",
    "Findings submission exists exactly when Review is completed",
)
FINDING_UNPINNED_EVIDENCE: ReviewValidationError = (
    "finding_unpinned_evidence",
    "finding references must be pinned by the Review",
)
RESOLUTION_EVENT_CHAIN: ReviewValidationError = (
    "resolution_event_chain",
    ("resolution events must be unique, review-bound, finding-bound, and append-only"),
)
RESOLUTION_EVIDENCE_PINS: ReviewValidationError = (
    "resolution_evidence_pins",
    "rebuttal and accepted risk require unique Review-pinned evidence",
)


def _raise_review_error(error: ReviewValidationError) -> Never:
    code, message = error
    raise PydanticCustomError(code, message)


class ReviewerCapabilities(Task6ContractModel):
    runner: Literal[False]
    python: Literal[False]
    bash: Literal[False]
    connector: Literal[False]
    network: Literal[False]
    artifact_write: Literal[False]
    tool_execute: Literal[False]
    version_update: Literal[False]
    reexecution: Literal[False]


class ReviewFinding(Task6ContractModel):
    id: Uuid7
    rule_id: Literal["RV01", "RV02", "RV03", "RV04", "RV05"]
    verdict: Literal["pass", "warn", "fail", "inconclusive"]
    status: Literal["open", "resolved", "rebutted", "accepted_risk"]
    artifact_version_ids: tuple[Uuid7, ...]
    execution_ids: tuple[Uuid7, ...]
    message: NonEmptyText
    disposition_actor_id: Uuid7 | None = None
    disposition_reason: NonEmptyText | None = None

    @model_validator(mode="after")
    def validate_evidence_and_legacy_disposition(self) -> Self:
        if not self.artifact_version_ids and not self.execution_ids:
            _raise_review_error(FINDING_EVIDENCE_REQUIRED)
        if len(set(self.artifact_version_ids)) != len(self.artifact_version_ids) or len(
            set(self.execution_ids)
        ) != len(self.execution_ids):
            _raise_review_error(FINDING_EVIDENCE_UNIQUE)
        audited_status = self.status in {"rebutted", "accepted_risk"}
        audit_present = (
            self.disposition_actor_id is not None
            and self.disposition_reason is not None
        )
        audit_absent = (
            self.disposition_actor_id is None and self.disposition_reason is None
        )
        if not (audit_present if audited_status else audit_absent):
            _raise_review_error(FINDING_DISPOSITION_AUDIT)
        return self


class ResolutionArtifactVersion(Task6ContractModel):
    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    artifact_id: Uuid7
    version: Revision
    input_version_ids: tuple[Uuid7, ...]
    content_sha256: Sha256
    created_at: UtcTimestamp


class ResolutionArtifactVersionResolver(Protocol):
    def resolve(self, version_id: Uuid7) -> ResolutionArtifactVersion | None: ...


class FindingResolutionEvent(Task6ContractModel):
    event_id: Uuid7
    review_id: Uuid7
    finding_id: Uuid7
    predecessor_event_id: Uuid7 | None = None
    kind: Literal["correction", "rebuttal", "accepted_risk"]
    actor_id: Uuid7
    occurred_at: UtcTimestamp
    reason: NonEmptyText
    evidence_digest: Sha256
    evidence_artifact_version_ids: tuple[Uuid7, ...] = ()
    evidence_execution_ids: tuple[Uuid7, ...] = ()
    old_artifact_version_id: Uuid7 | None = None
    new_artifact_version_id: Uuid7 | None = None
    successor_checksum: Sha256 | None = None
    canonical_checksum: Sha256

    @model_validator(mode="after")
    def validate_version_linkage(self) -> Self:
        correction = self.kind == "correction"
        linkage = (
            self.old_artifact_version_id,
            self.new_artifact_version_id,
            self.successor_checksum,
        )
        if correction and (
            any(value is None for value in linkage)
            or self.old_artifact_version_id == self.new_artifact_version_id
        ):
            _raise_review_error(RESOLUTION_CORRECTION_LINKAGE)
        if not correction and any(value is not None for value in linkage):
            _raise_review_error(RESOLUTION_VERSION_LINKAGE)
        if not correction and (
            not self.evidence_artifact_version_ids and not self.evidence_execution_ids
        ):
            _raise_review_error(RESOLUTION_EVIDENCE_PINS)
        if len(set(self.evidence_artifact_version_ids)) != len(
            self.evidence_artifact_version_ids
        ) or len(set(self.evidence_execution_ids)) != len(self.evidence_execution_ids):
            _raise_review_error(RESOLUTION_EVIDENCE_PINS)
        if self.canonical_checksum != finding_resolution_event_checksum(self):
            _raise_review_error(RESOLUTION_EVENT_CHECKSUM)
        return self


def finding_resolution_event_checksum(event: FindingResolutionEvent) -> str:
    payload = json.dumps(
        event.model_dump(mode="json", exclude={"canonical_checksum"}),
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def current_finding_disposition(
    review: "PersistedReview", finding_id: Uuid7
) -> Literal["open", "resolved", "rebutted", "accepted_risk"]:
    events = tuple(
        event for event in review.resolution_events if event.finding_id == finding_id
    )
    if events:
        return _resolution_disposition(events[-1].kind)

    submission = review.submission
    if submission is None:
        return "open"
    finding = next(
        (finding for finding in submission.findings if finding.id == finding_id),
        None,
    )
    return "open" if finding is None else finding.status


def _resolution_disposition(
    kind: Literal["correction", "rebuttal", "accepted_risk"],
) -> Literal["resolved", "rebutted", "accepted_risk"]:
    if kind == "correction":
        return "resolved"
    if kind == "rebuttal":
        return "rebutted"
    return kind


class FindingsSubmission(Task6ContractModel):
    submission_id: Uuid7
    exactly_once: Literal[True]
    submitted_at: UtcTimestamp
    findings: Annotated[tuple[ReviewFinding, ...], Field(min_length=1)]

    @model_validator(mode="after")
    def validate_open_unique_findings(self) -> Self:
        if len({finding.id for finding in self.findings}) != len(self.findings) or any(
            finding.status != "open" for finding in self.findings
        ):
            _raise_review_error(RESOLUTION_EVENT_CHAIN)
        return self


class PersistedReview(Task6ContractModel):
    id: Uuid7
    revision: Revision
    run_id: Uuid7
    source_run_id: Uuid7
    status: Literal["queued", "running", "completed", "failed"]
    pinned_artifact_version_ids: tuple[Uuid7, ...]
    pinned_execution_ids: tuple[Uuid7, ...]
    pinned_input_sha256: Sha256
    reviewer_capabilities: ReviewerCapabilities
    submission: FindingsSubmission | None
    resolution_events: tuple[FindingResolutionEvent, ...] = ()
    created_at: UtcTimestamp

    @model_validator(mode="after")
    def validate_submission_lifecycle(self) -> Self:
        if not self.pinned_artifact_version_ids and not self.pinned_execution_ids:
            _raise_review_error(MISSING_REVIEW_PINS)
        if len(set(self.pinned_artifact_version_ids)) != len(
            self.pinned_artifact_version_ids
        ) or len(set(self.pinned_execution_ids)) != len(self.pinned_execution_ids):
            _raise_review_error(REVIEW_PIN_UNIQUE)
        if (self.status == "completed") != (self.submission is not None):
            _raise_review_error(MISSING_FINDINGS_SUBMISSION)
        submission = self.submission
        if submission is not None and any(
            set(finding.artifact_version_ids) - set(self.pinned_artifact_version_ids)
            or set(finding.execution_ids) - set(self.pinned_execution_ids)
            for finding in submission.findings
        ):
            _raise_review_error(FINDING_UNPINNED_EVIDENCE)
        finding_ids: set[Uuid7] = (
            set()
            if submission is None
            else {finding.id for finding in submission.findings}
        )
        if any(
            set(event.evidence_artifact_version_ids)
            - set(self.pinned_artifact_version_ids)
            or set(event.evidence_execution_ids) - set(self.pinned_execution_ids)
            for event in self.resolution_events
        ):
            _raise_review_error(RESOLUTION_EVIDENCE_PINS)
        if (
            len({event.event_id for event in self.resolution_events})
            != len(self.resolution_events)
            or any(
                event.review_id != self.id or event.finding_id not in finding_ids
                for event in self.resolution_events
            )
            or any(
                event.predecessor_event_id
                != (None if index == 0 else self.resolution_events[index - 1].event_id)
                or (
                    index > 0
                    and event.occurred_at
                    < self.resolution_events[index - 1].occurred_at
                )
                for index, event in enumerate(self.resolution_events)
            )
        ):
            _raise_review_error(RESOLUTION_EVENT_CHAIN)
        return self


class FindingsSubmitted(Task6ContractModel):
    ok: Literal[True]
    review: PersistedReview


class FindingsRejected(Task6ContractModel):
    ok: Literal[False]
    reason: Literal[
        "review_not_found",
        "stale_revision",
        "findings_already_submitted",
        "review_not_running",
    ]


SubmitFindingsResult = FindingsSubmitted | FindingsRejected


class SubmitFindingsCommand(Task6ContractModel):
    review_id: Uuid7
    expected_revision: Revision
    submission: FindingsSubmission


class FindingResolutionAppended(Task6ContractModel):
    ok: Literal[True]
    review: PersistedReview


class FindingResolutionRejected(Task6ContractModel):
    ok: Literal[False]
    reason: Literal[
        "review_not_found",
        "stale_revision",
        "event_already_appended",
        "invalid_event",
    ]


AppendFindingResolutionResult = FindingResolutionAppended | FindingResolutionRejected


class AppendFindingResolutionCommand(Task6ContractModel):
    review_id: Uuid7
    expected_revision: Revision
    event: FindingResolutionEvent


class FindingResolutionStore(Protocol):
    def compare_and_append_resolution(
        self, command: AppendFindingResolutionCommand
    ) -> AppendFindingResolutionResult: ...


class ReviewFindingsStore(Protocol):
    def compare_and_submit(
        self, command: SubmitFindingsCommand
    ) -> SubmitFindingsResult: ...


@final
class InMemoryReviewFindingsStore(ReviewFindingsStore):
    def __init__(
        self,
        reviews: Iterable[PersistedReview],
        resolution_version_resolver: ResolutionArtifactVersionResolver | None = None,
    ) -> None:
        self._resolution_version_resolver = resolution_version_resolver
        self._records = {
            review.id: PersistedReview.model_validate(review.model_dump(mode="python"))
            for review in reviews
        }
        self._lock = Lock()

    @override
    def compare_and_submit(
        self, command: SubmitFindingsCommand
    ) -> SubmitFindingsResult:
        with self._lock:
            review = self._records.get(command.review_id)
            if review is None:
                return FindingsRejected(ok=False, reason="review_not_found")
            if command.expected_revision != review.revision:
                return FindingsRejected(ok=False, reason="stale_revision")
            if review.submission is not None:
                return FindingsRejected(ok=False, reason="findings_already_submitted")
            if review.status != "running":
                return FindingsRejected(ok=False, reason="review_not_running")
            updated = PersistedReview.model_validate(
                {
                    **review.model_dump(mode="python"),
                    "status": "completed",
                    "revision": review.revision + 1,
                    "submission": command.submission,
                }
            )
            self._records[review.id] = updated
            return FindingsSubmitted(ok=True, review=updated)

    def _correction_lineage_is_valid(
        self, review: PersistedReview, event: FindingResolutionEvent
    ) -> bool:
        resolver = self._resolution_version_resolver
        if event.kind != "correction":
            return True
        if (
            resolver is None
            or event.old_artifact_version_id is None
            or event.new_artifact_version_id is None
            or event.successor_checksum is None
        ):
            return False
        current_versions = set(review.pinned_artifact_version_ids)
        for existing in review.resolution_events:
            if existing.kind != "correction":
                continue
            old_version_id = existing.old_artifact_version_id
            new_version_id = existing.new_artifact_version_id
            if (
                old_version_id is None
                or new_version_id is None
                or old_version_id not in current_versions
                or new_version_id in current_versions
            ):
                return False
            current_versions.remove(old_version_id)
            current_versions.add(new_version_id)
        if (
            event.old_artifact_version_id not in current_versions
            or event.new_artifact_version_id in current_versions
        ):
            return False
        previous = resolver.resolve(event.old_artifact_version_id)
        successor = resolver.resolve(event.new_artifact_version_id)
        predecessor_correction = next(
            (
                existing
                for existing in reversed(review.resolution_events)
                if (
                    existing.kind == "correction"
                    and (
                        existing.new_artifact_version_id
                        == event.old_artifact_version_id
                    )
                )
            ),
            None,
        )
        return (
            previous is not None
            and successor is not None
            and previous.id == event.old_artifact_version_id
            and successor.id == event.new_artifact_version_id
            and previous.org_id == successor.org_id
            and previous.project_id == successor.project_id
            and previous.artifact_id == successor.artifact_id
            and (
                predecessor_correction is None
                or previous.content_sha256 == predecessor_correction.successor_checksum
            )
            and successor.version == previous.version + 1
            and previous.id in successor.input_version_ids
            and successor.created_at >= previous.created_at
            and successor.content_sha256 == event.successor_checksum
        )

    def _validated_resolution_update(
        self,
        review: PersistedReview,
        raw_event: FindingResolutionEvent,
    ) -> PersistedReview:
        event = FindingResolutionEvent.model_validate(
            raw_event.model_dump(mode="python")
        )
        if event != raw_event or not self._correction_lineage_is_valid(review, event):
            raise ValueError
        return PersistedReview.model_validate(
            {
                **review.model_dump(mode="python"),
                "revision": review.revision + 1,
                "resolution_events": (*review.resolution_events, event),
            }
        )

    def compare_and_append_resolution(
        self, command: AppendFindingResolutionCommand
    ) -> AppendFindingResolutionResult:
        with self._lock:
            review = self._records.get(command.review_id)
            if review is None:
                return FindingResolutionRejected(ok=False, reason="review_not_found")
            existing = next(
                (
                    event
                    for event in review.resolution_events
                    if event.event_id == command.event.event_id
                ),
                None,
            )
            if existing is not None:
                reason: Literal["event_already_appended", "invalid_event"] = (
                    "event_already_appended"
                    if existing == command.event
                    else "invalid_event"
                )
                return FindingResolutionRejected(ok=False, reason=reason)
            if command.expected_revision != review.revision:
                return FindingResolutionRejected(ok=False, reason="stale_revision")
            try:
                updated = self._validated_resolution_update(review, command.event)
            except ValueError:
                return FindingResolutionRejected(ok=False, reason="invalid_event")
            self._records[review.id] = updated
            return FindingResolutionAppended(ok=True, review=updated)


def submit_findings_once(
    store: ReviewFindingsStore, command: SubmitFindingsCommand
) -> SubmitFindingsResult:
    return store.compare_and_submit(command)


def append_finding_resolution_once(
    store: FindingResolutionStore, command: AppendFindingResolutionCommand
) -> AppendFindingResolutionResult:
    return store.compare_and_append_resolution(command)
