from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import timedelta
from pathlib import Path
from threading import Barrier
from typing import final
from uuid import UUID

import pytest
from pydantic import ValidationError

import science_workbench_contracts.reviews_v1 as reviewer_contracts
from science_workbench_contracts.artifact_versions import (
    ArtifactVersionCreateCommand,
    ArtifactVersionCreated,
    ArtifactVersionCreateRejected,
    create_artifact_version_cas,
)
from science_workbench_contracts.artifacts import ReviewCreate
from science_workbench_contracts.dry_lab_contract import DryLabRunContract
from science_workbench_contracts.reviews_v1 import (
    AppendFindingResolutionCommand,
    FindingResolutionAppended,
    FindingResolutionEvent,
    FindingResolutionRejected,
    FindingsRejected,
    FindingsSubmitted,
    InMemoryReviewFindingsStore,
    PersistedReview,
    ResolutionArtifactVersion,
    ReviewFinding,
    SubmitFindingsCommand,
    append_finding_resolution_once,
    current_finding_disposition,
    finding_resolution_event_checksum,
    submit_findings_once,
)

FIXTURE = Path(__file__).parents[2] / "fixtures" / "gs04-dry-lab-contract.json"


def _contract() -> DryLabRunContract:
    return DryLabRunContract.model_validate_json(FIXTURE.read_text(encoding="utf-8"))


def _resolution_event(
    review: PersistedReview,
    correction: "_CorrectionFixture",
    event_id: UUID,
    predecessor_event_id: UUID | None = None,
) -> FindingResolutionEvent:
    unsigned = FindingResolutionEvent.model_construct(
        event_id=event_id,
        review_id=review.id,
        finding_id=correction.finding.id,
        predecessor_event_id=predecessor_event_id,
        kind="correction",
        actor_id=review.run_id,
        occurred_at=review.created_at,
        reason="A successor artifact corrects the finding.",
        evidence_digest="a" * 64,
        old_artifact_version_id=correction.old.id,
        new_artifact_version_id=correction.new.id,
        successor_checksum=correction.new.content_sha256,
        canonical_checksum="0" * 64,
    )
    return FindingResolutionEvent.model_validate(
        {
            **unsigned.model_dump(mode="python"),
            "canonical_checksum": finding_resolution_event_checksum(unsigned),
        }
    )


def _resigned_event(
    event: FindingResolutionEvent, **updates: object
) -> FindingResolutionEvent:
    unsigned = event.model_copy(update={**updates, "canonical_checksum": "0" * 64})
    return FindingResolutionEvent.model_validate(
        {
            **unsigned.model_dump(mode="python"),
            "canonical_checksum": finding_resolution_event_checksum(unsigned),
        }
    )


@dataclass(frozen=True)
class _CorrectionFixture:
    finding: ReviewFinding
    old: ResolutionArtifactVersion
    new: ResolutionArtifactVersion


@final
class _ResolutionVersionIndex:
    _versions: dict[UUID, ResolutionArtifactVersion]

    def __init__(self, versions: tuple[ResolutionArtifactVersion, ...]) -> None:
        self._versions = {version.id: version for version in versions}

    def resolve(self, version_id: UUID) -> ResolutionArtifactVersion | None:
        return self._versions.get(version_id)


@final
class _MisroutedResolutionVersionIndex:
    def __init__(self, version: ResolutionArtifactVersion) -> None:
        self._version = version

    def resolve(self, version_id: UUID) -> ResolutionArtifactVersion:
        _ = version_id
        return self._version


def _correction_fixtures(
    contract: DryLabRunContract,
) -> tuple[_CorrectionFixture, _CorrectionFixture, _CorrectionFixture]:
    submission = contract.review.submission
    assert submission is not None
    finding = submission.findings[0]
    old_record = next(
        version
        for version in contract.artifact_versions
        if version.id == finding.artifact_version_ids[0]
    )
    old = ResolutionArtifactVersion(
        id=old_record.id,
        org_id=old_record.org_id,
        project_id=old_record.project_id,
        artifact_id=old_record.artifact_id,
        version=old_record.version,
        input_version_ids=old_record.input_version_ids,
        content_sha256=old_record.content_sha256,
        created_at=old_record.created_at,
    )
    corrected_ids = (
        UUID("018f47a0-7b9c-7a60-8def-0123456789ab"),
        UUID("018f47a0-7b9c-7a61-8def-0123456789ab"),
        UUID("018f47a0-7b9c-7a62-8def-0123456789ab"),
    )
    successors = tuple(
        ResolutionArtifactVersion(
            id=version_id,
            org_id=old.org_id,
            project_id=old.project_id,
            artifact_id=old.artifact_id,
            version=old.version + index + 1,
            input_version_ids=(old.id if index == 0 else corrected_ids[index - 1],),
            content_sha256="b" * 64,
            created_at=old.created_at + timedelta(seconds=index + 1),
        )
        for index, version_id in enumerate(corrected_ids)
    )
    return (
        _CorrectionFixture(finding, old, successors[0]),
        _CorrectionFixture(finding, successors[0], successors[1]),
        _CorrectionFixture(finding, successors[1], successors[2]),
    )


def _resolution_version_index(contract: DryLabRunContract) -> _ResolutionVersionIndex:
    return _ResolutionVersionIndex(
        tuple(
            version
            for correction in _correction_fixtures(contract)
            for version in (correction.old, correction.new)
        )
    )


def test_creates_monotonic_artifact_version_and_rejects_stale_base() -> None:
    # Given: immutable Version 1 and a same-Artifact Version 2 successor.
    contract = _contract()
    current = contract.artifact_versions[0]
    successor = current.model_copy(
        update={
            "id": contract.artifact_versions[1].id,
            "version": 2,
            "content_sha256": "b" * 64,
        }
    )
    command = ArtifactVersionCreateCommand(
        base_version_id=current.id, next_version=successor
    )

    # When: CAS creates from the current base and then receives a stale base ID.
    created = create_artifact_version_cas(current, command)
    stale = create_artifact_version_cas(
        current,
        command.model_copy(
            update={"base_version_id": contract.artifact_versions[2].id}
        ),
    )

    # Then: the successor is monotonic, V1 checksum is preserved, and stale CAS rejects.
    assert isinstance(created, ArtifactVersionCreated)
    assert created.previous.content_sha256 == "a" * 64
    assert created.created.version == 2
    assert isinstance(stale, ArtifactVersionCreateRejected)
    assert stale.reason == "stale_base"


def test_rejects_cross_org_same_id_and_backdated_successor() -> None:
    # Given: successor candidates change tenant, reuse ID, or predate Version 1.
    contract = _contract()
    current = contract.artifact_versions[0]
    template = contract.artifact_versions[1]
    valid = current.model_copy(update={"id": template.id, "version": 2})
    candidates = (
        valid.model_copy(update={"org_id": template.runtime_connection_id}),
        valid.model_copy(update={"id": current.id}),
        valid.model_copy(
            update={"created_at": current.created_at - timedelta(seconds=1)}
        ),
    )

    # When: CAS evaluates each invalid successor.
    results = tuple(
        create_artifact_version_cas(
            current,
            ArtifactVersionCreateCommand(base_version_id=current.id, next_version=item),
        )
        for item in candidates
    )

    # Then: tenant, identity, and timestamp monotonicity all fail closed.
    assert all(
        isinstance(result, ArtifactVersionCreateRejected)
        and result.reason == "invalid_successor"
        for result in results
    )


def test_submits_review_findings_once_and_rejects_duplicate() -> None:
    # Given: a running persisted Review with no prior submission.
    contract = _contract()
    submission = contract.review.submission
    assert submission is not None
    pending_data = contract.review.model_dump(mode="python")
    pending_data["status"] = "running"
    pending_data["submission"] = None
    pending = PersistedReview.model_validate(pending_data)

    store = InMemoryReviewFindingsStore((pending,))
    command = SubmitFindingsCommand(
        review_id=pending.id,
        expected_revision=pending.revision,
        submission=submission,
    )
    # When: Findings are submitted twice from the same pending snapshot.
    first = submit_findings_once(store, command)
    assert isinstance(first, FindingsSubmitted)
    second = submit_findings_once(store, command)

    # Then: exactly one submission mutates the returned Review projection.
    assert first.review.status == "completed"
    assert first.review.revision == pending.revision + 1
    assert isinstance(second, FindingsRejected)
    assert second.reason == "stale_revision"


def test_authoritative_store_serializes_competing_pending_submissions() -> None:
    # Given: two workers captured the same pending Review revision.
    contract = _contract()
    submission = contract.review.submission
    assert submission is not None
    pending = PersistedReview.model_validate(
        {
            **contract.review.model_dump(mode="python"),
            "status": "running",
            "submission": None,
        }
    )
    store = InMemoryReviewFindingsStore((pending,))
    command = SubmitFindingsCommand(
        review_id=pending.id,
        expected_revision=pending.revision,
        submission=submission,
    )
    barrier = Barrier(3)

    def submit_after_release() -> FindingsSubmitted | FindingsRejected:
        _ = barrier.wait()
        return submit_findings_once(store, command)

    # When: both workers compare-and-submit concurrently.
    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(submit_after_release) for _ in range(2))
        _ = barrier.wait()
        results = tuple(future.result() for future in futures)

    # Then: the store commits once and rejects the other stale snapshot.
    assert sum(isinstance(result, FindingsSubmitted) for result in results) == 1
    assert sum(isinstance(result, FindingsRejected) for result in results) == 1
    submitted = next(
        result for result in results if isinstance(result, FindingsSubmitted)
    )
    with pytest.raises(ValidationError, match="frozen"):
        submitted.review.__setattr__("revision", 99)


def test_requires_actor_and_reason_for_audited_finding_dispositions() -> None:
    # Given: an existing Finding is changed to a rebuttal without its audit fields.
    contract = _contract()
    finding = contract.review.submission
    assert finding is not None
    raw = finding.findings[0].model_dump(mode="python")
    raw["status"] = "rebutted"

    # When/Then: the boundary requires both actor and reason for that disposition.
    with pytest.raises(ValidationError, match="actor and reason"):
        _ = ReviewFinding.model_validate(raw)
    audited = ReviewFinding.model_validate(
        {
            **raw,
            "disposition_actor_id": contract.review.run_id,
            "disposition_reason": "Pinned evidence supports the original result.",
        }
    )
    assert audited.status == "rebutted"


def test_accepts_execution_only_review_pins_and_rejects_empty_pins() -> None:
    # Given: a persisted Review projection with only its Execution evidence retained.
    contract = _contract()
    submission = contract.review.submission
    assert submission is not None
    execution_only = {
        **contract.review.model_dump(mode="python"),
        "pinned_artifact_version_ids": (),
        "submission": submission.model_copy(
            update={
                "findings": (
                    submission.findings[0].model_copy(
                        update={"artifact_version_ids": ()}
                    ),
                )
            }
        ),
    }

    # When: execution-only and evidence-free projections cross the boundary.
    accepted = PersistedReview.model_validate(execution_only)
    empty_pins = {**execution_only, "pinned_execution_ids": ()}

    # Then: execution evidence is sufficient, while no evidence is rejected.
    assert accepted.pinned_artifact_version_ids == ()
    with pytest.raises(ValidationError, match="Artifact Version or Execution"):
        _ = PersistedReview.model_validate(empty_pins)
    request = ReviewCreate(
        source_run_id=contract.review.source_run_id,
        execution_ids=contract.review.pinned_execution_ids,
    )
    assert request.artifact_version_ids == ()
    with pytest.raises(ValidationError, match="Artifact Version or Execution"):
        _ = ReviewCreate(source_run_id=contract.review.source_run_id)


def test_rejects_duplicate_or_unpinned_finding_evidence() -> None:
    contract = _contract()
    submission = contract.review.submission
    assert submission is not None
    finding = submission.findings[0]
    duplicate = finding.model_copy(
        update={"artifact_version_ids": (finding.artifact_version_ids[0],) * 2}
    )
    with pytest.raises(ValidationError, match="unique"):
        _ = ReviewFinding.model_validate(duplicate.model_dump(mode="python"))
    with pytest.raises(ValidationError, match="pinned"):
        _ = PersistedReview.model_validate(
            {
                **contract.review.model_dump(mode="python"),
                "submission": submission.model_copy(
                    update={
                        "findings": (
                            finding.model_copy(
                                update={
                                    "artifact_version_ids": (
                                        contract.artifact_versions[0].id,
                                    )
                                }
                            ),
                        )
                    }
                ),
            }
        )


def test_appends_checksumming_resolution_events_under_revision_cas() -> None:
    contract = _contract()
    review = contract.review
    submission = review.submission
    assert submission is not None
    correction = _correction_fixtures(contract)[0]
    finding = correction.finding
    unsigned = FindingResolutionEvent.model_construct(
        event_id=contract.artifact_versions[0].id,
        review_id=review.id,
        finding_id=correction.finding.id,
        predecessor_event_id=None,
        kind="correction",
        actor_id=review.run_id,
        occurred_at=review.created_at,
        reason="A successor artifact corrects the finding.",
        evidence_digest="a" * 64,
        old_artifact_version_id=correction.old.id,
        new_artifact_version_id=correction.new.id,
        successor_checksum=correction.new.content_sha256,
        canonical_checksum="0" * 64,
    )
    with pytest.raises(ValidationError, match="canonical checksum"):
        _ = FindingResolutionEvent.model_validate(unsigned.model_dump(mode="python"))
    event = FindingResolutionEvent(
        event_id=unsigned.event_id,
        review_id=unsigned.review_id,
        finding_id=unsigned.finding_id,
        predecessor_event_id=unsigned.predecessor_event_id,
        kind=unsigned.kind,
        actor_id=unsigned.actor_id,
        occurred_at=unsigned.occurred_at,
        reason=unsigned.reason,
        evidence_digest=unsigned.evidence_digest,
        old_artifact_version_id=unsigned.old_artifact_version_id,
        new_artifact_version_id=unsigned.new_artifact_version_id,
        successor_checksum=unsigned.successor_checksum,
        canonical_checksum=finding_resolution_event_checksum(unsigned),
    )
    store = InMemoryReviewFindingsStore((review,), _resolution_version_index(contract))
    appended = append_finding_resolution_once(
        store,
        AppendFindingResolutionCommand(
            review_id=review.id, expected_revision=review.revision, event=event
        ),
    )
    assert appended.ok is True
    assert appended.review.resolution_events == (event,)
    assert appended.review.revision == review.revision + 1
    disposition_event = FindingResolutionEvent.model_construct(
        event_id=contract.artifact_versions[0].id,
        review_id=review.id,
        finding_id=finding.id,
        kind="rebuttal",
        actor_id=review.run_id,
        occurred_at=review.created_at,
        reason="The pinned execution evidence rebuts this finding.",
        evidence_digest="a" * 64,
        evidence_artifact_version_ids=(review.pinned_artifact_version_ids[0],),
        canonical_checksum="0" * 64,
    )
    disposition_event = FindingResolutionEvent.model_validate(
        {
            **disposition_event.model_dump(mode="python"),
            "canonical_checksum": finding_resolution_event_checksum(disposition_event),
        }
    )
    reviewed = PersistedReview.model_validate(
        {
            **review.model_dump(mode="python"),
            "resolution_events": (disposition_event,),
        }
    )
    assert current_finding_disposition(reviewed, finding.id) == "rebutted"
    unpinned_unsigned = disposition_event.model_copy(
        update={
            "evidence_artifact_version_ids": (review.run_id,),
            "canonical_checksum": "0" * 64,
        }
    )
    unpinned_event = FindingResolutionEvent.model_validate(
        {
            **unpinned_unsigned.model_dump(mode="python"),
            "canonical_checksum": finding_resolution_event_checksum(unpinned_unsigned),
        }
    )
    with pytest.raises(ValidationError, match="pinned"):
        _ = PersistedReview.model_validate(
            {
                **review.model_dump(mode="python"),
                "resolution_events": (unpinned_event,),
            }
        )
    unlinked_unsigned = disposition_event.model_copy(
        update={
            "event_id": contract.artifact_versions[1].id,
            "canonical_checksum": "0" * 64,
        }
    )
    unlinked_event = FindingResolutionEvent.model_validate(
        {
            **unlinked_unsigned.model_dump(mode="python"),
            "canonical_checksum": finding_resolution_event_checksum(unlinked_unsigned),
        }
    )
    with pytest.raises(ValidationError, match="append-only"):
        _ = PersistedReview.model_validate(
            {
                **review.model_dump(mode="python"),
                "resolution_events": (disposition_event, unlinked_event),
            }
        )


def test_resolution_store_distinguishes_replay_invalid_stale_and_lineage() -> None:
    contract = _contract()
    review = contract.review
    submission = review.submission
    assert submission is not None
    corrections = _correction_fixtures(contract)
    first = _resolution_event(review, corrections[0], contract.artifact_versions[0].id)
    unresolved = append_finding_resolution_once(
        InMemoryReviewFindingsStore((review,)),
        AppendFindingResolutionCommand(
            review_id=review.id, expected_revision=review.revision, event=first
        ),
    )
    assert isinstance(unresolved, FindingResolutionRejected)
    assert unresolved.reason == "invalid_event"
    misrouted = append_finding_resolution_once(
        InMemoryReviewFindingsStore(
            (review,), _MisroutedResolutionVersionIndex(corrections[0].new)
        ),
        AppendFindingResolutionCommand(
            review_id=review.id, expected_revision=review.revision, event=first
        ),
    )
    assert isinstance(misrouted, FindingResolutionRejected)
    assert misrouted.reason == "invalid_event"
    tampered_successor = corrections[0].new.model_copy(
        update={"content_sha256": "c" * 64}
    )
    stale_evidence = append_finding_resolution_once(
        InMemoryReviewFindingsStore(
            (review,),
            _ResolutionVersionIndex((corrections[0].old, tampered_successor)),
        ),
        AppendFindingResolutionCommand(
            review_id=review.id, expected_revision=review.revision, event=first
        ),
    )
    assert isinstance(stale_evidence, FindingResolutionRejected)
    assert stale_evidence.reason == "invalid_event"
    store = InMemoryReviewFindingsStore((review,), _resolution_version_index(contract))
    appended = append_finding_resolution_once(
        store,
        AppendFindingResolutionCommand(
            review_id=review.id, expected_revision=review.revision, event=first
        ),
    )
    assert appended.ok is True
    assert appended.review.resolution_events == (first,)
    replay = append_finding_resolution_once(
        store,
        AppendFindingResolutionCommand(
            review_id=review.id, expected_revision=review.revision, event=first
        ),
    )
    assert isinstance(replay, FindingResolutionRejected)
    assert replay.reason == "event_already_appended"
    mutated = _resigned_event(first, reason="Mutated replay event.")
    invalid_replay = append_finding_resolution_once(
        store,
        AppendFindingResolutionCommand(
            review_id=review.id, expected_revision=review.revision, event=mutated
        ),
    )
    assert isinstance(invalid_replay, FindingResolutionRejected)
    assert invalid_replay.reason == "invalid_event"
    successor = _resolution_event(
        review,
        corrections[1],
        contract.artifact_versions[1].id,
        predecessor_event_id=first.event_id,
    )
    stale = append_finding_resolution_once(
        store,
        AppendFindingResolutionCommand(
            review_id=review.id, expected_revision=review.revision, event=successor
        ),
    )
    assert isinstance(stale, FindingResolutionRejected)
    assert stale.reason == "stale_revision"
    rewritten_prior = corrections[1].old.model_copy(update={"content_sha256": "c" * 64})
    stale_prior_evidence = append_finding_resolution_once(
        InMemoryReviewFindingsStore(
            (appended.review,),
            _ResolutionVersionIndex((rewritten_prior, corrections[1].new)),
        ),
        AppendFindingResolutionCommand(
            review_id=review.id,
            expected_revision=appended.review.revision,
            event=successor,
        ),
    )
    assert isinstance(stale_prior_evidence, FindingResolutionRejected)
    assert stale_prior_evidence.reason == "invalid_event"
    accepted_successor = append_finding_resolution_once(
        store,
        AppendFindingResolutionCommand(
            review_id=review.id,
            expected_revision=appended.review.revision,
            event=successor,
        ),
    )
    assert accepted_successor.ok is True
    assert accepted_successor.review.resolution_events == (first, successor)
    final_event = _resolution_event(
        review,
        corrections[2],
        contract.outputs.figure_png_version_id,
        predecessor_event_id=successor.event_id,
    )
    invalid_events = (
        _resigned_event(final_event, review_id=contract.review.run_id),
        _resigned_event(final_event, finding_id=contract.review.run_id),
        _resigned_event(final_event, predecessor_event_id=None),
        _resigned_event(
            final_event,
            occurred_at=review.created_at - timedelta(seconds=1),
        ),
        _resigned_event(final_event, successor_checksum="c" * 64),
    )
    for event in invalid_events:
        isolated_store = InMemoryReviewFindingsStore(
            (accepted_successor.review,),
            _resolution_version_index(contract),
        )
        before = accepted_successor.review.resolution_events
        rejected = append_finding_resolution_once(
            isolated_store,
            AppendFindingResolutionCommand(
                review_id=review.id,
                expected_revision=accepted_successor.review.revision,
                event=event,
            ),
        )
        assert isinstance(rejected, FindingResolutionRejected)
        assert rejected.reason == "invalid_event"
        assert accepted_successor.review.resolution_events == before

        positive_control = append_finding_resolution_once(
            isolated_store,
            AppendFindingResolutionCommand(
                review_id=review.id,
                expected_revision=accepted_successor.review.revision,
                event=final_event,
            ),
        )
        assert positive_control.ok is True
        assert positive_control.review.resolution_events == (
            first,
            successor,
            final_event,
        )


def test_resolution_store_serializes_concurrent_correction_append() -> None:
    contract = _contract()
    review = contract.review
    submission = review.submission
    assert submission is not None
    correction = _correction_fixtures(contract)[0]
    event = _resolution_event(review, correction, contract.artifact_versions[0].id)
    store = InMemoryReviewFindingsStore((review,), _resolution_version_index(contract))
    command = AppendFindingResolutionCommand(
        review_id=review.id,
        expected_revision=review.revision,
        event=event,
    )
    barrier = Barrier(3)

    def append_after_release() -> FindingResolutionAppended | FindingResolutionRejected:
        _ = barrier.wait()
        return append_finding_resolution_once(store, command)

    with ThreadPoolExecutor(max_workers=2) as executor:
        futures = tuple(executor.submit(append_after_release) for _ in range(2))
        _ = barrier.wait()
        results = tuple(future.result() for future in futures)
    assert sum(result.ok for result in results) == 1
    rejected = next(result for result in results if not result.ok)
    assert isinstance(rejected, FindingResolutionRejected)
    assert rejected.reason == "event_already_appended"


def test_rejects_submission_before_completion_and_exposes_no_execution_api() -> None:
    # Given: a running Review that already carries Findings.
    contract = _contract()
    premature = contract.review.model_dump(mode="python")
    premature["status"] = "running"

    # When/Then: lifecycle parsing rejects it and module exports no execution function.
    with pytest.raises(ValidationError, match="exactly when"):
        _ = PersistedReview.model_validate(premature)
    forbidden_names = {"run", "execute", "reexecute", "write_artifact"}
    assert forbidden_names.isdisjoint(dir(reviewer_contracts))
