"""Behavioral tests for the tenant-isolated retention governance store."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from threading import Barrier, Thread
from typing import TYPE_CHECKING, Final

import pytest
from tools.platform_policy.models import (
    CANDIDATES_MUST_NOT_BE_EMPTY,
    AuditDraft,
    BreakGlassRequest,
    BreakGlassUseCommand,
    DeletionAttestation,
    DeletionAttestationVerifierSet,
    DeletionSystem,
    HmacDeletionAttestationVerifier,
    HoldPlaceCommand,
    LegalHold,
    OperationalLog,
    PolicyChange,
    RetentionCompletionCommand,
    RetentionCompletionError,
    RetentionPolicy,
    RetentionPolicyError,
    RetentionPrincipal,
    build_audit_record,
    canonical_attestation_json,
    retention_policy_digest,
    verify_audit_record,
)
from tools.platform_policy.retention import (
    BreakGlassDeniedError,
    DuplicateRecordIdError,
    PolicyAuditRequiredError,
    RetentionAuthorizationError,
    RetentionStore,
)

if TYPE_CHECKING:
    from tools.platform_policy.models import AuditRecord, RetentionRun

NOW: Final[datetime] = datetime(2026, 7, 13, tzinfo=UTC)
ARCHIVE_SECRET: Final[bytes] = bytes.fromhex(
    "746573742d617263686976652d64656c657465722d736563726574"
)
PRIMARY_SECRET: Final[bytes] = bytes.fromhex(
    "746573742d7072696d6172792d64656c657465722d736563726574"
)
TENANT: Final[str] = "tenant-1"


class FixedClock:
    def __init__(self, value: datetime = NOW) -> None:
        self.value: datetime = value

    def now(self) -> datetime:
        return self.value


class FixedRestoreEpochAuthority:
    value: int

    def __init__(self, value: int = 1) -> None:
        self.value = value

    def current_epoch(self, tenant_id: str) -> int:
        assert tenant_id == TENANT
        return self.value


class OpaqueDeletionVerifier:
    issuer_id: str
    system: DeletionSystem
    key_id: str

    def __init__(
        self,
        issuer_id: str,
        system: DeletionSystem,
        key_id: str,
    ) -> None:
        self.issuer_id = issuer_id
        self.system = system
        self.key_id = key_id

    def verify(self, attestation: DeletionAttestation) -> bool:
        if (
            attestation.issuer_id != self.issuer_id
            or attestation.system is not self.system
            or attestation.key_id != self.key_id
        ):
            return False
        secret = (
            ARCHIVE_SECRET if self.system is DeletionSystem.ARCHIVE else PRIMARY_SECRET
        )
        expected = hmac.new(
            secret,
            canonical_attestation_json(attestation).encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, attestation.signature)


def operator(
    tenant_id: str = TENANT,
    principal_id: str = "operator",
) -> RetentionPrincipal:
    return RetentionPrincipal(
        principal_id=principal_id,
        tenant_id=tenant_id,
        roles=frozenset({"compliance_operator"}),
    )


def member(tenant_id: str = TENANT) -> RetentionPrincipal:
    return RetentionPrincipal(principal_id="member", tenant_id=tenant_id)


def verifier() -> DeletionAttestationVerifierSet:
    return DeletionAttestationVerifierSet(
        (
            OpaqueDeletionVerifier(
                "archive-deleter",
                DeletionSystem.ARCHIVE,
                "archive-test",
            ),
            OpaqueDeletionVerifier(
                "primary-deleter",
                DeletionSystem.PRIMARY,
                "primary-test",
            ),
        )
    )


def store(
    tenant_id: str = TENANT,
    restore_epoch_authority: FixedRestoreEpochAuthority | None = None,
) -> RetentionStore:
    return RetentionStore(
        tenant_id,
        RetentionPolicy.default(NOW),
        receipt_verifier=verifier(),
        restore_epoch_authority=restore_epoch_authority
        if restore_epoch_authority is not None
        else FixedRestoreEpochAuthority(),
    )


def audit(record_id: str, occurred_at: datetime = NOW) -> AuditRecord:
    return build_audit_record(
        AuditDraft(
            record_id=record_id,
            tenant_id=TENANT,
            event="test.event",
            actor_id="operator",
            subject_id=record_id,
            scope_id="project",
            reason="test",
            occurred_at=occurred_at,
            policy_version="retention-v1",
            state="created",
        )
    )


def sign_attestation(value: DeletionAttestation, secret: bytes) -> DeletionAttestation:
    signature = hmac.new(
        secret,
        canonical_attestation_json(value).encode(),
        hashlib.sha256,
    ).hexdigest()
    return replace(value, signature=signature)


def attestation(
    run: RetentionRun,
    record_id: str,
    system: DeletionSystem,
    *,
    tenant_id: str = TENANT,
    evidence_digest: str = "evidence",
) -> DeletionAttestation:
    run_id = run.run_id
    secret = ARCHIVE_SECRET if system is DeletionSystem.ARCHIVE else PRIMARY_SECRET
    issuer_id = (
        "archive-deleter" if system is DeletionSystem.ARCHIVE else "primary-deleter"
    )
    key_id = "archive-test" if system is DeletionSystem.ARCHIVE else "primary-test"
    return sign_attestation(
        DeletionAttestation(
            issuer_id=issuer_id,
            key_id=key_id,
            tenant_id=tenant_id,
            run_id=run_id,
            record_id=record_id,
            system=system,
            deleted_at=NOW + timedelta(seconds=1),
            evidence_digest=evidence_digest,
            challenge=run.challenge,
            candidate_manifest_digest=run.candidate_manifest_digest,
            signature="unsigned",
        ),
        secret,
    )


def completion(
    run: RetentionRun,
    record_ids: tuple[str, ...],
    *,
    evidence_digest: str = "evidence",
) -> RetentionCompletionCommand:
    attestations = tuple(
        attestation(run, record_id, system, evidence_digest=evidence_digest)
        for record_id in record_ids
        for system in DeletionSystem
    )
    return RetentionCompletionCommand(run_id=run.run_id, attestations=attestations)


@pytest.mark.parametrize(
    ("operational_days", "audit_days"),
    [(89, 365), (90, 364), (91, 365), (90, 366)],
)
def test_policy_retention_periods_are_exact(
    operational_days: int,
    audit_days: int,
) -> None:
    with pytest.raises(RetentionPolicyError):
        _ = RetentionPolicy("v", NOW, operational_days, audit_days)
    with pytest.raises(ValueError, match="HMAC secret must not be empty"):
        _ = HmacDeletionAttestationVerifier(
            "issuer", DeletionSystem.ARCHIVE, "test", b""
        )


def test_production_store_rejects_symmetric_hmac_verifier_bindings() -> None:
    hmac_verifiers = DeletionAttestationVerifierSet(
        (
            HmacDeletionAttestationVerifier(
                "archive-deleter",
                DeletionSystem.ARCHIVE,
                "archive-test",
                ARCHIVE_SECRET,
            ),
            HmacDeletionAttestationVerifier(
                "primary-deleter",
                DeletionSystem.PRIMARY,
                "primary-test",
                PRIMARY_SECRET,
            ),
        )
    )

    with pytest.raises(TypeError, match="opaque or asymmetric"):
        _ = RetentionStore(
            TENANT,
            RetentionPolicy.default(NOW),
            receipt_verifier=hmac_verifiers,
            restore_epoch_authority=FixedRestoreEpochAuthority(),
        )


def test_append_and_read_are_tenant_and_capability_bound() -> None:
    subject = store()
    assert not hasattr(subject, "__dict__")
    assert not hasattr(subject, "_replace_policy")
    assert not hasattr(subject, "receipt_verifier")
    assert not hasattr(verifier().verifiers[0], "_secret")
    assert not hasattr(verifier().verifiers[0], "secret")
    assert not hasattr(verifier().verifiers[0], "secret_fingerprint")
    opaque = DeletionAttestationVerifierSet(
        (
            OpaqueDeletionVerifier(
                "archive-public-verifier",
                DeletionSystem.ARCHIVE,
                "archive-public-key",
            ),
            OpaqueDeletionVerifier(
                "primary-public-verifier",
                DeletionSystem.PRIMARY,
                "primary-public-key",
            ),
        )
    )
    assert all(not hasattr(item, "_secret") for item in opaque.verifiers)
    attribute = "tenant_id"
    with pytest.raises(AttributeError):
        setattr(subject, attribute, "tenant-2")
    for attribute, value in (
        ("_tenant_id", "tenant-2"),
        ("policy", RetentionPolicy.default(NOW)),
        ("_policy", RetentionPolicy.default(NOW)),
        ("_receipt_verifier", verifier()),
        ("_restore_epoch_authority", FixedRestoreEpochAuthority()),
    ):
        with pytest.raises(AttributeError):
            setattr(subject, attribute, value)
    record = OperationalLog("record", TENANT, "project", NOW)

    with pytest.raises(RetentionAuthorizationError):
        subject.append_operational(record, member(), FixedClock())
    with pytest.raises(RetentionAuthorizationError):
        subject.append_operational(
            OperationalLog("foreign", "tenant-2", "project", NOW),
            operator(),
            FixedClock(NOW + timedelta(seconds=30)),
        )
    with pytest.raises(RetentionAuthorizationError):
        subject.append_audit(
            replace(audit("foreign-audit"), tenant_id="tenant-2"),
            operator(),
            FixedClock(NOW + timedelta(seconds=30)),
        )

    subject.append_operational(record, operator(), FixedClock())
    audit_record = audit("audit-record")
    subject.append_audit(audit_record, operator(), FixedClock())
    assert (
        subject.read_audit(
            "audit-record",
            operator(),
            FixedClock(),
            "audit-read",
        )
        == audit_record
    )

    with pytest.raises(RetentionAuthorizationError):
        _ = subject.operational_ids(operator("tenant-2"), FixedClock())

    with pytest.raises(RetentionAuthorizationError):
        _ = subject.read_audit(
            "audit-record",
            operator("tenant-2"),
            FixedClock(),
            "foreign-read",
        )
    assert subject.operational_ids(operator(), FixedClock()) == ("record",)


def test_monotonic_clock_and_event_identifier_binding_are_store_wide() -> None:
    subject = store()
    subject.append_operational(
        OperationalLog("record", TENANT, "project", NOW),
        operator(),
        FixedClock(),
    )

    with pytest.raises(DuplicateRecordIdError):
        _ = subject.place_legal_hold(
            HoldPlaceCommand(
                hold_id="hold",
                tenant_id=TENANT,
                scope_id="project",
                case_id="case",
                authority="court",
                reason="preserve",
                event_id="record",
            ),
            operator(),
            FixedClock(),
        )
    with pytest.raises(DuplicateRecordIdError):
        _ = subject.place_legal_hold(
            HoldPlaceCommand(
                hold_id="hold-event",
                tenant_id=TENANT,
                scope_id="project",
                case_id="case",
                authority="court",
                reason="preserve",
                event_id="hold-event",
            ),
            operator(),
            FixedClock(),
        )
    with pytest.raises(DuplicateRecordIdError):
        _ = subject.request_break_glass(
            BreakGlassRequest(
                "grant-event",
                TENANT,
                "resource",
                "read_metadata",
                1,
                NOW + timedelta(minutes=1),
                "grant-event",
            ),
            operator(),
            FixedClock(),
        )
    with pytest.raises(ValueError, match="clock must be monotonic"):
        _ = subject.operational_ids(operator(), FixedClock(NOW - timedelta(seconds=1)))


def test_rejected_legal_hold_commands_do_not_consume_audit_or_state() -> None:
    """Validate every hold field before consuming identifiers or mutating state."""
    subject = store()
    _ = subject.place_legal_hold(
        HoldPlaceCommand(
            "existing-hold",
            TENANT,
            "project",
            "case",
            "court",
            "preserve",
            "existing-hold-event",
        ),
        operator(),
        FixedClock(),
    )
    _ = subject.release_legal_hold(
        "existing-hold",
        operator(),
        FixedClock(),
        "existing-release-event",
        "released",
    )
    before = (
        subject.audit_records(operator(), FixedClock()),
        subject.audit_ids(operator(), FixedClock()),
        subject.legal_hold_history("project", operator(), FixedClock()),
    )

    for field in ("case_id", "authority", "reason"):
        command = HoldPlaceCommand(
            hold_id=f"hold-{field}",
            tenant_id=TENANT,
            scope_id="project",
            case_id="case",
            authority="court",
            reason="preserve",
            event_id=f"hold-{field}-event",
        )
        with pytest.raises(ValueError, match=f"{field} must not be empty"):
            _ = subject.place_legal_hold(
                replace(command, **{field: ""}), operator(), FixedClock()
            )
        assert (
            subject.audit_records(operator(), FixedClock()),
            subject.audit_ids(operator(), FixedClock()),
            subject.legal_hold_history("project", operator(), FixedClock()),
        ) == before


def test_rejected_legal_hold_releases_leave_clock_and_ids_unchanged() -> None:
    """Release validation failures must not consume time or event identifiers."""
    subject = store()
    _ = subject.place_legal_hold(
        HoldPlaceCommand(
            "hold",
            TENANT,
            "project",
            "case",
            "court",
            "preserve",
            "placed-event",
        ),
        operator(),
        FixedClock(),
    )

    with pytest.raises(ValueError, match="reason must not be empty"):
        _ = subject.release_legal_hold(
            "hold",
            operator(),
            FixedClock(NOW + timedelta(seconds=2)),
            "invalid-release",
            "",
        )
    with pytest.raises(DuplicateRecordIdError):
        _ = subject.release_legal_hold(
            "hold",
            operator(),
            FixedClock(NOW + timedelta(seconds=2)),
            "placed-event",
            "released",
        )

    released = subject.release_legal_hold(
        "hold",
        operator(),
        FixedClock(NOW + timedelta(seconds=1)),
        "invalid-release",
        "released",
    )
    assert released.released_at == NOW + timedelta(seconds=1)
    assert subject.audit_ids(operator(), FixedClock(NOW + timedelta(seconds=1))) == (
        "placed-event",
        "invalid-release",
    )


def test_audit_record_preserves_datetime_while_hashing_canonical_isoformat() -> None:
    record = audit("audit-record")

    assert record.occurred_at is NOW
    assert record.checksum_sha256


def test_expiry_hides_candidates_then_completed_run_purges_them() -> None:
    subject = store()
    subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    subject.append_operational(
        OperationalLog("fresh", TENANT, "project", NOW - timedelta(days=89)),
        operator(),
        FixedClock(),
    )

    receipt = subject.expire(operator(), FixedClock())

    assert receipt.operational_ids == ("old",)
    assert subject.operational_ids(operator(), FixedClock()) == ("fresh",)

    run = subject.start_retention_run("run", "key", operator(), FixedClock())
    completed = subject.complete_retention_run(
        completion(run, run.operational_ids),
        operator(),
        FixedClock(NOW + timedelta(seconds=1)),
    )

    assert completed.completed_at == NOW + timedelta(seconds=1)
    assert subject.verify_run(
        completed,
        operator(),
        FixedClock(NOW + timedelta(seconds=1)),
    )
    assert not subject.verify_run(
        replace(completed, checksum_sha256="tampered"),
        operator(),
        FixedClock(NOW + timedelta(seconds=1)),
    )
    assert subject.operational_ids(
        operator(), FixedClock(NOW + timedelta(seconds=1))
    ) == ("fresh",)


def test_overlapping_runs_reserve_expired_candidates_and_replay_is_stable() -> None:
    subject = store()
    subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())

    first = subject.start_retention_run("run-1", "key-1", operator(), FixedClock())
    replay = subject.start_retention_run("run-1", "key-1", operator(), FixedClock())

    assert first.operational_ids == ("old",)
    assert replay == first
    with pytest.raises(ValueError, match="retention run must have candidates"):
        _ = subject.start_retention_run("run-2", "key-2", operator(), FixedClock())


def test_zero_candidate_runs_are_rejected_before_completion() -> None:
    """Reject runs without deletion candidates before they can be completed."""
    subject = store()

    with pytest.raises(ValueError, match="retention run must have candidates"):
        _ = subject.start_retention_run(
            "empty-run", "empty-key", operator(), FixedClock()
        )


def test_completion_rejects_missing_foreign_duplicate_and_bad_receipts() -> None:
    subject = store()
    subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())
    run = subject.start_retention_run("run", "key", operator(), FixedClock())
    archive = attestation(run, "old", DeletionSystem.ARCHIVE)
    primary = attestation(run, "old", DeletionSystem.PRIMARY)
    stale_archive = sign_attestation(
        replace(
            archive,
            deleted_at=NOW,
            signature="unsigned",
        ),
        ARCHIVE_SECRET,
    )

    invalid_commands = (
        RetentionCompletionCommand("run", (archive,)),
        RetentionCompletionCommand("run", (archive, archive)),
        RetentionCompletionCommand(
            "run",
            (
                archive,
                attestation(
                    run,
                    "old",
                    DeletionSystem.PRIMARY,
                    tenant_id="tenant-2",
                ),
            ),
        ),
        RetentionCompletionCommand(
            "run",
            (archive, replace(primary, signature="bad")),
        ),
        RetentionCompletionCommand("run", (stale_archive, primary)),
    )

    for command in invalid_commands:
        with pytest.raises(RetentionCompletionError):
            _ = subject.complete_retention_run(
                command, operator(), FixedClock(NOW + timedelta(seconds=1))
            )

    completed = subject.complete_retention_run(
        RetentionCompletionCommand("run", (primary, archive)),
        operator(),
        FixedClock(NOW + timedelta(seconds=1)),
    )
    assert subject.verify_run(
        completed,
        operator(),
        FixedClock(NOW + timedelta(seconds=1)),
    )


def test_completed_run_requires_exact_replay_and_authorizes_lookup_and_resume() -> None:
    subject = store()
    subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())
    run = subject.start_retention_run("run", "key", operator(), FixedClock())
    command = completion(run, run.operational_ids)
    completed = subject.complete_retention_run(
        command, operator(), FixedClock(NOW + timedelta(seconds=1))
    )

    assert (
        subject.retention_run("run", operator(), FixedClock(NOW + timedelta(seconds=1)))
        == completed
    )
    assert (
        subject.resume_retention_run(
            "run", operator(), FixedClock(NOW + timedelta(seconds=1))
        )
        == completed
    )
    assert (
        subject.complete_retention_run(
            command, operator(), FixedClock(NOW + timedelta(seconds=1))
        )
        == completed
    )

    with pytest.raises(RetentionCompletionError):
        _ = subject.complete_retention_run(
            completion(run, run.operational_ids, evidence_digest="conflict"),
            operator(),
            FixedClock(NOW + timedelta(seconds=1)),
        )
    with pytest.raises(RetentionAuthorizationError):
        _ = subject.retention_run("run", member(), FixedClock())
    with pytest.raises(RetentionAuthorizationError):
        _ = subject.resume_retention_run("run", member(), FixedClock())


def test_holds_block_expiry_and_late_holds_quarantine_reserved_candidates() -> None:
    subject = store()
    subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.place_legal_hold(
        HoldPlaceCommand(
            "hold",
            TENANT,
            "project",
            "case",
            "court",
            "preserve",
            "hold-place",
        ),
        operator(),
        FixedClock(),
    )

    assert subject.expire(operator(), FixedClock()).operational_ids == ()

    _ = subject.release_legal_hold(
        "hold",
        operator(),
        FixedClock(),
        "hold-release",
        "released",
    )
    _ = subject.expire(operator(), FixedClock())
    run = subject.start_retention_run("run", "key", operator(), FixedClock())
    _ = subject.place_legal_hold(
        HoldPlaceCommand(
            "hold-2",
            TENANT,
            "project",
            "case-2",
            "court",
            "preserve",
            "hold-place-2",
        ),
        operator(),
        FixedClock(),
    )
    delayed = subject.complete_retention_run(
        completion(run, run.operational_ids),
        operator(),
        FixedClock(NOW + timedelta(seconds=1)),
    )

    assert delayed.completed_at is None
    assert delayed.attempts == 2


def test_break_glass_enforces_approval_order_tenant_binding_and_boundaries() -> None:
    subject = store()
    requester = operator(principal_id="requester")
    expiry = NOW + timedelta(minutes=1)
    request = BreakGlassRequest(
        "grant",
        TENANT,
        "resource",
        "read_metadata",
        1,
        expiry,
        "request-event",
    )

    grant = subject.request_break_glass(request, requester, FixedClock())

    with pytest.raises(BreakGlassDeniedError):
        _ = subject.use_break_glass(
            BreakGlassUseCommand(
                "grant",
                TENANT,
                "resource",
                "read_metadata",
                1,
                "early-use",
            ),
            requester,
            FixedClock(),
        )
    with pytest.raises(BreakGlassDeniedError):
        _ = subject.approve_break_glass(
            grant.grant_id,
            requester,
            FixedClock(),
            "self-approve",
        )

    approved = subject.approve_break_glass(
        grant.grant_id,
        operator(),
        FixedClock(),
        "approve",
    )

    assert approved.approver_id == "operator"
    assert subject.use_break_glass(
        BreakGlassUseCommand("grant", TENANT, "resource", "read_metadata", 1, "use"),
        requester,
        FixedClock(),
    )

    with pytest.raises(BreakGlassDeniedError):
        _ = subject.use_break_glass(
            BreakGlassUseCommand(
                "grant",
                TENANT,
                "resource",
                "read_metadata",
                1,
                "expiry-use",
            ),
            requester,
            FixedClock(expiry),
        )
    with pytest.raises(RetentionAuthorizationError):
        _ = subject.revoke_break_glass(
            grant.grant_id,
            operator("tenant-2"),
            FixedClock(expiry),
            "foreign-revoke",
        )

    expired = subject.expire_break_glass(
        grant.grant_id,
        operator(),
        FixedClock(expiry),
        "expire",
    )

    assert expired.expired_at == expiry


def test_completion_rejects_every_attestation_binding_adversary() -> None:
    """Reject signed evidence with any altered run, trust, or time binding."""
    subject = store()
    subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())
    run = subject.start_retention_run("run", "key", operator(), FixedClock())
    archive = attestation(run, "old", DeletionSystem.ARCHIVE)
    primary = attestation(run, "old", DeletionSystem.PRIMARY)
    adversaries = (
        sign_attestation(
            replace(archive, issuer_id="other", signature="unsigned"),
            ARCHIVE_SECRET,
        ),
        sign_attestation(
            replace(archive, key_id="other", signature="unsigned"),
            ARCHIVE_SECRET,
        ),
        sign_attestation(
            replace(archive, challenge="other", signature="unsigned"),
            ARCHIVE_SECRET,
        ),
        sign_attestation(
            replace(
                archive,
                candidate_manifest_digest="other",
                signature="unsigned",
            ),
            ARCHIVE_SECRET,
        ),
        sign_attestation(
            replace(archive, deleted_at=NOW, signature="unsigned"),
            ARCHIVE_SECRET,
        ),
        sign_attestation(
            replace(
                archive,
                deleted_at=NOW + timedelta(seconds=2),
                signature="unsigned",
            ),
            ARCHIVE_SECRET,
        ),
    )
    for adversary in adversaries:
        with pytest.raises(RetentionCompletionError):
            _ = subject.complete_retention_run(
                RetentionCompletionCommand(run.run_id, (adversary, primary)),
                operator(),
                FixedClock(NOW + timedelta(seconds=1)),
            )

    wrong_system = sign_attestation(
        replace(
            archive,
            system=DeletionSystem.PRIMARY,
            issuer_id="primary-deleter",
            key_id="primary-test",
            signature="unsigned",
        ),
        PRIMARY_SECRET,
    )
    with pytest.raises(RetentionCompletionError):
        _ = subject.complete_retention_run(
            RetentionCompletionCommand(run.run_id, (wrong_system, primary)),
            operator(),
            FixedClock(NOW + timedelta(seconds=1)),
        )


def test_zero_candidate_run_cannot_produce_verifiable_completion() -> None:
    """Fail closed before a producer can create empty completion evidence."""
    subject = store()

    with pytest.raises(ValueError, match="retention run must have candidates"):
        _ = subject.start_retention_run("run", "key", operator(), FixedClock())


def test_policy_change_events_are_fully_audited() -> None:
    """Require bound policy evidence and preserve every emergency audit record."""
    subject = store()
    updated = RetentionPolicy("retention-v2", NOW, 90, 365)
    change = PolicyChange(
        "operator", "scheduled", NOW, updated, retention_policy_digest(updated)
    )
    evidence = build_audit_record(
        AuditDraft(
            record_id="policy-event",
            tenant_id=TENANT,
            event="retention.policy.changed",
            actor_id="operator",
            subject_id=updated.version,
            scope_id="policy",
            reason=change.reason,
            occurred_at=NOW,
            policy_version="retention-v1",
            state=(
                "from=retention-v1;to=retention-v2;"
                f"policy_sha256={change.policy_digest};reason=scheduled"
            ),
        )
    )
    valid_scope_tamper = build_audit_record(
        AuditDraft(
            record_id="policy-event-scope",
            tenant_id=TENANT,
            event="retention.policy.changed",
            actor_id="operator",
            subject_id=updated.version,
            scope_id="other",
            reason=change.reason,
            occurred_at=NOW,
            policy_version="retention-v1",
            state=(
                "from=retention-v1;to=retention-v2;"
                f"policy_sha256={change.policy_digest};reason=scheduled"
            ),
        )
    )
    with pytest.raises(PolicyAuditRequiredError):
        subject.change_policy(change, valid_scope_tamper, operator(), FixedClock())

    for field, value in (
        ("tenant_id", "tenant-2"),
        ("event", "other"),
        ("actor_id", "other"),
        ("subject_id", "other"),
        ("scope_id", "other"),
        ("reason", "other"),
        ("occurred_at", NOW - timedelta(seconds=1)),
        ("policy_version", "retention-v0"),
        ("state", "other"),
        ("checksum_sha256", "tampered"),
    ):
        with pytest.raises(PolicyAuditRequiredError):
            subject.change_policy(
                change,
                replace(evidence, **{field: value}),
                operator(),
                FixedClock(),
            )
    with pytest.raises(PolicyAuditRequiredError):
        subject.change_policy(
            change,
            evidence,
            operator(),
            FixedClock(NOW + timedelta(seconds=1)),
        )
    assert subject.policy == RetentionPolicy.default(NOW)
    assert subject.audit_ids(operator(), FixedClock()) == ()
    subject.change_policy(change, evidence, operator(), FixedClock())
    assert subject.policy == updated
    assert verify_audit_record(evidence)


def test_initial_policy_cannot_apply_before_its_effective_time() -> None:
    future = NOW + timedelta(minutes=1)
    subject = RetentionStore(
        TENANT,
        RetentionPolicy.default(future),
        receipt_verifier=verifier(),
        restore_epoch_authority=FixedRestoreEpochAuthority(),
    )
    record = OperationalLog("future-policy-record", TENANT, "project", NOW)

    with pytest.raises(ValueError, match="not yet effective"):
        subject.append_operational(record, operator(), FixedClock())

    subject.append_operational(record, operator(), FixedClock(future))
    assert subject.operational_ids(operator(), FixedClock(future)) == (
        record.record_id,
    )


def test_policy_change_evidence_cannot_bind_a_different_policy() -> None:
    """Bind evidence to all replacement-policy fields, including effective_at."""
    subject = store()
    original = RetentionPolicy("retention-v2", NOW, 90, 365)
    change = PolicyChange(
        "operator", "scheduled", NOW, original, retention_policy_digest(original)
    )
    evidence = build_audit_record(
        AuditDraft(
            record_id="policy-event",
            tenant_id=TENANT,
            event="retention.policy.changed",
            actor_id="operator",
            subject_id=original.version,
            scope_id="policy",
            reason=change.reason,
            occurred_at=NOW,
            policy_version="retention-v1",
            state=(
                "from=retention-v1;to=retention-v2;"
                f"policy_sha256={change.policy_digest};reason=scheduled"
            ),
        )
    )
    replacement = RetentionPolicy("retention-v2", NOW + timedelta(seconds=1), 90, 365)
    different_effective_time = PolicyChange(
        "operator",
        "scheduled",
        replacement.effective_at,
        replacement,
        retention_policy_digest(replacement),
    )

    with pytest.raises(PolicyAuditRequiredError):
        subject.change_policy(
            different_effective_time,
            evidence,
            operator(),
            FixedClock(replacement.effective_at),
        )
    assert subject.policy == RetentionPolicy.default(NOW)
    assert subject.audit_records(operator(), FixedClock(replacement.effective_at)) == ()
    assert subject.audit_ids(operator(), FixedClock(replacement.effective_at)) == ()

    for replacement_policy in (
        RetentionPolicy("retention-v3", NOW, 90, 365),
        RetentionPolicy("retention-v2", NOW + timedelta(seconds=1), 90, 365),
    ):
        with pytest.raises(ValueError, match="policy_digest must bind"):
            _ = PolicyChange(
                "operator",
                "scheduled",
                replacement_policy.effective_at,
                replacement_policy,
                change.policy_digest,
            )


def test_break_glass_events_are_fully_audited() -> None:
    subject = store()
    request = BreakGlassRequest(
        "grant-audit",
        TENANT,
        "resource",
        "read_metadata",
        1,
        NOW + timedelta(minutes=1),
        "request-audit",
    )
    grant = subject.request_break_glass(
        request,
        operator(principal_id="requester"),
        FixedClock(),
    )
    _ = subject.approve_break_glass(
        grant.grant_id, operator(), FixedClock(), "approval-audit"
    )
    with pytest.raises(BreakGlassDeniedError):
        _ = subject.use_break_glass(
            BreakGlassUseCommand(
                grant.grant_id,
                TENANT,
                "other",
                "read_metadata",
                1,
                "denial-audit",
            ),
            operator(principal_id="requester"),
            FixedClock(),
        )
    _ = subject.revoke_break_glass(
        grant.grant_id, operator(), FixedClock(), "revocation-audit"
    )
    assert all(
        verify_audit_record(record)
        for record in subject.audit_records(operator(), FixedClock())
    )


def test_denied_break_glass_transitions_are_audited_without_grants() -> None:
    """Audit each denied transition while preserving the grant state machine."""
    subject = store()
    requester = operator(principal_id="requester")
    expiry = NOW + timedelta(minutes=1)

    with pytest.raises(BreakGlassDeniedError):
        _ = subject.request_break_glass(
            BreakGlassRequest(
                "invalid",
                TENANT,
                "resource",
                "write",
                1,
                expiry,
                "request-denied",
            ),
            requester,
            FixedClock(),
        )
    grant = subject.request_break_glass(
        BreakGlassRequest(
            "grant",
            TENANT,
            "resource",
            "read_metadata",
            1,
            expiry,
            "request",
        ),
        requester,
        FixedClock(),
    )
    with pytest.raises(BreakGlassDeniedError):
        _ = subject.approve_break_glass(
            grant.grant_id, requester, FixedClock(), "approval-denied"
        )
    approved = subject.approve_break_glass(
        grant.grant_id, operator(), FixedClock(), "approval"
    )
    with pytest.raises(BreakGlassDeniedError):
        _ = subject.expire_break_glass(
            approved.grant_id, operator(), FixedClock(), "expiry-denied"
        )
    _ = subject.revoke_break_glass(
        approved.grant_id, operator(), FixedClock(), "revocation"
    )
    with pytest.raises(BreakGlassDeniedError):
        _ = subject.revoke_break_glass(
            approved.grant_id, operator(), FixedClock(), "revocation-denied"
        )
    with pytest.raises(BreakGlassDeniedError):
        _ = subject.expire_break_glass(
            approved.grant_id, operator(), FixedClock(), "expiry-revoked-denied"
        )

    events = {
        record.event for record in subject.audit_records(operator(), FixedClock())
    }
    assert {
        "break_glass.request.denied",
        "break_glass.approval.denied",
        "break_glass.expiry.denied",
        "break_glass.revocation.denied",
    } <= events
    with pytest.raises(BreakGlassDeniedError):
        _ = subject.use_break_glass(
            BreakGlassUseCommand(
                "invalid", TENANT, "resource", "read_metadata", 1, "invalid-use"
            ),
            requester,
            FixedClock(),
        )


def test_restored_break_glass_grant_requires_current_external_epoch() -> None:
    epoch_authority = FixedRestoreEpochAuthority()
    subject = store(restore_epoch_authority=epoch_authority)
    requester = operator(principal_id="requester")
    grant = subject.request_break_glass(
        BreakGlassRequest(
            "epoch-grant",
            TENANT,
            "resource",
            "read_metadata",
            1,
            NOW + timedelta(minutes=1),
            "epoch-request",
        ),
        requester,
        FixedClock(),
    )
    _ = subject.approve_break_glass(
        grant.grant_id,
        operator(),
        FixedClock(),
        "epoch-approval",
    )

    epoch_authority.value = 2
    with pytest.raises(BreakGlassDeniedError, match="restore epoch"):
        _ = subject.use_break_glass(
            BreakGlassUseCommand(
                grant.grant_id,
                TENANT,
                "resource",
                "read_metadata",
                1,
                "stale-epoch-use",
            ),
            requester,
            FixedClock(NOW + timedelta(seconds=30)),
        )
    with pytest.raises(BreakGlassDeniedError, match="restore epoch"):
        _ = subject.request_break_glass(
            BreakGlassRequest(
                "stale-epoch-grant",
                TENANT,
                "resource",
                "read_metadata",
                1,
                NOW + timedelta(minutes=1),
                "stale-epoch-request",
            ),
            requester,
            FixedClock(NOW + timedelta(seconds=30)),
        )

    current = subject.request_break_glass(
        BreakGlassRequest(
            "current-epoch-grant",
            TENANT,
            "resource",
            "read_metadata",
            2,
            NOW + timedelta(minutes=1),
            "current-epoch-request",
        ),
        requester,
        FixedClock(),
    )
    assert current.restore_epoch == 2


def test_unauthorized_break_glass_use_does_not_mutate_store() -> None:
    """Reject unauthorized actors and foreign payloads without any mutation."""
    subject = store()
    requester = operator(principal_id="requester")
    grant = subject.request_break_glass(
        BreakGlassRequest(
            "grant",
            TENANT,
            "resource",
            "read_metadata",
            1,
            NOW + timedelta(minutes=1),
            "request",
        ),
        requester,
        FixedClock(),
    )
    _ = subject.approve_break_glass(
        grant.grant_id,
        operator(),
        FixedClock(),
        "approval",
    )

    with pytest.raises(RetentionAuthorizationError):
        _ = subject.use_break_glass(
            BreakGlassUseCommand(
                grant.grant_id,
                TENANT,
                "resource",
                "read_metadata",
                1,
                "roleless-use-denied",
            ),
            member(),
            FixedClock(NOW + timedelta(seconds=30)),
        )

    with pytest.raises(RetentionAuthorizationError):
        _ = subject.use_break_glass(
            BreakGlassUseCommand(
                grant.grant_id,
                "tenant-2",
                "resource",
                "read_metadata",
                1,
                "shared-use-event",
            ),
            operator(),
            FixedClock(NOW + timedelta(seconds=30)),
        )
    assert subject.use_break_glass(
        BreakGlassUseCommand(
            grant.grant_id,
            TENANT,
            "resource",
            "read_metadata",
            1,
            "shared-use-event",
        ),
        requester,
        FixedClock(),
    )

    denied = tuple(
        record
        for record in subject.audit_records(operator(), FixedClock())
        if record.event == "break_glass.denied"
        and record.record_id in {"roleless-use-denied", "shared-use-event"}
    )
    assert denied == ()


def test_threaded_run_start_reserves_each_expired_candidate_once() -> None:
    """Serialize competing runs after a deterministic pre-invocation barrier."""
    subject = store()
    _ = subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())
    barrier = Barrier(2)
    runs: list[RetentionRun] = []
    errors: list[ValueError] = []

    def start(run_id: str, key: str) -> None:
        _ = barrier.wait()
        try:
            run = subject.start_retention_run(run_id, key, operator(), FixedClock())
        except ValueError as error:
            errors.append(error)
        else:
            runs.append(run)

    first = Thread(target=start, args=("run-1", "key-1"))
    second = Thread(target=start, args=("run-2", "key-2"))
    first.start()
    second.start()
    first.join()
    second.join()

    assert len(runs) == 1
    assert runs[0].operational_ids == ("old",)
    assert len(errors) == 1
    assert errors[0].args == (CANDIDATES_MUST_NOT_BE_EMPTY,)


def test_threaded_shared_event_id_creates_one_grant_and_one_audit() -> None:
    """Serialize competing requests that attempt to reuse one audit identity."""
    subject = store()
    barrier = Barrier(2)
    grants: list[str] = []
    errors: list[DuplicateRecordIdError] = []

    def request(grant_id: str) -> None:
        _ = barrier.wait()
        try:
            grant = subject.request_break_glass(
                BreakGlassRequest(
                    grant_id,
                    TENANT,
                    "resource",
                    "read_metadata",
                    1,
                    NOW + timedelta(minutes=1),
                    "shared-event",
                ),
                operator(principal_id=grant_id),
                FixedClock(),
            )
            grants.append(grant.grant_id)
        except DuplicateRecordIdError as error:
            errors.append(error)

    first = Thread(target=request, args=("grant-1",))
    second = Thread(target=request, args=("grant-2",))
    first.start()
    second.start()
    first.join()
    second.join()

    assert len(grants) == 1
    assert len(errors) == 1
    assert isinstance(errors[0], DuplicateRecordIdError)
    assert tuple(
        record.record_id
        for record in subject.audit_records(operator(), FixedClock())
        if record.event == "break_glass.requested"
    ) == ("shared-event",)


def test_threaded_hold_and_completion_are_serialized_without_purge_race() -> None:
    """A concurrent hold either precedes completion or follows a completed purge."""
    subject = store()
    _ = subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())
    run = subject.start_retention_run("run", "key", operator(), FixedClock())
    barrier = Barrier(2)
    outcomes: list[RetentionRun | LegalHold] = []

    def complete() -> None:
        _ = barrier.wait()
        outcomes.append(
            subject.complete_retention_run(
                completion(run, run.operational_ids),
                operator(),
                FixedClock(NOW + timedelta(seconds=1)),
            )
        )

    def place_hold() -> None:
        _ = barrier.wait()
        outcomes.append(
            subject.place_legal_hold(
                HoldPlaceCommand(
                    "hold",
                    TENANT,
                    "project",
                    "case",
                    "court",
                    "preserve",
                    "hold-event",
                ),
                operator(),
                FixedClock(NOW + timedelta(seconds=1)),
            )
        )

    completion_thread = Thread(target=complete)
    hold_thread = Thread(target=place_hold)
    completion_thread.start()
    hold_thread.start()
    completion_thread.join()
    hold_thread.join()

    stored = subject.retention_run(
        run.run_id, operator(), FixedClock(NOW + timedelta(seconds=1))
    )
    assert len(outcomes) == 2
    if stored.completed_at is None:
        assert stored.receipts == ()
        assert stored.attempts == 2
    else:
        assert stored.receipts
        assert stored.completed_at == NOW + timedelta(seconds=1)


def test_audit_exact_boundary_and_released_hold_evidence_remain_protected() -> None:
    """Expire exactly 365-day audits but reject evidence produced during a hold."""
    subject = store()
    boundary = audit("audit-boundary", NOW - timedelta(days=365))
    subject.append_audit(boundary, operator(), FixedClock())
    assert subject.expire(operator(), FixedClock()).audit_ids == ("audit-boundary",)

    subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())
    run = subject.start_retention_run("held-run", "held-key", operator(), FixedClock())
    _ = subject.place_legal_hold(
        HoldPlaceCommand(
            "hold",
            TENANT,
            "project",
            "case",
            "court",
            "preserve",
            "hold-event",
        ),
        operator(),
        FixedClock(),
    )
    _ = subject.release_legal_hold(
        "hold",
        operator(),
        FixedClock(NOW + timedelta(seconds=2)),
        "release-event",
        "released",
    )
    delayed = subject.complete_retention_run(
        completion(run, run.operational_ids),
        operator(),
        FixedClock(NOW + timedelta(seconds=3)),
    )
    assert delayed.completed_at is None


def test_audit_inspection_requires_authorization() -> None:
    """Keep complete audit inspection tenant- and role-bound."""
    subject = store()
    with pytest.raises(RetentionAuthorizationError):
        _ = subject.audit_records(member(), FixedClock())


def test_policy_change_rejects_unbound_audit_evidence() -> None:
    """Reject policy changes without fully matching immutable audit evidence."""
    subject = store()
    updated = RetentionPolicy("retention-v2", NOW, 90, 365)
    change = PolicyChange(
        "operator", "scheduled", NOW, updated, retention_policy_digest(updated)
    )
    with pytest.raises(PolicyAuditRequiredError):
        subject.change_policy(change, None, operator(), FixedClock())


def test_candidate_run_challenges_and_manifests_are_unique_per_run() -> None:
    """Freeze a distinct unpredictable challenge and manifest for every run."""
    subject = store()
    subject.append_operational(
        OperationalLog("old-1", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())
    first = subject.start_retention_run("run-1", "key-1", operator(), FixedClock())
    subject.append_operational(
        OperationalLog("old-2", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())
    second = subject.start_retention_run("run-2", "key-2", operator(), FixedClock())

    assert first.challenge != second.challenge
    assert first.candidate_manifest_digest != second.candidate_manifest_digest


def test_released_hold_leaves_candidate_available_for_later_retry() -> None:
    """Leave quarantined candidates intact when hold-era evidence is rejected."""
    subject = store()
    subject.append_operational(
        OperationalLog("old", TENANT, "project", NOW - timedelta(days=90)),
        operator(),
        FixedClock(),
    )
    _ = subject.expire(operator(), FixedClock())
    run = subject.start_retention_run("run", "key", operator(), FixedClock())
    _ = subject.place_legal_hold(
        HoldPlaceCommand(
            "hold",
            TENANT,
            "project",
            "case",
            "court",
            "preserve",
            "hold-event",
        ),
        operator(),
        FixedClock(),
    )
    _ = subject.release_legal_hold(
        "hold",
        operator(),
        FixedClock(NOW + timedelta(seconds=2)),
        "release-event",
        "released",
    )
    delayed = subject.complete_retention_run(
        completion(run, run.operational_ids),
        operator(),
        FixedClock(NOW + timedelta(seconds=3)),
    )

    assert delayed.completed_at is None
    assert (
        subject.retention_run(
            run.run_id,
            operator(),
            FixedClock(NOW + timedelta(seconds=3)),
        )
        == delayed
    )
