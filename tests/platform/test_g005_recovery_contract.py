import hashlib
import json
import sqlite3
import threading
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from itertools import product
from pathlib import Path
from typing import Final, Literal, cast, final, override
from uuid import UUID

import pytest
from tools.platform_policy.ci_contract import (
    EvidenceIntegrityError,
    RequiredSecurityCatalog,
    SecurityEvidenceMapping,
    TaskAttemptBundle,
    TaskAttemptEvidence,
    load_task_attempt_bundle,
    persist_task_attempt_bundle,
    task_attempt_root,
    verify_security_evidence_mapping,
)

from science_workbench_contracts.protocols.recovery import (
    AttemptCompareAndSetRequest,
    AttemptStatus,
    BreakGlassActionRequest,
    BreakGlassGrant,
    ClaimAttemptRequest,
    CompleteAttemptRequest,
    DurableCompareAndSetRequest,
    EffectState,
    ExecutionAttempt,
    GovernancePermit,
    GovernanceSnapshot,
    HeartbeatAttemptRequest,
    HoldRecord,
    PhysicalPurgePermit,
    ReconciliationProof,
    ReconciliationProofStore,
    RecordEffectRequest,
    RecoveryProtocolError,
    RestoreGovernanceManifest,
    RestoreLifecycle,
    RetryAttemptCreationOutcome,
    RetryAttemptCreationRequest,
    RetryCommand,
    TombstoneRecord,
    advance_restore,
    advance_restore_authoritatively,
    claim_attempt,
    claim_attempt_durable,
    complete_attempt,
    complete_attempt_durable,
    heartbeat_attempt_durable,
    normal_access_allowed,
    perform_break_glass_action,
    perform_downstream_effect,
    perform_normal_access_from_store,
    perform_physical_purge_from_store,
    physical_purge_allowed,
    reconcile_no_effect,
    reconciliation_proof_digest,
    reconciliation_proof_id,
    record_effect,
    record_effect_durable,
    restore_manifest_digest,
    retry_attempt,
)

NOW: Final = datetime(2026, 7, 13, tzinfo=UTC)
DIGEST: Final = "a" * 64


@final
class DurableCas:
    """Test double for a restartable durable compare-and-set authority."""

    values: dict[str, str]

    def __init__(self) -> None:
        self.values = {}

    def compare_and_set(self, request: DurableCompareAndSetRequest) -> bool:
        if self.values.get(request.key) != request.expected:
            return False
        self.values[request.key] = request.value
        return True


@final
class ProofResolver:
    """Independent immutable proof-anchor authority for recovery tests."""

    anchors: dict[str, str]

    def __init__(self, anchors: dict[str, str]) -> None:
        self.anchors = anchors

    def resolve_anchor(self, proof_id: str) -> str | None:
        return self.anchors.get(proof_id)


@final
class AttemptCas:
    """Durable authoritative attempt row model with an injected store clock."""

    current: ExecutionAttempt
    now: datetime

    def __init__(self, current: ExecutionAttempt, now: datetime = NOW) -> None:
        self.current = current
        self.now = now
        self._lock = threading.Lock()

    def compare_and_set_at_authoritative_time(
        self,
        request: AttemptCompareAndSetRequest,
        transition: Callable[[ExecutionAttempt, datetime], ExecutionAttempt],
    ) -> ExecutionAttempt | None:
        with self._lock:
            if self.current != request.expected:
                return None
            assert callable(transition)
            replacement = transition(self.current, self.now)
            self.current = replacement
            return replacement

    def compare_and_set_perform_at_authoritative_time(
        self,
        request: AttemptCompareAndSetRequest,
        transition: Callable[[ExecutionAttempt, datetime], ExecutionAttempt],
        action: Callable[[], None],
    ) -> ExecutionAttempt | None:
        with self._lock:
            if self.current != request.expected:
                return None
            assert callable(transition)
            replacement = transition(self.current, self.now)
            assert callable(action)
            self.current = replacement
            _ = action()
            return replacement


@final
class AtomicRetryAuthority:
    """Test authority modeling one durable proof reservation and child insert transaction."""

    def __init__(self, reservations: DurableCas, resolver: ProofResolver) -> None:
        self._reservations = reservations
        self._resolver = resolver
        self.children: dict[UUID, ExecutionAttempt] = {}
        self._lock = threading.Lock()

    def resolve_reserve_and_create(
        self, request: RetryAttemptCreationRequest
    ) -> RetryAttemptCreationOutcome:
        with self._lock:
            digest = reconciliation_proof_digest(request.proof)
            if (
                self._resolver.resolve_anchor(reconciliation_proof_id(request.proof))
                != digest
                or request.command.reconciliation_proof_sha256 != digest
                or request.child.execution_id != request.command.execution_id
                or request.child.run_id != request.command.run_id
                or request.child.predecessor_execution_id
                != request.predecessor.execution_id
                or request.child.idempotency_key != request.command.idempotency_key
                or request.child.reconciliation_proof_sha256 != digest
            ):
                return "binding_mismatch"
            if request.child.execution_id in self.children:
                return "child_conflict"
            reservation = DurableCompareAndSetRequest(
                key=(
                    "reconciliation-proof-consumed:"
                    f"{reconciliation_proof_id(request.proof)}:{digest}"
                ),
                expected=None,
                value=str(request.child.execution_id),
            )
            if not self._reservations.compare_and_set(reservation):
                return "proof_consumed"
            self.children[request.child.execution_id] = request.child
            return "created"


@final
class SqliteRetryAuthority:
    """SQLite transaction fixture for durable proof reservation plus child creation."""

    def __init__(self, path: Path, resolver: ProofResolver) -> None:
        self._path = path
        self._resolver = resolver
        with sqlite3.connect(path) as connection:
            _ = connection.execute(
                "CREATE TABLE IF NOT EXISTS retry_children "
                "(execution_id TEXT PRIMARY KEY, payload TEXT NOT NULL)"
            )
            _ = connection.execute(
                "CREATE TABLE IF NOT EXISTS reservations "
                "(key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )

    def resolve_reserve_and_create(
        self, request: RetryAttemptCreationRequest
    ) -> RetryAttemptCreationOutcome:
        digest = reconciliation_proof_digest(request.proof)
        if (
            self._resolver.resolve_anchor(reconciliation_proof_id(request.proof))
            != digest
            or request.command.reconciliation_proof_sha256 != digest
            or request.child.execution_id != request.command.execution_id
            or request.child.run_id != request.command.run_id
            or request.child.predecessor_execution_id
            != request.predecessor.execution_id
            or request.child.idempotency_key != request.command.idempotency_key
            or request.child.reconciliation_proof_sha256 != digest
        ):
            return "binding_mismatch"
        with sqlite3.connect(self._path, isolation_level="IMMEDIATE") as connection:
            existing = cast(
                "tuple[int] | None",
                connection.execute(
                    "SELECT 1 FROM retry_children WHERE execution_id = ?",
                    (str(request.child.execution_id),),
                ).fetchone(),
            )
            if existing is not None:
                return "child_conflict"
            reserved = connection.execute(
                "INSERT OR IGNORE INTO reservations(key, value) VALUES (?, ?)",
                (
                    "reconciliation-proof-consumed:"
                    f"{reconciliation_proof_id(request.proof)}:{digest}",
                    str(request.child.execution_id),
                ),
            )
            if reserved.rowcount != 1:
                return "proof_consumed"
            created = connection.execute(
                "INSERT INTO retry_children(execution_id, payload) VALUES (?, ?)",
                (str(request.child.execution_id), request.child.model_dump_json()),
            )
            if created.rowcount != 1:
                connection.rollback()
                return "child_conflict"
            return "created"

    def child(self, execution_id: UUID) -> ExecutionAttempt | None:
        with sqlite3.connect(self._path) as connection:
            row = cast(
                "tuple[str] | None",
                connection.execute(
                    "SELECT payload FROM retry_children WHERE execution_id = ?",
                    (str(execution_id),),
                ).fetchone(),
            )
        if row is None:
            return None
        payload = row[0]
        return ExecutionAttempt.model_validate_json(payload)


def identifier(number: int) -> UUID:
    return UUID(f"018f0000-0000-7{number:03x}-8000-000000000000")


def attempt() -> ExecutionAttempt:
    return ExecutionAttempt(
        execution_id=identifier(1),
        run_id=identifier(2),
        deadline=NOW + timedelta(minutes=1),
    )


def stream_digest(
    records: tuple[TombstoneRecord, ...] | tuple[HoldRecord, ...],
) -> str:
    return hashlib.sha256(
        json.dumps(
            [record.model_dump(mode="json") for record in records],
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def activated_governance(
    tombstones: tuple[TombstoneRecord, ...],
    holds: tuple[HoldRecord, ...],
) -> RestoreLifecycle:
    manifest = RestoreGovernanceManifest(
        backup_sha256=DIGEST,
        source_governance_root_sha256=DIGEST,
        tombstone_high_watermark=len(tombstones),
        hold_high_watermark=len(holds),
        tombstone_stream_sha256=stream_digest(tombstones),
        hold_stream_sha256=stream_digest(holds),
        required_deletion_systems=("store",),
        deletion_receipt_roots=(DIGEST,),
        restore_epoch=2,
        quarantined_transient_records=True,
        invariant_report_sha256=DIGEST,
    )
    lifecycle = RestoreLifecycle(
        restore_epoch=2,
        phase="validating",
        backup_digest_verified=True,
        backup_sha256=DIGEST,
        verified_backup_sha256=DIGEST,
        tombstone_high_watermark=len(tombstones),
        replayed_tombstone_high_watermark=len(tombstones),
        hold_high_watermark=len(holds),
        replayed_hold_high_watermark=len(holds),
        tombstone_stream_sha256=stream_digest(tombstones),
        hold_stream_sha256=stream_digest(holds),
        required_deletion_systems=("store",),
        deletion_receipt_systems=("store",),
        quarantined_transient_records=True,
        invariant_report_sha256=DIGEST,
        governance_manifest=manifest,
        governance_manifest_anchor_sha256=restore_manifest_digest(manifest),
    )
    ready = advance_restore_authoritatively(
        lifecycle, "ready", RestoreResolver(manifest)
    )
    return advance_restore_authoritatively(
        ready, "activated", RestoreResolver(manifest)
    )


def governed_lifecycle() -> RestoreLifecycle:
    """Build a valid pre-activation restore against an external manifest anchor."""
    manifest = RestoreGovernanceManifest(
        backup_sha256=DIGEST,
        source_governance_root_sha256=DIGEST,
        tombstone_high_watermark=1,
        hold_high_watermark=1,
        tombstone_stream_sha256=DIGEST,
        hold_stream_sha256=DIGEST,
        required_deletion_systems=("store",),
        deletion_receipt_roots=(DIGEST,),
        restore_epoch=2,
        quarantined_transient_records=True,
        invariant_report_sha256=DIGEST,
    )
    return RestoreLifecycle(
        restore_epoch=2,
        backup_digest_verified=True,
        backup_sha256=DIGEST,
        verified_backup_sha256=DIGEST,
        tombstone_high_watermark=1,
        replayed_tombstone_high_watermark=1,
        hold_high_watermark=1,
        replayed_hold_high_watermark=1,
        required_deletion_systems=("store",),
        deletion_receipt_systems=("store",),
        quarantined_transient_records=True,
        invariant_report_sha256=DIGEST,
        tombstone_stream_sha256=DIGEST,
        hold_stream_sha256=DIGEST,
        governance_manifest=manifest,
        governance_manifest_anchor_sha256=restore_manifest_digest(manifest),
    )


class RestoreResolver:
    """Independent test authority for a fixed restore manifest."""

    manifest: RestoreGovernanceManifest

    def __init__(self, manifest: RestoreGovernanceManifest) -> None:
        self.manifest = manifest

    def resolve_manifest_anchor(
        self, backup_sha256: str, restore_epoch: int
    ) -> str | None:
        if (
            backup_sha256 != self.manifest.backup_sha256
            or restore_epoch != self.manifest.restore_epoch
        ):
            return None
        return restore_manifest_digest(self.manifest)

    def resolve_source_governance_root(
        self, backup_sha256: str, restore_epoch: int
    ) -> str | None:
        if (
            backup_sha256 != self.manifest.backup_sha256
            or restore_epoch != self.manifest.restore_epoch
        ):
            return None
        return self.manifest.source_governance_root_sha256

    def resolve_tombstone_stream_root(
        self, backup_sha256: str, restore_epoch: int
    ) -> str | None:
        if (
            backup_sha256 != self.manifest.backup_sha256
            or restore_epoch != self.manifest.restore_epoch
        ):
            return None
        return self.manifest.tombstone_stream_sha256

    def resolve_hold_stream_root(
        self, backup_sha256: str, restore_epoch: int
    ) -> str | None:
        if (
            backup_sha256 != self.manifest.backup_sha256
            or restore_epoch != self.manifest.restore_epoch
        ):
            return None
        return self.manifest.hold_stream_sha256

    def resolve_deletion_receipt_root(
        self, system: str, backup_sha256: str, restore_epoch: int
    ) -> str | None:
        if (
            backup_sha256 != self.manifest.backup_sha256
            or restore_epoch != self.manifest.restore_epoch
        ):
            return None
        try:
            return self.manifest.deletion_receipt_roots[
                self.manifest.required_deletion_systems.index(system)
            ]
        except ValueError:
            return None

    def resolve_activation_receipt(
        self, backup_sha256: str, restore_epoch: int, phase: str
    ) -> str | None:
        if (
            backup_sha256 != self.manifest.backup_sha256
            or restore_epoch != self.manifest.restore_epoch
            or phase not in {"ready", "activated"}
        ):
            return None
        return hashlib.sha256(
            f"{restore_manifest_digest(self.manifest)}:{phase}".encode()
        ).hexdigest()


def resolver_for(lifecycle: RestoreLifecycle) -> RestoreResolver:
    manifest = lifecycle.governance_manifest
    assert manifest is not None
    return RestoreResolver(manifest)


@final
class MissingActivationReceiptResolver(RestoreResolver):
    """Returns no phase receipt while preserving the other external roots."""

    @override
    def resolve_activation_receipt(
        self, backup_sha256: str, restore_epoch: int, phase: str
    ) -> str | None:
        del backup_sha256, restore_epoch, phase
        return None


@final
class TamperedTombstoneRootResolver(RestoreResolver):
    """Independent resolver fixture returning a mismatched canonical tombstone root."""

    @override
    def resolve_tombstone_stream_root(
        self, backup_sha256: str, restore_epoch: int
    ) -> str | None:
        if (
            backup_sha256 != self.manifest.backup_sha256
            or restore_epoch != self.manifest.restore_epoch
        ):
            return None
        return "b" * 64


def test_authoritative_attempt_cas_rejects_concurrent_and_stale_epoch_effects() -> None:
    original = attempt()
    authority = AttemptCas(original)
    claimed = claim_attempt_durable(
        authority,
        ClaimAttemptRequest(
            attempt=original,
            lease_owner="worker-a",
            expected_token=1,
            occurred_at=NOW,
            deadline=NOW + timedelta(seconds=10),
        ),
    )
    with pytest.raises(RecoveryProtocolError, match="STALE_ATTEMPT_TOKEN"):
        _ = claim_attempt_durable(
            authority,
            ClaimAttemptRequest(
                attempt=original,
                lease_owner="worker-b",
                expected_token=1,
                occurred_at=NOW,
                deadline=NOW + timedelta(seconds=10),
            ),
        )
    stale_epoch = claimed.model_copy(
        update={"restore_epoch": claimed.restore_epoch + 1}
    )
    with pytest.raises(RecoveryProtocolError, match="STALE_ATTEMPT_TOKEN"):
        _ = complete_attempt_durable(
            authority,
            CompleteAttemptRequest(
                attempt=stale_epoch,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                outcome="failed",
            ),
        )


def test_authoritative_attempt_cas_fences_complete_identity_and_lineage() -> None:
    current = ExecutionAttempt(
        execution_id=identifier(70),
        run_id=identifier(71),
        deadline=NOW + timedelta(minutes=1),
        predecessor_execution_id=identifier(72),
        idempotency_key="retry-70",
        reconciliation_proof_sha256=DIGEST,
    )
    authority = AttemptCas(current)
    forged_expected_states = (
        current.model_copy(update={"run_id": identifier(73)}),
        current.model_copy(update={"predecessor_execution_id": identifier(73)}),
    )
    for forged_expected in forged_expected_states:
        assert (
            authority.compare_and_set_at_authoritative_time(
                AttemptCompareAndSetRequest(expected=forged_expected),
                lambda stored, _: stored,
            )
            is None
        )
    assert authority.current == current


def test_authoritative_attempt_cas_fences_effect_state_and_lease_deadline() -> None:
    claimed = claim_attempt(attempt(), "worker-a", 1, NOW, NOW + timedelta(seconds=10))

    effect_authority = AttemptCas(claimed)
    started = record_effect_durable(
        effect_authority,
        RecordEffectRequest(
            attempt=claimed,
            lease_owner="worker-a",
            expected_token=1,
            occurred_at=NOW,
            effect_state="started",
        ),
    )
    with pytest.raises(RecoveryProtocolError, match="STALE_ATTEMPT_TOKEN"):
        _ = heartbeat_attempt_durable(
            effect_authority,
            HeartbeatAttemptRequest(
                attempt=claimed,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                deadline=NOW + timedelta(seconds=20),
            ),
        )
    assert effect_authority.current == started
    assert effect_authority.current.effect_state == "started"

    deadline_authority = AttemptCas(claimed)
    renewed = heartbeat_attempt_durable(
        deadline_authority,
        HeartbeatAttemptRequest(
            attempt=claimed,
            lease_owner="worker-a",
            expected_token=1,
            occurred_at=NOW,
            deadline=NOW + timedelta(seconds=20),
        ),
    )
    with pytest.raises(RecoveryProtocolError, match="STALE_ATTEMPT_TOKEN"):
        _ = record_effect_durable(
            deadline_authority,
            RecordEffectRequest(
                attempt=claimed,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                effect_state="started",
            ),
        )
    assert deadline_authority.current == renewed
    assert deadline_authority.current.deadline == NOW + timedelta(seconds=20)

    started_for_completion = record_effect(claimed, "worker-a", 1, NOW, "started")
    committed = record_effect(started_for_completion, "worker-a", 1, NOW, "committed")
    completion_authority = AttemptCas(committed)
    completion_renewed = heartbeat_attempt_durable(
        completion_authority,
        HeartbeatAttemptRequest(
            attempt=committed,
            lease_owner="worker-a",
            expected_token=1,
            occurred_at=NOW,
            deadline=NOW + timedelta(seconds=20),
        ),
    )
    with pytest.raises(RecoveryProtocolError, match="STALE_ATTEMPT_TOKEN"):
        _ = complete_attempt_durable(
            completion_authority,
            CompleteAttemptRequest(
                attempt=committed,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                outcome="completed",
            ),
        )
    assert completion_authority.current == completion_renewed
    assert completion_authority.current.status == "claimed"
    assert completion_authority.current.effect_state == "committed"


def test_downstream_effect_action_is_fenced_by_authoritative_cas() -> None:
    claimed = claim_attempt(attempt(), "worker-a", 1, NOW, NOW + timedelta(seconds=10))
    authority = AttemptCas(claimed)
    executed: list[str] = []
    result = perform_downstream_effect(
        authority,
        RecordEffectRequest(
            attempt=claimed,
            lease_owner="worker-a",
            expected_token=1,
            occurred_at=NOW,
            effect_state="started",
        ),
        lambda: executed.append("effect"),
    )
    assert result.effect_state == "started"
    assert executed == ["effect"]
    stale = claimed.model_copy(update={"deadline": NOW + timedelta(seconds=20)})
    with pytest.raises(RecoveryProtocolError, match="STALE_ATTEMPT_TOKEN"):
        _ = perform_downstream_effect(
            authority,
            RecordEffectRequest(
                attempt=stale,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                effect_state="started",
            ),
            lambda: executed.append("stale-effect"),
        )
    assert executed == ["effect"]


def test_downstream_effect_failure_consumes_the_fence_before_action() -> None:
    claimed = claim_attempt(attempt(), "worker-a", 1, NOW, NOW + timedelta(seconds=10))
    authority = AttemptCas(claimed)

    def fail_after_effect_started() -> None:
        message = "downstream unavailable"
        raise RuntimeError(message)

    with pytest.raises(RuntimeError, match="downstream unavailable"):
        _ = perform_downstream_effect(
            authority,
            RecordEffectRequest(
                attempt=claimed,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                effect_state="started",
            ),
            fail_after_effect_started,
        )

    assert authority.current.effect_state == "started"
    with pytest.raises(RecoveryProtocolError, match="STALE_ATTEMPT_TOKEN"):
        _ = perform_downstream_effect(
            authority,
            RecordEffectRequest(
                attempt=claimed,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                effect_state="started",
            ),
            lambda: None,
        )


def test_concurrent_downstream_effect_has_one_fenced_winner() -> None:
    claimed = claim_attempt(attempt(), "worker-a", 1, NOW, NOW + timedelta(seconds=10))
    authority = AttemptCas(claimed)
    barrier = threading.Barrier(2)
    executed: list[str] = []
    failures: list[RecoveryProtocolError] = []

    def invoke(label: str) -> None:
        _ = barrier.wait()
        try:
            _ = perform_downstream_effect(
                authority,
                RecordEffectRequest(
                    attempt=claimed,
                    lease_owner="worker-a",
                    expected_token=1,
                    occurred_at=NOW,
                    effect_state="started",
                ),
                lambda: executed.append(label),
            )
        except RecoveryProtocolError as error:
            failures.append(error)

    threads = (
        threading.Thread(target=invoke, args=("first",)),
        threading.Thread(target=invoke, args=("second",)),
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert len(executed) == 1
    assert len(failures) == 1
    assert failures[0].code == "STALE_ATTEMPT_TOKEN"


def test_authoritative_clock_rejects_backdated_expired_lease_transitions() -> None:
    claimed = claim_attempt(attempt(), "worker-a", 1, NOW, NOW + timedelta(seconds=10))
    expired_authority = AttemptCas(claimed, now=NOW + timedelta(seconds=10))
    with pytest.raises(RecoveryProtocolError, match="LEASE_EXPIRED"):
        _ = heartbeat_attempt_durable(
            expired_authority,
            HeartbeatAttemptRequest(
                attempt=claimed,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                deadline=NOW + timedelta(minutes=1),
            ),
        )
    with pytest.raises(RecoveryProtocolError, match="LEASE_EXPIRED"):
        _ = record_effect_durable(
            expired_authority,
            RecordEffectRequest(
                attempt=claimed,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                effect_state="started",
            ),
        )
    with pytest.raises(RecoveryProtocolError, match="LEASE_EXPIRED"):
        _ = complete_attempt_durable(
            expired_authority,
            CompleteAttemptRequest(
                attempt=claimed,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                outcome="failed",
            ),
        )
    executed: list[str] = []
    with pytest.raises(RecoveryProtocolError, match="LEASE_EXPIRED"):
        _ = perform_downstream_effect(
            expired_authority,
            RecordEffectRequest(
                attempt=claimed,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                effect_state="started",
            ),
            lambda: executed.append("unsafe"),
        )
    assert not executed
    queued = attempt()
    with pytest.raises(RecoveryProtocolError, match="INVALID_LEASE_DEADLINE"):
        _ = claim_attempt_durable(
            AttemptCas(queued, now=NOW + timedelta(seconds=10)),
            ClaimAttemptRequest(
                attempt=queued,
                lease_owner="worker-a",
                expected_token=1,
                occurred_at=NOW,
                deadline=NOW + timedelta(seconds=5),
            ),
        )


def test_crash_before_effect_reacquires_with_a_fresh_fencing_token() -> None:
    claimed = claim_attempt(attempt(), "worker-a", 1, NOW, NOW + timedelta(seconds=10))
    reacquired = claim_attempt(
        claimed,
        "worker-b",
        1,
        NOW + timedelta(seconds=10),
        NOW + timedelta(minutes=1),
    )
    assert reacquired.attempt_token == 2
    with pytest.raises(RecoveryProtocolError, match="STALE_ATTEMPT_TOKEN"):
        _ = record_effect(reacquired, "worker-b", 1, NOW, "started")


def test_crash_after_effect_requires_reconciliation_and_never_replays() -> None:
    claimed = claim_attempt(attempt(), "worker-a", 1, NOW, NOW + timedelta(seconds=10))
    started = record_effect(claimed, "worker-a", 1, NOW, "started")
    recovered = claim_attempt(
        started,
        "worker-b",
        1,
        NOW + timedelta(seconds=10),
        NOW + timedelta(minutes=1),
    )
    assert recovered.status == "reconciliation_required"
    with pytest.raises(RecoveryProtocolError, match="ATTEMPT_NOT_CLAIMABLE"):
        _ = claim_attempt(
            recovered,
            "worker-c",
            2,
            NOW + timedelta(minutes=2),
            NOW + timedelta(minutes=3),
        )


def test_expired_or_wrong_owner_cannot_mutate_or_complete() -> None:
    claimed = claim_attempt(attempt(), "worker-a", 1, NOW, NOW + timedelta(seconds=10))
    with pytest.raises(RecoveryProtocolError, match="LEASE_OWNER_MISMATCH"):
        _ = record_effect(claimed, "worker-b", 1, NOW, "started")
    with pytest.raises(RecoveryProtocolError, match="LEASE_EXPIRED"):
        _ = complete_attempt(
            claimed, "worker-a", 1, NOW + timedelta(seconds=10), "failed"
        )


def test_ambiguous_effect_is_persisted_only_as_reconciliation_required() -> None:
    sealed = ExecutionAttempt(
        execution_id=identifier(1),
        run_id=identifier(2),
        deadline=NOW + timedelta(minutes=1),
        effect_state="ambiguous",
        status="reconciliation_required",
    )
    with pytest.raises(RecoveryProtocolError, match="ATTEMPT_NOT_CLAIMABLE"):
        _ = claim_attempt(sealed, "worker-a", 1, NOW, NOW + timedelta(seconds=10))


def test_retry_requires_independent_proof_and_consumes_it_once() -> None:
    requiring_reconciliation = attempt().model_copy(
        update={"effect_state": "not_started", "status": "reconciliation_required"}
    )
    proof = ReconciliationProof(
        predecessor_run_id=requiring_reconciliation.run_id,
        predecessor_execution_id=requiring_reconciliation.execution_id,
        predecessor_attempt_token=requiring_reconciliation.attempt_token,
        predecessor_effect_state="not_started",
        reconciliation_root_sha256=DIGEST,
    )
    proof_anchor = reconciliation_proof_digest(proof)
    durable_store = DurableCas()
    proof_resolver = ProofResolver({reconciliation_proof_id(proof): proof_anchor})
    proof_store = ReconciliationProofStore(proof_resolver)
    retry_authority = AtomicRetryAuthority(durable_store, proof_resolver)
    reconciled = reconcile_no_effect(requiring_reconciliation, proof, proof_store)
    command = RetryCommand(
        run_id=identifier(6),
        execution_id=identifier(7),
        deadline=NOW + timedelta(minutes=2),
        reconciliation_proof_sha256=proof_anchor,
        idempotency_key="retry-key",
    )

    retried = retry_attempt(reconciled, command, proof, retry_authority)

    assert retried.execution_id == command.execution_id
    assert retried.run_id == command.run_id
    assert retried.predecessor_execution_id == reconciled.execution_id
    assert retried.idempotency_key == command.idempotency_key
    assert retried.reconciliation_proof_sha256 == command.reconciliation_proof_sha256
    with pytest.raises(RecoveryProtocolError, match="RETRY_ID_REUSE"):
        _ = retry_attempt(
            reconciled,
            command,
            proof,
            retry_authority,
        )
    conflicting_authority = AtomicRetryAuthority(DurableCas(), proof_resolver)
    conflicting_authority.children[command.execution_id] = retried
    with pytest.raises(RecoveryProtocolError, match="RETRY_ID_REUSE"):
        _ = retry_attempt(reconciled, command, proof, conflicting_authority)


@pytest.mark.parametrize(
    ("status", "effect_state", "lease_owner"),
    [
        ("claimed", "not_started", "worker-a"),
        ("claimed", "started", "worker-a"),
        ("completed", "committed", None),
        ("failed", "not_started", None),
        ("reconciled_no_effect", "not_started", None),
        ("reconciliation_required", "not_started", None),
        ("reconciliation_required", "ambiguous", None),
    ],
)
def test_retry_lineage_is_valid_for_each_reachable_child_state(
    status: AttemptStatus,
    effect_state: EffectState,
    lease_owner: str | None,
) -> None:
    child = ExecutionAttempt(
        execution_id=identifier(91),
        run_id=identifier(92),
        deadline=NOW + timedelta(minutes=2),
        status=status,
        effect_state=effect_state,
        lease_owner=lease_owner,
        predecessor_execution_id=identifier(90),
        idempotency_key="retry-lineage",
        reconciliation_proof_sha256=DIGEST,
    )
    assert child.status == status


def test_retry_child_can_claim_effect_and_complete_durably() -> None:
    predecessor = attempt().model_copy(
        update={"effect_state": "not_started", "status": "reconciliation_required"}
    )
    proof = ReconciliationProof(
        predecessor_run_id=predecessor.run_id,
        predecessor_execution_id=predecessor.execution_id,
        predecessor_attempt_token=predecessor.attempt_token,
        predecessor_effect_state="not_started",
        reconciliation_root_sha256=DIGEST,
    )
    proof_digest = reconciliation_proof_digest(proof)
    resolver = ProofResolver({reconciliation_proof_id(proof): proof_digest})
    sealed = reconcile_no_effect(predecessor, proof, ReconciliationProofStore(resolver))
    child = retry_attempt(
        sealed,
        RetryCommand(
            run_id=identifier(93),
            execution_id=identifier(94),
            deadline=NOW + timedelta(minutes=2),
            reconciliation_proof_sha256=proof_digest,
            idempotency_key="retry-durable",
        ),
        proof,
        AtomicRetryAuthority(DurableCas(), resolver),
    )
    authority = AttemptCas(child)
    claimed = claim_attempt_durable(
        authority,
        ClaimAttemptRequest(
            attempt=child,
            lease_owner="worker-a",
            expected_token=1,
            occurred_at=NOW,
            deadline=NOW + timedelta(minutes=1),
        ),
    )
    started = record_effect_durable(
        authority,
        RecordEffectRequest(
            attempt=claimed,
            lease_owner="worker-a",
            expected_token=claimed.attempt_token,
            occurred_at=NOW,
            effect_state="started",
        ),
    )
    committed = record_effect_durable(
        authority,
        RecordEffectRequest(
            attempt=started,
            lease_owner="worker-a",
            expected_token=started.attempt_token,
            occurred_at=NOW,
            effect_state="committed",
        ),
    )
    completed = complete_attempt_durable(
        authority,
        CompleteAttemptRequest(
            attempt=committed,
            lease_owner="worker-a",
            expected_token=committed.attempt_token,
            occurred_at=NOW,
            outcome="completed",
        ),
    )
    assert completed.status == "completed"
    assert completed.predecessor_execution_id == predecessor.execution_id


def test_retry_authority_rejects_tampered_proof_without_creating_child() -> None:
    pending = attempt().model_copy(
        update={"effect_state": "not_started", "status": "reconciliation_required"}
    )
    proof = ReconciliationProof(
        predecessor_run_id=pending.run_id,
        predecessor_execution_id=pending.execution_id,
        predecessor_attempt_token=pending.attempt_token,
        predecessor_effect_state="not_started",
        reconciliation_root_sha256=DIGEST,
    )
    digest = reconciliation_proof_digest(proof)
    reservations = DurableCas()
    resolver = ProofResolver({reconciliation_proof_id(proof): digest})
    proof_store = ReconciliationProofStore(resolver)
    sealed = reconcile_no_effect(pending, proof, proof_store)
    authority = AtomicRetryAuthority(reservations, resolver)
    with pytest.raises(RecoveryProtocolError, match="RECONCILIATION_PROOF_MISMATCH"):
        _ = retry_attempt(
            sealed,
            RetryCommand(
                run_id=identifier(80),
                execution_id=identifier(81),
                deadline=NOW + timedelta(minutes=2),
                reconciliation_proof_sha256="b" * 64,
                idempotency_key="tampered-proof",
            ),
            proof,
            authority,
        )
    assert not authority.children


def test_sqlite_proof_consumption_is_restart_persistent_and_single_winner(
    tmp_path: Path,
) -> None:
    pending = ExecutionAttempt(
        execution_id=identifier(30),
        run_id=identifier(31),
        deadline=NOW + timedelta(minutes=1),
        effect_state="not_started",
        status="reconciliation_required",
    )
    proof = ReconciliationProof(
        predecessor_run_id=pending.run_id,
        predecessor_execution_id=pending.execution_id,
        predecessor_attempt_token=pending.attempt_token,
        predecessor_effect_state="not_started",
        reconciliation_root_sha256=DIGEST,
    )
    anchor = reconciliation_proof_digest(proof)
    proof_resolver = ProofResolver({reconciliation_proof_id(proof): anchor})
    proof_store = ReconciliationProofStore(proof_resolver)
    retry_authority = SqliteRetryAuthority(tmp_path / "proofs.sqlite", proof_resolver)
    sealed = reconcile_no_effect(pending, proof, proof_store)
    successes: list[UUID] = []
    failures: list[RecoveryProtocolError] = []
    lock = threading.Lock()

    def consume(child: UUID) -> None:
        try:
            _ = retry_attempt(
                sealed,
                RetryCommand(
                    run_id=identifier(32 + child.int % 2),
                    execution_id=child,
                    deadline=NOW + timedelta(minutes=2),
                    reconciliation_proof_sha256=anchor,
                    idempotency_key=f"retry-{child}",
                ),
                proof,
                retry_authority,
            )
            with lock:
                successes.append(child)
        except RecoveryProtocolError as error:
            with lock:
                failures.append(error)

    children = (identifier(40), identifier(41))
    threads = tuple(
        threading.Thread(target=consume, args=(child,)) for child in children
    )
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(successes) == 1
    assert len(failures) == 1
    assert retry_authority.child(successes[0]) is not None
    reopened = SqliteRetryAuthority(tmp_path / "proofs.sqlite", proof_resolver)
    assert reopened.child(successes[0]) is not None
    with pytest.raises(RecoveryProtocolError, match="RECONCILIATION_PROOF_CONSUMED"):
        _ = retry_attempt(
            sealed,
            RetryCommand(
                run_id=identifier(50),
                execution_id=identifier(51),
                deadline=NOW + timedelta(minutes=2),
                reconciliation_proof_sha256=anchor,
                idempotency_key="after-restart",
            ),
            proof,
            reopened,
        )


def test_independent_proof_resolver_rejects_caller_forged_anchor() -> None:
    pending = ExecutionAttempt(
        execution_id=identifier(30),
        run_id=identifier(31),
        deadline=NOW + timedelta(minutes=1),
        status="reconciliation_required",
    )
    proof = ReconciliationProof(
        predecessor_run_id=pending.run_id,
        predecessor_execution_id=pending.execution_id,
        predecessor_attempt_token=pending.attempt_token,
        predecessor_effect_state="not_started",
        reconciliation_root_sha256=DIGEST,
    )
    with pytest.raises(RecoveryProtocolError, match="RECONCILIATION_PROOF_MISMATCH"):
        _ = reconcile_no_effect(
            pending,
            proof,
            ReconciliationProofStore(
                ProofResolver({reconciliation_proof_id(proof): "b" * 64}),
            ),
        )


def test_attempt_ingestion_rejects_invalid_authority_and_partial_lineage() -> None:
    with pytest.raises(ValueError, match="ATTEMPT_INVALID_STATE"):
        _ = ExecutionAttempt(
            execution_id=identifier(9),
            run_id=identifier(10),
            deadline=NOW,
            status="claimed",
        )
    with pytest.raises(ValueError, match="ATTEMPT_INVALID_STATE"):
        _ = ExecutionAttempt(
            execution_id=identifier(11),
            run_id=identifier(12),
            deadline=NOW,
            predecessor_execution_id=identifier(1),
        )


@pytest.mark.parametrize(
    ("status", "effect_state", "has_lineage"),
    tuple(
        (status, effect_state, has_lineage)
        for status, effect_state, has_lineage in product(
            (
                "queued",
                "claimed",
                "completed",
                "failed",
                "reconciled_no_effect",
                "reconciliation_required",
            ),
            ("not_started", "started", "ambiguous", "committed"),
            (False, True),
        )
    ),
)
def test_execution_attempt_status_effect_and_lineage_matrix(
    status: AttemptStatus, effect_state: EffectState, has_lineage: bool
) -> None:
    payload: dict[str, object] = {
        "execution_id": identifier(60),
        "run_id": identifier(61),
        "deadline": NOW,
        "status": status,
        "effect_state": effect_state,
        "lease_owner": "worker" if status == "claimed" else None,
    }
    if has_lineage:
        payload.update(
            {
                "predecessor_execution_id": identifier(62),
                "idempotency_key": "retry",
                "reconciliation_proof_sha256": DIGEST,
            }
        )
    valid = (
        (status == "queued" and effect_state == "not_started")
        or (
            status == "claimed"
            and effect_state in ("not_started", "started", "committed")
        )
        or (status == "completed" and effect_state == "committed")
        or (
            status in ("failed", "reconciled_no_effect")
            and effect_state == "not_started"
        )
        or status == "reconciliation_required"
    )
    if valid:
        _ = ExecutionAttempt.model_validate(payload)
    else:
        with pytest.raises(ValueError, match="ATTEMPT_INVALID_STATE"):
            _ = ExecutionAttempt.model_validate(payload)


def test_execution_attempt_rejects_self_referential_lineage_in_every_state() -> None:
    states: tuple[tuple[AttemptStatus, EffectState], ...] = (
        ("queued", "not_started"),
        ("claimed", "started"),
        ("completed", "committed"),
        ("failed", "not_started"),
        ("reconciled_no_effect", "not_started"),
        ("reconciliation_required", "ambiguous"),
    )
    for status, effect_state in states:
        with pytest.raises(ValueError, match="ATTEMPT_INVALID_STATE"):
            _ = ExecutionAttempt(
                execution_id=identifier(63),
                run_id=identifier(64),
                deadline=NOW,
                status=status,
                effect_state=effect_state,
                lease_owner="worker" if status == "claimed" else None,
                predecessor_execution_id=identifier(63),
                idempotency_key="self",
                reconciliation_proof_sha256=DIGEST,
            )


def test_activation_requires_a_complete_governance_snapshot() -> None:
    with pytest.raises(RecoveryProtocolError, match="RESTORE_MANIFEST_ANCHOR_MISMATCH"):
        _ = RestoreLifecycle(restore_epoch=1, phase="activated")


def test_pre_tombstone_backup_blocks_visibility_and_released_hold_allows_purge() -> (
    None
):
    tombstone = TombstoneRecord(
        subject_id=identifier(3),
        sequence=1,
        recorded_at=NOW,
        digest=DIGEST,
    )
    active_hold = HoldRecord(
        subject_id=identifier(3),
        sequence=1,
        active=True,
        recorded_at=NOW,
        digest=DIGEST,
    )
    released_hold = HoldRecord(
        subject_id=identifier(3),
        sequence=2,
        active=False,
        recorded_at=NOW,
        digest=DIGEST,
    )
    active_governance = activated_governance((tombstone,), (active_hold,))
    released_governance = activated_governance(
        (tombstone,), (active_hold, released_hold)
    )
    active_resolver = resolver_for(active_governance)
    released_resolver = resolver_for(released_governance)
    assert not normal_access_allowed((tombstone,), identifier(3))
    assert not physical_purge_allowed(
        (tombstone,),
        (active_hold,),
        identifier(3),
        active_governance,
        active_resolver,
    )
    assert physical_purge_allowed(
        (tombstone,),
        (active_hold, released_hold),
        identifier(3),
        released_governance,
        released_resolver,
    )
    assert not physical_purge_allowed(
        (tombstone,),
        (released_hold, active_hold),
        identifier(3),
        released_governance,
        released_resolver,
    )
    assert not physical_purge_allowed(
        (tombstone,),
        (),
        identifier(3),
        released_governance,
        released_resolver,
    )
    assert not physical_purge_allowed(
        (tombstone, tombstone),
        (active_hold,),
        identifier(3),
        active_governance,
        active_resolver,
    )
    future_tombstone = TombstoneRecord(
        subject_id=identifier(3),
        sequence=2,
        recorded_at=NOW,
        digest="b" * 64,
    )
    assert not physical_purge_allowed(
        (tombstone, future_tombstone),
        (active_hold,),
        identifier(3),
        active_governance,
        active_resolver,
    )
    assert not physical_purge_allowed(
        (tombstone,),
        (active_hold,),
        identifier(3),
        active_governance.model_copy(update={"tombstone_stream_sha256": "b" * 64}),
        active_resolver,
    )


def test_authoritative_activation_round_trips_and_forgery_cannot_purge() -> None:
    tombstone = TombstoneRecord(
        subject_id=identifier(3), sequence=1, recorded_at=NOW, digest=DIGEST
    )
    released_hold = HoldRecord(
        subject_id=identifier(3),
        sequence=1,
        active=False,
        recorded_at=NOW,
        digest=DIGEST,
    )
    activated = activated_governance((tombstone,), (released_hold,))
    resolver = resolver_for(activated)
    restored = RestoreLifecycle.model_validate_json(activated.model_dump_json())
    assert restored == activated
    assert physical_purge_allowed(
        (tombstone,), (released_hold,), identifier(3), restored, resolver
    )

    lifecycle = governed_lifecycle()
    validating = advance_restore(
        advance_restore(lifecycle, "replaying_governance"), "validating"
    )
    forged = validating.model_copy(update={"phase": "activated"})
    assert not physical_purge_allowed(
        (tombstone,), (released_hold,), identifier(3), forged, resolver
    )
    action: list[str] = []
    assert not perform_physical_purge_from_store(
        SnapshotStore((GovernanceSnapshot(1, (tombstone,), (released_hold,)),)),
        identifier(3),
        forged,
        resolver,
        lambda: action.append("purged"),
    )
    assert action == []

    missing_receipt_resolver = MissingActivationReceiptResolver(resolver.manifest)
    assert not physical_purge_allowed(
        (tombstone,),
        (released_hold,),
        identifier(3),
        activated,
        missing_receipt_resolver,
    )


def test_restore_governance_replays_to_ready_then_activated() -> None:
    lifecycle = governed_lifecycle()
    manifest = lifecycle.governance_manifest
    assert manifest is not None
    resolver = RestoreResolver(manifest)
    validating = advance_restore(
        advance_restore(lifecycle, "replaying_governance"), "validating"
    )
    ready = advance_restore_authoritatively(validating, "ready", resolver)
    assert (
        advance_restore_authoritatively(ready, "activated", resolver).phase
        == "activated"
    )
    with pytest.raises(RecoveryProtocolError, match="RESTORE_MANIFEST_ANCHOR_MISMATCH"):
        _ = advance_restore(validating, "ready")


def test_authoritative_activation_rejects_tampered_canonical_tombstone_root() -> None:
    lifecycle = governed_lifecycle()
    manifest = lifecycle.governance_manifest
    assert manifest is not None
    resolver = TamperedTombstoneRootResolver(manifest)
    validating = advance_restore(
        advance_restore(lifecycle, "replaying_governance"), "validating"
    )
    with pytest.raises(RecoveryProtocolError, match="TOMBSTONE_SNAPSHOT_MISMATCH"):
        _ = advance_restore_authoritatively(validating, "ready", resolver)


@pytest.mark.parametrize(
    "changes",
    [
        {"backup_digest_verified": False},
        {"replayed_tombstone_high_watermark": 0},
        {"deletion_receipt_systems": ()},
        {"quarantined_transient_records": False},
    ],
)
def test_restore_corruption_lag_missing_receipts_and_transient_work_block_activation(
    changes: dict[str, object],
) -> None:
    lifecycle = governed_lifecycle().model_copy(update=changes)
    manifest = lifecycle.governance_manifest
    assert manifest is not None
    resolver = RestoreResolver(manifest)
    replaying = advance_restore(lifecycle, "replaying_governance")
    validating = advance_restore(replaying, "validating")
    with pytest.raises(RecoveryProtocolError):
        _ = advance_restore_authoritatively(validating, "ready", resolver)


def test_break_glass_expiry_is_not_a_caller_time_predicate() -> None:
    grant = BreakGlassGrant(
        grant_id=identifier(4),
        subject_id=identifier(3),
        restore_epoch=1,
        expires_at=NOW + timedelta(minutes=1),
        authorized_by=identifier(5),
        audit_id="audit-1",
    )
    authority = BreakGlassAuthority(grant, 1, now=NOW + timedelta(minutes=2))
    performed: list[str] = []
    with pytest.raises(RecoveryProtocolError, match="BREAK_GLASS_UNAUTHORIZED"):
        perform_break_glass_action(
            authority,
            BreakGlassActionRequest(
                grant=grant,
                subject_id=grant.subject_id,
                restore_epoch=1,
                occurred_at=NOW,
                action="restore-egress",
            ),
            lambda: performed.append("unsafe"),
        )
    assert not performed


@final
class BreakGlassAuthority:
    """Test authority that independently binds the exact audit grant at action time."""

    def __init__(
        self, grant: BreakGlassGrant, restore_epoch: int, now: datetime = NOW
    ) -> None:
        self._grant = grant
        self.restore_epoch = restore_epoch
        self.now = now
        self.revoked = False
        self._consumed = False
        self._lock = threading.Lock()

    def resolve_consume_and_perform(
        self, request: BreakGlassActionRequest, action: object
    ) -> bool:
        with self._lock:
            if (
                self.revoked
                or self._consumed
                or request.grant != self._grant
                or request.subject_id != self._grant.subject_id
                or request.restore_epoch != self.restore_epoch
                or request.restore_epoch != self._grant.restore_epoch
                or self.now >= self._grant.expires_at
            ):
                return False
            self._consumed = True
            assert callable(action)
            _ = action()
            return True


def test_break_glass_action_requires_atomic_authoritative_grant_consumption() -> None:
    grant = BreakGlassGrant(
        grant_id=identifier(4),
        subject_id=identifier(3),
        restore_epoch=1,
        expires_at=NOW + timedelta(minutes=1),
        authorized_by=identifier(5),
        audit_id="audit-1",
    )
    authority = BreakGlassAuthority(grant, 1)
    performed: list[str] = []
    request = BreakGlassActionRequest(
        grant=grant,
        subject_id=grant.subject_id,
        restore_epoch=1,
        occurred_at=NOW,
        action="restore-egress",
    )
    perform_break_glass_action(authority, request, lambda: performed.append("done"))
    assert performed == ["done"]
    with pytest.raises(RecoveryProtocolError, match="BREAK_GLASS_UNAUTHORIZED"):
        perform_break_glass_action(
            authority, request, lambda: performed.append("replay")
        )
    assert performed == ["done"]


def test_break_glass_authority_allows_exactly_one_concurrent_action() -> None:
    grant = BreakGlassGrant(
        grant_id=identifier(14),
        subject_id=identifier(13),
        restore_epoch=1,
        expires_at=NOW + timedelta(minutes=1),
        authorized_by=identifier(15),
        audit_id="audit-race",
    )
    authority = BreakGlassAuthority(grant, 1)
    request = BreakGlassActionRequest(
        grant=grant,
        subject_id=grant.subject_id,
        restore_epoch=1,
        occurred_at=NOW,
        action="restore-egress",
    )
    performed: list[str] = []
    failures: list[RecoveryProtocolError] = []
    lock = threading.Lock()

    def consume() -> None:
        try:
            perform_break_glass_action(
                authority, request, lambda: performed.append("performed")
            )
        except RecoveryProtocolError as error:
            with lock:
                failures.append(error)

    threads = tuple(threading.Thread(target=consume) for _ in range(2))
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert performed == ["performed"]
    assert len(failures) == 1


@pytest.mark.parametrize(
    (
        "grant_changes",
        "subject_id",
        "restore_epoch",
        "occurred_at",
        "authority_state",
    ),
    [
        ({"audit_id": "forged"}, identifier(3), 1, NOW, (NOW, False)),
        ({}, identifier(6), 1, NOW, (NOW, False)),
        ({}, identifier(3), 2, NOW, (NOW, False)),
        ({}, identifier(3), 1, NOW, (NOW + timedelta(minutes=1), False)),
        ({}, identifier(3), 1, NOW, (NOW, True)),
    ],
)
def test_break_glass_action_fails_closed_for_tamper_expiry_epoch_and_revocation(
    grant_changes: dict[str, object],
    subject_id: UUID,
    restore_epoch: int,
    occurred_at: datetime,
    authority_state: tuple[datetime, bool],
) -> None:
    authority_now, revoked = authority_state
    grant = BreakGlassGrant(
        grant_id=identifier(4),
        subject_id=identifier(3),
        restore_epoch=1,
        expires_at=NOW + timedelta(minutes=1),
        authorized_by=identifier(5),
        audit_id="audit-1",
    )
    authority = BreakGlassAuthority(grant, 1, authority_now)
    authority.revoked = revoked
    performed: list[str] = []
    with pytest.raises(RecoveryProtocolError, match="BREAK_GLASS_UNAUTHORIZED"):
        perform_break_glass_action(
            authority,
            BreakGlassActionRequest(
                grant=grant.model_copy(update=grant_changes),
                subject_id=subject_id,
                restore_epoch=restore_epoch,
                occurred_at=occurred_at,
                action="restore-egress",
            ),
            lambda: performed.append("unsafe"),
        )
    assert not performed


@final
class SnapshotStore:
    """Returns scripted authoritative snapshots for revision-race tests."""

    _snapshots: tuple[GovernanceSnapshot, ...]
    _activation_bindings: tuple[tuple[str, int, str | None], ...]
    _index: int

    def __init__(
        self,
        snapshots: tuple[GovernanceSnapshot, ...],
        activation_bindings: tuple[tuple[str, int, str | None], ...] = (),
    ) -> None:
        self._snapshots = snapshots
        self._activation_bindings = activation_bindings
        self._index = 0

    def read_snapshot(self) -> GovernanceSnapshot:
        snapshot = self._snapshots[min(self._index, len(self._snapshots) - 1)]
        self._index += 1
        return snapshot

    def consume_and_perform(self, permit: GovernancePermit, action: object) -> bool:
        """Model an atomic root/revision comparison at action time."""
        snapshot = self.read_snapshot()
        accepted = (
            permit.revision == snapshot.revision
            and permit.tombstone_root_sha256 == stream_digest(snapshot.tombstones)
            and permit.hold_root_sha256 == stream_digest(snapshot.holds)
        )
        if accepted:
            assert callable(action)
            _ = action()
        return accepted

    def resolve_activation_consume_and_perform(
        self, permit: PhysicalPurgePermit, action: object
    ) -> bool:
        """Model atomic root and independently resolved activation receipt checks."""
        snapshot = self.read_snapshot()
        binding = (
            self._activation_bindings[
                min(self._index - 1, len(self._activation_bindings) - 1)
            ]
            if self._activation_bindings
            else None
        )
        accepted = (
            permit.governance.revision == snapshot.revision
            and permit.governance.tombstone_root_sha256
            == stream_digest(snapshot.tombstones)
            and permit.governance.hold_root_sha256 == stream_digest(snapshot.holds)
            and binding is not None
            and binding[0] == permit.backup_sha256
            and binding[1] == permit.restore_epoch
            and binding[2] is not None
            and binding[2] == permit.activation_receipt_sha256
        )
        if accepted:
            assert callable(action)
            _ = action()
        return accepted


def test_same_snapshot_cannot_be_claimed_while_its_lease_is_active() -> None:
    claimed = claim_attempt(attempt(), "worker-a", 1, NOW, NOW + timedelta(seconds=10))
    with pytest.raises(RecoveryProtocolError, match="ATTEMPT_LEASE_ACTIVE"):
        _ = claim_attempt(
            claimed,
            "worker-b",
            1,
            NOW + timedelta(seconds=1),
            NOW + timedelta(seconds=20),
        )


@pytest.mark.parametrize("effect_state", ["ambiguous", "committed"])
def test_committed_and_ambiguous_attempts_never_retry(
    effect_state: Literal["ambiguous", "committed"],
) -> None:
    sealed = attempt().model_copy(
        update={"effect_state": effect_state, "status": "reconciliation_required"}
    )
    with pytest.raises(RecoveryProtocolError, match="RETRY_NOT_SEALED"):
        _ = retry_attempt(
            sealed,
            RetryCommand(
                run_id=identifier(20),
                execution_id=identifier(21),
                deadline=NOW + timedelta(minutes=2),
                reconciliation_proof_sha256=DIGEST,
                idempotency_key="retry-key",
            ),
            ReconciliationProof(
                predecessor_run_id=sealed.run_id,
                predecessor_execution_id=sealed.execution_id,
                predecessor_attempt_token=sealed.attempt_token,
                predecessor_effect_state="not_started",
                reconciliation_root_sha256=DIGEST,
            ),
            AtomicRetryAuthority(DurableCas(), ProofResolver({})),
        )


def test_authoritative_snapshot_revision_race_fails_closed_after_activation() -> None:
    tombstone = TombstoneRecord(
        subject_id=identifier(3), sequence=1, recorded_at=NOW, digest=DIGEST
    )
    released_hold = HoldRecord(
        subject_id=identifier(3),
        sequence=1,
        active=False,
        recorded_at=NOW,
        digest=DIGEST,
    )
    stable = GovernanceSnapshot(1, (tombstone,), (released_hold,))
    changed = GovernanceSnapshot(2, (tombstone,), ())
    normal_action: list[str] = []
    purge_action: list[str] = []
    assert not perform_normal_access_from_store(
        SnapshotStore((GovernanceSnapshot(1, (), ()), changed)),
        identifier(3),
        lambda: normal_action.append("visible"),
    )
    governance = activated_governance((tombstone,), (released_hold,))
    manifest = governance.governance_manifest
    assert manifest is not None
    assert not perform_physical_purge_from_store(
        SnapshotStore((stable, changed)),
        identifier(3),
        governance,
        RestoreResolver(manifest),
        lambda: purge_action.append("purged"),
    )
    assert normal_action == []
    assert purge_action == []


def test_physical_purge_activation_revocation_race_leaves_action_unperformed() -> None:
    tombstone = TombstoneRecord(
        subject_id=identifier(3), sequence=1, recorded_at=NOW, digest=DIGEST
    )
    released_hold = HoldRecord(
        subject_id=identifier(3),
        sequence=1,
        active=False,
        recorded_at=NOW,
        digest=DIGEST,
    )
    governance = activated_governance((tombstone,), (released_hold,))
    manifest = governance.governance_manifest
    receipt = governance.activation_receipt_sha256
    assert manifest is not None
    assert receipt is not None
    performed: list[str] = []
    assert not perform_physical_purge_from_store(
        SnapshotStore(
            (
                GovernanceSnapshot(1, (tombstone,), (released_hold,)),
                GovernanceSnapshot(1, (tombstone,), (released_hold,)),
            ),
            (
                (DIGEST, governance.restore_epoch, receipt),
                (DIGEST, governance.restore_epoch, "b" * 64),
            ),
        ),
        identifier(3),
        governance,
        RestoreResolver(manifest),
        lambda: performed.append("unsafe"),
    )
    assert not performed


def bundle(
    outcome: Literal["failure", "incomplete"] = "failure",
    high_threat_evidence: tuple[SecurityEvidenceMapping, ...] = (),
    attachment_sha256: tuple[str, ...] = (),
) -> TaskAttemptBundle:
    raw_log = b"exact raw log"
    provisional = TaskAttemptBundle(
        task_id="task",
        run_id="run",
        execution_id="execution",
        attempt_id="attempt",
        revision=1,
        outcome=outcome,
        exit_code=1 if outcome == "failure" else None,
        started_at="2026-07-13T00:00:00Z",
        finished_at=None if outcome == "incomplete" else "2026-07-13T00:01:00Z",
        command=("pytest",),
        control_id="RECOVERY",
        attachment_sha256=attachment_sha256,
        high_threat_evidence=high_threat_evidence,
        raw_log_sha256=hashlib.sha256(raw_log).hexdigest(),
        root_sha256="0" * 64,
    )
    return provisional.model_copy(
        update={"root_sha256": task_attempt_root(provisional)}
    )


def test_task_attempt_bundles_detect_tampering_and_are_append_only(
    tmp_path: Path,
) -> None:
    outcomes: tuple[Literal["failure", "incomplete"], ...] = (
        "failure",
        "incomplete",
    )
    for outcome in outcomes:
        sealed = bundle(outcome)
        raw_log = b"exact raw log"
        path = persist_task_attempt_bundle(
            tmp_path / outcome, sealed, TaskAttemptEvidence(raw_log=raw_log)
        )
        assert load_task_attempt_bundle(path, sealed.root_sha256) == sealed
        with pytest.raises(EvidenceIntegrityError, match="already exists"):
            _ = persist_task_attempt_bundle(
                tmp_path / outcome, sealed, TaskAttemptEvidence(raw_log=raw_log)
            )
        _ = (path / "raw.log").write_bytes(b"tampered")
        with pytest.raises(EvidenceIntegrityError, match="checksum"):
            _ = load_task_attempt_bundle(path, sealed.root_sha256)


def test_task_attempt_identity_cannot_be_reused_for_a_new_revision(
    tmp_path: Path,
) -> None:
    sealed = bundle()
    _ = persist_task_attempt_bundle(
        tmp_path, sealed, TaskAttemptEvidence(raw_log=b"exact raw log")
    )
    provisional_revision = sealed.model_copy(
        update={"revision": 2, "root_sha256": "0" * 64}
    )
    revised = provisional_revision.model_copy(
        update={"root_sha256": task_attempt_root(provisional_revision)}
    )

    with pytest.raises(EvidenceIntegrityError, match="already exists"):
        _ = persist_task_attempt_bundle(
            tmp_path, revised, TaskAttemptEvidence(raw_log=b"exact raw log")
        )


def test_task_attempt_bundle_json_root_anchor_and_attachment_tampering_are_rejected(
    tmp_path: Path,
) -> None:
    attachment = b"attachment"
    attachment_sha256 = hashlib.sha256(attachment).hexdigest()
    sealed = bundle(attachment_sha256=(attachment_sha256,))
    path = persist_task_attempt_bundle(
        tmp_path,
        sealed,
        TaskAttemptEvidence(raw_log=b"exact raw log", attachments=(attachment,)),
    )
    _ = (path / "bundle.json").write_text(
        (path / "bundle.json").read_text().replace('"revision":1', '"revision":2')
    )
    with pytest.raises(EvidenceIntegrityError, match="anchor"):
        _ = load_task_attempt_bundle(path, sealed.root_sha256)

    anchored = persist_task_attempt_bundle(
        tmp_path / "anchor",
        sealed,
        TaskAttemptEvidence(raw_log=b"exact raw log", attachments=(attachment,)),
    )
    _ = (anchored / "attachment-0").write_bytes(b"tampered")
    with pytest.raises(EvidenceIntegrityError, match="raw output checksum"):
        _ = load_task_attempt_bundle(anchored, sealed.root_sha256)
    _ = (anchored / "attachment-0").write_bytes(attachment)
    with pytest.raises(EvidenceIntegrityError, match="anchor"):
        _ = load_task_attempt_bundle(anchored, "b" * 64)


def test_non_security_attempt_rejects_stray_security_sidecar(tmp_path: Path) -> None:
    with pytest.raises(EvidenceIntegrityError, match="High threat"):
        _ = persist_task_attempt_bundle(
            tmp_path,
            bundle(),
            TaskAttemptEvidence(
                raw_log=b"exact raw log",
                security_catalog_bytes=b"stray catalog",
            ),
        )


@pytest.mark.parametrize(
    "unsafe_id",
    ["../escape", "/absolute", "dot.name", "task/sub"],
)
def test_task_attempt_paths_reject_navigation(unsafe_id: str) -> None:
    with pytest.raises(ValueError, match="path-safe"):
        _ = TaskAttemptBundle(
            task_id=unsafe_id,
            run_id="run",
            execution_id="execution",
            attempt_id="attempt",
            revision=1,
            outcome="incomplete",
            started_at="2026-07-13T00:00:00Z",
            command=("pytest",),
            control_id="SECURITY",
            raw_log_sha256=DIGEST,
            root_sha256=DIGEST,
        )


def test_task_attempt_persistence_rejects_symlinked_evidence_root(
    tmp_path: Path,
) -> None:
    target = tmp_path / "target"
    target.mkdir()
    evidence_root = tmp_path / "evidence"
    evidence_root.symlink_to(target, target_is_directory=True)
    with pytest.raises(EvidenceIntegrityError, match="path-safe"):
        _ = persist_task_attempt_bundle(
            evidence_root, bundle(), TaskAttemptEvidence(raw_log=b"exact raw log")
        )
    nested_root = tmp_path / "nested"
    nested_root.symlink_to(target, target_is_directory=True)
    with pytest.raises(EvidenceIntegrityError, match="path-safe"):
        _ = persist_task_attempt_bundle(
            nested_root / "evidence",
            bundle(),
            TaskAttemptEvidence(raw_log=b"exact raw log"),
        )


def test_security_mapping_requires_independent_required_catalog() -> None:
    catalog = RequiredSecurityCatalog(
        high_threat_ids=("H-1", "H-2"),
        source_root_sha256=DIGEST,
    )
    mapping = SecurityEvidenceMapping(
        threat_id="H-1",
        positive_case_count=1,
        evidence_root_sha256=DIGEST,
    )
    with pytest.raises(EvidenceIntegrityError, match="exactly once"):
        verify_security_evidence_mapping(catalog, (mapping,))


def test_empty_required_catalog_and_mismatched_catalog_root_are_rejected(
    tmp_path: Path,
) -> None:
    with pytest.raises(ValueError, match="at least 1"):
        _ = RequiredSecurityCatalog(high_threat_ids=(), source_root_sha256=DIGEST)
    catalog = RequiredSecurityCatalog(
        high_threat_ids=("H-1",), source_root_sha256=DIGEST
    )
    with pytest.raises(EvidenceIntegrityError, match="exactly once"):
        verify_security_evidence_mapping(catalog, ())
    with pytest.raises(EvidenceIntegrityError, match="map every High threat"):
        _ = persist_task_attempt_bundle(
            tmp_path,
            bundle(),
            TaskAttemptEvidence(
                raw_log=b"exact raw log",
                security_catalog=catalog,
                security_catalog_bytes=b"untrusted catalog bytes",
            ),
        )
