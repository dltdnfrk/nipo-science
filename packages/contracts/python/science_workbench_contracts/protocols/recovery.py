"""Fail-closed execution recovery and restore governance contracts."""



import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import (
    Annotated,
    Final,
    Literal,
    Never,
    Protocol,
    Self,
    cast,
    final,
    override,
)

from pydantic import Field, model_validator

from science_workbench_contracts.common import (
    NonEmptyText,
    Sha256,
    UtcTimestamp,
    Uuid7,
)

from .models import ProtocolModel

EffectState = Literal["not_started", "started", "ambiguous", "committed"]
AttemptStatus = Literal[
    "queued",
    "claimed",
    "completed",
    "failed",
    "reconciled_no_effect",
    "reconciliation_required",
]
ATTEMPT_VALID_STATES: Final[
    dict[AttemptStatus, dict[EffectState, frozenset[bool]]]
] = {
    "queued": {"not_started": frozenset({False, True})},
    "claimed": {
        "not_started": frozenset({False, True}),
        "started": frozenset({False, True}),
        "committed": frozenset({False, True}),
    },
    "completed": {"committed": frozenset({False, True})},
    "failed": {"not_started": frozenset({False, True})},
    "reconciled_no_effect": {"not_started": frozenset({False, True})},
    "reconciliation_required": {
        "not_started": frozenset({False, True}),
        "started": frozenset({False, True}),
        "ambiguous": frozenset({False, True}),
        "committed": frozenset({False, True}),
    },
}
RestorePhase = Literal[
    "restoring",
    "replaying_governance",
    "validating",
    "ready",
    "activated",
    "failed",
]
STALE_ATTEMPT_FENCE_CODE: Final = "STALE_ATTEMPT_TOKEN"
INVALID_LEASE_DEADLINE: Final = "INVALID_LEASE_DEADLINE"
ATTEMPT_NOT_CLAIMABLE: Final = "ATTEMPT_NOT_CLAIMABLE"
ATTEMPT_LEASE_ACTIVE: Final = "ATTEMPT_LEASE_ACTIVE"
LEASE_OWNER_MISMATCH: Final = "LEASE_OWNER_MISMATCH"
LEASE_EXPIRED: Final = "LEASE_EXPIRED"
ATTEMPT_NOT_RUNNING: Final = "ATTEMPT_NOT_RUNNING"
INVALID_EFFECT_TRANSITION: Final = "INVALID_EFFECT_TRANSITION"
UNPROVEN_EFFECT: Final = "UNPROVEN_EFFECT"
RETRY_ID_REUSE: Final = "RETRY_ID_REUSE"
INVALID_RESTORE_TRANSITION: Final = "INVALID_RESTORE_TRANSITION"
RESTORE_NOT_INERT: Final = "RESTORE_NOT_INERT"
BACKUP_DIGEST_UNVERIFIED: Final = "BACKUP_DIGEST_UNVERIFIED"
BACKUP_DIGEST_MISMATCH: Final = "BACKUP_DIGEST_MISMATCH"
TOMBSTONE_REPLAY_LAG: Final = "TOMBSTONE_REPLAY_LAG"
HOLD_REPLAY_LAG: Final = "HOLD_REPLAY_LAG"
DELETION_RECEIPT_MISMATCH: Final = "DELETION_RECEIPT_MISMATCH"
TRANSIENT_RESTORE_STATE: Final = "TRANSIENT_RESTORE_STATE"
INVARIANT_REPORT_MISSING: Final = "INVARIANT_REPORT_MISSING"
ATTEMPT_INVALID_STATE: Final = "ATTEMPT_INVALID_STATE"
RETRY_NOT_SEALED: Final = "RETRY_NOT_SEALED"
INVALID_OCCURRED_AT: Final = "INVALID_OCCURRED_AT"
TOMBSTONE_SNAPSHOT_MISMATCH: Final = "TOMBSTONE_SNAPSHOT_MISMATCH"
HOLD_SNAPSHOT_MISMATCH: Final = "HOLD_SNAPSHOT_MISMATCH"
RECONCILIATION_PROOF_MISMATCH: Final = "RECONCILIATION_PROOF_MISMATCH"
RECONCILIATION_PROOF_CONSUMED: Final = "RECONCILIATION_PROOF_CONSUMED"
RESTORE_MANIFEST_MISMATCH: Final = "RESTORE_MANIFEST_MISMATCH"
RESTORE_MANIFEST_ANCHOR_MISMATCH: Final = "RESTORE_MANIFEST_ANCHOR_MISMATCH"
BREAK_GLASS_UNAUTHORIZED: Final = "BREAK_GLASS_UNAUTHORIZED"


@dataclass(frozen=True, slots=True)
class RecoveryProtocolError(Exception):
    """Rejects unsafe recovery transitions without weakening run-state contracts."""

    code: str
    current: str
    requested: str

    @override
    def __str__(self) -> str:
        return f"{self.code}: {self.current} -> {self.requested}"


class ReconciliationProof(ProtocolModel):
    """Versioned immutable evidence that one predecessor made no external effect."""

    version: Literal[1] = 1
    predecessor_run_id: Uuid7
    predecessor_execution_id: Uuid7
    predecessor_attempt_token: Annotated[int, Field(ge=1)]
    predecessor_effect_state: Literal["not_started"]
    reconciliation_root_sha256: Sha256


def reconciliation_proof_digest(proof: ReconciliationProof) -> str:
    """Hash complete proof content before comparison to trusted external evidence."""
    return hashlib.sha256(
        json.dumps(
            proof.model_dump(mode="json"),
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


@dataclass(frozen=True, slots=True)
class DurableCompareAndSetRequest:
    """One durable immutable-proof consumption reservation."""

    key: str
    expected: str | None
    value: str


class DurableCompareAndSet(Protocol):
    """Durable reservation authority; implementations survive process restart."""

    def compare_and_set(self, request: DurableCompareAndSetRequest) -> bool:
        """Atomically write value only while key contains expected."""
        ...


class ReconciliationProofAnchorResolver(Protocol):
    """Independent durable authority for immutable reconciliation proof anchors."""

    def resolve_anchor(self, proof_id: str) -> Sha256 | None:
        """Return the anchor persisted for one immutable proof identity."""
        ...


def reconciliation_proof_id(proof: ReconciliationProof) -> str:
    """Return the immutable identity used to resolve proof authority."""
    return ":".join(
        (
            str(proof.predecessor_run_id),
            str(proof.predecessor_execution_id),
            str(proof.predecessor_attempt_token),
        )
    )


@final
class ReconciliationProofStore:
    """Resolves immutable reconciliation evidence from an independent authority."""

    _resolver: ReconciliationProofAnchorResolver

    def __init__(self, resolver: ReconciliationProofAnchorResolver) -> None:
        self._resolver = resolver

    def trusted_digest(self, proof: ReconciliationProof) -> str:
        """Resolve and verify proof content without consuming its retry right."""
        expected_anchor = self._resolver.resolve_anchor(reconciliation_proof_id(proof))
        proof_digest = reconciliation_proof_digest(proof)
        if expected_anchor is None or proof_digest != expected_anchor:
            _reject(RECONCILIATION_PROOF_MISMATCH, proof_digest, str(expected_anchor))
        return proof_digest


class RestoreGovernanceManifest(ProtocolModel):
    """An independently anchored immutable governance baseline for one restore."""

    version: Literal[1] = 1
    backup_sha256: Sha256
    source_governance_root_sha256: Sha256
    tombstone_high_watermark: Annotated[int, Field(gt=0)]
    hold_high_watermark: Annotated[int, Field(gt=0)]
    tombstone_stream_sha256: Sha256
    hold_stream_sha256: Sha256
    required_deletion_systems: tuple[NonEmptyText, ...]
    deletion_receipt_roots: tuple[Sha256, ...]
    restore_epoch: Annotated[int, Field(ge=1)]
    quarantined_transient_records: Literal[True]
    invariant_report_sha256: Sha256

    @model_validator(mode="after")
    def receipt_roots_cover_required_systems(self) -> Self:
        """Require a non-empty receipt root for every required external system."""
        if (
            not self.required_deletion_systems
            or len(set(self.required_deletion_systems))
            != len(self.required_deletion_systems)
            or len(self.deletion_receipt_roots) != len(self.required_deletion_systems)
        ):
            raise ValueError(DELETION_RECEIPT_MISMATCH)
        return self


def restore_manifest_digest(manifest: RestoreGovernanceManifest) -> str:
    """Hash immutable restore governance content for external anchor comparison."""
    return hashlib.sha256(
        json.dumps(
            manifest.model_dump(mode="json"),
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()




class ExecutionAttempt(ProtocolModel):
    """A fenced, immutable description of one externally-effectful attempt."""

    execution_id: Uuid7
    run_id: Uuid7
    lease_owner: NonEmptyText | None = None
    attempt_token: Annotated[int, Field(ge=1)] = 1
    restore_epoch: Annotated[int, Field(ge=1)] = 1
    deadline: UtcTimestamp
    effect_state: EffectState = "not_started"
    status: AttemptStatus = "queued"
    predecessor_execution_id: Uuid7 | None = None
    idempotency_key: NonEmptyText | None = None
    reconciliation_proof_sha256: Sha256 | None = None
    @model_validator(mode="after")
    def authority_matches_status(self) -> Self:
        """Validate every persisted state against its complete immutable lineage."""
        lineage = (
            self.predecessor_execution_id,
            self.idempotency_key,
            self.reconciliation_proof_sha256,
        )
        has_lineage = all(value is not None for value in lineage)
        if any(value is not None for value in lineage) and not has_lineage:
            raise ValueError(ATTEMPT_INVALID_STATE)
        if has_lineage not in ATTEMPT_VALID_STATES[self.status].get(
            self.effect_state, frozenset()
        ):
            raise ValueError(ATTEMPT_INVALID_STATE)
        if (self.status == "claimed") != (self.lease_owner is not None):
            raise ValueError(ATTEMPT_INVALID_STATE)
        if (
            self.predecessor_execution_id is not None
            and self.predecessor_execution_id == self.execution_id
        ):
            raise ValueError(ATTEMPT_INVALID_STATE)
        return self


@dataclass(frozen=True, slots=True)
class RetryCommand:
    """Sealed inputs for creating a new execution attempt after reconciliation."""

    run_id: Uuid7
    execution_id: Uuid7
    deadline: UtcTimestamp
    reconciliation_proof_sha256: Sha256
    idempotency_key: NonEmptyText


RetryAttemptCreationOutcome = Literal[
    "created",
    "proof_consumed",
    "binding_mismatch",
    "child_conflict",
]


@dataclass(frozen=True, slots=True)
class RetryAttemptCreationRequest:
    """Complete retry creation bound to one predecessor and immutable proof."""

    predecessor: ExecutionAttempt
    command: RetryCommand
    proof: ReconciliationProof
    child: ExecutionAttempt


class RetryAttemptCreationAuthority(Protocol):
    """Durably resolves, reserves, and materializes one reconciled retry transaction."""

    def resolve_reserve_and_create(
        self, request: RetryAttemptCreationRequest
    ) -> RetryAttemptCreationOutcome:
        """Atomically resolve, reserve, and create one retry."""
        ...


class TombstoneRecord(ProtocolModel):
    """Append-only deletion intent; it always denies normal visibility."""

    subject_id: Uuid7
    sequence: Annotated[int, Field(ge=1)]
    recorded_at: UtcTimestamp
    digest: Sha256


class HoldRecord(ProtocolModel):
    """Append-only hold event; a release never removes a tombstone."""

    subject_id: Uuid7
    sequence: Annotated[int, Field(ge=1)]
    active: bool
    recorded_at: UtcTimestamp
    digest: Sha256
@dataclass(frozen=True, slots=True)
class GovernanceSnapshot:
    """A revisioned authoritative governance read used for visibility and purge."""

    revision: int
    tombstones: tuple[TombstoneRecord, ...]
    holds: tuple[HoldRecord, ...]


class GovernanceSnapshotStore(Protocol):
    """Returns a complete monotonic governance snapshot from one authority."""

    def read_snapshot(self) -> GovernanceSnapshot:
        """Read a revisioned, complete snapshot."""
        ...
@dataclass(frozen=True, slots=True)
class GovernancePermit:
    """Revision and complete-stream-root-bound authorization for one action."""

    subject_id: Uuid7
    revision: int
    tombstone_root_sha256: Sha256
    hold_root_sha256: Sha256
    action: Literal["visibility", "purge"]
@dataclass(frozen=True, slots=True)
class PhysicalPurgePermit:
    """One purge permit bound to governance roots and an activation receipt identity."""

    governance: GovernancePermit
    backup_sha256: Sha256
    restore_epoch: int
    activation_receipt_sha256: Sha256


class PhysicalPurgeAuthority(GovernanceSnapshotStore, Protocol):
    """Atomically resolves current activation, consumes the permit, and purges."""

    def resolve_activation_consume_and_perform(
        self, permit: PhysicalPurgePermit, action: Callable[[], None]
    ) -> bool:
        """Recheck roots and non-null activation receipt before consuming and acting."""
        ...


class GovernanceActionStore(GovernanceSnapshotStore, Protocol):
    """Authoritative store that consumes a permit while performing its action."""

    def consume_and_perform(
        self, permit: GovernancePermit, action: Callable[[], None]
    ) -> bool:
        """Recheck current revision and roots, then consume and perform atomically."""
        ...


class RestoreGovernanceResolver(Protocol):
    """Independent resolver for restore manifest and external governance roots."""

    def resolve_manifest_anchor(
        self, backup_sha256: Sha256, restore_epoch: int
    ) -> Sha256 | None:
        """Resolve the immutable manifest anchor bound to backup and epoch."""
        ...

    def resolve_source_governance_root(
        self, backup_sha256: Sha256, restore_epoch: int
    ) -> Sha256 | None:
        """Resolve trusted canonical source-governance bytes root."""
        ...
    def resolve_tombstone_stream_root(
        self, backup_sha256: Sha256, restore_epoch: int
    ) -> Sha256 | None:
        """Resolve the canonical tombstone stream root independently."""
        ...

    def resolve_hold_stream_root(
        self, backup_sha256: Sha256, restore_epoch: int
    ) -> Sha256 | None:
        """Resolve the canonical hold stream root independently."""
        ...

    def resolve_deletion_receipt_root(
        self, system: NonEmptyText, backup_sha256: Sha256, restore_epoch: int
    ) -> Sha256 | None:
        """Resolve one named trusted deletion-system receipt root."""
        ...


    def resolve_activation_receipt(
        self,
        backup_sha256: Sha256,
        restore_epoch: int,
        phase: Literal["ready", "activated"],
    ) -> Sha256 | None:
        """Resolve the current independent activation receipt for one restore phase."""
        ...




class BreakGlassGrant(ProtocolModel):
    """Authorizes a time-bounded, audited exception within one restore epoch."""

    grant_id: Uuid7
    subject_id: Uuid7
    restore_epoch: Annotated[int, Field(ge=1)]
    expires_at: UtcTimestamp
    authorized_by: Uuid7
    audit_id: NonEmptyText


@dataclass(frozen=True, slots=True)
class BreakGlassActionRequest:
    """One exception request bound to grant, subject, epoch, and audit metadata."""

    grant: BreakGlassGrant
    subject_id: Uuid7
    restore_epoch: Annotated[int, Field(ge=1)]
    occurred_at: UtcTimestamp
    action: NonEmptyText


class BreakGlassActionAuthority(Protocol):
    """Atomically resolves grants using an authority-owned clock."""

    def resolve_consume_and_perform(
        self, request: BreakGlassActionRequest, action: Callable[[], None]
    ) -> bool:
        """Check expiry at transaction time before performing the action."""
        ...


class RestoreLifecycle(ProtocolModel):
    """Restore is deliberately inert until every governance invariant is sealed."""

    restore_epoch: Annotated[int, Field(ge=1)]
    phase: RestorePhase = "restoring"
    workers_enabled: bool = False
    egress_enabled: bool = False
    backup_digest_verified: bool = False
    backup_sha256: Sha256 | None = None
    verified_backup_sha256: Sha256 | None = None
    tombstone_high_watermark: Annotated[int, Field(ge=0)] = 0
    replayed_tombstone_high_watermark: Annotated[int, Field(ge=0)] = 0
    hold_high_watermark: Annotated[int, Field(ge=0)] = 0
    replayed_hold_high_watermark: Annotated[int, Field(ge=0)] = 0
    tombstone_stream_sha256: Sha256 | None = None
    hold_stream_sha256: Sha256 | None = None
    required_deletion_systems: tuple[NonEmptyText, ...] = ()
    deletion_receipt_systems: tuple[NonEmptyText, ...] = ()
    quarantined_transient_records: bool = False
    invariant_report_sha256: Sha256 | None = None
    governance_manifest: RestoreGovernanceManifest | None = None
    governance_manifest_anchor_sha256: Sha256 | None = None
    activation_receipt_sha256: Sha256 | None = None
    @model_validator(mode="after")
    def activated_state_is_valid(self) -> Self:
        """Allow serialized activation only with complete restore state and receipt."""
        if self.phase in {"ready", "activated"}:
            if self.activation_receipt_sha256 is None:
                _reject(RESTORE_MANIFEST_ANCHOR_MISMATCH, "missing", self.phase)
            _validate_restore(self)
        return self


def _reject(code: str, current: str, requested: str) -> Never:
    """Raise one stable recovery transition error."""
    raise RecoveryProtocolError(code=code, current=current, requested=requested)


def _require_utc(occurred_at: UtcTimestamp) -> None:
    """Reject naive or non-UTC timestamps before evaluating authority."""
    if occurred_at.utcoffset() != timedelta(0):
        _reject(INVALID_OCCURRED_AT, str(occurred_at), "UTC")


def _attempt_transition(
    attempt: ExecutionAttempt, **changes: object
) -> ExecutionAttempt:
    """Revalidate every persisted transition; model_copy bypasses validation."""
    payload = attempt.model_dump()
    payload.update(changes)
    return ExecutionAttempt.model_validate(payload)


@dataclass(frozen=True, slots=True)
class AttemptCompareAndSetRequest:
    """One complete authoritative attempt-state replacement predicate."""

    expected: ExecutionAttempt


class ExecutionAttemptStore(Protocol):
    """Durable authority that reads its clock inside every attempt transaction."""

    def compare_and_set_at_authoritative_time(
        self,
        request: AttemptCompareAndSetRequest,
        transition: Callable[[ExecutionAttempt, UtcTimestamp], ExecutionAttempt],
    ) -> ExecutionAttempt | None:
        """CAS, read transaction time, compute, and persist atomically."""
        ...


class DownstreamEffectStore(ExecutionAttemptStore, Protocol):
    """Executes a downstream action inside the same authoritative time fence."""

    def compare_and_set_perform_at_authoritative_time(
        self,
        request: AttemptCompareAndSetRequest,
        transition: Callable[[ExecutionAttempt, UtcTimestamp], ExecutionAttempt],
        action: Callable[[], None],
    ) -> ExecutionAttempt | None:
        """CAS, obtain authoritative time, perform, and persist atomically."""
        ...


def _persist_attempt_transition(
    store: ExecutionAttemptStore,
    attempt: ExecutionAttempt,
    transition: Callable[[ExecutionAttempt, UtcTimestamp], ExecutionAttempt],
) -> ExecutionAttempt:
    """Compute and persist a transition with time supplied by the authority."""
    replacement = store.compare_and_set_at_authoritative_time(
        AttemptCompareAndSetRequest(expected=attempt), transition
    )
    if replacement is None:
        _reject(STALE_ATTEMPT_FENCE_CODE, str(attempt.attempt_token), "authoritative")
    return replacement


@dataclass(frozen=True, slots=True)
class ClaimAttemptRequest:
    """Inputs for one durable claim transition."""

    attempt: ExecutionAttempt
    lease_owner: NonEmptyText
    expected_token: int
    occurred_at: UtcTimestamp
    deadline: UtcTimestamp


@dataclass(frozen=True, slots=True)
class HeartbeatAttemptRequest:
    """Inputs for one durable heartbeat transition."""

    attempt: ExecutionAttempt
    lease_owner: NonEmptyText
    expected_token: int
    occurred_at: UtcTimestamp
    deadline: UtcTimestamp


@dataclass(frozen=True, slots=True)
class RecordEffectRequest:
    """Inputs for one durable effect-boundary transition."""

    attempt: ExecutionAttempt
    lease_owner: NonEmptyText
    expected_token: int
    occurred_at: UtcTimestamp
    effect_state: EffectState


@dataclass(frozen=True, slots=True)
class CompleteAttemptRequest:
    """Inputs for one durable completion transition."""

    attempt: ExecutionAttempt
    lease_owner: NonEmptyText
    expected_token: int
    occurred_at: UtcTimestamp
    outcome: Literal["completed", "failed"]


def claim_attempt_durable(
    store: ExecutionAttemptStore, request: ClaimAttemptRequest
) -> ExecutionAttempt:
    """Claim with transaction time; occurred_at is audit metadata only."""
    _require_utc(request.occurred_at)
    return _persist_attempt_transition(
        store,
        request.attempt,
        lambda current, now: claim_attempt(
            current,
            request.lease_owner,
            request.expected_token,
            now,
            request.deadline,
        ),
    )


def heartbeat_attempt_durable(
    store: ExecutionAttemptStore, request: HeartbeatAttemptRequest
) -> ExecutionAttempt:
    """Renew a lease using authoritative transaction time."""
    _require_utc(request.occurred_at)
    return _persist_attempt_transition(
        store,
        request.attempt,
        lambda current, now: heartbeat_attempt(
            current,
            request.lease_owner,
            request.expected_token,
            now,
            request.deadline,
        ),
    )


def record_effect_durable(
    store: ExecutionAttemptStore, request: RecordEffectRequest
) -> ExecutionAttempt:
    """Persist an effect boundary using authoritative transaction time."""
    _require_utc(request.occurred_at)
    return _persist_attempt_transition(
        store,
        request.attempt,
        lambda current, now: record_effect(
            current,
            request.lease_owner,
            request.expected_token,
            now,
            request.effect_state,
        ),
    )


def perform_downstream_effect(
    store: DownstreamEffectStore,
    request: RecordEffectRequest,
    action: Callable[[], None],
) -> ExecutionAttempt:
    """Perform an effect only inside the authoritative lease-time transaction."""
    _require_utc(request.occurred_at)
    if request.effect_state != "started":
        _reject(INVALID_EFFECT_TRANSITION, request.effect_state, "started")
    replacement = store.compare_and_set_perform_at_authoritative_time(
        AttemptCompareAndSetRequest(expected=request.attempt),
        lambda current, now: record_effect(
            current,
            request.lease_owner,
            request.expected_token,
            now,
            request.effect_state,
        ),
        action,
    )
    if replacement is None:
        _reject(
            STALE_ATTEMPT_FENCE_CODE,
            str(request.attempt.attempt_token),
            "authoritative",
        )
    return replacement


def complete_attempt_durable(
    store: ExecutionAttemptStore, request: CompleteAttemptRequest
) -> ExecutionAttempt:
    """Complete using authoritative transaction time."""
    _require_utc(request.occurred_at)
    return _persist_attempt_transition(
        store,
        request.attempt,
        lambda current, now: complete_attempt(
            current,
            request.lease_owner,
            request.expected_token,
            now,
            request.outcome,
        ),
    )


def claim_attempt(
    attempt: ExecutionAttempt,
    lease_owner: NonEmptyText,
    expected_token: int,
    occurred_at: UtcTimestamp,
    deadline: UtcTimestamp,
) -> ExecutionAttempt:
    """CAS-claim, fencing stale owners and refusing uncertain effects."""
    _require_utc(occurred_at)
    if expected_token != attempt.attempt_token:
        _reject(
            STALE_ATTEMPT_FENCE_CODE,
            str(attempt.attempt_token),
            str(expected_token),
        )
    if deadline <= occurred_at:
        _reject(
            INVALID_LEASE_DEADLINE,
            attempt.deadline.isoformat(),
            deadline.isoformat(),
        )
    if attempt.status == "queued":
        if attempt.effect_state != "not_started":
            return _attempt_transition(
                attempt,
                lease_owner=None,
                attempt_token=attempt.attempt_token + 1,
                status="reconciliation_required",
            )
        return _attempt_transition(
            attempt,
            lease_owner=lease_owner,
            deadline=deadline,
            status="claimed",
        )
    if attempt.status != "claimed":
        _reject(ATTEMPT_NOT_CLAIMABLE, attempt.status, "claimed")
    if occurred_at < attempt.deadline:
        _reject(
            ATTEMPT_LEASE_ACTIVE,
            attempt.deadline.isoformat(),
            occurred_at.isoformat(),
        )
    if attempt.effect_state != "not_started":
        return _attempt_transition(
            attempt,
            lease_owner=None,
            attempt_token=attempt.attempt_token + 1,
            status="reconciliation_required",
        )
    return _attempt_transition(
        attempt,
        lease_owner=lease_owner,
        attempt_token=attempt.attempt_token + 1,
        deadline=deadline,
        status="claimed",
    )


def heartbeat_attempt(
    attempt: ExecutionAttempt,
    lease_owner: NonEmptyText,
    expected_token: int,
    occurred_at: UtcTimestamp,
    deadline: UtcTimestamp,
) -> ExecutionAttempt:
    """CAS-renew the currently fenced lease."""
    _require_utc(occurred_at)
    if expected_token != attempt.attempt_token:
        _reject(
            STALE_ATTEMPT_FENCE_CODE,
            str(attempt.attempt_token),
            str(expected_token),
        )
    if (
        attempt.status != "claimed"
        or attempt.lease_owner != lease_owner
    ):
        _reject(LEASE_OWNER_MISMATCH, str(attempt.lease_owner), lease_owner)
    if occurred_at >= attempt.deadline:
        _reject(LEASE_EXPIRED, attempt.deadline.isoformat(), occurred_at.isoformat())
    if deadline <= occurred_at:
        _reject(
            INVALID_LEASE_DEADLINE,
            attempt.deadline.isoformat(),
            deadline.isoformat(),
        )
    return _attempt_transition(attempt, deadline=deadline)


def record_effect(
    attempt: ExecutionAttempt,
    lease_owner: NonEmptyText,
    expected_token: int,
    occurred_at: UtcTimestamp,
    effect_state: EffectState,
) -> ExecutionAttempt:
    """Persist the durable effect boundary before completion."""
    _require_utc(occurred_at)
    if expected_token != attempt.attempt_token:
        _reject(
            STALE_ATTEMPT_FENCE_CODE,
            str(attempt.attempt_token),
            str(expected_token),
        )
    if attempt.status != "claimed" or attempt.lease_owner != lease_owner:
        _reject(LEASE_OWNER_MISMATCH, str(attempt.lease_owner), lease_owner)
    if occurred_at >= attempt.deadline:
        _reject(LEASE_EXPIRED, attempt.deadline.isoformat(), occurred_at.isoformat())
    allowed: dict[EffectState, set[EffectState]] = {
        "not_started": {"started", "ambiguous"},
        "started": {"ambiguous", "committed"},
        "ambiguous": set[EffectState](),
        "committed": set[EffectState](),
    }
    if effect_state not in allowed[attempt.effect_state]:
        _reject(INVALID_EFFECT_TRANSITION, attempt.effect_state, effect_state)
    if effect_state == "ambiguous":
        return _attempt_transition(
            attempt,
            attempt_token=attempt.attempt_token + 1,
            lease_owner=None,
            effect_state=effect_state,
            status="reconciliation_required",
        )
    return _attempt_transition(attempt, effect_state=effect_state)


def complete_attempt(
    attempt: ExecutionAttempt,
    lease_owner: NonEmptyText,
    expected_token: int,
    occurred_at: UtcTimestamp,
    outcome: Literal["completed", "failed"],
) -> ExecutionAttempt:
    """CAS-complete a claimed attempt; reconciliation is never completion."""
    _require_utc(occurred_at)
    if expected_token != attempt.attempt_token:
        _reject(
            STALE_ATTEMPT_FENCE_CODE,
            str(attempt.attempt_token),
            str(expected_token),
        )
    if attempt.status != "claimed" or attempt.lease_owner != lease_owner:
        _reject(LEASE_OWNER_MISMATCH, str(attempt.lease_owner), lease_owner)
    if occurred_at >= attempt.deadline:
        _reject(LEASE_EXPIRED, attempt.deadline.isoformat(), occurred_at.isoformat())
    if outcome == "completed" and attempt.effect_state != "committed":
        _reject(UNPROVEN_EFFECT, attempt.effect_state, outcome)
    if outcome == "failed" and attempt.effect_state != "not_started":
        return _attempt_transition(
            attempt,
            attempt_token=attempt.attempt_token + 1,
            lease_owner=None,
            status="reconciliation_required",
        )
    return _attempt_transition(
        attempt,
        attempt_token=attempt.attempt_token + 1,
        lease_owner=None,
        status=outcome,
    )


def reconcile_no_effect(
    attempt: ExecutionAttempt,
    proof: ReconciliationProof,
    proof_store: ReconciliationProofStore,
) -> ExecutionAttempt:
    """Seal only a proof resolved by an independent durable authority."""
    if attempt.status != "reconciliation_required":
        _reject(RETRY_NOT_SEALED, attempt.status, "reconciliation_required")
    if (
        attempt.effect_state != "not_started"
        or proof.predecessor_run_id != attempt.run_id
        or proof.predecessor_execution_id != attempt.execution_id
        or proof.predecessor_attempt_token != attempt.attempt_token
        or proof.predecessor_effect_state != "not_started"
    ):
        _reject(
            RECONCILIATION_PROOF_MISMATCH,
            str(attempt.execution_id),
            str(proof.predecessor_execution_id),
        )
    _ = proof_store.trusted_digest(proof)
    return _attempt_transition(attempt, status="reconciled_no_effect")


def retry_attempt(
    attempt: ExecutionAttempt,
    command: RetryCommand,
    proof: ReconciliationProof,
    authority: RetryAttemptCreationAuthority,
) -> ExecutionAttempt:
    """Return only a retry atomically created with its anchored proof reservation."""
    if (
        attempt.status != "reconciled_no_effect"
        or attempt.effect_state != "not_started"
    ):
        _reject(RETRY_NOT_SEALED, attempt.status, "reconciled_no_effect")
    if attempt.predecessor_execution_id == attempt.execution_id:
        _reject(RETRY_ID_REUSE, str(attempt.execution_id), str(command.execution_id))
    if (
        proof.predecessor_run_id != attempt.run_id
        or proof.predecessor_execution_id != attempt.execution_id
        or proof.predecessor_attempt_token != attempt.attempt_token
        or proof.predecessor_effect_state != attempt.effect_state
    ):
        _reject(
            RECONCILIATION_PROOF_MISMATCH,
            str(attempt.execution_id),
            str(proof.predecessor_execution_id),
        )
    if command.run_id == attempt.run_id or command.execution_id == attempt.execution_id:
        _reject(RETRY_ID_REUSE, str(attempt.execution_id), str(command.execution_id))
    child = ExecutionAttempt(
        execution_id=command.execution_id,
        run_id=command.run_id,
        restore_epoch=attempt.restore_epoch,
        deadline=command.deadline,
        predecessor_execution_id=attempt.execution_id,
        idempotency_key=command.idempotency_key,
        reconciliation_proof_sha256=command.reconciliation_proof_sha256,
    )
    request = RetryAttemptCreationRequest(
        predecessor=attempt,
        command=command,
        proof=proof,
        child=child,
    )
    outcome = authority.resolve_reserve_and_create(request)
    if outcome == "created":
        return child
    if outcome == "proof_consumed":
        _reject(
            RECONCILIATION_PROOF_CONSUMED,
            str(attempt.execution_id),
            str(command.execution_id),
        )
    if outcome == "binding_mismatch":
        _reject(
            RECONCILIATION_PROOF_MISMATCH,
            str(attempt.execution_id),
            str(command.execution_id),
        )
    if outcome == "child_conflict":
        _reject(RETRY_ID_REUSE, str(attempt.execution_id), str(command.execution_id))
    _reject(ATTEMPT_INVALID_STATE, str(outcome), "retry-creation-outcome")


def normal_access_allowed(
    tombstones: tuple[TombstoneRecord, ...], subject_id: Uuid7
) -> bool:
    """Return whether no tombstone denies the subject normal visibility."""
    return not any(record.subject_id == subject_id for record in tombstones)

def _governance_permit(
    snapshot: GovernanceSnapshot,
    subject_id: Uuid7,
    action: Literal["visibility", "purge"],
) -> GovernancePermit:
    """Bind an authorization to the exact complete streams, not only revision."""
    return GovernancePermit(
        subject_id=subject_id,
        revision=snapshot.revision,
        tombstone_root_sha256=_stream_digest(snapshot.tombstones),
        hold_root_sha256=_stream_digest(snapshot.holds),
        action=action,
    )


def perform_normal_access_from_store(
    store: GovernanceActionStore, subject_id: Uuid7, action: Callable[[], None]
) -> bool:
    """Perform visibility work only while its authoritative permit is consumed."""
    snapshot = store.read_snapshot()
    if (
        snapshot.revision < 1
        or not normal_access_allowed(snapshot.tombstones, subject_id)
    ):
        return False
    return store.consume_and_perform(
        _governance_permit(snapshot, subject_id, "visibility"), action
    )


def perform_physical_purge_from_store(
    store: PhysicalPurgeAuthority,
    subject_id: Uuid7,
    governance: RestoreLifecycle,
    resolver: RestoreGovernanceResolver,
    action: Callable[[], None],
) -> bool:
    """Perform purge only through an authority that rechecks current activation."""
    snapshot = store.read_snapshot()
    if snapshot.revision < 1 or not physical_purge_allowed(
        snapshot.tombstones,
        snapshot.holds,
        subject_id,
        governance,
        resolver,
    ):
        return False
    if (
        governance.backup_sha256 is None
        or governance.activation_receipt_sha256 is None
    ):
        return False
    return store.resolve_activation_consume_and_perform(
        PhysicalPurgePermit(
            governance=_governance_permit(snapshot, subject_id, "purge"),
            backup_sha256=governance.backup_sha256,
            restore_epoch=governance.restore_epoch,
            activation_receipt_sha256=governance.activation_receipt_sha256,
        ),
        action,
    )


def physical_purge_allowed(
    tombstones: tuple[TombstoneRecord, ...],
    holds: tuple[HoldRecord, ...],
    subject_id: Uuid7,
    governance: RestoreLifecycle,
    resolver: RestoreGovernanceResolver,
) -> bool:
    """Allow purge only from a freshly resolved activated snapshot."""
    if governance.phase != "activated":
        return False
    try:
        validate_restore_authority(governance, resolver)
        _validate_activation_receipt(governance, resolver)
    except RecoveryProtocolError:
        return False
    if not _governance_snapshot_matches(tombstones, holds, governance):
        return False
    subject_tombstones = tuple(
        record for record in tombstones if record.subject_id == subject_id
    )
    subject_holds = tuple(record for record in holds if record.subject_id == subject_id)
    return bool(subject_tombstones) and (
        not subject_holds or not subject_holds[-1].active
    )


def _governance_snapshot_matches(
    tombstones: tuple[TombstoneRecord, ...],
    holds: tuple[HoldRecord, ...],
    governance: RestoreLifecycle,
) -> bool:
    """Require both complete supplied streams to match the activated snapshot."""
    return _stream_matches_snapshot(
        tombstones,
        governance.replayed_tombstone_high_watermark,
        governance.tombstone_stream_sha256,
    ) and _stream_matches_snapshot(
        holds,
        governance.replayed_hold_high_watermark,
        governance.hold_stream_sha256,
    )


def _stream_matches_snapshot(
    records: tuple[TombstoneRecord, ...] | tuple[HoldRecord, ...],
    high_watermark: int,
    expected_digest: Sha256 | None,
) -> bool:
    """Require the complete ordered stream bound into the activated restore."""
    if expected_digest is None or len(records) != high_watermark:
        return False
    if tuple(record.sequence for record in records) != tuple(
        range(1, high_watermark + 1)
    ):
        return False
    return _stream_digest(records) == expected_digest


def _stream_digest(
    records: tuple[TombstoneRecord, ...] | tuple[HoldRecord, ...],
) -> str:
    """Hash the exact canonical event stream, including its supplied order."""
    return hashlib.sha256(
        json.dumps(
            [record.model_dump(mode="json") for record in records],
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
    ).hexdigest()


def perform_break_glass_action(
    authority: BreakGlassActionAuthority,
    request: BreakGlassActionRequest,
    action: Callable[[], None],
) -> None:
    """Delegate grant expiry and consumption to the authoritative transaction."""
    _require_utc(request.occurred_at)
    if (
        request.subject_id != request.grant.subject_id
        or not authority.resolve_consume_and_perform(request, action)
    ):
        _reject(
            BREAK_GLASS_UNAUTHORIZED,
            str(request.grant.grant_id),
            str(request.subject_id),
        )


def validate_restore_authority(
    lifecycle: RestoreLifecycle, resolver: RestoreGovernanceResolver
) -> None:
    """Resolve every manifest, source, and named receipt root independently."""
    manifest = lifecycle.governance_manifest
    if manifest is None or lifecycle.backup_sha256 is None:
        _reject(RESTORE_MANIFEST_MISMATCH, "missing", "required")
    if resolver.resolve_manifest_anchor(
        lifecycle.backup_sha256, lifecycle.restore_epoch
    ) != restore_manifest_digest(manifest):
        _reject(RESTORE_MANIFEST_ANCHOR_MISMATCH, "untrusted", "manifest")
    if resolver.resolve_source_governance_root(
        lifecycle.backup_sha256, lifecycle.restore_epoch
    ) != manifest.source_governance_root_sha256:
        _reject(RESTORE_MANIFEST_MISMATCH, "source-root", "manifest")
    if resolver.resolve_tombstone_stream_root(
        lifecycle.backup_sha256, lifecycle.restore_epoch
    ) != manifest.tombstone_stream_sha256:
        _reject(TOMBSTONE_SNAPSHOT_MISMATCH, "canonical-root", "manifest")
    if resolver.resolve_hold_stream_root(
        lifecycle.backup_sha256, lifecycle.restore_epoch
    ) != manifest.hold_stream_sha256:
        _reject(HOLD_SNAPSHOT_MISMATCH, "canonical-root", "manifest")
    resolved_receipts = tuple(
        resolver.resolve_deletion_receipt_root(
            system, lifecycle.backup_sha256, lifecycle.restore_epoch
        )
        for system in manifest.required_deletion_systems
    )
    if (
        any(root is None for root in resolved_receipts)
        or tuple(resolved_receipts) != manifest.deletion_receipt_roots
        or len(set(manifest.deletion_receipt_roots))
        != len(manifest.deletion_receipt_roots)
    ):
        _reject(DELETION_RECEIPT_MISMATCH, "receipt-root", "manifest")


def advance_restore_authoritatively(
    lifecycle: RestoreLifecycle,
    phase: RestorePhase,
    resolver: RestoreGovernanceResolver,
) -> RestoreLifecycle:
    """Advance only after independent authority validates activation inputs."""
    if phase in {"ready", "activated"}:
        validate_restore_authority(lifecycle, resolver)
        backup_sha256 = lifecycle.backup_sha256
        if backup_sha256 is None:
            _reject(BACKUP_DIGEST_UNVERIFIED, "missing", phase)
        activation_phase = cast("Literal['ready', 'activated']", phase)
        receipt = resolver.resolve_activation_receipt(
            backup_sha256,
            lifecycle.restore_epoch,
            activation_phase,
        )
        if receipt is None:
            _reject(RESTORE_MANIFEST_ANCHOR_MISMATCH, "missing", phase)
        lifecycle = lifecycle.model_copy(
            update={"activation_receipt_sha256": receipt}
        )
    return _advance_restore(lifecycle, phase)


def advance_restore(
    lifecycle: RestoreLifecycle, phase: RestorePhase
) -> RestoreLifecycle:
    """Advance inert or failure phases; activation requires independent authority."""
    if phase in {"ready", "activated"}:
        _reject(RESTORE_MANIFEST_ANCHOR_MISMATCH, lifecycle.phase, phase)
    return _advance_restore(lifecycle, phase)


def _advance_restore(
    lifecycle: RestoreLifecycle, phase: RestorePhase
) -> RestoreLifecycle:
    """Advance a restore after its caller has supplied the required authority."""
    transitions: dict[RestorePhase, set[RestorePhase]] = {
        "restoring": {"replaying_governance", "failed"},
        "replaying_governance": {"validating", "failed"},
        "validating": {"ready", "failed"},
        "ready": {"activated", "failed"},
        "activated": set[RestorePhase](),
        "failed": set[RestorePhase](),
    }
    if phase not in transitions[lifecycle.phase]:
        _reject(INVALID_RESTORE_TRANSITION, lifecycle.phase, phase)
    if phase in {"ready", "activated"}:
        _validate_restore(lifecycle)
    return lifecycle.model_copy(update={"phase": phase})


def _validate_restore(lifecycle: RestoreLifecycle) -> None:
    _validate_restore_inert_backup(lifecycle)
    _validate_restore_governance(lifecycle)
    _validate_restore_receipts(lifecycle)


def _validate_restore_inert_backup(lifecycle: RestoreLifecycle) -> None:
    """Require an inert restore with a verified backup digest."""
    if lifecycle.workers_enabled or lifecycle.egress_enabled:
        _reject(RESTORE_NOT_INERT, "enabled", "ready")
    if not lifecycle.backup_digest_verified:
        _reject(BACKUP_DIGEST_UNVERIFIED, "false", "ready")
    if (
        lifecycle.backup_sha256 is None
        or lifecycle.verified_backup_sha256 != lifecycle.backup_sha256
    ):
        _reject(
            BACKUP_DIGEST_MISMATCH,
            str(lifecycle.verified_backup_sha256),
            str(lifecycle.backup_sha256),
        )


def _validate_restore_governance(lifecycle: RestoreLifecycle) -> None:
    """Require replayed governance to equal an independently anchored baseline."""
    manifest = lifecycle.governance_manifest
    anchor = lifecycle.governance_manifest_anchor_sha256
    if manifest is None or anchor is None:
        _reject(RESTORE_MANIFEST_ANCHOR_MISMATCH, "missing", "required")
    if restore_manifest_digest(manifest) != anchor:
        _reject(RESTORE_MANIFEST_ANCHOR_MISMATCH, "mismatch", "required")
    if lifecycle.backup_sha256 != manifest.backup_sha256:
        _reject(
            BACKUP_DIGEST_MISMATCH,
            str(lifecycle.backup_sha256),
            manifest.backup_sha256,
        )
    if lifecycle.restore_epoch != manifest.restore_epoch:
        _reject(
            RESTORE_MANIFEST_MISMATCH,
            str(lifecycle.restore_epoch),
            str(manifest.restore_epoch),
        )
    if (
        lifecycle.tombstone_high_watermark != manifest.tombstone_high_watermark
        or lifecycle.replayed_tombstone_high_watermark
        != manifest.tombstone_high_watermark
        or lifecycle.tombstone_stream_sha256 != manifest.tombstone_stream_sha256
    ):
        _reject(TOMBSTONE_SNAPSHOT_MISMATCH, "replayed", "anchored")
    if (
        lifecycle.hold_high_watermark != manifest.hold_high_watermark
        or lifecycle.replayed_hold_high_watermark != manifest.hold_high_watermark
        or lifecycle.hold_stream_sha256 != manifest.hold_stream_sha256
    ):
        _reject(HOLD_SNAPSHOT_MISMATCH, "replayed", "anchored")


def _validate_restore_receipts(lifecycle: RestoreLifecycle) -> None:
    """Require receipt coverage and quarantine/invariant results from the manifest."""
    manifest = lifecycle.governance_manifest
    if manifest is None:
        _reject(RESTORE_MANIFEST_MISMATCH, "missing", "required")
    if tuple(lifecycle.required_deletion_systems) != manifest.required_deletion_systems:
        _reject(DELETION_RECEIPT_MISMATCH, "systems", "anchored")
    if tuple(lifecycle.deletion_receipt_systems) != manifest.required_deletion_systems:
        _reject(DELETION_RECEIPT_MISMATCH, "receipts", "anchored")
    if (
        not lifecycle.quarantined_transient_records
        or not manifest.quarantined_transient_records
    ):
        _reject(TRANSIENT_RESTORE_STATE, "unquarantined", "ready")
    if lifecycle.invariant_report_sha256 != manifest.invariant_report_sha256:
        _reject(INVARIANT_REPORT_MISSING, "mismatch", "anchored")
def _validate_activation_receipt(
    lifecycle: RestoreLifecycle, resolver: RestoreGovernanceResolver
) -> None:
    """Require a current independent receipt before activation use."""
    backup_sha256 = lifecycle.backup_sha256
    if lifecycle.phase not in {"ready", "activated"} or backup_sha256 is None:
        _reject(RESTORE_MANIFEST_ANCHOR_MISMATCH, "receipt", lifecycle.phase)
    activation_phase = cast(
        "Literal['ready', 'activated']",
        lifecycle.phase,
    )
    resolved_receipt = resolver.resolve_activation_receipt(
        backup_sha256,
        lifecycle.restore_epoch,
        activation_phase,
    )
    if (
        lifecycle.activation_receipt_sha256 is None
        or resolved_receipt is None
        or lifecycle.activation_receipt_sha256 != resolved_receipt
    ):
        _reject(RESTORE_MANIFEST_ANCHOR_MISMATCH, "receipt", lifecycle.phase)



