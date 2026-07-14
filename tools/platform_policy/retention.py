"""Tenant-isolated, append-only retention governance store."""

from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta
from functools import wraps
from secrets import token_urlsafe
from threading import RLock
from typing import TYPE_CHECKING, Concatenate, Final, Protocol, final, override

from .models import (
    CANDIDATES_MUST_NOT_BE_EMPTY,
    REQUIRED_DELETION_SYSTEMS,
    AuditDraft,
    BreakGlassGrant,
    BreakGlassRequest,
    BreakGlassUseCommand,
    CandidateManifest,
    DeletionAttestationVerifierSet,
    ExpiryReceipt,
    HmacDeletionAttestationVerifier,
    HoldPlaceCommand,
    LegalHold,
    RetentionCompletionError,
    RetentionRun,
    build_audit_record,
    candidate_manifest_digest,
    canonical_sha256,
    completion_digest,
    require_utc,
    retention_policy_digest,
    run_payload,
    verify_audit_record,
    verify_retention_run,
)

if TYPE_CHECKING:
    from collections.abc import Callable

    from .models import (
        AuditRecord,
        Clock,
        DeletionAttestationVerifier,
        OperationalLog,
        PolicyChange,
        RetentionCompletionCommand,
        RetentionPolicy,
        RetentionPrincipal,
    )

CAPABILITY_APPEND: Final[str] = "retention.append"
CAPABILITY_READ_AUDIT: Final[str] = "audit.read"
CAPABILITY_PLACE_HOLD: Final[str] = "legal_hold.place"
CAPABILITY_RELEASE_HOLD: Final[str] = "legal_hold.release"
CAPABILITY_APPROVE_BREAK_GLASS: Final[str] = "break_glass.approve"
CAPABILITY_EXPIRE: Final[str] = "retention.expire"
CAPABILITY_START_RUN: Final[str] = "retention.run.start"
CAPABILITY_RESUME_RUN: Final[str] = "retention.run.resume"
CAPABILITY_COMPLETE_RUN: Final[str] = "retention.run.complete"
COMPLIANCE_OPERATOR_ROLE: Final[str] = "compliance_operator"
BREAK_GLASS_ALLOWED_ACTIONS: Final[frozenset[str]] = frozenset({"read_metadata"})
TENANT_ID_MUST_NOT_BE_EMPTY: Final[str] = "tenant_id must not be empty"
CLOCK_MUST_BE_MONOTONIC: Final[str] = "clock must be monotonic"
RECORD_ID_MUST_NOT_BE_EMPTY: Final[str] = "record ID must not be empty"
RECEIPT_VERIFIER_MUST_COVER_SYSTEMS: Final[str] = (
    "receipt verifier must cover every fixed deletion system"
)
OPAQUE_RECEIPT_VERIFIER_REQUIRED: Final[str] = (
    "production retention store requires opaque or asymmetric deletion verifiers"
)
POLICY_NOT_EFFECTIVE: Final[str] = "retention policy is not yet effective"
RESTORE_EPOCH_AUTHORITY_ERROR: Final[str] = "restore epoch authority rejected request"


class RestoreEpochAuthority(Protocol):
    """Resolve the current non-restorable break-glass epoch."""

    def current_epoch(self, tenant_id: str) -> int:
        """Return the durable current epoch for one tenant."""
        ...


def _validated_receipt_verifier(value: object) -> DeletionAttestationVerifierSet:
    if not isinstance(value, DeletionAttestationVerifierSet):
        raise TypeError(RECEIPT_VERIFIER_MUST_COVER_SYSTEMS)
    if any(
        isinstance(verifier, HmacDeletionAttestationVerifier)
        for verifier in value.verifiers
    ):
        raise TypeError(OPAQUE_RECEIPT_VERIFIER_REQUIRED)
    return value


def _synchronized[**P, R](
    method: Callable[Concatenate[RetentionStore, P], R],
) -> Callable[Concatenate[RetentionStore, P], R]:
    """Serialize one public store operation with the instance lock."""

    @wraps(method)
    def wrapped(
        self: RetentionStore,
        /,
        *args: P.args,
        **kwargs: P.kwargs,
    ) -> R:
        with self.synchronization_lock():
            return method(self, *args, **kwargs)

    return wrapped


@final
class RetentionAuthorizationError(PermissionError):
    """Reject a request that lacks tenant or role authorization."""

    def __init__(self, principal_id: str, capability: str) -> None:
        """Initialize a stable authorization error."""
        self.principal_id = principal_id
        self.capability = capability
        super().__init__(principal_id, capability)


@final
class BreakGlassDeniedError(PermissionError):
    """Reject invalid emergency-access state transitions."""

    def __init__(self, grant_id: str) -> None:
        """Initialize a stable break-glass denial error."""
        self.grant_id = grant_id
        super().__init__(grant_id)


@final
class DuplicateRecordIdError(ValueError):
    """Reject reuse of an immutable store identifier."""

    def __init__(self, record_id: str) -> None:
        """Initialize a stable duplicate identifier error."""
        self.record_id = record_id
        super().__init__(record_id)


@final
class RecordNotFoundError(LookupError):
    """Report a missing tenant-bound record."""

    def __init__(self, record_id: str) -> None:
        """Initialize a stable missing record error."""
        self.record_id = record_id
        super().__init__(record_id)


@final
class PolicyAuditRequiredError(RuntimeError):
    """Require policy-change audit evidence."""

    def __init__(self, policy_version: str) -> None:
        """Initialize a stable policy-audit error."""
        self.policy_version = policy_version
        super().__init__(policy_version)


@final
class ActiveHoldError(ValueError):
    """Reject a second active hold for one tenant scope."""

    def __init__(self, tenant_id: str, scope_id: str) -> None:
        """Initialize a stable active-hold error."""
        self.tenant_id = tenant_id
        self.scope_id = scope_id
        super().__init__(tenant_id, scope_id)


@final
@dataclass(frozen=True, slots=True)
class AuditEventCommand:
    """Bind a governance event to its principal, subject, and timestamp."""

    event_id: str
    event: str
    principal: RetentionPrincipal
    subject_id: str
    scope_id: str
    state: str
    occurred_at: datetime


@final
@dataclass(frozen=True, slots=True)
class BreakGlassDenialContext:
    """Bind a denied break-glass transition to its audit identity."""

    event_id: str
    event: str
    principal: RetentionPrincipal
    grant_id: str
    resource_id: str
    state: str

    def audit_command(self, occurred_at: datetime) -> AuditEventCommand:
        """Build the immutable denied-transition audit command."""
        return AuditEventCommand(
            event_id=self.event_id,
            event=self.event,
            principal=self.principal,
            subject_id=self.grant_id,
            scope_id=self.resource_id,
            state=self.state,
            occurred_at=occurred_at,
        )


@final
class RetentionStore:
    """Store tenant-bound retention state with monotonic time."""

    __slots__ = (
        "_audits",
        "_expired_ids",
        "_grants",
        "_hold_history",
        "_holds",
        "_idempotency_keys",
        "_last_now",
        "_lock",
        "_operational",
        "_policy",
        "_receipt_verifier",
        "_reserved_ids",
        "_restore_epoch_authority",
        "_runs",
        "_tenant_id",
        "_used_ids",
    )

    def __init__(
        self,
        tenant_id: str,
        policy: RetentionPolicy,
        *,
        receipt_verifier: object,
        restore_epoch_authority: RestoreEpochAuthority,
    ) -> None:
        """Initialize tenant policy, verifier, and external restore-epoch roots."""
        if not tenant_id:
            raise ValueError(TENANT_ID_MUST_NOT_BE_EMPTY)
        verified_receipt_verifier = _validated_receipt_verifier(receipt_verifier)
        self._lock = RLock()
        self._tenant_id: str = tenant_id
        self._policy: RetentionPolicy = policy
        self._receipt_verifier: DeletionAttestationVerifier = verified_receipt_verifier
        self._restore_epoch_authority: RestoreEpochAuthority = restore_epoch_authority
        self._operational: list[OperationalLog] = []
        self._audits: list[AuditRecord] = []
        self._holds: dict[tuple[str, str], LegalHold] = {}
        self._hold_history: dict[tuple[str, str], list[LegalHold]] = {}
        self._grants: dict[str, BreakGlassGrant] = {}
        self._runs: dict[str, RetentionRun] = {}
        self._idempotency_keys: dict[str, str] = {}
        self._used_ids: set[str] = set()
        self._expired_ids: set[str] = set()
        self._reserved_ids: set[str] = set()
        self._last_now: datetime | None = None

    @override
    def __setattr__(self, name: str, value: object) -> None:
        """Prevent callers from rebinding tenant, policy, or verifier trust roots."""
        if name in {"tenant_id", "policy"}:
            message = f"{name} is immutable"
            raise AttributeError(message)
        if name in {
            "_tenant_id",
            "_policy",
            "_receipt_verifier",
            "_restore_epoch_authority",
        } and hasattr(self, name):
            message = f"{name} is immutable"
            raise AttributeError(message)
        object.__setattr__(self, name, value)

    def synchronization_lock(self) -> RLock:
        """Return the store lock used by public operation decorators."""
        return self._lock

    @property
    def policy(self) -> RetentionPolicy:
        """Return the immutable policy binding."""
        return self._policy

    @property
    def tenant_id(self) -> str:
        """Return the immutable tenant binding."""
        return self._tenant_id

    def _authorize(self, principal: RetentionPrincipal, capability: str) -> None:
        if principal.tenant_id != self.tenant_id:
            raise RetentionAuthorizationError(principal.principal_id, "tenant.match")
        if COMPLIANCE_OPERATOR_ROLE not in principal.roles:
            raise RetentionAuthorizationError(principal.principal_id, capability)

    def _validate_now(self, clock: Clock) -> datetime:
        """Return a valid monotonic time without consuming it."""
        now = clock.now()
        require_utc(now)
        if self._last_now is not None and now < self._last_now:
            raise ValueError(CLOCK_MUST_BE_MONOTONIC)
        if now < self.policy.effective_at:
            raise ValueError(POLICY_NOT_EFFECTIVE)
        return now

    def _now(self, clock: Clock) -> datetime:
        """Return and consume a valid monotonic time."""
        now = self._validate_now(clock)
        self._last_now = now
        return now

    def _require_unused_id(self, value: str) -> None:
        if not value:
            raise ValueError(RECORD_ID_MUST_NOT_BE_EMPTY)
        if value in self._used_ids:
            raise DuplicateRecordIdError(value)

    def _append_event(self, command: AuditEventCommand) -> None:
        self._require_unused_id(command.event_id)
        record = build_audit_record(
            AuditDraft(
                record_id=command.event_id,
                tenant_id=self.tenant_id,
                event=command.event,
                actor_id=command.principal.principal_id,
                subject_id=command.subject_id,
                scope_id=command.scope_id,
                reason=command.event,
                occurred_at=command.occurred_at,
                policy_version=self.policy.version,
                state=command.state,
            )
        )
        self._audits.append(record)
        self._used_ids.add(command.event_id)

    def _append_break_glass_denial(
        self,
        context: BreakGlassDenialContext,
        occurred_at: datetime,
    ) -> None:
        """Append a denied emergency transition without changing grant state."""
        self._append_event(context.audit_command(occurred_at))

    def _current_restore_epoch(self) -> int:
        epoch = self._restore_epoch_authority.current_epoch(self.tenant_id)
        if type(epoch) is not int or epoch < 1:
            raise BreakGlassDeniedError(RESTORE_EPOCH_AUTHORITY_ERROR)
        return epoch

    def _authorize_break_glass_transition(
        self,
        principal: RetentionPrincipal,
        capability: str,
        clock: Clock,
        *,
        payload_tenant_id: str | None = None,
        restore_epoch: int | None = None,
    ) -> datetime:
        """Authorize every external binding before consuming store time."""
        self._authorize(principal, capability)
        if payload_tenant_id is not None and payload_tenant_id != self.tenant_id:
            raise RetentionAuthorizationError(principal.principal_id, "tenant.match")
        if restore_epoch is not None and restore_epoch != self._current_restore_epoch():
            raise BreakGlassDeniedError(RESTORE_EPOCH_AUTHORITY_ERROR)
        return self._now(clock)

    def _record_scope(self, record_id: str) -> str | None:
        for record in self._operational:
            if record.record_id == record_id:
                return record.scope_id
        for record in self._audits:
            if record.record_id == record_id:
                return record.scope_id
        return None

    def _held_scopes(self, now: datetime) -> set[str]:
        return {
            scope_id
            for (tenant_id, scope_id), hold in self._holds.items()
            if tenant_id == self.tenant_id
            and hold.placed_at <= now
            and (hold.released_at is None or hold.released_at > now)
        }

    def _deletion_intersects_hold(
        self,
        scope_id: str,
        attestations: tuple[object, ...],
    ) -> bool:
        """Fail closed when evidence falls in any historical hold interval."""
        latest_by_hold = {
            hold.hold_id: hold
            for hold in self._hold_history.get((self.tenant_id, scope_id), [])
        }
        for hold in latest_by_hold.values():
            for attestation in attestations:
                deleted_at = getattr(attestation, "deleted_at", None)
                if deleted_at is None:
                    return True
                if deleted_at >= hold.placed_at and (
                    hold.released_at is None or deleted_at <= hold.released_at
                ):
                    return True
        return False

    def _eligible_ids(self, now: datetime) -> tuple[tuple[str, ...], tuple[str, ...]]:
        held_scopes = self._held_scopes(now)
        operational_cutoff = now - timedelta(days=self.policy.operational_days)
        audit_cutoff = now - timedelta(days=self.policy.audit_days)
        operational_ids = tuple(
            record.record_id
            for record in self._operational
            if record.record_id in self._expired_ids
            and record.record_id not in self._reserved_ids
            and record.scope_id not in held_scopes
            and record.occurred_at <= operational_cutoff
        )
        audit_ids = tuple(
            record.record_id
            for record in self._audits
            if record.record_id in self._expired_ids
            and record.record_id not in self._reserved_ids
            and record.scope_id not in held_scopes
            and record.occurred_at <= audit_cutoff
        )
        return operational_ids, audit_ids

    @_synchronized
    def append_operational(
        self,
        record: OperationalLog,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> None:
        """Append a tenant-bound operational record."""
        self._authorize(principal, CAPABILITY_APPEND)
        if record.tenant_id != self.tenant_id:
            raise RetentionAuthorizationError(principal.principal_id, "tenant.match")
        _ = self._now(clock)
        self._require_unused_id(record.record_id)
        self._operational.append(record)
        self._used_ids.add(record.record_id)

    @_synchronized
    def append_audit(
        self,
        record: AuditRecord,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> None:
        """Append an integrity-protected tenant-bound audit record."""
        self._authorize(principal, CAPABILITY_APPEND)
        if record.tenant_id != self.tenant_id:
            raise RetentionAuthorizationError(principal.principal_id, "tenant.match")
        _ = self._now(clock)
        if not verify_audit_record(record):
            raise RetentionAuthorizationError(principal.principal_id, "audit.integrity")
        self._require_unused_id(record.record_id)
        self._audits.append(record)
        self._used_ids.add(record.record_id)

    @_synchronized
    def operational_ids(
        self,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> tuple[str, ...]:
        """Return visible operational-log identifiers."""
        self._authorize(principal, CAPABILITY_READ_AUDIT)
        _ = self._now(clock)
        return tuple(
            record.record_id
            for record in self._operational
            if record.record_id not in self._expired_ids
        )

    @_synchronized
    def audit_ids(
        self,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> tuple[str, ...]:
        """Return visible audit-record identifiers."""
        self._authorize(principal, CAPABILITY_READ_AUDIT)
        _ = self._now(clock)
        return tuple(
            record.record_id
            for record in self._audits
            if record.record_id not in self._expired_ids
        )

    @_synchronized
    def audit_records(
        self,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> tuple[AuditRecord, ...]:
        """Return all visible integrity-protected audit records."""
        self._authorize(principal, CAPABILITY_READ_AUDIT)
        _ = self._now(clock)
        return tuple(
            record
            for record in self._audits
            if record.record_id not in self._expired_ids
        )

    @_synchronized
    def legal_hold_history(
        self,
        scope_id: str,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> tuple[LegalHold, ...]:
        """Return immutable revision history for one authorized tenant scope."""
        self._authorize(principal, CAPABILITY_READ_AUDIT)
        _ = self._now(clock)
        return tuple(self._hold_history.get((self.tenant_id, scope_id), []))

    @_synchronized
    def read_audit(
        self,
        record_id: str,
        principal: RetentionPrincipal,
        clock: Clock,
        request_id: str,
    ) -> AuditRecord:
        """Return an audit record and append a read-access event."""
        self._authorize(principal, CAPABILITY_READ_AUDIT)
        now = self._now(clock)
        for record in self._audits:
            if record.record_id == record_id and record_id not in self._expired_ids:
                self._append_event(
                    AuditEventCommand(
                        event_id=request_id,
                        event="audit.accessed",
                        principal=principal,
                        subject_id=record_id,
                        scope_id=record.scope_id,
                        state="read",
                        occurred_at=now,
                    )
                )
                return record
        raise RecordNotFoundError(record_id)

    @_synchronized
    def change_policy(
        self,
        change: PolicyChange,
        evidence: AuditRecord | None,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> None:
        """Apply a policy change supported by a valid audit record."""
        self._authorize(principal, "retention.policy.change")
        now = self._validate_now(clock)
        expected_state = (
            f"from={self.policy.version};to={change.policy.version};"
            f"policy_sha256={change.policy_digest};reason={change.reason}"
        )
        if (
            evidence is None
            or change.actor_id != principal.principal_id
            or change.occurred_at != now
            or evidence.tenant_id != self.tenant_id
            or evidence.event != "retention.policy.changed"
            or evidence.actor_id != principal.principal_id
            or evidence.subject_id != change.policy.version
            or evidence.reason != change.reason
            or evidence.scope_id != "policy"
            or evidence.occurred_at != change.occurred_at
            or evidence.policy_version != self.policy.version
            or evidence.state != expected_state
            or not verify_audit_record(evidence)
            or change.policy_digest != retention_policy_digest(change.policy)
        ):
            raise PolicyAuditRequiredError(change.policy.version)
        self._require_unused_id(evidence.record_id)
        self._last_now = now
        self._audits.append(evidence)
        self._used_ids.add(evidence.record_id)
        object.__setattr__(self, "_policy", change.policy)

    @_synchronized
    def place_legal_hold(
        self,
        command: HoldPlaceCommand,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> LegalHold:
        """Place a legal hold and record its governance event."""
        self._authorize(principal, CAPABILITY_PLACE_HOLD)
        now = self._validate_now(clock)
        if command.tenant_id != self.tenant_id:
            raise RetentionAuthorizationError(principal.principal_id, "tenant.match")
        key = (self.tenant_id, command.scope_id)
        existing = self._holds.get(key)
        if existing is not None and existing.released_at is None:
            raise ActiveHoldError(self.tenant_id, command.scope_id)
        if command.hold_id == command.event_id:
            raise DuplicateRecordIdError(command.event_id)
        self._require_unused_id(command.hold_id)
        self._require_unused_id(command.event_id)
        hold = LegalHold(
            hold_id=command.hold_id,
            tenant_id=self.tenant_id,
            scope_id=command.scope_id,
            placed_at=now,
            released_at=None,
            case_id=command.case_id,
            authority=command.authority,
            reason=command.reason,
        )
        event = AuditEventCommand(
            event_id=command.event_id,
            event="legal_hold.placed",
            principal=principal,
            subject_id=command.hold_id,
            scope_id=command.scope_id,
            state=(f"case={command.case_id};authority={command.authority};revision=1"),
            occurred_at=now,
        )
        self._last_now = now
        self._append_event(event)
        self._holds[key] = hold
        self._hold_history.setdefault(key, []).append(hold)
        self._used_ids.add(command.hold_id)
        return hold

    @_synchronized
    def release_legal_hold(
        self,
        hold_id: str,
        principal: RetentionPrincipal,
        clock: Clock,
        event_id: str,
        reason: str,
    ) -> LegalHold:
        """Release an active legal hold and record its governance event."""
        self._authorize(principal, CAPABILITY_RELEASE_HOLD)
        now = self._validate_now(clock)
        hold = next(
            (
                candidate
                for candidate in self._holds.values()
                if candidate.hold_id == hold_id
            ),
            None,
        )
        if hold is None or hold.released_at is not None:
            raise RecordNotFoundError(hold_id)
        released = replace(
            hold,
            released_at=now,
            reason=reason,
            revision=hold.revision + 1,
        )
        event = AuditEventCommand(
            event_id=event_id,
            event="legal_hold.released",
            principal=principal,
            subject_id=hold_id,
            scope_id=hold.scope_id,
            state=(
                f"case={hold.case_id};authority={hold.authority};"
                f"revision={released.revision}"
            ),
            occurred_at=now,
        )
        self._require_unused_id(event_id)
        self._last_now = now
        self._append_event(event)
        self._holds[(self.tenant_id, hold.scope_id)] = released
        self._hold_history[(self.tenant_id, hold.scope_id)].append(released)
        return released

    @_synchronized
    def expire(
        self,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> ExpiryReceipt:
        """Mark retention-eligible records as expired."""
        self._authorize(principal, CAPABILITY_EXPIRE)
        now = self._now(clock)
        held_scopes = self._held_scopes(now)
        operational_cutoff = now - timedelta(days=self.policy.operational_days)
        audit_cutoff = now - timedelta(days=self.policy.audit_days)
        operational_ids = tuple(
            record.record_id
            for record in self._operational
            if record.record_id not in self._expired_ids
            and record.scope_id not in held_scopes
            and record.occurred_at <= operational_cutoff
        )
        audit_ids = tuple(
            record.record_id
            for record in self._audits
            if record.record_id not in self._expired_ids
            and record.scope_id not in held_scopes
            and record.occurred_at <= audit_cutoff
        )
        self._expired_ids.update(operational_ids)
        self._expired_ids.update(audit_ids)
        receipt_payload: dict[str, object] = {
            "tenant_id": self.tenant_id,
            "policy_version": self.policy.version,
            "occurred_at": now.isoformat(),
            "operational_ids": operational_ids,
            "audit_ids": audit_ids,
        }
        return ExpiryReceipt(
            tenant_id=self.tenant_id,
            policy_version=self.policy.version,
            occurred_at=now,
            operational_ids=operational_ids,
            audit_ids=audit_ids,
            checksum_sha256=canonical_sha256(receipt_payload),
        )

    @_synchronized
    def request_break_glass(
        self,
        request: BreakGlassRequest,
        requester: RetentionPrincipal,
        clock: Clock,
    ) -> BreakGlassGrant:
        """Create a pending emergency-access grant."""
        context = BreakGlassDenialContext(
            event_id=request.event_id,
            event="break_glass.request.denied",
            principal=requester,
            grant_id=request.grant_id,
            resource_id=request.resource_id,
            state="authorization_denied",
        )
        now = self._authorize_break_glass_transition(
            requester,
            CAPABILITY_APPEND,
            clock,
            payload_tenant_id=request.tenant_id,
            restore_epoch=request.restore_epoch,
        )
        state = f"epoch={request.restore_epoch};expiry={request.expires_at.isoformat()}"
        if request.action not in BREAK_GLASS_ALLOWED_ACTIONS:
            self._append_break_glass_denial(
                replace(context, state=f"unsupported_action;{state}"),
                now,
            )
            raise BreakGlassDeniedError(request.grant_id)
        if request.expires_at <= now:
            self._append_break_glass_denial(
                replace(context, state=f"expired_request;{state}"),
                now,
            )
            raise BreakGlassDeniedError(request.grant_id)
        if request.grant_id == request.event_id or request.grant_id in self._used_ids:
            self._append_break_glass_denial(
                replace(context, state=f"duplicate_grant_id;{state}"),
                now,
            )
            raise DuplicateRecordIdError(request.grant_id)
        self._append_event(
            AuditEventCommand(
                event_id=request.event_id,
                event="break_glass.requested",
                principal=requester,
                subject_id=request.grant_id,
                scope_id=request.resource_id,
                state=(
                    f"epoch={request.restore_epoch};"
                    f"expiry={request.expires_at.isoformat()}"
                ),
                occurred_at=now,
            )
        )
        grant = BreakGlassGrant(
            grant_id=request.grant_id,
            tenant_id=self.tenant_id,
            resource_id=request.resource_id,
            action=request.action,
            restore_epoch=request.restore_epoch,
            requester_id=requester.principal_id,
            issued_at=now,
            expires_at=request.expires_at,
        )
        self._grants[request.grant_id] = grant
        self._used_ids.add(request.grant_id)
        return grant

    @_synchronized
    def approve_break_glass(
        self,
        grant_id: str,
        approver: RetentionPrincipal,
        clock: Clock,
        event_id: str,
    ) -> BreakGlassGrant:
        """Approve an eligible emergency-access grant."""
        context = BreakGlassDenialContext(
            event_id=event_id,
            event="break_glass.approval.denied",
            principal=approver,
            grant_id=grant_id,
            resource_id="break_glass",
            state="authorization_denied",
        )
        now = self._authorize_break_glass_transition(
            approver,
            CAPABILITY_APPROVE_BREAK_GLASS,
            clock,
        )
        grant = self._grants.get(grant_id)
        if grant is None:
            self._append_break_glass_denial(
                replace(context, state="grant_not_found"),
                now,
            )
            raise RecordNotFoundError(grant_id)
        if (
            grant.requester_id == approver.principal_id
            or grant.approver_id is not None
            or grant.revoked_at is not None
            or grant.expired_at is not None
            or now >= grant.expires_at
        ):
            self._append_break_glass_denial(
                replace(
                    context,
                    resource_id=grant.resource_id,
                    state=(
                        f"epoch={grant.restore_epoch};"
                        f"expiry={grant.expires_at.isoformat()}"
                    ),
                ),
                now,
            )
            raise BreakGlassDeniedError(grant_id)
        self._append_event(
            AuditEventCommand(
                event_id=event_id,
                event="break_glass.approved",
                principal=approver,
                subject_id=grant_id,
                scope_id=grant.resource_id,
                state=(
                    f"epoch={grant.restore_epoch};expiry={grant.expires_at.isoformat()}"
                ),
                occurred_at=now,
            )
        )
        approved = replace(grant, approver_id=approver.principal_id)
        self._grants[grant_id] = approved
        return approved

    @_synchronized
    def use_break_glass(
        self,
        use: BreakGlassUseCommand,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> bool:
        """Authorize an emergency-access use and record the result."""
        now = self._authorize_break_glass_transition(
            principal,
            CAPABILITY_APPEND,
            clock,
            payload_tenant_id=use.tenant_id,
            restore_epoch=use.restore_epoch,
        )
        grant = self._grants.get(use.grant_id)
        allowed = (
            grant is not None
            and grant.approver_id is not None
            and grant.requester_id == principal.principal_id
            and grant.tenant_id == use.tenant_id
            and grant.resource_id == use.resource_id
            and grant.action == use.action
            and grant.restore_epoch == use.restore_epoch
            and grant.revoked_at is None
            and grant.expired_at is None
            and now < grant.expires_at
        )
        self._append_event(
            AuditEventCommand(
                event_id=use.event_id,
                event=("break_glass.used" if allowed else "break_glass.denied"),
                principal=principal,
                subject_id=use.grant_id,
                scope_id=use.resource_id,
                state=f"epoch={use.restore_epoch}",
                occurred_at=now,
            )
        )
        if not allowed:
            raise BreakGlassDeniedError(use.grant_id)
        return True

    @_synchronized
    def revoke_break_glass(
        self,
        grant_id: str,
        principal: RetentionPrincipal,
        clock: Clock,
        event_id: str,
    ) -> BreakGlassGrant:
        """Revoke an active emergency-access grant."""
        context = BreakGlassDenialContext(
            event_id=event_id,
            event="break_glass.revocation.denied",
            principal=principal,
            grant_id=grant_id,
            resource_id="break_glass",
            state="authorization_denied",
        )
        now = self._authorize_break_glass_transition(
            principal,
            CAPABILITY_APPROVE_BREAK_GLASS,
            clock,
        )
        grant = self._grants.get(grant_id)
        if grant is None:
            self._append_break_glass_denial(
                replace(context, state="grant_not_found"),
                now,
            )
            raise RecordNotFoundError(grant_id)
        if (
            grant.revoked_at is not None
            or grant.expired_at is not None
            or now >= grant.expires_at
        ):
            self._append_break_glass_denial(
                replace(
                    context,
                    resource_id=grant.resource_id,
                    state=(
                        f"epoch={grant.restore_epoch};"
                        f"expiry={grant.expires_at.isoformat()}"
                    ),
                ),
                now,
            )
            raise BreakGlassDeniedError(grant_id)
        self._append_event(
            AuditEventCommand(
                event_id=event_id,
                event="break_glass.revoked",
                principal=principal,
                subject_id=grant_id,
                scope_id=grant.resource_id,
                state=(
                    f"epoch={grant.restore_epoch};expiry={grant.expires_at.isoformat()}"
                ),
                occurred_at=now,
            )
        )
        revoked = replace(grant, revoked_at=now)
        self._grants[grant_id] = revoked
        return revoked

    @_synchronized
    def expire_break_glass(
        self,
        grant_id: str,
        principal: RetentionPrincipal,
        clock: Clock,
        event_id: str,
    ) -> BreakGlassGrant:
        """Mark an expired emergency-access grant as unavailable."""
        context = BreakGlassDenialContext(
            event_id=event_id,
            event="break_glass.expiry.denied",
            principal=principal,
            grant_id=grant_id,
            resource_id="break_glass",
            state="authorization_denied",
        )
        now = self._authorize_break_glass_transition(
            principal,
            CAPABILITY_EXPIRE,
            clock,
        )
        grant = self._grants.get(grant_id)
        if grant is None:
            self._append_break_glass_denial(
                replace(context, state="grant_not_found"),
                now,
            )
            raise RecordNotFoundError(grant_id)
        if (
            grant.revoked_at is not None
            or grant.expired_at is not None
            or now < grant.expires_at
        ):
            self._append_break_glass_denial(
                replace(
                    context,
                    resource_id=grant.resource_id,
                    state=(
                        f"epoch={grant.restore_epoch};"
                        f"expiry={grant.expires_at.isoformat()}"
                    ),
                ),
                now,
            )
            raise BreakGlassDeniedError(grant_id)
        self._append_event(
            AuditEventCommand(
                event_id=event_id,
                event="break_glass.expired",
                principal=principal,
                subject_id=grant_id,
                scope_id=grant.resource_id,
                state=(
                    f"epoch={grant.restore_epoch};expiry={grant.expires_at.isoformat()}"
                ),
                occurred_at=now,
            )
        )
        expired = replace(grant, expired_at=now)
        self._grants[grant_id] = expired
        return expired

    @_synchronized
    def start_retention_run(
        self,
        run_id: str,
        idempotency_key: str,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> RetentionRun:
        """Create or replay a retention run for eligible records."""
        self._authorize(principal, CAPABILITY_START_RUN)
        now = self._now(clock)
        existing_run_id = self._idempotency_keys.get(idempotency_key)
        if existing_run_id is not None:
            if existing_run_id != run_id:
                raise DuplicateRecordIdError(run_id)
            return self._runs[existing_run_id]
        self._require_unused_id(run_id)
        operational_ids, audit_ids = self._eligible_ids(now)
        if not operational_ids and not audit_ids:
            raise ValueError(CANDIDATES_MUST_NOT_BE_EMPTY)
        challenge = token_urlsafe(32)
        manifest_digest = candidate_manifest_digest(
            CandidateManifest(
                tenant_id=self.tenant_id,
                run_id=run_id,
                policy_version=self.policy.version,
                cutoff_at=now,
                operational_ids=operational_ids,
                audit_ids=audit_ids,
                required_systems=REQUIRED_DELETION_SYSTEMS,
                challenge=challenge,
            )
        )
        run = RetentionRun(
            run_id=run_id,
            tenant_id=self.tenant_id,
            idempotency_key=idempotency_key,
            cutoff_at=now,
            policy_version=self.policy.version,
            attempts=1,
            operational_ids=operational_ids,
            audit_ids=audit_ids,
            challenge=challenge,
            candidate_manifest_digest=manifest_digest,
        )
        self._runs[run_id] = run
        self._idempotency_keys[idempotency_key] = run_id
        self._used_ids.add(run_id)
        self._reserved_ids.update(operational_ids)
        self._reserved_ids.update(audit_ids)
        return run

    @_synchronized
    def retention_run(
        self,
        run_id: str,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> RetentionRun:
        """Return a retention run by its identifier."""
        self._authorize(principal, CAPABILITY_READ_AUDIT)
        _ = self._now(clock)
        run = self._runs.get(run_id)
        if run is None:
            raise RecordNotFoundError(run_id)
        return run

    @_synchronized
    def resume_retention_run(
        self,
        run_id: str,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> RetentionRun:
        """Resume an incomplete retention run."""
        self._authorize(principal, CAPABILITY_RESUME_RUN)
        _ = self._now(clock)
        run = self._runs.get(run_id)
        if run is None:
            raise RecordNotFoundError(run_id)
        if run.completed_at is not None:
            return run
        resumed = replace(run, attempts=run.attempts + 1)
        self._runs[run_id] = resumed
        return resumed

    @_synchronized
    def complete_retention_run(
        self,
        completion: RetentionCompletionCommand,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> RetentionRun:
        """Complete a retention run with exact independently verified receipts."""
        self._authorize(principal, CAPABILITY_COMPLETE_RUN)
        if any(
            attestation.tenant_id != self.tenant_id
            for attestation in completion.attestations
        ):
            raise RetentionCompletionError
        now = self._now(clock)
        run = self._runs.get(completion.run_id)
        if run is None:
            raise RecordNotFoundError(completion.run_id)
        received_digest = completion_digest(completion.attestations)
        if run.completed_at is not None:
            if run.completion_digest != received_digest:
                raise RetentionCompletionError
            return run
        candidate_ids = run.operational_ids + run.audit_ids
        held_scopes = self._held_scopes(now)
        for record_id in candidate_ids:
            scope_id = self._record_scope(record_id)
            if (
                scope_id is None
                or scope_id in held_scopes
                or self._deletion_intersects_hold(scope_id, completion.attestations)
            ):
                delayed = replace(run, attempts=run.attempts + 1)
                self._runs[run.run_id] = delayed
                return delayed
        expected_coordinates = {
            (record_id, system)
            for record_id in candidate_ids
            for system in run.required_systems
        }
        actual_coordinates = tuple(
            (attestation.record_id, attestation.system)
            for attestation in completion.attestations
        )
        if (
            len(actual_coordinates) != len(set(actual_coordinates))
            or set(actual_coordinates) != expected_coordinates
        ):
            raise RetentionCompletionError
        if any(
            attestation.tenant_id != self.tenant_id
            or attestation.run_id != run.run_id
            or attestation.challenge != run.challenge
            or attestation.candidate_manifest_digest != run.candidate_manifest_digest
            or not run.cutoff_at < attestation.deleted_at <= now
            or not self._receipt_verifier.verify(attestation)
            for attestation in completion.attestations
        ):
            raise RetentionCompletionError
        prospective = replace(
            run,
            attempts=run.attempts + 1,
            receipts=completion.attestations,
            completion_digest=received_digest,
        )
        completed_payload = run_payload(prospective)
        completed_payload["completed_at"] = now.isoformat()
        completed = replace(
            run,
            attempts=prospective.attempts,
            receipts=prospective.receipts,
            completed_at=now,
            checksum_sha256=canonical_sha256(completed_payload),
            completion_digest=prospective.completion_digest,
        )
        self._operational = [
            record
            for record in self._operational
            if record.record_id not in candidate_ids
        ]
        self._audits = [
            record for record in self._audits if record.record_id not in candidate_ids
        ]
        self._expired_ids.difference_update(candidate_ids)
        self._reserved_ids.difference_update(candidate_ids)
        self._runs[run.run_id] = completed
        return completed

    @_synchronized
    def verify_run(
        self,
        run: RetentionRun,
        principal: RetentionPrincipal,
        clock: Clock,
    ) -> bool:
        """Validate a retention run using the injected receipt verifier."""
        self._authorize(principal, CAPABILITY_READ_AUDIT)
        _ = self._now(clock)
        stored = self._runs.get(run.run_id)
        return (
            run.tenant_id == self.tenant_id
            and stored == run
            and verify_retention_run(run, self._receipt_verifier)
        )
