"""Immutable tenant-bound records for retention governance."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import TYPE_CHECKING, Final, Protocol, final

if TYPE_CHECKING:
    from collections.abc import Callable

DEFAULT_OPERATIONAL_DAYS: Final[int] = 90
DEFAULT_AUDIT_DAYS: Final[int] = 365
REVISION_MUST_BE_POSITIVE: Final[str] = "revision must be positive"
RELEASED_AT_MUST_NOT_PRECEDE_PLACED_AT: Final[str] = (
    "released_at must not precede placed_at"
)
EXPIRY_MUST_FOLLOW_ISSUANCE: Final[str] = "expires_at must follow issued_at"
ATTEMPTS_MUST_BE_POSITIVE: Final[str] = "attempts must be positive"
REQUIRED_SYSTEMS_MUST_BE_FIXED: Final[str] = "required_systems must be fixed"
CANDIDATE_IDS_MUST_BE_UNIQUE: Final[str] = "candidate IDs must be unique"
EMPTY_HMAC_KEY_MESSAGE: Final[str] = "HMAC secret must not be empty"
DELETION_VERIFIER_BINDINGS_MUST_BE_DISTINCT: Final[str] = (
    "deletion verifier issuer/key bindings must be distinct"
)
COMPLETED_AT_MUST_NOT_PRECEDE_CUTOFF: Final[str] = (
    "completed_at must not precede cutoff_at"
)
CANDIDATES_MUST_NOT_BE_EMPTY: Final[str] = "retention run must have candidates"
POLICY_EFFECTIVE_AT_MUST_EQUAL_OCCURRED_AT: Final[str] = (
    "policy effective_at must equal occurred_at"
)
POLICY_DIGEST_MUST_BIND_COMPLETE_POLICY: Final[str] = (
    "policy_digest must bind the complete policy"
)


def require_utc(value: datetime, field_name: str = "occurred_at") -> None:
    """Reject timestamps that are not aware UTC values."""
    if value.tzinfo is None or value.utcoffset() != UTC.utcoffset(value):
        message = f"{field_name} must be an aware UTC datetime"
        raise ValueError(message)


def _require_identifier(value: str, field_name: str) -> None:
    if not value:
        message = f"{field_name} must not be empty"
        raise ValueError(message)


def canonical_sha256(payload: object) -> str:
    """Return the SHA-256 digest of canonical JSON."""
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest()


def canonical_retention_policy_bytes(policy: RetentionPolicy) -> bytes:
    """Return the canonical, complete representation of a retention policy."""
    payload = {
        "audit_days": policy.audit_days,
        "effective_at": policy.effective_at.isoformat(),
        "operational_days": policy.operational_days,
        "version": policy.version,
    }
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()


def retention_policy_digest(policy: RetentionPolicy) -> str:
    """Return the SHA-256 digest binding every retention-policy field."""
    return hashlib.sha256(canonical_retention_policy_bytes(policy)).hexdigest()


@final
class RetentionPolicyError(ValueError):
    """Report a policy retention-period mismatch."""

    def __init__(self, operational_days: int, audit_days: int) -> None:
        """Initialize the stable policy mismatch error."""
        self.operational_days = operational_days
        self.audit_days = audit_days
        super().__init__(operational_days, audit_days)


@final
class RetentionCompletionError(ValueError):
    """Reject incomplete or invalid independent deletion evidence."""


class Clock(Protocol):
    """Provide the UTC time used by retention operations."""

    def now(self) -> datetime:
        """Return an aware UTC timestamp."""
        ...


@final
@dataclass(frozen=True, slots=True)
class RetentionPolicy:
    """Define an immutable exact retention policy."""

    version: str
    effective_at: datetime
    operational_days: int
    audit_days: int

    def __post_init__(self) -> None:
        """Validate exact retention periods and UTC policy time."""
        _require_identifier(self.version, "version")
        require_utc(self.effective_at, "effective_at")
        if (
            self.operational_days != DEFAULT_OPERATIONAL_DAYS
            or self.audit_days != DEFAULT_AUDIT_DAYS
        ):
            raise RetentionPolicyError(self.operational_days, self.audit_days)

    @classmethod
    def default(cls, effective_at: datetime) -> RetentionPolicy:
        """Return the default retention policy at the supplied effective time."""
        return cls(
            version="retention-v1",
            effective_at=effective_at,
            operational_days=DEFAULT_OPERATIONAL_DAYS,
            audit_days=DEFAULT_AUDIT_DAYS,
        )


@final
@dataclass(frozen=True, slots=True)
class RetentionPrincipal:
    """Identify a tenant-scoped caller."""

    principal_id: str
    tenant_id: str
    roles: frozenset[str] = field(default_factory=frozenset)

    def __post_init__(self) -> None:
        """Validate the tenant-scoped principal identity."""
        _require_identifier(self.principal_id, "principal_id")
        _require_identifier(self.tenant_id, "tenant_id")


@final
@dataclass(frozen=True, slots=True)
class HoldPlaceCommand:
    """Request a tenant-scoped legal hold."""

    hold_id: str
    tenant_id: str
    scope_id: str
    case_id: str
    authority: str
    reason: str
    event_id: str


@final
@dataclass(frozen=True, slots=True)
class BreakGlassRequest:
    """Request a bounded emergency-access grant."""

    grant_id: str
    tenant_id: str
    resource_id: str
    action: str
    restore_epoch: int
    expires_at: datetime
    event_id: str

    def __post_init__(self) -> None:
        """Validate the request expiry timestamp."""
        require_utc(self.expires_at, "expires_at")


@final
@dataclass(frozen=True, slots=True)
class BreakGlassUseCommand:
    """Request an approved emergency-access use."""

    grant_id: str
    tenant_id: str
    resource_id: str
    action: str
    restore_epoch: int
    event_id: str


class DeletionSystem(StrEnum):
    """Name a deletion system requiring independent evidence."""

    ARCHIVE = "archive"
    PRIMARY = "primary"


REQUIRED_DELETION_SYSTEMS: Final[tuple[DeletionSystem, ...]] = (
    DeletionSystem.ARCHIVE,
    DeletionSystem.PRIMARY,
)


@final
@dataclass(frozen=True, slots=True)
class DeletionAttestation:
    """Bind external deletion evidence to one tenant record."""

    issuer_id: str
    key_id: str
    tenant_id: str
    run_id: str
    record_id: str
    system: DeletionSystem
    deleted_at: datetime
    evidence_digest: str
    challenge: str
    candidate_manifest_digest: str
    signature: str

    def __post_init__(self) -> None:
        """Validate all signed attestation fields."""
        require_utc(self.deleted_at, "deleted_at")
        _require_identifier(self.issuer_id, "issuer_id")
        _require_identifier(self.key_id, "key_id")
        _require_identifier(self.tenant_id, "tenant_id")
        _require_identifier(self.run_id, "run_id")
        _require_identifier(self.record_id, "record_id")
        _require_identifier(self.evidence_digest, "evidence_digest")
        _require_identifier(self.challenge, "challenge")
        _require_identifier(self.candidate_manifest_digest, "candidate_manifest_digest")
        _require_identifier(self.signature, "signature")


class DeletionAttestationVerifier(Protocol):
    """Verify external deletion evidence independently of the store."""

    def verify(self, attestation: DeletionAttestation) -> bool:
        """Verify an attestation independently of the retention store."""
        ...


class DeletionAttestationVerifierBinding(DeletionAttestationVerifier, Protocol):
    """Expose only public issuer, system, and verification-key bindings."""

    @property
    def issuer_id(self) -> str:
        """Return the trusted issuer identity."""
        ...

    @property
    def system(self) -> DeletionSystem:
        """Return the fixed deletion system."""
        ...

    @property
    def key_id(self) -> str:
        """Return the public verification key identity."""
        ...


@final
@dataclass(frozen=True, slots=True, init=False)
class HmacDeletionAttestationVerifier:
    """Test-only symmetric verifier; production stores reject this binding."""

    issuer_id: str
    system: DeletionSystem
    key_id: str
    _verify_signature: Callable[[bytes, str], bool] = field(
        repr=False,
        compare=False,
    )

    def __init__(
        self,
        issuer_id: str,
        system: DeletionSystem,
        key_id: str,
        secret: bytes,
    ) -> None:
        """Initialize an opaque verifier without retaining raw key bytes."""
        secret_copy = bytes(secret)
        if not secret_copy:
            raise ValueError(EMPTY_HMAC_KEY_MESSAGE)

        def verify_signature(payload: bytes, signature: str) -> bool:
            expected = hmac.new(secret_copy, payload, hashlib.sha256).hexdigest()
            return hmac.compare_digest(expected, signature)

        object.__setattr__(self, "issuer_id", issuer_id)
        object.__setattr__(self, "system", system)
        object.__setattr__(self, "key_id", key_id)
        object.__setattr__(self, "_verify_signature", verify_signature)
        self.__post_init__()

    def __post_init__(self) -> None:
        """Validate the configured verifier trust root."""
        _require_identifier(self.issuer_id, "issuer_id")
        _require_identifier(self.key_id, "key_id")

    def verify(self, attestation: DeletionAttestation) -> bool:
        """Verify an attestation against this verifier's configured HMAC key."""
        if (
            attestation.issuer_id != self.issuer_id
            or attestation.system is not self.system
            or attestation.key_id != self.key_id
        ):
            return False
        return self._verify_signature(
            canonical_attestation_json(attestation).encode(),
            attestation.signature,
        )


@final
@dataclass(frozen=True, slots=True)
class DeletionAttestationVerifierSet:
    """Verify exactly one distinct trusted issuer for every fixed system."""

    verifiers: tuple[DeletionAttestationVerifierBinding, ...]

    def __post_init__(self) -> None:
        """Validate the independent fixed-system verifier bindings."""
        systems = tuple(verifier.system for verifier in self.verifiers)
        if set(systems) != set(REQUIRED_DELETION_SYSTEMS) or len(systems) != len(
            set(systems)
        ):
            raise ValueError(REQUIRED_SYSTEMS_MUST_BE_FIXED)
        issuer_keys = tuple(
            (verifier.issuer_id, verifier.key_id) for verifier in self.verifiers
        )
        issuer_ids = tuple(verifier.issuer_id for verifier in self.verifiers)
        if len(issuer_keys) != len(set(issuer_keys)) or len(issuer_ids) != len(
            set(issuer_ids)
        ):
            raise ValueError(DELETION_VERIFIER_BINDINGS_MUST_BE_DISTINCT)

    def verify(self, attestation: DeletionAttestation) -> bool:
        """Verify an attestation with its independently bound system verifier."""
        return any(
            verifier.system is attestation.system and verifier.verify(attestation)
            for verifier in self.verifiers
        )


def attestation_payload(attestation: DeletionAttestation) -> dict[str, str]:
    """Return fields covered by an attestation signature."""
    return {
        "issuer_id": attestation.issuer_id,
        "key_id": attestation.key_id,
        "tenant_id": attestation.tenant_id,
        "run_id": attestation.run_id,
        "record_id": attestation.record_id,
        "system": attestation.system.value,
        "deleted_at": attestation.deleted_at.isoformat(),
        "evidence_digest": attestation.evidence_digest,
        "challenge": attestation.challenge,
        "candidate_manifest_digest": attestation.candidate_manifest_digest,
    }


def canonical_attestation_json(attestation: DeletionAttestation) -> str:
    """Serialize signed attestation fields as canonical JSON."""
    return json.dumps(
        attestation_payload(attestation),
        separators=(",", ":"),
        sort_keys=True,
    )


@final
@dataclass(frozen=True, slots=True)
class RetentionCompletionCommand:
    """Bind a retention completion to immutable attestations."""

    run_id: str
    attestations: tuple[DeletionAttestation, ...]

    def __post_init__(self) -> None:
        """Validate the run identifier, including for empty runs."""
        _require_identifier(self.run_id, "run_id")


@final
@dataclass(frozen=True, slots=True)
class OperationalLog:
    """Represent an immutable tenant operational log."""

    record_id: str
    tenant_id: str
    scope_id: str
    occurred_at: datetime

    def __post_init__(self) -> None:
        """Validate an immutable operational log."""
        _require_identifier(self.record_id, "record_id")
        _require_identifier(self.tenant_id, "tenant_id")
        _require_identifier(self.scope_id, "scope_id")
        require_utc(self.occurred_at)


@final
@dataclass(frozen=True, slots=True)
class LegalHold:
    """Represent a tenant and scope legal hold."""

    hold_id: str
    tenant_id: str
    scope_id: str
    placed_at: datetime
    released_at: datetime | None
    case_id: str
    authority: str
    reason: str
    revision: int = 1

    def __post_init__(self) -> None:
        """Validate a legal hold and its revision timeline."""
        _require_identifier(self.hold_id, "hold_id")
        _require_identifier(self.tenant_id, "tenant_id")
        _require_identifier(self.scope_id, "scope_id")
        _require_identifier(self.case_id, "case_id")
        _require_identifier(self.authority, "authority")
        _require_identifier(self.reason, "reason")
        require_utc(self.placed_at, "placed_at")
        if self.revision < 1:
            raise ValueError(REVISION_MUST_BE_POSITIVE)
        if self.released_at is not None:
            require_utc(self.released_at, "released_at")
            if self.released_at < self.placed_at:
                raise ValueError(RELEASED_AT_MUST_NOT_PRECEDE_PLACED_AT)


@final
@dataclass(frozen=True, slots=True)
class AuditDraft:
    """Provide canonical fields for an audit record."""

    record_id: str
    tenant_id: str
    event: str
    actor_id: str
    subject_id: str
    scope_id: str
    reason: str
    occurred_at: datetime
    policy_version: str
    state: str

    def __post_init__(self) -> None:
        """Validate every canonical audit field."""
        for value, name in (
            (self.record_id, "record_id"),
            (self.tenant_id, "tenant_id"),
            (self.event, "event"),
            (self.actor_id, "actor_id"),
            (self.subject_id, "subject_id"),
            (self.scope_id, "scope_id"),
            (self.reason, "reason"),
            (self.policy_version, "policy_version"),
            (self.state, "state"),
        ):
            _require_identifier(value, name)
        require_utc(self.occurred_at)


@final
@dataclass(frozen=True, slots=True)
class AuditRecord:
    """Represent an integrity-protected immutable audit event."""

    record_id: str
    tenant_id: str
    event: str
    actor_id: str
    subject_id: str
    scope_id: str
    reason: str
    occurred_at: datetime
    policy_version: str
    state: str
    checksum_sha256: str

    def __post_init__(self) -> None:
        """Validate the immutable audit timestamp and checksum."""
        require_utc(self.occurred_at)
        _require_identifier(self.checksum_sha256, "checksum_sha256")


def audit_payload(draft: AuditDraft) -> dict[str, str]:
    """Return the canonical representation of an audit draft."""
    return {
        "record_id": draft.record_id,
        "tenant_id": draft.tenant_id,
        "event": draft.event,
        "actor_id": draft.actor_id,
        "subject_id": draft.subject_id,
        "scope_id": draft.scope_id,
        "reason": draft.reason,
        "occurred_at": draft.occurred_at.isoformat(),
        "policy_version": draft.policy_version,
        "state": draft.state,
    }


def build_audit_record(draft: AuditDraft) -> AuditRecord:
    """Construct an audit record with its canonical checksum."""
    payload = audit_payload(draft)
    return AuditRecord(
        record_id=draft.record_id,
        tenant_id=draft.tenant_id,
        event=draft.event,
        actor_id=draft.actor_id,
        subject_id=draft.subject_id,
        scope_id=draft.scope_id,
        reason=draft.reason,
        occurred_at=draft.occurred_at,
        policy_version=draft.policy_version,
        state=draft.state,
        checksum_sha256=canonical_sha256(payload),
    )


def verify_audit_record(record: AuditRecord) -> bool:
    """Return whether an audit record matches its canonical checksum."""
    draft = AuditDraft(
        record_id=record.record_id,
        tenant_id=record.tenant_id,
        event=record.event,
        actor_id=record.actor_id,
        subject_id=record.subject_id,
        scope_id=record.scope_id,
        reason=record.reason,
        occurred_at=record.occurred_at,
        policy_version=record.policy_version,
        state=record.state,
    )
    expected = build_audit_record(draft).checksum_sha256
    return hmac.compare_digest(expected, record.checksum_sha256)


@final
@dataclass(frozen=True, slots=True)
class PolicyChange:
    """Request an immediate policy change bound to its complete replacement.

    A replacement becomes active atomically when this command is accepted.
    Its effective_at is immutable policy identity and must equal occurred_at,
    so policy changes cannot be scheduled or applied retroactively.
    """

    actor_id: str
    reason: str
    occurred_at: datetime
    policy: RetentionPolicy
    policy_digest: str

    def __post_init__(self) -> None:
        """Validate command identity, timing, and replacement-policy binding."""
        _require_identifier(self.actor_id, "actor_id")
        _require_identifier(self.reason, "reason")
        _require_identifier(self.policy_digest, "policy_digest")
        require_utc(self.occurred_at)
        if self.policy.effective_at != self.occurred_at:
            raise ValueError(POLICY_EFFECTIVE_AT_MUST_EQUAL_OCCURRED_AT)
        if not hmac.compare_digest(
            self.policy_digest, retention_policy_digest(self.policy)
        ):
            raise ValueError(POLICY_DIGEST_MUST_BIND_COMPLETE_POLICY)


@final
@dataclass(frozen=True, slots=True)
class BreakGlassGrant:
    """Represent a tenant-bound emergency-access grant."""

    grant_id: str
    tenant_id: str
    resource_id: str
    action: str
    restore_epoch: int
    requester_id: str
    issued_at: datetime
    expires_at: datetime
    approver_id: str | None = None
    revoked_at: datetime | None = None
    expired_at: datetime | None = None

    def __post_init__(self) -> None:
        """Validate the emergency grant identity and timeline."""
        for value, name in (
            (self.grant_id, "grant_id"),
            (self.tenant_id, "tenant_id"),
            (self.resource_id, "resource_id"),
            (self.action, "action"),
            (self.requester_id, "requester_id"),
        ):
            _require_identifier(value, name)
        require_utc(self.issued_at, "issued_at")
        require_utc(self.expires_at, "expires_at")
        if self.expires_at <= self.issued_at:
            raise ValueError(EXPIRY_MUST_FOLLOW_ISSUANCE)
        for value, name in (
            (self.revoked_at, "revoked_at"),
            (self.expired_at, "expired_at"),
        ):
            if value is not None:
                require_utc(value, name)


@final
@dataclass(frozen=True, slots=True)
class RetentionRun:
    """Represent a retention run and its deletion proof."""

    run_id: str
    tenant_id: str
    idempotency_key: str
    cutoff_at: datetime
    policy_version: str
    attempts: int
    operational_ids: tuple[str, ...]
    audit_ids: tuple[str, ...]
    required_systems: tuple[DeletionSystem, ...] = REQUIRED_DELETION_SYSTEMS
    challenge: str = ""
    candidate_manifest_digest: str = ""
    receipts: tuple[DeletionAttestation, ...] = ()
    completed_at: datetime | None = None
    checksum_sha256: str = ""
    completion_digest: str = ""

    def __post_init__(self) -> None:
        """Validate the run identity, systems, candidates, and completion."""
        for value, name in (
            (self.run_id, "run_id"),
            (self.tenant_id, "tenant_id"),
            (self.idempotency_key, "idempotency_key"),
            (self.policy_version, "policy_version"),
        ):
            _require_identifier(value, name)
        require_utc(self.cutoff_at, "cutoff_at")
        if self.attempts < 1:
            raise ValueError(ATTEMPTS_MUST_BE_POSITIVE)
        if self.required_systems != REQUIRED_DELETION_SYSTEMS:
            raise ValueError(REQUIRED_SYSTEMS_MUST_BE_FIXED)
        candidate_ids = self.operational_ids + self.audit_ids
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError(CANDIDATE_IDS_MUST_BE_UNIQUE)
        if not candidate_ids:
            raise ValueError(CANDIDATES_MUST_NOT_BE_EMPTY)
        _require_identifier(self.challenge, "challenge")
        _require_identifier(self.candidate_manifest_digest, "candidate_manifest_digest")
        if self.completed_at is not None:
            require_utc(self.completed_at, "completed_at")
            if self.completed_at < self.cutoff_at:
                raise ValueError(COMPLETED_AT_MUST_NOT_PRECEDE_CUTOFF)
            _require_identifier(self.checksum_sha256, "checksum_sha256")
            _require_identifier(self.completion_digest, "completion_digest")


@final
@dataclass(frozen=True, slots=True)
class ExpiryReceipt:
    """Record expiry decisions without deleting candidates."""

    tenant_id: str
    policy_version: str
    occurred_at: datetime
    operational_ids: tuple[str, ...]
    audit_ids: tuple[str, ...]
    checksum_sha256: str


@final
@dataclass(frozen=True, slots=True)
class CandidateManifest:
    """Bind a retention run's frozen deletion candidates and challenge."""

    tenant_id: str
    run_id: str
    policy_version: str
    cutoff_at: datetime
    operational_ids: tuple[str, ...]
    audit_ids: tuple[str, ...]
    required_systems: tuple[DeletionSystem, ...]
    challenge: str

    def __post_init__(self) -> None:
        """Validate manifest bindings before they are hashed."""
        for value, name in (
            (self.tenant_id, "tenant_id"),
            (self.run_id, "run_id"),
            (self.policy_version, "policy_version"),
            (self.challenge, "challenge"),
        ):
            _require_identifier(value, name)
        require_utc(self.cutoff_at, "cutoff_at")
        if self.required_systems != REQUIRED_DELETION_SYSTEMS:
            raise ValueError(REQUIRED_SYSTEMS_MUST_BE_FIXED)
        candidate_ids = self.operational_ids + self.audit_ids
        if len(candidate_ids) != len(set(candidate_ids)):
            raise ValueError(CANDIDATE_IDS_MUST_BE_UNIQUE)


def candidate_manifest_digest(manifest: CandidateManifest) -> str:
    """Return the frozen, challenge-bound candidate manifest digest."""
    return canonical_sha256(
        {
            "tenant_id": manifest.tenant_id,
            "run_id": manifest.run_id,
            "policy_version": manifest.policy_version,
            "cutoff_at": manifest.cutoff_at.isoformat(),
            "operational_ids": manifest.operational_ids,
            "audit_ids": manifest.audit_ids,
            "required_systems": tuple(
                system.value for system in manifest.required_systems
            ),
            "challenge": manifest.challenge,
        }
    )


def completion_digest(attestations: tuple[DeletionAttestation, ...]) -> str:
    """Return the deterministic digest of exact receipt evidence."""
    payload = tuple(
        {
            **attestation_payload(attestation),
            "signature": attestation.signature,
        }
        for attestation in attestations
    )
    return canonical_sha256(payload)


def run_payload(run: RetentionRun) -> dict[str, object]:
    """Return canonical fields covered by a retention-run checksum."""
    return {
        "tenant_id": run.tenant_id,
        "run_id": run.run_id,
        "idempotency_key": run.idempotency_key,
        "cutoff_at": run.cutoff_at.isoformat(),
        "policy_version": run.policy_version,
        "attempts": run.attempts,
        "operational_ids": run.operational_ids,
        "audit_ids": run.audit_ids,
        "challenge": run.challenge,
        "candidate_manifest_digest": run.candidate_manifest_digest,
        "required_systems": tuple(system.value for system in run.required_systems),
        "receipts": tuple(
            {
                **attestation_payload(attestation),
                "signature": attestation.signature,
            }
            for attestation in run.receipts
        ),
        "completed_at": (
            run.completed_at.isoformat() if run.completed_at is not None else None
        ),
        "completion_digest": run.completion_digest,
    }


def verify_retention_run(
    run: RetentionRun,
    verifier: DeletionAttestationVerifier,
) -> bool:
    """Validate completed-run evidence, digest, and checksum."""
    expected = {
        (record_id, system)
        for record_id in run.operational_ids + run.audit_ids
        for system in run.required_systems
    }
    actual = tuple((item.record_id, item.system) for item in run.receipts)
    manifest = CandidateManifest(
        tenant_id=run.tenant_id,
        run_id=run.run_id,
        policy_version=run.policy_version,
        cutoff_at=run.cutoff_at,
        operational_ids=run.operational_ids,
        audit_ids=run.audit_ids,
        required_systems=run.required_systems,
        challenge=run.challenge,
    )
    return (
        bool(run.operational_ids or run.audit_ids)
        and run.completed_at is not None
        and run.completed_at >= run.cutoff_at
        and run.candidate_manifest_digest == candidate_manifest_digest(manifest)
        and len(actual) == len(set(actual))
        and set(actual) == expected
        and run.completion_digest == completion_digest(run.receipts)
        and run.checksum_sha256 == canonical_sha256(run_payload(run))
        and all(
            item.tenant_id == run.tenant_id
            and item.run_id == run.run_id
            and item.challenge == run.challenge
            and item.candidate_manifest_digest == run.candidate_manifest_digest
            and run.cutoff_at < item.deleted_at <= run.completed_at
            and verifier.verify(item)
            for item in run.receipts
        )
    )
