"""Public contracts for provider runtime connections."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING, Literal, Protocol

if TYPE_CHECKING:
    from collections.abc import Mapping

    from services.api.provider_qualification_receipt import (
        QualificationReceipt,
    )

type Flow = Literal["callback", "device"]
type Health = Literal[
    "pending",
    "healthy",
    "reauth_required",
    "unavailable",
    "quota_exhausted",
    "revoked",
]
type AuditReceipt = tuple[str, str]

ERROR_ACCOUNT_UNAVAILABLE = "account_unavailable"
ERROR_ADAPTER_DISABLED = "adapter_disabled"
ERROR_INVALID_COMPLETION = "invalid_completion"
ERROR_INVALID_CLEANUP_POLICY = "invalid_cleanup_policy"
ERROR_INVALID_CONNECTION_ID = "invalid_connection_id"
ERROR_INVALID_HEALTH = "invalid_health"
ERROR_INVALID_NONCE = "invalid_nonce"
ERROR_INVALID_OAUTH_REQUEST = "invalid_oauth_request"
ERROR_MODEL_UNAVAILABLE = "model_unavailable"
ERROR_NOT_FOUND = "not_found"
ERROR_OAUTH_BINDING_MISMATCH = "oauth_binding_mismatch"
ERROR_OAUTH_EXPIRED = "oauth_expired"
ERROR_PROVIDER_UNAVAILABLE = "provider_unavailable"
ERROR_PROVIDER_CLEANUP_OVERDUE = "provider_cleanup_overdue"
ERROR_QUALIFICATION_REQUIRED = "qualification_required"
ERROR_QUOTA_EXHAUSTED = "quota_exhausted"
ERROR_REAUTH_REQUIRED = "reauth_required"
ERROR_REVISION_CONFLICT = "revision_conflict"
ERROR_UNSAFE_COMPLETION = "token_material_rejected"


class ProviderRuntimeError(Exception):
    """Stable domain failure with a non-sensitive code."""

    def __init__(self, code: str) -> None:
        """Initialize the failure with its stable code."""
        super().__init__(code)
        self.code: str = code


class ConnectionNotFoundError(ProviderRuntimeError):
    """Raised when a connection or pending OAuth state is unavailable."""

    def __init__(self) -> None:
        """Initialize the stable not-found failure."""
        super().__init__(ERROR_NOT_FOUND)


@dataclass(frozen=True, slots=True)
class ProviderPrincipal:
    """Server-derived identity that scopes a provider connection."""

    user_id: str
    org_id: str


@dataclass(frozen=True, slots=True)
class ProviderRuntimeIdentity:
    """Composition-owned exact adapter, runtime version, and executable pin."""

    adapter_id: str
    runtime_version: str
    executable_sha256: str


@dataclass(frozen=True, slots=True)
class ProviderQualificationIdentity:
    """Historical live profile bound to one exact provider runtime identity."""

    runtime: ProviderRuntimeIdentity
    profile_sha256: str
    receipt: QualificationReceipt
    receipt_sha256: str


@dataclass(frozen=True, slots=True)
class OAuthInitiation:
    """A pending official OAuth flow that the client may continue."""

    state: str
    expires_at: datetime
    flow: Flow


@dataclass(frozen=True, slots=True)
class OfficialOAuthCompletion:
    """Token-free result from the runtime-owned official OAuth exchanger."""

    vault_home_ref: str
    account_id: str
    eligible_models: tuple[str, ...]
    metadata: Mapping[str, str]
    staging_lease_id: str
    destroy_by: datetime


@dataclass(frozen=True, slots=True)
class ProviderCompletionAdoption:
    """Durable broker adoption intent stored with a bound runtime home."""

    connection_id: str
    staging_lease_id: str
    runtime_home_ref: str
    destroy_by: datetime


@dataclass(frozen=True, slots=True)
class ProviderUpsertControl:
    """CAS and lifecycle controls for one provider persistence upsert."""

    expected_revision: int | None
    superseded_runtime_home_ref: str | None = None
    completion_adoption: ProviderCompletionAdoption | None = None
    qualification_receipt: QualificationReceipt | None = None


@dataclass(frozen=True, slots=True)
class OAuthClaim:
    """Frozen server-validated context for one official OAuth exchange."""

    claim_id: str
    adapter_id: str
    state: str
    flow: Flow
    redirect_uri: str
    expires_at: datetime


@dataclass(frozen=True, slots=True)
class ProviderConnection:
    """A redacted view of an authorized provider connection."""

    connection_id: str
    adapter_id: str
    account_id: str
    eligible_models: tuple[str, ...]
    selected_model: str | None
    health: Health
    cleanup_verified: bool
    qualified_live: bool
    created_at: datetime
    revision: int
    qualification: ProviderQualificationIdentity | None


@dataclass(frozen=True, slots=True)
class ProviderCleanupReceipt:
    """Redacted confirmation that runtime material was destroyed."""

    connection_id: str
    adapter_id: str
    requested_at: datetime
    destroy_by: datetime
    destroyed_at: datetime
    evidence_sha256: str
    redacted: Literal[True] = True


@dataclass(frozen=True, slots=True)
class ProviderConnectionSnapshot:
    """One durable connection plus its opaque runtime-home reference."""

    connection: ProviderConnection
    runtime_home_ref: str
    cleanup_receipt: ProviderCleanupReceipt | None = None
    cleanup_requested_at: datetime | None = None
    destroy_by: datetime | None = None
    superseded_runtime_home_ref: str | None = None
    completion_adoption: ProviderCompletionAdoption | None = None


@dataclass(frozen=True, slots=True)
class ProviderRevokeMutation:
    """Frozen revocation state passed atomically to persistence."""

    current: ProviderConnection
    proposed: ProviderConnection
    runtime_home_ref: str
    expected_revision: int
    requested_at: datetime
    destroy_by: datetime


class ProviderPersistence(Protocol):
    """Persistence boundary receiving redacted connections and opaque runtime refs."""

    def load(
        self, principal: ProviderPrincipal
    ) -> tuple[ProviderConnectionSnapshot, ...]:
        """Load every durable connection owned by one requester."""
        ...

    def upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        control: ProviderUpsertControl,
    ) -> None:
        """Persist a connection and durably destroy any superseded runtime home."""

    def confirm_completion_adoption(
        self, principal: ProviderPrincipal, connection_id: str, staging_lease_id: str
    ) -> None:
        """Atomically clear one broker adoption intent after idempotent adoption."""

    def discard_runtime_home(
        self, principal: ProviderPrincipal, runtime_home_ref: str
    ) -> None:
        """Destroy an exchanged runtime home unless it became durably bound."""

    def revoke(
        self, principal: ProviderPrincipal, mutation: ProviderRevokeMutation
    ) -> ProviderCleanupReceipt:
        """Destroy runtime material and durably revoke a connection."""
        ...


@dataclass(frozen=True, slots=True)
class DispatchAuthorization:
    """Authorization to dispatch work to one selected provider model."""

    adapter_id: str
    connection_id: str
    model_id: str
    qualification_receipt_id: str
    qualification_receipt_sha256: str
    qualification_connection_revision: int
    qualification_profile_sha256: str
    qualification_runtime_version: str
    qualification_executable_sha256: str
    built_in_tools_enabled: Literal[False] = False


def _normalize_utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _runtime_error(code: str) -> ProviderRuntimeError:
    return ProviderRuntimeError(code)


normalize_utc = _normalize_utc
runtime_error = _runtime_error
