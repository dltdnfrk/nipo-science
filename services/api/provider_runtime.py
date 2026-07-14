"""Thread-safe domain for runtime-owned official subscription OAuth connections."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from secrets import token_bytes
from threading import RLock
from typing import TYPE_CHECKING, Final, Literal, Protocol
from urllib.parse import urlparse

from services.api.artifacts.runtime import Uuid7Factory
from services.api.provider_qualification import is_issued_qualification_result

if TYPE_CHECKING:
    from collections.abc import Callable, Generator, Mapping

    from services.api.provider_qualification import QualificationResult

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

NONCE_BYTES: Final[int] = 32
OAUTH_EXPIRATION: Final[timedelta] = timedelta(minutes=10)

ERROR_ACCOUNT_UNAVAILABLE: Final[str] = "account_unavailable"
ERROR_ADAPTER_DISABLED: Final[str] = "adapter_disabled"
ERROR_INVALID_COMPLETION: Final[str] = "invalid_completion"
ERROR_INVALID_CONNECTION_ID: Final[str] = "invalid_connection_id"
ERROR_INVALID_HEALTH: Final[str] = "invalid_health"
ERROR_INVALID_NONCE: Final[str] = "invalid_nonce"
ERROR_INVALID_OAUTH_REQUEST: Final[str] = "invalid_oauth_request"
ERROR_MODEL_UNAVAILABLE: Final[str] = "model_unavailable"
ERROR_NOT_FOUND: Final[str] = "not_found"
ERROR_OAUTH_BINDING_MISMATCH: Final[str] = "oauth_binding_mismatch"
ERROR_OAUTH_EXPIRED: Final[str] = "oauth_expired"
ERROR_PROVIDER_UNAVAILABLE: Final[str] = "provider_unavailable"
ERROR_QUALIFICATION_REQUIRED: Final[str] = "qualification_required"
ERROR_QUOTA_EXHAUSTED: Final[str] = "quota_exhausted"
ERROR_REAUTH_REQUIRED: Final[str] = "reauth_required"
ERROR_REVISION_CONFLICT: Final[str] = "revision_conflict"
ERROR_UNSAFE_COMPLETION: Final[str] = "token_material_rejected"


@dataclass(frozen=True, slots=True)
class ProviderPrincipal:
    """Server-derived identity that scopes a provider connection."""

    user_id: str
    org_id: str


@dataclass(frozen=True, slots=True)
class ProviderAdapter:
    """A supported provider adapter and its launch availability."""

    adapter_id: str
    required: bool
    launch_default: bool
    connectable: bool
    disabled_reason: str | None = None


ADAPTERS: Final[tuple[ProviderAdapter, ...]] = (
    ProviderAdapter(
        adapter_id="openai_codex",
        required=True,
        launch_default=True,
        connectable=True,
    ),
    ProviderAdapter(
        adapter_id="anthropic_claude_code",
        required=False,
        launch_default=False,
        connectable=False,
        disabled_reason="not_qualified",
    ),
    ProviderAdapter(
        adapter_id="xai_grok_build",
        required=False,
        launch_default=False,
        connectable=False,
        disabled_reason="not_qualified",
    ),
    ProviderAdapter(
        adapter_id="moonshot_kimi_code",
        required=False,
        launch_default=False,
        connectable=False,
        disabled_reason="not_qualified",
    ),
    ProviderAdapter(
        adapter_id="zai_glm",
        required=False,
        launch_default=False,
        connectable=False,
        disabled_reason="unsupported_auth",
    ),
)
_ADAPTER_BY_ID: Final[dict[str, ProviderAdapter]] = {
    adapter.adapter_id: adapter for adapter in ADAPTERS
}


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

    def upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        expected_revision: int | None,
    ) -> None:
        """Persist a private connection record with an optimistic revision."""

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
    built_in_tools_enabled: Literal[False] = False


@dataclass(slots=True)
class _Attempt:
    state_digest: str
    principal: ProviderPrincipal
    adapter_id: str
    flow: Flow
    redirect_uri: str
    expires_at: datetime
    reauth_connection_id: str | None


@dataclass(slots=True)
class _ConnectionLock:
    lock: RLock
    users: int = 0


@dataclass(frozen=True, slots=True)
class _ConnectionRecord:
    connection_id: str
    principal: ProviderPrincipal
    adapter_id: str
    account_id: str
    eligible_models: tuple[str, ...]
    selected_model: str | None
    health: Health
    cleanup_verified: bool
    qualified_live: bool
    created_at: datetime
    runtime_home_ref: str
    revision: int


class ProviderRuntimeService:
    """In-memory provider domain that never receives OAuth secrets."""

    def __init__(
        self,
        clock: Callable[[], datetime],
        nonce_factory: Callable[[], bytes] | None = None,
        id_factory: Callable[[], str] | None = None,
        *,
        persistence: ProviderPersistence,
    ) -> None:
        """Initialize the service with injectable clock and identifier sources."""
        self._clock: Callable[[], datetime] = clock
        self._nonce_factory: Callable[[], bytes] = nonce_factory or _default_nonce
        self._id_factory: Callable[[], str] = id_factory or _default_id
        self._persistence: ProviderPersistence = persistence
        self._attempts: dict[str, _Attempt] = {}
        self._connections: dict[str, _ConnectionRecord] = {}
        self._cleanup_receipts: dict[str, ProviderCleanupReceipt] = {}
        self._audit: list[AuditReceipt] = []
        self._lock: RLock = RLock()
        self._connection_locks: dict[str, _ConnectionLock] = {}
        self._claims: dict[str, _Attempt] = {}

    def adapters(self) -> tuple[ProviderAdapter, ...]:
        """Return the fixed provider registry."""
        return ADAPTERS

    def initiate(
        self,
        principal: ProviderPrincipal,
        adapter_id: str,
        flow: Flow,
        redirect_uri: str,
        reauth_connection_id: str | None = None,
    ) -> OAuthInitiation:
        """Create a single-use OAuth attempt for a connectable adapter."""
        adapter = self._connectable_adapter(adapter_id)
        if flow not in ("callback", "device") or not _safe_redirect(redirect_uri):
            raise _runtime_error(ERROR_INVALID_OAUTH_REQUEST)
        nonce = self._nonce_factory()
        if len(nonce) != NONCE_BYTES:
            raise _runtime_error(ERROR_INVALID_NONCE)
        state = urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
        expires_at = _utc(self._clock()) + OAUTH_EXPIRATION
        digest = _state_digest(state)
        with self._lock:
            if reauth_connection_id is not None:
                record = self._owned_record(principal, reauth_connection_id)
                if record.adapter_id != adapter.adapter_id:
                    raise _runtime_error(ERROR_INVALID_OAUTH_REQUEST)
            self._attempts[digest] = _Attempt(
                state_digest=digest,
                principal=principal,
                adapter_id=adapter_id,
                flow=flow,
                redirect_uri=redirect_uri,
                expires_at=expires_at,
                reauth_connection_id=reauth_connection_id,
            )
            self._audit.append(("oauth_initiated", adapter_id))
        return OAuthInitiation(state, expires_at, flow)

    def complete_callback(
        self,
        principal: ProviderPrincipal,
        state: str,
        redirect_uri: str,
        completion: OfficialOAuthCompletion,
    ) -> ProviderConnection:
        """Complete a callback OAuth attempt."""
        claim = self.claim_oauth(principal, state, "callback", redirect_uri)
        return self.finalize_oauth(principal, claim, completion)

    def complete_device(
        self,
        principal: ProviderPrincipal,
        state: str,
        completion: OfficialOAuthCompletion,
        redirect_uri: str = "/oauth/device",
    ) -> ProviderConnection:
        """Complete a device OAuth attempt."""
        claim = self.claim_oauth(principal, state, "device", redirect_uri)
        return self.finalize_oauth(principal, claim, completion)

    def claim_oauth(
        self,
        principal: ProviderPrincipal,
        state: str,
        flow: Flow,
        redirect_uri: str,
    ) -> OAuthClaim:
        """Atomically validate and consume an owned OAuth state for exchange."""
        digest = _state_digest(state)
        now = _utc(self._clock())
        with self._lock:
            attempt = self._attempts.get(digest)
            if attempt is None or attempt.principal != principal:
                raise ConnectionNotFoundError
            if now >= attempt.expires_at:
                del self._attempts[digest]
                raise _runtime_error(ERROR_OAUTH_EXPIRED)
            if attempt.flow != flow or attempt.redirect_uri != redirect_uri:
                raise _runtime_error(ERROR_OAUTH_BINDING_MISMATCH)
            del self._attempts[digest]
        claim_id = self._id_factory()
        if not claim_id:
            raise _runtime_error(ERROR_INVALID_CONNECTION_ID)
        with self._lock:
            self._claims[claim_id] = attempt
        return OAuthClaim(
            claim_id,
            attempt.adapter_id,
            state,
            attempt.flow,
            attempt.redirect_uri,
            attempt.expires_at,
        )

    def abort_oauth(self, principal: ProviderPrincipal, claim: OAuthClaim) -> None:
        """Abort a claimed exchange after the official broker fails."""
        with self._lock:
            attempt = self._claims.pop(claim.claim_id, None)
            if attempt is None or attempt.principal != principal:
                raise ConnectionNotFoundError
            self._audit.append(("oauth_aborted", attempt.adapter_id))

    def finalize_oauth(
        self,
        principal: ProviderPrincipal,
        claim: OAuthClaim,
        completion: OfficialOAuthCompletion,
    ) -> ProviderConnection:
        """Consume one validated claim and persist its official completion."""
        with self._lock:
            attempt = self._claims.pop(claim.claim_id, None)
            if (
                attempt is None
                or attempt.principal != principal
                or attempt.adapter_id != claim.adapter_id
                or attempt.flow != claim.flow
                or attempt.redirect_uri != claim.redirect_uri
            ):
                raise ConnectionNotFoundError
        return self._finalize_attempt(principal, attempt, completion)

    def cancel_pending(self, principal: ProviderPrincipal, state: str) -> None:
        """Cancel a pending OAuth attempt owned by the principal."""
        with self._lock:
            attempt = self._attempts.get(_state_digest(state))
            if attempt is None or attempt.principal != principal:
                raise ConnectionNotFoundError
            del self._attempts[attempt.state_digest]
            self._audit.append(("oauth_cancelled", attempt.adapter_id))

    def list_connections(
        self, principal: ProviderPrincipal
    ) -> tuple[ProviderConnection, ...]:
        """List connections owned by the principal."""
        with self._lock:
            return tuple(
                self._view(record)
                for record in self._connections.values()
                if record.principal == principal
            )

    def connection_detail(
        self, principal: ProviderPrincipal, connection_id: str
    ) -> ProviderConnection:
        """Return one connection owned by the principal."""
        with self._lock:
            return self._view(self._owned_record(principal, connection_id))

    def select_account(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        account_id: str,
    ) -> ProviderConnection:
        """Confirm the account selected by the official OAuth completion."""
        with self._lock:
            record = self._owned_record(principal, connection_id)
            if record.account_id != account_id:
                raise _runtime_error(ERROR_ACCOUNT_UNAVAILABLE)
            return self._view(record)

    def select_model(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        model_id: str,
        expected_revision: int | None = None,
    ) -> ProviderConnection:
        """Select an eligible model for a connection."""
        def update(record: _ConnectionRecord) -> _ConnectionRecord:
            if model_id not in record.eligible_models:
                raise _runtime_error(ERROR_MODEL_UNAVAILABLE)
            return replace(record, selected_model=model_id)

        return self._mutated(principal, connection_id, expected_revision, update)

    def set_health(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        health: Health,
        expected_revision: int | None = None,
    ) -> ProviderConnection:
        """Update the connection health after validating allowed transitions."""
        def update(record: _ConnectionRecord) -> _ConnectionRecord:
            if health not in (
                "healthy",
                "reauth_required",
                "unavailable",
                "quota_exhausted",
            ):
                raise _runtime_error(ERROR_INVALID_HEALTH)
            if health == "healthy" and not _is_qualified(record):
                raise _runtime_error(ERROR_QUALIFICATION_REQUIRED)
            return replace(record, health=health)

        return self._mutated(principal, connection_id, expected_revision, update)

    def initiate_reauth(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        flow: Flow,
        redirect_uri: str,
        expected_revision: int | None = None,
    ) -> OAuthInitiation:
        """Mark a connection for reauthentication and start its OAuth flow."""
        _ = self._mutated(
            principal,
            connection_id,
            expected_revision,
            lambda record: replace(record, health="reauth_required"),
        )
        with self._lock:
            adapter_id = self._owned_record(principal, connection_id).adapter_id
        return self.initiate(
            principal, adapter_id, flow, redirect_uri, connection_id
        )

    def revoke(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        expected_revision: int | None = None,
    ) -> ProviderCleanupReceipt:
        """Revoke a connection and request runtime-owned material destruction."""
        requested_at = _utc(self._clock())
        destroy_by = requested_at + timedelta(hours=24)
        with self._locked_connection(principal, connection_id):
            with self._lock:
                record = self._owned_record(principal, connection_id)
                self._require_revision(record, expected_revision)
                proposed = replace(
                    record,
                    health="revoked",
                    selected_model=None,
                    revision=record.revision + 1,
                )
            receipt = self._persistence.revoke(
                principal,
                ProviderRevokeMutation(
                    current=self._view(record),
                    proposed=self._view(proposed),
                    runtime_home_ref=record.runtime_home_ref,
                    expected_revision=record.revision,
                    requested_at=requested_at,
                    destroy_by=destroy_by,
                ),
            )
            with self._lock:
                if self._connections.get(connection_id) != record:
                    raise _runtime_error(ERROR_REVISION_CONFLICT)
                self._connections[connection_id] = proposed
                self._cleanup_receipts[connection_id] = receipt
                self._audit.append(("connection_revoked", record.adapter_id))
            return receipt

    def cleanup_receipt(
        self, principal: ProviderPrincipal, connection_id: str
    ) -> ProviderCleanupReceipt:
        """Return an owned connection's redacted cleanup receipt."""
        with self._lock:
            _ = self._owned_record(principal, connection_id)
            receipt = self._cleanup_receipts.get(connection_id)
            if receipt is None:
                raise ConnectionNotFoundError
            return receipt

    def record_qualification(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        result: QualificationResult,
        expected_revision: int | None = None,
    ) -> ProviderConnection:
        """Record an evaluator-issued live result bound to this connection."""
        issued = is_issued_qualification_result(result)

        def update(record: _ConnectionRecord) -> _ConnectionRecord:
            if (
                not issued
                or not result.contract_valid
                or not result.live_qualified
                or result.adapter != record.adapter_id
                or result.account_ref != record.account_id
            ):
                raise _runtime_error(ERROR_QUALIFICATION_REQUIRED)
            return replace(record, cleanup_verified=True, qualified_live=True)

        connection = self._mutated(principal, connection_id, expected_revision, update)
        with self._lock:
            self._audit.append(
                ("qualification_cleanup_verified", connection.adapter_id)
            )
        return connection

    def dispatch_authorization(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        model_id: str,
    ) -> DispatchAuthorization:
        """Authorize dispatch only for a qualified healthy selected model."""
        with self._lock:
            record = self._owned_record(principal, connection_id)
            self._require_dispatchable(record, model_id)
            return DispatchAuthorization(
                adapter_id=record.adapter_id,
                connection_id=record.connection_id,
                model_id=model_id,
            )

    def audit_receipts(self) -> tuple[AuditReceipt, ...]:
        """Return redacted event names and adapter identifiers only."""
        with self._lock:
            return tuple(self._audit)

    def active_connection_lock_count(self) -> int:
        """Return the number of connection locks currently in use."""
        with self._lock:
            return len(self._connection_locks)


    def _finalize_attempt(
        self,
        principal: ProviderPrincipal,
        attempt: _Attempt,
        completion: OfficialOAuthCompletion,
    ) -> ProviderConnection:
        self._validate_completion(completion)
        connection_id = attempt.reauth_connection_id or self._id_factory()
        created_at = _utc(self._clock())
        if not connection_id:
            raise _runtime_error(ERROR_INVALID_CONNECTION_ID)
        with self._locked_connection(
            principal,
            connection_id,
            new=attempt.reauth_connection_id is None,
        ):
            with self._lock:
                if attempt.reauth_connection_id is None:
                    if connection_id in self._connections:
                        raise _runtime_error(ERROR_REVISION_CONFLICT)
                    record = _ConnectionRecord(
                        connection_id=connection_id,
                        principal=principal,
                        adapter_id=attempt.adapter_id,
                        account_id=completion.account_id,
                        eligible_models=completion.eligible_models,
                        selected_model=None,
                        health="pending",
                        cleanup_verified=False,
                        qualified_live=False,
                        created_at=created_at,
                        runtime_home_ref=completion.vault_home_ref,
                        revision=1,
                    )
                    expected_revision = None
                    current = None
                else:
                    current = self._owned_record(principal, connection_id)
                    record = replace(
                        current,
                        account_id=completion.account_id,
                        eligible_models=completion.eligible_models,
                        selected_model=None,
                        cleanup_verified=False,
                        qualified_live=False,
                        health="pending",
                        runtime_home_ref=completion.vault_home_ref,
                        revision=current.revision + 1,
                    )
                    expected_revision = current.revision
            self._persist(record, expected_revision)
            with self._lock:
                if self._connections.get(connection_id) != current:
                    raise _runtime_error(ERROR_REVISION_CONFLICT)
                self._connections[connection_id] = record
                self._audit.append(("oauth_completed", attempt.adapter_id))
                return self._view(record)

    def _connectable_adapter(self, adapter_id: str) -> ProviderAdapter:
        adapter = _ADAPTER_BY_ID.get(adapter_id)
        if adapter is None or not adapter.connectable:
            raise _runtime_error(ERROR_ADAPTER_DISABLED)
        return adapter

    def _owned_record(
        self, principal: ProviderPrincipal, connection_id: str
    ) -> _ConnectionRecord:
        record = self._connections.get(connection_id)
        if record is None or record.principal != principal:
            raise ConnectionNotFoundError
        return record

    @staticmethod
    def _validate_completion(completion: OfficialOAuthCompletion) -> None:
        if (
            not _safe_vault_ref(completion.vault_home_ref)
            or not completion.account_id
            or not completion.eligible_models
        ):
            raise _runtime_error(ERROR_INVALID_COMPLETION)
        if any(not model for model in completion.eligible_models):
            raise _runtime_error(ERROR_INVALID_COMPLETION)
        if any(
            "token" in key.lower()
            or "secret" in key.lower()
            or "token" in value.lower()
            or "bearer " in value.lower()
            for key, value in completion.metadata.items()
        ):
            raise _runtime_error(ERROR_UNSAFE_COMPLETION)

    @staticmethod
    def _view(record: _ConnectionRecord) -> ProviderConnection:
        return ProviderConnection(
            connection_id=record.connection_id,
            adapter_id=record.adapter_id,
            account_id=record.account_id,
            eligible_models=record.eligible_models,
            selected_model=record.selected_model,
            health=record.health,
            cleanup_verified=record.cleanup_verified,
            qualified_live=record.qualified_live,
            created_at=record.created_at,
            revision=record.revision,
        )

    def _mutated(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        expected_revision: int | None,
        update: Callable[[_ConnectionRecord], _ConnectionRecord],
    ) -> ProviderConnection:
        with self._locked_connection(principal, connection_id):
            with self._lock:
                record = self._owned_record(principal, connection_id)
                self._require_revision(record, expected_revision)
                proposed = replace(update(record), revision=record.revision + 1)
            self._persist(proposed, record.revision)
            with self._lock:
                if self._connections.get(connection_id) != record:
                    raise _runtime_error(ERROR_REVISION_CONFLICT)
                self._connections[connection_id] = proposed
                return self._view(proposed)

    @contextmanager
    def _locked_connection(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        *,
        new: bool = False,
    ) -> Generator[None, None, None]:
        with self._lock:
            if new:
                if connection_id in self._connections:
                    raise _runtime_error(ERROR_REVISION_CONFLICT)
            else:
                _ = self._owned_record(principal, connection_id)
            entry = self._connection_locks.get(connection_id)
            if entry is None:
                entry = _ConnectionLock(RLock())
                self._connection_locks[connection_id] = entry
            entry.users += 1
        _ = entry.lock.acquire()
        try:
            with self._lock:
                if new:
                    if connection_id in self._connections:
                        raise _runtime_error(ERROR_REVISION_CONFLICT)
                else:
                    _ = self._owned_record(principal, connection_id)
            yield
        finally:
            entry.lock.release()
            with self._lock:
                entry.users -= 1
                if (
                    entry.users == 0
                    and self._connection_locks.get(connection_id) is entry
                ):
                    del self._connection_locks[connection_id]

    def _persist(
        self, record: _ConnectionRecord, expected_revision: int | None
    ) -> None:
        self._persistence.upsert(
            record.principal,
            self._view(record),
            record.runtime_home_ref,
            expected_revision,
        )

    @staticmethod
    def _require_revision(
        record: _ConnectionRecord, expected_revision: int | None
    ) -> None:
        if expected_revision is not None and expected_revision != record.revision:
            raise _runtime_error(ERROR_REVISION_CONFLICT)

    @staticmethod
    def _require_dispatchable(record: _ConnectionRecord, model_id: str) -> None:
        if record.health == "reauth_required":
            raise _runtime_error(ERROR_REAUTH_REQUIRED)
        if record.health == "quota_exhausted":
            raise _runtime_error(ERROR_QUOTA_EXHAUSTED)
        if record.health != "healthy":
            raise _runtime_error(ERROR_PROVIDER_UNAVAILABLE)
        if not _is_qualified(record):
            raise _runtime_error(ERROR_QUALIFICATION_REQUIRED)
        if record.selected_model != model_id or model_id not in record.eligible_models:
            raise _runtime_error(ERROR_MODEL_UNAVAILABLE)


def _default_nonce() -> bytes:
    return token_bytes(NONCE_BYTES)


def _default_id() -> str:
    return str(Uuid7Factory().new_uuid7())


def _runtime_error(code: str) -> ProviderRuntimeError:
    return ProviderRuntimeError(code)


def _is_qualified(record: _ConnectionRecord) -> bool:
    return record.cleanup_verified and record.qualified_live




def _utc(value: datetime) -> datetime:
    if value.tzinfo is None:
        return value.replace(tzinfo=UTC)
    return value.astimezone(UTC)


def _state_digest(state: str) -> str:
    return sha256(state.encode("ascii")).hexdigest()


def _safe_redirect(value: str) -> bool:
    parsed = urlparse(value)
    return (
        bool(value)
        and value.startswith("/")
        and not value.startswith("//")
        and not parsed.scheme
        and not parsed.netloc
    )


def _safe_vault_ref(value: str) -> bool:
    parsed = urlparse(value)
    return (
        parsed.scheme == "vault"
        and parsed.netloc == "runtime"
        and parsed.path.startswith("/")
        and ".." not in parsed.path
        and not parsed.query
        and not parsed.fragment
    )
