"""Loopback product server for same-origin auth and tenant fixture journeys."""

from __future__ import annotations

import hmac
import json
import re
import secrets
import traceback as traceback_module
from collections.abc import Callable
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from html import escape
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from threading import Condition, Lock, Thread
from typing import TYPE_CHECKING, Final, Protocol, cast, final, override
from urllib.parse import urlsplit
from uuid import UUID

from pydantic import TypeAdapter, ValidationError

from services.api.artifacts.http import ArtifactHttpResponse, ArtifactHttpService
from services.api.artifacts.runtime import UUID7_VERSION, Uuid7Factory
from services.api.bounded_http import BoundedThreadingHttpServer
from services.api.product_artifacts import ProductArtifactService
from services.api.product_connectors import (
    CollectedDocument,
    CollectionBackend,
    CollectionFetcher,
    CollectionPlan,
    CollectionPlanStore,
    CollectionStore,
    ConnectorSettingsBackend,
    ConnectorSettingsError,
    ConnectorSettingsStore,
    StoredCollection,
    fixture_collection_fetcher,
    live_collection_fetcher,
    parse_collection_prompt,
)
from services.api.product_dry_lab import (
    DryLabResourceKind,
    LocalRunCreate,
    ProductDryLabService,
    ProviderRunCreate,
)
from services.api.product_tenancy import (
    InMemoryTenantRepository,
    ProjectView,
    SessionView,
    TenantPrincipal,
    TenantRepository,
)
from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_runtime import (
    ERROR_ACCOUNT_UNAVAILABLE,
    ERROR_ADAPTER_DISABLED,
    ERROR_INVALID_COMPLETION,
    ERROR_INVALID_CONNECTION_ID,
    ERROR_INVALID_HEALTH,
    ERROR_INVALID_NONCE,
    ERROR_INVALID_OAUTH_REQUEST,
    ERROR_MODEL_UNAVAILABLE,
    ERROR_OAUTH_BINDING_MISMATCH,
    ERROR_OAUTH_EXPIRED,
    ERROR_PROVIDER_UNAVAILABLE,
    ERROR_QUALIFICATION_REQUIRED,
    ERROR_QUOTA_EXHAUSTED,
    ERROR_REAUTH_REQUIRED,
    ERROR_REVISION_CONFLICT,
    ERROR_UNSAFE_COMPLETION,
    ConnectionNotFoundError,
    Health,
    OAuthClaim,
    OAuthInitiation,
    OfficialOAuthCompletion,
    ProviderCleanupReceipt,
    ProviderCompletionAdoption,
    ProviderConnection,
    ProviderPrincipal,
    ProviderRuntimeError,
    ProviderRuntimeService,
)

if TYPE_CHECKING:
    from types import TracebackType

    from services.api.artifacts.models import IdFactory
    from services.api.provider_run_dispatch import ProviderRunDispatcher

Clock = Callable[[], datetime]
type JsonScalar = None | bool | int | float | str
type JsonList = list[JsonValue]
type JsonObject = dict[str, JsonValue]
type JsonValue = JsonScalar | JsonList | JsonObject
type ProviderIdempotencyKey = tuple[str, str, str, str]


@dataclass(frozen=True, slots=True)
class ProviderIdempotencyRequest:
    """Identity and diagnostics bound to one provider mutation."""

    cache_key: ProviderIdempotencyKey
    digest: str
    route: str
    method: str
    principal_hash: str


@dataclass(slots=True)
class _ProviderIdempotencyEntry:
    digest: str
    expires_at: datetime
    complete: bool = False
    status: HTTPStatus | None = None
    body: JsonObject | None = None
    failure_type: str | None = None


_JSON_OBJECT_ADAPTER: Final[TypeAdapter[JsonObject]] = TypeAdapter(JsonObject)
_DEVELOPMENT_INTENT_COOKIE: Final = "product_intent"
_DEVELOPMENT_SESSION_COOKIE: Final = "product_session"
_DEVELOPMENT_CSRF_COOKIE: Final = "product_csrf"
_PRODUCTION_INTENT_COOKIE: Final = "__Host-swb_intent"
_PRODUCTION_SESSION_COOKIE: Final = "__Host-swb_session"
_PRODUCTION_CSRF_COOKIE: Final = "__Host-swb_csrf"

_SECONDS_PER_MINUTE: Final = 60
_MINUTES_PER_HOUR: Final = 60
_MAGIC_LINK_MAX_AGE: Final = 15 * _SECONDS_PER_MINUTE
_SESSION_MAX_AGE: Final = 24 * _MINUTES_PER_HOUR * _SECONDS_PER_MINUTE
_MAGIC_LINK_TTL: Final = timedelta(minutes=15)
_SESSION_IDLE_TTL: Final = timedelta(hours=8)
_SESSION_ABSOLUTE_TTL: Final = timedelta(hours=24)
_MAX_JSON_BODY_BYTES: Final = 1_000_000
_NOT_FOUND: Final = b'{"error":"not_found"}'
_UNAUTHORIZED: Final = b'{"error":"unauthorized"}'
_BAD_REQUEST: Final = b'{"error":"invalid_request"}'
_SERVICE_UNAVAILABLE: Final = b'{"error":"service_unavailable"}'
_INVALID_RESEARCH_INTENT: Final = b'{"error":"research-intent-invalid"}'
_PROVIDER_DISPATCH_UNAVAILABLE: Final = b'{"error":"provider_dispatch_unavailable"}'
_FORBIDDEN: Final = b'{"error":"invalid_origin"}'
_INVALID_CSRF: Final = b'{"error":"invalid_csrf"}'
_PAYLOAD_TOO_LARGE: Final = b'{"error":"request_too_large"}'
_MAGIC_LINK_RESPONSE: Final = b'{"status":"ok"}'
_PROVIDER_IDEMPOTENCY_TTL: Final = timedelta(minutes=10)
_PROVIDER_IDEMPOTENCY_CAPACITY: Final = 256
_PROVIDER_AUTHORIZATION_MAX_LENGTH: Final = 2_048
_PROVIDER_ADAPTER_ID: Final[re.Pattern[str]] = re.compile(
    r"^[a-z][a-z0-9_]{0,63}$"
)
_PROVIDER_AUTHORIZATION_POLICY_MARKER: Final = (
    "__PRODUCT_PROVIDER_AUTHORIZATION_POLICY__"
)
_FIXTURE_PROVIDER_AUTHORIZATION_ENDPOINTS: Final = (
    ("openai_codex", "https://provider.example.test/authorize"),
)
_UNSAFE_PROVIDER_AUTHORIZATION_MESSAGE: Final = (
    "provider authorization endpoint is not allowed"
)
_PRODUCT_CONTENT_SECURITY_POLICY: Final = (
    "default-src 'none'; base-uri 'none'; connect-src 'self'; "
    "frame-ancestors 'none'; frame-src 'self' blob:; "
    "img-src 'self' blob: data:; object-src 'none'; "
    "script-src 'self'; style-src 'self'; form-action 'self'"
)
_RUN_ACTION_PATH_PARTS: Final = 6
_PROVIDER_DEPENDENCIES_MESSAGE: Final = (
    "provider_diagnostic_sink is required with provider dependencies"
)
_PROVIDER_DIAGNOSTIC_SINK_MESSAGE: Final = "provider diagnostic sink is unavailable"
_PROVIDER_ERROR_ENVELOPE_MESSAGE: Final = "provider error envelope is invalid"
_PUBLIC_ORIGIN_MESSAGE: Final = "public_origin must be a canonical HTTP(S) origin"
_FIXTURE_SESSION_UNAVAILABLE_MESSAGE: Final = "fixture session is unavailable"
_FIXTURE_SESSION_ALREADY_INITIALIZED_MESSAGE: Final = (
    "fixture session token is already initialized"
)
_FIXTURE_SESSION_REQUIRES_AUTH_MESSAGE: Final = (
    "fixture_session_token requires authenticated_fixture"
)
_DRY_LAB_FIXTURE_REQUIRES_AUTH_MESSAGE: Final = (
    "ProductDryLabService requires authenticated_fixture"
)
_ARTIFACT_PRODUCTION_DEPENDENCIES_MESSAGE: Final = (
    "durable Artifact HTTP requires an external session authority"
)
_EXTERNAL_SESSION_FIXTURE_MESSAGE: Final = (
    "external session authority cannot be combined with a fixture principal"
)
_FIXTURE_PROJECT_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331677b01"
_FIXTURE_ARCHIVED_PROJECT_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331677b02"
_FIXTURE_FOREIGN_PROJECT_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331677b03"
_FIXTURE_SESSION_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331677c01"
_FIXTURE_ARCHIVED_SESSION_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331677c02"
_FIXTURE_FOREIGN_SESSION_ID: Final = "018f0d7d-6b17-7a91-8b31-2f7331677c03"
_DYNAMIC_PRODUCT_ROUTE: Final[re.Pattern[str]] = re.compile(
    r"^/(?:runs/[A-Za-z0-9][A-Za-z0-9_-]*(?:/approval)?|"
    r"(?:artifacts|reviews|exports)/[A-Za-z0-9][A-Za-z0-9_-]*)$"
)
_DRY_LAB_RESOURCE_API: Final[re.Pattern[str]] = re.compile(
    r"^/api/v1/(?P<kind>runs|reviews|exports|artifacts)/"
    r"(?P<resource_id>[A-Za-z0-9][A-Za-z0-9_-]*)$"
)
_ARTIFACT_RESOURCE_API: Final[re.Pattern[str]] = re.compile(
    r"^/api/v1/artifacts/(?P<artifact_id>[A-Za-z0-9][A-Za-z0-9_-]*)"
    r"(?:/versions(?:/(?P<version_id>[A-Za-z0-9][A-Za-z0-9_-]*)"
    r"(?:/(?P<operation>download|attachments))?)?)?$"
)


@dataclass(frozen=True, slots=True)
class Principal:
    """The server-derived authenticated identity."""

    user_id: str
    organization_id: str
    email: str
    organization_name: str


class SessionAuthority(Protocol):
    """Resolve, verify, and revoke opaque authenticated browser sessions."""

    def principal_for(self, token: str) -> Principal | None:
        """Return an active server-derived principal."""
        ...

    def csrf_matches(self, token: str, supplied: str) -> bool:
        """Verify a CSRF capability bound to the opaque session."""
        ...

    def revoke(self, token: str) -> None:
        """Revoke the opaque session if it exists."""
        ...


@dataclass(frozen=True, slots=True)
class ProviderAuthorization:
    """Official OAuth instructions produced by the server-side broker."""

    authorization_url: str | None = None
    device_instruction: str | None = None


@dataclass(frozen=True, slots=True)
class ProviderDiagnosticRecord:
    """Redacted durable evidence for a suppressed provider failure."""

    request_id: str
    occurred_at: datetime
    route: str
    method: str
    principal_hash: str
    exception_class: str
    traceback_sha256: str


@dataclass(frozen=True, slots=True)
class _ProviderDiagnosticContext:
    request_id: str
    route: str
    method: str
    principal_hash: str


class ProviderDiagnosticSink(Protocol):
    """Durably append redacted provider diagnostics."""

    def append(self, record: ProviderDiagnosticRecord) -> None:
        """Persist a diagnostic before its failure is suppressed."""
        ...


class ProviderOAuthBroker(Protocol):
    """Boundary that alone handles official provider authorization and exchange."""

    def authorize(
        self, adapter_id: str, state: str, flow: str, redirect_uri: str
    ) -> ProviderAuthorization:
        """Create official authorization instructions."""
        ...

    def exchange(self, claim: OAuthClaim) -> OfficialOAuthCompletion:
        """Exchange a server-validated official OAuth claim."""
        ...

    def adopt_completion(
        self, adoption: ProviderCompletionAdoption, connection: ProviderConnection
    ) -> None:
        """Durably adopt a staged lease and cancel its broker-owned cleanup TTL."""
        ...

    def abandon_completion(self, completion: OfficialOAuthCompletion) -> None:
        """Durably defer or destroy an unadopted lease using broker-owned TTL."""
        ...

    def health(self, connection: ProviderConnection) -> Health:
        """Return runtime health without qualification evidence."""
        ...


@dataclass(frozen=True, slots=True)
class ProductServerOptions:
    """Bundled dependencies for loopback tenant, provider, and fixture surfaces."""

    repository: TenantRepository | None = None
    dry_lab: ProductDryLabService | None = None
    principal: Principal | None = None
    provider_runtime: ProviderRuntimeService | None = None
    provider_oauth_broker: ProviderOAuthBroker | None = None
    provider_diagnostic_sink: ProviderDiagnosticSink | None = None
    provider_authorization_endpoints: tuple[tuple[str, str], ...] = ()
    public_origin: str | None = None
    session_authority: SessionAuthority | None = None
    artifact_http: ArtifactHttpService | None = None
    provider_run_dispatcher: ProviderRunDispatcher | None = None
    uuid7_factory: IdFactory | None = None
    collection_fetcher: CollectionFetcher | None = None
    connector_settings: ConnectorSettingsBackend | None = None
    collections: CollectionBackend | None = None


@dataclass(frozen=True, slots=True)
class _TrustedOrigin:
    origin: str
    authority: str


def _trusted_origin(value: str) -> _TrustedOrigin:
    """Validate and split one canonical deployment-controlled public origin."""
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as error:
        raise ValueError(_PUBLIC_ORIGIN_MESSAGE) from error
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(_PUBLIC_ORIGIN_MESSAGE)
    ascii_hostname = hostname.encode("idna").decode("ascii")
    host = f"[{ascii_hostname}]" if ":" in ascii_hostname else ascii_hostname
    default_port = 80 if parsed.scheme == "http" else 443
    authority = host if port in {None, default_port} else f"{host}:{port}"
    origin = f"{parsed.scheme}://{authority}"
    if value != origin:
        raise ValueError(_PUBLIC_ORIGIN_MESSAGE)
    return _TrustedOrigin(origin, authority)


def _trusted_provider_authorization_endpoints(
    entries: tuple[tuple[str, str], ...],
) -> dict[str, str]:
    endpoints: dict[str, str] = {}
    for adapter_id, endpoint in entries:
        try:
            parsed = urlsplit(endpoint)
            port = parsed.port
        except ValueError as error:
            raise ValueError(_UNSAFE_PROVIDER_AUTHORIZATION_MESSAGE) from error
        if (
            _PROVIDER_ADAPTER_ID.fullmatch(adapter_id) is None
            or adapter_id in endpoints
            or len(endpoint) > _PROVIDER_AUTHORIZATION_MAX_LENGTH
            or parsed.scheme != "https"
            or parsed.hostname is None
            or parsed.username is not None
            or parsed.password is not None
            or port is not None
            or not parsed.path.startswith("/")
            or parsed.query
            or parsed.fragment
            or parsed.geturl() != endpoint
        ):
            raise ValueError(_UNSAFE_PROVIDER_AUTHORIZATION_MESSAGE)
        endpoints[adapter_id] = endpoint
    return endpoints


def _bound_loopback_origin(server: BoundedThreadingHttpServer) -> _TrustedOrigin:
    """Derive the local default from the bound socket, never request headers."""
    host = cast("str", server.server_address[0])
    port = server.server_address[1]
    authority = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    return _TrustedOrigin(f"http://{authority}", authority)


@dataclass(slots=True)
class MagicLink:
    """Persisted one-use magic-link metadata; plaintext token is never stored."""

    token_digest: str
    intent_digest: str
    principal: Principal
    expires_at: datetime
    used: bool = False


@dataclass(slots=True)
class Session:
    """Persisted opaque browser session metadata."""

    token_digest: str
    principal: Principal
    created_at: datetime
    last_seen_at: datetime
    absolute_expires_at: datetime
    revoked: bool = False


@final
class ProductStore:
    """Thread-safe typed in-process state for loopback product journeys."""

    def __init__(
        self, clock: Clock, fixture_principal: Principal | None = None
    ) -> None:
        """Initialize tenant fixtures and isolated session state with `clock`."""
        self._clock = clock
        self._lock = Lock()
        self._magic_links: dict[str, MagicLink] = {}
        self._sessions: dict[str, Session] = {}
        self._csrf_key = secrets.token_bytes(32)
        self._delivery_token: str | None = None
        self.fixture_principal = fixture_principal

    def issue_magic_link(self, email: str) -> tuple[str | None, str]:
        """Create a test link only for the fixture principal and always issue intent."""
        intent = secrets.token_urlsafe(32)
        principal = self.fixture_principal
        if principal is None or email != principal.email:
            return None, intent

        token = secrets.token_urlsafe(32)
        digest = _digest(token)
        with self._lock:
            self._magic_links[digest] = MagicLink(
                digest,
                _digest(intent),
                principal,
                self._clock() + _MAGIC_LINK_TTL,
            )
        return token, intent

    def delivered_token(self) -> str | None:
        """Return the latest delivered plaintext token for tests, never HTTP."""
        # A digest cannot be reversed. Keep the test delivery outbox separate
        # from persisted state.
        with self._lock:
            return self._delivery_token

    def request_magic_link(self, email: str) -> str:
        """Retain only valid test delivery values outside persisted link records."""
        token, intent = self.issue_magic_link(email)
        if token is not None:
            with self._lock:
                self._delivery_token = token
        return intent

    def exchange(self, token: str, intent: str) -> str | None:
        """Atomically consume a valid intent-bound magic link and create a session."""
        now = self._clock()
        with self._lock:
            link = self._magic_links.get(_digest(token))
            if (
                link is None
                or link.used
                or link.expires_at <= now
                or not secrets.compare_digest(link.intent_digest, _digest(intent))
            ):
                return None
            link.used = True
            session_token = secrets.token_urlsafe(32)
            digest = _digest(session_token)
            self._sessions[digest] = Session(
                digest,
                link.principal,
                now,
                now,
                now + _SESSION_ABSOLUTE_TTL,
            )
            return session_token

    def fixture_session_token(self, token: str | None = None) -> str:
        """Create an authenticated test session without exposing an HTTP bypass."""
        principal = self.fixture_principal
        if principal is None:
            raise RuntimeError(_FIXTURE_SESSION_UNAVAILABLE_MESSAGE)
        now = self._clock()
        token = token or secrets.token_urlsafe(32)
        digest = _digest(token)
        with self._lock:
            self._sessions[digest] = Session(
                digest,
                principal,
                now,
                now,
                now + _SESSION_ABSOLUTE_TTL,
            )
        return token

    def csrf_token_for(self, token: str) -> str | None:
        """Return the CSRF capability only while its browser session is valid."""
        now = self._clock()
        with self._lock:
            session = self._sessions.get(_digest(token))
            if not self._session_is_valid(session, now):
                return None
        return hmac.digest(self._csrf_key, token.encode("utf-8"), "sha256").hex()

    def csrf_matches(self, token: str, supplied: str) -> bool:
        """Verify one unguessable CSRF capability bound to the opaque session."""
        expected = self.csrf_token_for(token)
        return expected is not None and hmac.compare_digest(expected, supplied)

    @staticmethod
    def _session_is_valid(session: Session | None, now: datetime) -> bool:
        return bool(
            session is not None
            and not session.revoked
            and session.absolute_expires_at > now
            and session.last_seen_at + _SESSION_IDLE_TTL > now
        )

    def principal_for(self, token: str) -> Principal | None:
        """Resolve a currently valid session and update its idle timestamp."""
        now = self._clock()
        with self._lock:
            session = self._sessions.get(_digest(token))
            if session is None or not self._session_is_valid(session, now):
                return None
            session.last_seen_at = now
            return session.principal

    def revoke(self, token: str) -> None:
        """Revoke a session token if it exists."""
        with self._lock:
            session = self._sessions.get(_digest(token))
            if session is not None:
                session.revoked = True


def _digest(value: str) -> str:
    return sha256(value.encode("utf-8")).hexdigest()


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _provider_error_status(code: str) -> HTTPStatus:
    """Map stable provider domain errors to their documented HTTP status."""
    if code == ERROR_ADAPTER_DISABLED:
        return HTTPStatus.FORBIDDEN
    if code == ERROR_REVISION_CONFLICT:
        return HTTPStatus.PRECONDITION_FAILED
    if code in {
        ERROR_QUALIFICATION_REQUIRED,
        ERROR_QUOTA_EXHAUSTED,
        ERROR_REAUTH_REQUIRED,
    }:
        return HTTPStatus.CONFLICT
    if code == ERROR_PROVIDER_UNAVAILABLE:
        return HTTPStatus.SERVICE_UNAVAILABLE
    if code in {
        ERROR_ACCOUNT_UNAVAILABLE,
        ERROR_INVALID_COMPLETION,
        ERROR_INVALID_CONNECTION_ID,
        ERROR_INVALID_HEALTH,
        ERROR_INVALID_NONCE,
        ERROR_INVALID_OAUTH_REQUEST,
        ERROR_MODEL_UNAVAILABLE,
        ERROR_OAUTH_BINDING_MISMATCH,
        ERROR_OAUTH_EXPIRED,
        ERROR_UNSAFE_COMPLETION,
    }:
        return HTTPStatus.BAD_REQUEST
    return HTTPStatus.SERVICE_UNAVAILABLE


class ProductServer(BoundedThreadingHttpServer):
    """HTTP server carrying auth state and an injected tenant repository."""

    def __init__(
        self,
        address: tuple[str, int],
        clock: Clock,
        options: ProductServerOptions | None = None,
    ) -> None:
        """Initialize the loopback server with fixture auth and injected boundaries."""
        options = options or ProductServerOptions()
        configured_origin = (
            _trusted_origin(options.public_origin)
            if options.public_origin is not None
            else None
        )
        provider_configured = (
            options.provider_runtime is not None
            or options.provider_oauth_broker is not None
        )
        if provider_configured and options.provider_diagnostic_sink is None:
            raise ValueError(_PROVIDER_DEPENDENCIES_MESSAGE)
        if options.session_authority is not None and options.principal is not None:
            raise ValueError(_EXTERNAL_SESSION_FIXTURE_MESSAGE)
        if options.artifact_http is not None and options.session_authority is None:
            raise ValueError(_ARTIFACT_PRODUCTION_DEPENDENCIES_MESSAGE)
        super().__init__(address, ProductRequestHandler)
        trusted_origin = configured_origin or _bound_loopback_origin(self)
        self.daemon_threads: bool = True
        self.public_origin: str = trusted_origin.origin
        self.public_authority: str = trusted_origin.authority
        self.secure_cookies: bool = trusted_origin.origin.startswith("https://")
        self.intent_cookie_name: str = (
            _PRODUCTION_INTENT_COOKIE
            if self.secure_cookies
            else _DEVELOPMENT_INTENT_COOKIE
        )
        self.session_cookie_name: str = (
            _PRODUCTION_SESSION_COOKIE
            if self.secure_cookies
            else _DEVELOPMENT_SESSION_COOKIE
        )
        self.csrf_cookie_name: str = (
            _PRODUCTION_CSRF_COOKIE
            if self.secure_cookies
            else _DEVELOPMENT_CSRF_COOKIE
        )
        self.store: ProductStore = ProductStore(clock, options.principal)
        self.connector_settings: ConnectorSettingsBackend = (
            options.connector_settings or ConnectorSettingsStore()
        )
        self.collection_plans: CollectionPlanStore = CollectionPlanStore(clock)
        self.collections: CollectionBackend = options.collections or CollectionStore(
            clock
        )
        self.collection_fetcher: CollectionFetcher = (
            options.collection_fetcher or live_collection_fetcher
        )
        self.session_authority: SessionAuthority = (
            options.session_authority or self.store
        )
        self.local_auth_enabled: bool = options.session_authority is None
        self.artifact_http: ArtifactHttpService | None = options.artifact_http
        self.repository: TenantRepository = (
            options.repository or InMemoryTenantRepository((), ())
        )
        self.clock: Clock = clock
        self.uuid7_factory: IdFactory = options.uuid7_factory or Uuid7Factory()
        self.provider_runtime: ProviderRuntimeService | None = options.provider_runtime
        self.provider_run_dispatcher: ProviderRunDispatcher | None = (
            options.provider_run_dispatcher
        )
        self.provider_oauth_broker: ProviderOAuthBroker | None = (
            options.provider_oauth_broker
        )
        self.provider_authorization_endpoints: dict[str, str] = (
            _trusted_provider_authorization_endpoints(
                options.provider_authorization_endpoints
            )
        )
        self.provider_diagnostic_sink: ProviderDiagnosticSink | None = (
            options.provider_diagnostic_sink
        )
        self._provider_idempotency: dict[
            ProviderIdempotencyKey, _ProviderIdempotencyEntry
        ] = {}
        self._provider_idempotency_lock: Lock = Lock()
        self._provider_idempotency_ready: Condition = Condition(
            self._provider_idempotency_lock
        )
        self._fixture_session_token: str | None = None
        self.dry_lab: ProductDryLabService | None = options.dry_lab

    def fixture_session_cookie(self, token: str | None = None) -> str:
        """Return the stable non-production authenticated fixture cookie value."""
        session_token = self._ensure_fixture_session_token(token)
        csrf_token = self.store.csrf_token_for(session_token)
        if csrf_token is None:
            raise RuntimeError(_FIXTURE_SESSION_UNAVAILABLE_MESSAGE)
        return (
            f"{self.session_cookie_name}={session_token}; "
            f"{self.csrf_cookie_name}={csrf_token}"
        )

    def fixture_csrf_token(self) -> str:
        """Return the CSRF capability paired with the authenticated fixture."""
        csrf_token = self.store.csrf_token_for(self._ensure_fixture_session_token())
        if csrf_token is None:
            raise RuntimeError(_FIXTURE_SESSION_UNAVAILABLE_MESSAGE)
        return csrf_token

    def _ensure_fixture_session_token(self, requested: str | None = None) -> str:
        if self._fixture_session_token is None:
            self._fixture_session_token = self.store.fixture_session_token(requested)
        elif requested is not None and requested != self._fixture_session_token:
            raise ValueError(_FIXTURE_SESSION_ALREADY_INITIALIZED_MESSAGE)
        return self._fixture_session_token

    def _make_idempotency_capacity(self, now: datetime) -> bool:
        """Prune expired entries and evict one completed entry when full."""
        expired = [
            key
            for key, entry in self._provider_idempotency.items()
            if entry.complete and entry.expires_at <= now
        ]
        for key in expired:
            del self._provider_idempotency[key]
        if len(self._provider_idempotency) < _PROVIDER_IDEMPOTENCY_CAPACITY:
            return True
        completed = [
            (key, cached)
            for key, cached in self._provider_idempotency.items()
            if cached.complete
        ]
        if not completed:
            return False
        oldest_key, _ = min(completed, key=lambda item: item[1].expires_at)
        del self._provider_idempotency[oldest_key]
        return True

    def abandon_provider_idempotency(self, entry: _ProviderIdempotencyEntry) -> None:
        """Remove an unrecorded failure and wake followers without caching it."""
        with self._provider_idempotency_ready:
            for key, cached in self._provider_idempotency.items():
                if cached is entry:
                    del self._provider_idempotency[key]
                    break
            self._provider_idempotency_ready.notify_all()

    def record_provider_failure(
        self,
        context: _ProviderDiagnosticContext,
        exception: Exception,
        exception_traceback: TracebackType | None,
    ) -> None:
        """Durably append the minimal redacted evidence for a suppressed failure."""
        sink = self.provider_diagnostic_sink
        if sink is None:
            raise RuntimeError(_PROVIDER_DIAGNOSTIC_SINK_MESSAGE)
        rendered = "".join(
            traceback_module.format_exception(
                type(exception), exception, exception_traceback
            )
        )
        sink.append(
            ProviderDiagnosticRecord(
                request_id=context.request_id,
                occurred_at=self.clock().astimezone(UTC),
                route=context.route,
                method=context.method,
                principal_hash=context.principal_hash,
                exception_class=type(exception).__name__,
                traceback_sha256=sha256(rendered.encode()).hexdigest(),
            )
        )

    @staticmethod
    def provider_request_id(body: JsonObject) -> str:
        """Extract the generated ErrorEnvelope request ID."""
        error = body.get("error")
        if not isinstance(error, dict):
            raise TypeError(_PROVIDER_ERROR_ENVELOPE_MESSAGE)
        request_id = error.get("request_id")
        if not isinstance(request_id, str):
            raise TypeError(_PROVIDER_ERROR_ENVELOPE_MESSAGE)
        return request_id

    def complete_provider_idempotency(
        self,
        entry: _ProviderIdempotencyEntry,
        status: HTTPStatus,
        body: JsonObject,
        failure_type: str | None = None,
    ) -> None:
        """Publish a terminal idempotency response and wake all followers."""
        with self._provider_idempotency_ready:
            entry.status = status
            entry.body = body
            entry.failure_type = failure_type
            entry.complete = True
            self._provider_idempotency_ready.notify_all()

    def _cached_provider_response(
        self,
        request: ProviderIdempotencyRequest,
        entry: _ProviderIdempotencyEntry,
    ) -> tuple[HTTPStatus, JsonObject]:
        """Resolve conflict, follower abandonment, or an exact cached response."""
        if entry.digest != request.digest:
            return self.provider_error(HTTPStatus.CONFLICT, "idempotency_conflict")
        while not entry.complete:
            _ = self._provider_idempotency_ready.wait()
            if self._provider_idempotency.get(request.cache_key) is not entry:
                return self.provider_error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "diagnostic_unavailable",
                )
        if entry.status is None or entry.body is None:
            return self.provider_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "idempotency_incomplete",
            )
        return entry.status, entry.body

    def execute_provider_idempotency(
        self,
        request: ProviderIdempotencyRequest,
        operation: Callable[[], tuple[HTTPStatus, JsonObject]],
    ) -> tuple[HTTPStatus, JsonObject]:
        """Single-flight a provider POST and bound its replay cache."""
        with self._provider_idempotency_ready:
            now = self.clock()
            entry = self._provider_idempotency.get(request.cache_key)
            if entry is not None:
                return self._cached_provider_response(request, entry)
            has_capacity = self._make_idempotency_capacity(now)
            if not has_capacity:
                return self.provider_error(
                    HTTPStatus.SERVICE_UNAVAILABLE,
                    "idempotency_capacity_exceeded",
                )
            entry = _ProviderIdempotencyEntry(
                digest=request.digest,
                expires_at=now + _PROVIDER_IDEMPOTENCY_TTL,
            )
            self._provider_idempotency[request.cache_key] = entry
        failure_guard = _ProviderIdempotencyFailureGuard(
            self,
            entry,
            request,
        )
        with failure_guard:
            try:
                status, body = operation()
            except ConnectionNotFoundError:
                status, body = self.provider_error(HTTPStatus.NOT_FOUND, "not_found")
            except ProviderRuntimeError as error:
                status, body = self.provider_error(
                    _provider_error_status(error.code), error.code
                )
            self.complete_provider_idempotency(entry, status, body)
            return status, body
        return failure_guard.response()

    def provider_error(
        self, status: HTTPStatus, code: str
    ) -> tuple[HTTPStatus, JsonObject]:
        """Return the OpenAPI ErrorEnvelope for provider endpoints."""
        return status, {
            "error": {
                "code": code,
                "message": code.replace("_", " "),
                "request_id": str(self.uuid7_factory.new_uuid7()),
            }
        }


@final
class _ProviderIdempotencyFailureGuard:
    """Terminalize ordinary unexpected failures without intercepting controls."""

    def __init__(
        self,
        server: ProductServer,
        entry: _ProviderIdempotencyEntry,
        request: ProviderIdempotencyRequest,
    ) -> None:
        self._server = server
        self._entry = entry
        self._request = request
        self._response: tuple[HTTPStatus, JsonObject] | None = None

    def __enter__(self) -> _ProviderIdempotencyFailureGuard:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        if exception_type is None or not issubclass(exception_type, Exception):
            return False
        if not isinstance(exception, Exception):
            return False
        status, body = self._server.provider_error(
            HTTPStatus.SERVICE_UNAVAILABLE, "provider_unavailable"
        )
        context = _ProviderDiagnosticContext(
            self._server.provider_request_id(body),
            self._request.route,
            self._request.method,
            self._request.principal_hash,
        )
        write_guard = _ProviderDiagnosticWriteGuard(self._server, self._entry)
        with write_guard:
            self._server.record_provider_failure(
                context,
                exception,
                traceback,
            )
        if write_guard.failed:
            return False
        self._server.complete_provider_idempotency(self._entry, status, body)
        self._response = status, body
        return True

    def response(self) -> tuple[HTTPStatus, JsonObject]:
        """Return the terminal response published for a suppressed failure."""
        if self._response is None:
            return self._server.provider_error(
                HTTPStatus.SERVICE_UNAVAILABLE,
                "provider_unavailable",
            )
        return self._response


@final
class _ProviderDiagnosticWriteGuard:
    """Abandon an idempotency entry if durable diagnostic append fails."""

    def __init__(
        self,
        server: ProductServer,
        entry: _ProviderIdempotencyEntry,
    ) -> None:
        self._server = server
        self._entry = entry
        self.failed: bool = False

    def __enter__(self) -> _ProviderDiagnosticWriteGuard:
        return self

    def __exit__(
        self,
        exception_type: type[BaseException] | None,
        exception: BaseException | None,
        traceback: TracebackType | None,
    ) -> bool:
        del exception, traceback
        if exception_type is None:
            return False
        self._server.abandon_provider_idempotency(self._entry)
        if not issubclass(exception_type, Exception):
            return False
        self.failed = True
        return True



def _parse_dry_lab_run_action(path: str) -> tuple[str, str] | None:
    parts = path.split("/")
    if len(parts) != _RUN_ACTION_PATH_PARTS or parts[1:4] != ["api", "v1", "runs"]:
        return None
    run_id, action = parts[4:]
    if not run_id or action not in {
        "approve",
        "reject",
        "cancel",
        "execute",
        "review",
        "export",
        "cleanup",
    }:
        return None
    return run_id, action


class ProductRequestHandler(BaseHTTPRequestHandler):
    """Minimal same-origin HTTP handler with redacted request logging."""

    @property
    def product_server(self) -> ProductServer:
        """Return the typed product server backing this request handler."""
        return cast("ProductServer", self.server)

    @override
    def log_message(self, format: str, *args: object) -> None:
        """Avoid emitting request paths, cookies, or token-bearing payloads."""
        del format, args

    def do_GET(self) -> None:
        """Serve an authenticated API response or a product static asset."""
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/"):
            self._get_api(path)
            return
        self._static(path)

    def do_POST(self) -> None:
        """Handle same-origin authentication and research-run mutations."""
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/provider-connections"):
            self._provider_mutation(path)
        elif self._local_auth_mutation(path):
            return
        elif path.startswith("/api/v1/connectors/"):
            self._connector_mutation(path)
        elif self._collection_mutation(path):
            return
        elif path == "/api/v1/runs":
            self._create_local_run()
        elif path.startswith("/api/v1/runs/"):
            self._dry_lab_mutation(path)
        elif path == "/api/v1/artifacts":
            self._artifact_create()
        elif path.startswith("/api/v1/artifacts/"):
            self._artifact_mutation(path, attach=True)
        else:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)

    def _local_auth_mutation(self, path: str) -> bool:
        if path == "/api/v1/auth/logout":
            self._logout()
            return True
        operation = {
            "/api/v1/auth/magic-link": self._magic_link,
            "/api/v1/auth/exchange": self._exchange,
        }.get(path)
        if operation is None:
            return False
        if self.product_server.local_auth_enabled:
            operation()
        else:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
        return True

    def _collection_mutation(self, path: str) -> bool:
        """Dispatch collection plan, execute, and materialize mutations."""
        if path == "/api/v1/collections/plan":
            self._collection_plan()
        elif path == "/api/v1/collections/execute":
            self._collection_execute()
        elif path.startswith("/api/v1/collections/") and path.endswith(
            "/materialize"
        ):
            self._collection_materialize(path)
        else:
            return False
        return True

    def do_DELETE(self) -> None:
        """Revoke a provider connection through the same-origin mutation boundary."""
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/provider-connections/"):
            self._provider_mutation(path)
        elif path.startswith("/api/v1/artifacts/"):
            self._artifact_mutation(path, attach=False)
        else:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)

    def _json(self) -> tuple[JsonObject | None, HTTPStatus]:
        """Read one unambiguously framed JSON object within the request budget."""
        lengths = self.headers.get_all("Content-Length") or []
        transfer_encodings = self.headers.get_all("Transfer-Encoding") or []
        if len(lengths) != 1 or transfer_encodings:
            return None, HTTPStatus.BAD_REQUEST
        try:
            length = int(lengths[0])
        except ValueError:
            return None, HTTPStatus.BAD_REQUEST
        if length > _MAX_JSON_BODY_BYTES:
            return None, HTTPStatus.REQUEST_ENTITY_TOO_LARGE
        if length <= 0 or str(length) != lengths[0]:
            return None, HTTPStatus.BAD_REQUEST
        try:
            body = self.rfile.read(length)
            data = _JSON_OBJECT_ADAPTER.validate_json(body)
            return (
                (data, HTTPStatus.OK)
                if len(body) == length
                else (None, HTTPStatus.BAD_REQUEST)
            )
        except (OSError, ValidationError):
            return None, HTTPStatus.BAD_REQUEST

    def _same_origin_mutation(self) -> bool:
        origins = self.headers.get_all("Origin") or []
        hosts = self.headers.get_all("Host") or []
        fetch_sites = self.headers.get_all("Sec-Fetch-Site") or []
        fetch_modes = self.headers.get_all("Sec-Fetch-Mode") or []
        return (
            origins == [self.product_server.public_origin]
            and hosts == [self.product_server.public_authority]
            and fetch_sites == ["same-origin"]
            and len(fetch_modes) == 1
            and fetch_modes[0] in {"cors", "same-origin"}
        )

    def _cookie_value(self, name: str) -> str | None:
        """Resolve one unambiguous cookie value from one Cookie header."""
        headers = self.headers.get_all("Cookie") or []
        if len(headers) != 1:
            return None
        matches = [
            value
            for part in headers[0].split(";")
            for cookie_name, separator, value in (part.strip().partition("="),)
            if cookie_name == name and separator
        ]
        return matches[0] if len(matches) == 1 else None

    def _csrf_matches(self, token: str) -> bool:
        csrf_headers = self.headers.get_all("X-CSRF-Token") or []
        return (
            len(csrf_headers) == 1
            and self.product_server.session_authority.csrf_matches(
                token,
                csrf_headers[0],
            )
        )

    def _send_body_error(self, status: HTTPStatus) -> None:
        body = (
            _PAYLOAD_TOO_LARGE
            if status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
            else _BAD_REQUEST
        )
        self._send(status, body)

    def _magic_link(self) -> None:
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return
        data, status = self._json()
        if data is None:
            self._send_body_error(status)
            return
        email = data.get("email") if data else None
        if not isinstance(email, str):
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        intent = self.product_server.store.request_magic_link(email)
        self._send(
            HTTPStatus.ACCEPTED,
            _MAGIC_LINK_RESPONSE,
            {
                "Set-Cookie": _cookie(
                    self.product_server.intent_cookie_name,
                    intent,
                    max_age=_MAGIC_LINK_MAX_AGE,
                    secure=self.product_server.secure_cookies,
                )
            },
        )

    def _exchange(self) -> None:
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return
        data, status = self._json()
        if data is None:
            self._send_body_error(status)
            return
        token = data.get("token") if data else None
        intent = self._cookie_value(self.product_server.intent_cookie_name) or ""
        if not isinstance(token, str):
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        session_token = self.product_server.store.exchange(token, intent)
        if session_token is None:
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        csrf_token = self.product_server.store.csrf_token_for(session_token)
        if csrf_token is None:
            self.product_server.store.revoke(session_token)
            self._send(HTTPStatus.SERVICE_UNAVAILABLE, _SERVICE_UNAVAILABLE)
            return
        self._send(
            HTTPStatus.OK,
            b'{"status":"authenticated"}',
            (
                (
                    "Set-Cookie",
                    _cookie(
                        self.product_server.session_cookie_name,
                        session_token,
                        max_age=_SESSION_MAX_AGE,
                        secure=self.product_server.secure_cookies,
                    ),
                ),
                (
                    "Set-Cookie",
                    _cookie(
                        self.product_server.csrf_cookie_name,
                        csrf_token,
                        max_age=_SESSION_MAX_AGE,
                        secure=self.product_server.secure_cookies,
                        http_only=False,
                    ),
                ),
                (
                    "Set-Cookie",
                    _expired_cookie(
                        self.product_server.intent_cookie_name,
                        secure=self.product_server.secure_cookies,
                    ),
                ),
            ),
        )

    def _logout(self) -> None:
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return
        token = self._session_token()
        if token and not self._csrf_matches(token):
            self._send(HTTPStatus.FORBIDDEN, _INVALID_CSRF)
            return
        if token:
            dry_lab = self.product_server.dry_lab
            if dry_lab is not None:
                dry_lab.drop_session(_digest(token))
            self.product_server.session_authority.revoke(token)
        self._send(
            HTTPStatus.NO_CONTENT,
            b"",
            (
                (
                    "Set-Cookie",
                    _expired_cookie(
                        self.product_server.session_cookie_name,
                        secure=self.product_server.secure_cookies,
                    ),
                ),
                (
                    "Set-Cookie",
                    _expired_cookie(
                        self.product_server.csrf_cookie_name,
                        secure=self.product_server.secure_cookies,
                        http_only=False,
                    ),
                ),
            ),
        )

    def _session_token(self) -> str | None:
        """Return the opaque session cookie without exposing it to adapters."""
        return self._cookie_value(self.product_server.session_cookie_name)

    def _principal(self) -> Principal | None:
        token = self._session_token()
        return (
            self.product_server.session_authority.principal_for(token)
            if token
            else None
        )

    def _tenant_principal(self, principal: Principal) -> TenantPrincipal:
        """Adapt server-derived auth state to the repository's RLS identity."""
        return TenantPrincipal(principal.user_id, principal.organization_id)

    def _dry_lab_service(self) -> ProductDryLabService | None:
        service = self.product_server.dry_lab
        if service is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
        return service

    def _get_api(self, path: str) -> None:
        if self.product_server.artifact_http is not None and (
            (self.headers.get_all("Host") or [])
            != [self.product_server.public_authority]
        ):
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return
        principal = self._principal()
        if principal is None:
            if path.startswith("/api/v1/provider-connections"):
                self._send_provider_error(HTTPStatus.UNAUTHORIZED, "unauthorized")
            else:
                self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return
        self._respond_to_api(path, principal)

    def _respond_to_api(self, path: str, principal: Principal) -> None:
        if path.startswith("/api/v1/provider-connections"):
            self._provider_get(path, principal)
        elif (
            handler := {
                "/api/v1/me": self._api_me,
                "/api/v1/workspace": self._api_workspace,
                "/api/v1/connectors": self._connectors_list,
                "/api/v1/collections": self._api_collections,
            }.get(path)
        ) is not None:
            handler(principal)
        elif path.startswith("/api/v1/collections/"):
            self._api_collection(path, principal)
        elif path == "/api/v1/artifacts":
            self._api_artifacts()
        elif path.startswith("/api/v1/artifacts/"):
            artifact_http = self.product_server.artifact_http
            if artifact_http is None:
                self._artifact_get(path)
            else:
                self._durable_artifact_get(artifact_http, path, principal)
        elif _DRY_LAB_RESOURCE_API.fullmatch(path):
            self._dry_lab_resource(path)
        elif path.startswith("/api/v1/projects/"):
            self._api_project(path, principal)
        elif path.startswith("/api/v1/sessions/"):
            self._api_session(path, principal)
        else:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)

    def _provider_get(self, path: str, principal: Principal) -> None:
        runtime = self.product_server.provider_runtime
        broker = self.product_server.provider_oauth_broker
        if runtime is None or broker is None:
            self._send_provider_error(HTTPStatus.FORBIDDEN, "capability_disabled")
            return
        provider_principal = self._provider_principal(principal)
        try:
            for adoption, connection in runtime.pending_completion_adoptions(
                provider_principal
            ):
                broker.adopt_completion(adoption, connection)
                runtime.confirm_completion_adoption(
                    provider_principal,
                    connection.connection_id,
                    adoption.staging_lease_id,
                )
            if path == "/api/v1/provider-connections/registry":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "adapters": [
                            {
                                "id": adapter.adapter_id,
                                "name": adapter.display_name,
                                "availability_label": adapter.availability_label,
                                "required": adapter.required,
                                "default": adapter.launch_default,
                                "connectable": adapter.connectable,
                                "disabled_reason": adapter.disabled_reason,
                            }
                            for adapter in runtime.adapters()
                        ]
                    },
                )
            elif path == "/api/v1/provider-connections":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "connections": [
                            _provider_connection_json(connection)
                            for connection in runtime.list_connections(
                                provider_principal
                            )
                        ]
                    },
                )
            else:
                connection_id = path.removeprefix("/api/v1/provider-connections/")
                if "/" in connection_id or not connection_id:
                    self._send_provider_error(HTTPStatus.NOT_FOUND, "not_found")
                    return
                self._send_json(
                    HTTPStatus.OK,
                    _provider_connection_json(
                        runtime.connection_detail(provider_principal, connection_id)
                    ),
                )
        except ConnectionNotFoundError:
            self._send_provider_error(HTTPStatus.NOT_FOUND, "not_found")
        except ProviderRuntimeError as error:
            self._send_provider_error(_provider_error_status(error.code), error.code)
        except (OSError, RuntimeError, TimeoutError, ValueError) as error:
            self._send_unexpected_provider_error(path, provider_principal, error)

    def _provider_mutation(self, path: str) -> None:
        if not self._same_origin_mutation():
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_origin")
            return
        dependencies = self._authenticated_provider_dependencies()
        if dependencies is None:
            return
        token = self._session_token()
        if token is None or not self._csrf_matches(token):
            self._send_provider_error(HTTPStatus.FORBIDDEN, "invalid_csrf")
            return
        if self.command == "POST" and not self.headers.get("Idempotency-Key"):
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_request")
            return
        data = self._provider_mutation_body(path)
        if data is None:
            return
        provider_principal, runtime, broker = dependencies
        try:
            for adoption, connection in runtime.pending_completion_adoptions(
                provider_principal
            ):
                broker.adopt_completion(adoption, connection)
                runtime.confirm_completion_adoption(
                    provider_principal,
                    connection.connection_id,
                    adoption.staging_lease_id,
                )
            self._dispatch_provider_mutation(path, *dependencies, data)
        except ConnectionNotFoundError:
            self._send_provider_error(HTTPStatus.NOT_FOUND, "not_found")
        except ProviderRuntimeError as error:
            self._send_provider_error(_provider_error_status(error.code), error.code)
        except (OSError, RuntimeError, TimeoutError, ValueError) as error:
            self._send_unexpected_provider_error(path, provider_principal, error)

    def _authenticated_provider_dependencies(
        self,
    ) -> tuple[ProviderPrincipal, ProviderRuntimeService, ProviderOAuthBroker] | None:
        """Resolve the authenticated runtime and OAuth broker for a mutation."""
        principal = self._principal()
        runtime = self.product_server.provider_runtime
        broker = self.product_server.provider_oauth_broker
        if principal is None:
            self._send_provider_error(HTTPStatus.UNAUTHORIZED, "unauthorized")
            return None
        if runtime is None or broker is None:
            self._send_provider_error(HTTPStatus.FORBIDDEN, "capability_disabled")
            return None
        return self._provider_principal(principal), runtime, broker

    def _provider_mutation_body(self, path: str) -> JsonObject | None:
        """Parse strict provider POST bodies, allowing only documented empty bodies."""
        if self.command != "POST":
            return {}
        lengths = self.headers.get_all("Content-Length") or []
        transfer_encodings = self.headers.get_all("Transfer-Encoding") or []
        if len(lengths) != 1 or transfer_encodings:
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_request")
            return None
        if lengths == ["0"]:
            if path.endswith(("/health", "/reauth")):
                return {}
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_request")
            return None
        data, status = self._json()
        if data is None:
            code = (
                "request_too_large"
                if status == HTTPStatus.REQUEST_ENTITY_TOO_LARGE
                else "invalid_request"
            )
            self._send_provider_error(status, code)
        return data

    def _dispatch_provider_mutation(
        self,
        path: str,
        principal: ProviderPrincipal,
        runtime: ProviderRuntimeService,
        broker: ProviderOAuthBroker,
        data: JsonObject,
    ) -> None:
        """Route an authenticated provider mutation to its domain operation."""
        if path == "/api/v1/provider-connections" and self.command == "POST":
            self._provider_initiate(principal, runtime, broker, data)
        elif (
            path == "/api/v1/provider-connections/oauth/complete"
            and self.command == "POST"
        ):
            self._provider_complete(principal, runtime, broker, data)
        elif (
            path == "/api/v1/provider-connections/oauth/cancel"
            and self.command == "POST"
        ):
            self._provider_cancel(principal, runtime, data)
        else:
            self._provider_connection_mutation(path, principal, runtime, broker, data)

    def _provider_cancel(
        self,
        principal: ProviderPrincipal,
        runtime: ProviderRuntimeService,
        data: JsonObject,
    ) -> None:
        """Cancel one pending OAuth flow after validating its single state field."""
        key = self.headers["Idempotency-Key"]
        state = data.get("state")
        if not isinstance(state, str) or len(data) != 1:
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_request")
            return
        digest = _digest(json.dumps(data, sort_keys=True, separators=(",", ":")))
        cache_key = (
            principal.user_id + ":" + principal.org_id,
            self.command,
            "/api/v1/provider-connections/oauth/cancel",
            key,
        )

        def operation() -> tuple[HTTPStatus, JsonObject]:
            runtime.cancel_pending(principal, state)
            return HTTPStatus.OK, {"status": "cancelled"}

        status, payload = self.product_server.execute_provider_idempotency(
            ProviderIdempotencyRequest(
                cache_key,
                digest,
                "/api/v1/provider-connections/oauth/cancel",
                self.command,
                _provider_principal_hash(principal),
            ),
            operation,
        )
        self._send_json(status, payload)

    def _provider_initiate(
        self,
        principal: ProviderPrincipal,
        runtime: ProviderRuntimeService,
        broker: ProviderOAuthBroker,
        data: JsonObject,
    ) -> None:
        key = self.headers["Idempotency-Key"]
        adapter_id = data.get("adapter_id")
        flow = data.get("flow")
        redirect_uri = data.get("redirect_uri")
        if (
            not isinstance(adapter_id, str)
            or flow not in ("callback", "device")
            or not isinstance(redirect_uri, str)
            or set(data) != {"adapter_id", "flow", "redirect_uri"}
        ):
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_request")
            return
        digest = _digest(json.dumps(data, sort_keys=True, separators=(",", ":")))
        cache_key = (
            principal.user_id + ":" + principal.org_id,
            self.command,
            "/api/v1/provider-connections",
            key,
        )

        def operation() -> tuple[HTTPStatus, JsonObject]:
            initiation = runtime.initiate(principal, adapter_id, flow, redirect_uri)
            authorization = broker.authorize(
                adapter_id, initiation.state, flow, redirect_uri
            )
            return HTTPStatus.ACCEPTED, _provider_initiation_json(
                adapter_id,
                initiation,
                authorization,
                self.product_server.provider_authorization_endpoints,
            )

        status, payload = self.product_server.execute_provider_idempotency(
            ProviderIdempotencyRequest(
                cache_key,
                digest,
                "/api/v1/provider-connections",
                self.command,
                _provider_principal_hash(principal),
            ),
            operation,
        )
        self._send_json(status, payload)

    def _provider_complete(
        self,
        principal: ProviderPrincipal,
        runtime: ProviderRuntimeService,
        broker: ProviderOAuthBroker,
        data: JsonObject,
    ) -> None:
        key = self.headers["Idempotency-Key"]
        state = data.get("state")
        flow = data.get("flow")
        redirect_uri = data.get("redirect_uri")
        if (
            not isinstance(state, str)
            or flow not in ("callback", "device")
            or not isinstance(redirect_uri, str)
            or set(data) != {"state", "flow", "redirect_uri"}
        ):
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_request")
            return
        digest = _digest(json.dumps(data, sort_keys=True, separators=(",", ":")))
        cache_key = (
            principal.user_id + ":" + principal.org_id,
            self.command,
            "/api/v1/provider-connections/oauth/complete",
            key,
        )

        def operation() -> tuple[HTTPStatus, JsonObject]:
            claim = runtime.claim_oauth(principal, state, flow, redirect_uri)
            try:
                completion = broker.exchange(claim)
            except Exception:
                runtime.abort_oauth(principal, claim)
                raise
            try:
                connection = runtime.finalize_oauth(principal, claim, completion)
            except Exception:
                with suppress(Exception):
                    broker.abandon_completion(completion)
                raise
            adoption = next(
                adoption
                for adoption, pending_connection in (
                    runtime.pending_completion_adoptions(principal)
                )
                if pending_connection.connection_id == connection.connection_id
            )
            broker.adopt_completion(adoption, connection)
            runtime.confirm_completion_adoption(
                principal, connection.connection_id, adoption.staging_lease_id
            )
            return HTTPStatus.OK, _provider_connection_json(connection)

        status, payload = self.product_server.execute_provider_idempotency(
            ProviderIdempotencyRequest(
                cache_key,
                digest,
                "/api/v1/provider-connections/oauth/complete",
                self.command,
                _provider_principal_hash(principal),
            ),
            operation,
        )
        self._send_json(status, payload)

    @staticmethod
    def _provider_connection_action(
        command: str,
        action: str,
        data: JsonObject,
    ) -> tuple[bool, str | None]:
        """Validate a connection mutation action and return its optional model."""
        if command != "POST" or action not in {"model", "health", "reauth"}:
            return False, None
        if action != "model":
            return not data, None
        model_id = data.get("model_id")
        return (
            isinstance(model_id, str)
            and provider_model_id_is_valid(model_id)
            and set(data) == {"model_id"}
        ), (model_id if isinstance(model_id, str) else None)

    def _provider_connection_mutation(
        self,
        path: str,
        principal: ProviderPrincipal,
        runtime: ProviderRuntimeService,
        broker: ProviderOAuthBroker,
        data: JsonObject,
    ) -> None:
        suffix = path.removeprefix("/api/v1/provider-connections/")
        connection_id, separator, action = suffix.partition("/")
        if not connection_id:
            self._send_provider_error(HTTPStatus.NOT_FOUND, "not_found")
            return
        revision = _if_match_revision(self.headers.get("If-Match"))
        if revision is None:
            self._send_provider_error(
                HTTPStatus.PRECONDITION_FAILED, ERROR_REVISION_CONFLICT
            )
            return
        if self.command == "DELETE" and not separator:
            receipt = runtime.revoke(principal, connection_id, revision)
            self._send_json(
                HTTPStatus.OK, {"cleanup_receipt": _cleanup_receipt_json(receipt)}
            )
            return
        valid_action, model_id = self._provider_connection_action(
            self.command,
            action,
            data,
        )
        if not valid_action:
            status = (
                HTTPStatus.NOT_FOUND
                if self.command != "POST" or action not in {"model", "health", "reauth"}
                else HTTPStatus.BAD_REQUEST
            )
            self._send_provider_error(
                status,
                "not_found" if status == HTTPStatus.NOT_FOUND else "invalid_request",
            )
            return
        key = self.headers["Idempotency-Key"]
        digest = _digest(
            json.dumps(
                {"body": data, "if_match": revision},
                sort_keys=True,
                separators=(",", ":"),
            )
        )
        cache_key = (
            principal.user_id + ":" + principal.org_id,
            self.command,
            path,
            key,
        )

        def operation() -> tuple[HTTPStatus, JsonObject]:
            if action == "model":
                return HTTPStatus.OK, _provider_connection_json(
                    runtime.select_model(
                        principal,
                        connection_id,
                        cast("str", model_id),
                        revision,
                    )
                )
            if action == "health":
                connection = runtime.connection_detail(principal, connection_id)
                health = broker.health(connection)
                return HTTPStatus.OK, _provider_connection_json(
                    runtime.set_health(principal, connection_id, health, revision)
                )
            connection = runtime.connection_detail(principal, connection_id)
            initiation = runtime.initiate_reauth(
                principal, connection_id, "callback", "/settings/providers", revision
            )
            authorization = broker.authorize(
                connection.adapter_id,
                initiation.state,
                initiation.flow,
                "/settings/providers",
            )
            return HTTPStatus.ACCEPTED, _provider_initiation_json(
                connection.adapter_id,
                initiation,
                authorization,
                self.product_server.provider_authorization_endpoints,
            )

        status, payload = self.product_server.execute_provider_idempotency(
            ProviderIdempotencyRequest(
                cache_key,
                digest,
                path,
                self.command,
                _provider_principal_hash(principal),
            ),
            operation,
        )
        self._send_json(status, payload)

    @staticmethod
    def _provider_principal(principal: Principal) -> ProviderPrincipal:
        return ProviderPrincipal(principal.user_id, principal.organization_id)

    def _api_artifacts(self) -> None:
        """Project the authenticated dry-lab outputs into the artifact library."""
        if self.product_server.artifact_http is not None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        dry_lab = self._dry_lab_service()
        if dry_lab is None:
            return
        token = self._session_token()
        if token is None:
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return
        self._send_json(
            HTTPStatus.OK,
            dry_lab.artifact_library(_digest(token)),
        )

    def _dry_lab_resource(self, path: str) -> None:
        """Resolve a generated dry-lab resource by its exact authenticated URL ID."""
        dry_lab = self._dry_lab_service()
        if dry_lab is None:
            return
        match = _DRY_LAB_RESOURCE_API.fullmatch(path)
        token = self._session_token()
        if match is None or token is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        kind = cast(
            "DryLabResourceKind",
            {
                "runs": "run",
                "reviews": "review",
                "exports": "export",
                "artifacts": "artifact",
            }[match.group("kind")],
        )
        response = dry_lab.resource(_digest(token), kind, match.group("resource_id"))
        if response is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        self._send_json(HTTPStatus(response.status), response.payload)

    def _artifact_get(self, path: str) -> None:
        """Serve one exact dry-lab Artifact Version or its immutable bytes."""
        dry_lab = self._dry_lab_service()
        if dry_lab is None:
            return
        match = _ARTIFACT_RESOURCE_API.fullmatch(path)
        token = self._session_token()
        if match is None or token is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        artifact_id = match.group("artifact_id")
        version_id = match.group("version_id")
        operation = match.group("operation")
        if operation == "download" and version_id is not None:
            download = dry_lab.download_artifact(
                _digest(token), artifact_id, version_id
            )
            if download is None:
                self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
                return
            self._send(
                HTTPStatus.OK,
                download.content,
                {
                    "Content-Type": download.media_type,
                    "Content-Disposition": (f'attachment; filename="{download.name}"'),
                    "X-Content-SHA256": download.sha256,
                    "X-Content-Type-Options": "nosniff",
                },
            )
            return
        if operation is not None or path.endswith("/versions"):
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        detail = dry_lab.artifact_detail(_digest(token), artifact_id, version_id)
        if detail is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        self._send_json(HTTPStatus.OK, detail)

    def _durable_artifact_get(
        self,
        artifact_http: ArtifactHttpService,
        path: str,
        principal: Principal,
    ) -> None:
        """Serve durable metadata or bytes through the authenticated core."""
        match = _ARTIFACT_RESOURCE_API.fullmatch(path)
        if match is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        artifact_id = match.group("artifact_id")
        version_id = match.group("version_id")
        operation = match.group("operation")
        if version_id is None and operation is None and not path.endswith("/versions"):
            result = artifact_http.read_artifact(
                principal.organization_id,
                principal.user_id,
                artifact_id,
            )
        elif version_id is not None and operation is None:
            result = artifact_http.read_version(
                principal.organization_id,
                principal.user_id,
                artifact_id,
                version_id,
            )
        elif version_id is not None and operation == "download":
            result = artifact_http.download_version(
                principal.organization_id,
                principal.user_id,
                artifact_id,
                version_id,
            )
        else:
            result = ArtifactHttpResponse(
                HTTPStatus.NOT_FOUND,
                {"error": "not_found"},
            )
        self._send_artifact_response(result)

    def _artifact_create(self) -> None:
        """Create a durable Artifact only through external production auth."""
        artifact_http = self.product_server.artifact_http
        if artifact_http is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        session = self._artifact_mutation_session()
        if session is None:
            return
        body, status = self._json()
        if body is None:
            self._send_body_error(status)
            return
        principal = session[0]
        self._send_artifact_response(
            artifact_http.create_artifact(
                principal.organization_id,
                principal.user_id,
                body,
            )
        )

    def _artifact_mutation(self, path: str, *, attach: bool) -> None:
        """Apply a CSRF-bound Version append or owned-Session association."""
        session = self._artifact_mutation_session()
        if session is None:
            return
        token = session[1]
        match = _ARTIFACT_RESOURCE_API.fullmatch(path)
        if match is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        body, status = self._json()
        if body is None:
            self._send_body_error(status)
            return
        artifact_id = match.group("artifact_id")
        version_id = match.group("version_id")
        operation = match.group("operation")
        artifact_http = self.product_server.artifact_http
        if artifact_http is not None:
            if version_id is None and path.endswith("/versions") and attach:
                principal = session[0]
                self._send_artifact_response(
                    artifact_http.create_version(
                        principal.organization_id,
                        principal.user_id,
                        artifact_id,
                        body,
                    )
                )
            else:
                self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        if version_id is None and path.endswith("/versions") and attach:
            self._append_artifact_version(token, artifact_id, body)
            return
        if version_id is None or operation != "attachments":
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        self._mutate_artifact_attachment(
            session, artifact_id, version_id, body, attach=attach
        )

    def _artifact_mutation_session(self) -> tuple[Principal, str] | None:
        """Authenticate one same-origin, CSRF-bound Artifact mutation."""
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return None
        principal = self._principal()
        token = self._session_token()
        if principal is None or token is None:
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return None
        if not self._csrf_matches(token):
            self._send(HTTPStatus.FORBIDDEN, _INVALID_CSRF)
            return None
        return principal, token

    def _send_artifact_response(self, response: ArtifactHttpResponse) -> None:
        """Emit one normalized durable Artifact response without private fields."""
        if response.content is not None:
            headers = {
                "Content-Type": "application/octet-stream",
                "Content-Disposition": 'attachment; filename="artifact-version"',
                "Content-Security-Policy": "default-src 'none'; sandbox",
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            }
            if response.content_sha256 is not None:
                headers["X-Content-SHA256"] = response.content_sha256
            self._send(response.status, response.content, headers)
            return
        payload = response.payload or {"error": "service_unavailable"}
        self._send_json(response.status, cast("JsonObject", payload))

    def _append_artifact_version(
        self, token: str, artifact_id: str, body: JsonObject
    ) -> None:
        """Append one validated Version through the session-owned store."""
        dry_lab = self._dry_lab_service()
        if dry_lab is None:
            return
        response = dry_lab.create_artifact_version(_digest(token), artifact_id, body)
        self._send_json(HTTPStatus(response.status), response.payload)

    def _mutate_artifact_attachment(
        self,
        session: tuple[Principal, str],
        artifact_id: str,
        version_id: str,
        body: JsonObject,
        *,
        attach: bool,
    ) -> None:
        """Mutate a Version association only for an owned active Session."""
        principal, token = session
        research_session_id = body.get("session_id")
        if not isinstance(research_session_id, str):
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        tenant_principal = self._tenant_principal(principal)
        research_session = self.product_server.repository.session(
            tenant_principal, research_session_id
        )
        project = (
            self.product_server.repository.project(
                tenant_principal, research_session.project_id
            )
            if research_session is not None
            else None
        )
        if research_session is None or project is None or project.archived:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        dry_lab = self._dry_lab_service()
        if dry_lab is None:
            return
        payload = dry_lab.mutate_artifact_attachment(
            _digest(token),
            artifact_id,
            version_id,
            research_session_id,
            attach=attach,
        )
        if payload is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        self._send_json(HTTPStatus.OK, payload)

    def _dry_lab_mutation(self, path: str) -> None:
        """Dispatch an authenticated same-origin dry-lab mutation."""
        dry_lab = self._dry_lab_service()
        parsed = _parse_dry_lab_run_action(path)
        if dry_lab is None or parsed is None:
            if dry_lab is not None:
                self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        run_id, action = parsed
        if not self._authorize_same_origin_mutation():
            return
        principal = self._principal()
        token = self._session_token()
        if principal is None:
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return
        if token is None or not self._csrf_matches(token):
            self._send(HTTPStatus.FORBIDDEN, _INVALID_CSRF)
            return
        self._execute_dry_lab_mutation(dry_lab, principal, token, run_id, action)

    def _authorize_same_origin_mutation(self) -> bool:
        if self._same_origin_mutation():
            return True
        self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
        return False

    def _execute_dry_lab_mutation(
        self,
        dry_lab: ProductDryLabService,
        principal: Principal,
        token: str,
        run_id: str,
        action: str,
    ) -> None:
        body, status = self._json()
        request_run_id = body.get("run_id") if body is not None else None
        if body is None:
            self._send_body_error(status)
            return
        if request_run_id is not None and request_run_id != run_id:
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        body["run_id"] = run_id
        if action == "execute" and self._send_provider_execute(
            dry_lab, principal, token, body
        ):
            return
        response = dry_lab.dispatch(_digest(token), action, body)
        self._send_json(HTTPStatus(response.status), response.payload)

    def _send_provider_execute(
        self,
        dry_lab: ProductDryLabService,
        principal: Principal,
        token: str,
        body: JsonObject,
    ) -> bool:
        provider_response = dry_lab.dispatch_provider_run(
            _digest(token),
            body,
            ProviderPrincipal(
                principal.user_id,
                principal.organization_id,
            ),
            self.product_server.provider_run_dispatcher,
        )
        if provider_response is None:
            return False
        if provider_response.status == HTTPStatus.SERVICE_UNAVAILABLE:
            self._send(
                HTTPStatus.SERVICE_UNAVAILABLE,
                _PROVIDER_DISPATCH_UNAVAILABLE,
            )
        else:
            self._send_json(
                HTTPStatus(provider_response.status),
                provider_response.payload,
            )
        return True

    def _connectors_list(self, principal: Principal) -> None:
        """Return the canonical connector registry merged with saved state."""
        items: JsonList = [
            {
                "connector_id": str(item["connector_id"]),
                "label": str(item["label"]),
                "note": str(item["note"]),
                "accepts_key": bool(item["accepts_key"]),
                "enabled": bool(item["enabled"]),
                "key_env": (
                    item["key_env"] if isinstance(item["key_env"], str) else None
                ),
                "last_success_at": (
                    item["last_success_at"]
                    if isinstance(item["last_success_at"], str)
                    else None
                ),
                "last_failure_at": (
                    item["last_failure_at"]
                    if isinstance(item["last_failure_at"], str)
                    else None
                ),
            }
            for item in self.product_server.connector_settings.list_for(
                principal.user_id
            )
        ]
        self._send_json(HTTPStatus.OK, {"connectors": items})

    def _connector_mutation(self, path: str) -> None:
        """Enable or disable one canonical connector for this principal."""
        identity = self._authenticated_run_request()
        if identity is None:
            return
        principal, _token = identity
        connector_id = path.removeprefix("/api/v1/connectors/").strip("/")
        body, status = self._json()
        if body is None:
            self._send_body_error(status)
            return
        enabled = body.get("enabled")
        key_env = body.get("key_env")
        if key_env is not None and not isinstance(key_env, str):
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        if not isinstance(enabled, bool):
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        try:
            updated = self.product_server.connector_settings.update(
                principal.user_id,
                connector_id,
                enabled=enabled,
                key_env=key_env or None,
            )
        except ConnectorSettingsError as error:
            self._send_json(
                HTTPStatus.BAD_REQUEST, {"error": str(error) or "invalid_connector"}
            )
            return
        self._send_json(HTTPStatus.OK, cast("JsonObject", updated))

    def _collection_plan(self) -> None:
        """Parse a topic into a confirmation-first collection plan."""
        identity = self._authenticated_run_request()
        if identity is None:
            return
        principal, _token = identity
        body, status = self._json()
        if body is None:
            self._send_body_error(status)
            return
        prompt = body.get("prompt")
        if not isinstance(prompt, str):
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        settings = self.product_server.connector_settings
        try:
            source_hint, query, limit = parse_collection_prompt(prompt)
        except ConnectorSettingsError as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        enabled = settings.enabled_ids(principal.user_id)
        enabled_ids = set(enabled)
        connector_id = (
            source_hint
            if source_hint and source_hint in enabled_ids
            else (enabled[0] if enabled else None)
        )
        if connector_id is None:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": "no_enabled_connector"})
            return
        plan = self.product_server.collection_plans.create(
            principal.user_id, connector_id, query, limit
        )
        label = self._connector_label(principal, connector_id)
        self._send_json(
            HTTPStatus.OK,
            {
                "plan_id": plan.plan_id,
                "connector_id": connector_id,
                "connector_label": label,
                "query": query,
                "limit": limit,
                "summary": f"연결된 {label}에서 '{query}' {limit}건 수집합니다",
            },
        )

    def _collection_execute(self) -> None:
        """Run one confirmed collection plan and return the calibrated CSV input."""
        identity = self._authenticated_run_request()
        if identity is None:
            return
        principal, _token = identity
        body, status = self._json()
        if body is None:
            self._send_body_error(status)
            return
        plan_id = body.get("plan_id")
        if not isinstance(plan_id, str) or not plan_id:
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        try:
            plan = self.product_server.collection_plans.consume(
                principal.user_id, plan_id
            )
        except ConnectorSettingsError as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        records = self._run_collection_fetch(plan)
        if records is None:
            return
        stored = self.product_server.collections.create(
            principal.user_id, plan.connector_id, plan.query, records
        )
        csv_text = self.product_server.collections.materialize(
            principal.user_id,
            stored.collection_id,
            _record_ids(stored),
        )
        self._send_json(
            HTTPStatus.OK,
            {
                "collection_id": stored.collection_id,
                "connector_id": plan.connector_id,
                "connector_label": self._connector_label(
                    principal, plan.connector_id
                ),
                "query": plan.query,
                "limit": plan.limit,
                "records": _collected_records_json(stored),
                "filename": (
                    f"{plan.connector_id}-{stored.collection_id[:8]}.csv"
                ),
                "media_type": "text/csv",
                "content": csv_text,
                "row_count": len(stored.records),
            },
        )

    def _run_collection_fetch(
        self, plan: CollectionPlan
    ) -> list[CollectedDocument] | None:
        """Fetch records for one consumed plan, reporting any failure inline."""
        try:
            records = self.product_server.collection_fetcher(
                plan.connector_id, plan.query, plan.limit
            )
        except ConnectorSettingsError as error:
            self._record_fetch_outcome(plan, succeeded=False)
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return None
        except Exception:  # noqa: BLE001 — upstream failures never leak internals
            self._record_fetch_outcome(plan, succeeded=False)
            self._send_json(
                HTTPStatus.BAD_GATEWAY, {"error": "collection_fetch_failed"}
            )
            return None
        if not records:
            self._record_fetch_outcome(plan, succeeded=False)
            self._send_json(HTTPStatus.BAD_GATEWAY, {"error": "collection_empty"})
            return None
        self._record_fetch_outcome(plan, succeeded=True)
        return records

    def _record_fetch_outcome(self, plan: CollectionPlan, *, succeeded: bool) -> None:
        """Stamp the connector's last fetch outcome without masking the result."""
        try:
            self.product_server.connector_settings.record_fetch_outcome(
                plan.principal_id,
                plan.connector_id,
                succeeded=succeeded,
                at=self.product_server.clock(),
            )
        except ConnectorSettingsError:
            return

    def _collection_materialize(self, path: str) -> None:
        """Render a selected subset of one owned collection as CSV run input."""
        identity = self._authenticated_run_request()
        if identity is None:
            return
        principal, _token = identity
        collection_id = (
            path.removeprefix("/api/v1/collections/")
            .removesuffix("/materialize")
            .strip("/")
        )
        body, status = self._json()
        if body is None:
            self._send_body_error(status)
            return
        record_ids_value = body.get("record_ids")
        if not isinstance(record_ids_value, list) or not record_ids_value:
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        record_ids: list[str] = []
        for item in record_ids_value:
            if not isinstance(item, str):
                self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
                return
            record_ids.append(item)
        try:
            csv_text = self.product_server.collections.materialize(
                principal.user_id, collection_id, record_ids
            )
        except ConnectorSettingsError as error:
            self._send_json(HTTPStatus.BAD_REQUEST, {"error": str(error)})
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "filename": f"collection-{collection_id[:8]}-selection.csv",
                "media_type": "text/csv",
                "content": csv_text,
                "row_count": len(record_ids),
            },
        )

    def _api_collections(self, principal: Principal) -> None:
        """List summaries of the principal's stored collections."""
        collections: JsonList = [
            {
                "collection_id": item.collection_id,
                "connector_id": item.connector_id,
                "connector_label": self._connector_label(
                    principal, item.connector_id
                ),
                "query": item.query,
                "created_at": item.created_at.isoformat(),
                "record_count": len(item.records),
            }
            for item in self.product_server.collections.list_for(
                principal.user_id
            )
        ]
        self._send_json(HTTPStatus.OK, {"collections": collections})

    def _api_collection(self, path: str, principal: Principal) -> None:
        """Return one owned collection with its structured records."""
        collection_id = path.removeprefix("/api/v1/collections/").strip("/")
        stored = self.product_server.collections.get(
            principal.user_id, collection_id
        )
        if stored is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "collection_id": stored.collection_id,
                "connector_id": stored.connector_id,
                "connector_label": self._connector_label(
                    principal, stored.connector_id
                ),
                "query": stored.query,
                "created_at": stored.created_at.isoformat(),
                "records": _collected_records_json(stored),
            },
        )

    def _connector_label(self, principal: Principal, connector_id: str) -> str:
        """Resolve the product-facing label for one canonical connector id."""
        return next(
            str(item["label"])
            for item in self.product_server.connector_settings.list_for(
                principal.user_id
            )
            if item["connector_id"] == connector_id
        )

    def _create_local_run(self) -> None:
        identity = self._authenticated_run_request()
        if identity is None:
            return
        principal, token = identity
        body, status = self._json()
        if body is None:
            self._send_body_error(status)
            return
        dry_lab = self._dry_lab_service()
        if dry_lab is None:
            return
        if body.get("execution_mode") == "provider_model":
            self._create_provider_run(dry_lab, principal, token, body)
            return
        request = _local_run_create(body)
        if request is None:
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        if not self._run_session_is_active(
            principal, request.research_session_id
        ) or not self._collection_is_owned(principal, request.collection_id):
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        response = dry_lab.create_local_run(
            _digest(token),
            request,
        )
        self._send_json(HTTPStatus(response.status), response.payload)

    def _authenticated_run_request(self) -> tuple[Principal, str] | None:
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return None
        principal = self._principal()
        token = self._session_token()
        if principal is None or token is None:
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return None
        if not self._csrf_matches(token):
            self._send(HTTPStatus.FORBIDDEN, _INVALID_CSRF)
            return None
        return principal, token

    def _create_provider_run(
        self,
        dry_lab: ProductDryLabService,
        principal: Principal,
        token: str,
        body: JsonObject,
    ) -> None:
        request = _provider_run_create(body)
        if request is None:
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        if not self._run_session_is_active(principal, request.research_session_id):
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        if not self._collection_is_owned(principal, request.collection_id):
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        response = dry_lab.create_provider_run(
            _digest(token),
            request,
        )
        self._send_json(HTTPStatus(response.status), response.payload)

    def _run_session_is_active(self, principal: Principal, session_id: str) -> bool:
        tenant_principal = self._tenant_principal(principal)
        research_session = self.product_server.repository.session(
            tenant_principal,
            session_id,
        )
        project = (
            self.product_server.repository.project(
                tenant_principal,
                research_session.project_id,
            )
            if research_session is not None
            else None
        )
        return (
            research_session is not None
            and project is not None
            and not project.archived
        )

    def _collection_is_owned(
        self, principal: Principal, collection_id: str | None
    ) -> bool:
        """Return whether an optional provenance reference resolves for the owner."""
        return collection_id is None or (
            self.product_server.collections.get(principal.user_id, collection_id)
            is not None
        )

    def _api_me(self, principal: Principal) -> None:
        token = self._session_token()
        csrf_token = self._cookie_value(self.product_server.csrf_cookie_name)
        if (
            token is None
            or csrf_token is None
            or not self.product_server.session_authority.csrf_matches(
                token,
                csrf_token,
            )
        ):
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return
        self._send_json(
            HTTPStatus.OK,
            {
                "user": {"id": principal.user_id, "email": principal.email},
                "organization": {
                    "id": principal.organization_id,
                    "name": principal.organization_name,
                },
                "csrf_token": csrf_token,
            },
        )

    def _api_workspace(self, principal: Principal) -> None:
        workspace = self.product_server.repository.workspace(
            self._tenant_principal(principal)
        )
        token = self._session_token()
        if token is None:
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return
        projects: list[JsonValue] = [
            {"id": project.id, "name": project.name}
            for project in workspace.projects
            if not project.archived
        ]
        sessions: list[JsonValue] = [
            {
                "id": session.id,
                "project_id": session.project_id,
                "name": session.name,
            }
            for session in workspace.sessions
        ]
        self._send_json(
            HTTPStatus.OK,
            {
                "projects": projects,
                "sessions": sessions,
                "recent_runs": (
                    list(self.product_server.dry_lab.workspace_runs(_digest(token)))
                    if self.product_server.dry_lab is not None
                    else []
                ),
            },
        )

    def _api_project(self, path: str, principal: Principal) -> None:
        project_id = path.removeprefix("/api/v1/projects/")
        project = self.product_server.repository.project(
            self._tenant_principal(principal), project_id
        )
        if project is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
        else:
            self._send_json(HTTPStatus.OK, _project_json(project))

    def _api_session(self, path: str, principal: Principal) -> None:
        session_id = path.removeprefix("/api/v1/sessions/")
        session = self.product_server.repository.session(
            self._tenant_principal(principal), session_id
        )
        if session is None:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
        else:
            self._send_json(
                HTTPStatus.OK,
                {
                    "id": session.id,
                    "project_id": session.project_id,
                    "name": session.name,
                },
            )

    def _static(self, path: str) -> None:
        product_routes = {
            "/",
            "/workspace",
            "/upload",
            "/artifacts",
            "/settings/providers",
        }
        static_root = Path(__file__).resolve().parents[2] / "apps/web/product"
        if path in product_routes or _DYNAMIC_PRODUCT_ROUTE.fullmatch(path):
            requested = "index.html"
        elif path.startswith("/product/"):
            requested = path.removeprefix("/product/")
        else:
            requested = path.lstrip("/")
        candidate = (static_root / requested).resolve()
        if static_root not in candidate.parents and candidate != static_root:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        if not candidate.is_file():
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        content_type = "text/html; charset=utf-8"
        if candidate.suffix == ".js":
            content_type = "text/javascript; charset=utf-8"
        elif candidate.suffix == ".css":
            content_type = "text/css; charset=utf-8"
        elif candidate.suffix == ".svg":
            content_type = "image/svg+xml"
        body = candidate.read_bytes()
        if requested == "index.html":
            policy = json.dumps(
                self.product_server.provider_authorization_endpoints,
                ensure_ascii=True,
                separators=(",", ":"),
                sort_keys=True,
            )
            body = body.replace(
                _PROVIDER_AUTHORIZATION_POLICY_MARKER.encode(),
                escape(policy, quote=True).encode(),
            )
        self._send(
            HTTPStatus.OK,
            body,
            {
                "Content-Type": content_type,
                "Content-Security-Policy": _PRODUCT_CONTENT_SECURITY_POLICY,
                "Referrer-Policy": "no-referrer",
                "X-Content-Type-Options": "nosniff",
            },
        )

    def _send_provider_error(self, status: HTTPStatus, code: str) -> None:
        """Send the canonical OpenAPI error envelope for provider endpoints."""
        error_status, payload = self.product_server.provider_error(status, code)
        self._send_json(error_status, payload)

    def _send_unexpected_provider_error(
        self, path: str, principal: ProviderPrincipal, error: Exception
    ) -> None:
        """Record an unexpected failure before returning its canonical envelope."""
        status, payload = self.product_server.provider_error(
            HTTPStatus.SERVICE_UNAVAILABLE, "provider_unavailable"
        )
        context = _ProviderDiagnosticContext(
            self.product_server.provider_request_id(payload),
            path,
            self.command,
            _provider_principal_hash(principal),
        )
        self.product_server.record_provider_failure(
            context,
            error,
            error.__traceback__,
        )
        self._send_json(status, payload)

    def _send_json(self, status: HTTPStatus, payload: JsonObject) -> None:
        """Serialize a JSON-compatible response body."""
        self._send(
            status,
            json.dumps(payload, separators=(",", ":")).encode("utf-8"),
        )

    def _send(
        self,
        status: HTTPStatus,
        body: bytes,
        headers: dict[str, str] | tuple[tuple[str, str], ...] | None = None,
    ) -> None:
        self.send_response(status)
        header_items = tuple(
            headers.items() if isinstance(headers, dict) else (headers or ())
        )
        content_type = next(
            (value for key, value in header_items if key.lower() == "content-type"),
            "application/json; charset=utf-8",
        )
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        for key, value in header_items:
            if key.lower() != "content-type":
                self.send_header(key, value)
        self.end_headers()
        _ = self.wfile.write(body)


def _cookie(
    name: str,
    value: str,
    *,
    max_age: int,
    secure: bool,
    http_only: bool = True,
) -> str:
    secure_attribute = "; Secure" if secure else ""
    http_only_attribute = "; HttpOnly" if http_only else ""
    return (
        f"{name}={value}; Max-Age={max_age}; Path=/{http_only_attribute}; "
        "SameSite=Lax"
        f"{secure_attribute}"
    )


def _expired_cookie(name: str, *, secure: bool, http_only: bool = True) -> str:
    secure_attribute = "; Secure" if secure else ""
    http_only_attribute = "; HttpOnly" if http_only else ""
    return (
        f"{name}=; Max-Age=0; Path=/{http_only_attribute}; SameSite=Lax"
        f"{secure_attribute}"
    )


def _project_json(project: ProjectView) -> JsonObject:
    """Return the JSON response representation of a project."""
    return {"id": project.id, "name": project.name, "archived": project.archived}


def _provider_principal_hash(principal: ProviderPrincipal) -> str:
    """Return a one-way stable diagnostic scope for a provider principal."""
    return sha256(f"{principal.user_id}:{principal.org_id}".encode()).hexdigest()


def _provider_connection_json(connection: ProviderConnection) -> JsonObject:
    """Map the redacted domain view to the fixed product UI contract."""
    return {
        "id": connection.connection_id,
        "adapter_id": connection.adapter_id,
        "account": {"id": connection.account_id},
        "models": list(connection.eligible_models),
        "selected_model": connection.selected_model,
        "status": connection.health,
        "health": connection.health,
        "qualification": {
            "cleanup_verified": connection.cleanup_verified,
            "live": connection.qualified_live,
        },
        "revision": str(connection.revision),
        "created_at": connection.created_at.isoformat().replace("+00:00", "Z"),
    }


def _provider_initiation_json(
    adapter_id: str,
    initiation: OAuthInitiation,
    authorization: ProviderAuthorization,
    authorization_endpoints: dict[str, str],
) -> JsonObject:
    return {
        "state": initiation.state,
        "flow": initiation.flow,
        "expires_at": initiation.expires_at.isoformat().replace("+00:00", "Z"),
        "revision": "0",
        "authorization_url": _canonical_provider_authorization_url(
            adapter_id, authorization.authorization_url, authorization_endpoints
        ),
        "device_instruction": authorization.device_instruction,
    }


def _canonical_provider_authorization_url(
    adapter_id: str,
    authorization_url: str | None,
    authorization_endpoints: dict[str, str],
) -> str | None:
    if authorization_url is None:
        return None
    endpoint = authorization_endpoints.get(adapter_id)
    if endpoint is None or len(authorization_url) > _PROVIDER_AUTHORIZATION_MAX_LENGTH:
        raise ValueError(_UNSAFE_PROVIDER_AUTHORIZATION_MESSAGE)
    candidate = urlsplit(authorization_url)
    expected = urlsplit(endpoint)
    if (
        candidate.scheme != "https"
        or candidate.scheme != expected.scheme
        or candidate.netloc != expected.netloc
        or candidate.path != expected.path
        or candidate.fragment
        or candidate.username is not None
        or candidate.password is not None
        or candidate.port is not None
        or candidate.geturl() != authorization_url
    ):
        raise ValueError(_UNSAFE_PROVIDER_AUTHORIZATION_MESSAGE)
    return authorization_url


def _cleanup_receipt_json(receipt: ProviderCleanupReceipt) -> JsonObject:
    return {
        "connection_id": receipt.connection_id,
        "adapter_id": receipt.adapter_id,
        "requested_at": receipt.requested_at.isoformat().replace("+00:00", "Z"),
        "destroy_by": receipt.destroy_by.isoformat().replace("+00:00", "Z"),
        "destroyed_at": receipt.destroyed_at.isoformat().replace("+00:00", "Z"),
        "evidence_sha256": receipt.evidence_sha256,
        "redacted": receipt.redacted,
    }


def _if_match_revision(value: str | None) -> int | None:
    if value is None:
        return None
    quoted = value.startswith('"')
    if quoted != value.endswith('"'):
        return None
    revision = value[1:-1] if quoted else value
    return int(revision) if revision.isdecimal() else None


_RUN_INPUT_REQUIRED_KEYS: Final = frozenset({"filename", "media_type", "content"})
_RUN_INPUT_KEYS: Final = _RUN_INPUT_REQUIRED_KEYS | {"provenance"}


def _run_input_is_valid(input_value: JsonValue | None) -> bool:
    """Return whether the run input object matches the upload contract."""
    if not isinstance(input_value, dict):
        return False
    keys = set(input_value)
    if not _RUN_INPUT_REQUIRED_KEYS <= keys <= _RUN_INPUT_KEYS:
        return False
    if not all(
        isinstance(input_value.get(field), str)
        for field in _RUN_INPUT_REQUIRED_KEYS
    ):
        return False
    provenance = input_value.get("provenance")
    if provenance is None:
        return True
    return (
        isinstance(provenance, dict)
        and set(provenance) == {"collection_id"}
        and isinstance(provenance.get("collection_id"), str)
    )


def _run_input_collection_id(input_value: JsonValue | None) -> str | None:
    """Return the validated optional provenance collection id."""
    if not isinstance(input_value, dict):
        return None
    provenance = input_value.get("provenance")
    if not isinstance(provenance, dict):
        return None
    collection_id = provenance.get("collection_id")
    return collection_id if isinstance(collection_id, str) else None


def _record_ids(stored: StoredCollection) -> list[str]:
    """Return the positional r1..rN ids of one stored collection."""
    return [f"r{index + 1}" for index in range(len(stored.records))]


def _collected_document_json(
    record_id: str, document: CollectedDocument
) -> JsonObject:
    """Return the JSON contract representation of one collected document."""
    return {
        "id": record_id,
        "title": document.title,
        "authors": list(document.authors),
        "year": document.year,
        "venue": document.venue,
        "citation_count": document.citation_count,
        "abstract": document.abstract,
        "url": document.url,
    }


def _collected_records_json(stored: StoredCollection) -> JsonList:
    """Return the r1..rN record list for one stored collection."""
    return [
        _collected_document_json(record_id, document)
        for record_id, document in zip(
            _record_ids(stored), stored.records, strict=True
        )
    ]


def _local_run_create(body: JsonObject) -> LocalRunCreate | None:
    input_value = body.get("input")
    if (
        set(body)
        != {"execution_mode", "session_id", "prompt", "research_intent", "input"}
        or body.get("execution_mode") != "local_dry_lab"
        or not _is_uuid7_text(body.get("session_id"))
        or not isinstance(body.get("prompt"), str)
        or not body["prompt"]
        or not isinstance(body.get("research_intent"), dict)
        or not _run_input_is_valid(input_value)
    ):
        return None
    input_object = cast("JsonObject", input_value)
    return LocalRunCreate(
        research_session_id=cast("str", body["session_id"]),
        prompt=cast("str", body["prompt"]),
        research_intent=body["research_intent"],
        filename=cast("str", input_object["filename"]),
        media_type=cast("str", input_object["media_type"]),
        content=cast("str", input_object["content"]),
        collection_id=_run_input_collection_id(input_value),
    )


def _provider_run_create(body: JsonObject) -> ProviderRunCreate | None:
    session_id = body.get("session_id")
    connection_id = body.get("connection_id")
    model_id = body.get("model_id")
    input_value = body.get("input")
    if (
        set(body)
        != {
            "execution_mode",
            "session_id",
            "prompt",
            "research_intent",
            "input",
            "connection_id",
            "model_id",
        }
        or body.get("execution_mode") != "provider_model"
        or not _is_uuid7_text(session_id)
        or not _is_uuid7_text(connection_id)
        or not isinstance(body.get("prompt"), str)
        or not body["prompt"]
        or not isinstance(body.get("research_intent"), dict)
        or not _run_input_is_valid(input_value)
        or not isinstance(model_id, str)
        or not provider_model_id_is_valid(model_id)
    ):
        return None
    input_object = cast("JsonObject", input_value)
    return ProviderRunCreate(
        research_session_id=cast("str", session_id),
        prompt=cast("str", body["prompt"]),
        research_intent=body["research_intent"],
        filename=cast("str", input_object["filename"]),
        media_type=cast("str", input_object["media_type"]),
        content=cast("str", input_object["content"]),
        connection_id=cast("str", connection_id),
        model_id=model_id,
        collection_id=_run_input_collection_id(input_value),
    )


def _is_uuid7_text(value: JsonValue | None) -> bool:
    if not isinstance(value, str):
        return False
    try:
        parsed = UUID(value)
    except ValueError:
        return False
    return str(parsed) == value and parsed.version == UUID7_VERSION


def _loopback_fixture_options(
    options: ProductServerOptions, clock: Clock
) -> ProductServerOptions:
    repository = options.repository or InMemoryTenantRepository(
        (
            (
                "org-mineral",
                ProjectView(_FIXTURE_PROJECT_ID, "스펙트럼 보정 실험", archived=False),
            ),
            (
                "org-mineral",
                ProjectView(
                    _FIXTURE_ARCHIVED_PROJECT_ID,
                    "보관된 기준선 비교",
                    archived=True,
                ),
            ),
            (
                "org-foreign",
                ProjectView(
                    _FIXTURE_FOREIGN_PROJECT_ID, "Foreign project", archived=False
                ),
            ),
        ),
        (
            (
                "org-mineral",
                SessionView(_FIXTURE_SESSION_ID, _FIXTURE_PROJECT_ID, "보정 세션"),
            ),
            (
                "org-mineral",
                SessionView(
                    _FIXTURE_ARCHIVED_SESSION_ID,
                    _FIXTURE_ARCHIVED_PROJECT_ID,
                    "보관 세션",
                ),
            ),
            (
                "org-foreign",
                SessionView(
                    _FIXTURE_FOREIGN_SESSION_ID,
                    _FIXTURE_FOREIGN_PROJECT_ID,
                    "Foreign session",
                ),
            ),
        ),
    )
    dry_lab = options.dry_lab or ProductDryLabService(
        lambda: ProductArtifactService(clock), clock=clock
    )
    principal = options.principal or Principal(
        "user-mineral",
        "org-mineral",
        "researcher@example.test",
        "Nipo Labs",
    )
    return ProductServerOptions(
        repository=repository,
        dry_lab=dry_lab,
        principal=principal,
        provider_runtime=options.provider_runtime,
        provider_oauth_broker=options.provider_oauth_broker,
        provider_diagnostic_sink=options.provider_diagnostic_sink,
        provider_authorization_endpoints=(
            options.provider_authorization_endpoints
            or _FIXTURE_PROVIDER_AUTHORIZATION_ENDPOINTS
        ),
        public_origin=options.public_origin,
        provider_run_dispatcher=options.provider_run_dispatcher,
        uuid7_factory=options.uuid7_factory,
        collection_fetcher=options.collection_fetcher or fixture_collection_fetcher,
        connector_settings=options.connector_settings,
        collections=options.collections,
    )


def run_product_server(
    address: tuple[str, int] = ("127.0.0.1", 0),
    authenticated_fixture: bool = False,
    clock: Clock = _utc_now,
    options: ProductServerOptions | None = None,
    fixture_session_token: str | None = None,
) -> ProductServer:
    """Start a loopback server with bundled optional RLS and provider boundaries."""
    if fixture_session_token is not None and not authenticated_fixture:
        raise ValueError(_FIXTURE_SESSION_REQUIRES_AUTH_MESSAGE)
    if (
        options is not None
        and options.dry_lab is not None
        and not authenticated_fixture
    ):
        raise ValueError(_DRY_LAB_FIXTURE_REQUIRES_AUTH_MESSAGE)
    if authenticated_fixture:
        options = _loopback_fixture_options(options or ProductServerOptions(), clock)
    server = ProductServer(address, clock, options)
    if authenticated_fixture:
        _ = server.fixture_session_cookie(fixture_session_token)
    Thread(target=server.serve_forever, daemon=True).start()
    return server
