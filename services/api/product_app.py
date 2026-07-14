"""Loopback product server for same-origin auth and tenant fixture journeys."""

from __future__ import annotations

import json
import re
import secrets
import traceback as traceback_module
from collections.abc import Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Condition, Lock, Thread
from typing import TYPE_CHECKING, Final, Protocol, cast, final, override
from urllib.parse import urlsplit

from pydantic import TypeAdapter, ValidationError

from services.api.artifacts.runtime import Uuid7Factory
from services.api.product_dry_lab import ProductDryLabService
from services.api.product_tenancy import (
    InMemoryTenantRepository,
    ProjectView,
    SessionView,
    TenantPrincipal,
    TenantRepository,
)
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
    ProviderConnection,
    ProviderPrincipal,
    ProviderRuntimeError,
    ProviderRuntimeService,
)

if TYPE_CHECKING:
    from types import TracebackType

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
_INTENT_COOKIE: Final = "product_intent"
_SESSION_COOKIE: Final = "product_session"

_SECONDS_PER_MINUTE: Final = 60
_MINUTES_PER_HOUR: Final = 60
_COOKIE_SEPARATOR: Final = "="
_MAGIC_LINK_MAX_AGE: Final = 15 * _SECONDS_PER_MINUTE
_SESSION_MAX_AGE: Final = 24 * _MINUTES_PER_HOUR * _SECONDS_PER_MINUTE
_MAGIC_LINK_TTL: Final = timedelta(minutes=15)
_SESSION_IDLE_TTL: Final = timedelta(hours=8)
_SESSION_ABSOLUTE_TTL: Final = timedelta(hours=24)
_NOT_FOUND: Final = b'{"error":"not_found"}'
_UNAUTHORIZED: Final = b'{"error":"unauthorized"}'
_BAD_REQUEST: Final = b'{"error":"invalid_request"}'
_FORBIDDEN: Final = b'{"error":"invalid_origin"}'
_MAGIC_LINK_RESPONSE: Final = b'{"status":"ok"}'
_PROVIDER_IDEMPOTENCY_TTL: Final = timedelta(minutes=10)
_PROVIDER_IDEMPOTENCY_CAPACITY: Final = 256
_PROVIDER_DEPENDENCIES_MESSAGE: Final = (
    "provider_diagnostic_sink is required with provider dependencies"
)
_PROVIDER_DIAGNOSTIC_SINK_MESSAGE: Final = "provider diagnostic sink is unavailable"
_PROVIDER_ERROR_ENVELOPE_MESSAGE: Final = "provider error envelope is invalid"
_DYNAMIC_PRODUCT_ROUTE: Final[re.Pattern[str]] = re.compile(
    r"^/(?:runs/[A-Za-z0-9][A-Za-z0-9_-]*(?:/approval)?|"
    r"(?:artifacts|reviews|exports)/[A-Za-z0-9][A-Za-z0-9_-]*)$"
)


@dataclass(frozen=True, slots=True)
class Principal:
    """The server-derived authenticated identity."""

    user_id: str
    organization_id: str
    email: str
    organization_name: str


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

    def health(self, connection: ProviderConnection) -> Health:
        """Return runtime health without qualification evidence."""
        ...


@dataclass(frozen=True, slots=True)
class ProductServerOptions:
    """Bundled dependencies for tenant and provider HTTP surfaces."""

    repository: TenantRepository | None = None
    principal: Principal | None = None
    provider_runtime: ProviderRuntimeService | None = None
    provider_oauth_broker: ProviderOAuthBroker | None = None
    provider_diagnostic_sink: ProviderDiagnosticSink | None = None

@dataclass(frozen=True, slots=True)
class Project:
    """A tenant-owned project fixture."""

    id: str
    organization_id: str
    name: str
    archived: bool = False


@dataclass(frozen=True, slots=True)
class ResearchSession:
    """A tenant-owned research session fixture."""

    id: str
    organization_id: str
    project_id: str
    name: str


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
        self._delivery_token: str | None = None
        self.projects: dict[str, Project] = {
            "project-demo": Project(
                "project-demo",
                "org-mineral",
                "스펙트럼 보정 실험",
            ),
            "project-archived": Project(
                "project-archived",
                "org-mineral",
                "보관된 광물 비교",
                archived=True,
            ),
            "project-foreign": Project(
                "project-foreign",
                "org-foreign",
                "Foreign project",
            ),
        }
        self.research_sessions: dict[str, ResearchSession] = {
            "session-demo": ResearchSession(
                "session-demo", "org-mineral", "project-demo", "보정 세션"
            ),
            "session-archived": ResearchSession(
                "session-archived", "org-mineral", "project-archived", "보관 세션"
            ),
            "session-foreign": ResearchSession(
                "session-foreign", "org-foreign", "project-foreign", "Foreign session"
            ),
        }
        self.fixture_principal = fixture_principal or Principal(
            "user-mineral", "org-mineral", "researcher@example.test", "한국 광물 연구실"
        )

    def issue_magic_link(self, email: str) -> tuple[str | None, str]:
        """Create a test link only for the fixture principal and always issue intent."""
        intent = secrets.token_urlsafe(32)
        if email != self.fixture_principal.email:
            return None, intent

        token = secrets.token_urlsafe(32)
        digest = _digest(token)
        with self._lock:
            self._magic_links[digest] = MagicLink(
                digest,
                _digest(intent),
                self.fixture_principal,
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

    def fixture_session_cookie(self) -> str:
        """Create an authenticated test cookie without exposing an HTTP bypass."""
        now = self._clock()
        token = secrets.token_urlsafe(32)
        digest = _digest(token)
        with self._lock:
            self._sessions[digest] = Session(
                digest,
                self.fixture_principal,
                now,
                now,
                now + _SESSION_ABSOLUTE_TTL,
            )
        return f"{_SESSION_COOKIE}={token}"

    def principal_for(self, token: str) -> Principal | None:
        """Resolve a currently valid session and update its idle timestamp."""
        now = self._clock()
        with self._lock:
            session = self._sessions.get(_digest(token))
            if (
                session is None
                or session.revoked
                or session.absolute_expires_at <= now
                or session.last_seen_at + _SESSION_IDLE_TTL <= now
            ):
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


def _cookies(header: str | None) -> dict[str, str]:
    """Parse well-formed cookie pairs while ignoring malformed segments."""
    if not header:
        return {}

    cookies: dict[str, str] = {}
    for part in header.split(";"):
        name, separator, value = part.strip().partition(_COOKIE_SEPARATOR)
        if name and separator:
            cookies[name] = value
    return cookies




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


class ProductServer(ThreadingHTTPServer):
    """HTTP server carrying auth state and an injected tenant repository."""

    def __init__(
        self,
        address: tuple[str, int],
        clock: Clock,
        options: ProductServerOptions | None = None,
    ) -> None:
        """Initialize the loopback server with fixture auth and injected boundaries."""
        provider_configured = (
            options is not None
            and (
                options.provider_runtime is not None
                or options.provider_oauth_broker is not None
            )
        )
        if (
            provider_configured
            and options is not None
            and options.provider_diagnostic_sink is None
        ):
            raise ValueError(_PROVIDER_DEPENDENCIES_MESSAGE)
        super().__init__(address, ProductRequestHandler)
        options = options or ProductServerOptions()
        self.daemon_threads: bool = True
        self.store: ProductStore = ProductStore(clock, options.principal)
        repository = options.repository
        if repository is None:
            repository = InMemoryTenantRepository(
                tuple(
                    (
                        project.organization_id,
                        ProjectView(project.id, project.name, project.archived),
                    )
                    for project in self.store.projects.values()
                ),
                tuple(
                    (
                        session.organization_id,
                        SessionView(session.id, session.project_id, session.name),
                    )
                    for session in self.store.research_sessions.values()
                ),
            )
        self.repository: TenantRepository = repository
        self.clock: Clock = clock
        self.provider_runtime: ProviderRuntimeService | None = options.provider_runtime
        self.provider_oauth_broker: ProviderOAuthBroker | None = (
            options.provider_oauth_broker
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
        self._fixture_session_cookie: str | None = None
        self.dry_lab: ProductDryLabService = ProductDryLabService()

    def fixture_session_cookie(self) -> str:
        """Return the stable non-production authenticated fixture cookie value."""
        if self._fixture_session_cookie is None:
            self._fixture_session_cookie = self.store.fixture_session_cookie()
        return self._fixture_session_cookie

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

    @staticmethod
    def provider_error(status: HTTPStatus, code: str) -> tuple[HTTPStatus, JsonObject]:
        """Return the OpenAPI ErrorEnvelope for provider endpoints."""
        return status, {
            "error": {
                "code": code,
                "message": code.replace("_", " "),
                "request_id": str(Uuid7Factory().new_uuid7()),
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
        elif path == "/api/v1/auth/magic-link":
            self._magic_link()
        elif path == "/api/v1/auth/exchange":
            self._exchange()
        elif path == "/api/v1/auth/logout":
            self._logout()
        elif path.startswith("/api/v1/dry-lab/"):
            self._dry_lab_mutation(path)
        elif path.startswith("/api/v1/sessions/") and path.endswith("/runs"):
            self._start_run(path)
        else:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)

    def do_DELETE(self) -> None:
        """Revoke a provider connection through the same-origin mutation boundary."""
        path = urlsplit(self.path).path
        if path.startswith("/api/v1/provider-connections/"):
            self._provider_mutation(path)
        else:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)

    def _json(self) -> JsonObject | None:
        """Read and validate a JSON request object."""
        length = self.headers.get("Content-Length", "0")
        try:
            body = self.rfile.read(int(length))
            return _JSON_OBJECT_ADAPTER.validate_json(body)
        except (ValueError, ValidationError):
            return None

    def _same_origin_mutation(self) -> bool:
        origin = self.headers.get("Origin")
        expected = f"http://{self.headers.get('Host', '')}"
        return (
            origin == expected
            and self.headers.get("Sec-Fetch-Site") == "same-origin"
            and self.headers.get("Sec-Fetch-Mode") in {"cors", "same-origin"}
        )

    def _magic_link(self) -> None:
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return
        data = self._json()
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
                    _INTENT_COOKIE,
                    intent,
                    max_age=_MAGIC_LINK_MAX_AGE,
                )
            },
        )

    def _exchange(self) -> None:
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return
        data = self._json()
        token = data.get("token") if data else None
        intent = _cookies(self.headers.get("Cookie")).get(_INTENT_COOKIE, "")
        if not isinstance(token, str):
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        session_token = self.product_server.store.exchange(token, intent)
        if session_token is None:
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        self._send(
            HTTPStatus.OK,
            b'{"status":"authenticated"}',
            (
                (
                    "Set-Cookie",
                    _cookie(
                        _SESSION_COOKIE,
                        session_token,
                        max_age=_SESSION_MAX_AGE,
                    ),
                ),
                ("Set-Cookie", _expired_cookie(_INTENT_COOKIE)),
            ),
        )

    def _logout(self) -> None:
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return
        token = _cookies(self.headers.get("Cookie")).get(_SESSION_COOKIE)
        if token:
            self.product_server.dry_lab.drop_session(_digest(token))
            self.product_server.store.revoke(token)
        self._send(
            HTTPStatus.NO_CONTENT,
            b"",
            {"Set-Cookie": _expired_cookie(_SESSION_COOKIE)},
        )

    def _session_token(self) -> str | None:
        """Return the opaque session cookie without exposing it to adapters."""
        return _cookies(self.headers.get("Cookie")).get(_SESSION_COOKIE)

    def _principal(self) -> Principal | None:
        token = self._session_token()
        return self.product_server.store.principal_for(token) if token else None

    def _tenant_principal(self, principal: Principal) -> TenantPrincipal:
        """Adapt server-derived auth state to the repository's RLS identity."""
        return TenantPrincipal(principal.user_id, principal.organization_id)

    def _get_api(self, path: str) -> None:
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
        elif path == "/api/v1/me":
            self._api_me(principal)
        elif path == "/api/v1/workspace":
            self._api_workspace(principal)
        elif path == "/api/v1/artifacts":
            self._api_artifacts()
        elif path == "/api/v1/dry-lab/state":
            self._dry_lab_state()
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
            if path == "/api/v1/provider-connections/registry":
                self._send_json(
                    HTTPStatus.OK,
                    {
                        "adapters": [
                            {
                                "id": adapter.adapter_id,
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
        if self.command == "POST" and not self.headers.get("Idempotency-Key"):
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_request")
            return
        data = self._provider_mutation_body(path)
        if data is None:
            return
        try:
            self._dispatch_provider_mutation(path, *dependencies, data)
        except ConnectionNotFoundError:
            self._send_provider_error(HTTPStatus.NOT_FOUND, "not_found")
        except ProviderRuntimeError as error:
            self._send_provider_error(_provider_error_status(error.code), error.code)
        except (OSError, RuntimeError, TimeoutError, ValueError) as error:
            self._send_unexpected_provider_error(path, dependencies[0], error)

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
        if self.headers.get("Content-Length", "0") == "0":
            if path.endswith(("/health", "/reauth")):
                return {}
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_request")
            return None
        data = self._json()
        if data is None:
            self._send_provider_error(HTTPStatus.BAD_REQUEST, "invalid_request")
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
                initiation, authorization
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
            connection = runtime.finalize_oauth(principal, claim, completion)
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
        return isinstance(model_id, str) and set(data) == {"model_id"}, (
            model_id if isinstance(model_id, str) else None
        )

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
                if self.command != "POST"
                or action not in {"model", "health", "reauth"}
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
            initiation = runtime.initiate_reauth(
                principal, connection_id, "callback", "/settings/providers", revision
            )
            authorization = broker.authorize(
                runtime.connection_detail(principal, connection_id).adapter_id,
                initiation.state,
                initiation.flow,
                "/settings/providers",
            )
            return HTTPStatus.ACCEPTED, _provider_initiation_json(
                initiation, authorization
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

    def _dry_lab_state(self) -> None:
        """Return the authenticated session's dry-lab projection."""
        token = self._session_token()
        if token is None:
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return
        response = self.product_server.dry_lab.dispatch(
            _digest(token), "state", {}
        )
        self._send_json(HTTPStatus(response.status), response.payload)

    def _api_artifacts(self) -> None:
        """Project the authenticated dry-lab outputs into the artifact library."""
        token = self._session_token()
        if token is None:
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return
        response = self.product_server.dry_lab.dispatch(
            _digest(token), "state", {}
        )
        artifacts = response.payload.get("artifacts")
        items: list[JsonValue] = []
        if isinstance(artifacts, list):
            for index, artifact in enumerate(artifacts, start=1):
                if not isinstance(artifact, dict):
                    continue
                name = artifact.get("name")
                artifact_hash = artifact.get("sha256")
                if not isinstance(name, str) or not isinstance(artifact_hash, str):
                    continue
                suffix = Path(name).suffix.lower()
                media_type = {
                    ".csv": "text/csv",
                    ".md": "text/markdown",
                    ".png": "image/png",
                    ".json": "application/json",
                }.get(suffix, "application/octet-stream")
                items.append(
                    {
                        "artifact_id": f"dry-lab-{index}",
                        "name": name,
                        "version_no": 1,
                        "media_type": media_type,
                        "sha256": artifact_hash,
                    }
                )
        self._send_json(
            HTTPStatus(response.status),
            {"artifacts": items},
        )

    def _dry_lab_mutation(self, path: str) -> None:
        """Dispatch an authenticated same-origin dry-lab mutation."""
        action = path.removeprefix("/api/v1/dry-lab/")
        if action not in {
            "upload",
            "plan",
            "approve",
            "execute",
            "review",
            "export",
            "cleanup",
        }:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return
        if self._principal() is None:
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return
        body = self._json()
        token = self._session_token()
        if body is None or token is None:
            self._send(HTTPStatus.BAD_REQUEST, _BAD_REQUEST)
            return
        if action == "upload" and "csv" not in body:
            content = body.get("content")
            if isinstance(content, str):
                body = {**body, "csv": content}
        response = self.product_server.dry_lab.dispatch(_digest(token), action, body)
        self._send_json(HTTPStatus(response.status), response.payload)

    def _api_me(self, principal: Principal) -> None:
        self._send_json(
            HTTPStatus.OK,
            {
                "user": {"id": principal.user_id, "email": principal.email},
                "organization": {
                    "id": principal.organization_id,
                    "name": principal.organization_name,
                },
            },
        )

    def _api_workspace(self, principal: Principal) -> None:
        workspace = self.product_server.repository.workspace(
            self._tenant_principal(principal)
        )
        projects: list[JsonValue] = [
            {"id": project.id, "name": project.name}
            for project in workspace.projects
        ]
        self._send_json(
            HTTPStatus.OK,
            {"projects": projects, "recent_runs": []},
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

    def _start_run(self, path: str) -> None:
        if not self._same_origin_mutation():
            self._send(HTTPStatus.FORBIDDEN, _FORBIDDEN)
            return
        principal = self._principal()
        if principal is None:
            self._send(HTTPStatus.UNAUTHORIZED, _UNAUTHORIZED)
            return
        session_id = path.removeprefix("/api/v1/sessions/").removesuffix("/runs")
        tenant_principal = self._tenant_principal(principal)
        session = self.product_server.repository.session(tenant_principal, session_id)
        project = (
            self.product_server.repository.project(
                tenant_principal, session.project_id
            )
            if session
            else None
        )
        if session is None or project is None or project.archived:
            self._send(HTTPStatus.NOT_FOUND, _NOT_FOUND)
            return
        self._send_json(
            HTTPStatus.ACCEPTED,
            {"status": "queued", "session_id": session.id},
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
        self._send(
            HTTPStatus.OK,
            candidate.read_bytes(),
            {"Content-Type": content_type},
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


def _cookie(name: str, value: str, *, max_age: int) -> str:
    return f"{name}={value}; Max-Age={max_age}; Path=/; HttpOnly; SameSite=Strict"


def _expired_cookie(name: str) -> str:
    return f"{name}=; Max-Age=0; Path=/; HttpOnly; SameSite=Strict"


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
    initiation: OAuthInitiation, authorization: ProviderAuthorization
) -> JsonObject:
    return {
        "state": initiation.state,
        "flow": initiation.flow,
        "expires_at": initiation.expires_at.isoformat().replace("+00:00", "Z"),
        "revision": "0",
        "authorization_url": authorization.authorization_url,
        "device_instruction": authorization.device_instruction,
    }


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


def run_product_server(
    address: tuple[str, int] = ("127.0.0.1", 0),
    authenticated_fixture: bool = False,
    clock: Clock = _utc_now,
    options: ProductServerOptions | None = None,
) -> ProductServer:
    """Start a loopback server with bundled optional RLS and provider boundaries."""
    server = ProductServer(address, clock, options)
    if authenticated_fixture:
        _ = server.fixture_session_cookie()
    Thread(target=server.serve_forever, daemon=True).start()
    return server
