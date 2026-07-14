"""Same-origin provider HTTP lifecycle coverage."""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from threading import Barrier, Event, Lock
from typing import TYPE_CHECKING, Literal, cast, override

if TYPE_CHECKING:
    from collections.abc import Callable

from pydantic import TypeAdapter
from services.api.product_app import (
    ProductServer,
    ProductServerOptions,
    ProviderAuthorization,
    ProviderDiagnosticRecord,
    ProviderDiagnosticSink,
    ProviderOAuthBroker,
    run_product_server,
)
from services.api.provider_runtime import (
    Health,
    OAuthClaim,
    OfficialOAuthCompletion,
    ProviderCleanupReceipt,
    ProviderConnection,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderRevokeMutation,
    ProviderRuntimeService,
)

_RESPONSE_ADAPTER = TypeAdapter(dict[str, object])
_LOOPBACK = "127.0.0.1"

def _clock() -> datetime:
    return datetime(2026, 7, 13, tzinfo=UTC)


class _MutableClock:
    def __init__(self) -> None:
        self.now: datetime = _clock()

    def __call__(self) -> datetime:
        return self.now

    def advance(self, duration: timedelta) -> None:
        self.now += duration


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: dict[str, object]


@dataclass(frozen=True, slots=True)
class _Request:
    method: str
    path: str


class _Broker(ProviderOAuthBroker):
    """Official boundary fixture; it never accepts browser token/tool fields."""

    def __init__(self) -> None:
        self.authorizations: list[tuple[str, str, str, str]] = []
        self.exchanges: list[tuple[str, str, str]] = []
        self.health_checks: int = 0
        self._lock: Lock = Lock()

    @override
    def authorize(
        self, adapter_id: str, state: str, flow: str, redirect_uri: str
    ) -> ProviderAuthorization:
        assert adapter_id == "openai_codex"
        assert flow in {"callback", "device"}
        assert redirect_uri.startswith("/")
        with self._lock:
            self.authorizations.append((adapter_id, state, flow, redirect_uri))
        return ProviderAuthorization(
            authorization_url=f"https://provider.example.test/authorize?state={state}",
            device_instruction="Use the official device page" if flow == "device" else None,
        )

    @override
    def exchange(self, claim: OAuthClaim) -> OfficialOAuthCompletion:
        assert claim.state
        assert claim.flow in {"callback", "device"}
        assert claim.redirect_uri.startswith("/")
        with self._lock:
            self.exchanges.append((claim.state, claim.flow, claim.redirect_uri))
        return OfficialOAuthCompletion(
            "vault://runtime/connection/http",
            "account-redacted",
            ("codex-mini", "codex-max"),
            {"issuer": "official"},
        )

    @override
    def health(self, connection: ProviderConnection) -> Health:
        del connection
        with self._lock:
            self.health_checks += 1
        return "healthy"


class _DiagnosticSink(ProviderDiagnosticSink):
    """Thread-safe durable diagnostic fixture."""

    def __init__(self) -> None:
        self.records: list[ProviderDiagnosticRecord] = []
        self._lock: Lock = Lock()

    @override
    def append(self, record: ProviderDiagnosticRecord) -> None:
        with self._lock:
            self.records.append(record)


class _UnexpectedBrokerFailureError(Exception):
    """A broker failure outside the product's expected exception hierarchy."""
_UNEXPECTED_BROKER_FAILURE_MESSAGE = "broker fixture failure"


class _UnexpectedFailureBroker(_Broker):
    def __init__(self) -> None:
        super().__init__()
        self.authorize_started: Event = Event()
        self.release_authorize: Event = Event()
        self.authorize_count: int = 0

    @override
    def authorize(
        self, adapter_id: str, state: str, flow: str, redirect_uri: str
    ) -> ProviderAuthorization:
        del adapter_id, state, flow, redirect_uri
        with self._lock:
            self.authorize_count += 1
        self.authorize_started.set()
        assert self.release_authorize.wait(timeout=1)
        raise _UnexpectedBrokerFailureError(_UNEXPECTED_BROKER_FAILURE_MESSAGE)

class _Persistence(ProviderPersistence):
    """Thread-safe, observable test-only persistence boundary."""

    def __init__(self) -> None:
        self.upsert_count: int = 0
        self.revoke_count: int = 0
        self.upsert_inputs: list[
            tuple[ProviderPrincipal, ProviderConnection, str, int | None]
        ] = []
        self.revoke_inputs: list[
            tuple[ProviderPrincipal, ProviderRevokeMutation]
        ] = []
        self._lock: Lock = Lock()

    @override
    def upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        expected_revision: int | None,
    ) -> None:
        with self._lock:
            self.upsert_count += 1
            self.upsert_inputs.append(
                (principal, connection, runtime_home_ref, expected_revision)
            )

    @override
    def revoke(
        self, principal: ProviderPrincipal, mutation: ProviderRevokeMutation
    ) -> ProviderCleanupReceipt:
        with self._lock:
            self.revoke_count += 1
            self.revoke_inputs.append((principal, mutation))
        return ProviderCleanupReceipt(
            mutation.proposed.connection_id,
            mutation.proposed.adapter_id,
            mutation.requested_at,
            mutation.destroy_by,
            mutation.requested_at,
            "0" * 64,
        )


_PERSISTENCE_UNAVAILABLE_MESSAGE = "persistence unavailable"


class _FailingPersistence(_Persistence):
    @override
    def upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        expected_revision: int | None,
    ) -> None:
        del principal, connection, runtime_home_ref, expected_revision
        raise OSError(_PERSISTENCE_UNAVAILABLE_MESSAGE)

class _FailingRevokePersistence(_Persistence):
    @override
    def revoke(
        self, principal: ProviderPrincipal, mutation: ProviderRevokeMutation
    ) -> ProviderCleanupReceipt:
        del principal, mutation
        raise OSError(_PERSISTENCE_UNAVAILABLE_MESSAGE)




def _runtime(
    clock: _MutableClock | Callable[[], datetime],
    persistence: _Persistence | None = None,
) -> ProviderRuntimeService:
    return ProviderRuntimeService(clock, persistence=persistence or _Persistence())


def _error_code(response: _Response) -> str:
    error = response.body["error"]
    assert isinstance(error, dict)
    error = cast("dict[str, object]", error)
    assert set(error) == {"code", "message", "request_id"}
    assert isinstance(error["code"], str)
    assert isinstance(error["message"], str)
    assert isinstance(error["request_id"], str)
    return error["code"]

def _request(
    server: ProductServer,
    request: _Request,
    *,
    cookie: str | None = None,
    payload: dict[str, object] | None = None,
    headers: dict[str, str] | None = None,
) -> _Response:
    connection = HTTPConnection(_LOOPBACK, server.server_port)
    request_headers = headers.copy() if headers else {}
    if cookie is not None:
        request_headers["Cookie"] = cookie
    if payload is not None:
        request_headers["Content-Type"] = "application/json"
    body = json.dumps(payload).encode() if payload is not None else None
    try:
        connection.request(request.method, request.path, body, request_headers)
        response = connection.getresponse()
        return _Response(response.status, _RESPONSE_ADAPTER.validate_json(response.read()))
    finally:
        connection.close()


def _concurrent_requests(
    server: ProductServer,
    request: _Request,
    *,
    cookie: str,
    payload: dict[str, object] | None,
    headers: dict[str, str],
) -> tuple[_Response, _Response]:
    barrier = Barrier(2)

    def send() -> _Response:
        _ = barrier.wait()
        return _request(
            server, request, cookie=cookie, payload=payload, headers=headers
        )

    with ThreadPoolExecutor(max_workers=2) as executor:
        first = executor.submit(send)
        second = executor.submit(send)
    return first.result(), second.result()


def _same_origin(server: ProductServer, cookie: str, **extra: str) -> dict[str, str]:
    return {
        "Cookie": cookie,
        "Origin": f"http://{_LOOPBACK}:{server.server_port}",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        **extra,
    }


def _initiate(
    server: ProductServer,
    cookie: str,
    flow: Literal["callback", "device"],
    key: str,
) -> dict[str, object]:
    redirect_uri = "/settings/providers" if flow == "callback" else "/oauth/device"
    initiated = _request(
        server,
        _Request("POST", "/api/v1/provider-connections"),
        cookie=cookie,
        headers=_same_origin(server, cookie, **{"Idempotency-Key": key}),
        payload={
            "adapter_id": "openai_codex",
            "flow": flow,
            "redirect_uri": redirect_uri,
        },
    )
    assert initiated.status == 202
    return initiated.body


def _connect(
    server: ProductServer,
    cookie: str,
    flow: Literal["callback", "device"] = "callback",
    key_prefix: str = "",
) -> tuple[dict[str, object], dict[str, object]]:
    redirect_uri = "/settings/providers" if flow == "callback" else "/oauth/device"
    initiated = _initiate(server, cookie, flow, f"{key_prefix}init-{flow}")
    completed = _request(
        server,
        _Request("POST", "/api/v1/provider-connections/oauth/complete"),
        cookie=cookie,
        headers=_same_origin(
            server, cookie, **{"Idempotency-Key": f"{key_prefix}complete-{flow}"}
        ),
        payload={
            "state": initiated["state"],
            "flow": flow,
            "redirect_uri": redirect_uri,
        },
    )
    assert completed.status == 200
    return initiated, completed.body


def _exercise_connection_lifecycle(
    server: ProductServer,
    cookie: str,
    connection: dict[str, object],
    broker: _Broker,
) -> None:
    connection_id = str(connection["id"])
    listed = _request(
        server, _Request("GET", "/api/v1/provider-connections"), cookie=cookie
    )
    detail = _request(
        server,
        _Request("GET", f"/api/v1/provider-connections/{connection_id}"),
        cookie=cookie,
    )
    assert listed.status == detail.status == 200
    assert set(detail.body) == {
        "id",
        "adapter_id",
        "account",
        "models",
        "selected_model",
        "status",
        "health",
        "qualification",
        "revision",
        "created_at",
    }
    assert detail.body["account"] == {"id": "account-redacted"}
    assert detail.body["models"] == ["codex-mini", "codex-max"]

    stale = _request(
        server,
        _Request("POST", f"/api/v1/provider-connections/{connection_id}/model"),
        cookie=cookie,
        headers=_same_origin(
            server, cookie, **{"If-Match": "0", "Idempotency-Key": "model-stale"}
        ),
        payload={"model_id": "codex-mini"},
    )
    selected = _request(
        server,
        _Request("POST", f"/api/v1/provider-connections/{connection_id}/model"),
        cookie=cookie,
        headers=_same_origin(
            server,
            cookie,
            **{
                "If-Match": str(connection["revision"]),
                "Idempotency-Key": "model-select",
            },
        ),
        payload={"model_id": "codex-mini"},
    )
    assert stale.status == 412
    assert selected.status == 200
    selected_replay = _request(
        server,
        _Request("POST", f"/api/v1/provider-connections/{connection_id}/model"),
        cookie=cookie,
        headers=_same_origin(
            server,
            cookie,
            **{
                "If-Match": str(connection["revision"]),
                "Idempotency-Key": "model-select",
            },
        ),
        payload={"model_id": "codex-mini"},
    )
    assert selected_replay.status == selected.status
    assert selected_replay.body == selected.body
    healthy = _request(
        server,
        _Request("POST", f"/api/v1/provider-connections/{connection_id}/health"),
        cookie=cookie,
        headers=_same_origin(
            server,
            cookie,
            **{
                "If-Match": str(selected.body["revision"]),
                "Idempotency-Key": "health",
            },
        ),
    )
    assert healthy.status == 409
    assert _error_code(healthy) == "qualification_required"
    healthy_replay = _request(
        server,
        _Request("POST", f"/api/v1/provider-connections/{connection_id}/health"),
        cookie=cookie,
        headers=_same_origin(
            server,
            cookie,
            **{
                "If-Match": str(selected.body["revision"]),
                "Idempotency-Key": "health",
            },
        ),
    )
    assert healthy_replay.status == healthy.status
    assert healthy_replay.body == healthy.body
    assert broker.health_checks == 1
    authorization_count = len(broker.authorizations)
    reauth = _request(
        server,
        _Request("POST", f"/api/v1/provider-connections/{connection_id}/reauth"),
        cookie=cookie,
        headers=_same_origin(
            server,
            cookie,
            **{
                "If-Match": str(selected.body["revision"]),
                "Idempotency-Key": "reauth",
            },
        ),
    )
    assert reauth.status == 202
    reauth_replay = _request(
        server,
        _Request("POST", f"/api/v1/provider-connections/{connection_id}/reauth"),
        cookie=cookie,
        headers=_same_origin(
            server,
            cookie,
            **{
                "If-Match": str(selected.body["revision"]),
                "Idempotency-Key": "reauth",
            },
        ),
    )
    assert reauth_replay.status == reauth.status
    assert reauth_replay.body == reauth.body
    assert len(broker.authorizations) == authorization_count + 1
    current = _request(
        server,
        _Request("GET", f"/api/v1/provider-connections/{connection_id}"),
        cookie=cookie,
    )
    revoked = _request(
        server,
        _Request("DELETE", f"/api/v1/provider-connections/{connection_id}"),
        cookie=cookie,
        headers=_same_origin(
            server, cookie, **{"If-Match": str(current.body["revision"])}
        ),
    )
    assert revoked.status == 200
    cleanup = revoked.body["cleanup_receipt"]
    assert isinstance(cleanup, dict)
    cleanup_body = cast("dict[str, object]", cleanup)
    assert set(cleanup_body) == {
        "connection_id",
        "adapter_id",
        "requested_at",
        "destroy_by",
        "destroyed_at",
        "evidence_sha256",
        "redacted",
    }
    assert cleanup_body["redacted"] is True
    assert "vault" not in json.dumps(cleanup_body)


def test_provider_lifecycle_is_same_origin_idempotent_and_redacted() -> None:
    broker = _Broker()
    runtime = _runtime(_clock)
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=runtime,
            provider_oauth_broker=broker,
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        registry = _request(
            server,
            _Request("GET", "/api/v1/provider-connections/registry"),
            cookie=cookie,
        )
        assert registry.status == 200
        adapters = registry.body["adapters"]
        assert isinstance(adapters, list)
        adapter_items = cast("list[dict[str, object]]", adapters)
        assert set(adapter_items[0]) == {
            "id",
            "required",
            "default",
            "connectable",
            "disabled_reason",
        }
        assert adapter_items[0]["id"] == "openai_codex"
        assert adapter_items[-1]["id"] == "zai_glm"
        assert adapter_items[0]["default"] is True

        request_body: dict[str, object] = {
            "adapter_id": "openai_codex",
            "flow": "callback",
            "redirect_uri": "/settings/providers",
        }
        headers = _same_origin(server, cookie, **{"Idempotency-Key": "replay-key"})
        initiated = _request(
            server,
            _Request("POST", "/api/v1/provider-connections"),
            cookie=cookie,
            payload=request_body,
            headers=headers,
        )
        replay = _request(
            server,
            _Request("POST", "/api/v1/provider-connections"),
            cookie=cookie,
            payload=request_body,
            headers=headers,
        )
        conflict = _request(
            server,
            _Request("POST", "/api/v1/provider-connections"),
            cookie=cookie,
            payload={**request_body, "flow": "device"},
            headers=headers,
        )
        assert (initiated.status, replay.status, conflict.status) == (202, 202, 409)
        assert initiated.body == replay.body
        assert set(initiated.body) == {
            "state",
            "flow",
            "expires_at",
            "revision",
            "authorization_url",
            "device_instruction",
        }
        assert "vault" not in json.dumps(initiated.body)

        _, connection = _connect(server, cookie)
        completion_replay = _request(
            server,
            _Request("POST", "/api/v1/provider-connections/oauth/complete"),
            cookie=cookie,
            headers=_same_origin(server, cookie, **{"Idempotency-Key": "replay-complete"}),
            payload={
                "state": initiated.body["state"],
                "flow": "callback",
                "redirect_uri": "/settings/providers",
            },
        )
        assert completion_replay.status == 200
        assert len(broker.exchanges) == 2
        assert "vault" not in json.dumps(connection)
        assert "token" not in json.dumps(connection)
        _exercise_connection_lifecycle(server, cookie, connection, broker)
    finally:
        server.shutdown()
        server.server_close()


def test_provider_mutations_reject_unauthenticated_and_cross_origin_requests() -> None:
    server = run_product_server(
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=_runtime(_clock),
            provider_oauth_broker=_Broker(),
            provider_diagnostic_sink=_DiagnosticSink(),
        )
    )
    try:
        body: dict[str, object] = {
            "adapter_id": "openai_codex",
            "flow": "device",
            "redirect_uri": "/oauth/device",
        }
        unauthenticated = _request(
            server,
            _Request("POST", "/api/v1/provider-connections"),
            payload=body,
            headers={
                "Origin": f"http://{_LOOPBACK}:{server.server_port}",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
                "Idempotency-Key": "unauth",
            },
        )
        cross_origin = _request(
            server,
            _Request("POST", "/api/v1/provider-connections"),
            payload=body,
            headers={
                "Origin": "https://evil.example.test",
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "cors",
                "Idempotency-Key": "cross",
            },
        )
        assert unauthenticated.status == 401
        assert cross_origin.status == 400
    finally:
        server.shutdown()
        server.server_close()
def test_provider_dependencies_are_capability_forbidden() -> None:
    server = run_product_server(authenticated_fixture=True, clock=_clock)
    try:
        cookie = server.fixture_session_cookie()
        missing_get = _request(
            server,
            _Request("GET", "/api/v1/provider-connections"),
            cookie=cookie,
        )
        missing_mutation = _request(
            server,
            _Request("POST", "/api/v1/provider-connections"),
            cookie=cookie,
            headers=_same_origin(
                server, cookie, **{"Idempotency-Key": "missing-dependency"}
            ),
            payload={
                "adapter_id": "openai_codex",
                "flow": "callback",
                "redirect_uri": "/settings/providers",
            },
        )
        assert missing_get.status == missing_mutation.status == 403
        assert _error_code(missing_get) == _error_code(missing_mutation) == (
            "capability_disabled"
        )
    finally:
        server.shutdown()
        server.server_close()


def test_provider_revoke_persistence_failure_is_canonical_and_non_mutating() -> None:
    persistence = _FailingRevokePersistence()
    runtime = _runtime(_clock, persistence)
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=runtime,
            provider_oauth_broker=_Broker(),
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        _, connection = _connect(server, cookie, key_prefix="failing-revoke-")
        connection_id = connection["id"]
        revision = connection["revision"]
        assert isinstance(connection_id, str)
        assert isinstance(revision, str)

        failed = _request(
            server,
            _Request("DELETE", f"/api/v1/provider-connections/{connection_id}"),
            cookie=cookie,
            headers=_same_origin(server, cookie, **{"If-Match": revision}),
        )

        assert failed.status == 503
        assert _error_code(failed) == "provider_unavailable"
        current = _request(
            server,
            _Request("GET", f"/api/v1/provider-connections/{connection_id}"),
            cookie=cookie,
        )
        assert current.status == 200
        assert current.body == connection
        assert persistence.revoke_count == 0
    finally:
        server.shutdown()
        server.server_close()

def test_provider_adapter_and_persistence_failures_have_documented_statuses() -> None:
    failing_runtime = _runtime(_clock, _FailingPersistence())
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=failing_runtime,
            provider_oauth_broker=_Broker(),
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        disabled = _request(
            server,
            _Request("POST", "/api/v1/provider-connections"),
            cookie=cookie,
            headers=_same_origin(server, cookie, **{"Idempotency-Key": "disabled"}),
            payload={
                "adapter_id": "anthropic_claude_code",
                "flow": "callback",
                "redirect_uri": "/settings/providers",
            },
        )
        initiated = _request(
            server,
            _Request("POST", "/api/v1/provider-connections"),
            cookie=cookie,
            headers=_same_origin(server, cookie, **{"Idempotency-Key": "persistence"}),
            payload={
                "adapter_id": "openai_codex",
                "flow": "callback",
                "redirect_uri": "/settings/providers",
            },
        )
        state = initiated.body["state"]
        assert initiated.status == 202
        assert isinstance(state, str)
        persistence = _request(
            server,
            _Request("POST", "/api/v1/provider-connections/oauth/complete"),
            cookie=cookie,
            headers=_same_origin(
                server, cookie, **{"Idempotency-Key": "persistence-complete"}
            ),
            payload={
                "state": state,
                "flow": "callback",
                "redirect_uri": "/settings/providers",
            },
        )
        assert disabled.status == 403
        assert _error_code(disabled) == "adapter_disabled"
        assert persistence.status == 503
        assert _error_code(persistence) == "provider_unavailable"
    finally:
        server.shutdown()
        server.server_close()


def test_foreign_and_missing_provider_connections_are_non_disclosing() -> None:
    broker = _Broker()
    runtime = _runtime(_clock)
    owner = ProviderPrincipal("foreign-user", "foreign-org")
    initiation = runtime.initiate(
        owner, "openai_codex", "callback", "/settings/providers"
    )
    claim = runtime.claim_oauth(
        owner, initiation.state, "callback", "/settings/providers"
    )
    foreign_connection = runtime.finalize_oauth(owner, claim, broker.exchange(claim))
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=runtime,
            provider_oauth_broker=broker,
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        responses = (
            _request(
                server,
                _Request(
                    "GET",
                    f"/api/v1/provider-connections/{foreign_connection.connection_id}",
                ),
                cookie=cookie,
            ),
            _request(
                server,
                _Request("GET", "/api/v1/provider-connections/missing"),
                cookie=cookie,
            ),
        )
        assert all(response.status == 404 for response in responses)
        assert all(_error_code(response) == "not_found" for response in responses)
    finally:
        server.shutdown()
        server.server_close()


def test_every_provider_post_requires_idempotency_key() -> None:
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=_runtime(_clock),
            provider_oauth_broker=_Broker(),
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        headers = _same_origin(server, cookie)
        requests: tuple[tuple[str, dict[str, object]], ...] = (
            ("/api/v1/provider-connections", {}),
            ("/api/v1/provider-connections/oauth/complete", {}),
            ("/api/v1/provider-connections/oauth/cancel", {}),
            ("/api/v1/provider-connections/missing/model", {}),
            ("/api/v1/provider-connections/missing/health", {}),
            ("/api/v1/provider-connections/missing/reauth", {}),
        )
        for path, payload in requests:
            response = _request(
                server,
                _Request("POST", path),
                cookie=cookie,
                headers=headers,
                payload=payload,
            )
            assert response.status == 400
            assert _error_code(response) == "invalid_request"
    finally:
        server.shutdown()
        server.server_close()


def test_device_oauth_lifecycle_is_redacted() -> None:
    broker = _Broker()
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=_runtime(_clock),
            provider_oauth_broker=broker,
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        initiated, completed = _connect(server, cookie, "device")

        assert initiated["device_instruction"] == "Use the official device page"
        assert broker.exchanges[0][1:] == ("device", "/oauth/device")
        response_text = json.dumps((initiated, completed))
        assert "vault" not in response_text
        assert "token" not in response_text
    finally:
        server.shutdown()
        server.server_close()


def _assert_idempotency_conflict(response: _Response) -> None:
    assert response.status == 409
    assert _error_code(response) == "idempotency_conflict"


def _exercise_cancel_single_flight(
    server: ProductServer, cookie: str, runtime: ProviderRuntimeService
) -> None:
    state = _initiate(server, cookie, "device", "cancel-single")["state"]
    alternate_state = _initiate(
        server, cookie, "device", "cancel-conflict"
    )["state"]
    assert isinstance(state, str)
    assert isinstance(alternate_state, str)
    request = _Request("POST", "/api/v1/provider-connections/oauth/cancel")
    headers = _same_origin(server, cookie, **{"Idempotency-Key": "single-cancel"})
    payload: dict[str, object] = {"state": state}

    concurrent = _concurrent_requests(
        server, request, cookie=cookie, payload=payload, headers=headers
    )

    assert (concurrent[0].status, concurrent[1].status) == (200, 200)
    assert concurrent[0].body == concurrent[1].body == {"status": "cancelled"}
    assert runtime.audit_receipts().count(("oauth_cancelled", "openai_codex")) == 1
    replay = _request(server, request, cookie=cookie, payload=payload, headers=headers)
    assert replay.status == 200
    assert replay.body == concurrent[0].body
    conflict = _request(
        server,
        request,
        cookie=cookie,
        payload={"state": alternate_state},
        headers=headers,
    )
    _assert_idempotency_conflict(conflict)


def _exercise_model_single_flight(
    server: ProductServer, cookie: str, persistence: _Persistence
) -> None:
    _, connection = _connect(server, cookie, key_prefix="model-single-")
    connection_id = str(connection["id"])
    revision = str(connection["revision"])
    request = _Request("POST", f"/api/v1/provider-connections/{connection_id}/model")
    headers = _same_origin(
        server,
        cookie,
        **{"Idempotency-Key": "single-model", "If-Match": revision},
    )
    payload: dict[str, object] = {"model_id": "codex-mini"}
    before_upserts = persistence.upsert_count

    concurrent = _concurrent_requests(
        server, request, cookie=cookie, payload=payload, headers=headers
    )

    assert (concurrent[0].status, concurrent[1].status) == (200, 200)
    assert concurrent[0].body == concurrent[1].body
    assert persistence.upsert_count == before_upserts + 1
    assert persistence.upsert_inputs[-1][1].selected_model == "codex-mini"
    replay = _request(server, request, cookie=cookie, payload=payload, headers=headers)
    assert replay.status == 200
    assert replay.body == concurrent[0].body
    conflict = _request(
        server,
        request,
        cookie=cookie,
        payload={"model_id": "codex-max"},
        headers=headers,
    )
    _assert_idempotency_conflict(conflict)


def _exercise_health_single_flight(
    server: ProductServer, cookie: str, broker: _Broker
) -> None:
    _, connection = _connect(server, cookie, key_prefix="health-single-")
    connection_id = str(connection["id"])
    revision = str(connection["revision"])
    request = _Request("POST", f"/api/v1/provider-connections/{connection_id}/health")
    headers = _same_origin(
        server,
        cookie,
        **{"Idempotency-Key": "single-health", "If-Match": revision},
    )

    concurrent = _concurrent_requests(
        server, request, cookie=cookie, payload=None, headers=headers
    )

    assert (concurrent[0].status, concurrent[1].status) == (409, 409)
    assert concurrent[0].body == concurrent[1].body
    assert broker.health_checks == 1
    replay = _request(server, request, cookie=cookie, headers=headers)
    assert replay.status == 409
    assert replay.body == concurrent[0].body
    conflict = _request(
        server,
        request,
        cookie=cookie,
        headers=_same_origin(
            server,
            cookie,
            **{"Idempotency-Key": "single-health", "If-Match": "0"},
        ),
    )
    _assert_idempotency_conflict(conflict)


def _exercise_reauth_single_flight(
    server: ProductServer, cookie: str, broker: _Broker
) -> None:
    _, connection = _connect(server, cookie, key_prefix="reauth-single-")
    connection_id = str(connection["id"])
    revision = str(connection["revision"])
    request = _Request("POST", f"/api/v1/provider-connections/{connection_id}/reauth")
    headers = _same_origin(
        server,
        cookie,
        **{"Idempotency-Key": "single-reauth", "If-Match": revision},
    )
    authorizations_before = len(broker.authorizations)

    concurrent = _concurrent_requests(
        server, request, cookie=cookie, payload=None, headers=headers
    )

    assert (concurrent[0].status, concurrent[1].status) == (202, 202)
    assert concurrent[0].body == concurrent[1].body
    assert len(broker.authorizations) == authorizations_before + 1
    replay = _request(server, request, cookie=cookie, headers=headers)
    assert replay.status == 202
    assert replay.body == concurrent[0].body
    conflict = _request(
        server,
        request,
        cookie=cookie,
        headers=_same_origin(
            server,
            cookie,
            **{"Idempotency-Key": "single-reauth", "If-Match": "0"},
        ),
    )
    _assert_idempotency_conflict(conflict)


def test_remaining_provider_post_routes_are_single_flight_and_conflict_safe() -> None:
    broker = _Broker()
    persistence = _Persistence()
    runtime = _runtime(_clock, persistence)
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=runtime,
            provider_oauth_broker=broker,
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        _exercise_cancel_single_flight(server, cookie, runtime)
        _exercise_model_single_flight(server, cookie, persistence)
        _exercise_health_single_flight(server, cookie, broker)
        _exercise_reauth_single_flight(server, cookie, broker)
    finally:
        server.shutdown()
        server.server_close()


def test_provider_http_same_key_operations_are_single_flight() -> None:
    broker = _Broker()
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=_runtime(_clock),
            provider_oauth_broker=broker,
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        initiation_payload: dict[str, object] = {
            "adapter_id": "openai_codex",
            "flow": "callback",
            "redirect_uri": "/settings/providers",
        }
        initiated = _concurrent_requests(
            server,
            _Request("POST", "/api/v1/provider-connections"),
            cookie=cookie,
            payload=initiation_payload,
            headers=_same_origin(server, cookie, **{"Idempotency-Key": "single-init"}),
        )
        assert (initiated[0].status, initiated[1].status) == (202, 202)
        assert initiated[0].body == initiated[1].body
        assert len(broker.authorizations) == 1

        completion_payload: dict[str, object] = {
            "state": initiated[0].body["state"],
            "flow": "callback",
            "redirect_uri": "/settings/providers",
        }
        completed = _concurrent_requests(
            server,
            _Request("POST", "/api/v1/provider-connections/oauth/complete"),
            cookie=cookie,
            payload=completion_payload,
            headers=_same_origin(
                server, cookie, **{"Idempotency-Key": "single-complete"}
            ),
        )
        assert (completed[0].status, completed[1].status) == (200, 200)
        assert completed[0].body == completed[1].body
        assert len(broker.exchanges) == 1
    finally:
        server.shutdown()
        server.server_close()


def test_unexpected_broker_exception_terminalizes_idempotency_entry() -> None:
    broker = _UnexpectedFailureBroker()
    diagnostic_sink = _DiagnosticSink()
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=_runtime(_clock),
            provider_oauth_broker=broker,
            provider_diagnostic_sink=diagnostic_sink,
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        request = _Request("POST", "/api/v1/provider-connections")
        payload: dict[str, object] = {
            "adapter_id": "openai_codex",
            "flow": "callback",
            "redirect_uri": "/settings/providers",
        }
        headers = _same_origin(
            server, cookie, **{"Idempotency-Key": "unexpected-broker"}
        )
        with ThreadPoolExecutor(max_workers=2) as executor:
            leader = executor.submit(
                _request,
                server,
                request,
                cookie=cookie,
                payload=payload,
                headers=headers,
            )
            assert broker.authorize_started.wait(timeout=1)
            follower = executor.submit(
                _request,
                server,
                request,
                cookie=cookie,
                payload=payload,
                headers=headers,
            )
            broker.release_authorize.set()
            responses = (leader.result(timeout=1), follower.result(timeout=1))

        assert (responses[0].status, responses[1].status) == (503, 503)
        assert responses[0].body == responses[1].body
        assert _error_code(responses[0]) == "provider_unavailable"
        assert broker.authorize_count == 1
        assert len(diagnostic_sink.records) == 1
        diagnostic = diagnostic_sink.records[0]
        error = cast("dict[str, object]", responses[0].body["error"])
        assert diagnostic.request_id == error["request_id"]
        assert diagnostic.exception_class == "_UnexpectedBrokerFailureError"
        assert len(diagnostic.traceback_sha256) == 64
        assert int(diagnostic.traceback_sha256, 16) >= 0
        assert _UNEXPECTED_BROKER_FAILURE_MESSAGE not in str(diagnostic)

        replay = _request(
            server, request, cookie=cookie, payload=payload, headers=headers
        )
        assert replay.status == 503
        assert replay.body == responses[0].body
        assert broker.authorize_count == 1
        assert len(diagnostic_sink.records) == 1

        conflict = _request(
            server,
            request,
            cookie=cookie,
            payload={**payload, "flow": "device"},
            headers=headers,
        )
        _assert_idempotency_conflict(conflict)
        assert broker.authorize_count == 1

        unrelated = _request(
            server,
            request,
            cookie=cookie,
            payload=payload,
            headers=_same_origin(
                server, cookie, **{"Idempotency-Key": "unexpected-broker-other"}
            ),
        )
        assert unrelated.status == 503
        assert _error_code(unrelated) == "provider_unavailable"
        assert broker.authorize_count == 2
    finally:
        server.shutdown()
        server.server_close()

def test_provider_http_rejects_invalid_oauth_claims_before_exchange() -> None:
    broker = _Broker()
    clock = _MutableClock()
    runtime = _runtime(clock)
    server = run_product_server(
        authenticated_fixture=True,
        clock=clock,
        options=ProductServerOptions(
            provider_runtime=runtime,
            provider_oauth_broker=broker,
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        bound = _initiate(server, cookie, "callback", "bound-state")
        binding_mismatch = _request(
            server,
            _Request("POST", "/api/v1/provider-connections/oauth/complete"),
            cookie=cookie,
            headers=_same_origin(
                server, cookie, **{"Idempotency-Key": "bound-complete"}
            ),
            payload={
                "state": bound["state"],
                "flow": "callback",
                "redirect_uri": "/oauth/device",
            },
        )
        assert binding_mismatch.status == 400
        assert _error_code(binding_mismatch) == "oauth_binding_mismatch"
        assert len(broker.exchanges) == 0

        expired = _initiate(server, cookie, "device", "expired-state")
        clock.advance(timedelta(minutes=11))
        expired_completion = _request(
            server,
            _Request("POST", "/api/v1/provider-connections/oauth/complete"),
            cookie=cookie,
            headers=_same_origin(
                server, cookie, **{"Idempotency-Key": "expired-complete"}
            ),
            payload={
                "state": expired["state"],
                "flow": "device",
                "redirect_uri": "/oauth/device",
            },
        )
        assert expired_completion.status == 400
        assert _error_code(expired_completion) == "oauth_expired"
        assert len(broker.exchanges) == 0
    finally:
        server.shutdown()
        server.server_close()


def test_cancelled_oauth_state_is_non_disclosing() -> None:
    broker = _Broker()
    server = run_product_server(
        authenticated_fixture=True,
        clock=_clock,
        options=ProductServerOptions(
            provider_runtime=_runtime(_clock),
            provider_oauth_broker=broker,
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        initiated = _initiate(server, cookie, "device", "cancel-device")
        state = initiated["state"]
        assert isinstance(state, str)
        cancel_request = _Request(
            "POST", "/api/v1/provider-connections/oauth/cancel"
        )

        unauthenticated = _request(
            server,
            cancel_request,
            headers={
                "Origin": f"http://{_LOOPBACK}:{server.server_port}",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
            },
            payload={"state": state},
        )
        cross_origin = _request(
            server,
            cancel_request,
            cookie=cookie,
            headers={
                "Origin": "https://evil.example.test",
                "Sec-Fetch-Site": "cross-site",
                "Sec-Fetch-Mode": "cors",
            },
            payload={"state": state},
        )
        cancelled = _request(
            server,
            cancel_request,
            cookie=cookie,
            headers=_same_origin(server, cookie, **{"Idempotency-Key": "cancel"}),
            payload={"state": state},
        )
        assert (unauthenticated.status, cross_origin.status, cancelled.status) == (
            401,
            400,
            200,
        )
        assert cancelled.body == {"status": "cancelled"}

        completion_request = _Request(
            "POST", "/api/v1/provider-connections/oauth/complete"
        )
        completion_headers = _same_origin(
            server, cookie, **{"Idempotency-Key": "cancel-complete"}
        )
        completion_payload: dict[str, object] = {
            "flow": "device",
            "redirect_uri": "/oauth/device",
        }
        cancelled_completion = _request(
            server,
            completion_request,
            cookie=cookie,
            headers=completion_headers,
            payload={**completion_payload, "state": state},
        )
        missing_completion = _request(
            server,
            completion_request,
            cookie=cookie,
            headers=_same_origin(
                server,
                cookie,
                **{"Idempotency-Key": "missing-complete"},
            ),
            payload={**completion_payload, "state": "missing-state"},
        )
        assert cancelled_completion.status == missing_completion.status == 404
        assert _error_code(cancelled_completion) == _error_code(missing_completion) == "not_found"
        assert state not in json.dumps(cancelled_completion.body)
        assert "missing-state" not in json.dumps(missing_completion.body)
        assert len(broker.exchanges) == 0
    finally:
        server.shutdown()
        server.server_close()
