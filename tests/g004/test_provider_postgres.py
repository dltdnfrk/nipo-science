"""HTTP-to-Postgres persistence coverage for provider connections."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime
from http.client import HTTPConnection
from threading import Lock
from typing import Final, override

import pytest
from pydantic import TypeAdapter
from services.api.product_app import (
    Principal,
    ProductServer,
    ProductServerOptions,
    ProviderAuthorization,
    ProviderDiagnosticRecord,
    ProviderDiagnosticSink,
    ProviderOAuthBroker,
    run_product_server,
)
from services.api.provider_postgres import (
    PostgresProviderPersistence,
    RuntimeHomeDestroyer,
)
from services.api.provider_runtime import (
    Health,
    OAuthClaim,
    OfficialOAuthCompletion,
    ProviderConnection,
    ProviderPrincipal,
    ProviderRuntimeService,
)
from services.api.tests.persistence.postgres_harness import (
    database_url_asyncpg,
    psql,
)
from services.api.tests.persistence.test_rls import (
    ORG_A,
    USER_A,
    seed_tenants,
)

pytest_plugins = ("services.api.tests.persistence.conftest",)
pytestmark = pytest.mark.usefixtures("migrated_database")

_LOOPBACK: Final = "127.0.0.1"
_SHA256_EVIDENCE: Final = "a" * 64
_RESPONSE = TypeAdapter(dict[str, object])


class _DiagnosticSink(ProviderDiagnosticSink):
    """Thread-safe durable diagnostic fixture."""

    def __init__(self) -> None:
        self.records: list[ProviderDiagnosticRecord] = []
        self._lock: Lock = Lock()

    @override
    def append(self, record: ProviderDiagnosticRecord) -> None:
        with self._lock:
            self.records.append(record)


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: dict[str, object]


@dataclass(frozen=True, slots=True)
class _RequestSpec:
    method: str
    path: str
    payload: dict[str, object] | None = None
    headers: dict[str, str] | None = None

class _Destroyer(RuntimeHomeDestroyer):
    def __init__(self) -> None:
        self.refs: list[str] = []

    @override
    def destroy(self, opaque_ref: str) -> str:
        self.refs.append(opaque_ref)
        return _SHA256_EVIDENCE



class _Broker(ProviderOAuthBroker):
    @override
    def authorize(
        self, adapter_id: str, state: str, flow: str, redirect_uri: str
    ) -> ProviderAuthorization:
        assert adapter_id == "openai_codex"
        assert state
        assert flow == "callback"
        assert redirect_uri == "/settings/providers"
        return ProviderAuthorization(
            authorization_url=f"https://provider.example.test/authorize?state={state}"
        )

    @override
    def exchange(self, claim: OAuthClaim) -> OfficialOAuthCompletion:
        assert claim.adapter_id == "openai_codex"
        assert claim.state
        assert claim.flow == "callback"
        assert claim.redirect_uri == "/settings/providers"
        return OfficialOAuthCompletion(
            "vault://runtime/connection/postgres",
            "account-redacted",
            ("codex-mini", "codex-max"),
            {"issuer": "official"},
        )

    @override
    def health(self, connection: ProviderConnection) -> Health:
        assert connection.connection_id
        return "healthy"


def _request(
    server: ProductServer, cookie: str, spec: _RequestSpec
) -> _Response:
    request_headers = {"Cookie": cookie} | (spec.headers or {})
    if spec.payload is not None:
        request_headers["Content-Type"] = "application/json"
    connection = HTTPConnection(_LOOPBACK, server.server_port)
    try:
        connection.request(
            spec.method,
            spec.path,
            json.dumps(spec.payload).encode() if spec.payload is not None else None,
            request_headers,
        )
        response = connection.getresponse()
        return _Response(response.status, _RESPONSE.validate_json(response.read()))
    finally:
        connection.close()


def _same_origin(server: ProductServer, **extra: str) -> dict[str, str]:
    return {
        "Origin": f"http://{_LOOPBACK}:{server.server_port}",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        **extra,
    }


def _connection_row() -> dict[str, object]:
    result = psql(
        "SELECT json_build_object("
        "'id', id, 'org_id', org_id, 'requester_user_id', requester_user_id, "
        "'adapter_id', adapter_id, 'account_metadata', account_metadata, "
        "'selected_model', selected_model, 'status', status, "
        "'qualified_at', qualified_at IS NOT NULL, "
        "'runtime_ref', encrypted_runtime_home_ref, "
        "'health_checked_at', health_checked_at IS NOT NULL, "
        "'revoked_at', revoked_at IS NOT NULL)::text "
        "FROM provider_connections ORDER BY created_at DESC LIMIT 1"
    )
    return _RESPONSE.validate_json(result.stdout)

def _other_requester_connection_count_query() -> str:
    return (
        "SET ROLE science_workbench_app; "
        "SELECT set_config('app.org_id', "
        "'018f0d7d-6b17-7a91-8b31-2f7331677a01', false); "
        "SELECT set_config('app.user_id', "
        "'018f0d7d-6b17-7a91-8b31-2f7331677a03', false); "
        "SELECT count(*) FROM provider_connections"
    )


def _assert_created_connection(connection_id: str) -> None:
    created = _connection_row()
    assert created["id"] == connection_id
    metadata = created["account_metadata"]
    assert isinstance(metadata, dict)
    assert created["org_id"] == ORG_A
    assert created["requester_user_id"] == USER_A
    assert created["adapter_id"] == "openai_codex"
    assert connection_id[14] == "7"
    assert created["selected_model"] is None
    assert created["status"] == "pending"
    assert created["runtime_ref"] == "vault://runtime/connection/postgres"
    assert metadata == {
        "account_id": "account-redacted",
        "models": ["codex-mini", "codex-max"],
        "provider": "openai_codex",
        "revision": "1",
        "subscription_tier": (
            "health=pending;qualified=False;cleanup=False;revision=1"
        ),
    }
    assert "vault" not in json.dumps(metadata)
    assert "token" not in json.dumps(metadata)

    hidden = psql(_other_requester_connection_count_query())
    assert hidden.stdout.splitlines()[-1] == "0"


def _complete_connection(
    server: ProductServer, cookie: str, state: object
) -> _Response:
    return _request(
        server,
        cookie,
        _RequestSpec(
            "POST",
            "/api/v1/provider-connections/oauth/complete",
            {
                "state": state,
                "flow": "callback",
                "redirect_uri": "/settings/providers",
            },
            _same_origin(server),
        ),
    )

def _assert_completed_connection(response: _Response) -> str:
    assert response.status == 200
    response_text = json.dumps(response.body)
    assert "vault" not in response_text
    assert "token" not in response_text
    assert "authorization_response" not in response_text
    return str(response.body["id"])


def test_http_provider_lifecycle_persists_only_safe_requester_owned_data() -> None:
    seed_tenants()
    destroyer = _Destroyer()
    runtime = ProviderRuntimeService(
        lambda: datetime(2026, 7, 13, tzinfo=UTC),
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(), destroyer
        ),
    )
    server = run_product_server(
        authenticated_fixture=True,
        options=ProductServerOptions(
            principal=Principal(USER_A, ORG_A, "a@example.test", "A"),
            provider_runtime=runtime,
            provider_oauth_broker=_Broker(),
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        initiated = _request(
            server,
            cookie,
            _RequestSpec(
                "POST",
                "/api/v1/provider-connections",
                {
                    "adapter_id": "openai_codex",
                    "flow": "callback",
                    "redirect_uri": "/settings/providers",
                },
                _same_origin(server, **{"Idempotency-Key": "postgres-init"}),
            ),
        )
        assert initiated.status == 202
        completed = _complete_connection(server, cookie, initiated.body["state"])
        connection_id = _assert_completed_connection(completed)
        _assert_created_connection(connection_id)

        selected = _request(
            server,
            cookie,
            _RequestSpec(
                "POST",
                f"/api/v1/provider-connections/{connection_id}/model",
                {"model_id": "codex-mini"},
                _same_origin(
                    server, **{"If-Match": str(completed.body["revision"])}
                ),
            ),
        )
        assert selected.status == 200
        stale = _request(
            server,
            cookie,
            _RequestSpec(
                "POST",
                f"/api/v1/provider-connections/{connection_id}/model",
                {"model_id": "codex-max"},
                _same_origin(
                    server, **{"If-Match": str(completed.body["revision"])}
                ),
            ),
        )
        assert stale.status == 409
        unqualified_health = _request(
            server,
            cookie,
            _RequestSpec(
                "POST",
                f"/api/v1/provider-connections/{connection_id}/health",
                {},
                _same_origin(
                    server, **{"If-Match": str(selected.body["revision"])}
                ),
            ),
        )
        assert unqualified_health.status == 409
        unqualified = _connection_row()
        assert unqualified["selected_model"] == "codex-mini"
        assert unqualified["status"] == "pending"
        assert unqualified["qualified_at"] is False
        assert unqualified["health_checked_at"] is True

        revoked = _request(
            server,
            cookie,
            _RequestSpec(
                "DELETE",
                f"/api/v1/provider-connections/{connection_id}",
                headers=_same_origin(
                    server, **{"If-Match": str(selected.body["revision"])}
                ),
            ),
        )
        assert revoked.status == 200
        receipt = runtime.cleanup_receipt(
            ProviderPrincipal(USER_A, ORG_A), connection_id
        )
        assert receipt.evidence_sha256 == _SHA256_EVIDENCE
        assert receipt.destroyed_at >= receipt.requested_at
        cleanup = revoked.body["cleanup_receipt"]
        assert isinstance(cleanup, dict)
        assert cleanup["redacted"] is True
        assert "vault" not in json.dumps(cleanup)
        assert "token" not in json.dumps(cleanup)
        assert destroyer.refs == ["vault://runtime/connection/postgres"]

        deleted = _connection_row()
        metadata = deleted["account_metadata"]
        assert isinstance(metadata, dict)
        assert deleted["selected_model"] is None
        assert deleted["status"] == "revoked"
        assert deleted["revoked_at"] is True
        assert deleted["runtime_ref"] == f"vault://runtime/destroyed/{connection_id}"
        assert metadata["cleanup_status"] == "completed"
        assert metadata["evidence_sha256"] == _SHA256_EVIDENCE
        revision = selected.body["revision"]
        assert isinstance(revision, str)
        assert metadata["revision"] == str(int(revision) + 1)
    finally:
        server.shutdown()
        server.server_close()
