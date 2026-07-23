"""Loopback contract coverage for G003 identity and tenant boundaries.

Postgres row-level-security proof remains canonical at ``make test-rls``; these
HTTP tests intentionally exercise only the in-process product-server boundary.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import timedelta
from http.client import HTTPConnection
from socket import AF_INET, AF_INET6
from typing import cast

import pytest
from services.api.product_app import (
    Principal,
    ProductServer,
    ProductServerOptions,
    run_product_server,
)
from services.api.product_artifacts import ProductArtifactService
from services.api.product_dry_lab import ProductDryLabService
from services.api.product_tenancy import (
    InMemoryTenantRepository,
    ProjectView,
    SessionView,
)

from .fixtures import (
    ARCHIVED_SESSION_ID,
    FIXTURE_NOW,
    FOREIGN_PROJECT_ID,
    FOREIGN_SESSION_ID,
    PRIMARY_PROJECT_ID,
    PRIMARY_SESSION_ID,
    MutableClock,
)

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
_UNSUPPORTED_ADDRESS = "unsupported address family"
AUTH_PRINCIPAL = Principal(
    "user-mineral",
    "org-mineral",
    "researcher@example.test",
    "Nipo Labs",
)


def _research_intent() -> JsonObject:
    return {
        "question": "보정된 관측값을 재현 가능하게 정규화할 수 있는가?",
        "rationale": "반복 분석에서 입력 순서가 결과를 바꾸지 않도록 확인한다.",
        "intended_benefit": "검증 가능한 정규화 기준선을 만든다.",
        "success_criteria": ["동일 입력은 동일 체크섬을 만든다."],
        "constraints": ["비임상 연구 데이터만 사용한다."],
        "stop_conditions": ["보정 메타데이터가 없으면 중단한다."],
        "research_mode": "copilot",
        "data_origin": "observed",
    }


def _local_run_request(session_id: str = PRIMARY_SESSION_ID) -> JsonObject:
    return {
        "execution_mode": "local_dry_lab",
        "session_id": session_id,
        "prompt": "보정값을 정규화하고 근거를 검토한다.",
        "research_intent": _research_intent(),
        "input": {
            "filename": "calibrated.csv",
            "media_type": "text/csv",
            "content": "sample,value,calibration\na,1.0,cal-1\n",
        },
    }


def _server_host_port(server: ProductServer) -> tuple[str, int]:
    address = server.server_address
    if server.address_family == AF_INET:
        return cast("tuple[str, int]", address)
    if server.address_family == AF_INET6:
        host, port, _, _ = cast("tuple[str, int, int, int]", address)
        return host, port
    raise ValueError(_UNSUPPORTED_ADDRESS)


@dataclass(frozen=True, slots=True)
class Response:
    """Fully buffered loopback HTTP response."""

    status: int
    body: bytes
    headers: tuple[tuple[str, str], ...]

    def getheader(self, name: str) -> str | None:
        """Return the first matching response header."""
        return next((value for key, value in self.headers if key == name), None)

    def getheaders(self) -> tuple[tuple[str, str], ...]:
        """Return all response headers."""
        return self.headers

    def read(self) -> bytes:
        """Return buffered body bytes."""
        return self.body


def _request(
    server: ProductServer,
    method: str,
    path: str,
    *,
    body: JsonObject | None = None,
    headers: dict[str, str] | None = None,
) -> Response:
    connection = HTTPConnection(*_server_host_port(server))
    try:
        encoded = json.dumps(body).encode() if body is not None else None
        request_headers = headers or {}
        if encoded is not None:
            request_headers = {**request_headers, "Content-Type": "application/json"}
        connection.request(method, path, encoded, request_headers)
        response = connection.getresponse()
        return Response(response.status, response.read(), tuple(response.getheaders()))
    finally:
        connection.close()


def _request_with_header_pairs(
    server: ProductServer,
    path: str,
    body: JsonObject,
    headers: tuple[tuple[str, str], ...],
) -> Response:
    """Send duplicate-capable raw headers through the real loopback server."""
    connection = HTTPConnection(*_server_host_port(server))
    encoded = json.dumps(body).encode()
    try:
        connection.putrequest("POST", path, skip_host=True)
        for name, value in headers:
            connection.putheader(name, value)
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", str(len(encoded)))
        connection.endheaders(encoded)
        response = connection.getresponse()
        return Response(response.status, response.read(), tuple(response.getheaders()))
    finally:
        connection.close()


def _same_origin_headers(server: ProductServer, cookie: str = "") -> dict[str, str]:
    host, port = _server_host_port(server)
    return {
        "Cookie": cookie,
        "Origin": f"http://{host}:{port}",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
    }


def test_magic_link_exchange_rotation_replay_and_logout() -> None:
    """The one-use intent-bound exchange rotates into a revocable session."""
    clock = MutableClock(FIXTURE_NOW)
    server = run_product_server(
        clock=clock, options=ProductServerOptions(principal=AUTH_PRINCIPAL)
    )
    try:
        first = _request(
            server,
            "POST",
            "/api/v1/auth/magic-link",
            body={"email": "researcher@example.test"},
            headers=_same_origin_headers(server),
        )
        valid_set_cookie = first.getheader("Set-Cookie")
        assert valid_set_cookie is not None
        intent_cookie, cookie_attributes = valid_set_cookie.split(";", 1)
        token = server.store.delivered_token()
        assert token is not None

        second = _request(
            server,
            "POST",
            "/api/v1/auth/magic-link",
            body={"email": "missing@test"},
            headers=_same_origin_headers(server),
        )
        unknown_set_cookie = second.getheader("Set-Cookie")
        assert unknown_set_cookie is not None
        unknown_intent_cookie, unknown_cookie_attributes = unknown_set_cookie.split(
            ";", 1
        )
        assert first.status == second.status == 202
        assert first.read() == second.read()
        assert cookie_attributes == unknown_cookie_attributes
        assert intent_cookie != unknown_intent_cookie
        assert server.store.delivered_token() == token

        exchange = _request(
            server,
            "POST",
            "/api/v1/auth/exchange",
            body={"token": token},
            headers=_same_origin_headers(server, intent_cookie),
        )
        assert exchange.status == 200
        cookies = exchange.getheaders()
        session_cookie = next(
            value.split(";", 1)[0]
            for key, value in cookies
            if key == "Set-Cookie" and value.startswith("product_session=")
        )
        csrf_cookie = next(
            value.split(";", 1)[0]
            for key, value in cookies
            if key == "Set-Cookie" and value.startswith("product_csrf=")
        )
        browser_cookies = f"{session_cookie}; {csrf_cookie}"
        assert "HttpOnly" in next(
            value
            for key, value in cookies
            if key == "Set-Cookie" and value.startswith("product_session=")
        )
        assert "SameSite=Lax" in next(
            value
            for key, value in cookies
            if key == "Set-Cookie" and value.startswith("product_csrf=")
        )
        assert token not in exchange.read().decode()

        identity = _request(
            server, "GET", "/api/v1/me", headers={"Cookie": browser_cookies}
        )
        identity_payload = cast("JsonObject", json.loads(identity.read()))
        csrf_token = identity_payload["csrf_token"]
        assert identity.status == 200
        assert isinstance(csrf_token, str)
        organization = cast("JsonObject", identity_payload["organization"])
        assert organization["name"] == "Nipo Labs"
        replay = _request(
            server,
            "POST",
            "/api/v1/auth/exchange",
            body={"token": token},
            headers=_same_origin_headers(server, intent_cookie),
        )
        assert replay.status == 400
        logout = _request(
            server,
            "POST",
            "/api/v1/auth/logout",
            headers={
                **_same_origin_headers(server, browser_cookies),
                "X-CSRF-Token": csrf_token,
            },
        )
        assert logout.status == 204
        assert (
            _request(
                server, "GET", "/api/v1/me", headers={"Cookie": browser_cookies}
            ).status
            == 401
        )
    finally:
        server.shutdown()
        server.server_close()


def test_unknown_magic_link_does_not_create_delivery() -> None:
    """An enumeration-safe unknown request has no test-only link delivery."""
    server = run_product_server()
    try:
        response = _request(
            server,
            "POST",
            "/api/v1/auth/magic-link",
            body={"email": "missing@test"},
            headers=_same_origin_headers(server),
        )
        assert response.status == 202
        assert response.read() == b'{"status":"ok"}'
        assert server.store.delivered_token() is None
    finally:
        server.shutdown()
        server.server_close()


def test_magic_link_rejects_cross_origin_without_delivery() -> None:
    """Cross-origin requests cannot initiate a token-delivery side effect."""
    server = run_product_server()
    try:
        response = _request(
            server,
            "POST",
            "/api/v1/auth/magic-link",
            body={"email": "researcher@example.test"},
            headers={
                "Origin": "https://attacker.test",
                "Sec-Fetch-Site": "cross-site",
            },
        )
        assert (response.status, response.read()) == (
            403,
            b'{"error":"invalid_origin"}',
        )
        assert server.store.delivered_token() is None
    finally:
        server.shutdown()
        server.server_close()


def test_mutation_authority_cannot_be_forged_from_host_header() -> None:
    """Derive trusted authority from server configuration, never request Host."""
    server = run_product_server()
    try:
        response = _request(
            server,
            "POST",
            "/api/v1/auth/magic-link",
            body={"email": "researcher@example.test"},
            headers={
                "Host": "attacker.test",
                "Origin": "http://attacker.test",
                "Sec-Fetch-Site": "same-origin",
                "Sec-Fetch-Mode": "cors",
            },
        )
        assert (response.status, response.read()) == (
            403,
            b'{"error":"invalid_origin"}',
        )
        assert server.store.delivered_token() is None
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("duplicate", ["origin", "host"])
def test_mutation_rejects_duplicate_default_authority_headers(duplicate: str) -> None:
    """Reject ambiguous security headers even when their first value is exact."""
    server = run_product_server()
    host, port = _server_host_port(server)
    authority = f"{host}:{port}"
    headers: tuple[tuple[str, str], ...] = (
        ("Host", authority),
        ("Origin", f"http://{authority}"),
        ("Sec-Fetch-Site", "same-origin"),
        ("Sec-Fetch-Mode", "cors"),
    )
    duplicate_value = (
        ("Origin", "https://attacker.test")
        if duplicate == "origin"
        else ("Host", "attacker.test")
    )
    try:
        response = _request_with_header_pairs(
            server,
            "/api/v1/auth/magic-link",
            {"email": "researcher@example.test"},
            (*headers, duplicate_value),
        )
        assert response.status == 403
        assert server.store.delivered_token() is None
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    "headers",
    [
        (("Host", "product.example.test"),),
        (
            ("Host", "product.example.test"),
            ("Origin", "https://product.example.test"),
            ("Origin", "https://attacker.test"),
        ),
        (
            ("Host", "product.example.test"),
            ("Host", "attacker.test"),
            ("Origin", "https://product.example.test"),
        ),
        (
            ("Host", "product.example.test"),
            ("Origin", "http://product.example.test"),
        ),
        (
            ("Host", "product.example.test"),
            ("Origin", "https://product.example.test@attacker.test"),
        ),
        (
            ("Host", "product.example.test"),
            ("Origin", "https://product.example.test:444"),
        ),
        (
            ("Host", "product.example.test"),
            ("Origin", "https://product.example.test/path"),
        ),
        (
            ("Host", "product.example.test"),
            ("Origin", "not-an-origin"),
        ),
        (
            ("Host", "attacker.test"),
            ("Origin", "https://product.example.test"),
        ),
        (
            ("Host", "attacker.test"),
            ("Origin", "https://attacker.test"),
        ),
    ],
    ids=(
        "missing-origin",
        "duplicate-origin",
        "duplicate-host",
        "wrong-scheme",
        "userinfo",
        "wrong-port",
        "path",
        "malformed",
        "wrong-host",
        "forged-pair",
    ),
)
def test_mutation_rejects_every_noncanonical_origin_and_authority(
    headers: tuple[tuple[str, str], ...],
) -> None:
    """Accept only one exact configured Origin and Host authority."""
    server = run_product_server(
        options=ProductServerOptions(
            principal=AUTH_PRINCIPAL,
            public_origin="https://product.example.test",
        )
    )
    try:
        response = _request_with_header_pairs(
            server,
            "/api/v1/auth/magic-link",
            {"email": "researcher@example.test"},
            (*headers, ("Sec-Fetch-Site", "same-origin"), ("Sec-Fetch-Mode", "cors")),
        )
        assert (response.status, response.read()) == (
            403,
            b'{"error":"invalid_origin"}',
        )
        assert server.store.delivered_token() is None
    finally:
        server.shutdown()
        server.server_close()


def test_mutation_accepts_the_exact_configured_origin_and_authority() -> None:
    """Allow the configured public origin while the socket remains loopback."""
    server = run_product_server(
        options=ProductServerOptions(
            principal=AUTH_PRINCIPAL,
            public_origin="https://product.example.test",
        )
    )
    try:
        response = _request_with_header_pairs(
            server,
            "/api/v1/auth/magic-link",
            {"email": "researcher@example.test"},
            (
                ("Host", "product.example.test"),
                ("Origin", "https://product.example.test"),
                ("Sec-Fetch-Site", "same-origin"),
                ("Sec-Fetch-Mode", "cors"),
            ),
        )
        assert response.status == 202
        assert server.store.delivered_token() is not None
    finally:
        server.shutdown()
        server.server_close()


def test_production_session_cookie_and_csrf_are_bound_to_the_session() -> None:
    """Production cookies and authenticated mutations implement the auth contract."""
    server = run_product_server(
        authenticated_fixture=True,
        options=ProductServerOptions(
            principal=AUTH_PRINCIPAL,
            dry_lab=ProductDryLabService(ProductArtifactService),
            repository=InMemoryTenantRepository(
                (
                    (
                        "org-mineral",
                        ProjectView(
                            PRIMARY_PROJECT_ID,
                            "스펙트럼 보정 실험",
                            archived=False,
                        ),
                    ),
                ),
                (
                    (
                        "org-mineral",
                        SessionView(
                            PRIMARY_SESSION_ID, PRIMARY_PROJECT_ID, "보정 세션"
                        ),
                    ),
                ),
            ),
            public_origin="https://product.example.test",
        )
    )
    mutation_headers = {
        "Host": "product.example.test",
        "Origin": "https://product.example.test",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
    }
    try:
        requested = _request(
            server,
            "POST",
            "/api/v1/auth/magic-link",
            body={"email": "researcher@example.test"},
            headers=mutation_headers,
        )
        intent_header = requested.getheader("Set-Cookie")
        token = server.store.delivered_token()
        assert requested.status == 202
        assert intent_header is not None
        assert token is not None

        exchanged = _request(
            server,
            "POST",
            "/api/v1/auth/exchange",
            body={"token": token},
            headers={
                **mutation_headers,
                "Cookie": intent_header.split(";", maxsplit=1)[0],
            },
        )
        session_header = next(
            value
            for key, value in exchanged.getheaders()
            if key == "Set-Cookie" and value.startswith("__Host-swb_session=")
        )
        session_cookie = session_header.split(";", maxsplit=1)[0]
        csrf_header = next(
            value
            for key, value in exchanged.getheaders()
            if key == "Set-Cookie" and value.startswith("__Host-swb_csrf=")
        )
        csrf_cookie = csrf_header.split(";", maxsplit=1)[0]
        browser_cookies = f"{session_cookie}; {csrf_cookie}"
        assert exchanged.status == 200
        assert "Path=/" in session_header
        assert "Secure" in session_header
        assert "HttpOnly" in session_header
        assert "SameSite=Lax" in session_header
        assert "Domain=" not in session_header
        assert "Path=/" in csrf_header
        assert "Secure" in csrf_header
        assert "HttpOnly" not in csrf_header
        assert "SameSite=Lax" in csrf_header
        assert "Domain=" not in csrf_header

        identity = _request(
            server,
            "GET",
            "/api/v1/me",
            headers={"Cookie": browser_cookies},
        )
        csrf_token = cast("dict[str, object]", json.loads(identity.read())).get(
            "csrf_token"
        )
        assert identity.status == 200
        assert isinstance(csrf_token, str)
        assert csrf_token

        missing = _request(
            server,
            "POST",
            "/api/v1/runs",
            body=_local_run_request(),
            headers={**mutation_headers, "Cookie": browser_cookies},
        )
        wrong = _request(
            server,
            "POST",
            "/api/v1/runs",
            body=_local_run_request(),
            headers={
                **mutation_headers,
                "Cookie": browser_cookies,
                "X-CSRF-Token": "wrong-session-token",
            },
        )
        accepted = _request(
            server,
            "POST",
            "/api/v1/runs",
            body=_local_run_request(),
            headers={
                **mutation_headers,
                "Cookie": browser_cookies,
                "X-CSRF-Token": csrf_token,
            },
        )
        assert missing.status == wrong.status == 403
        assert accepted.status == 201
        accepted_body = cast("dict[str, object]", json.loads(accepted.read()))
        assert accepted_body["research_intent_sha256"]

        bypass = _request(
            server,
            "POST",
            f"/api/v1/sessions/{PRIMARY_SESSION_ID}/runs",
            body={"research_intent": _research_intent()},
            headers={
                **mutation_headers,
                "Cookie": browser_cookies,
                "X-CSRF-Token": csrf_token,
            },
        )
        assert bypass.status == 404

        invalid_body = _local_run_request()
        del invalid_body["research_intent"]
        invalid_intent = _request(
            server,
            "POST",
            "/api/v1/runs",
            body=invalid_body,
            headers={
                **mutation_headers,
                "Cookie": browser_cookies,
                "X-CSRF-Token": csrf_token,
            },
        )
        assert invalid_intent.status == 400
        assert invalid_intent.read() == b'{"error":"invalid_request"}'
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize("ambiguous_header", ["duplicate-length", "transfer-encoding"])
def test_json_mutations_reject_ambiguous_body_framing(
    ambiguous_header: str,
) -> None:
    """Request framing ambiguity is rejected before parsing or side effects."""
    server = run_product_server()
    host, port = _server_host_port(server)
    authority = f"{host}:{port}"
    body: JsonObject = {"email": "researcher@example.test"}
    encoded_length = len(json.dumps(body).encode())
    extra = (
        ("Content-Length", str(encoded_length))
        if ambiguous_header == "duplicate-length"
        else ("Transfer-Encoding", "chunked")
    )
    try:
        response = _request_with_header_pairs(
            server,
            "/api/v1/auth/magic-link",
            body,
            (
                ("Host", authority),
                ("Origin", f"http://{authority}"),
                ("Sec-Fetch-Site", "same-origin"),
                ("Sec-Fetch-Mode", "cors"),
                extra,
            ),
        )
        assert response.status == 400
        assert server.store.delivered_token() is None
    finally:
        server.shutdown()
        server.server_close()


def test_json_mutations_reject_oversized_bodies_before_side_effects() -> None:
    """The HTTP boundary rejects a body above its explicit one-megabyte budget."""
    server = run_product_server()
    host, port = _server_host_port(server)
    authority = f"{host}:{port}"
    connection = HTTPConnection(host, port)
    try:
        connection.putrequest("POST", "/api/v1/auth/magic-link", skip_host=True)
        connection.putheader("Host", authority)
        connection.putheader("Origin", f"http://{authority}")
        connection.putheader("Sec-Fetch-Site", "same-origin")
        connection.putheader("Sec-Fetch-Mode", "cors")
        connection.putheader("Content-Type", "application/json")
        connection.putheader("Content-Length", "1000001")
        connection.endheaders()
        raw_response = connection.getresponse()
        response = Response(
            raw_response.status,
            raw_response.read(),
            tuple(raw_response.getheaders()),
        )
        assert response.status == 413
        assert server.store.delivered_token() is None
    finally:
        connection.close()
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    "public_origin",
    [
        "",
        "product.example.test",
        "ftp://product.example.test",
        "https://user@product.example.test",
        "https://product.example.test/path",
        "https://product.example.test?query=yes",
        "https://product.example.test#fragment",
        "https://product.example.test:443",
        "https://product.example.test:not-a-port",
    ],
)
def test_public_origin_configuration_rejects_noncanonical_values(
    public_origin: str,
) -> None:
    """Fail startup before binding when deployment authority is ambiguous."""
    with pytest.raises(
        ValueError, match=r"^public_origin must be a canonical HTTP\(S\) origin$"
    ):
        _ = run_product_server(
            options=ProductServerOptions(public_origin=public_origin)
        )


def test_auth_rejects_expired_wrong_intent_and_cross_origin_exchange() -> None:
    """Exchange failures are stable and require same-origin mutation metadata."""
    clock = MutableClock(FIXTURE_NOW)
    server = run_product_server(
        clock=clock, options=ProductServerOptions(principal=AUTH_PRINCIPAL)
    )
    try:
        _ = _request(
            server,
            "POST",
            "/api/v1/auth/magic-link",
            body={"email": "researcher@example.test"},
            headers=_same_origin_headers(server),
        )
        token = server.store.delivered_token()
        assert token is not None
        clock.now += timedelta(minutes=16)
        expired = _request(
            server,
            "POST",
            "/api/v1/auth/exchange",
            body={"token": token},
            headers=_same_origin_headers(server, "product_intent=wrong"),
        )
        assert expired.status == 400
        assert expired.read() == b'{"error":"invalid_request"}'
        forbidden = _request(
            server,
            "POST",
            "/api/v1/auth/exchange",
            body={"token": token},
            headers={"Origin": "https://attacker.test", "Sec-Fetch-Site": "cross-site"},
        )
        assert forbidden.status == 403
    finally:
        server.shutdown()
        server.server_close()


def test_tenant_resources_hide_foreign_and_archived_parents() -> None:
    """Tenant IDs come from the session, never request input; unknown is indistinguishable."""
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    try:
        assert (
            _request(
                server,
                "GET",
                f"/api/v1/projects/{PRIMARY_PROJECT_ID}",
                headers={"Cookie": cookie},
            ).status
            == 200
        )
        workspace = _request(
            server, "GET", "/api/v1/workspace", headers={"Cookie": cookie}
        )
        workspace_body = cast("dict[str, object]", json.loads(workspace.read()))
        sessions = cast("list[dict[str, object]]", workspace_body["sessions"])
        assert [session["id"] for session in sessions] == [PRIMARY_SESSION_ID]
        foreign = _request(
            server,
            "GET",
            f"/api/v1/projects/{FOREIGN_PROJECT_ID}",
            headers={"Cookie": cookie},
        )
        missing = _request(
            server,
            "GET",
            "/api/v1/projects/no-such-project",
            headers={"Cookie": cookie},
        )
        assert (
            (foreign.status, foreign.read())
            == (missing.status, missing.read())
            == (404, b'{"error":"not_found"}')
        )
        assert (
            _request(
                server,
                "GET",
                f"/api/v1/sessions/{FOREIGN_SESSION_ID}",
                headers={"Cookie": cookie},
            ).status
            == 404
        )
        assert (
            _request(
                server,
                "GET",
                f"/api/v1/sessions/{PRIMARY_SESSION_ID}",
                headers={"Cookie": cookie},
            ).status
            == 200
        )
        rejected = _request(
            server,
            "POST",
            "/api/v1/runs",
            body=_local_run_request(ARCHIVED_SESSION_ID),
            headers={
                **_same_origin_headers(server, cookie),
                "X-CSRF-Token": server.fixture_csrf_token(),
            },
        )
        assert rejected.status == 404
    finally:
        server.shutdown()
        server.server_close()


def test_product_shell_serves_namespaced_static_assets() -> None:
    """Browser-declared product assets resolve from their namespaced URLs."""
    server = run_product_server(authenticated_fixture=True)
    try:
        shell = _request(server, "GET", "/workspace")
        stylesheet = _request(server, "GET", "/product/styles.css")
        artifacts = _request(server, "GET", "/artifacts")
        script = _request(server, "GET", "/product/app.js")
        favicon = _request(server, "GET", "/product/favicon.svg")

        assert (
            shell.status
            == artifacts.status
            == stylesheet.status
            == script.status
            == favicon.status
            == 200
        )
        assert stylesheet.getheader("Content-Type") == "text/css; charset=utf-8"
        assert script.getheader("Content-Type") == "text/javascript; charset=utf-8"
        assert favicon.getheader("Content-Type") == "image/svg+xml"
        assert shell.getheader("Content-Security-Policy") == (
            "default-src 'none'; base-uri 'none'; connect-src 'self'; "
            "frame-ancestors 'none'; frame-src 'self' blob:; "
            "img-src 'self' blob: data:; object-src 'none'; "
            "script-src 'self'; style-src 'self'; form-action 'self'"
        )
        assert shell.getheader("Referrer-Policy") == "no-referrer"
        assert shell.getheader("X-Content-Type-Options") == "nosniff"
        assert b".app-shell" in stylesheet.read()
        assert b"/api/v1/me" in script.read()
    finally:
        server.shutdown()
        server.server_close()


def test_product_shell_injects_the_fixture_provider_authorization_policy() -> None:
    server = run_product_server(authenticated_fixture=True)
    try:
        shell = _request(server, "GET", "/workspace").read().decode()
        script = _request(server, "GET", "/product/app.js").read().decode()

        assert "__PRODUCT_PROVIDER_AUTHORIZATION_POLICY__" not in shell
        assert (
            'content="{&quot;openai_codex&quot;:'
            '&quot;https://provider.example.test/authorize&quot;}"' in shell
        )
        assert "https://provider.example.test/authorize" not in script
    finally:
        server.shutdown()
        server.server_close()


def test_product_shell_injects_the_deployment_provider_authorization_policy() -> (
    None
):
    endpoint = "https://identity.research.example/oauth/authorize"
    server = run_product_server(
        options=ProductServerOptions(
            provider_authorization_endpoints=(("openai_codex", endpoint),)
        )
    )
    try:
        shell = _request(server, "GET", "/settings/providers").read().decode()

        assert "__PRODUCT_PROVIDER_AUTHORIZATION_POLICY__" not in shell
        assert (
            'content="{&quot;openai_codex&quot;:'
            f'&quot;{endpoint}&quot;}}"' in shell
        )
        assert "provider.example.test" not in shell
    finally:
        server.shutdown()
        server.server_close()
