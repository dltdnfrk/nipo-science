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

from services.api.product_app import ProductServer, run_product_server

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
    server = run_product_server(clock=clock)
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
        unknown_intent_cookie, unknown_cookie_attributes = unknown_set_cookie.split(";", 1)
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
        session_cookie = next(value.split(";", 1)[0] for key, value in cookies if key == "Set-Cookie")
        assert "HttpOnly" in next(value for key, value in cookies if key == "Set-Cookie")
        assert "SameSite=Strict" in next(value for key, value in cookies if key == "Set-Cookie")
        assert token not in exchange.read().decode()

        assert _request(server, "GET", "/api/v1/me", headers={"Cookie": session_cookie}).status == 200
        replay = _request(
            server,
            "POST",
            "/api/v1/auth/exchange",
            body={"token": token},
            headers=_same_origin_headers(server, intent_cookie),
        )
        assert replay.status == 400
        logout = _request(
            server, "POST", "/api/v1/auth/logout", headers=_same_origin_headers(server, session_cookie)
        )
        assert logout.status == 204
        assert _request(server, "GET", "/api/v1/me", headers={"Cookie": session_cookie}).status == 401
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

def test_auth_rejects_expired_wrong_intent_and_cross_origin_exchange() -> None:
    """Exchange failures are stable and require same-origin mutation metadata."""
    clock = MutableClock(FIXTURE_NOW)
    server = run_product_server(clock=clock)
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
        assert _request(server, "GET", f"/api/v1/projects/{PRIMARY_PROJECT_ID}", headers={"Cookie": cookie}).status == 200
        foreign = _request(server, "GET", f"/api/v1/projects/{FOREIGN_PROJECT_ID}", headers={"Cookie": cookie})
        missing = _request(server, "GET", "/api/v1/projects/no-such-project", headers={"Cookie": cookie})
        assert (foreign.status, foreign.read()) == (missing.status, missing.read()) == (404, b'{"error":"not_found"}')
        assert _request(server, "GET", f"/api/v1/sessions/{FOREIGN_SESSION_ID}", headers={"Cookie": cookie}).status == 404
        assert _request(server, "GET", f"/api/v1/sessions/{PRIMARY_SESSION_ID}", headers={"Cookie": cookie}).status == 200
        rejected = _request(
            server,
            "POST",
            f"/api/v1/sessions/{ARCHIVED_SESSION_ID}/runs",
            body={"org_id": "org-foreign"},
            headers=_same_origin_headers(server, cookie),
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

        assert shell.status == artifacts.status == stylesheet.status == script.status == 200
        assert stylesheet.getheader("Content-Type") == "text/css; charset=utf-8"
        assert script.getheader("Content-Type") == "text/javascript; charset=utf-8"
        assert b".app-shell" in stylesheet.read()
        assert b"/api/v1/me" in script.read()
    finally:
        server.shutdown()
        server.server_close()
