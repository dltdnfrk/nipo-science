"""Authenticated same-origin HTTP coverage for the G003 dry-lab product flow."""

from __future__ import annotations

import json
from dataclasses import dataclass
from http.client import HTTPConnection
from socket import AF_INET, AF_INET6
from typing import cast

from services.api.product_app import ProductServer, run_product_server

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
_CSV = "sample,value,calibration\na,1.0,cal-1\nb,2.5,cal-1\n"
_UNSUPPORTED_ADDRESS = "unsupported address family"


@dataclass(frozen=True, slots=True)
class Response:
    """Fully buffered loopback HTTP response."""

    status: int
    body: bytes


def _server_host_port(server: ProductServer) -> tuple[str, int]:
    address = server.server_address
    if server.address_family == AF_INET:
        return cast("tuple[str, int]", address)
    if server.address_family == AF_INET6:
        host, port, _, _ = cast("tuple[str, int, int, int]", address)
        return host, port
    raise ValueError(_UNSUPPORTED_ADDRESS)


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
        return Response(response.status, response.read())
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


def _json(response: Response) -> JsonObject:
    return cast("JsonObject", json.loads(response.body))


def _assert_denied_requests(server: ProductServer, cookie: str) -> None:
    assert _request(server, "GET", "/api/v1/dry-lab/state").status == 401
    denied = _request(
        server,
        "POST",
        "/api/v1/dry-lab/upload",
        body={"filename": "calibrated.csv", "content": _CSV},
        headers={
            "Cookie": cookie,
            "Origin": "https://attacker.test",
            "Sec-Fetch-Site": "cross-site",
        },
    )
    assert (denied.status, denied.body) == (403, b'{"error":"invalid_origin"}')


def _upload(server: ProductServer, headers: dict[str, str]) -> None:
    upload = _request(
        server,
        "POST",
        "/api/v1/dry-lab/upload",
        body={"filename": "calibrated.csv", "content": _CSV, "request": ""},
        headers=headers,
    )
    assert upload.status == 201


def _plan(server: ProductServer, headers: dict[str, str]) -> str:
    plan = _request(
        server,
        "POST",
        "/api/v1/dry-lab/plan",
        body={"lease_id": "fresh"},
        headers=headers,
    )
    plan_digest = _json(plan)["digest"]
    assert plan.status == 201
    assert isinstance(plan_digest, str)
    return plan_digest


def _approve(server: ProductServer, headers: dict[str, str], plan_digest: str) -> str:
    approval = _request(
        server,
        "POST",
        "/api/v1/dry-lab/approve",
        body={"plan_digest": plan_digest},
        headers=headers,
    )
    token = _json(approval)["token"]
    assert approval.status == 202
    assert isinstance(token, str)
    return token


def _execute(server: ProductServer, headers: dict[str, str], token: str) -> None:
    execution = _request(
        server,
        "POST",
        "/api/v1/dry-lab/execute",
        body={"token": token, "request": ""},
        headers=headers,
    )
    execution_body = _json(execution)
    assert execution.status == 200
    assert execution_body["child_succeeded"] is True
    assert len(cast("list[JsonObject]", execution_body["artifacts"])) == 5

def _assert_artifact_library(server: ProductServer, cookie: str) -> None:
    library = _request(
        server,
        "GET",
        "/api/v1/artifacts",
        headers={"Cookie": cookie},
    )
    artifacts = cast("list[JsonObject]", _json(library)["artifacts"])

    assert library.status == 200
    assert len(artifacts) == 5
    assert {
        cast("str", artifact["media_type"]) for artifact in artifacts
    } == {
        "application/json",
        "image/png",
        "text/csv",
        "text/markdown",
    }
    assert all(artifact["sha256"] for artifact in artifacts)

def _review(server: ProductServer, headers: dict[str, str]) -> None:
    review = _request(
        server, "POST", "/api/v1/dry-lab/review", body={}, headers=headers
    )
    review_body = _json(review)
    assert review.status == 201
    assert cast("JsonObject", review_body["review"])["verdict"] == "verified"


def _export(server: ProductServer, headers: dict[str, str]) -> None:
    export = _request(
        server, "POST", "/api/v1/dry-lab/export", body={}, headers=headers
    )
    export_body = _json(export)
    assert export.status == 200
    assert cast("JsonObject", export_body["export"])["manifest_sha256"]


def _cleanup(server: ProductServer, headers: dict[str, str]) -> JsonObject:
    cleanup = _request(
        server, "POST", "/api/v1/dry-lab/cleanup", body={}, headers=headers
    )
    cleanup_body = _json(cleanup)
    assert cleanup.status == 200
    assert cast("JsonObject", cleanup_body["cleanup"])["removed_runtime_data"] is True
    return cleanup_body


def _assert_cleanup_state(
    server: ProductServer, cookie: str, cleanup_body: JsonObject
) -> None:
    state = _request(
        server, "GET", "/api/v1/dry-lab/state", headers={"Cookie": cookie}
    )
    state_body = _json(state)
    assert state.status == 200
    assert state_body["stage"] == "cleanup"
    assert state_body["artifacts"] == cleanup_body["artifacts"]
    assert server.dry_lab.session_count == 1


def _assert_static_routes(server: ProductServer) -> None:
    for path in (
        "/runs/run-123/approval",
        "/runs/run-123",
        "/artifacts/run-123",
        "/reviews/run-123",
        "/exports/run-123",
    ):
        assert _request(server, "GET", path).status == 200
    assert _request(server, "GET", "/runs/run-123/extra").status == 404
    assert _request(server, "GET", "/runs/../approval").status == 404


def _assert_logout_cleanup(
    server: ProductServer, cookie: str, headers: dict[str, str]
) -> None:
    logout = _request(server, "POST", "/api/v1/auth/logout", headers=headers)
    assert logout.status == 204
    assert server.dry_lab.session_count == 0
    assert (
        _request(
            server, "GET", "/api/v1/dry-lab/state", headers={"Cookie": cookie}
        ).status
        == 401
    )


def test_authenticated_same_origin_dry_lab_journey_and_logout_cleanup() -> None:
    """Run the complete session-scoped dry-lab journey through loopback HTTP."""
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        _assert_denied_requests(server, cookie)
        _upload(server, headers)
        plan_digest = _plan(server, headers)
        token = _approve(server, headers, plan_digest)
        _execute(server, headers, token)
        _assert_artifact_library(server, cookie)
        _review(server, headers)
        _export(server, headers)
        cleanup_body = _cleanup(server, headers)
        _assert_cleanup_state(server, cookie, cleanup_body)
        _assert_static_routes(server)
        _assert_logout_cleanup(server, cookie, headers)
    finally:
        server.shutdown()
        server.server_close()
