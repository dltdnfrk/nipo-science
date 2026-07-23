"""Authenticated same-origin HTTP coverage for the G003 dry-lab product flow."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from socket import AF_INET, AF_INET6
from typing import cast

import pytest
from services.api.product_app import (
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

from .fixtures import FOREIGN_SESSION_ID, PRIMARY_SESSION_ID

type JsonScalar = str | int | float | bool | None
type JsonValue = JsonScalar | list[JsonValue] | dict[str, JsonValue]
type JsonObject = dict[str, JsonValue]
_CSV = "sample,value,calibration\na,1.0,cal-1\nb,2.5,cal-1\n"
_UNSUPPORTED_ADDRESS = "unsupported address family"


def _research_intent() -> JsonObject:
    return {
        "question": "보정된 관측값을 재현 가능하게 정규화할 수 있는가?",
        "rationale": "반복 분석에서 입력 순서가 결과를 바꾸지 않도록 확인한다.",
        "intended_benefit": "검증 가능한 정규화 기준선을 만든다.",
        "success_criteria": ["동일 입력은 동일 체크섬을 만든다."],
        "constraints": ["비임상 연구 데이터만 사용한다."],
        "stop_conditions": ["보정 메타데이터가 없으면 중단한다."],
        "research_mode": "bounded_agentic",
        "data_origin": "observed",
    }


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
    headers = {
        "Cookie": cookie,
        "Origin": f"http://{host}:{port}",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
    }
    if cookie:
        headers["X-CSRF-Token"] = server.fixture_csrf_token()
    return headers


def _json(response: Response) -> JsonObject:
    return cast("JsonObject", json.loads(response.body))


def _assert_denied_requests(server: ProductServer, cookie: str) -> None:
    denied_without_session = _request(
        server,
        "POST",
        "/api/v1/runs",
        body=_run_body(),
        headers=_same_origin_headers(server),
    )
    assert (denied_without_session.status, denied_without_session.body) == (
        401,
        b'{"error":"unauthorized"}',
    )
    denied = _request(
        server,
        "POST",
        "/api/v1/runs",
        body=_run_body(),
        headers={
            "Cookie": cookie,
            "Origin": "https://attacker.test",
            "Sec-Fetch-Site": "cross-site",
        },
    )
    assert (denied.status, denied.body) == (403, b'{"error":"invalid_origin"}')


def _run_body(
    filename: str = "calibrated.csv",
    *,
    research_intent: JsonObject | None = None,
    session_id: str = PRIMARY_SESSION_ID,
) -> JsonObject:
    return {
        "execution_mode": "local_dry_lab",
        "session_id": session_id,
        "prompt": "보정값을 정규화하고 재현성을 검증한다.",
        "research_intent": research_intent or _research_intent(),
        "input": {
            "filename": filename,
            "media_type": "text/csv",
            "content": _CSV,
        },
    }


def _create_run(
    server: ProductServer,
    headers: dict[str, str],
    filename: str = "calibrated.csv",
    *,
    research_intent: JsonObject | None = None,
    session_id: str = PRIMARY_SESSION_ID,
) -> tuple[str, str]:
    created = _request(
        server,
        "POST",
        "/api/v1/runs",
        body=_run_body(
            filename,
            research_intent=research_intent,
            session_id=session_id,
        ),
        headers=headers,
    )
    payload = _json(created)
    run_id = payload["run_id"]
    plan_digest = payload["plan_digest"]
    assert created.status == 201
    assert isinstance(run_id, str)
    assert isinstance(plan_digest, str)
    return run_id, plan_digest


def test_http_run_creation_rejects_missing_or_incomplete_research_intent() -> None:
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        body = _run_body()
        missing = _request(
            server,
            "POST",
            "/api/v1/runs",
            body={
                key: value for key, value in body.items() if key != "research_intent"
            },
            headers=headers,
        )
        incomplete_body: JsonObject = {
            **body,
            "research_intent": {"question": "불완전한 의도"},
        }
        incomplete = _request(
            server,
            "POST",
            "/api/v1/runs",
            body=incomplete_body,
            headers=headers,
        )
        workspace = _request(
            server, "GET", "/api/v1/workspace", headers={"Cookie": cookie}
        )

        assert (missing.status, missing.body) == (400, b'{"error":"invalid_request"}')
        assert (incomplete.status, _json(incomplete)) == (
            400,
            {"code": "research-intent-invalid"},
        )
        assert _json(workspace)["recent_runs"] == []
    finally:
        server.shutdown()
        server.server_close()


def test_all_legacy_dry_lab_routes_return_not_found() -> None:
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        responses = (
            _request(
                server,
                "GET",
                "/api/v1/dry-lab/state",
                headers={"Cookie": cookie},
            ),
            _request(
                server,
                "POST",
                "/api/v1/dry-lab/upload",
                body={"filename": "calibrated.csv", "content": _CSV},
                headers=headers,
            ),
            _request(
                server,
                "POST",
                "/api/v1/dry-lab/plan",
                body={"research_intent": _research_intent()},
                headers=headers,
            ),
            *(
                _request(
                    server,
                    "POST",
                    f"/api/v1/dry-lab/{action}",
                    body={},
                    headers=headers,
                )
                for action in ("approve", "execute", "review", "export", "cleanup")
            ),
        )

        assert all(
            (response.status, response.body) == (404, b'{"error":"not_found"}')
            for response in responses
        )
    finally:
        server.shutdown()
        server.server_close()


def test_canonical_local_run_route_persists_exact_intent_and_resource_links() -> None:
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    body = _run_body()
    try:
        created = _request(
            server,
            "POST",
            "/api/v1/runs",
            body=body,
            headers=headers,
        )
        payload = _json(created)
        run_id = payload["run_id"]

        assert created.status == 201
        assert isinstance(run_id, str)
        assert payload["stage"] == "plan"
        assert payload["research_intent"] == _research_intent() | {
            "synthetic_generator_ref": None,
            "synthetic_validator_ref": None,
        }
        assert payload["research_intent_sha256"]
        assert (
            cast("JsonObject", payload["action_plan"])["digest"]
            == payload["plan_digest"]
        )
        assert {
            cast("str", link["href"])
            for link in cast("list[JsonObject]", payload["links"])
        } == {f"/runs/{run_id}", f"/runs/{run_id}/approval"}

        exact = _request(
            server,
            "GET",
            f"/api/v1/runs/{run_id}",
            headers={"Cookie": cookie},
        )
        assert exact.status == 200
        assert (
            _json(exact)["research_intent_sha256"] == payload["research_intent_sha256"]
        )
        mismatched = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/approve",
            body={"run_id": "another-run", "plan_digest": payload["plan_digest"]},
            headers=headers,
        )
        assert (mismatched.status, mismatched.body) == (
            400,
            b'{"error":"invalid_request"}',
        )

        rejected = _request(
            server,
            "POST",
            "/api/v1/runs",
            body=body | {"session_id": FOREIGN_SESSION_ID},
            headers=headers,
        )
        assert (rejected.status, rejected.body) == (404, b'{"error":"not_found"}')
        malformed = _request(
            server,
            "POST",
            "/api/v1/runs",
            body=body | {"session_id": "session-demo"},
            headers=headers,
        )
        assert (malformed.status, malformed.body) == (
            400,
            b'{"error":"invalid_request"}',
        )
    finally:
        server.shutdown()
        server.server_close()


def _approve(
    server: ProductServer, headers: dict[str, str], run_id: str, plan_digest: str
) -> str:
    approval = _request(
        server,
        "POST",
        f"/api/v1/runs/{run_id}/approve",
        body={"plan_digest": plan_digest},
        headers=headers,
    )
    token = _json(approval)["token"]
    assert approval.status == 202
    assert isinstance(token, str)
    return token


def _execute(
    server: ProductServer, headers: dict[str, str], run_id: str, token: str
) -> None:
    execution = _request(
        server,
        "POST",
        f"/api/v1/runs/{run_id}/execute",
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
    assert {cast("str", artifact["media_type"]) for artifact in artifacts} == {
        "application/json",
        "image/png",
        "text/csv",
        "text/markdown",
    }
    assert all(artifact["sha256"] for artifact in artifacts)


def _review(server: ProductServer, headers: dict[str, str], run_id: str) -> None:
    review = _request(
        server,
        "POST",
        f"/api/v1/runs/{run_id}/review",
        body={},
        headers=headers,
    )
    review_body = _json(review)
    assert review.status == 201
    assert cast("JsonObject", review_body["review"])["verdict"] == "verified"


def _export(server: ProductServer, headers: dict[str, str], run_id: str) -> None:
    export = _request(
        server,
        "POST",
        f"/api/v1/runs/{run_id}/export",
        body={},
        headers=headers,
    )
    export_body = _json(export)
    assert export.status == 200
    assert cast("JsonObject", export_body["export"])["manifest_sha256"]


def _cleanup(server: ProductServer, headers: dict[str, str], run_id: str) -> JsonObject:
    denied = _request(
        server,
        "POST",
        f"/api/v1/runs/{run_id}/cleanup",
        body={},
        headers=headers,
    )
    assert (denied.status, denied.body) == (
        400,
        b'{"code":"cleanup-confirmation-required"}',
    )
    cleanup = _request(
        server,
        "POST",
        f"/api/v1/runs/{run_id}/cleanup",
        body={"confirmed": True},
        headers=headers,
    )
    cleanup_body = _json(cleanup)
    assert cleanup.status == 200
    assert cast("JsonObject", cleanup_body["cleanup"])["removed_runtime_data"] is True
    return cleanup_body


def _assert_cleanup_state(
    server: ProductServer, cookie: str, run_id: str, cleanup_body: JsonObject
) -> None:
    state = _request(
        server, "GET", f"/api/v1/runs/{run_id}", headers={"Cookie": cookie}
    )
    state_body = _json(state)
    assert state.status == 200
    assert state_body["stage"] == "cleanup"
    assert state_body["artifacts"] == cleanup_body["artifacts"]
    dry_lab = server.dry_lab
    assert dry_lab is not None
    assert dry_lab.session_count == 1


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
    server: ProductServer, cookie: str, headers: dict[str, str], run_id: str
) -> None:
    logout = _request(server, "POST", "/api/v1/auth/logout", headers=headers)
    assert logout.status == 204
    dry_lab = server.dry_lab
    assert dry_lab is not None
    assert dry_lab.session_count == 0
    exact = _request(
        server,
        "GET",
        f"/api/v1/runs/{run_id}",
        headers={"Cookie": cookie},
    )
    assert (exact.status, exact.body) == (401, b'{"error":"unauthorized"}')


def test_authenticated_same_origin_dry_lab_journey_and_logout_cleanup() -> None:
    """Run the complete session-scoped dry-lab journey through loopback HTTP."""
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        _assert_denied_requests(server, cookie)
        run_id, plan_digest = _create_run(server, headers)
        token = _approve(server, headers, run_id, plan_digest)
        _execute(server, headers, run_id, token)
        _assert_artifact_library(server, cookie)
        _review(server, headers, run_id)
        _export(server, headers, run_id)
        cleanup_body = _cleanup(server, headers, run_id)
        _assert_cleanup_state(server, cookie, run_id, cleanup_body)
        _assert_static_routes(server)
        _assert_logout_cleanup(server, cookie, headers, run_id)
    finally:
        server.shutdown()
        server.server_close()


def test_exact_reject_and_cancel_routes_are_terminal_without_side_effects() -> None:
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        rejected_id, _ = _create_run(server, headers, "rejected.csv")
        cancelled_id, cancelled_digest = _create_run(
            server, headers, "cancelled.csv"
        )
        rejected = _request(
            server,
            "POST",
            f"/api/v1/runs/{rejected_id}/reject",
            body={},
            headers=headers,
        )
        token = _approve(server, headers, cancelled_id, cancelled_digest)
        cancelled = _request(
            server,
            "POST",
            f"/api/v1/runs/{cancelled_id}/cancel",
            body={},
            headers=headers,
        )

        assert rejected.status == cancelled.status == 200
        assert _json(rejected)["stage"] == "reject"
        assert _json(cancelled)["stage"] == "cancel"
        assert _json(rejected)["artifacts"] == _json(cancelled)["artifacts"] == []
        assert _request(
            server,
            "POST",
            f"/api/v1/runs/{cancelled_id}/execute",
            body={"token": token, "request": ""},
            headers=headers,
        ).status == 409
        assert _request(
            server,
            "POST",
            f"/api/v1/runs/{rejected_id}/reject/extra",
            body={},
            headers=headers,
        ).status == 404
        assert _json(
            _request(server, "GET", "/api/v1/artifacts", headers={"Cookie": cookie})
        ) == {"artifacts": []}
    finally:
        server.shutdown()
        server.server_close()


def test_expired_approval_is_visible_and_fails_closed_over_http() -> None:
    now = [datetime(2026, 7, 16, 2, 0, tzinfo=UTC)]
    server = run_product_server(
        authenticated_fixture=True,
        clock=lambda: now[0],
    )
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        run_id, plan_digest = _create_run(server, headers)
        token = _approve(server, headers, run_id, plan_digest)
        now[0] += timedelta(minutes=10)

        resource = _request(
            server, "GET", f"/api/v1/runs/{run_id}", headers={"Cookie": cookie}
        )
        execution = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/execute",
            body={"token": token, "request": ""},
            headers=headers,
        )
        review = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/review",
            body={},
            headers=headers,
        )

        assert resource.status == 200
        assert _json(resource)["stage"] == "expire"
        assert (execution.status, execution.body) == (
            409,
            b'{"code":"approval-expired"}',
        )
        assert (review.status, review.body) == (409, b'{"code":"invalid-order"}')
        assert _json(
            _request(server, "GET", "/api/v1/artifacts", headers={"Cookie": cookie})
        ) == {"artifacts": []}
    finally:
        server.shutdown()
        server.server_close()


def test_generated_resource_urls_require_exact_id_and_browser_session() -> None:
    """Run, Review, Export, and Artifact URLs never alias singleton state."""
    created_at = datetime(2026, 7, 15, 3, 22, tzinfo=UTC)
    server = run_product_server(authenticated_fixture=True, clock=lambda: created_at)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        run_id, plan_digest = _create_run(server, headers)
        token = _approve(server, headers, run_id, plan_digest)
        execution = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/execute",
            body={"run_id": run_id, "token": token, "request": ""},
            headers=headers,
        )
        execution_body = _json(execution)
        artifact_ids = [
            artifact["artifact_id"]
            for artifact in cast("list[JsonObject]", execution_body["artifacts"])
        ]
        review = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/review",
            body={"run_id": run_id},
            headers=headers,
        )
        export = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/export",
            body={"run_id": run_id},
            headers=headers,
        )
        review_id = _json(review)["review_id"]
        export_id = _json(export)["export_id"]
        workspace = _request(
            server, "GET", "/api/v1/workspace", headers={"Cookie": cookie}
        )
        recent_runs = cast("list[JsonObject]", _json(workspace)["recent_runs"])

        assert isinstance(run_id, str)
        assert isinstance(review_id, str)
        assert isinstance(export_id, str)
        assert all(isinstance(artifact_id, str) for artifact_id in artifact_ids)
        assert workspace.status == 200
        assert recent_runs[0]["id"] == run_id
        assert recent_runs[0]["display_id"] == f"Run {run_id[-8:]}"
        assert recent_runs[0]["created_at"] == "2026-07-15T03:22:00Z"
        exact_run = _request(
            server,
            "GET",
            f"/api/v1/runs/{run_id}",
            headers={"Cookie": cookie},
        )
        assert _json(exact_run)["created_at"] == "2026-07-15T03:22:00Z"
        assert {
            cast("str", link["href"])
            for link in cast("list[JsonObject]", recent_runs[0]["links"])
        } == {
            f"/runs/{run_id}",
            f"/reviews/{review_id}",
            f"/exports/{export_id}",
        }
        resources = [
            ("runs", run_id),
            ("reviews", review_id),
            ("exports", export_id),
            *(("artifacts", cast("str", artifact_id)) for artifact_id in artifact_ids),
        ]
        other_token = server.store.fixture_session_token()
        other_cookie = f"{server.session_cookie_name}={other_token}"
        for kind, resource_id in resources:
            exact = _request(
                server,
                "GET",
                f"/api/v1/{kind}/{resource_id}",
                headers={"Cookie": cookie},
            )
            wrong = _request(
                server,
                "GET",
                f"/api/v1/{kind}/not-{resource_id}",
                headers={"Cookie": cookie},
            )
            other_session = _request(
                server,
                "GET",
                f"/api/v1/{kind}/{resource_id}",
                headers={"Cookie": other_cookie},
            )
            assert exact.status == 200
            assert (wrong.status, other_session.status) == (404, 404)
    finally:
        server.shutdown()
        server.server_close()


def test_product_server_exposes_real_dry_lab_artifact_versions() -> None:
    """Artifact detail, bytes, lineage, and Session links share the dry-lab source."""
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        run_id, plan_digest = _create_run(server, headers)
        token = _approve(server, headers, run_id, plan_digest)
        execution = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/execute",
            body={"run_id": run_id, "token": token, "request": ""},
            headers=headers,
        )
        artifacts = cast("list[JsonObject]", _json(execution)["artifacts"])
        normalized = next(
            artifact for artifact in artifacts if artifact["name"] == "normalized.csv"
        )
        artifact_id = cast("str", normalized["artifact_id"])

        detail_response = _request(
            server,
            "GET",
            f"/api/v1/artifacts/{artifact_id}",
            headers={"Cookie": cookie},
        )
        detail = _json(detail_response)
        selected = cast("JsonObject", detail["selected"])
        version_id = cast("str", selected["id"])
        assert detail_response.status == 200
        assert selected["sha256"] == normalized["sha256"]
        assert selected["producer_execution_id"] == _json(execution)["run_id"]

        download = _request(
            server,
            "GET",
            f"/api/v1/artifacts/{artifact_id}/versions/{version_id}/download",
            headers={"Cookie": cookie},
        )
        assert download.status == 200
        assert hashlib.sha256(download.body).hexdigest() == selected["sha256"]

        attached = _request(
            server,
            "POST",
            f"/api/v1/artifacts/{artifact_id}/versions/{version_id}/attachments",
            body={"session_id": PRIMARY_SESSION_ID},
            headers=headers,
        )
        hidden = _request(
            server,
            "POST",
            f"/api/v1/artifacts/{artifact_id}/versions/{version_id}/attachments",
            body={"session_id": FOREIGN_SESSION_ID},
            headers=headers,
        )
        assert _json(attached)["attached_session_ids"] == [PRIMARY_SESSION_ID]
        assert hidden.status == 404

        created = _request(
            server,
            "POST",
            f"/api/v1/artifacts/{artifact_id}/versions",
            body={
                "base_version_no": 1,
                "name": "normalized.csv",
                "media_type": "text/csv",
                "content": "sample,value,calibration\na,2,cal-1\n",
            },
            headers=headers,
        )
        created_body = _json(created)
        created_selected = cast("JsonObject", created_body["selected"])
        assert created.status == 201
        assert created_selected["version_no"] == 2
        assert created_selected["lineage_version_ids"] == [version_id]
        library = _request(
            server, "GET", "/api/v1/artifacts", headers={"Cookie": cookie}
        )
        latest = next(
            artifact
            for artifact in cast("list[JsonObject]", _json(library)["artifacts"])
            if artifact["artifact_id"] == artifact_id
        )
        assert latest["version_no"] == 2
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    "body",
    [
        {"request": ""},
        {"token": None, "request": ""},
        {"token": "", "request": ""},
        {"token": 7, "request": ""},
        {"token": "not-the-approved-token", "request": ""},
        {"token": "토큰", "request": ""},
    ],
    ids=("omitted", "null", "empty", "non-string", "wrong", "unicode"),
)
def test_http_execute_rejects_malformed_tokens_without_consuming_approval(
    body: JsonObject,
) -> None:
    """Fail closed at the HTTP boundary and leave the valid token usable."""
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        run_id, plan_digest = _create_run(server, headers)
        token = _approve(server, headers, run_id, plan_digest)

        rejected = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/execute",
            body={**body, "run_id": run_id},
            headers=headers,
        )
        state = _request(
            server,
            "GET",
            f"/api/v1/runs/{run_id}",
            headers={"Cookie": cookie},
        )

        assert (rejected.status, _json(rejected)) == (
            409,
            {"code": "approval-token-mismatch"},
        )
        assert _json(state)["artifacts"] == []
        _execute(server, headers, run_id, token)
    finally:
        server.shutdown()
        server.server_close()


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"plan_digest": None},
        {"plan_digest": 7},
        {"plan_digest": ""},
        {"plan_digest": "not-the-current-plan"},
        {"plan_digest": "계획"},
    ],
    ids=("omitted", "null", "non-string", "empty", "wrong", "unicode"),
)
def test_http_approve_requires_the_exact_plan_digest(body: JsonObject) -> None:
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        run_id, plan_digest = _create_run(server, headers)

        rejected = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/approve",
            body={**body, "run_id": run_id},
            headers=headers,
        )
        assert (rejected.status, _json(rejected)) == (
            409,
            {"code": "approval-plan-mismatch"},
        )

        token = _approve(server, headers, run_id, plan_digest)
        _execute(server, headers, run_id, token)
    finally:
        server.shutdown()
        server.server_close()


def test_http_two_runs_reload_exact_resources_and_hide_other_session_ids() -> None:
    server = run_product_server(authenticated_fixture=True)
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        first_run_id, first_digest = _create_run(server, headers, "first.csv")
        second_run_id, second_digest = _create_run(
            server,
            headers,
            "second.csv",
            research_intent=_research_intent()
            | {"question": "두 번째 실행의 리소스도 정확히 다시 읽히는가?"},
        )
        assert first_run_id != second_run_id
        other_token = server.store.fixture_session_token()
        other_cookie = f"{server.session_cookie_name}={other_token}"

        resources: list[tuple[str, str, JsonValue]] = []
        for run_id, expected_digest in (
            (first_run_id, first_digest),
            (second_run_id, second_digest),
        ):
            token = _approve(server, headers, run_id, expected_digest)
            _execute(server, headers, run_id, token)
            review = _request(
                server,
                "POST",
                f"/api/v1/runs/{run_id}/review",
                body={"run_id": run_id},
                headers=headers,
            )
            export = _request(
                server,
                "POST",
                f"/api/v1/runs/{run_id}/export",
                body={"run_id": run_id},
                headers=headers,
            )
            review_id = _json(review)["review_id"]
            export_id = _json(export)["export_id"]
            assert isinstance(review_id, str)
            assert isinstance(export_id, str)
            resources.extend(
                (
                    ("runs", run_id, expected_digest),
                    ("reviews", review_id, expected_digest),
                    ("exports", export_id, expected_digest),
                )
            )

        for kind, resource_id, expected_digest in resources:
            exact = _request(
                server,
                "GET",
                f"/api/v1/{kind}/{resource_id}",
                headers={"Cookie": cookie},
            )
            unknown = _request(
                server,
                "GET",
                f"/api/v1/{kind}/unknown-{resource_id}",
                headers={"Cookie": cookie},
            )
            other = _request(
                server,
                "GET",
                f"/api/v1/{kind}/{resource_id}",
                headers={"Cookie": other_cookie},
            )
            assert exact.status == 200
            assert _json(exact)["plan_digest"] == expected_digest
            assert (unknown.status, unknown.body) == (404, b'{"error":"not_found"}')
            assert (other.status, other.body) == (404, b'{"error":"not_found"}')
    finally:
        server.shutdown()
        server.server_close()


def test_product_server_does_not_create_demo_resources_without_dependencies() -> None:
    server = run_product_server(options=ProductServerOptions())
    try:
        magic_link = _request(
            server,
            "POST",
            "/api/v1/auth/magic-link",
            body={"email": "researcher@example.test"},
            headers=_same_origin_headers(server),
        )
        workspace = _request(server, "GET", "/api/v1/workspace")

        assert magic_link.status == 202
        assert server.store.delivered_token() is None
        assert (workspace.status, workspace.body) == (401, b'{"error":"unauthorized"}')
        with pytest.raises(RuntimeError, match=r"^fixture session is unavailable$"):
            _ = server.fixture_session_cookie()
        assert server.dry_lab is None
    finally:
        server.shutdown()
        server.server_close()


def test_product_server_rejects_fixture_dry_lab_without_explicit_fixture_mode() -> None:
    with pytest.raises(
        ValueError, match=r"^ProductDryLabService requires authenticated_fixture$"
    ):
        _ = run_product_server(
            options=ProductServerOptions(
                dry_lab=ProductDryLabService(ProductArtifactService)
            )
        )


def test_artifact_attachment_uses_only_the_injected_session_repository() -> None:
    repository = InMemoryTenantRepository(
        (
            (
                "org-mineral",
                ProjectView("project-owned", "소유 프로젝트", archived=False),
            ),
        ),
        (
            (
                "org-mineral",
                SessionView(PRIMARY_SESSION_ID, "project-owned", "소유 세션"),
            ),
        ),
    )
    server = run_product_server(
        authenticated_fixture=True,
        options=ProductServerOptions(
            repository=repository,
            dry_lab=ProductDryLabService(ProductArtifactService),
        ),
    )
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    try:
        run_id, plan_digest = _create_run(server, headers)
        token = _approve(server, headers, run_id, plan_digest)
        execution = _request(
            server,
            "POST",
            f"/api/v1/runs/{run_id}/execute",
            body={"run_id": run_id, "token": token, "request": ""},
            headers=headers,
        )
        artifact = cast("list[JsonObject]", _json(execution)["artifacts"])[0]
        artifact_id = cast("str", artifact["artifact_id"])
        detail = _request(
            server,
            "GET",
            f"/api/v1/artifacts/{artifact_id}",
            headers={"Cookie": cookie},
        )
        version_id = cast("str", cast("JsonObject", _json(detail)["selected"])["id"])

        attached = _request(
            server,
            "POST",
            f"/api/v1/artifacts/{artifact_id}/versions/{version_id}/attachments",
            body={"session_id": PRIMARY_SESSION_ID},
            headers=headers,
        )
        implicit_demo = _request(
            server,
            "POST",
            f"/api/v1/artifacts/{artifact_id}/versions/{version_id}/attachments",
            body={"session_id": FOREIGN_SESSION_ID},
            headers=headers,
        )

        assert attached.status == 200
        assert _json(attached)["attached_session_ids"] == [PRIMARY_SESSION_ID]
        assert (implicit_demo.status, implicit_demo.body) == (
            404,
            b'{"error":"not_found"}',
        )
    finally:
        server.shutdown()
        server.server_close()
