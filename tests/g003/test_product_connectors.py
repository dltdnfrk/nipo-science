"""Data-source connector settings, collection plans, and HTTP coverage."""

from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from socket import AF_INET, AF_INET6
from typing import TYPE_CHECKING, cast

import pytest
from services.api.product_app import (
    ProductServer,
    ProductServerOptions,
    run_product_server,
)
from services.api.product_connectors import (
    CollectedDocument,
    CollectionPlanStore,
    ConnectorSettingsError,
    ConnectorSettingsStore,
    parse_collection_prompt,
)

from .fixtures import PRIMARY_SESSION_ID

if TYPE_CHECKING:
    from collections.abc import Callable

type JsonObject = dict[str, object]
type JsonValue = None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
_UNSUPPORTED_ADDRESS = "unsupported address family"


# ---- prompt parsing ---------------------------------------------------------


def test_parse_extracts_limit_and_strips_noise() -> None:
    hint, query, limit = parse_collection_prompt(
        "knowledge graph extraction 논문 5개 수집해줘"
    )
    assert hint is None
    assert query == "knowledge graph extraction"
    assert limit == 5


def test_parse_honors_source_hint_and_clamps_limit() -> None:
    hint, query, limit = parse_collection_prompt("openalex catalyst 연구 99개")
    assert hint == "openalex"
    assert query == "catalyst 연구"
    assert limit == 25


def test_parse_defaults_limit_and_rejects_empty_query() -> None:
    _hint, _query, limit = parse_collection_prompt("정규화 검증")
    assert limit == 5
    with pytest.raises(ConnectorSettingsError):
        _ = parse_collection_prompt("수집해줘")
    with pytest.raises(ConnectorSettingsError):
        _ = parse_collection_prompt("   ")
    with pytest.raises(ConnectorSettingsError):
        _ = parse_collection_prompt("x" * 501)


def test_parse_ignores_embedded_and_oversized_numbers() -> None:
    _hint, query, limit = parse_collection_prompt("COVID19 변이 분석")
    assert query == "COVID19 변이 분석"
    assert limit == 5

    _hint, query, limit = parse_collection_prompt("정규화 1000000개 수집")
    assert "1000000" in query
    assert limit == 5


def test_parse_honors_standalone_count_tokens() -> None:
    _hint, query, limit = parse_collection_prompt("정규화 연구 3건")
    assert query == "정규화 연구"
    assert limit == 3

    _hint, query, limit = parse_collection_prompt("정규화 5")
    assert query == "정규화"
    assert limit == 5


# ---- settings store ---------------------------------------------------------


def test_settings_defaults_and_roundtrip() -> None:
    store = ConnectorSettingsStore()
    defaults = {item["connector_id"]: item["enabled"] for item in store.list_for("u1")}
    assert defaults == {
        "arxiv": True,
        "openalex": False,
        "pubmed": False,
        "semantic_scholar": False,
        "europe_pmc": False,
        "core": False,
        "crossref": False,
    }

    _ = store.update("u1", "pubmed", enabled=True, key_env="NCBI_API_KEY")
    items = {item["connector_id"]: item for item in store.list_for("u1")}
    assert items["pubmed"]["enabled"] is True
    assert items["pubmed"]["key_env"] == "NCBI_API_KEY"
    # 다른 주체의 상태는 오염되지 않는다
    assert store.is_enabled("u2", "pubmed") is False


def test_settings_fail_closed_on_bad_input() -> None:
    store = ConnectorSettingsStore()
    with pytest.raises(ConnectorSettingsError):
        _ = store.update("u1", "attacker", enabled=True)
    with pytest.raises(ConnectorSettingsError):
        _ = store.update("u1", "pubmed", enabled=True, key_env="lower case name")
    with pytest.raises(ConnectorSettingsError):
        _ = store.update("u1", "arxiv", enabled=True, key_env="NCBI_API_KEY")


# ---- plan store -------------------------------------------------------------


def test_plan_is_one_shot_and_owner_scoped() -> None:
    clock_now = datetime(2026, 7, 25, tzinfo=UTC)
    store = CollectionPlanStore(lambda: clock_now)
    plan = store.create("u1", "arxiv", "정규화", 3)
    with pytest.raises(ConnectorSettingsError):
        _ = store.consume("u2", plan.plan_id)
    assert store.consume("u1", plan.plan_id).query == "정규화"
    with pytest.raises(ConnectorSettingsError):
        _ = store.consume("u1", plan.plan_id)


def test_plan_expires() -> None:
    clock_now = datetime(2026, 7, 25, tzinfo=UTC)
    store = CollectionPlanStore(lambda: clock_now)
    plan = store.create("u1", "arxiv", "정규화", 3)
    clock_now += timedelta(minutes=11)
    with pytest.raises(ConnectorSettingsError):
        _ = store.consume("u1", plan.plan_id)




# ---- HTTP boundary ----------------------------------------------------------


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
) -> tuple[int, bytes]:
    connection = HTTPConnection(*_server_host_port(server))
    try:
        encoded = json.dumps(body).encode() if body is not None else None
        request_headers = dict(headers or {})
        if encoded is not None:
            request_headers["Content-Type"] = "application/json"
        connection.request(method, path, encoded, request_headers)
        response = connection.getresponse()
        return response.status, response.read()
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


@pytest.fixture
def server() -> object:
    instance = run_product_server(("127.0.0.1", 0), authenticated_fixture=True)
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()


def test_connector_endpoints_require_session_and_origin(server: ProductServer) -> None:
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/plan",
        body={"prompt": "정규화"},
        headers=_same_origin_headers(server),
    )
    assert (status, body) == (401, b'{"error":"unauthorized"}')

    cookie = server.fixture_session_cookie()
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/plan",
        body={"prompt": "정규화"},
        headers={
            "Cookie": cookie,
            "Origin": "https://attacker.test",
            "Sec-Fetch-Site": "cross-site",
        },
    )
    assert (status, body) == (403, b'{"error":"invalid_origin"}')


def test_full_collection_journey(server: ProductServer) -> None:
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)

    status, body = _request(server, "GET", "/api/v1/connectors", headers=headers)
    assert status == 200
    connectors = cast("list[JsonObject]", json.loads(body)["connectors"])
    assert {item["connector_id"] for item in connectors} == {
        "arxiv",
        "openalex",
        "pubmed",
        "semantic_scholar",
        "europe_pmc",
        "core",
        "crossref",
    }

    # OpenAlex 연결 후 해당 소스로 플랜이 배정된다
    status, _body = _request(
        server,
        "POST",
        "/api/v1/connectors/openalex",
        body={"enabled": True},
        headers=headers,
    )
    assert status == 200
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/plan",
        body={"prompt": "openalex 정규화 연구 3개"},
        headers=headers,
    )
    assert status == 200
    plan = cast("JsonObject", json.loads(body))
    assert plan["connector_id"] == "openalex"
    assert plan["limit"] == 3
    assert "수집합니다" in cast("str", plan["summary"])

    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/execute",
        body={"plan_id": plan["plan_id"]},
        headers=headers,
    )
    assert status == 200
    collected = cast("JsonObject", json.loads(body))
    assert collected["row_count"] == 3
    assert cast("str", collected["content"]).startswith("sample,value,calibration\n")
    assert cast("str", collected["content"]).count("\n") == 4

    # 계획은 1회용이다
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/execute",
        body={"plan_id": plan["plan_id"]},
        headers=headers,
    )
    assert status == 400
    assert json.loads(body)["error"] == "unknown_or_expired_plan"


def test_plan_rejects_disabled_source_hint_and_empty_query(
    server: ProductServer,
) -> None:
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)

    # openalex는 해제 상태이므로 힌트가 무시되고 기본 활성 소스(arXiv)로 간다
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/plan",
        body={"prompt": "openalex 정규화"},
        headers=headers,
    )
    assert status == 200
    assert json.loads(body)["connector_id"] == "arxiv"

    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/plan",
        body={"prompt": "수집해줘"},
        headers=headers,
    )
    assert status == 400
    assert json.loads(body)["error"] == "empty_query"

    # 전부 해제하면 플랜을 만들 수 없다
    _status, _body = _request(
        server,
        "POST",
        "/api/v1/connectors/arxiv",
        body={"enabled": False},
        headers=headers,
    )
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/plan",
        body={"prompt": "정규화"},
        headers=headers,
    )
    assert status == 400
    assert json.loads(body)["error"] == "no_enabled_connector"


def _research_intent() -> JsonObject:
    return {
        "question": "수집한 문헌을 재현 가능하게 정규화할 수 있는가?",
        "rationale": "선택 수집물이 연구 입력으로 그대로 주입되는지 확인한다.",
        "intended_benefit": "수집 provenance가 보존된 실행 기준선을 만든다.",
        "success_criteria": ["동일 입력은 동일 체크섬을 만든다."],
        "constraints": ["수집된 문헌 데이터만 사용한다."],
        "stop_conditions": ["provenance가 없으면 중단한다."],
        "research_mode": "bounded_agentic",
        "data_origin": "observed",
    }


def _plan_and_execute(server: ProductServer, headers: dict[str, str]) -> JsonObject:
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/plan",
        body={"prompt": "정규화 연구 3개"},
        headers=headers,
    )
    assert status == 200
    plan = cast("JsonObject", json.loads(body))
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/execute",
        body={"plan_id": plan["plan_id"]},
        headers=headers,
    )
    assert status == 200
    return cast("JsonObject", json.loads(body))


def test_execute_list_get_materialize_and_provenance_journey(
    server: ProductServer,
) -> None:
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)

    collected = _plan_and_execute(server, headers)
    assert collected["connector_id"] == "arxiv"
    assert collected["connector_label"] == "arXiv"
    assert collected["query"] == "정규화 연구"
    assert collected["limit"] == 3
    assert collected["media_type"] == "text/csv"
    assert collected["row_count"] == 3
    assert cast("str", collected["content"]).startswith("sample,value,calibration\n")

    records = cast("list[JsonObject]", collected["records"])
    assert [record["id"] for record in records] == ["r1", "r2", "r3"]
    first = records[0]
    for key in ("title", "authors", "year", "venue", "citation_count"):
        assert key in first
    for key in ("abstract", "url"):
        assert key in first
    assert first["title"] == "정규화 연구 — arXiv 수집 결과 1"
    assert isinstance(first["authors"], list)
    assert first["year"] == 2024

    collection_id = cast("str", collected["collection_id"])

    status, body = _request(server, "GET", "/api/v1/collections", headers=headers)
    assert status == 200
    summaries = cast("list[JsonObject]", json.loads(body)["collections"])
    assert len(summaries) == 1
    summary = summaries[0]
    assert summary["collection_id"] == collection_id
    assert summary["connector_label"] == "arXiv"
    assert summary["record_count"] == 3
    assert summary["created_at"]
    assert "records" not in summary

    status, body = _request(
        server, "GET", f"/api/v1/collections/{collection_id}", headers=headers
    )
    assert status == 200
    detail = cast("JsonObject", json.loads(body))
    assert detail["collection_id"] == collection_id
    assert detail["created_at"]
    detail_records = cast("list[JsonObject]", detail["records"])
    assert [r["id"] for r in detail_records] == ["r1", "r2", "r3"]

    # 부분 선택 수집물을 연구 입력 CSV로 구체화한다
    status, body = _request(
        server,
        "POST",
        f"/api/v1/collections/{collection_id}/materialize",
        body={"record_ids": ["r1", "r3"]},
        headers=headers,
    )
    assert status == 200
    materialized = cast("JsonObject", json.loads(body))
    assert materialized["media_type"] == "text/csv"
    assert materialized["row_count"] == 2
    assert cast("str", materialized["content"]).count("\n") == 3

    # provenance와 함께 연구 실행을 생성한다
    status, body = _request(
        server,
        "POST",
        "/api/v1/runs",
        body={
            "execution_mode": "local_dry_lab",
            "session_id": PRIMARY_SESSION_ID,
            "prompt": "선택 수집물을 정규화하고 재현성을 검증한다.",
            "research_intent": _research_intent(),
            "input": {
                "filename": materialized["filename"],
                "media_type": materialized["media_type"],
                "content": materialized["content"],
                "provenance": {"collection_id": collection_id},
            },
        },
        headers=headers,
    )
    assert status == 201
    run = cast("JsonObject", json.loads(body))
    assert run["input_provenance"] == {"collection_id": collection_id}

    status, body = _request(
        server,
        "GET",
        f"/api/v1/runs/{run['run_id']}",
        headers={"Cookie": cookie},
    )
    assert status == 200
    assert json.loads(body)["input_provenance"] == {"collection_id": collection_id}


def test_run_without_provenance_exposes_null_input_provenance(
    server: ProductServer,
) -> None:
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    status, body = _request(
        server,
        "POST",
        "/api/v1/runs",
        body={
            "execution_mode": "local_dry_lab",
            "session_id": PRIMARY_SESSION_ID,
            "prompt": "보정값을 정규화하고 재현성을 검증한다.",
            "research_intent": _research_intent(),
            "input": {
                "filename": "calibrated.csv",
                "media_type": "text/csv",
                "content": "sample,value,calibration\na,1.0,cal-1\n",
            },
        },
        headers=headers,
    )
    assert status == 201
    assert json.loads(body)["input_provenance"] is None


def test_collections_hide_foreign_and_reject_bad_selection(
    server: ProductServer,
) -> None:
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)

    foreign = server.collections.create(
        "foreign-user",
        "arxiv",
        "타인 주제",
        [
            CollectedDocument(
                title="foreign",
                authors=(),
                year=None,
                venue=None,
                citation_count=None,
                abstract=None,
                url=None,
            )
        ],
    )

    # 타인 소유 컬렉션은 존재 자체를 숨긴다
    status, body = _request(
        server,
        "GET",
        f"/api/v1/collections/{foreign.collection_id}",
        headers=headers,
    )
    assert (status, body) == (404, b'{"error":"not_found"}')
    assert (
        _request(server, "GET", "/api/v1/collections/no-such-id", headers=headers)[0]
        == 404
    )

    status, body = _request(server, "GET", "/api/v1/collections", headers=headers)
    assert status == 200
    assert json.loads(body)["collections"] == []

    # 타인 소유 컬렉션의 선택 수집은 실패한다
    status, body = _request(
        server,
        "POST",
        f"/api/v1/collections/{foreign.collection_id}/materialize",
        body={"record_ids": ["r1"]},
        headers=headers,
    )
    assert status == 400
    assert json.loads(body)["error"] == "unknown_collection"

    # 빈 선택은 400이다
    status, _body = _request(
        server,
        "POST",
        f"/api/v1/collections/{foreign.collection_id}/materialize",
        body={"record_ids": []},
        headers=headers,
    )
    assert status == 400

    # 소유하지 않은 provenance로는 실행을 만들 수 없다
    status, body = _request(
        server,
        "POST",
        "/api/v1/runs",
        body={
            "execution_mode": "local_dry_lab",
            "session_id": PRIMARY_SESSION_ID,
            "prompt": "보정값을 정규화하고 재현성을 검증한다.",
            "research_intent": _research_intent(),
            "input": {
                "filename": "calibrated.csv",
                "media_type": "text/csv",
                "content": "sample,value,calibration\na,1.0,cal-1\n",
                "provenance": {"collection_id": foreign.collection_id},
            },
        },
        headers=headers,
    )
    assert (status, body) == (404, b'{"error":"not_found"}')


def test_materialize_rejects_mismatched_record_ids(server: ProductServer) -> None:
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    collected = _plan_and_execute(server, headers)
    collection_id = cast("str", collected["collection_id"])

    status, body = _request(
        server,
        "POST",
        f"/api/v1/collections/{collection_id}/materialize",
        body={"record_ids": ["r1", "r9"]},
        headers=headers,
    )
    assert status == 400
    assert json.loads(body)["error"] == "invalid_record_selection"

def _run_server_with_fetcher(
    fetcher: Callable[[str, str, int], list[CollectedDocument]],
) -> ProductServer:
    """Start a fixture server whose collection boundary is the given fetcher."""
    return run_product_server(
        ("127.0.0.1", 0),
        authenticated_fixture=True,
        options=ProductServerOptions(collection_fetcher=fetcher),
    )


def _plan_id(server: ProductServer, headers: dict[str, str]) -> str:
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/plan",
        body={"prompt": "정규화 연구 3개"},
        headers=headers,
    )
    assert status == 200
    return cast("str", json.loads(body)["plan_id"])


def test_execute_maps_fetcher_failure_to_bad_gateway() -> None:
    def failing_fetcher(
        _connector_id: str, _query: str, _limit: int
    ) -> list[CollectedDocument]:
        raise RuntimeError

    server = _run_server_with_fetcher(failing_fetcher)
    try:
        cookie = server.fixture_session_cookie()
        headers = _same_origin_headers(server, cookie)
        plan_id = _plan_id(server, headers)
        status, body = _request(
            server,
            "POST",
            "/api/v1/collections/execute",
            body={"plan_id": plan_id},
            headers=headers,
        )
        assert status == 502
        assert json.loads(body)["error"] == "collection_fetch_failed"
    finally:
        server.shutdown()
        server.server_close()


def test_execute_maps_empty_result_to_bad_gateway() -> None:
    def empty_fetcher(
        _connector_id: str, _query: str, _limit: int
    ) -> list[CollectedDocument]:
        return []

    server = _run_server_with_fetcher(empty_fetcher)
    try:
        cookie = server.fixture_session_cookie()
        headers = _same_origin_headers(server, cookie)
        plan_id = _plan_id(server, headers)
        status, body = _request(
            server,
            "POST",
            "/api/v1/collections/execute",
            body={"plan_id": plan_id},
            headers=headers,
        )
        assert status == 502
        assert json.loads(body)["error"] == "collection_empty"
    finally:
        server.shutdown()
        server.server_close()


def test_connector_mutation_rejects_invalid_key_env(
    server: ProductServer,
) -> None:
    cookie = server.fixture_session_cookie()
    headers = _same_origin_headers(server, cookie)
    status, body = _request(
        server,
        "POST",
        "/api/v1/connectors/pubmed",
        body={"enabled": True, "key_env": "lower case name"},
        headers=headers,
    )
    assert status == 400
    assert json.loads(body)["error"] == "invalid_key_env"

    # 실패한 변경은 저장되지 않는다
    status, body = _request(server, "GET", "/api/v1/connectors", headers=headers)
    assert status == 200
    pubmed = next(
        item
        for item in cast("list[JsonObject]", json.loads(body)["connectors"])
        if item["connector_id"] == "pubmed"
    )
    assert pubmed["enabled"] is False
    assert pubmed["key_env"] is None
