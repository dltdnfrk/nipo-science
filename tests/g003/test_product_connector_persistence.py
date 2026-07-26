"""SQLite persistence for connector settings and collections (restart-proof)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from http.client import HTTPConnection
from socket import AF_INET, AF_INET6
from typing import TYPE_CHECKING, cast

import pytest
from services.api.product_app import (
    ProductServer,
    ProductServerOptions,
    run_product_server,
)
from services.api.product_connector_persistence import (
    SqliteCollectionStore,
    SqliteConnectorSettingsStore,
    initialize_connector_schema,
)
from services.api.product_connectors import CollectedDocument

if TYPE_CHECKING:
    from pathlib import Path

type JsonObject = dict[str, object]
_UNSUPPORTED_ADDRESS = "unsupported address family"


def _document(title: str) -> CollectedDocument:
    return CollectedDocument(
        title=title,
        authors=("Alice A",),
        year=2024,
        venue="Venue",
        citation_count=3,
        abstract="abstract",
        url="https://example.test/1",
    )


# ---- schema -----------------------------------------------------------------


def test_schema_initialization_is_idempotent(tmp_path: Path) -> None:
    db_path = tmp_path / "nested" / "nipo.db"
    initialize_connector_schema(db_path)
    initialize_connector_schema(db_path)
    store = SqliteConnectorSettingsStore(db_path)
    assert {item["connector_id"] for item in store.list_for("u1")} == {
        "arxiv",
        "openalex",
        "pubmed",
        "semantic_scholar",
        "europe_pmc",
        "core",
        "crossref",
    }


def test_fetch_outcomes_survive_store_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "nipo.db"
    moment = datetime(2026, 7, 26, tzinfo=UTC)
    first = SqliteConnectorSettingsStore(db_path)
    first.record_fetch_outcome("u1", "openalex", succeeded=True, at=moment)
    first.record_fetch_outcome("u1", "pubmed", succeeded=False, at=moment)

    # 재기동 후에도 마지막 성공/실패 시각이 남아 있다
    second = SqliteConnectorSettingsStore(db_path)
    items = {item["connector_id"]: item for item in second.list_for("u1")}
    assert items["openalex"]["last_success_at"] == moment.isoformat()
    assert items["openalex"]["last_failure_at"] is None
    assert items["pubmed"]["last_failure_at"] == moment.isoformat()
    assert items["arxiv"]["last_success_at"] is None

    # 실패 이후 성공이 누적되고, 설정 토글과 독립적으로 유지된다
    second.record_fetch_outcome("u1", "pubmed", succeeded=True, at=moment)
    _ = second.update("u1", "pubmed", enabled=True)
    items = {item["connector_id"]: item for item in second.list_for("u1")}
    assert items["pubmed"]["last_success_at"] == moment.isoformat()
    assert items["pubmed"]["last_failure_at"] == moment.isoformat()


# ---- settings restart --------------------------------------------------------


def test_settings_survive_store_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "nipo.db"
    first = SqliteConnectorSettingsStore(db_path)
    _ = first.update("u1", "pubmed", enabled=True, key_env="NCBI_API_KEY")
    _ = first.update("u1", "arxiv", enabled=False)

    # 재기동: 같은 파일을 여는 새 저장소 인스턴스
    second = SqliteConnectorSettingsStore(db_path)
    items = {item["connector_id"]: item for item in second.list_for("u1")}
    assert items["pubmed"]["enabled"] is True
    assert items["pubmed"]["key_env"] == "NCBI_API_KEY"
    assert items["arxiv"]["enabled"] is False
    # 기본값과 다른 주체는 저장 상태에 오염되지 않는다
    assert items["openalex"]["enabled"] is False
    assert second.is_enabled("u2", "pubmed") is False
    assert second.enabled_ids("u1") == ["pubmed"]


def test_settings_fail_closed_before_writing(tmp_path: Path) -> None:
    db_path = tmp_path / "nipo.db"
    store = SqliteConnectorSettingsStore(db_path)
    with pytest.raises(Exception, match="invalid_key_env"):
        _ = store.update("u1", "pubmed", enabled=True, key_env="lower case name")
    assert store.is_enabled("u1", "pubmed") is False


# ---- collections restart -----------------------------------------------------


def test_collections_survive_store_restart(tmp_path: Path) -> None:
    db_path = tmp_path / "nipo.db"
    clock_now = datetime(2026, 7, 26, tzinfo=UTC)
    first = SqliteCollectionStore(db_path, lambda: clock_now)
    created = first.create("u1", "arxiv", "정규화", [_document("one"), _document("two")])
    _ = first.create("u2", "pubmed", "타인 주제", [_document("three")])

    # 재기동 후에도 스냅샷·소유자 범위·CSV 실체화가 동일하다
    second = SqliteCollectionStore(db_path, lambda: clock_now)
    restored = second.get("u1", created.collection_id)
    assert restored == created
    assert [c.collection_id for c in second.list_for("u1")] == [
        created.collection_id
    ]
    assert second.get("u2", created.collection_id) is None

    csv_text = second.materialize("u1", created.collection_id, ["r2"])
    lines = csv_text.splitlines()
    assert lines[0] == "sample,value,calibration"
    assert lines[1].startswith("two,")


def test_collection_order_is_oldest_first(tmp_path: Path) -> None:
    db_path = tmp_path / "nipo.db"
    base = datetime(2026, 7, 26, tzinfo=UTC)
    moments = iter(
        [
            base.replace(hour=9),
            base.replace(hour=10),
            base.replace(hour=11),
        ]
    )
    store = SqliteCollectionStore(db_path, lambda: next(moments))
    first = store.create("u1", "arxiv", "첫째", [_document("one")])
    second = store.create("u1", "arxiv", "둘째", [_document("two")])
    _ = store.create("u2", "arxiv", "타인", [_document("three")])
    assert [c.collection_id for c in store.list_for("u1")] == [
        first.collection_id,
        second.collection_id,
    ]


# ---- server-level restart via options injection ------------------------------


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


def _run_persistent_server(db_path: Path) -> ProductServer:
    return run_product_server(
        ("127.0.0.1", 0),
        authenticated_fixture=True,
        options=ProductServerOptions(
            connector_settings=SqliteConnectorSettingsStore(db_path),
            collections=SqliteCollectionStore(db_path),
        ),
    )


def test_server_restart_preserves_settings_and_collections(tmp_path: Path) -> None:
    db_path = tmp_path / "nipo.db"
    server = _run_persistent_server(db_path)
    try:
        cookie = server.fixture_session_cookie()
        headers = _same_origin_headers(server, cookie)

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
            body={"prompt": "정규화 연구 3개"},
            headers=headers,
        )
        assert status == 200
        plan_id = cast("str", cast("JsonObject", json.loads(body))["plan_id"])
        status, body = _request(
            server,
            "POST",
            "/api/v1/collections/execute",
            body={"plan_id": plan_id},
            headers=headers,
        )
        assert status == 200
        collection_id = cast(
            "str", cast("JsonObject", json.loads(body))["collection_id"]
        )
    finally:
        server.shutdown()
        server.server_close()

    # 재기동: 같은 DB 파일을 주입한 새 서버
    restarted = _run_persistent_server(db_path)
    try:
        cookie = restarted.fixture_session_cookie()
        headers = _same_origin_headers(restarted, cookie)

        status, body = _request(
            restarted, "GET", "/api/v1/connectors", headers=headers
        )
        assert status == 200
        connectors = cast(
            "list[JsonObject]",
            cast("JsonObject", json.loads(body))["connectors"],
        )
        openalex = next(
            item for item in connectors if item["connector_id"] == "openalex"
        )
        assert openalex["enabled"] is True

        status, body = _request(
            restarted, "GET", "/api/v1/collections", headers=headers
        )
        assert status == 200
        summaries = cast(
            "list[JsonObject]",
            cast("JsonObject", json.loads(body))["collections"],
        )
        assert [item["collection_id"] for item in summaries] == [collection_id]

        status, body = _request(
            restarted,
            "GET",
            f"/api/v1/collections/{collection_id}",
            headers=headers,
        )
        assert status == 200
        detail = cast("JsonObject", json.loads(body))
        records = cast("list[JsonObject]", detail["records"])
        assert [record["id"] for record in records] == ["r1", "r2", "r3"]
    finally:
        restarted.shutdown()
        restarted.server_close()


def test_fixture_default_stays_in_memory() -> None:
    server = run_product_server(("127.0.0.1", 0), authenticated_fixture=True)
    try:
        cookie = server.fixture_session_cookie()
        headers = _same_origin_headers(server, cookie)
        status, _body = _request(
            server,
            "POST",
            "/api/v1/connectors/openalex",
            body={"enabled": True},
            headers=headers,
        )
        assert status == 200

        # 같은 프로세스 재기동 없이 새 서버를 띄우면 상태가 남지 않는다
        fresh = run_product_server(("127.0.0.1", 0), authenticated_fixture=True)
        try:
            fresh_cookie = fresh.fixture_session_cookie()
            fresh_headers = _same_origin_headers(fresh, fresh_cookie)
            status, body = _request(
                fresh, "GET", "/api/v1/connectors", headers=fresh_headers
            )
            assert status == 200
            connectors = cast(
                "list[JsonObject]",
                cast("JsonObject", json.loads(body))["connectors"],
            )
            openalex = next(
                item for item in connectors if item["connector_id"] == "openalex"
            )
            assert openalex["enabled"] is False
            status, body = _request(
                fresh, "GET", "/api/v1/collections", headers=fresh_headers
            )
            assert status == 200
            assert cast("JsonObject", json.loads(body))["collections"] == []
        finally:
            fresh.shutdown()
            fresh.server_close()
    finally:
        server.shutdown()
        server.server_close()
