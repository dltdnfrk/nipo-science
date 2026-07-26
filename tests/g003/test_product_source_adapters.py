"""Expanded source adapters: canned parsing, politeness, and outcome mapping."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from http.client import HTTPConnection
from socket import AF_INET, AF_INET6
from typing import cast

import pytest
from services.api import product_connectors
from services.api.product_app import (
    ProductServer,
    ProductServerOptions,
    run_product_server,
)
from services.api.product_connectors import (
    ConnectorSettingsError,
    ConnectorSettingsStore,
    TokenBucket,
    configure_live_rate_limit,
    core_documents,
    crossref_documents,
    europe_pmc_documents,
    live_collection_fetcher,
    semantic_scholar_documents,
)

type JsonObject = dict[str, object]
_UNSUPPORTED_ADDRESS = "unsupported address family"
_HIGH_RATE = 1000.0


# ---- Semantic Scholar parsing ------------------------------------------------


def test_semantic_scholar_documents_parse_structured_fields() -> None:
    payload: dict[str, object] = {
        "data": [
            {
                "title": "Graph Nets Revisited",
                "authors": [{"name": "Alice A"}, {"name": "Bob B"}, "junk"],
                "year": 2024,
                "venue": "NeurIPS",
                "citationCount": 12,
                "abstract": "We study graphs.",
                "url": "https://www.semanticscholar.org/paper/1",
            },
            {"paperId": "W2"},
            "junk",
        ]
    }
    documents = semantic_scholar_documents(payload, 10)
    assert len(documents) == 2

    first = documents[0]
    assert first.title == "Graph Nets Revisited"
    assert first.authors == ("Alice A", "Bob B")
    assert first.year == 2024
    assert first.venue == "NeurIPS"
    assert first.citation_count == 12
    assert first.abstract == "We study graphs."
    assert first.url == "https://www.semanticscholar.org/paper/1"

    second = documents[1]
    assert second.title == "Semantic Scholar 결과 2"
    assert second.authors == ()
    assert second.year is None
    assert second.citation_count is None
    assert second.url is None


def test_semantic_scholar_documents_honor_limit_and_bad_payload() -> None:
    payload: dict[str, object] = {"data": [{"title": "A"}, {"title": "B"}]}
    assert [d.title for d in semantic_scholar_documents(payload, 1)] == ["A"]
    assert semantic_scholar_documents({"data": "nope"}, 5) == []
    assert semantic_scholar_documents({}, 5) == []


# ---- Europe PMC parsing -------------------------------------------------------


def test_europe_pmc_documents_parse_structured_fields() -> None:
    payload: dict[str, object] = {
        "resultList": {
            "result": [
                {
                    "title": "Deep seizure detection",
                    "authorString": "Kim Y, Lee J.",
                    "pubYear": "2024",
                    "journalTitle": "J Neurol",
                    "citedByCount": 5,
                    "abstractText": "Seizure abstract.",
                    "doi": "10.1/x",
                    "id": "123",
                    "source": "MED",
                },
                {"id": "456", "source": "MED"},
                "junk",
            ]
        }
    }
    documents = europe_pmc_documents(payload, 10)
    assert len(documents) == 2

    first = documents[0]
    assert first.title == "Deep seizure detection"
    assert first.authors == ("Kim Y", "Lee J")
    assert first.year == 2024
    assert first.venue == "J Neurol"
    assert first.citation_count == 5
    assert first.abstract == "Seizure abstract."
    assert first.url == "https://doi.org/10.1/x"

    second = documents[1]
    assert second.title == "Europe PMC 결과 2"
    assert second.authors == ()
    assert second.year is None
    assert second.url == "https://europepmc.org/article/MED/456"


def test_europe_pmc_documents_bad_payload() -> None:
    assert europe_pmc_documents({"resultList": "nope"}, 5) == []
    assert europe_pmc_documents({}, 5) == []


# ---- CORE parsing -------------------------------------------------------------


def test_core_documents_parse_structured_fields() -> None:
    payload: dict[str, object] = {
        "results": [
            {
                "title": "Open access graphs",
                "authors": [{"name": "No Y"}, "Plain Author", {}],
                "yearPublished": 2023,
                "publisher": "CORE Press",
                "citationCount": 3,
                "abstract": "OA abstract.",
                "downloadUrl": "https://core.ac.uk/download/1",
            },
            {"title": "Second", "authors": []},
            "junk",
        ]
    }
    documents = core_documents(payload, 10)
    assert len(documents) == 2

    first = documents[0]
    assert first.title == "Open access graphs"
    assert first.authors == ("No Y", "Plain Author")
    assert first.year == 2023
    assert first.venue == "CORE Press"
    assert first.citation_count == 3
    assert first.abstract == "OA abstract."
    assert first.url == "https://core.ac.uk/download/1"

    second = documents[1]
    assert second.title == "Second"
    assert second.authors == ()
    assert second.url is None


def test_core_documents_bad_payload() -> None:
    assert core_documents({"results": "nope"}, 5) == []
    assert core_documents({}, 5) == []


# ---- Crossref parsing -----------------------------------------------------------


def test_crossref_documents_parse_structured_fields() -> None:
    payload: dict[str, object] = {
        "message": {
            "items": [
                {
                    "title": ["Graph study"],
                    "author": [
                        {"given": "Yuna", "family": "Kim"},
                        {"family": "Lee"},
                        "junk",
                    ],
                    "published": {"date-parts": [[2024, 1, 15]]},
                    "container-title": ["Nature"],
                    "is-referenced-by-count": 9,
                    "abstract": "<jats:p>We <jats:italic>study</jats:italic>"
                    " graphs.</jats:p>",
                    "DOI": "10.1234/g",
                    "URL": "https://doi.org/10.1234/g",
                },
                {"DOI": "10.1234/h"},
                "junk",
            ]
        }
    }
    documents = crossref_documents(payload, 10)
    assert len(documents) == 2

    first = documents[0]
    assert first.title == "Graph study"
    assert first.authors == ("Yuna Kim", "Lee")
    assert first.year == 2024
    assert first.venue == "Nature"
    assert first.citation_count == 9
    assert first.abstract == "We study graphs."
    assert first.url == "https://doi.org/10.1234/g"

    second = documents[1]
    assert second.title == "Crossref 결과 2"
    assert second.authors == ()
    assert second.year is None
    assert second.url == "https://doi.org/10.1234/h"


def test_crossref_documents_bad_payload() -> None:
    assert crossref_documents({"message": "nope"}, 5) == []
    assert crossref_documents({}, 5) == []


# ---- token bucket politeness ----------------------------------------------------


def test_token_bucket_spaces_requests_at_the_configured_rate() -> None:
    now = [0.0]
    sleeps: list[float] = []

    def _sleeper(seconds: float) -> None:
        sleeps.append(seconds)
        now[0] += seconds

    bucket = TokenBucket(1.0, clock=lambda: now[0], sleeper=_sleeper)
    bucket.acquire()
    bucket.acquire()
    bucket.acquire()
    assert sleeps == [1.0, 1.0]

    with pytest.raises(ConnectorSettingsError, match="invalid_rate_limit"):
        _ = TokenBucket(0.0)


def test_configure_live_rate_limit_rejects_unknown_connector() -> None:
    with pytest.raises(ConnectorSettingsError, match="unknown_connector"):
        configure_live_rate_limit("attacker", 1.0)


# ---- live-path success/failure mapping and outcome timestamps -------------------


_CANNED_SUCCESS: dict[str, bytes] = {
    "semantic_scholar": json.dumps(
        {"data": [{"title": "S2 paper", "year": 2024, "citationCount": 1}]}
    ).encode(),
    "europe_pmc": json.dumps(
        {"resultList": {"result": [{"title": "EPMC paper", "pubYear": "2023"}]}}
    ).encode(),
    "core": json.dumps(
        {"results": [{"title": "CORE paper", "yearPublished": 2022}]}
    ).encode(),
    "crossref": json.dumps(
        {"message": {"items": [{"title": ["CR paper"], "DOI": "10.1/cr"}]}}
    ).encode(),
}

_SOURCE_PROMPTS: dict[str, str] = {
    "semantic_scholar": "semanticscholar 정규화 2개",
    "europe_pmc": "europepmc 정규화 2개",
    "core": "코어 정규화 2개",
    "crossref": "crossref 정규화 2개",
}


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
def live_server() -> object:
    instance = run_product_server(
        ("127.0.0.1", 0),
        authenticated_fixture=True,
        options=ProductServerOptions(collection_fetcher=live_collection_fetcher),
    )
    try:
        yield instance
    finally:
        instance.shutdown()
        instance.server_close()


def _enable_and_plan(
    server: ProductServer, headers: dict[str, str], connector_id: str
) -> str:
    status, _body = _request(
        server,
        "POST",
        f"/api/v1/connectors/{connector_id}",
        body={"enabled": True},
        headers=headers,
    )
    assert status == 200
    status, body = _request(
        server,
        "POST",
        "/api/v1/collections/plan",
        body={"prompt": _SOURCE_PROMPTS[connector_id]},
        headers=headers,
    )
    assert status == 200
    plan = cast("JsonObject", json.loads(body))
    assert plan["connector_id"] == connector_id
    return cast("str", plan["plan_id"])


def _connector_item(
    server: ProductServer, headers: dict[str, str], connector_id: str
) -> JsonObject:
    status, body = _request(server, "GET", "/api/v1/connectors", headers=headers)
    assert status == 200
    connectors = cast(
        "list[JsonObject]", cast("JsonObject", json.loads(body))["connectors"]
    )
    return next(item for item in connectors if item["connector_id"] == connector_id)


@pytest.mark.parametrize("connector_id", sorted(_CANNED_SUCCESS))
def test_live_success_records_last_success_at(
    live_server: ProductServer,
    monkeypatch: pytest.MonkeyPatch,
    connector_id: str,
) -> None:
    configure_live_rate_limit(connector_id, _HIGH_RATE)
    def _serve(_url: str) -> bytes:
        return _CANNED_SUCCESS[connector_id]

    monkeypatch.setattr(product_connectors, "_read_bounded", _serve)
    cookie = live_server.fixture_session_cookie()
    headers = _same_origin_headers(live_server, cookie)
    plan_id = _enable_and_plan(live_server, headers, connector_id)

    status, body = _request(
        live_server,
        "POST",
        "/api/v1/collections/execute",
        body={"plan_id": plan_id},
        headers=headers,
    )
    assert status == 200
    assert cast("JsonObject", json.loads(body))["row_count"] == 1

    item = _connector_item(live_server, headers, connector_id)
    assert item["last_success_at"]
    assert item["last_failure_at"] is None


@pytest.mark.parametrize("connector_id", sorted(_SOURCE_PROMPTS))
def test_live_failure_maps_to_collection_fetch_failed(
    live_server: ProductServer,
    monkeypatch: pytest.MonkeyPatch,
    connector_id: str,
) -> None:
    configure_live_rate_limit(connector_id, _HIGH_RATE)

    def _fail(_url: str) -> bytes:
        raise RuntimeError

    monkeypatch.setattr(product_connectors, "_read_bounded", _fail)
    cookie = live_server.fixture_session_cookie()
    headers = _same_origin_headers(live_server, cookie)
    plan_id = _enable_and_plan(live_server, headers, connector_id)

    status, body = _request(
        live_server,
        "POST",
        "/api/v1/collections/execute",
        body={"plan_id": plan_id},
        headers=headers,
    )
    assert status == 502
    assert cast("JsonObject", json.loads(body))["error"] == "collection_fetch_failed"

    item = _connector_item(live_server, headers, connector_id)
    assert item["last_failure_at"]
    assert item["last_success_at"] is None


# ---- outcome bookkeeping on the in-memory store ---------------------------------


def test_settings_outcome_survives_toggle_updates() -> None:
    store = ConnectorSettingsStore()
    moment = datetime(2026, 7, 26, tzinfo=UTC)
    store.record_fetch_outcome("u1", "openalex", succeeded=True, at=moment)
    _ = store.update("u1", "openalex", enabled=True)

    items = {item["connector_id"]: item for item in store.list_for("u1")}
    assert items["openalex"]["last_success_at"] == moment.isoformat()
    assert items["openalex"]["last_failure_at"] is None

    # 토글 후에도 수집 시각 기록은 유지된다
    _ = store.update("u1", "openalex", enabled=False)
    items = {item["connector_id"]: item for item in store.list_for("u1")}
    assert items["openalex"]["last_success_at"] == moment.isoformat()

    store.record_fetch_outcome("u1", "openalex", succeeded=False, at=moment)
    items = {item["connector_id"]: item for item in store.list_for("u1")}
    assert items["openalex"]["last_failure_at"] == moment.isoformat()

    with pytest.raises(ConnectorSettingsError, match="unknown_connector"):
        store.record_fetch_outcome("u1", "attacker", succeeded=True, at=moment)
