"""Structured collected-document domain coverage: adapters, store, and CSV."""

from __future__ import annotations

import io
import urllib.request
from datetime import UTC, datetime
from http.client import HTTPMessage
from typing import TypedDict, Unpack

import pytest
from services.api.product_connectors import (
    CollectedDocument,
    CollectionStore,
    ConnectorSettingsError,
    PinnedRedirectHandler,
    arxiv_documents,
    fixture_collection_fetcher,
    materialize_csv,
    openalex_documents,
    pubmed_documents,
)

_PUBMED_BASE = "https://pubmed.ncbi.nlm.nih.gov"


class _DocumentOverrides(TypedDict, total=False):
    """Optional field overrides accepted by `_document`."""

    authors: tuple[str, ...]
    year: int | None
    venue: str | None
    citation_count: int | None
    abstract: str | None
    url: str | None


def _document(
    title: str, **overrides: Unpack[_DocumentOverrides]
) -> CollectedDocument:
    return CollectedDocument(
        title=title,
        authors=overrides.get("authors", ("Alice A",)),
        year=overrides.get("year", 2024),
        venue=overrides.get("venue", "Venue"),
        citation_count=overrides.get("citation_count", 3),
        abstract=overrides.get("abstract", "abstract"),
        url=overrides.get("url", "https://example.test/1"),
    )


# ---- OpenAlex parsing -------------------------------------------------------


def test_openalex_documents_parse_structured_fields() -> None:
    payload: dict[str, object] = {
        "results": [
            {
                "display_name": "Graph Networks Revisited",
                "authorships": [
                    {"author": {"display_name": "Alice A"}},
                    {"author": {"display_name": "Bob B"}},
                    {"author": {}},
                    "junk",
                ],
                "publication_year": 2024,
                "primary_location": {"source": {"display_name": "Nature"}},
                "cited_by_count": 12,
                "abstract_inverted_index": {
                    "Graph": [0],
                    "networks": [1],
                    "learn": [2],
                    "broken": "nope",
                },
                "doi": "https://doi.org/10.1234/graph",
                "id": "https://openalex.org/W1",
            },
            {
                "id": "https://openalex.org/W2",
                "cited_by_count": None,
            },
            "junk",
        ]
    }
    documents = openalex_documents(payload, 10)
    assert len(documents) == 2

    first = documents[0]
    assert first.title == "Graph Networks Revisited"
    assert first.authors == ("Alice A", "Bob B")
    assert first.year == 2024
    assert first.venue == "Nature"
    assert first.citation_count == 12
    assert first.abstract == "Graph networks learn"
    assert first.url == "https://doi.org/10.1234/graph"

    second = documents[1]
    assert second.title == "OpenAlex 결과 2"
    assert second.authors == ()
    assert second.year is None
    assert second.venue is None
    assert second.citation_count is None
    assert second.abstract is None
    assert second.url == "https://openalex.org/W2"


def test_openalex_documents_honor_limit_and_bad_payload() -> None:
    payload: dict[str, object] = {"results": [{"display_name": "A"}, {"display_name": "B"}]}
    assert [d.title for d in openalex_documents(payload, 1)] == ["A"]
    assert openalex_documents({"results": "nope"}, 5) == []
    assert openalex_documents({}, 5) == []


# ---- arXiv parsing ----------------------------------------------------------

_ARXIV_FEED = """<?xml version="1.0" encoding="UTF-8"?>
<feed xmlns="http://www.w3.org/2005/Atom">
<title>arXiv Query: graph</title>
<author><name>arxiv</name></author>
<entry>
<id>http://arxiv.org/abs/2401.00001v1</id>
<title>  Graph   Networks
  Revisited </title>
<author><name>Alice A</name></author>
<author><name>Bob B</name></author>
<published>2024-01-15T00:00:00Z</published>
<summary> We study
 graph networks &amp; friends. </summary>
</entry>
<entry>
<id>http://arxiv.org/abs/2401.00002v1</id>
</entry>
</feed>
"""


def test_arxiv_documents_parse_entries() -> None:
    documents = arxiv_documents(_ARXIV_FEED, 10)
    assert len(documents) == 2

    first = documents[0]
    assert first.title == "Graph Networks Revisited"
    assert first.authors == ("Alice A", "Bob B")
    assert first.year == 2024
    assert first.venue is None
    assert first.citation_count is None
    assert first.abstract == "We study graph networks & friends."
    assert first.url == "http://arxiv.org/abs/2401.00001v1"

    second = documents[1]
    assert second.title == "arXiv 결과 2"
    assert second.authors == ()
    assert second.year is None
    assert second.abstract is None
    assert second.url == "http://arxiv.org/abs/2401.00002v1"


def test_arxiv_documents_honor_limit() -> None:
    assert len(arxiv_documents(_ARXIV_FEED, 1)) == 1
    assert arxiv_documents("<feed></feed>", 5) == []


# ---- PubMed parsing ---------------------------------------------------------


def test_pubmed_documents_parse_summary() -> None:
    payload: dict[str, object] = {
        "result": {
            "uids": ["111", "222"],
            "111": {
                "title": "Deep seizure detection",
                "authors": [
                    {"name": "Kim Y"},
                    {"name": "Lee J"},
                    "junk",
                ],
                "pubdate": "2024 Jan 5",
                "source": "J Neurol",
            },
            "222": {},
        }
    }
    documents = pubmed_documents(payload, ["111", "222", "333"], _PUBMED_BASE)
    assert len(documents) == 2

    first = documents[0]
    assert first.title == "Deep seizure detection"
    assert first.authors == ("Kim Y", "Lee J")
    assert first.year == 2024
    assert first.venue == "J Neurol"
    assert first.citation_count is None
    assert first.abstract is None
    assert first.url == f"{_PUBMED_BASE}/111/"

    second = documents[1]
    assert second.title == "PubMed PMID 222"
    assert second.authors == ()
    assert second.year is None
    assert second.venue is None
    assert second.url == f"{_PUBMED_BASE}/222/"


def test_pubmed_documents_bad_payload() -> None:
    assert pubmed_documents({"result": "nope"}, ["1"], _PUBMED_BASE) == []
    assert pubmed_documents({}, ["1"], _PUBMED_BASE) == []


# ---- collection store -------------------------------------------------------


def test_store_create_list_get_owner_scoped() -> None:
    clock_now = datetime(2026, 7, 25, tzinfo=UTC)
    store = CollectionStore(lambda: clock_now)
    documents = [_document("one"), _document("two")]
    collection = store.create("u1", "arxiv", "정규화", documents)
    documents.append(_document("three"))

    assert collection.principal_id == "u1"
    assert collection.connector_id == "arxiv"
    assert collection.query == "정규화"
    assert collection.created_at == clock_now
    # 생성 시점의 불변 스냅샷이 유지된다
    assert len(collection.records) == 2

    other = store.create("u1", "pubmed", "다른 주제", [_document("four")])
    _ = store.create("u2", "arxiv", "타인", [_document("five")])
    assert store.list_for("u1") == [collection, other]
    assert [c.principal_id for c in store.list_for("u2")] == ["u2"]
    assert store.list_for("u3") == []

    assert store.get("u1", collection.collection_id) == collection
    # 타인 소유 컬렉션은 존재 자체를 숨긴다
    assert store.get("u2", collection.collection_id) is None
    assert store.get("u1", "missing") is None


def test_store_materialize_selection() -> None:
    store = CollectionStore(lambda: datetime(2026, 7, 25, tzinfo=UTC))
    collection = store.create(
        "u1",
        "arxiv",
        "정규화",
        [_document("one"), _document("two"), _document("three")],
    )
    csv_text = store.materialize("u1", collection.collection_id, ["r1", "r3"])
    lines = csv_text.splitlines()
    assert lines[0] == "sample,value,calibration"
    assert len(lines) == 3
    assert lines[1].startswith("one,")
    assert lines[2].startswith("three,")


def test_store_materialize_fail_closed() -> None:
    store = CollectionStore(lambda: datetime(2026, 7, 25, tzinfo=UTC))
    collection = store.create("u1", "arxiv", "정규화", [_document("one")])
    with pytest.raises(ConnectorSettingsError):
        # 타인 소유
        _ = store.materialize("u2", collection.collection_id, ["r1"])
    with pytest.raises(ConnectorSettingsError):
        # 알 수 없는 컬렉션
        _ = store.materialize("u1", "missing", ["r1"])
    with pytest.raises(ConnectorSettingsError):
        # 빈 선택
        _ = store.materialize("u1", collection.collection_id, [])
    with pytest.raises(ConnectorSettingsError):
        # 범위 밖 레코드
        _ = store.materialize("u1", collection.collection_id, ["r2"])
    with pytest.raises(ConnectorSettingsError):
        # 잘못된 레코드 id 형식
        _ = store.materialize("u1", collection.collection_id, ["x1"])


def test_store_materialize_rejects_duplicate_selection() -> None:
    store = CollectionStore(lambda: datetime(2026, 7, 25, tzinfo=UTC))
    collection = store.create(
        "u1", "arxiv", "정규화", [_document("one"), _document("two")]
    )
    with pytest.raises(ConnectorSettingsError, match="duplicate_record_selection"):
        _ = store.materialize("u1", collection.collection_id, ["r1", "r2", "r1"])


def test_store_materialize_rejects_selection_exceeding_records() -> None:
    store = CollectionStore(lambda: datetime(2026, 7, 25, tzinfo=UTC))
    collection = store.create(
        "u1", "arxiv", "정규화", [_document("one"), _document("two")]
    )
    with pytest.raises(ConnectorSettingsError, match="selection_exceeds_records"):
        _ = store.materialize("u1", collection.collection_id, ["r1", "r2", "r3"])


# ---- fixture fetcher --------------------------------------------------------


def test_fixture_fetcher_is_deterministic_and_structured() -> None:
    first = fixture_collection_fetcher("pubmed", "정규화", 4)
    second = fixture_collection_fetcher("pubmed", "정규화", 4)
    assert first == second
    assert len(first) == 4

    for index, document in enumerate(first):
        assert document.title == f"정규화 — PubMed (NCBI) 수집 결과 {index + 1}"
        assert document.authors
        assert document.year is not None
        assert document.venue
        assert document.citation_count is not None
        assert document.abstract
        assert document.url == f"{_PUBMED_BASE}/fixture/{index + 1}"

    with pytest.raises(ConnectorSettingsError):
        _ = fixture_collection_fetcher("attacker", "x", 1)


# ---- CSV materialization ----------------------------------------------------


def test_materialize_csv_escapes_and_normalizes() -> None:
    records = [
        CollectedDocument(
            title='Graph, "대규모" 연구\n개정판',
            authors=("A, B", 'C "D"'),
            year=2024,
            venue=None,
            citation_count=12,
            abstract="line1\r\nline2",
            url=None,
        ),
        CollectedDocument(
            title="plain",
            authors=(),
            year=None,
            venue="Venue",
            citation_count=None,
            abstract=None,
            url="https://example.test/2",
        ),
    ]
    csv_text = materialize_csv("arxiv", records)
    lines = csv_text.splitlines()
    assert lines[0] == "sample,value,calibration"
    assert lines[1] == '"Graph, ""대규모"" 연구 개정판",12,arxiv'
    assert lines[2] == "plain,2,arxiv"
    assert csv_text.endswith("\n")


def test_materialize_csv_rejects_unknown_connector() -> None:
    with pytest.raises(ConnectorSettingsError):
        _ = materialize_csv("attacker", [_document("one")])


def test_materialize_csv_defuses_spreadsheet_formula_cells() -> None:
    csv_text = materialize_csv(
        "arxiv",
        [
            _document("=HYPERLINK()"),
            _document("+SUM(A1:A2)"),
            _document("-10"),
            _document("@cmd"),
            _document("safe title"),
        ],
    )
    lines = csv_text.splitlines()
    assert lines[0] == "sample,value,calibration"
    assert lines[1].startswith("'=")
    assert lines[2].startswith("'+")
    assert lines[3].startswith("'-")
    assert lines[4].startswith("'@")
    assert lines[5] == "safe title,3,arxiv"


# ---- outbound fetch boundary ------------------------------------------------


def test_pinned_redirect_handler_rejects_cross_host_location() -> None:
    handler = PinnedRedirectHandler()
    request = urllib.request.Request("https://api.openalex.org/works")
    with pytest.raises(ConnectorSettingsError, match="redirect_not_pinned"):
        _ = handler.redirect_request(
            request,
            io.BytesIO(b""),
            302,
            "Found",
            HTTPMessage(),
            "https://attacker.test/steal",
        )


def test_pinned_redirect_handler_allows_same_host_location() -> None:
    handler = PinnedRedirectHandler()
    request = urllib.request.Request("https://api.openalex.org/works")
    redirected = handler.redirect_request(
        request,
        io.BytesIO(b""),
        302,
        "Found",
        HTTPMessage(),
        "https://api.openalex.org/v2/works",
    )
    assert redirected is not None
    assert redirected.full_url == "https://api.openalex.org/v2/works"
