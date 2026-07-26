"""Literature data-source connectors: settings, collection plans, and execution.

The flow mirrors the product's approval discipline: a natural-language topic becomes a
*collection plan* (source, query, limit) that the user confirms before any fetch runs.
Outbound fetches are pinned to the canonical hosts in `connector_registry` — the plan
can never steer the fetch to a user-supplied URL. API keys are referenced by environment
variable name only; secret material never enters the store, the page, or logs.
"""

from __future__ import annotations

import json
import re
import secrets
import time
import urllib.request
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from html import unescape
from threading import Lock
from typing import IO, TYPE_CHECKING, Final, Protocol, cast, override
from urllib.parse import quote_plus, urlsplit

from services.api.connector_registry import (
    CANONICAL_CONNECTOR_REGISTRY,
    ConnectorId,
)

if TYPE_CHECKING:
    from http.client import HTTPMessage, HTTPResponse

type Clock = Callable[[], datetime]

_KEY_ENV_PATTERN: Final = re.compile(r"^[A-Z][A-Z0-9_]{0,63}$")
_PROMPT_MAX_LENGTH: Final = 500
_QUERY_MAX_LENGTH: Final = 200
_LIMIT_DEFAULT: Final = 5
_LIMIT_MAX: Final = 25
_PLAN_TTL: Final = timedelta(minutes=10)
_FETCH_TIMEOUT_SECONDS: Final = 8.0
_FETCH_MAX_BYTES: Final = 1_000_000
_USER_AGENT: Final = "nipo-science/0.1 (local research workbench; +https://127.0.0.1)"

_UNKNOWN_CONNECTOR: Final = "unknown_connector"
_INVALID_KEY_ENV: Final = "invalid_key_env"
_KEY_NOT_ACCEPTED: Final = "key_not_accepted"
_INVALID_PROMPT: Final = "invalid_prompt"
_EMPTY_QUERY: Final = "empty_query"
_UNKNOWN_OR_EXPIRED_PLAN: Final = "unknown_or_expired_plan"
_FETCH_FAILED: Final = "collection_fetch_failed"
_UNKNOWN_COLLECTION: Final = "unknown_collection"
_INVALID_RECORD_SELECTION: Final = "invalid_record_selection"
_DUPLICATE_RECORD_SELECTION: Final = "duplicate_record_selection"
_SELECTION_EXCEEDS_RECORDS: Final = "selection_exceeds_records"
_REDIRECT_NOT_PINNED: Final = "redirect_not_pinned"
_INVALID_RATE_LIMIT: Final = "invalid_rate_limit"
_RECORD_ID_PATTERN: Final = re.compile(r"^r([1-9]\d*)$")
_PROMPT_LIMIT_PATTERN: Final = re.compile(r"(?:^|\s)(\d{1,2})(?=\s|$|개|건)")
_CSV_FORMULA_PREFIXES: Final = ("=", "+", "-", "@", "\t")


@dataclass(frozen=True)
class ConnectorDescriptor:
    """Static product-facing description of one literature connector."""

    connector_id: str
    label: str
    note: str
    accepts_key: bool
    default_enabled: bool


CONNECTOR_DESCRIPTORS: Final = (
    ConnectorDescriptor(
        connector_id=ConnectorId.ARXIV.value,
        label="arXiv",
        note="키 없이 사용 · 사전 등록 논문 검색",
        accepts_key=False,
        default_enabled=True,
    ),
    ConnectorDescriptor(
        connector_id=ConnectorId.OPENALEX.value,
        label="OpenAlex",
        note="키 없이 사용 가능 · 메일 등록 시 한도 상승",
        accepts_key=False,
        default_enabled=False,
    ),
    ConnectorDescriptor(
        connector_id=ConnectorId.PUBMED.value,
        label="PubMed (NCBI)",
        note="API 키 환경변수 등록 시 초당 3→10건",
        accepts_key=True,
        default_enabled=False,
    ),
    ConnectorDescriptor(
        connector_id=ConnectorId.SEMANTIC_SCHOLAR.value,
        label="Semantic Scholar",
        note="API 키 환경변수 등록 시 한도 상승 · 인용 메타 풍부",
        accepts_key=True,
        default_enabled=False,
    ),
    ConnectorDescriptor(
        connector_id=ConnectorId.EUROPE_PMC.value,
        label="Europe PMC",
        note="키 없이 사용 · 유럽 생명과학 문헌",
        accepts_key=False,
        default_enabled=False,
    ),
    ConnectorDescriptor(
        connector_id=ConnectorId.CORE.value,
        label="CORE",
        note="API 키 환경변수 필요 · 오픈액세스 전문",
        accepts_key=True,
        default_enabled=False,
    ),
    ConnectorDescriptor(
        connector_id=ConnectorId.CROSSREF.value,
        label="Crossref",
        note="키 없이 사용 · DOI 메타데이터",
        accepts_key=False,
        default_enabled=False,
    ),
)
_DESCRIPTOR_BY_ID: Final = {d.connector_id: d for d in CONNECTOR_DESCRIPTORS}


@dataclass(frozen=True)
class CollectionPlan:
    """A confirmed-or-pending fetch specification owned by one principal."""

    plan_id: str
    principal_id: str
    connector_id: str
    query: str
    limit: int
    expires_at: datetime


@dataclass(frozen=True)
class CollectedDocument:
    """One structured literature document ready for CSV materialization."""

    title: str
    authors: tuple[str, ...]
    year: int | None
    venue: str | None
    citation_count: int | None
    abstract: str | None
    url: str | None


class CollectionFetcher(Protocol):
    """Outbound boundary: returns normalized records for a confirmed plan."""

    def __call__(
        self, connector_id: str, query: str, limit: int, /
    ) -> list[CollectedDocument]:
        """Return normalized records for one confirmed plan."""
        ...


class ConnectorSettingsError(ValueError):
    """Raised when a connector mutation or plan violates the contract."""


class ConnectorSettingsStore:
    """Thread-safe per-principal connector enablement and key-env references."""

    def __init__(self) -> None:
        """Initialize empty per-principal settings."""
        self._lock: Lock = Lock()
        self._settings: dict[str, dict[str, dict[str, object]]] = {}

    def list_for(self, principal_id: str) -> list[dict[str, object]]:
        """Return every descriptor merged with the principal's saved state."""
        with self._lock:
            saved = dict(self._settings.get(principal_id, {}))
        items: list[dict[str, object]] = []
        for descriptor in CONNECTOR_DESCRIPTORS:
            state = saved.get(descriptor.connector_id, {})
            items.append(
                {
                    "connector_id": descriptor.connector_id,
                    "label": descriptor.label,
                    "note": descriptor.note,
                    "accepts_key": descriptor.accepts_key,
                    "enabled": bool(
                        state.get("enabled", descriptor.default_enabled)
                    ),
                    "key_env": state.get("key_env") or None,
                    "last_success_at": _iso_or_none(state.get("last_success_at")),
                    "last_failure_at": _iso_or_none(state.get("last_failure_at")),
                }
            )
        return items

    def update(
        self,
        principal_id: str,
        connector_id: str,
        *,
        enabled: bool,
        key_env: str | None = None,
    ) -> dict[str, object]:
        """Persist one connector's state; fail closed on bad ids or env names."""
        validate_connector_update(connector_id, key_env)
        with self._lock:
            bucket = self._settings.setdefault(principal_id, {})
            previous = bucket.get(connector_id, {})
            bucket[connector_id] = {
                "enabled": enabled,
                "key_env": key_env,
                "last_success_at": previous.get("last_success_at"),
                "last_failure_at": previous.get("last_failure_at"),
            }
        return {
            "connector_id": connector_id,
            "enabled": enabled,
            "key_env": key_env,
        }

    def is_enabled(self, principal_id: str, connector_id: str) -> bool:
        """Return whether the principal enabled this connector."""
        for item in self.list_for(principal_id):
            if item["connector_id"] == connector_id:
                return bool(item["enabled"])
        return False

    def enabled_ids(self, principal_id: str) -> list[str]:
        """Return the principal's enabled connector ids in descriptor order."""
        return [
            str(item["connector_id"])
            for item in self.list_for(principal_id)
            if item["enabled"]
        ]

    def record_fetch_outcome(
        self,
        principal_id: str,
        connector_id: str,
        *,
        succeeded: bool,
        at: datetime,
    ) -> None:
        """Record the latest live-fetch outcome timestamp for one connector."""
        if connector_id not in _DESCRIPTOR_BY_ID:
            raise ConnectorSettingsError(_UNKNOWN_CONNECTOR)
        with self._lock:
            bucket = self._settings.setdefault(principal_id, {})
            state = dict(bucket.get(connector_id, {}))
            state["last_success_at" if succeeded else "last_failure_at"] = at
            bucket[connector_id] = state


_SOURCE_WORDS: Final = {
    "arxiv": ConnectorId.ARXIV.value,
    "알카이브": ConnectorId.ARXIV.value,
    "openalex": ConnectorId.OPENALEX.value,
    "오픈알렉스": ConnectorId.OPENALEX.value,
    "pubmed": ConnectorId.PUBMED.value,
    "펍메드": ConnectorId.PUBMED.value,
    "semanticscholar": ConnectorId.SEMANTIC_SCHOLAR.value,
    "semantic scholar": ConnectorId.SEMANTIC_SCHOLAR.value,
    "시맨틱": ConnectorId.SEMANTIC_SCHOLAR.value,
    "europepmc": ConnectorId.EUROPE_PMC.value,
    "europe pmc": ConnectorId.EUROPE_PMC.value,
    "유럽pmc": ConnectorId.EUROPE_PMC.value,
    "코어": ConnectorId.CORE.value,
    "crossref": ConnectorId.CROSSREF.value,
    "크로스레프": ConnectorId.CROSSREF.value,
}
_NOISE_WORDS: Final = (
    "수집해줘",
    "수집해 줘",
    "수집",
    "가져와줘",
    "가져와 줘",
    "가져와",
    "검색해줘",
    "검색해 줘",
    "검색",
    "모아줘",
    "모아 줘",
    "찾아줘",
    "찾아 줘",
    "찾아",
    "해줘",
    "해 주세요",
    "주세요",
    "논문",
    "문헌",
    "자료",
    "개",
    "건",
)


def parse_collection_prompt(prompt: str) -> tuple[str | None, str, int]:
    """Parse a natural-language collection request into (source hint, query, limit).

    Deterministic and transparent: the confirmation card shows exactly this parse,
    so the user can correct it before anything is fetched. Only a standalone
    count token (``5``, ``5개``, ``3건``) sets the limit; digits embedded in
    words like ``COVID19`` or oversized counts like ``1000000개`` stay query text.
    """
    text = prompt.strip()
    if not text or len(text) > _PROMPT_MAX_LENGTH:
        raise ConnectorSettingsError(_INVALID_PROMPT)

    source_hint: str | None = None
    for word, connector_id in _SOURCE_WORDS.items():
        if word in text.lower():
            source_hint = connector_id
            text = re.sub(re.escape(word), " ", text, flags=re.IGNORECASE)
            break

    limit = _LIMIT_DEFAULT
    match = _PROMPT_LIMIT_PATTERN.search(text)
    if match:
        limit = max(1, min(_LIMIT_MAX, int(match.group(1))))
        text = text[: match.start(1)] + " " + text[match.end(1) :]

    query = text
    for noise in _NOISE_WORDS:
        query = query.replace(noise, " ")
    query = re.sub(r"\s+", " ", query).strip(" ,.")
    if not query or len(query) > _QUERY_MAX_LENGTH:
        raise ConnectorSettingsError(_EMPTY_QUERY)
    return source_hint, query, limit


class CollectionPlanStore:
    """One-shot, TTL-bound collection plans; execute consumes the plan."""

    def __init__(self, clock: Clock = lambda: datetime.now(UTC)) -> None:
        """Initialize the plan store with the supplied clock."""
        self._clock: Clock = clock
        self._lock: Lock = Lock()
        self._plans: dict[str, CollectionPlan] = {}

    def create(
        self, principal_id: str, connector_id: str, query: str, limit: int
    ) -> CollectionPlan:
        """Create and retain a plan for one principal."""
        plan = CollectionPlan(
            plan_id=secrets.token_urlsafe(16),
            principal_id=principal_id,
            connector_id=connector_id,
            query=query,
            limit=limit,
            expires_at=self._clock() + _PLAN_TTL,
        )
        with self._lock:
            self._plans[plan.plan_id] = plan
        return plan

    def consume(self, principal_id: str, plan_id: str) -> CollectionPlan:
        """Return the plan once; unknown, foreign, or expired plans fail closed.

        Validation precedes removal: a foreign or mistyped attempt never burns
        the owner's pending plan.
        """
        with self._lock:
            plan = self._plans.get(plan_id)
            if (
                plan is None
                or plan.principal_id != principal_id
                or plan.expires_at <= self._clock()
            ):
                raise ConnectorSettingsError(_UNKNOWN_OR_EXPIRED_PLAN)
            return self._plans.pop(plan_id)


@dataclass(frozen=True)
class StoredCollection:
    """One persisted set of structured documents owned by one principal."""

    collection_id: str
    principal_id: str
    connector_id: str
    query: str
    created_at: datetime
    records: tuple[CollectedDocument, ...]


class CollectionStore:
    """Thread-safe per-principal store of collected document sets.

    Records are snapshotted into an immutable tuple on create; record ids are
    the positional ``r1``..``rN`` labels shared with the API contract.
    """

    def __init__(self, clock: Clock = lambda: datetime.now(UTC)) -> None:
        """Initialize the collection store with the supplied clock."""
        self._clock: Clock = clock
        self._lock: Lock = Lock()
        self._collections: dict[str, StoredCollection] = {}

    def create(
        self,
        principal_id: str,
        connector_id: str,
        query: str,
        records: Iterable[CollectedDocument],
    ) -> StoredCollection:
        """Persist one collection for one principal and return it."""
        collection = StoredCollection(
            collection_id=secrets.token_urlsafe(16),
            principal_id=principal_id,
            connector_id=connector_id,
            query=query,
            created_at=self._clock(),
            records=tuple(records),
        )
        with self._lock:
            self._collections[collection.collection_id] = collection
        return collection

    def list_for(self, principal_id: str) -> list[StoredCollection]:
        """Return every collection owned by the principal, oldest first."""
        with self._lock:
            return [
                collection
                for collection in self._collections.values()
                if collection.principal_id == principal_id
            ]

    def get(self, principal_id: str, collection_id: str) -> StoredCollection | None:
        """Return the collection only when the principal owns it."""
        with self._lock:
            collection = self._collections.get(collection_id)
        if collection is None or collection.principal_id != principal_id:
            return None
        return collection

    def materialize(
        self, principal_id: str, collection_id: str, record_ids: list[str]
    ) -> str:
        """Render the selected records of one owned collection as CSV.

        Unknown or foreign collections, empty, duplicate, or oversized
        selections, and out-of-range or malformed record ids all fail closed
        with ConnectorSettingsError.
        """
        return materialize_owned_selection(
            self.get(principal_id, collection_id), record_ids
        )


class ConnectorSettingsBackend(Protocol):
    """Storage boundary for per-principal connector settings."""

    def list_for(self, principal_id: str) -> list[dict[str, object]]:
        """Return every descriptor merged with the principal's saved state."""
        ...

    def update(
        self,
        principal_id: str,
        connector_id: str,
        *,
        enabled: bool,
        key_env: str | None = None,
    ) -> dict[str, object]:
        """Persist one connector's state; fail closed on contract violations."""
        ...

    def is_enabled(self, principal_id: str, connector_id: str) -> bool:
        """Return whether the principal enabled this connector."""
        ...

    def enabled_ids(self, principal_id: str) -> list[str]:
        """Return the principal's enabled connector ids in descriptor order."""
        ...

    def record_fetch_outcome(
        self,
        principal_id: str,
        connector_id: str,
        *,
        succeeded: bool,
        at: datetime,
    ) -> None:
        """Record the latest live-fetch outcome timestamp for one connector."""
        ...


class CollectionBackend(Protocol):
    """Storage boundary for immutable collected document sets."""

    def create(
        self,
        principal_id: str,
        connector_id: str,
        query: str,
        records: Iterable[CollectedDocument],
    ) -> StoredCollection:
        """Persist one collection for one principal and return it."""
        ...

    def list_for(self, principal_id: str) -> list[StoredCollection]:
        """Return every collection owned by the principal, oldest first."""
        ...

    def get(self, principal_id: str, collection_id: str) -> StoredCollection | None:
        """Return the collection only when the principal owns it."""
        ...

    def materialize(
        self, principal_id: str, collection_id: str, record_ids: list[str]
    ) -> str:
        """Render the selected records of one owned collection as CSV."""
        ...


def validate_connector_update(connector_id: str, key_env: str | None) -> None:
    """Fail closed when a connector mutation violates the contract."""
    descriptor = _DESCRIPTOR_BY_ID.get(connector_id)
    if descriptor is None:
        raise ConnectorSettingsError(_UNKNOWN_CONNECTOR)
    if key_env is not None and not _KEY_ENV_PATTERN.fullmatch(key_env):
        raise ConnectorSettingsError(_INVALID_KEY_ENV)
    if key_env and not descriptor.accepts_key:
        raise ConnectorSettingsError(_KEY_NOT_ACCEPTED)


def materialize_owned_selection(
    collection: StoredCollection | None, record_ids: list[str]
) -> str:
    """Render the selected records of one owned collection as CSV.

    ``None`` hides unknown or foreign collections; empty, duplicate, or
    oversized selections and malformed or out-of-range record ids all fail
    closed with ConnectorSettingsError.
    """
    if not record_ids:
        raise ConnectorSettingsError(_INVALID_RECORD_SELECTION)
    if collection is None:
        raise ConnectorSettingsError(_UNKNOWN_COLLECTION)
    if len(record_ids) != len(set(record_ids)):
        raise ConnectorSettingsError(_DUPLICATE_RECORD_SELECTION)
    if len(record_ids) > len(collection.records):
        raise ConnectorSettingsError(_SELECTION_EXCEEDS_RECORDS)
    selected: list[CollectedDocument] = []
    for record_id in record_ids:
        match = _RECORD_ID_PATTERN.fullmatch(record_id)
        if match is None:
            raise ConnectorSettingsError(_INVALID_RECORD_SELECTION)
        index = int(match.group(1)) - 1
        if index >= len(collection.records):
            raise ConnectorSettingsError(_INVALID_RECORD_SELECTION)
        selected.append(collection.records[index])
    return materialize_csv(collection.connector_id, selected)


def _iso_or_none(value: object) -> str | None:
    """Return the ISO text of a datetime value, else None."""
    return value.isoformat() if isinstance(value, datetime) else None


class PinnedRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Follow redirects only while the target stays on the pinned host."""

    @override
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: IO[bytes],
        code: int,
        msg: str,
        headers: HTTPMessage,
        newurl: str,
    ) -> urllib.request.Request | None:
        """Re-verify the redirect target against the request's pinned host."""
        if urlsplit(newurl).netloc != urlsplit(req.full_url).netloc:
            raise ConnectorSettingsError(_REDIRECT_NOT_PINNED)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


_OPENER: Final = urllib.request.build_opener(PinnedRedirectHandler())


def _read_bounded(url: str) -> bytes:
    """GET one canonical URL with an explicit agent, timeout, and byte budget.

    Redirects never leave the pinned connector host; a cross-host Location
    fails closed with ``redirect_not_pinned`` instead of being followed.
    """
    request = urllib.request.Request(  # noqa: S310 — scheme and host are pinned to the ConnectorBaseUrl enum
        url, headers={"User-Agent": _USER_AGENT}
    )
    response = cast(
        "HTTPResponse", _OPENER.open(request, timeout=_FETCH_TIMEOUT_SECONDS)
    )
    with response:
        return response.read(_FETCH_MAX_BYTES + 1)[:_FETCH_MAX_BYTES]


def _arxiv_text(tag: str, chunk: str) -> str | None:
    """Lift one plain-text tag body from an arXiv entry chunk."""
    match = re.search(rf"<{tag}>(?P<text>.*?)</{tag}>", chunk, re.DOTALL)
    if match is None:
        return None
    text = re.sub(r"\s+", " ", unescape(match.group("text"))).strip()
    return text or None


def arxiv_documents(feed_text: str, limit: int) -> list[CollectedDocument]:
    """Extract structured documents from the arXiv Atom feed without an XML parser.

    Only plain-text fields are lifted from each `<entry>`; markup structure is
    never interpreted, so malicious XML has no parser to attack.
    """
    documents: list[CollectedDocument] = []
    for chunk in feed_text.split("<entry>")[1 : limit + 1]:
        title = _arxiv_text("title", chunk) or f"arXiv 결과 {len(documents) + 1}"
        raw_names = cast(
            "list[str]",
            re.findall(r"<name>(?P<name>.*?)</name>", chunk, re.DOTALL),
        )
        authors = tuple(
            name
            for name in (
                re.sub(r"\s+", " ", unescape(raw)).strip() for raw in raw_names
            )
            if name
        )
        published = re.search(r"<published>(\d{4})", chunk)
        documents.append(
            CollectedDocument(
                title=title,
                authors=authors,
                year=int(published.group(1)) if published else None,
                venue=None,
                citation_count=None,
                abstract=_arxiv_text("summary", chunk),
                url=_arxiv_text("id", chunk),
            )
        )
    return documents


def _as_int(value: object) -> int | None:
    """Return the value only when it is a genuine integer."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _as_text(value: object) -> str | None:
    """Return a stripped string, or None for missing or blank values."""
    return value.strip() if isinstance(value, str) and value.strip() else None


def _as_mapping(value: object) -> dict[str, object] | None:
    """Return the value as a string-keyed mapping, else None."""
    if not isinstance(value, dict):
        return None
    return cast("dict[str, object]", value)


def _as_list(value: object) -> list[object] | None:
    """Return the value as a plain list, else None."""
    if not isinstance(value, list):
        return None
    return cast("list[object]", value)


def _loads_mapping(raw: bytes) -> dict[str, object]:
    """Decode a JSON object payload, failing closed on a non-object root."""
    decoded = cast("object", json.loads(raw))
    mapping = _as_mapping(decoded)
    if mapping is None:
        raise ValueError(_FETCH_FAILED)
    return mapping


def _openalex_authors(work: Mapping[str, object]) -> tuple[str, ...]:
    """Collect author display names from one OpenAlex work."""
    names: list[str] = []
    for entry in _as_list(work.get("authorships")) or ():
        entry_map = _as_mapping(entry)
        if entry_map is None:
            continue
        author = _as_mapping(entry_map.get("author"))
        if author is None:
            continue
        name = _as_text(author.get("display_name"))
        if name is not None:
            names.append(name)
    return tuple(names)


def _openalex_venue(work: Mapping[str, object]) -> str | None:
    """Return the primary source display name of one OpenAlex work."""
    location = _as_mapping(work.get("primary_location"))
    if location is None:
        return None
    source = _as_mapping(location.get("source"))
    if source is None:
        return None
    return _as_text(source.get("display_name"))


def _openalex_abstract(inverted: object) -> str | None:
    """Rebuild the abstract text from OpenAlex's inverted index, if present."""
    mapping = _as_mapping(inverted)
    if mapping is None:
        return None
    positions: dict[int, str] = {}
    for word, places in mapping.items():
        place_list = _as_list(places)
        if place_list is None:
            continue
        for place in place_list:
            if isinstance(place, int) and not isinstance(place, bool):
                _ = positions.setdefault(place, word)
    if not positions:
        return None
    return " ".join(word for _position, word in sorted(positions.items()))


def openalex_documents(
    payload: Mapping[str, object], limit: int
) -> list[CollectedDocument]:
    """Normalize an OpenAlex /works payload into structured documents."""
    results = _as_list(payload.get("results"))
    if results is None:
        return []
    documents: list[CollectedDocument] = []
    for work in results[:limit]:
        work_map = _as_mapping(work)
        if work_map is None:
            continue
        title = _as_text(work_map.get("display_name"))
        url = _as_text(work_map.get("doi")) or _as_text(work_map.get("id"))
        documents.append(
            CollectedDocument(
                title=title or f"OpenAlex 결과 {len(documents) + 1}",
                authors=_openalex_authors(work_map),
                year=_as_int(work_map.get("publication_year")),
                venue=_openalex_venue(work_map),
                citation_count=_as_int(work_map.get("cited_by_count")),
                abstract=_openalex_abstract(work_map.get("abstract_inverted_index")),
                url=url,
            )
        )
    return documents


def pubmed_documents(
    payload: Mapping[str, object], id_list: list[str], base_url: str
) -> list[CollectedDocument]:
    """Normalize a PubMed esummary payload into structured documents."""
    result = _as_mapping(payload.get("result"))
    if result is None:
        return []
    documents: list[CollectedDocument] = []
    for pmid in id_list:
        entry = _as_mapping(result.get(pmid))
        if entry is None:
            continue
        names: list[str] = []
        for author in _as_list(entry.get("authors")) or ():
            author_map = _as_mapping(author)
            if author_map is None:
                continue
            name = _as_text(author_map.get("name"))
            if name is not None:
                names.append(name)
        year: int | None = None
        pubdate = entry.get("pubdate")
        if isinstance(pubdate, str):
            match = re.search(r"(\d{4})", pubdate)
            if match is not None:
                year = int(match.group(1))
        title = _as_text(entry.get("title"))
        documents.append(
            CollectedDocument(
                title=title or f"PubMed PMID {pmid}",
                authors=tuple(names),
                year=year,
                venue=_as_text(entry.get("source")),
                citation_count=None,
                abstract=None,
                url=f"{base_url}/{pmid}/",
            )
        )
    return documents


class TokenBucket:
    """Blocking token bucket: one token per request, refilled at a fixed rate."""

    def __init__(
        self,
        rate_per_second: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleeper: Callable[[float], None] = time.sleep,
    ) -> None:
        """Create a bucket with capacity for a single immediate request."""
        if rate_per_second <= 0:
            raise ConnectorSettingsError(_INVALID_RATE_LIMIT)
        self._rate: float = rate_per_second
        self._clock: Callable[[], float] = clock
        self._sleeper: Callable[[float], None] = sleeper
        self._lock: Lock = Lock()
        self._tokens: float = 1.0
        self._updated_at: float = clock()

    def acquire(self) -> None:
        """Take one token, sleeping until the bucket refills when empty."""
        with self._lock:
            now = self._clock()
            self._tokens = min(
                1.0, self._tokens + (now - self._updated_at) * self._rate
            )
            self._updated_at = now
            if self._tokens >= 1.0:
                self._tokens -= 1.0
                return
            wait = (1.0 - self._tokens) / self._rate
            self._tokens = 0.0
            self._updated_at = now + wait
        self._sleeper(wait)


_LIVE_RATE_LIMIT: Final = 1.0
_LIVE_LIMITERS: dict[ConnectorId, TokenBucket] = {}
_LIVE_LIMITERS_LOCK: Final = Lock()


def _live_limiter(connector: ConnectorId) -> TokenBucket:
    """Return the per-connector live-fetch limiter, creating it lazily."""
    with _LIVE_LIMITERS_LOCK:
        limiter = _LIVE_LIMITERS.get(connector)
        if limiter is None:
            limiter = TokenBucket(_LIVE_RATE_LIMIT)
            _LIVE_LIMITERS[connector] = limiter
        return limiter


def configure_live_rate_limit(connector_id: str, rate_per_second: float) -> None:
    """Set the live-fetch politeness rate for one connector (requests/second)."""
    try:
        connector = ConnectorId(connector_id)
    except ValueError as error:
        raise ConnectorSettingsError(_UNKNOWN_CONNECTOR) from error
    with _LIVE_LIMITERS_LOCK:
        _LIVE_LIMITERS[connector] = TokenBucket(rate_per_second)


def semantic_scholar_documents(
    payload: Mapping[str, object], limit: int
) -> list[CollectedDocument]:
    """Normalize a Semantic Scholar paper-search payload into documents."""
    data = _as_list(payload.get("data"))
    if data is None:
        return []
    documents: list[CollectedDocument] = []
    for paper in data[:limit]:
        paper_map = _as_mapping(paper)
        if paper_map is None:
            continue
        names: list[str] = []
        for author in _as_list(paper_map.get("authors")) or ():
            author_map = _as_mapping(author)
            if author_map is None:
                continue
            name = _as_text(author_map.get("name"))
            if name is not None:
                names.append(name)
        title = _as_text(paper_map.get("title"))
        documents.append(
            CollectedDocument(
                title=title or f"Semantic Scholar 결과 {len(documents) + 1}",
                authors=tuple(names),
                year=_as_int(paper_map.get("year")),
                venue=_as_text(paper_map.get("venue")),
                citation_count=_as_int(paper_map.get("citationCount")),
                abstract=_as_text(paper_map.get("abstract")),
                url=_as_text(paper_map.get("url")),
            )
        )
    return documents


def _as_year(value: object) -> int | None:
    """Return a year from a genuine int or a digit-only string."""
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().isdigit():
        return int(value.strip())
    return None


def europe_pmc_documents(
    payload: Mapping[str, object], limit: int
) -> list[CollectedDocument]:
    """Normalize an Europe PMC search payload into structured documents."""
    result_list = _as_mapping(payload.get("resultList"))
    results = _as_list(result_list.get("result")) if result_list else None
    if results is None:
        return []
    documents: list[CollectedDocument] = []
    for entry in results[:limit]:
        entry_map = _as_mapping(entry)
        if entry_map is None:
            continue
        author_string = _as_text(entry_map.get("authorString"))
        authors = tuple(
            name
            for name in (
                part.strip().rstrip(".")
                for part in (author_string or "").split(",")
            )
            if name
        )
        doi = _as_text(entry_map.get("doi"))
        source = _as_text(entry_map.get("source"))
        record_id = _as_text(entry_map.get("id"))
        url = (
            f"https://doi.org/{doi}"
            if doi
            else (
                f"https://europepmc.org/article/{source}/{record_id}"
                if source and record_id
                else None
            )
        )
        title = _as_text(entry_map.get("title"))
        documents.append(
            CollectedDocument(
                title=title or f"Europe PMC 결과 {len(documents) + 1}",
                authors=authors,
                year=_as_year(entry_map.get("pubYear")),
                venue=_as_text(entry_map.get("journalTitle")),
                citation_count=_as_int(entry_map.get("citedByCount")),
                abstract=_as_text(entry_map.get("abstractText")),
                url=url,
            )
        )
    return documents


def core_documents(
    payload: Mapping[str, object], limit: int
) -> list[CollectedDocument]:
    """Normalize a CORE /v3/search/works payload into structured documents."""
    results = _as_list(payload.get("results"))
    if results is None:
        return []
    documents: list[CollectedDocument] = []
    for work in results[:limit]:
        work_map = _as_mapping(work)
        if work_map is None:
            continue
        names: list[str] = []
        for author in _as_list(work_map.get("authors")) or ():
            author_map = _as_mapping(author)
            name = (
                _as_text(author_map.get("name"))
                if author_map is not None
                else _as_text(author)
            )
            if name is not None:
                names.append(name)
        title = _as_text(work_map.get("title"))
        documents.append(
            CollectedDocument(
                title=title or f"CORE 결과 {len(documents) + 1}",
                authors=tuple(names),
                year=_as_year(work_map.get("yearPublished")),
                venue=_as_text(work_map.get("publisher")),
                citation_count=_as_int(work_map.get("citationCount")),
                abstract=_as_text(work_map.get("abstract")),
                url=(
                    _as_text(work_map.get("downloadUrl"))
                    or _as_text(work_map.get("doi"))
                ),
            )
        )
    return documents


def _crossref_abstract(value: object) -> str | None:
    """Strip JATS markup from a Crossref abstract, if present."""
    raw = _as_text(value)
    if raw is None:
        return None
    text = re.sub(r"<[^>]+>", " ", raw)
    return re.sub(r"\s+", " ", unescape(text)).strip() or None


def crossref_documents(
    payload: Mapping[str, object], limit: int
) -> list[CollectedDocument]:
    """Normalize a Crossref /works payload into structured documents."""
    message = _as_mapping(payload.get("message"))
    items = _as_list(message.get("items")) if message else None
    if items is None:
        return []
    documents: list[CollectedDocument] = []
    for work in items[:limit]:
        work_map = _as_mapping(work)
        if work_map is None:
            continue
        titles = _as_list(work_map.get("title"))
        title = _as_text(titles[0]) if titles else None
        names: list[str] = []
        for author in _as_list(work_map.get("author")) or ():
            author_map = _as_mapping(author)
            if author_map is None:
                continue
            name = " ".join(
                part
                for part in (
                    _as_text(author_map.get("given")),
                    _as_text(author_map.get("family")),
                )
                if part
            )
            if name:
                names.append(name)
        year: int | None = None
        published = _as_mapping(work_map.get("published"))
        date_parts = _as_list(published.get("date-parts")) if published else None
        first_parts = _as_list(date_parts[0]) if date_parts else None
        if first_parts:
            year = _as_int(first_parts[0])
        containers = _as_list(work_map.get("container-title"))
        venue = _as_text(containers[0]) if containers else None
        doi = _as_text(work_map.get("DOI"))
        documents.append(
            CollectedDocument(
                title=title or f"Crossref 결과 {len(documents) + 1}",
                authors=tuple(names),
                year=year,
                venue=venue,
                citation_count=_as_int(work_map.get("is-referenced-by-count")),
                abstract=_crossref_abstract(work_map.get("abstract")),
                url=_as_text(work_map.get("URL"))
                or (f"https://doi.org/{doi}" if doi else None),
            )
        )
    return documents


def _fetch_openalex(base: str, query: str, limit: int) -> list[CollectedDocument]:
    """Live-fetch structured documents from OpenAlex."""
    _live_limiter(ConnectorId.OPENALEX).acquire()
    payload = _loads_mapping(
        _read_bounded(f"{base}/works?search={quote_plus(query)}&per-page={limit}")
    )
    return openalex_documents(payload, limit)


def _fetch_pubmed(base: str, query: str, limit: int) -> list[CollectedDocument]:
    """Live-fetch structured documents via PubMed esearch + esummary."""
    _live_limiter(ConnectorId.PUBMED).acquire()
    search_payload = _loads_mapping(
        _read_bounded(
            f"{base}/entrez/eutils/esearch.fcgi?db=pubmed&retmode=json"
            f"&retmax={limit}&term={quote_plus(query)}"
        )
    )
    search_result = _as_mapping(search_payload.get("esearchresult"))
    id_list_raw = _as_list(search_result.get("idlist")) if search_result else None
    id_list = [str(pmid) for pmid in (id_list_raw or [])[:limit]]
    if not id_list:
        return []
    _live_limiter(ConnectorId.PUBMED).acquire()
    summary_payload = _loads_mapping(
        _read_bounded(
            f"{base}/entrez/eutils/esummary.fcgi?db=pubmed&retmode=json"
            f"&id={','.join(id_list)}"
        )
    )
    return pubmed_documents(summary_payload, id_list, base)


def _fetch_arxiv(base: str, query: str, limit: int) -> list[CollectedDocument]:
    """Live-fetch structured documents from the arXiv Atom feed."""
    _live_limiter(ConnectorId.ARXIV).acquire()
    feed_text = _read_bounded(
        f"{base}/api/query?search_query=all:{quote_plus(query)}"
        f"&max_results={limit}"
    ).decode("utf-8", errors="replace")
    return arxiv_documents(feed_text, limit)


def _fetch_semantic_scholar(
    base: str, query: str, limit: int
) -> list[CollectedDocument]:
    """Live-fetch structured documents from Semantic Scholar."""
    _live_limiter(ConnectorId.SEMANTIC_SCHOLAR).acquire()
    payload = _loads_mapping(
        _read_bounded(
            f"{base}/graph/v1/paper/search?query={quote_plus(query)}"
            f"&limit={limit}"
            "&fields=title,authors,year,venue,citationCount,abstract,url"
        )
    )
    return semantic_scholar_documents(payload, limit)


def _fetch_europe_pmc(base: str, query: str, limit: int) -> list[CollectedDocument]:
    """Live-fetch structured documents from Europe PMC."""
    _live_limiter(ConnectorId.EUROPE_PMC).acquire()
    payload = _loads_mapping(
        _read_bounded(
            f"{base}/europepmc/webservices/rest/search"
            f"?query={quote_plus(query)}&format=json&pageSize={limit}"
        )
    )
    return europe_pmc_documents(payload, limit)


def _fetch_core(base: str, query: str, limit: int) -> list[CollectedDocument]:
    """Live-fetch structured documents from CORE."""
    _live_limiter(ConnectorId.CORE).acquire()
    payload = _loads_mapping(
        _read_bounded(f"{base}/v3/search/works?q={quote_plus(query)}&limit={limit}")
    )
    return core_documents(payload, limit)


def _fetch_crossref(base: str, query: str, limit: int) -> list[CollectedDocument]:
    """Live-fetch structured documents from Crossref."""
    _live_limiter(ConnectorId.CROSSREF).acquire()
    payload = _loads_mapping(
        _read_bounded(f"{base}/works?query={quote_plus(query)}&rows={limit}")
    )
    return crossref_documents(payload, limit)


type LiveFetchHandler = Callable[[str, str, int], list[CollectedDocument]]

_LIVE_FETCH_HANDLERS: Final = {
    ConnectorId.OPENALEX: _fetch_openalex,
    ConnectorId.PUBMED: _fetch_pubmed,
    ConnectorId.ARXIV: _fetch_arxiv,
    ConnectorId.SEMANTIC_SCHOLAR: _fetch_semantic_scholar,
    ConnectorId.EUROPE_PMC: _fetch_europe_pmc,
    ConnectorId.CORE: _fetch_core,
    ConnectorId.CROSSREF: _fetch_crossref,
}


def live_collection_fetcher(
    connector_id: str, query: str, limit: int
) -> list[CollectedDocument]:
    """Fetch structured documents from the canonical host for `connector_id`.

    The URL is constructed only from the registry's pinned host plus the parsed
    query; there is no caller-controlled base URL anywhere on this path. Every
    outbound call passes through the connector's token-bucket rate limiter.
    """
    try:
        connector = ConnectorId(connector_id)
    except ValueError as error:
        raise ConnectorSettingsError(_UNKNOWN_CONNECTOR) from error
    handler = _LIVE_FETCH_HANDLERS.get(connector)
    if handler is None:
        raise ConnectorSettingsError(_UNKNOWN_CONNECTOR)
    return handler(CANONICAL_CONNECTOR_REGISTRY[connector], query, limit)


@dataclass(frozen=True)
class _FixtureProfile:
    """Deterministic bibliographic shape used by the offline fixture fetcher."""

    authors: tuple[str, ...]
    year: int
    venue: str
    citation_count: int


_FIXTURE_PROFILES: Final = (
    _FixtureProfile(
        authors=("Kim, Yuna", "Lee, Junho"),
        year=2024,
        venue="Journal of Fixture Studies",
        citation_count=42,
    ),
    _FixtureProfile(
        authors=("Park, Seoyeon",),
        year=2023,
        venue="Fixture Review Letters",
        citation_count=7,
    ),
    _FixtureProfile(
        authors=("Choi, Minjun", "Han, Jiwon", "No, Yeseo"),
        year=2022,
        venue="Annals of Fixture Science",
        citation_count=0,
    ),
)


def fixture_collection_fetcher(
    connector_id: str, query: str, limit: int
) -> list[CollectedDocument]:
    """Deterministic offline fetcher for fixture journeys and tests."""
    descriptor = _DESCRIPTOR_BY_ID.get(connector_id)
    if descriptor is None:
        raise ConnectorSettingsError(_UNKNOWN_CONNECTOR)
    base = CANONICAL_CONNECTOR_REGISTRY[ConnectorId(connector_id)]
    documents: list[CollectedDocument] = []
    for index in range(limit):
        profile = _FIXTURE_PROFILES[index % len(_FIXTURE_PROFILES)]
        documents.append(
            CollectedDocument(
                title=f"{query} — {descriptor.label} 수집 결과 {index + 1}",
                authors=profile.authors,
                year=profile.year,
                venue=profile.venue,
                citation_count=profile.citation_count,
                abstract=(
                    f"'{query}' 주제의 {descriptor.label} 수집 요약 {index + 1}."
                ),
                url=f"{base}/fixture/{index + 1}",
            )
        )
    return documents


def _csv_cell(value: str) -> str:
    """Normalize, defuse, and quote one CSV cell.

    A leading spreadsheet-formula marker (``=``, ``+``, ``-``, ``@``, tab) is
    neutralized with a ``'`` prefix so Excel/Sheets render the text literally.
    """
    cell = re.sub(r"[\r\n]+", " ", value).strip()
    if cell.startswith(_CSV_FORMULA_PREFIXES):
        cell = f"'{cell}"
    if "," in cell or '"' in cell:
        cell = '"' + cell.replace('"', '""') + '"'
    return cell


def materialize_csv(connector_id: str, records: list[CollectedDocument]) -> str:
    """Render records as the calibrated CSV shape the run input validator accepts."""
    if connector_id not in _DESCRIPTOR_BY_ID:
        raise ConnectorSettingsError(_UNKNOWN_CONNECTOR)
    lines = ["sample,value,calibration"]
    for index, record in enumerate(records):
        title = _csv_cell(record.title) or "untitled"
        value = (
            record.citation_count
            if record.citation_count is not None
            else index + 1
        )
        lines.append(f"{title},{value},{connector_id}")
    return "\n".join(lines) + "\n"
