"""SQLite-backed connector settings and collection stores for local persistence.

The product runs as a single-owner local server, so one SQLite file
(``data/nipo.db`` by default) is the entire persistence layer for connector
configuration and collected document sets. Both stores expose exactly the
in-memory stores' interface; the fixture default stays in-memory and real
deployments inject these through ``ProductServerOptions``. Collection plans
stay in-memory by design (one-shot, TTL-bound).
"""

from __future__ import annotations

import json
import secrets
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final, cast

if TYPE_CHECKING:
    from collections.abc import Iterable

from services.api.product_connectors import (
    CONNECTOR_DESCRIPTORS,
    Clock,
    CollectedDocument,
    StoredCollection,
    materialize_owned_selection,
    validate_connector_update,
)

DEFAULT_DB_PATH: Final = Path("data/nipo.db")
_CORRUPT_STORE_ROW: Final = "corrupt_store_row"

_SCHEMA: Final = """
CREATE TABLE IF NOT EXISTS connector_settings (
    principal_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    enabled INTEGER NOT NULL,
    key_env TEXT,
    PRIMARY KEY (principal_id, connector_id)
);
CREATE TABLE IF NOT EXISTS collections (
    collection_id TEXT PRIMARY KEY,
    principal_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    query TEXT NOT NULL,
    created_at TEXT NOT NULL,
    records_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS connector_fetch_outcomes (
    principal_id TEXT NOT NULL,
    connector_id TEXT NOT NULL,
    last_success_at TEXT,
    last_failure_at TEXT,
    PRIMARY KEY (principal_id, connector_id)
);
"""


def initialize_connector_schema(db_path: Path) -> None:
    """Create the database file, parent directory, and schema idempotently."""
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(db_path)) as connection:
        _ = connection.executescript(_SCHEMA)


def _rows(cursor: sqlite3.Cursor) -> list[tuple[object, ...]]:
    """Materialize a cursor as plain object tuples for typed validation."""
    return cast("list[tuple[object, ...]]", cursor.fetchall())


def _optional_text(value: object) -> str | None:
    """Return the value only when it is a string."""
    return value if isinstance(value, str) else None


def _optional_int(value: object) -> int | None:
    """Return the value only when it is a genuine integer."""
    return value if isinstance(value, int) and not isinstance(value, bool) else None


def _document_json(document: CollectedDocument) -> dict[str, object]:
    """Serialize one document to its storage shape."""
    return {
        "title": document.title,
        "authors": list(document.authors),
        "year": document.year,
        "venue": document.venue,
        "citation_count": document.citation_count,
        "abstract": document.abstract,
        "url": document.url,
    }


def _document_from_json(value: object) -> CollectedDocument:
    """Parse one stored document, failing closed on corruption."""
    if not isinstance(value, dict):
        raise TypeError(_CORRUPT_STORE_ROW)
    mapping = cast("dict[str, object]", value)
    title = mapping.get("title")
    authors_value = mapping.get("authors")
    if not isinstance(title, str) or not isinstance(authors_value, list):
        raise TypeError(_CORRUPT_STORE_ROW)
    authors_raw = cast("list[object]", authors_value)
    if not all(isinstance(author, str) for author in authors_raw):
        raise ValueError(_CORRUPT_STORE_ROW)
    return CollectedDocument(
        title=title,
        authors=cast("tuple[str, ...]", tuple(authors_raw)),
        year=_optional_int(mapping.get("year")),
        venue=_optional_text(mapping.get("venue")),
        citation_count=_optional_int(mapping.get("citation_count")),
        abstract=_optional_text(mapping.get("abstract")),
        url=_optional_text(mapping.get("url")),
    )


def _collection_from_row(row: tuple[object, ...]) -> StoredCollection:
    """Parse one collections row, failing closed on corruption."""
    (
        collection_id,
        principal_id,
        connector_id,
        query,
        created_at_raw,
        records_json,
    ) = row
    if not all(
        isinstance(value, str)
        for value in (
            collection_id,
            principal_id,
            connector_id,
            query,
            created_at_raw,
            records_json,
        )
    ):
        raise ValueError(_CORRUPT_STORE_ROW)
    created_at = datetime.fromisoformat(cast("str", created_at_raw))
    decoded = cast("object", json.loads(cast("str", records_json)))
    if not isinstance(decoded, list):
        raise TypeError(_CORRUPT_STORE_ROW)
    records = tuple(
        _document_from_json(item) for item in cast("list[object]", decoded)
    )
    return StoredCollection(
        collection_id=cast("str", collection_id),
        principal_id=cast("str", principal_id),
        connector_id=cast("str", connector_id),
        query=cast("str", query),
        created_at=created_at,
        records=records,
    )


class SqliteConnectorSettingsStore:
    """SQLite-backed per-principal connector enablement and key-env references."""

    def __init__(self, db_path: Path = DEFAULT_DB_PATH) -> None:
        """Open the settings database, creating the schema on first use."""
        self._db_path: Path = db_path
        initialize_connector_schema(db_path)

    def _connect(self) -> sqlite3.Connection:
        """Open one short-lived connection (WAL keeps readers unblocked)."""
        connection = sqlite3.connect(self._db_path)
        _ = connection.execute("PRAGMA journal_mode=WAL")
        return connection

    def list_for(self, principal_id: str) -> list[dict[str, object]]:
        """Return every descriptor merged with the principal's saved state."""
        with closing(self._connect()) as connection:
            rows = _rows(
                connection.execute(
                    "SELECT connector_id, enabled, key_env"
                    " FROM connector_settings WHERE principal_id = ?",
                    (principal_id,),
                )
            )
            outcome_rows = _rows(
                connection.execute(
                    "SELECT connector_id, last_success_at, last_failure_at"
                    " FROM connector_fetch_outcomes WHERE principal_id = ?",
                    (principal_id,),
                )
            )
        saved: dict[str, tuple[bool, str | None]] = {}
        for row in rows:
            connector_id, enabled, key_env = row
            if not isinstance(connector_id, str) or not isinstance(enabled, int):
                raise TypeError(_CORRUPT_STORE_ROW)
            if key_env is not None and not isinstance(key_env, str):
                raise TypeError(_CORRUPT_STORE_ROW)
            saved[connector_id] = (bool(enabled), key_env)
        outcomes: dict[str, tuple[str | None, str | None]] = {}
        for row in outcome_rows:
            connector_id, last_success_at, last_failure_at = row
            if not isinstance(connector_id, str):
                raise TypeError(_CORRUPT_STORE_ROW)
            if last_success_at is not None and not isinstance(last_success_at, str):
                raise TypeError(_CORRUPT_STORE_ROW)
            if last_failure_at is not None and not isinstance(last_failure_at, str):
                raise TypeError(_CORRUPT_STORE_ROW)
            outcomes[connector_id] = (last_success_at, last_failure_at)
        items: list[dict[str, object]] = []
        for descriptor in CONNECTOR_DESCRIPTORS:
            state = saved.get(descriptor.connector_id)
            enabled, key_env = (
                state if state is not None else (descriptor.default_enabled, None)
            )
            last_success_at, last_failure_at = outcomes.get(
                descriptor.connector_id, (None, None)
            )
            items.append(
                {
                    "connector_id": descriptor.connector_id,
                    "label": descriptor.label,
                    "note": descriptor.note,
                    "accepts_key": descriptor.accepts_key,
                    "enabled": enabled,
                    "key_env": key_env,
                    "last_success_at": last_success_at,
                    "last_failure_at": last_failure_at,
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
        with closing(self._connect()) as connection, connection:
            _ = connection.execute(
                "INSERT INTO connector_settings"
                " (principal_id, connector_id, enabled, key_env)"
                " VALUES (?, ?, ?, ?)"
                " ON CONFLICT (principal_id, connector_id) DO UPDATE SET"
                " enabled = excluded.enabled, key_env = excluded.key_env",
                (principal_id, connector_id, int(enabled), key_env),
            )
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
        validate_connector_update(connector_id, None)
        with closing(self._connect()) as connection, connection:
            if succeeded:
                _ = connection.execute(
                    "INSERT INTO connector_fetch_outcomes"
                    " (principal_id, connector_id, last_success_at)"
                    " VALUES (?, ?, ?)"
                    " ON CONFLICT (principal_id, connector_id) DO UPDATE SET"
                    " last_success_at = excluded.last_success_at",
                    (principal_id, connector_id, at.isoformat()),
                )
            else:
                _ = connection.execute(
                    "INSERT INTO connector_fetch_outcomes"
                    " (principal_id, connector_id, last_failure_at)"
                    " VALUES (?, ?, ?)"
                    " ON CONFLICT (principal_id, connector_id) DO UPDATE SET"
                    " last_failure_at = excluded.last_failure_at",
                    (principal_id, connector_id, at.isoformat()),
                )


class SqliteCollectionStore:
    """SQLite-backed per-principal store of collected document sets.

    Records are serialized into one immutable JSON snapshot per collection;
    record ids stay the positional ``r1``..``rN`` labels shared with the API
    contract, so materialization semantics match the in-memory store exactly.
    """

    def __init__(
        self,
        db_path: Path = DEFAULT_DB_PATH,
        clock: Clock = lambda: datetime.now(UTC),
    ) -> None:
        """Open the collections database, creating the schema on first use."""
        self._db_path: Path = db_path
        self._clock: Clock = clock
        initialize_connector_schema(db_path)

    def _connect(self) -> sqlite3.Connection:
        """Open one short-lived connection (WAL keeps readers unblocked)."""
        connection = sqlite3.connect(self._db_path)
        _ = connection.execute("PRAGMA journal_mode=WAL")
        return connection

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
        records_json = json.dumps(
            [_document_json(record) for record in collection.records]
        )
        with closing(self._connect()) as connection, connection:
            _ = connection.execute(
                "INSERT INTO collections"
                " (collection_id, principal_id, connector_id, query,"
                " created_at, records_json)"
                " VALUES (?, ?, ?, ?, ?, ?)",
                (
                    collection.collection_id,
                    principal_id,
                    connector_id,
                    query,
                    collection.created_at.isoformat(),
                    records_json,
                ),
            )
        return collection

    def list_for(self, principal_id: str) -> list[StoredCollection]:
        """Return every collection owned by the principal, oldest first."""
        with closing(self._connect()) as connection:
            rows = _rows(
                connection.execute(
                    "SELECT collection_id, principal_id, connector_id, query,"
                    " created_at, records_json"
                    " FROM collections WHERE principal_id = ?"
                    " ORDER BY created_at ASC, collection_id ASC",
                    (principal_id,),
                )
            )
        return [_collection_from_row(row) for row in rows]

    def get(self, principal_id: str, collection_id: str) -> StoredCollection | None:
        """Return the collection only when the principal owns it."""
        with closing(self._connect()) as connection:
            rows = _rows(
                connection.execute(
                    "SELECT collection_id, principal_id, connector_id, query,"
                    " created_at, records_json"
                    " FROM collections WHERE collection_id = ?",
                    (collection_id,),
                )
            )
        if not rows:
            return None
        collection = _collection_from_row(rows[0])
        if collection.principal_id != principal_id:
            return None
        return collection

    def materialize(
        self, principal_id: str, collection_id: str, record_ids: list[str]
    ) -> str:
        """Render the selected records of one owned collection as CSV."""
        return materialize_owned_selection(
            self.get(principal_id, collection_id), record_ids
        )
