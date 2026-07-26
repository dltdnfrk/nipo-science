"""Production entry wiring for the local single-owner product server.

Covers ``tools/run_product_server.build_production_options``: real local
deployments must get the SQLite-backed connector stores (``data/nipo.db`` by
default), never the in-memory fixture defaults.
"""

from __future__ import annotations

from pathlib import Path

from services.api.product_connector_persistence import (
    DEFAULT_DB_PATH,
    SqliteCollectionStore,
    SqliteConnectorSettingsStore,
)
from services.api.product_connectors import CollectedDocument
from tools.run_product_server import build_production_options


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


def test_production_options_use_sqlite_stores_at_default_path() -> None:
    options = build_production_options()
    assert isinstance(options.connector_settings, SqliteConnectorSettingsStore)
    assert isinstance(options.collections, SqliteCollectionStore)
    assert Path("data/nipo.db") == DEFAULT_DB_PATH


def test_production_options_persist_across_rebuilds(tmp_path: Path) -> None:
    db_path = tmp_path / "nipo.db"
    options = build_production_options(db_path)
    assert options.connector_settings is not None
    assert options.collections is not None
    updated = options.connector_settings.update("u1", "openalex", enabled=True)
    assert updated["enabled"] is True
    created = options.collections.create("u1", "openalex", "정규화", [_document("p1")])

    rebuilt = build_production_options(db_path)
    assert rebuilt.connector_settings is not None
    assert rebuilt.collections is not None
    assert rebuilt.connector_settings.is_enabled("u1", "openalex") is True
    persisted = rebuilt.collections.list_for("u1")
    assert [item.collection_id for item in persisted] == [created.collection_id]
    assert [record.title for record in persisted[0].records] == ["p1"]
