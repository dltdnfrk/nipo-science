"""Run the local single-owner product server with SQLite persistence.

Unlike the browser-journey fixture (``run_product_ui_fixture.py``), this entry
uses no authenticated fixture and no in-memory stores: connector settings and
collections live in ``data/nipo.db`` (see
``services/api/product_connector_persistence.py``), so they survive restarts.
"""

from __future__ import annotations

import os
from threading import Event
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from pathlib import Path

    from services.api.product_connectors import Clock

from services.api.product_app import (
    ProductServerOptions,
    run_product_server,
)
from services.api.product_connector_persistence import (
    DEFAULT_DB_PATH,
    SqliteCollectionStore,
    SqliteConnectorSettingsStore,
)

_DEFAULT_PORT: Final = 8790
_PORT_ENV: Final = "NIPO_PRODUCT_PORT"


def build_production_options(
    db_path: Path = DEFAULT_DB_PATH,
    clock: Clock | None = None,
) -> ProductServerOptions:
    """Wire the SQLite-backed connector stores used by real local deployments."""
    return ProductServerOptions(
        connector_settings=SqliteConnectorSettingsStore(db_path),
        collections=(
            SqliteCollectionStore(db_path)
            if clock is None
            else SqliteCollectionStore(db_path, clock)
        ),
    )


def main() -> None:
    """Serve the product locally until interrupted."""
    port = int(os.environ.get(_PORT_ENV, str(_DEFAULT_PORT)))
    server = run_product_server(
        ("127.0.0.1", port),
        options=build_production_options(),
    )
    try:
        _ = Event().wait()
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    main()
