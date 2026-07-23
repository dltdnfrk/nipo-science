from __future__ import annotations

import services.api.provider_postgres as postgres_facade
from services.api.provider_postgres_persistence import PostgresProviderPersistence
from services.api.provider_postgres_support import (
    ProviderPersistenceError,
    RuntimeHomeDestroyer,
)


def test_provider_postgres_facade_reexports_exact_persistence_objects() -> None:
    assert postgres_facade.ProviderPersistenceError is ProviderPersistenceError
    assert postgres_facade.RuntimeHomeDestroyer is RuntimeHomeDestroyer
    assert postgres_facade.PostgresProviderPersistence is (PostgresProviderPersistence)
