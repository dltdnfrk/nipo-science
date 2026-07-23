"""Backward-compatible façade for requester PostgreSQL persistence."""

from services.api.provider_postgres_persistence import PostgresProviderPersistence
from services.api.provider_postgres_support import (
    ProviderPersistenceError,
    RuntimeHomeDestroyer,
)
from services.api.provider_runtime_configuration import is_safe_runtime_home_ref
from services.api.provider_runtime_contracts import (
    ERROR_PROVIDER_CLEANUP_OVERDUE,
    Health,
    ProviderCleanupReceipt,
    ProviderCompletionAdoption,
    ProviderConnection,
    ProviderConnectionSnapshot,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderRevokeMutation,
    ProviderRuntimeError,
    ProviderUpsertControl,
)

__all__ = [
    "ERROR_PROVIDER_CLEANUP_OVERDUE",
    "Health",
    "PostgresProviderPersistence",
    "ProviderCleanupReceipt",
    "ProviderCompletionAdoption",
    "ProviderConnection",
    "ProviderConnectionSnapshot",
    "ProviderPersistence",
    "ProviderPersistenceError",
    "ProviderPrincipal",
    "ProviderRevokeMutation",
    "ProviderRuntimeError",
    "ProviderUpsertControl",
    "RuntimeHomeDestroyer",
    "is_safe_runtime_home_ref",
]
