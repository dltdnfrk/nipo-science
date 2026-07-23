"""Typed metadata fields used by provider row decoding."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import TYPE_CHECKING, Final

from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_postgres_support import (
    ProviderPersistenceError,
    is_sha256,
)
from services.api.provider_runtime_contracts import (
    Health,
    ProviderCleanupReceipt,
    ProviderConnection,
)

if TYPE_CHECKING:
    from services.api.provider_postgres_support import (
        ProviderJsonValue,
        ProviderRowMetadata,
        ProviderRowValue,
    )

_HEALTH_BY_VALUE: Final[dict[str, Health]] = {
    "pending": "pending",
    "healthy": "healthy",
    "reauth_required": "reauth_required",
    "unavailable": "unavailable",
    "quota_exhausted": "quota_exhausted",
    "revoked": "revoked",
}


@dataclass(frozen=True, slots=True)
class CleanupRowFields:
    """Decoded cleanup metadata needed to reconstruct a receipt."""

    status: ProviderJsonValue
    requested_at: datetime | None
    destroy_by: datetime | None
    destroyed_at: datetime | None
    evidence_sha256: ProviderJsonValue


def cleanup_receipt(
    connection: ProviderConnection,
    fields: CleanupRowFields,
) -> ProviderCleanupReceipt | None:
    """Reconstruct a completed receipt or reject inconsistent fields."""
    if fields.status != "completed":
        return None
    if (
        fields.requested_at is None
        or fields.destroy_by is None
        or fields.destroyed_at is None
        or not isinstance(fields.evidence_sha256, str)
        or not is_sha256(fields.evidence_sha256)
    ):
        raise ProviderPersistenceError
    return ProviderCleanupReceipt(
        connection.connection_id,
        connection.adapter_id,
        fields.requested_at,
        fields.destroy_by,
        fields.destroyed_at,
        fields.evidence_sha256,
    )


def provider_models(value: ProviderJsonValue) -> tuple[str, ...]:
    """Parse a non-empty list of canonical provider model identifiers."""
    if not isinstance(value, list) or not value:
        raise ProviderPersistenceError
    if any(
        not isinstance(model, str) or not provider_model_id_is_valid(model)
        for model in value
    ):
        raise ProviderPersistenceError
    return tuple(model for model in value if isinstance(model, str))


def provider_health(value: ProviderRowValue) -> Health:
    """Parse the closed provider health variant set."""
    if not isinstance(value, str):
        raise ProviderPersistenceError
    health = _HEALTH_BY_VALUE.get(value)
    if health is None:
        raise ProviderPersistenceError
    return health


def metadata_datetime(metadata: ProviderRowMetadata, key: str) -> datetime | None:
    """Parse one UTC ISO timestamp from provider metadata."""
    value = metadata.get(key)
    if value is None:
        return None
    if not isinstance(value, str):
        raise ProviderPersistenceError
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as error:
        raise ProviderPersistenceError from error
    if parsed.utcoffset() != timedelta(0):
        raise ProviderPersistenceError
    return parsed
