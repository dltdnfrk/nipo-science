"""Shared contracts and safe values for requester provider persistence."""

from __future__ import annotations

from datetime import datetime
from typing import Final, Protocol
from uuid import UUID

from services.api.provider_runtime_contracts import (
    ProviderCompletionAdoption,
    ProviderConnection,
    ProviderRuntimeError,
)

_ERROR_PERSISTENCE: Final = "provider_persistence_failed"
_SHA256_HEX_LENGTH: Final = 64

type ProviderMetadata = dict[str, str | list[str]]
type ProviderJsonValue = (
    None
    | bool
    | int
    | float
    | str
    | list[ProviderJsonValue]
    | dict[str, ProviderJsonValue]
)
type ProviderRowMetadata = dict[str, ProviderJsonValue]
type ProviderRowValue = ProviderJsonValue | datetime | UUID


class RuntimeHomeDestroyer(Protocol):
    """Destroy a runtime home using only its opaque vault reference."""

    def destroy(self, opaque_ref: str) -> str:
        """Return lowercase SHA-256 evidence after idempotent destruction."""
        ...


class ProviderPersistenceError(ProviderRuntimeError):
    """Stable, non-disclosing durable-provider persistence failure."""

    def __init__(self) -> None:
        """Initialize a non-disclosing persistence error."""
        super().__init__(_ERROR_PERSISTENCE)


def safe_provider_metadata(
    connection: ProviderConnection,
    completion_adoption: ProviderCompletionAdoption | None = None,
) -> ProviderMetadata:
    """Build allowlisted metadata without storing OAuth material."""
    metadata: ProviderMetadata = {
        "account_id": connection.account_id,
        "models": list(connection.eligible_models),
        "provider": connection.adapter_id,
        "revision": str(connection.revision),
    }
    if connection.qualification is not None:
        metadata |= {
            "qualification_runtime_version": (
                connection.qualification.runtime.runtime_version
            ),
            "qualification_executable_sha256": (
                connection.qualification.runtime.executable_sha256
            ),
            "qualification_profile_sha256": connection.qualification.profile_sha256,
            "qualification_receipt_id": connection.qualification.receipt.receipt_id,
        }
    if completion_adoption is not None:
        metadata |= {
            "staging_lease_id": completion_adoption.staging_lease_id,
            "staging_lease_destroy_by": completion_adoption.destroy_by.isoformat(),
            "adoption_status": "pending",
        }
    return metadata


def is_sha256(value: str) -> bool:
    """Return whether a value is a canonical lowercase SHA-256 digest."""
    return (
        len(value) == _SHA256_HEX_LENGTH
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )


def destroy_runtime_home(destroyer: RuntimeHomeDestroyer, runtime_home_ref: str) -> str:
    """Destroy one opaque home and normalize boundary failures."""
    try:
        evidence = destroyer.destroy(runtime_home_ref)
    except Exception as error:  # noqa: RUF100  # noqa: BROAD_EXCEPT_OK
        raise ProviderPersistenceError from error
    if not is_sha256(evidence):
        raise ProviderPersistenceError
    return evidence
