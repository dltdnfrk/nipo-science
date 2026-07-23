"""Typed contracts shared by fixed provider cleanup operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Literal, Protocol

from services.api.provider_runtime import ProviderPrincipal, ProviderRuntimeError

_ERROR_PERSISTENCE: Final = "provider_persistence_failed"
_SHA256_HEX_LENGTH: Final = 64
type CleanupReason = Literal["unbound", "superseded", "revoke"]

if TYPE_CHECKING:
    from datetime import datetime


class CleanupQueryError(ProviderRuntimeError):
    """Stable failure for rejected or failed cleanup work."""

    def __init__(self) -> None:
        """Avoid disclosing cleanup storage or vault details."""
        super().__init__(_ERROR_PERSISTENCE)


class CleanupRuntimeHomeDestroyer(Protocol):
    """Destroy one runtime home and return lowercase SHA-256 evidence."""

    def destroy(self, opaque_ref: str) -> str:
        """Return lowercase SHA-256 evidence after idempotent destruction."""
        ...


class CleanupClock(Protocol):
    """Provide the service's timezone-aware cleanup clock."""

    def __call__(self) -> datetime:
        """Return the current service time."""
        ...


@dataclass(frozen=True, slots=True)
class DueCleanup:
    """Validated identity and opaque reference for one due cleanup row."""

    principal: ProviderPrincipal
    runtime_home_ref: str
    connection_id: str | None
    reason: CleanupReason


def destroy_runtime_home(
    destroyer: CleanupRuntimeHomeDestroyer, runtime_home_ref: str
) -> str:
    """Normalize vault failures and require lowercase SHA-256 evidence."""
    try:
        evidence = destroyer.destroy(runtime_home_ref)
    except (OSError, RuntimeError) as error:
        raise CleanupQueryError from error
    if not _is_sha256(evidence):
        raise CleanupQueryError
    return evidence


def _is_sha256(value: str) -> bool:
    return (
        len(value) == _SHA256_HEX_LENGTH
        and value == value.lower()
        and all(character in "0123456789abcdef" for character in value)
    )
