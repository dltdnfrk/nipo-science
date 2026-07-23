"""Canonical row-before-reference locking for provider connection writes."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from sqlalchemy import text

from services.api.provider_postgres_support import ProviderPersistenceError

if TYPE_CHECKING:
    from collections.abc import Iterable

    from sqlalchemy.ext.asyncio import AsyncConnection


@dataclass(frozen=True, slots=True)
class ProviderRowLockTarget:
    """Exact requester-owned connection state expected by one CAS write."""

    org_id: str
    user_id: str
    connection_id: str
    expected_revision: int
    runtime_home_ref: str
    superseded_runtime_home_ref: str | None


async def lock_expected_provider_row(
    database: AsyncConnection,
    target: ProviderRowLockTarget,
) -> None:
    """Lock and validate one CAS target before any runtime-ref advisory lock."""
    result = await database.execute(
        text(
            "SELECT encrypted_runtime_home_ref, superseded_runtime_home_ref FROM "
            "provider_connections WHERE org_id = :org AND id = :id AND "
            "requester_user_id = :user AND account_metadata ->> 'revision' = "
            ":expected_revision FOR UPDATE"
        ),
        {
            "org": target.org_id,
            "id": target.connection_id,
            "user": target.user_id,
            "expected_revision": str(target.expected_revision),
        },
    )
    row = result.one_or_none()
    if row is None:
        raise ProviderPersistenceError
    active_ref = cast("str", row[0])
    pending_ref = cast("str | None", row[1])
    expected_active_ref = (
        target.superseded_runtime_home_ref or target.runtime_home_ref
    )
    if pending_ref is not None or active_ref != expected_active_ref:
        raise ProviderPersistenceError


async def lock_runtime_home_refs(
    database: AsyncConnection,
    runtime_home_refs: Iterable[str],
) -> None:
    """Acquire distinct runtime-ref advisory locks in canonical lexical order."""
    for runtime_home_ref in sorted(set(runtime_home_refs)):
        _ = await database.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:runtime_ref, 0))"),
            {"runtime_ref": runtime_home_ref},
        )
