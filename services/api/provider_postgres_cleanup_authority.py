"""Requester entry point into global provider cleanup validation."""

from __future__ import annotations

from typing import TYPE_CHECKING, Literal, cast

from sqlalchemy import text

from services.api.provider_postgres_support import ProviderPersistenceError

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncConnection

    from services.api.provider_runtime_contracts import ProviderPrincipal

type RequesterCleanupReason = Literal["unbound", "superseded", "revoke"]


async def validate_requester_cleanup(
    database: AsyncConnection,
    principal: ProviderPrincipal,
    connection_id: str | None,
    runtime_home_ref: str,
    reason: RequesterCleanupReason,
) -> datetime:
    """Hold the exact global authorization until caller completion commits."""
    validation = await database.execute(
        text(
            "SELECT public.validate_due_provider_cleanup("
            ":org, :user, :id, :runtime_ref, :reason, NULL)"
        ),
        {
            "org": principal.org_id,
            "user": principal.user_id,
            "id": connection_id,
            "runtime_ref": runtime_home_ref,
            "reason": reason,
        },
    )
    requested_at = cast("datetime | None", validation.scalar_one())
    if requested_at is None:
        raise ProviderPersistenceError
    return requested_at
