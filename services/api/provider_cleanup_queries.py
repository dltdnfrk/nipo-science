"""Fixed PostgreSQL operations for cross-tenant provider cleanup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from sqlalchemy import text

from services.api.provider_cleanup_model import (
    CleanupClock,
    CleanupQueryError,
    CleanupReason,
    CleanupRuntimeHomeDestroyer,
    DueCleanup,
    destroy_runtime_home,
)
from services.api.provider_cleanup_revoke import DueRevokeExecutor
from services.api.provider_runtime import ProviderPrincipal, is_safe_runtime_home_ref

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncConnection

async def due_cleanup_candidates(
    database: AsyncConnection, now: datetime
) -> tuple[DueCleanup, ...]:
    """Load one bounded batch of globally due cleanup work."""
    result = await database.execute(
        text(
            "SELECT org_id::text AS org_id, requester_user_id::text AS user_id, "
            "runtime_home_ref, connection_id::text "
            "AS connection_id, reason, destroy_by, created_at FROM "
            "public.provider_due_cleanup_candidates(:now)"
        ),
        {"now": now},
    )
    candidates: list[DueCleanup] = []
    for row in result.mappings():
        org_id = row.get("org_id")
        user_id = row.get("user_id")
        runtime_home_ref = row.get("runtime_home_ref")
        connection_id = row.get("connection_id")
        match row.get("reason"):
            case "unbound":
                reason: CleanupReason = "unbound"
            case "superseded":
                reason = "superseded"
            case "revoke":
                reason = "revoke"
            case _:
                raise CleanupQueryError
        if (
            not isinstance(org_id, str)
            or not isinstance(user_id, str)
            or not isinstance(runtime_home_ref, str)
            or not is_safe_runtime_home_ref(runtime_home_ref)
            or (connection_id is not None and not isinstance(connection_id, str))
            or (reason == "unbound" and connection_id is not None)
            or (reason != "unbound" and connection_id is None)
        ):
            raise CleanupQueryError
        candidates.append(
            DueCleanup(
                ProviderPrincipal(user_id, org_id),
                runtime_home_ref,
                connection_id,
                reason,
            )
        )
    return tuple(candidates)


@dataclass(frozen=True, slots=True)
class DueCleanupExecutor:
    """Complete exact due rows with a fixed destroyer and clock."""

    destroyer: CleanupRuntimeHomeDestroyer
    clock: CleanupClock

    async def complete(
        self, database: AsyncConnection, candidate: DueCleanup, now: datetime
    ) -> bool:
        """Lock and complete one candidate without exposing a SQL callback."""
        match candidate.reason:
            case "unbound" | "superseded":
                return await self._complete_outbox(database, candidate, now)
            case "revoke":
                return await DueRevokeExecutor(self.destroyer, self.clock).complete(
                    database, candidate, now
                )

    async def _complete_outbox(
        self, database: AsyncConnection, candidate: DueCleanup, now: datetime
    ) -> bool:
        principal = candidate.principal
        parameters = {
            "org": principal.org_id,
            "user": principal.user_id,
            "runtime_ref": candidate.runtime_home_ref,
            "reason": candidate.reason,
            "now": now,
        }
        validation = await database.execute(
            text(
                "SELECT public.validate_due_provider_cleanup("
                ":org, :user, :id, :runtime_ref, :reason, :now)"
            ),
            parameters | {"id": candidate.connection_id},
        )
        requested_at = cast("datetime | None", validation.scalar_one())
        if requested_at is None:
            raise CleanupQueryError
        evidence = destroy_runtime_home(self.destroyer, candidate.runtime_home_ref)
        destroyed_at = max(self.clock(), requested_at)
        completed = await database.execute(
            text(
                "SELECT public.complete_provider_cleanup_outbox("
                ":org, :user, :id, :runtime_ref, :reason, :destroyed_at, :evidence)"
            ),
            parameters
            | {
                "id": candidate.connection_id,
                "destroyed_at": destroyed_at,
                "evidence": evidence,
            },
        )
        if completed.scalar_one() is not True:
            raise CleanupQueryError
        return True
