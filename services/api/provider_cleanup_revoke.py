"""Fixed PostgreSQL completion for due provider revocations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from sqlalchemy import text

from services.api.provider_cleanup_model import (
    CleanupClock,
    CleanupQueryError,
    CleanupRuntimeHomeDestroyer,
    DueCleanup,
    destroy_runtime_home,
)

if TYPE_CHECKING:
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncConnection


@dataclass(frozen=True, slots=True)
class DueRevokeExecutor:
    """Complete one exact due revoke with a fixed destroyer and clock."""

    destroyer: CleanupRuntimeHomeDestroyer
    clock: CleanupClock

    async def complete(
        self, database: AsyncConnection, candidate: DueCleanup, now: datetime
    ) -> bool:
        """Tombstone one locked revoke only after durable destruction evidence."""
        if candidate.connection_id is None:
            raise CleanupQueryError
        principal = candidate.principal
        parameters = {
            "org": principal.org_id,
            "user": principal.user_id,
            "id": candidate.connection_id,
            "runtime_ref": candidate.runtime_home_ref,
            "now": now,
        }
        result = await database.execute(
            text(
                "SELECT public.validate_due_provider_cleanup("
                ":org, :user, :id, :runtime_ref, 'revoke', :now)"
            ),
            parameters,
        )
        requested_at = cast("datetime | None", result.scalar_one())
        if requested_at is None:
            raise CleanupQueryError
        evidence = destroy_runtime_home(self.destroyer, candidate.runtime_home_ref)
        destroyed_at = max(self.clock(), requested_at)
        completed = await database.execute(
            text(
                "SELECT public.complete_provider_revoked_cleanup("
                ":org, :user, :id, :runtime_ref, :destroyed_at, :evidence)"
            ),
            parameters
            | {
                "destroyed_at": destroyed_at,
                "evidence": evidence,
            },
        )
        if completed.scalar_one() is not True:
            raise CleanupQueryError
        return True
