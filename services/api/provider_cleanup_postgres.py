"""Dedicated PostgreSQL service boundary for due provider cleanup."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, final

import anyio
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine, create_async_engine
from sqlalchemy.pool import NullPool

from services.api.provider_cleanup_model import (
    CleanupQueryError,
    CleanupRuntimeHomeDestroyer,
    DueCleanup,
)
from services.api.provider_cleanup_queries import (
    DueCleanupExecutor,
    due_cleanup_candidates,
)
from services.api.provider_cleanup_role import (
    PROVIDER_CLEANUP_CAPABILITY_ROLE,
    cleanup_service_login_is_confined,
)
from services.api.provider_runtime import ProviderRuntimeError

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

_ERROR_PERSISTENCE: Final = "provider_persistence_failed"
_FORBIDDEN_LOGIN_ROLES: Final = frozenset(
    {
        "science_workbench",
        "science_workbench_app",
        PROVIDER_CLEANUP_CAPABILITY_ROLE,
        "science_workbench_qualification",
    }
)


class ProviderCleanupPersistenceError(ProviderRuntimeError):
    """Stable error for an unavailable or rejected cleanup service boundary."""

    def __init__(self) -> None:
        """Avoid disclosing service database details."""
        super().__init__(_ERROR_PERSISTENCE)


@dataclass(frozen=True, slots=True)
class ProviderCleanupSweepResult:
    """Redacted counters that never expose runtime-home references."""

    scanned: int
    completed: int
    failed: int


@final
class PostgresProviderCleanupSweeper:
    """Run fixed due-cleanup SQL through one dedicated service credential."""

    def __init__(
        self,
        service_database_url: str,
        destroyer: CleanupRuntimeHomeDestroyer,
        *,
        clock: Callable[[], datetime],
        expected_login_role: str,
    ) -> None:
        """Bind the service DSN, exact login identity, destroyer, and clock."""
        if (
            not service_database_url
            or not expected_login_role
            or expected_login_role in _FORBIDDEN_LOGIN_ROLES
            or not expected_login_role.replace("_", "").isalnum()
        ):
            raise ProviderCleanupPersistenceError
        self._service_database_url = service_database_url
        self._expected_login_role = expected_login_role
        self._executor = DueCleanupExecutor(destroyer, clock)
        self._clock = clock

    def sweep_due_cleanups(self) -> ProviderCleanupSweepResult:
        """Resume one bounded batch while containing failures per candidate."""
        try:
            return anyio.run(self._sweep)
        except ProviderCleanupPersistenceError:
            raise
        except (CleanupQueryError, OSError, SQLAlchemyError) as error:
            raise ProviderCleanupPersistenceError from error

    async def _sweep(self) -> ProviderCleanupSweepResult:
        engine = create_async_engine(self._service_database_url, poolclass=NullPool)
        try:
            now = self._clock()
            candidates = await self._select_candidates(engine, now)
            completed = 0
            failed = 0
            for candidate in candidates:
                try:
                    cleaned = await self._complete_candidate(engine, candidate, now)
                except (CleanupQueryError, OSError, SQLAlchemyError):
                    failed += 1
                else:
                    completed += int(cleaned)
            return ProviderCleanupSweepResult(len(candidates), completed, failed)
        finally:
            await engine.dispose()

    async def _select_candidates(
        self, engine: AsyncEngine, now: datetime
    ) -> tuple[DueCleanup, ...]:
        async with engine.begin() as database:
            await self._activate_capability(database)
            return await due_cleanup_candidates(database, now)

    async def _complete_candidate(
        self, engine: AsyncEngine, candidate: DueCleanup, now: datetime
    ) -> bool:
        async with engine.begin() as database:
            await self._activate_capability(database)
            return await self._executor.complete(database, candidate, now)

    async def _activate_capability(self, database: AsyncConnection) -> None:
        if not await cleanup_service_login_is_confined(
            database, self._expected_login_role
        ):
            raise ProviderCleanupPersistenceError
        _ = await database.execute(
            text(f"SET LOCAL ROLE {PROVIDER_CLEANUP_CAPABILITY_ROLE}")
        )
