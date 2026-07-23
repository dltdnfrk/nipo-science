"""Requester-scoped PostgreSQL transaction execution."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import TYPE_CHECKING, final

import anyio
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from services.api.migrations.versioned_0004_role_names import APP_ROLE
from services.api.provider_database_role import SAFE_PROVIDER_SEARCH_PATH_SQL
from services.api.provider_postgres_support import ProviderPersistenceError

if TYPE_CHECKING:
    from services.api.provider_runtime_contracts import ProviderPrincipal

type ProviderOperation[ResultT] = Callable[[AsyncConnection], Awaitable[ResultT]]


@final
class ProviderPostgresSession:
    """Execute one operation through the forced-RLS application role."""

    def __init__(self, database_url: str) -> None:
        """Bind the application database endpoint."""
        self._database_url = database_url

    def run[ResultT](
        self,
        principal: ProviderPrincipal,
        operation: ProviderOperation[ResultT],
    ) -> ResultT:
        """Run an operation in one requester-scoped transaction."""

        async def execute() -> ResultT:
            engine = create_async_engine(self._database_url, poolclass=NullPool)
            try:
                async with engine.begin() as database:
                    _ = await database.execute(
                        text(f"SET LOCAL ROLE {APP_ROLE}")
                    )
                    _ = await database.execute(text(SAFE_PROVIDER_SEARCH_PATH_SQL))
                    _ = await database.execute(
                        text(
                            "SELECT set_config('app.org_id', :org, true), "
                            "set_config('app.user_id', :user, true)"
                        ),
                        {"org": principal.org_id, "user": principal.user_id},
                    )
                    return await operation(database)
            finally:
                await engine.dispose()

        try:
            return anyio.run(execute)
        except ProviderPersistenceError:
            raise
        except (OSError, SQLAlchemyError) as error:
            raise ProviderPersistenceError from error
