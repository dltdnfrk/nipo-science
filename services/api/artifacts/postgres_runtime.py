"""Typed scoped SQLAlchemy runtime for durable Artifact operations."""

from collections.abc import Awaitable, Callable, Mapping
from datetime import datetime
from uuid import UUID

import anyio
from pydantic import TypeAdapter
from sqlalchemy import text
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from .models import ArtifactScope
from .store_contract import ArtifactStoreError, ArtifactStoreIntegrityError

type BindValue = str | int | datetime | UUID | list[str]
BOOLEAN = TypeAdapter(bool)


def identity(scope: ArtifactScope) -> dict[str, BindValue]:
    """Return reusable tenant and Project bind values."""
    return {"org": scope.org_id, "project": scope.project_id}


async def exists(
    connection: AsyncConnection,
    query: str,
    values: Mapping[str, BindValue],
) -> bool:
    """Execute a typed SQL EXISTS scalar query."""
    return BOOLEAN.validate_python(
        (await connection.execute(text(query), values)).scalar_one()
    )


def run_scoped[RunResult](
    database_url: str,
    scope: ArtifactScope,
    operation: Callable[[AsyncConnection], Awaitable[RunResult]],
) -> RunResult:
    """Run one transaction under the exact active requester RLS principal."""

    async def execute() -> RunResult:
        engine = create_async_engine(database_url, poolclass=NullPool)
        try:
            async with engine.begin() as connection:
                _ = await connection.execute(
                    text("SET LOCAL ROLE science_workbench_app")
                )
                _ = await connection.execute(
                    text(
                        "SELECT set_config('app.org_id', :org, true), "
                        "set_config('app.user_id', :user, true)"
                    ),
                    {"org": str(scope.org_id), "user": str(scope.requester_id)},
                )
                return await operation(connection)
        finally:
            await engine.dispose()

    try:
        return anyio.run(execute)
    except IntegrityError as error:
        raise ArtifactStoreIntegrityError from error
    except SQLAlchemyError as error:
        raise ArtifactStoreError from error
