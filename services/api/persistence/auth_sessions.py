"""Persisted opaque-session authentication through a narrow database function."""

from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Final, final

import anyio
from pydantic import UUID7, BaseModel, ConfigDict, ValidationError
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from services.api.product_app import Principal

if TYPE_CHECKING:
    from collections.abc import Awaitable, Callable

    from sqlalchemy.ext.asyncio import AsyncConnection

MAX_OPAQUE_CAPABILITY_CHARACTERS: Final = 4096


class _SessionProjection(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
    )

    session_id: UUID7
    organization_id: UUID7
    user_id: UUID7
    email: str
    organization_name: str
    csrf_hash: bytes


@dataclass(frozen=True, slots=True)
class _ResolvedSession:
    principal: Principal
    csrf_hash: bytes


@final
class PostgresSessionAuthority:
    """Resolve and revoke production sessions without exposing identity tables."""

    def __init__(self, database_url: str) -> None:
        """Bind the database endpoint used by the security-definer boundary."""
        self._database_url = database_url

    def principal_for(self, token: str) -> Principal | None:
        """Return the active persisted principal for one opaque cookie value."""
        resolved = self._resolve(token)
        return None if resolved is None else resolved.principal

    def csrf_matches(self, token: str, supplied: str) -> bool:
        """Match a CSRF capability against its persisted digest."""
        if not supplied or len(supplied) > MAX_OPAQUE_CAPABILITY_CHARACTERS:
            return False
        resolved = self._resolve(token)
        supplied_hash = hashlib.sha256(supplied.encode()).digest()
        return resolved is not None and hmac.compare_digest(
            resolved.csrf_hash,
            supplied_hash,
        )

    def revoke(self, token: str) -> None:
        """Revoke one persisted session through the privileged narrow function."""
        token_hash = _capability_hash(token)
        if token_hash is None:
            return

        async def operation(connection: AsyncConnection) -> None:
            _ = await connection.execute(
                text("SELECT revoke_auth_session(:token_hash)"),
                {"token_hash": token_hash},
            )

        _ = self._execute(operation)

    def _resolve(self, token: str) -> _ResolvedSession | None:
        token_hash = _capability_hash(token)
        if token_hash is None:
            return None

        async def operation(
            connection: AsyncConnection,
        ) -> _ResolvedSession | None:
            row = (
                (
                    await connection.execute(
                        text(
                            "SELECT session_id, organization_id, user_id, email, "
                            "organization_name, csrf_hash "
                            "FROM resolve_auth_session(:token_hash)"
                        ),
                        {"token_hash": token_hash},
                    )
                )
                .mappings()
                .one_or_none()
            )
            if row is None:
                return None
            projection = _SessionProjection.model_validate(row)
            return _ResolvedSession(
                Principal(
                    user_id=str(projection.user_id),
                    organization_id=str(projection.organization_id),
                    email=projection.email,
                    organization_name=projection.organization_name,
                ),
                projection.csrf_hash,
            )

        return self._execute(operation)

    def _execute[Result](
        self,
        operation: Callable[[AsyncConnection], Awaitable[Result]],
    ) -> Result | None:
        async def execute() -> Result:
            engine = create_async_engine(self._database_url, poolclass=NullPool)
            try:
                async with engine.begin() as connection:
                    _ = await connection.execute(
                        text("SET LOCAL ROLE science_workbench_app")
                    )
                    return await operation(connection)
            finally:
                await engine.dispose()

        try:
            return anyio.run(execute)
        except (SQLAlchemyError, ValidationError):
            return None


def _capability_hash(value: str) -> bytes | None:
    if not value or len(value) > MAX_OPAQUE_CAPABILITY_CHARACTERS:
        return None
    return hashlib.sha256(value.encode()).digest()
