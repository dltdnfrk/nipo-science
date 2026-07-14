"""PostgreSQL persistence for requester-owned provider connections."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import datetime
from typing import Final, Protocol, final, override

import anyio
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import AsyncConnection, create_async_engine
from sqlalchemy.pool import NullPool

from services.api.provider_runtime import (
    ProviderCleanupReceipt,
    ProviderConnection,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderRevokeMutation,
    ProviderRuntimeError,
)

_ERROR_PERSISTENCE: str = "provider_persistence_failed"
_SHA256_HEX_LENGTH: Final[int] = 64
_METADATA_BIND = bindparam("metadata", type_=JSONB)


class RuntimeHomeDestroyer(Protocol):
    """Destroys a runtime home using only its opaque vault reference."""

    def destroy(self, opaque_ref: str) -> str:
        """Return lowercase SHA-256 evidence after idempotent destruction."""
        ...


@dataclass(frozen=True, slots=True)
class _RevokeCompletion:
    """Data required to complete a scheduled runtime-home destruction."""

    principal: ProviderPrincipal
    mutation: ProviderRevokeMutation
    destroyed_at: datetime
    evidence: str


class ProviderPersistenceError(ProviderRuntimeError):
    """Stable, non-disclosing durable-provider persistence failure."""

    def __init__(self) -> None:
        """Initialize a non-disclosing persistence error."""
        super().__init__(_ERROR_PERSISTENCE)


@final
class PostgresProviderPersistence(ProviderPersistence):
    """Persist redacted provider state through the forced-RLS application role."""

    def __init__(self, database_url: str, destroyer: RuntimeHomeDestroyer) -> None:
        """Initialize persistence with its database and runtime-home destroyer."""
        self._database_url = database_url
        self._destroyer = destroyer

    @override
    def upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        expected_revision: int | None,
    ) -> None:
        """Insert or CAS-update one requester-owned provider connection."""
        self._run(
            principal,
            self._upsert(principal, connection, runtime_home_ref, expected_revision),
        )

    @override
    def revoke(
        self, principal: ProviderPrincipal, mutation: ProviderRevokeMutation
    ) -> ProviderCleanupReceipt:
        """Schedule, destroy, then complete a requester-owned revocation."""
        self._run(principal, self._schedule_revoke(principal, mutation))
        try:
            evidence = self._destroyer.destroy(mutation.runtime_home_ref)
        except Exception as error:
            raise ProviderPersistenceError from error
        if not _is_sha256(evidence):
            raise ProviderPersistenceError
        destroyed_at = max(
            datetime.now(mutation.requested_at.tzinfo), mutation.requested_at
        )
        completion = _RevokeCompletion(principal, mutation, destroyed_at, evidence)
        self._run(principal, self._complete_revoke(completion))
        return ProviderCleanupReceipt(
            mutation.proposed.connection_id,
            mutation.proposed.adapter_id,
            mutation.requested_at,
            mutation.destroy_by,
            destroyed_at,
            evidence,
        )

    def _run(
        self, principal: ProviderPrincipal, operation: _ProviderOperation
    ) -> None:
        async def execute() -> None:
            engine = create_async_engine(self._database_url, poolclass=NullPool)
            try:
                async with engine.begin() as database:
                    _ = await database.execute(
                        text("SET LOCAL ROLE science_workbench_app")
                    )
                    _ = await database.execute(
                        text(
                            "SELECT set_config('app.org_id', :org, true), "
                            "set_config('app.user_id', :user, true)"
                        ),
                        {"org": principal.org_id, "user": principal.user_id},
                    )
                    await operation(database)
            finally:
                await engine.dispose()

        try:
            anyio.run(execute)
        except ProviderPersistenceError:
            raise
        except SQLAlchemyError as error:
            raise ProviderPersistenceError from error

    def _upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        expected_revision: int | None,
    ) -> _ProviderOperation:
        status = _schema_status(connection.health)
        metadata = _safe_metadata(connection)

        async def operation(database: AsyncConnection) -> None:
            if expected_revision is None:
                result = await database.execute(
                    text(
                        "INSERT INTO provider_connections "
                        "(id, org_id, requester_user_id, adapter_id, "
                        "encrypted_runtime_home_ref, account_metadata, selected_model, "
                        "status, qualified_at, health_checked_at) VALUES "
                        "(:id, :org, :user, :adapter, :runtime_ref, :metadata, "
                        ":model, :status, CASE WHEN :qualified THEN CURRENT_TIMESTAMP "
                        "ELSE NULL END, CASE WHEN :health = 'pending' THEN NULL "
                        "ELSE CURRENT_TIMESTAMP END)"
                    ).bindparams(_METADATA_BIND),
                    _upsert_parameters(
                        principal, connection, runtime_home_ref, metadata, status
                    ),
                )
            else:
                parameters = _upsert_parameters(
                    principal, connection, runtime_home_ref, metadata, status
                ) | {"expected_revision": str(expected_revision)}
                result = await database.execute(
                    text(
                        "UPDATE provider_connections SET adapter_id = :adapter, "
                        "encrypted_runtime_home_ref = :runtime_ref, "
                        "account_metadata = :metadata, selected_model = :model, "
                        "status = :status, qualified_at = CASE WHEN :qualified THEN "
                        "COALESCE(qualified_at, CURRENT_TIMESTAMP) ELSE NULL END, "
                        "health_checked_at = CASE WHEN :health = 'pending' THEN "
                        "health_checked_at ELSE CURRENT_TIMESTAMP END "
                        "WHERE org_id = :org AND id = :id AND requester_user_id = "
                        ":user AND account_metadata ->> 'revision' = :expected_revision"
                    ).bindparams(_METADATA_BIND),
                    parameters,
                )
            if result.rowcount != 1:
                raise ProviderPersistenceError

        return operation

    def _schedule_revoke(
        self, principal: ProviderPrincipal, mutation: ProviderRevokeMutation
    ) -> _ProviderOperation:
        scheduled = {
            "cleanup_status": "scheduled",
            "cleanup_requested_at": mutation.requested_at.isoformat(),
            "destroy_by": mutation.destroy_by.isoformat(),
        }

        async def operation(database: AsyncConnection) -> None:
            result = await database.execute(
                text(
                    "WITH locked AS (SELECT id FROM provider_connections "
                    "WHERE org_id = :org AND id = :id AND requester_user_id = :user "
                    "AND account_metadata ->> 'revision' = :expected_revision "
                    "FOR UPDATE) UPDATE provider_connections SET account_metadata = "
                    "account_metadata || :metadata WHERE id IN (SELECT id FROM locked) "
                    "AND org_id = :org AND requester_user_id = :user"
                ).bindparams(_METADATA_BIND),
                {
                    "org": principal.org_id,
                    "id": mutation.current.connection_id,
                    "user": principal.user_id,
                    "expected_revision": str(mutation.expected_revision),
                    "metadata": scheduled,
                },
            )
            if result.rowcount != 1:
                raise ProviderPersistenceError

        return operation

    def _complete_revoke(self, completion: _RevokeCompletion) -> _ProviderOperation:
        mutation = completion.mutation
        metadata = _safe_metadata(mutation.proposed) | {
            "cleanup_status": "completed",
            "cleanup_requested_at": mutation.requested_at.isoformat(),
            "destroy_by": mutation.destroy_by.isoformat(),
            "destroyed_at": completion.destroyed_at.isoformat(),
            "evidence_sha256": completion.evidence,
        }

        async def operation(database: AsyncConnection) -> None:
            result = await database.execute(
                text(
                    "UPDATE provider_connections SET status = 'revoked', "
                    "selected_model = NULL, revoked_at = :revoked_at, "
                    "encrypted_runtime_home_ref = :tombstone, "
                    "account_metadata = :metadata "
                    "WHERE org_id = :org AND id = :id AND requester_user_id = :user "
                    "AND account_metadata ->> 'revision' = :expected_revision "
                    "AND account_metadata ->> 'cleanup_status' = 'scheduled'"
                ).bindparams(_METADATA_BIND),
                {
                    "org": completion.principal.org_id,
                    "id": mutation.proposed.connection_id,
                    "user": completion.principal.user_id,
                    "revoked_at": mutation.requested_at,
                    "tombstone": (
                        f"vault://runtime/destroyed/{mutation.proposed.connection_id}"
                    ),
                    "metadata": metadata,
                    "expected_revision": str(mutation.expected_revision),
                },
            )
            if result.rowcount != 1:
                raise ProviderPersistenceError

        return operation


type _ProviderOperation = Callable[[AsyncConnection], Awaitable[None]]


def _upsert_parameters(
    principal: ProviderPrincipal,
    connection: ProviderConnection,
    runtime_home_ref: str,
    metadata: dict[str, str | list[str]],
    status: str,
) -> dict[str, str | bool | dict[str, str | list[str]] | None]:
    return {
        "id": connection.connection_id,
        "org": principal.org_id,
        "user": principal.user_id,
        "adapter": connection.adapter_id,
        "runtime_ref": runtime_home_ref,
        "metadata": metadata,
        "model": connection.selected_model,
        "status": status,
        "qualified": connection.qualified_live,
        "health": connection.health,
    }


def _schema_status(health: str) -> str:
    if health in {"unavailable", "quota_exhausted"}:
        return "pending"
    return health


def _safe_metadata(connection: ProviderConnection) -> dict[str, str | list[str]]:
    """Use allowlisted metadata keys without storing OAuth material."""
    return {
        "account_id": connection.account_id,
        "models": list(connection.eligible_models),
        "provider": connection.adapter_id,
        "revision": str(connection.revision),
        "subscription_tier": (
            f"health={connection.health};qualified={connection.qualified_live};"
            f"cleanup={connection.cleanup_verified};revision={connection.revision}"
        ),
    }


def _is_sha256(value: str) -> bool:
    return len(value) == _SHA256_HEX_LENGTH and value == value.lower() and all(
        character in "0123456789abcdef" for character in value
    )
