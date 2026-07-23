"""Requester provider-connection SQL operations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, cast

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB

from services.api.provider_postgres_connection_locking import (
    ProviderRowLockTarget,
    lock_expected_provider_row,
    lock_runtime_home_refs,
)
from services.api.provider_postgres_rows import provider_snapshot_from_row
from services.api.provider_postgres_support import (
    ProviderPersistenceError,
    safe_provider_metadata,
)
from services.api.provider_qualification_postgres import (
    qualification_connection_load_sql,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncConnection

    from services.api.provider_postgres_session import ProviderOperation
    from services.api.provider_postgres_support import (
        ProviderMetadata,
        ProviderRowValue,
    )
    from services.api.provider_runtime_contracts import (
        ProviderCompletionAdoption,
        ProviderConnection,
        ProviderConnectionSnapshot,
        ProviderPrincipal,
    )

_METADATA_BIND = bindparam("metadata", type_=JSONB)


@dataclass(frozen=True, slots=True)
class ProviderUpsertRequest:
    """Exact values participating in one connection CAS mutation."""

    principal: ProviderPrincipal
    connection: ProviderConnection
    runtime_home_ref: str
    expected_revision: int | None
    superseded_runtime_home_ref: str | None
    requested_at: datetime
    destroy_by: datetime
    completion_adoption: ProviderCompletionAdoption | None


def load_provider_connections() -> ProviderOperation[
    tuple[ProviderConnectionSnapshot, ...]
]:
    """Build the requester-scoped connection load operation."""

    async def operation(
        database: AsyncConnection,
    ) -> tuple[ProviderConnectionSnapshot, ...]:
        result = await database.execute(text(qualification_connection_load_sql()))
        return tuple(
            provider_snapshot_from_row(cast("Mapping[str, ProviderRowValue]", row))
            for row in result.mappings()
        )

    return operation


def upsert_provider_connection(
    request: ProviderUpsertRequest,
) -> ProviderOperation[None]:
    """Build an insert-or-CAS-update operation with durable replacement outbox."""
    metadata = safe_provider_metadata(request.connection, request.completion_adoption)

    async def operation(database: AsyncConnection) -> None:
        expected_revision = request.expected_revision
        superseded_ref = request.superseded_runtime_home_ref
        if expected_revision is None:
            if superseded_ref is not None:
                raise ProviderPersistenceError
        else:
            principal = request.principal
            await lock_expected_provider_row(
                database,
                ProviderRowLockTarget(
                    principal.org_id,
                    principal.user_id,
                    request.connection.connection_id,
                    expected_revision,
                    request.runtime_home_ref,
                    superseded_ref,
                ),
            )
        await lock_runtime_home_refs(
            database,
            (
                request.runtime_home_ref,
                *((superseded_ref,) if superseded_ref is not None else ()),
            ),
        )
        cleanup = await database.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM provider_runtime_home_cleanups "
                "WHERE encrypted_runtime_home_ref = :runtime_ref)"
            ),
            {"runtime_ref": request.runtime_home_ref},
        )
        if cleanup.scalar_one() is True:
            raise ProviderPersistenceError
        parameters = _upsert_parameters(request, metadata)
        if expected_revision is None:
            result = await database.execute(
                text(
                    "INSERT INTO provider_connections "
                    "(id, org_id, requester_user_id, adapter_id, "
                    "encrypted_runtime_home_ref, account_metadata, selected_model, "
                    "status, qualified_at, qualification_receipt_id, "
                    "health_checked_at, created_at) VALUES "
                    "(:id, :org, :user, :adapter, :runtime_ref, :metadata, "
                    ":model, :status, CASE WHEN :qualified THEN CURRENT_TIMESTAMP "
                    "ELSE NULL END, :qualification_receipt_id, CASE WHEN "
                    ":health = 'pending' THEN NULL ELSE CURRENT_TIMESTAMP END, "
                    ":created_at)"
                ).bindparams(_METADATA_BIND),
                parameters,
            )
        else:
            replacement = superseded_ref is not None
            result = await database.execute(
                text(
                    "UPDATE provider_connections SET adapter_id = :adapter, "
                    "superseded_runtime_home_ref = CASE WHEN :replacement THEN "
                    "encrypted_runtime_home_ref ELSE NULL END, "
                    "encrypted_runtime_home_ref = :runtime_ref, "
                    "account_metadata = :metadata, selected_model = :model, "
                    "status = :status, qualified_at = CASE WHEN :qualified THEN "
                    "COALESCE(qualified_at, CURRENT_TIMESTAMP) ELSE NULL END, "
                    "qualification_receipt_id = :qualification_receipt_id, "
                    "health_checked_at = CASE WHEN :health = 'pending' THEN "
                    "health_checked_at ELSE CURRENT_TIMESTAMP END WHERE "
                    "org_id = :org AND id = :id AND requester_user_id = :user "
                    "AND account_metadata ->> 'revision' = :expected_revision "
                    "AND superseded_runtime_home_ref IS NULL AND ((:replacement "
                    "AND encrypted_runtime_home_ref = :superseded_runtime_ref) OR "
                    "(NOT :replacement AND encrypted_runtime_home_ref = "
                    ":runtime_ref))"
                ).bindparams(_METADATA_BIND),
                parameters
                | {
                    "expected_revision": str(expected_revision),
                    "superseded_runtime_ref": superseded_ref,
                    "replacement": replacement,
                },
            )
        if result.rowcount != 1:
            raise ProviderPersistenceError
        if superseded_ref is not None:
            cleanup_result = await database.execute(
                text(
                    "INSERT INTO provider_runtime_home_cleanups (org_id, "
                    "requester_user_id, encrypted_runtime_home_ref, connection_id, "
                    "reason, status, requested_at, destroy_by) VALUES (:org, :user, "
                    ":superseded_runtime_ref, :id, 'superseded', 'scheduled', "
                    ":requested_at, :destroy_by)"
                ),
                {
                    "org": request.principal.org_id,
                    "user": request.principal.user_id,
                    "superseded_runtime_ref": superseded_ref,
                    "id": request.connection.connection_id,
                    "requested_at": request.requested_at,
                    "destroy_by": request.destroy_by,
                },
            )
            if cleanup_result.rowcount != 1:
                raise ProviderPersistenceError

    return operation


def confirm_completion_adoption(
    principal: ProviderPrincipal,
    connection_id: str,
    staging_lease_id: str,
) -> ProviderOperation[None]:
    """Build an exact pending-adoption lease confirmation operation."""

    async def operation(database: AsyncConnection) -> None:
        result = await database.execute(
            text(
                "UPDATE provider_connections SET account_metadata = "
                "account_metadata - 'staging_lease_id' - "
                "'staging_lease_destroy_by' - 'adoption_status' WHERE "
                "org_id = :org AND id = :id AND requester_user_id = :user "
                "AND account_metadata ->> 'staging_lease_id' = :lease "
                "AND account_metadata ->> 'adoption_status' = 'pending'"
            ),
            {
                "org": principal.org_id,
                "id": connection_id,
                "user": principal.user_id,
                "lease": staging_lease_id,
            },
        )
        if result.rowcount != 1:
            raise ProviderPersistenceError

    return operation


def _upsert_parameters(
    request: ProviderUpsertRequest,
    metadata: ProviderMetadata,
) -> dict[
    str,
    str | bool | datetime | ProviderMetadata | None,
]:
    connection = request.connection
    principal = request.principal
    return {
        "id": connection.connection_id,
        "org": principal.org_id,
        "user": principal.user_id,
        "adapter": connection.adapter_id,
        "runtime_ref": request.runtime_home_ref,
        "metadata": metadata,
        "model": connection.selected_model,
        "status": connection.health,
        "qualified": connection.qualified_live,
        "qualification_receipt_id": (
            None
            if connection.qualification is None
            else connection.qualification.receipt.receipt_id
        ),
        "health": connection.health,
        "created_at": connection.created_at,
    }
