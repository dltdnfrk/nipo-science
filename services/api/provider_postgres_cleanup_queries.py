"""Requester-scoped runtime-home cleanup outbox SQL."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import text

from services.api.provider_postgres_support import ProviderPersistenceError

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection

    from services.api.provider_postgres_session import ProviderOperation
    from services.api.provider_runtime_contracts import (
        ProviderConnection,
        ProviderPrincipal,
    )


@dataclass(frozen=True, slots=True)
class CleanupSchedule:
    """Durable bounds for one runtime-home destruction."""

    requested_at: datetime
    destroy_by: datetime


@dataclass(frozen=True, slots=True)
class PendingUnboundCleanup:
    """One requester-visible unbound home awaiting destruction."""

    runtime_home_ref: str
    schedule: CleanupSchedule


@dataclass(frozen=True, slots=True)
class RuntimeHomeDestruction:
    """Canonical evidence and timestamp returned by the vault boundary."""

    evidence: str
    destroyed_at: datetime


@dataclass(frozen=True, slots=True)
class SupersededCleanupCompletion:
    """Exact binding and evidence needed to complete a replacement cleanup."""

    principal: ProviderPrincipal
    connection: ProviderConnection
    runtime_home_ref: str
    superseded_runtime_home_ref: str
    destruction: RuntimeHomeDestruction


def schedule_unbound_runtime_home(
    principal: ProviderPrincipal,
    runtime_home_ref: str,
    schedule: CleanupSchedule,
) -> ProviderOperation[bool]:
    """Build an advisory-locked unbound cleanup scheduling operation."""

    async def operation(database: AsyncConnection) -> bool:
        parameters = {
            "org": principal.org_id,
            "user": principal.user_id,
            "runtime_ref": runtime_home_ref,
        }
        _ = await database.execute(
            text("SELECT pg_advisory_xact_lock(hashtextextended(:runtime_ref, 0))"),
            parameters,
        )
        bound = await database.execute(
            text(
                "SELECT EXISTS (SELECT 1 FROM provider_connections WHERE "
                "requester_user_id = :user AND (encrypted_runtime_home_ref = "
                ":runtime_ref OR superseded_runtime_home_ref = :runtime_ref))"
            ),
            parameters,
        )
        if bound.scalar_one() is True:
            return False
        _ = await database.execute(
            text(
                "INSERT INTO provider_runtime_home_cleanups (org_id, "
                "requester_user_id, encrypted_runtime_home_ref, connection_id, "
                "reason, status, requested_at, destroy_by) VALUES (:org, :user, "
                ":runtime_ref, NULL, 'unbound', 'scheduled', :requested_at, "
                ":destroy_by) ON CONFLICT DO NOTHING"
            ),
            parameters
            | {
                "requested_at": schedule.requested_at,
                "destroy_by": schedule.destroy_by,
            },
        )
        status = await database.execute(
            text(
                "SELECT status FROM provider_runtime_home_cleanups WHERE "
                "org_id = :org AND requester_user_id = :user AND "
                "encrypted_runtime_home_ref = :runtime_ref"
            ),
            parameters,
        )
        status_value = cast("str", status.scalar_one())
        return status_value == "scheduled"

    return operation


def complete_unbound_runtime_home(
    principal: ProviderPrincipal,
    runtime_home_ref: str,
    destruction: RuntimeHomeDestruction,
) -> ProviderOperation[None]:
    """Build an exact scheduled-to-completed unbound cleanup transition."""

    async def operation(database: AsyncConnection) -> None:
        result = await database.execute(
            text(
                "SELECT public.complete_provider_cleanup_outbox("
                ":org, :user, NULL::uuid, :runtime_ref, 'unbound', "
                ":destroyed_at, :evidence)"
            ),
            {
                "org": principal.org_id,
                "user": principal.user_id,
                "runtime_ref": runtime_home_ref,
                "destroyed_at": destruction.destroyed_at,
                "evidence": destruction.evidence,
            },
        )
        if result.scalar_one() is not True:
            raise ProviderPersistenceError

    return operation


def cleanup_schedule(
    runtime_home_ref: str, reason: str
) -> ProviderOperation[CleanupSchedule]:
    """Build an exact scheduled cleanup bounds lookup."""

    async def operation(database: AsyncConnection) -> CleanupSchedule:
        result = await database.execute(
            text(
                "SELECT requested_at, destroy_by FROM "
                "provider_runtime_home_cleanups WHERE "
                "encrypted_runtime_home_ref = :runtime_ref AND reason = "
                ":reason AND status = 'scheduled'"
            ),
            {"runtime_ref": runtime_home_ref, "reason": reason},
        )
        row = result.mappings().one()
        requested_at = row.get("requested_at")
        destroy_by = row.get("destroy_by")
        if not isinstance(requested_at, datetime) or not isinstance(
            destroy_by, datetime
        ):
            raise ProviderPersistenceError
        return CleanupSchedule(requested_at, destroy_by)

    return operation


def pending_unbound_runtime_homes() -> ProviderOperation[
    tuple[PendingUnboundCleanup, ...]
]:
    """Build an ordered lookup of requester-visible scheduled unbound homes."""

    async def operation(
        database: AsyncConnection,
    ) -> tuple[PendingUnboundCleanup, ...]:
        result = await database.execute(
            text(
                "SELECT encrypted_runtime_home_ref, requested_at, destroy_by "
                "FROM provider_runtime_home_cleanups WHERE status = "
                "'scheduled' AND reason = 'unbound' "
                "ORDER BY created_at, encrypted_runtime_home_ref"
            )
        )
        pending: list[PendingUnboundCleanup] = []
        for row in result.mappings():
            runtime_home_ref = row.get("encrypted_runtime_home_ref")
            requested_at = row.get("requested_at")
            destroy_by = row.get("destroy_by")
            if (
                not isinstance(runtime_home_ref, str)
                or not isinstance(requested_at, datetime)
                or not isinstance(destroy_by, datetime)
            ):
                raise ProviderPersistenceError
            pending.append(
                PendingUnboundCleanup(
                    runtime_home_ref,
                    CleanupSchedule(requested_at, destroy_by),
                )
            )
        return tuple(pending)

    return operation


def clear_superseded_runtime_home(
    completion: SupersededCleanupCompletion,
) -> ProviderOperation[None]:
    """Build the pointer-clear and outbox-completion transaction."""

    async def operation(database: AsyncConnection) -> None:
        principal = completion.principal
        connection = completion.connection
        result = await database.execute(
            text(
                "SELECT public.complete_provider_cleanup_outbox("
                ":org, :user, :id, :superseded_runtime_ref, 'superseded', "
                ":destroyed_at, :evidence)"
            ),
            {
                "org": principal.org_id,
                "id": connection.connection_id,
                "user": principal.user_id,
                "superseded_runtime_ref": completion.superseded_runtime_home_ref,
                "destroyed_at": completion.destruction.destroyed_at,
                "evidence": completion.destruction.evidence,
            },
        )
        if result.scalar_one() is not True:
            raise ProviderPersistenceError

    return operation
