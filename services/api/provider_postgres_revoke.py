"""Requester provider revocation state machine."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, final

from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB

from services.api.provider_postgres_cleanup_authority import (
    validate_requester_cleanup,
)
from services.api.provider_postgres_support import (
    ProviderPersistenceError,
    RuntimeHomeDestroyer,
    destroy_runtime_home,
    safe_provider_metadata,
)
from services.api.provider_runtime_contracts import (
    ProviderCleanupReceipt,
    ProviderConnectionSnapshot,
    ProviderPrincipal,
    ProviderRevokeMutation,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from sqlalchemy.ext.asyncio import AsyncConnection

    from services.api.provider_postgres_session import (
        ProviderOperation,
        ProviderPostgresSession,
    )

_METADATA_BIND = bindparam("metadata", type_=JSONB)


@dataclass(frozen=True, slots=True)
class RevokeCompletion:
    """Exact scheduled mutation and destruction proof to complete."""

    principal: ProviderPrincipal
    mutation: ProviderRevokeMutation
    destroyed_at: datetime
    evidence: str


@final
@dataclass(frozen=True, slots=True)
class ProviderRevokeStateMachine:
    """Persist schedule before destruction and CAS the terminal tombstone."""

    session: ProviderPostgresSession
    destroyer: RuntimeHomeDestroyer
    clock: Callable[[], datetime]

    def revoke(
        self,
        principal: ProviderPrincipal,
        mutation: ProviderRevokeMutation,
    ) -> ProviderCleanupReceipt:
        """Schedule, destroy, then complete a requester-owned revocation."""
        _ = self.session.run(principal, _schedule_revoke(principal, mutation))
        completion = self.session.run(
            principal,
            self._authorized_completion(principal, mutation),
        )
        return _cleanup_receipt(completion)

    def resume_scheduled_cleanup(
        self,
        principal: ProviderPrincipal,
        snapshot: ProviderConnectionSnapshot,
    ) -> ProviderConnectionSnapshot:
        """Resume a scheduled revoked snapshot to its terminal tombstone."""
        requested_at = snapshot.cleanup_requested_at
        destroy_by = snapshot.destroy_by
        connection = snapshot.connection
        if requested_at is None or destroy_by is None or connection.health != "revoked":
            raise ProviderPersistenceError
        mutation = ProviderRevokeMutation(
            current=connection,
            proposed=connection,
            runtime_home_ref=snapshot.runtime_home_ref,
            expected_revision=connection.revision,
            requested_at=requested_at,
            destroy_by=destroy_by,
        )
        completion = self.session.run(
            principal,
            self._authorized_completion(principal, mutation),
        )
        return ProviderConnectionSnapshot(
            connection,
            _tombstone(connection.connection_id),
            _cleanup_receipt(completion),
            requested_at,
            destroy_by,
        )

    def _destroy(
        self,
        principal: ProviderPrincipal,
        mutation: ProviderRevokeMutation,
    ) -> RevokeCompletion:
        evidence = destroy_runtime_home(self.destroyer, mutation.runtime_home_ref)
        return RevokeCompletion(
            principal,
            mutation,
            max(self.clock(), mutation.requested_at),
            evidence,
        )

    def _authorized_completion(
        self,
        principal: ProviderPrincipal,
        mutation: ProviderRevokeMutation,
    ) -> ProviderOperation[RevokeCompletion]:
        async def operation(database: AsyncConnection) -> RevokeCompletion:
            requested_at = await validate_requester_cleanup(
                database,
                principal,
                mutation.proposed.connection_id,
                mutation.runtime_home_ref,
                "revoke",
            )
            if requested_at != mutation.requested_at:
                raise ProviderPersistenceError
            completion = self._destroy(principal, mutation)
            await _complete_revoke(completion)(database)
            return completion

        return operation


def _schedule_revoke(
    principal: ProviderPrincipal,
    mutation: ProviderRevokeMutation,
) -> ProviderOperation[None]:
    scheduled = safe_provider_metadata(mutation.proposed) | {
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
                "FOR UPDATE) UPDATE provider_connections SET status = 'revoked', "
                "selected_model = NULL, revoked_at = :revoked_at, "
                "account_metadata = :metadata WHERE id IN (SELECT id FROM locked) "
                "AND org_id = :org AND requester_user_id = :user"
            ).bindparams(_METADATA_BIND),
            {
                "org": principal.org_id,
                "id": mutation.current.connection_id,
                "user": principal.user_id,
                "expected_revision": str(mutation.expected_revision),
                "metadata": scheduled,
                "revoked_at": mutation.requested_at,
            },
        )
        if result.rowcount != 1:
            raise ProviderPersistenceError

    return operation


def _complete_revoke(completion: RevokeCompletion) -> ProviderOperation[None]:
    mutation = completion.mutation
    metadata = safe_provider_metadata(mutation.proposed) | {
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
                "account_metadata = :metadata WHERE org_id = :org AND id = :id "
                "AND requester_user_id = :user AND account_metadata ->> "
                "'revision' = :expected_revision AND account_metadata ->> "
                "'cleanup_status' = 'scheduled'"
            ).bindparams(_METADATA_BIND),
            {
                "org": completion.principal.org_id,
                "id": mutation.proposed.connection_id,
                "user": completion.principal.user_id,
                "revoked_at": mutation.requested_at,
                "tombstone": _tombstone(mutation.proposed.connection_id),
                "metadata": metadata,
                "expected_revision": str(mutation.proposed.revision),
            },
        )
        if result.rowcount != 1:
            raise ProviderPersistenceError

    return operation


def _cleanup_receipt(completion: RevokeCompletion) -> ProviderCleanupReceipt:
    mutation = completion.mutation
    return ProviderCleanupReceipt(
        mutation.proposed.connection_id,
        mutation.proposed.adapter_id,
        mutation.requested_at,
        mutation.destroy_by,
        completion.destroyed_at,
        completion.evidence,
    )


def _tombstone(connection_id: str) -> str:
    return f"vault://runtime/destroyed/{connection_id}"
