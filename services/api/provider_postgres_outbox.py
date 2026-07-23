"""Requester cleanup outbox orchestration around vault destruction."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, final

from services.api.provider_postgres_cleanup_authority import (
    RequesterCleanupReason,
    validate_requester_cleanup,
)
from services.api.provider_postgres_cleanup_queries import (
    CleanupSchedule,
    RuntimeHomeDestruction,
    SupersededCleanupCompletion,
    cleanup_schedule,
    clear_superseded_runtime_home,
    complete_unbound_runtime_home,
    pending_unbound_runtime_homes,
    schedule_unbound_runtime_home,
)
from services.api.provider_postgres_support import (
    ProviderPersistenceError,
    RuntimeHomeDestroyer,
    destroy_runtime_home,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime, timedelta

    from sqlalchemy.ext.asyncio import AsyncConnection

    from services.api.provider_postgres_session import (
        ProviderOperation,
        ProviderPostgresSession,
    )
    from services.api.provider_runtime_contracts import (
        ProviderConnection,
        ProviderConnectionSnapshot,
        ProviderPrincipal,
    )
from services.api.provider_runtime_configuration import is_safe_runtime_home_ref


@dataclass(frozen=True, slots=True)
class SupersededRuntimeHome:
    """Exact current and replaced binding involved in cleanup."""

    principal: ProviderPrincipal
    connection: ProviderConnection
    runtime_home_ref: str
    superseded_runtime_home_ref: str


@final
@dataclass(frozen=True, slots=True)
class RequesterCleanupOutbox:
    """Resume requester-owned cleanup without a cross-tenant sweep surface."""

    session: ProviderPostgresSession
    destroyer: RuntimeHomeDestroyer
    clock: Callable[[], datetime]
    cleanup_window: timedelta

    def discard_runtime_home(
        self, principal: ProviderPrincipal, runtime_home_ref: str
    ) -> None:
        """Destroy exchanged material only when no owned connection bound it."""
        if not is_safe_runtime_home_ref(runtime_home_ref):
            raise ProviderPersistenceError
        requested_at = self.clock()
        schedule = CleanupSchedule(
            requested_at,
            requested_at + self.cleanup_window,
        )
        scheduled = self.session.run(
            principal,
            schedule_unbound_runtime_home(principal, runtime_home_ref, schedule),
        )
        if not scheduled:
            return
        _ = self.session.run(
            principal,
            self._authorized_cleanup(
                principal,
                runtime_home_ref,
                "unbound",
            ),
        )

    def resume_unbound_cleanups(self, principal: ProviderPrincipal) -> None:
        """Resume every requester-visible scheduled unbound cleanup in order."""
        for pending in self.session.run(principal, pending_unbound_runtime_homes()):
            _ = self.session.run(
                principal,
                self._authorized_cleanup(
                    principal,
                    pending.runtime_home_ref,
                    "unbound",
                ),
            )

    def destroy_superseded_runtime_home(self, binding: SupersededRuntimeHome) -> None:
        """Destroy an exact replacement predecessor and clear its pointer."""
        _ = self.session.run(
            binding.principal,
            cleanup_schedule(binding.superseded_runtime_home_ref, "superseded"),
        )
        _ = self.session.run(
            binding.principal,
            self._authorized_cleanup(
                binding.principal,
                binding.superseded_runtime_home_ref,
                "superseded",
                binding,
            ),
        )

    def resume_superseded_cleanup(
        self,
        principal: ProviderPrincipal,
        snapshot: ProviderConnectionSnapshot,
    ) -> ProviderConnectionSnapshot:
        """Complete a snapshot's durable predecessor cleanup if present."""
        superseded = snapshot.superseded_runtime_home_ref
        if superseded is None:
            return snapshot
        self.destroy_superseded_runtime_home(
            SupersededRuntimeHome(
                principal,
                snapshot.connection,
                snapshot.runtime_home_ref,
                superseded,
            )
        )
        return replace(snapshot, superseded_runtime_home_ref=None)

    def _destroy(
        self,
        runtime_home_ref: str,
        requested_at: datetime,
    ) -> RuntimeHomeDestruction:
        evidence = destroy_runtime_home(self.destroyer, runtime_home_ref)
        return RuntimeHomeDestruction(evidence, max(self.clock(), requested_at))

    def _authorized_cleanup(
        self,
        principal: ProviderPrincipal,
        runtime_home_ref: str,
        reason: RequesterCleanupReason,
        binding: SupersededRuntimeHome | None = None,
    ) -> ProviderOperation[RuntimeHomeDestruction]:
        async def operation(database: AsyncConnection) -> RuntimeHomeDestruction:
            connection_id = (
                None if binding is None else binding.connection.connection_id
            )
            requested_at = await validate_requester_cleanup(
                database,
                principal,
                connection_id,
                runtime_home_ref,
                reason,
            )
            destruction = self._destroy(runtime_home_ref, requested_at)
            if reason == "unbound":
                completion = complete_unbound_runtime_home(
                    principal,
                    runtime_home_ref,
                    destruction,
                )
            elif binding is not None:
                completion = clear_superseded_runtime_home(
                    SupersededCleanupCompletion(
                        principal,
                        binding.connection,
                        binding.runtime_home_ref,
                        runtime_home_ref,
                        destruction,
                    )
                )
            else:
                raise ProviderPersistenceError
            await completion(database)
            return destruction

        return operation
