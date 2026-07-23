"""Requester provider persistence composition."""

from __future__ import annotations

from contextlib import suppress
from datetime import timedelta
from typing import TYPE_CHECKING, final, override

from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_postgres_connections import (
    ProviderUpsertRequest,
    confirm_completion_adoption,
    load_provider_connections,
    upsert_provider_connection,
)
from services.api.provider_postgres_outbox import (
    RequesterCleanupOutbox,
    SupersededRuntimeHome,
)
from services.api.provider_postgres_revoke import ProviderRevokeStateMachine
from services.api.provider_postgres_session import ProviderPostgresSession
from services.api.provider_postgres_support import (
    ProviderPersistenceError,
    RuntimeHomeDestroyer,
)
from services.api.provider_runtime_contracts import (
    ProviderCleanupReceipt,
    ProviderConnection,
    ProviderConnectionSnapshot,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderRevokeMutation,
    ProviderRuntimeError,
    ProviderUpsertControl,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from services.api.provider_qualification_writer import QualificationWriter


@final
class PostgresProviderPersistence(ProviderPersistence):
    """Persist redacted provider state through the forced-RLS application role."""

    def __init__(
        self,
        database_url: str,
        destroyer: RuntimeHomeDestroyer,
        *,
        clock: Callable[[], datetime],
        cleanup_window: timedelta,
        qualification_writer: QualificationWriter | None = None,
    ) -> None:
        """Compose requester SQL, cleanup outbox, and revocation state."""
        if cleanup_window <= timedelta(0):
            raise ProviderPersistenceError
        session = ProviderPostgresSession(database_url)
        self._session = session
        self._clock = clock
        self._cleanup_window = cleanup_window
        self._qualification_writer = qualification_writer
        self._outbox = RequesterCleanupOutbox(
            session,
            destroyer,
            clock,
            cleanup_window,
        )
        self._revocations = ProviderRevokeStateMachine(session, destroyer, clock)

    @override
    def upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        control: ProviderUpsertControl,
    ) -> None:
        """Insert or CAS-update a connection and clean a replaced runtime home."""
        if (
            not connection.eligible_models
            or any(
                not provider_model_id_is_valid(model)
                for model in connection.eligible_models
            )
            or (
                connection.selected_model is not None
                and not provider_model_id_is_valid(connection.selected_model)
            )
        ):
            raise ProviderPersistenceError
        requested_at = self._clock()
        request = ProviderUpsertRequest(
            principal,
            connection,
            runtime_home_ref,
            control.expected_revision,
            control.superseded_runtime_home_ref,
            requested_at,
            requested_at + self._cleanup_window,
            control.completion_adoption,
        )
        if control.qualification_receipt is not None:
            if (
                self._qualification_writer is None
                or control.expected_revision is None
                or control.superseded_runtime_home_ref is not None
                or control.completion_adoption is not None
            ):
                raise ProviderPersistenceError
            self._qualification_writer.adopt(
                principal,
                connection,
                runtime_home_ref,
                control.qualification_receipt,
                expected_revision=control.expected_revision,
            )
        else:
            _ = self._session.run(principal, upsert_provider_connection(request))
        superseded_runtime_home_ref = control.superseded_runtime_home_ref
        if superseded_runtime_home_ref is not None:
            # The binding already committed, so durable cleanup failure must not
            # invite caller compensation that destroys the newly adopted home.
            with suppress(ProviderRuntimeError):
                self._outbox.destroy_superseded_runtime_home(
                    SupersededRuntimeHome(
                        principal,
                        connection,
                        runtime_home_ref,
                        superseded_runtime_home_ref,
                    )
                )

    @override
    def confirm_completion_adoption(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        staging_lease_id: str,
    ) -> None:
        """Clear an exact pending adoption lease through requester-scoped RLS."""
        _ = self._session.run(
            principal,
            confirm_completion_adoption(
                principal,
                connection_id,
                staging_lease_id,
            ),
        )

    @override
    def discard_runtime_home(
        self,
        principal: ProviderPrincipal,
        runtime_home_ref: str,
    ) -> None:
        """Destroy exchanged material only when no owned connection bound it."""
        self._outbox.discard_runtime_home(principal, runtime_home_ref)

    @override
    def load(
        self,
        principal: ProviderPrincipal,
    ) -> tuple[ProviderConnectionSnapshot, ...]:
        """Load one requester's durable redacted state through forced RLS."""
        self._outbox.resume_unbound_cleanups(principal)
        snapshots = tuple(
            self._outbox.resume_superseded_cleanup(principal, snapshot)
            for snapshot in self._session.run(principal, load_provider_connections())
        )
        return tuple(
            self._revocations.resume_scheduled_cleanup(principal, snapshot)
            if snapshot.cleanup_requested_at is not None
            and snapshot.cleanup_receipt is None
            else snapshot
            for snapshot in snapshots
        )

    @override
    def revoke(
        self,
        principal: ProviderPrincipal,
        mutation: ProviderRevokeMutation,
    ) -> ProviderCleanupReceipt:
        """Schedule, destroy, then complete a requester-owned revocation."""
        return self._revocations.revoke(principal, mutation)
