"""Provider connection workflows over one exclusive state owner."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING, final

from services.api.provider_connection_record import ConnectionRecord
from services.api.provider_connection_state import ProviderConnectionState
from services.api.provider_runtime_contracts import (
    ERROR_INVALID_CONNECTION_ID,
    ERROR_REVISION_CONFLICT,
    OfficialOAuthCompletion,
    ProviderCleanupReceipt,
    ProviderConnection,
    ProviderConnectionSnapshot,
    ProviderPrincipal,
    ProviderRevokeMutation,
    ProviderRuntimeError,
    normalize_utc,
    runtime_error,
)
from services.api.provider_runtime_rules import (
    connection_view,
    require_cleanup_state,
    require_mutable,
    require_reauth_target,
    require_revision,
    validate_completion,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from services.api.provider_oauth_state import OAuthAttempt
    from services.api.provider_qualification_receipt import (
        QualificationReceipt,
        QualificationReceiptVerifier,
    )
    from services.api.provider_runtime_configuration import ProviderCleanupPolicy
    from services.api.provider_runtime_contracts import (
        AuditReceipt,
        ProviderCompletionAdoption,
        ProviderPersistence,
        ProviderRuntimeIdentity,
    )


@final
class _ProviderConnectionAggregate:
    """Coordinate connection workflows without owning a second state copy."""

    def __init__(
        self,
        clock: Callable[[], datetime],
        id_factory: Callable[[], str],
        persistence: ProviderPersistence,
        cleanup_policy: ProviderCleanupPolicy,
    ) -> None:
        self._state = ProviderConnectionState(
            clock,
            id_factory,
            persistence,
            cleanup_policy,
        )

    @property
    def runtime_identity(self) -> ProviderRuntimeIdentity | None:
        return self._state.runtime_identity

    @property
    def qualification_verifier(self) -> QualificationReceiptVerifier | None:
        return self._state.qualification_verifier

    @property
    def clock(self) -> Callable[[], datetime]:
        return self._state.clock

    def record_audit(self, event: str, adapter_id: str) -> None:
        with self._state.lock:
            self._state.audit.append((event, adapter_id))

    def load_principal(self, principal: ProviderPrincipal) -> None:
        self._state.ensure_loaded(principal)

    def audit_receipts(self) -> tuple[AuditReceipt, ...]:
        with self._state.lock:
            return tuple(self._state.audit)

    def list_connections(
        self, principal: ProviderPrincipal
    ) -> tuple[ProviderConnection, ...]:
        return self._state.loader.connections(principal)

    def connection_detail(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
    ) -> ProviderConnection:
        return self._state.loader.detail(principal, connection_id)

    def inspect[T](
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        operation: Callable[[ConnectionRecord], T],
    ) -> T:
        return self._state.inspect(principal, connection_id, operation)

    def mutate(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        expected_revision: int | None,
        update: Callable[[ConnectionRecord], ConnectionRecord],
        qualification_receipt: QualificationReceipt | None = None,
    ) -> ProviderConnection:
        return self._state.mutate(
            principal,
            connection_id,
            expected_revision,
            update,
            qualification_receipt,
        )

    def finalize(
        self,
        principal: ProviderPrincipal,
        attempt: OAuthAttempt,
        completion: OfficialOAuthCompletion,
    ) -> ProviderConnection:
        validate_completion(completion, self.clock())
        connection_id = attempt.reauth_connection_id or self._state.id_factory()
        if not connection_id:
            raise runtime_error(ERROR_INVALID_CONNECTION_ID)
        created_at = normalize_utc(self.clock())
        with self._state.locked(
            principal,
            connection_id,
            new=attempt.reauth_connection_id is None,
        ):
            current = (
                None
                if attempt.reauth_connection_id is None
                else self._state.record(principal, connection_id)
            )
            if current is not None:
                require_mutable(current)
                require_reauth_target(current, attempt.reauth_revision)
            record = (
                ConnectionRecord.from_new_completion(
                    attempt,
                    completion,
                    connection_id,
                    created_at,
                )
                if current is None
                else current.with_reauthentication(completion)
            )
            self._state.persist(
                record,
                None if current is None else current.revision,
                (
                    None
                    if current is None
                    or current.runtime_home_ref == completion.vault_home_ref
                    else current.runtime_home_ref
                ),
            )
            self._state.publish(current, record, "oauth_completed")
            return connection_view(record)

    def revoke(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        expected_revision: int | None,
    ) -> ProviderCleanupReceipt:
        requested_at = normalize_utc(self.clock())
        with self._state.locked(principal, connection_id):
            record = self._state.record(principal, connection_id)
            require_revision(record, expected_revision)
            require_mutable(record)
            proposed = replace(
                record,
                health="revoked",
                selected_model=None,
                revision=record.revision + 1,
            )
            self._state.publish(record, proposed, "connection_revocation_pending")
            mutation = ProviderRevokeMutation(
                connection_view(record),
                connection_view(proposed),
                record.runtime_home_ref,
                record.revision,
                requested_at,
                requested_at + self._state.cleanup_window,
            )
            try:
                receipt = self._state.persistence.revoke(principal, mutation)
                require_cleanup_state(
                    ProviderConnectionSnapshot(
                        connection_view(proposed),
                        record.runtime_home_ref,
                        receipt,
                    ),
                    normalize_utc(self.clock()),
                )
            except ProviderRuntimeError:
                self._state.invalidate(principal, proposed)
                raise
            self._state.append_expected_audit(proposed, "connection_revoked")
            return receipt

    def cleanup_receipt(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
    ) -> ProviderCleanupReceipt:
        return self._state.loader.cleanup_receipt(principal, connection_id)

    def pending_adoptions(
        self,
        principal: ProviderPrincipal,
    ) -> tuple[tuple[ProviderCompletionAdoption, ProviderConnection], ...]:
        return self._state.pending_adoptions(principal)

    def confirm_adoption(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        staging_lease_id: str,
    ) -> None:
        with self._state.locked(principal, connection_id, refresh=False):
            record = self._state.record(principal, connection_id)
            adoption = record.completion_adoption
            if adoption is None or adoption.staging_lease_id != staging_lease_id:
                raise runtime_error(ERROR_REVISION_CONFLICT)
            try:
                self._state.persistence.confirm_completion_adoption(
                    principal,
                    connection_id,
                    staging_lease_id,
                )
            except ProviderRuntimeError:
                self._state.invalidate(principal)
                raise
            self._state.clear_adoption(record)

    def active_lock_count(self) -> int:
        with self._state.lock:
            return len(self._state.connection_locks)


ProviderConnectionAggregate = _ProviderConnectionAggregate
