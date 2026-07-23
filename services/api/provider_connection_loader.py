"""Stateless durable snapshot loading for provider connections."""

from __future__ import annotations

from typing import TYPE_CHECKING, final

from services.api.provider_connection_record import ConnectionRecord
from services.api.provider_runtime_contracts import (
    ERROR_PROVIDER_UNAVAILABLE,
    ConnectionNotFoundError,
    ProviderCleanupReceipt,
    ProviderConnection,
    ProviderConnectionSnapshot,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderRuntimeIdentity,
    ProviderUpsertControl,
    normalize_utc,
    runtime_error,
)
from services.api.provider_runtime_rules import (
    connection_view,
    require_cleanup_state,
    restored_connection_is_valid,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime

    from services.api.provider_qualification_receipt import (
        QualificationReceipt,
        QualificationReceiptVerifier,
    )


@final
class _ProviderConnectionLoader:
    """Parse durable snapshots without owning mutable connection state."""

    def __init__(
        self,
        clock: Callable[[], datetime],
        persistence: ProviderPersistence,
        runtime_identity: ProviderRuntimeIdentity | None,
        qualification_verifier: QualificationReceiptVerifier | None,
    ) -> None:
        self._clock = clock
        self._persistence = persistence
        self._runtime_identity = runtime_identity
        self._qualification_verifier = qualification_verifier

    def load(
        self,
        principal: ProviderPrincipal,
    ) -> tuple[tuple[ConnectionRecord, ...], tuple[ProviderCleanupReceipt, ...]]:
        snapshots = self._persistence.load(principal)
        restored = tuple(self._restore(principal, snapshot) for snapshot in snapshots)
        restored_ids = tuple(record.connection_id for record in restored)
        if len(restored_ids) != len(set(restored_ids)):
            raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)
        receipts = tuple(
            snapshot.cleanup_receipt
            for snapshot in snapshots
            if snapshot.cleanup_receipt is not None
        )
        now = normalize_utc(self._clock())
        for snapshot in snapshots:
            require_cleanup_state(snapshot, now)
        return restored, receipts

    def connections(
        self,
        principal: ProviderPrincipal,
    ) -> tuple[ProviderConnection, ...]:
        return tuple(connection_view(record) for record in self.load(principal)[0])

    def upsert(
        self,
        record: ConnectionRecord,
        expected_revision: int | None,
        superseded_runtime_home_ref: str | None,
        qualification_receipt: QualificationReceipt | None,
    ) -> None:
        self._persistence.upsert(
            record.principal,
            connection_view(record),
            record.runtime_home_ref,
            ProviderUpsertControl(
                expected_revision,
                superseded_runtime_home_ref,
                record.completion_adoption,
                qualification_receipt,
            ),
        )

    def detail(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
    ) -> ProviderConnection:
        record = next(
            (
                item
                for item in self.load(principal)[0]
                if item.connection_id == connection_id
            ),
            None,
        )
        if record is None:
            raise ConnectionNotFoundError
        return connection_view(record)

    def cleanup_receipt(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
    ) -> ProviderCleanupReceipt:
        records, receipts = self.load(principal)
        if not any(record.connection_id == connection_id for record in records):
            raise ConnectionNotFoundError
        receipt = next(
            (item for item in receipts if item.connection_id == connection_id),
            None,
        )
        if receipt is None:
            raise ConnectionNotFoundError
        return receipt

    def _restore(
        self,
        principal: ProviderPrincipal,
        snapshot: ProviderConnectionSnapshot,
    ) -> ConnectionRecord:
        connection = snapshot.connection
        current = restored_connection_is_valid(
            snapshot,
            self._runtime_identity,
            principal,
            self._qualification_verifier,
            self._clock(),
        )
        return ConnectionRecord(
            connection.connection_id,
            principal,
            connection.adapter_id,
            connection.account_id,
            connection.eligible_models,
            connection.selected_model,
            connection.health,
            connection.cleanup_verified and current,
            connection.qualified_live and current,
            normalize_utc(connection.created_at),
            snapshot.runtime_home_ref,
            connection.revision,
            connection.qualification,
            snapshot.completion_adoption,
        )


ProviderConnectionLoader = _ProviderConnectionLoader
