"""Exclusive mutable state for the provider connection aggregate."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, replace
from threading import RLock
from typing import TYPE_CHECKING, final

from services.api.provider_connection_loader import ProviderConnectionLoader
from services.api.provider_runtime_contracts import (
    ERROR_PROVIDER_UNAVAILABLE,
    ERROR_REVISION_CONFLICT,
    AuditReceipt,
    ConnectionNotFoundError,
    ProviderCompletionAdoption,
    ProviderConnection,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderRuntimeError,
    ProviderRuntimeIdentity,
    runtime_error,
)
from services.api.provider_runtime_rules import (
    connection_view,
    require_mutable,
    require_revision,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Generator
    from datetime import datetime, timedelta

    from services.api.provider_connection_record import ConnectionRecord
    from services.api.provider_qualification_receipt import (
        QualificationReceipt,
        QualificationReceiptVerifier,
    )
    from services.api.provider_runtime_configuration import ProviderCleanupPolicy


@dataclass(slots=True)
class _ConnectionLock:
    lock: RLock
    users: int = 0


@final
class _ProviderConnectionState:
    """Own every mutable connection collection and its synchronization."""

    def __init__(
        self,
        clock: Callable[[], datetime],
        id_factory: Callable[[], str],
        persistence: ProviderPersistence,
        cleanup_policy: ProviderCleanupPolicy,
    ) -> None:
        self.clock = clock
        self.runtime_identity: ProviderRuntimeIdentity | None = (
            cleanup_policy.runtime_identity
        )
        self.qualification_verifier: QualificationReceiptVerifier | None = (
            cleanup_policy.qualification_verifier
        )
        self.persistence = persistence
        self.cleanup_window: timedelta = cleanup_policy.runtime_home_destruction_window
        self.id_factory = id_factory
        self.loader = ProviderConnectionLoader(
            clock,
            persistence,
            self.runtime_identity,
            self.qualification_verifier,
        )
        self.connections: dict[str, ConnectionRecord] = {}
        self._loaded_principals: set[ProviderPrincipal] = set()
        self.audit: list[AuditReceipt] = []
        self.lock = RLock()
        self.connection_locks: dict[str, _ConnectionLock] = {}

    def inspect[T](
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        operation: Callable[[ConnectionRecord], T],
    ) -> T:
        self.ensure_loaded(principal)
        with self.locked(principal, connection_id):
            return operation(self.record(principal, connection_id))

    def mutate(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        expected_revision: int | None,
        update: Callable[[ConnectionRecord], ConnectionRecord],
        qualification_receipt: QualificationReceipt | None = None,
    ) -> ProviderConnection:
        self.ensure_loaded(principal)
        with self.locked(principal, connection_id):
            record = self.record(principal, connection_id)
            require_revision(record, expected_revision)
            require_mutable(record)
            proposed = replace(update(record), revision=record.revision + 1)
            self.persist(
                proposed, record.revision, qualification_receipt=qualification_receipt
            )
            self.publish(record, proposed)
            return connection_view(proposed)

    def record(
        self, principal: ProviderPrincipal, connection_id: str
    ) -> ConnectionRecord:
        with self.lock:
            record = self.connections.get(connection_id)
            if record is None or record.principal != principal:
                raise ConnectionNotFoundError
            return record

    def publish(
        self,
        expected: ConnectionRecord | None,
        proposed: ConnectionRecord,
        event: str | None = None,
    ) -> None:
        with self.lock:
            if self.connections.get(proposed.connection_id) != expected:
                raise runtime_error(ERROR_REVISION_CONFLICT)
            self.connections[proposed.connection_id] = proposed
            if event is not None:
                self.audit.append((event, proposed.adapter_id))

    def append_expected_audit(self, expected: ConnectionRecord, event: str) -> None:
        with self.lock:
            if self.connections.get(expected.connection_id) != expected:
                raise runtime_error(ERROR_REVISION_CONFLICT)
            self.audit.append((event, expected.adapter_id))

    def pending_adoptions(
        self, principal: ProviderPrincipal
    ) -> tuple[tuple[ProviderCompletionAdoption, ProviderConnection], ...]:
        self.ensure_loaded(principal)
        with self.lock:
            return tuple(
                (record.completion_adoption, connection_view(record))
                for record in sorted(
                    self.connections.values(), key=lambda item: item.connection_id
                )
                if record.principal == principal
                and record.completion_adoption is not None
            )

    def clear_adoption(self, expected: ConnectionRecord) -> None:
        self.publish(expected, replace(expected, completion_adoption=None))

    def persist(
        self,
        record: ConnectionRecord,
        expected_revision: int | None,
        superseded_runtime_home_ref: str | None = None,
        *,
        qualification_receipt: QualificationReceipt | None = None,
    ) -> None:
        try:
            self.loader.upsert(
                record,
                expected_revision,
                superseded_runtime_home_ref,
                qualification_receipt,
            )
        except ProviderRuntimeError:
            self.invalidate(record.principal)
            raise

    def invalidate(
        self, principal: ProviderPrincipal, preserve: ConnectionRecord | None = None
    ) -> None:
        with self.lock:
            self.connections = {
                connection_id: record
                for connection_id, record in self.connections.items()
                if record.principal != principal
                or (preserve is not None and connection_id == preserve.connection_id)
            }
            self._loaded_principals.discard(principal)

    def ensure_loaded(self, principal: ProviderPrincipal) -> None:
        with self.lock:
            if principal in self._loaded_principals:
                return
        restored, _ = self.loader.load(principal)
        with self.lock:
            if principal in self._loaded_principals:
                return
            for record in restored:
                existing = self.connections.get(record.connection_id)
                if existing is not None and existing.principal != principal:
                    raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)
                _ = self.connections.setdefault(record.connection_id, record)
            self._loaded_principals.add(principal)

    def _refresh_owned_record(
        self, principal: ProviderPrincipal, connection_id: str
    ) -> ConnectionRecord:
        restored, _ = self.loader.load(principal)
        record = next(
            (item for item in restored if item.connection_id == connection_id), None
        )
        with self.lock:
            existing = self.connections.get(connection_id)
            if record is None:
                if existing is not None and existing.principal == principal:
                    if existing.health == "revoked":
                        return existing
                    del self.connections[connection_id]
                raise ConnectionNotFoundError
            if existing is not None and existing.principal != principal:
                raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)
            if (
                existing is not None
                and existing.health == "revoked"
                and record.health != "revoked"
            ):
                return existing
            self.connections[connection_id] = record
            return record

    @contextmanager
    def locked(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        *,
        new: bool = False,
        refresh: bool = True,
    ) -> Generator[None, None, None]:
        if not new:
            with self.lock:
                cached = self.connections.get(connection_id)
                cached_owned = cached is not None and cached.principal == principal
            if not cached_owned and refresh:
                _ = self._refresh_owned_record(principal, connection_id)
        with self.lock:
            if new and connection_id in self.connections:
                raise runtime_error(ERROR_REVISION_CONFLICT)
            if not new:
                _ = self.record(principal, connection_id)
            entry = self.connection_locks.setdefault(
                connection_id, _ConnectionLock(RLock())
            )
            entry.users += 1
        _ = entry.lock.acquire()
        try:
            if new:
                with self.lock:
                    if connection_id in self.connections:
                        raise runtime_error(ERROR_REVISION_CONFLICT)
            elif refresh:
                _ = self._refresh_owned_record(principal, connection_id)
            else:
                _ = self.record(principal, connection_id)
            yield
        finally:
            entry.lock.release()
            with self.lock:
                entry.users -= 1
                if (
                    entry.users == 0
                    and self.connection_locks.get(connection_id) is entry
                ):
                    del self.connection_locks[connection_id]


ProviderConnectionState = _ProviderConnectionState
