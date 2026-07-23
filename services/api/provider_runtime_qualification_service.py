"""Qualification and dispatch operations for the provider runtime service."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from services.api.provider_qualification import (
    QualificationResult,
    qualification_result_is_verified,
)
from services.api.provider_qualification_receipt import (
    QualificationReceiptSubject,
    qualification_receipt_sha256,
)
from services.api.provider_runtime_connection_service import (
    ProviderRuntimeConnectionServiceMixin,
)
from services.api.provider_runtime_contracts import (
    ERROR_QUALIFICATION_REQUIRED,
    AuditReceipt,
    DispatchAuthorization,
    ProviderCompletionAdoption,
    ProviderConnection,
    ProviderPrincipal,
    ProviderQualificationIdentity,
    ProviderRuntimeIdentity,
    normalize_utc,
    runtime_error,
)
from services.api.provider_runtime_rules import (
    require_dispatchable,
    require_mutable,
    require_revision,
)

if TYPE_CHECKING:
    from services.api.provider_connection_record import ConnectionRecord


class _ProviderRuntimeQualificationService(ProviderRuntimeConnectionServiceMixin):
    """Bind verified qualification and expose authorized dispatch metadata."""

    def record_qualification(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        result: QualificationResult,
        expected_revision: int | None = None,
    ) -> ProviderConnection:
        """Bind an externally verified result to the next connection revision."""
        if type(result) is not QualificationResult or result.receipt is None:
            raise runtime_error(ERROR_QUALIFICATION_REQUIRED)
        receipt = result.receipt
        identity = ProviderRuntimeIdentity(
            result.adapter,
            result.runtime_version,
            result.executable_sha256,
        )
        qualification = ProviderQualificationIdentity(
            identity,
            result.profile_sha256,
            receipt,
            qualification_receipt_sha256(receipt),
        )

        def update(record: ConnectionRecord) -> ConnectionRecord:
            subject = QualificationReceiptSubject(
                org_id=principal.org_id,
                user_id=principal.user_id,
                connection_id=record.connection_id,
                connection_revision=record.revision + 1,
            )
            verifier = self._connections.qualification_verifier
            if (
                not qualification_result_is_verified(result, verifier, subject)
                or verifier is None
                or not verifier.verify(receipt)
                or result.adapter != record.adapter_id
                or identity != self._connections.runtime_identity
                or receipt.issued_at > normalize_utc(self._connections.clock())
            ):
                raise runtime_error(ERROR_QUALIFICATION_REQUIRED)
            return replace(
                record,
                cleanup_verified=True,
                qualified_live=True,
                qualification=qualification,
            )

        connection = self._connections.mutate(
            principal,
            connection_id,
            expected_revision,
            update,
            receipt,
        )
        self._connections.record_audit(
            "qualification_cleanup_verified",
            connection.adapter_id,
        )
        return connection

    def preflight_qualification(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        expected_revision: int,
        identity: ProviderRuntimeIdentity,
    ) -> None:
        """Validate an owned target and current runtime before live capture."""

        def validate(record: ConnectionRecord) -> None:
            require_revision(record, expected_revision)
            require_mutable(record)
            if (
                record.adapter_id != identity.adapter_id
                or identity != self._connections.runtime_identity
            ):
                raise runtime_error(ERROR_QUALIFICATION_REQUIRED)

        self._connections.inspect(principal, connection_id, validate)

    def dispatch_authorization(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        model_id: str,
    ) -> DispatchAuthorization:
        """Authorize dispatch only for a qualified healthy selected model."""

        def authorize(record: ConnectionRecord) -> DispatchAuthorization:
            require_dispatchable(
                record,
                model_id,
                self._connections.runtime_identity,
            )
            qualification = record.qualification
            if qualification is None:
                raise runtime_error(ERROR_QUALIFICATION_REQUIRED)
            return DispatchAuthorization(
                adapter_id=record.adapter_id,
                connection_id=record.connection_id,
                model_id=model_id,
                qualification_receipt_id=qualification.receipt.receipt_id,
                qualification_receipt_sha256=qualification.receipt_sha256,
                qualification_connection_revision=(
                    qualification.receipt.claim.subject.connection_revision
                ),
                qualification_profile_sha256=qualification.profile_sha256,
                qualification_runtime_version=qualification.runtime.runtime_version,
                qualification_executable_sha256=(
                    qualification.runtime.executable_sha256
                ),
            )

        return self._connections.inspect(principal, connection_id, authorize)

    def audit_receipts(self) -> tuple[AuditReceipt, ...]:
        """Return redacted event names and adapter identifiers only."""
        return self._connections.audit_receipts()

    def pending_completion_adoptions(
        self,
        principal: ProviderPrincipal,
    ) -> tuple[tuple[ProviderCompletionAdoption, ProviderConnection], ...]:
        """Return durable adoption intents for idempotent broker reconciliation."""
        return self._connections.pending_adoptions(principal)

    def confirm_completion_adoption(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        staging_lease_id: str,
    ) -> None:
        """Clear a durable adoption intent only after its broker lease is adopted."""
        self._connections.confirm_adoption(
            principal,
            connection_id,
            staging_lease_id,
        )

    def active_connection_lock_count(self) -> int:
        """Return the number of connection locks currently in use."""
        return self._connections.active_lock_count()


ProviderRuntimeQualificationServiceMixin = _ProviderRuntimeQualificationService
