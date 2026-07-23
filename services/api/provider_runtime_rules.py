"""Pure validation rules for durable provider connection state."""

from __future__ import annotations

from typing import TYPE_CHECKING

from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_qualification import (
    QualificationResult,
    qualification_result_is_verified,
)
from services.api.provider_qualification_receipt import qualification_receipt_sha256
from services.api.provider_runtime_configuration import (
    is_safe_runtime_home_ref,
    provider_adapter_exists,
)
from services.api.provider_runtime_contracts import (
    ERROR_INVALID_COMPLETION,
    ERROR_MODEL_UNAVAILABLE,
    ERROR_PROVIDER_CLEANUP_OVERDUE,
    ERROR_PROVIDER_UNAVAILABLE,
    ERROR_QUALIFICATION_REQUIRED,
    ERROR_QUOTA_EXHAUSTED,
    ERROR_REAUTH_REQUIRED,
    ERROR_REVISION_CONFLICT,
    ERROR_UNSAFE_COMPLETION,
    OfficialOAuthCompletion,
    ProviderConnection,
    ProviderConnectionSnapshot,
    ProviderPrincipal,
    ProviderRuntimeIdentity,
    normalize_utc,
    runtime_error,
)

if TYPE_CHECKING:
    from datetime import datetime

    from services.api.provider_connection_record import ConnectionRecord
    from services.api.provider_qualification_receipt import QualificationReceiptVerifier


def _connection_view(record: ConnectionRecord) -> ProviderConnection:
    return ProviderConnection(
        connection_id=record.connection_id,
        adapter_id=record.adapter_id,
        account_id=record.account_id,
        eligible_models=record.eligible_models,
        selected_model=record.selected_model,
        health=record.health,
        cleanup_verified=record.cleanup_verified,
        qualified_live=record.qualified_live,
        created_at=record.created_at,
        revision=record.revision,
        qualification=record.qualification,
    )


def _connection_is_qualified(record: ConnectionRecord) -> bool:
    return record.cleanup_verified and record.qualified_live


def _require_revision(record: ConnectionRecord, expected_revision: int | None) -> None:
    if expected_revision is not None and expected_revision != record.revision:
        raise runtime_error(ERROR_REVISION_CONFLICT)


def _require_mutable(record: ConnectionRecord) -> None:
    if record.health == "revoked":
        raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)


def _require_reauth_target(
    record: ConnectionRecord,
    expected_revision: int | None,
) -> None:
    if (
        expected_revision is None
        or record.revision != expected_revision
        or record.health != "reauth_required"
        or record.completion_adoption is not None
    ):
        raise runtime_error(ERROR_REVISION_CONFLICT)


def _validate_completion(completion: OfficialOAuthCompletion, now: datetime) -> None:
    if (
        not is_safe_runtime_home_ref(completion.vault_home_ref)
        or not completion.account_id
        or not completion.eligible_models
        or not completion.staging_lease_id
        or normalize_utc(completion.destroy_by) <= normalize_utc(now)
    ):
        raise runtime_error(ERROR_INVALID_COMPLETION)
    if any(
        not provider_model_id_is_valid(model) for model in completion.eligible_models
    ):
        raise runtime_error(ERROR_INVALID_COMPLETION)
    if any(
        "token" in key.lower()
        or "secret" in key.lower()
        or "token" in value.lower()
        or "bearer " in value.lower()
        for key, value in completion.metadata.items()
    ):
        raise runtime_error(ERROR_UNSAFE_COMPLETION)


def _require_cleanup_state(snapshot: ProviderConnectionSnapshot, now: datetime) -> None:
    connection = snapshot.connection
    receipt = snapshot.cleanup_receipt
    requested_at = snapshot.cleanup_requested_at
    destroy_by = snapshot.destroy_by
    if receipt is None:
        if (requested_at is None) != (destroy_by is None):
            raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)
        if requested_at is None or destroy_by is None:
            if connection.health == "revoked":
                raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)
            return
        requested = normalize_utc(requested_at)
        deadline = normalize_utc(destroy_by)
        if connection.health != "revoked" or deadline <= requested:
            raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)
        if normalize_utc(now) >= deadline:
            raise runtime_error(ERROR_PROVIDER_CLEANUP_OVERDUE)
        return
    receipt_requested = normalize_utc(receipt.requested_at)
    receipt_deadline = normalize_utc(receipt.destroy_by)
    destroyed_at = normalize_utc(receipt.destroyed_at)
    if (
        receipt.connection_id != connection.connection_id
        or receipt.adapter_id != connection.adapter_id
        or connection.health != "revoked"
        or receipt_deadline <= receipt_requested
        or destroyed_at < receipt_requested
        or (requested_at is None) != (destroy_by is None)
        or (
            requested_at is not None
            and normalize_utc(requested_at) != receipt_requested
        )
        or (destroy_by is not None and normalize_utc(destroy_by) != receipt_deadline)
    ):
        raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)


def _restored_connection_is_valid(
    snapshot: ProviderConnectionSnapshot,
    runtime_identity: ProviderRuntimeIdentity | None,
    principal: ProviderPrincipal,
    verifier: QualificationReceiptVerifier | None,
    now: datetime,
) -> bool:
    connection = snapshot.connection
    if (
        not provider_adapter_exists(connection.adapter_id)
        or not connection.connection_id
        or not connection.account_id
        or not connection.eligible_models
        or any(
            not provider_model_id_is_valid(model)
            for model in connection.eligible_models
        )
        or (
            connection.selected_model is not None
            and not provider_model_id_is_valid(connection.selected_model)
        )
        or connection.revision < 1
        or not is_safe_runtime_home_ref(snapshot.runtime_home_ref)
        or connection.selected_model not in (None, *connection.eligible_models)
        or connection.cleanup_verified != connection.qualified_live
        or (connection.health == "healthy" and not connection.qualified_live)
        or (connection.qualified_live and connection.qualification is None)
    ):
        raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)
    return (
        connection.qualification is not None
        and connection.qualification.runtime == runtime_identity
        and _qualification_is_verified(
            principal, connection, verifier, normalize_utc(now)
        )
    )


def _qualification_is_verified(
    principal: ProviderPrincipal,
    connection: ProviderConnection,
    verifier: QualificationReceiptVerifier | None,
    now: datetime,
) -> bool:
    qualification = connection.qualification
    if qualification is None:
        return False
    receipt = qualification.receipt
    subject = receipt.claim.subject
    result = QualificationResult(
        contract_valid=True,
        live_qualified=True,
        profile_sha256=qualification.profile_sha256,
        evidence_kind="captured_live_profile",
        adapter=qualification.runtime.adapter_id,
        operator_account_ref=receipt.claim.operator_account_ref,
        runtime_version=qualification.runtime.runtime_version,
        executable_sha256=qualification.runtime.executable_sha256,
        receipt=receipt,
    )
    return (
        subject.org_id == principal.org_id
        and subject.user_id == principal.user_id
        and subject.connection_id == connection.connection_id
        and subject.connection_revision <= connection.revision
        and receipt.issued_at <= now
        and qualification.receipt_sha256 == qualification_receipt_sha256(receipt)
        and qualification_result_is_verified(result, verifier, subject)
    )


def _require_dispatchable(
    record: ConnectionRecord,
    model_id: str,
    runtime_identity: ProviderRuntimeIdentity | None,
) -> None:
    if record.completion_adoption is not None:
        raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)
    if record.health == "reauth_required":
        raise runtime_error(ERROR_REAUTH_REQUIRED)
    if record.health == "quota_exhausted":
        raise runtime_error(ERROR_QUOTA_EXHAUSTED)
    if record.health != "healthy":
        raise runtime_error(ERROR_PROVIDER_UNAVAILABLE)
    if (
        not _connection_is_qualified(record)
        or record.qualification is None
        or record.qualification.runtime != runtime_identity
    ):
        raise runtime_error(ERROR_QUALIFICATION_REQUIRED)
    if (
        not provider_model_id_is_valid(model_id)
        or record.selected_model != model_id
        or model_id not in record.eligible_models
    ):
        raise runtime_error(ERROR_MODEL_UNAVAILABLE)


connection_is_qualified = _connection_is_qualified
connection_view = _connection_view
require_cleanup_state = _require_cleanup_state
require_dispatchable = _require_dispatchable
require_mutable = _require_mutable
require_reauth_target = _require_reauth_target
require_revision = _require_revision
restored_connection_is_valid = _restored_connection_is_valid
validate_completion = _validate_completion
