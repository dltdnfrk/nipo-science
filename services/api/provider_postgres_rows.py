"""Strict decoding of requester provider connection rows."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING

from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_postgres_row_fields import (
    CleanupRowFields,
    cleanup_receipt,
    metadata_datetime,
    provider_health,
    provider_models,
)
from services.api.provider_postgres_support import (
    ProviderPersistenceError,
    ProviderRowValue,
    is_sha256,
)
from services.api.provider_qualification_postgres import (
    QualificationReceiptPersistenceError,
    qualification_from_row,
)
from services.api.provider_runtime_configuration import is_safe_runtime_home_ref
from services.api.provider_runtime_contracts import (
    ProviderCompletionAdoption,
    ProviderConnection,
    ProviderConnectionSnapshot,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


def provider_snapshot_from_row(
    row: Mapping[str, ProviderRowValue],
) -> ProviderConnectionSnapshot:
    """Parse one database row into a complete redacted snapshot."""
    metadata_value = row.get("account_metadata")
    if not isinstance(metadata_value, dict):
        raise ProviderPersistenceError
    metadata = metadata_value
    adapter = row.get("adapter_id")
    runtime_home_ref = row.get("encrypted_runtime_home_ref")
    superseded_runtime_home_ref = row.get("superseded_runtime_home_ref")
    selected_model = row.get("selected_model")
    created_at = row.get("created_at")
    qualified_at = row.get("qualified_at")
    account_id = metadata.get("account_id")
    provider = metadata.get("provider")
    revision = metadata.get("revision")
    cleanup_status = metadata.get("cleanup_status")
    qualification_runtime_version = metadata.get("qualification_runtime_version")
    qualification_executable_sha256 = metadata.get("qualification_executable_sha256")
    qualification_profile_sha256 = metadata.get("qualification_profile_sha256")
    qualification_receipt_id = metadata.get("qualification_receipt_id")
    cleanup_requested_at = metadata_datetime(metadata, "cleanup_requested_at")
    destroy_by = metadata_datetime(metadata, "destroy_by")
    destroyed_at = metadata_datetime(metadata, "destroyed_at")
    evidence_sha256 = metadata.get("evidence_sha256")
    staging_lease_id = metadata.get("staging_lease_id")
    staging_lease_destroy_by = metadata_datetime(metadata, "staging_lease_destroy_by")
    adoption_status = metadata.get("adoption_status")
    models = provider_models(metadata.get("models"))
    qualification_values = (
        qualification_runtime_version,
        qualification_executable_sha256,
        qualification_profile_sha256,
        qualification_receipt_id,
    )
    if (cleanup_status is not None and not isinstance(cleanup_status, str)) or (
        adoption_status is not None and not isinstance(adoption_status, str)
    ):
        raise ProviderPersistenceError
    if (
        not isinstance(adapter, str)
        or not isinstance(runtime_home_ref, str)
        or (
            superseded_runtime_home_ref is not None
            and not isinstance(superseded_runtime_home_ref, str)
        )
        or (
            isinstance(superseded_runtime_home_ref, str)
            and (
                not is_safe_runtime_home_ref(superseded_runtime_home_ref)
                or superseded_runtime_home_ref == runtime_home_ref
            )
        )
        or (selected_model is not None and not isinstance(selected_model, str))
        or not isinstance(created_at, datetime)
        or (qualified_at is not None and not isinstance(qualified_at, datetime))
        or not isinstance(account_id, str)
        or (
            isinstance(selected_model, str)
            and not provider_model_id_is_valid(selected_model)
        )
        or provider != adapter
        or not isinstance(revision, str)
        or not revision.isdecimal()
        or any(value is not None for value in qualification_values)
        != all(value is not None for value in qualification_values)
        or cleanup_status not in {None, "scheduled", "completed"}
        or adoption_status not in {None, "pending"}
        or (adoption_status is None)
        != (staging_lease_id is None and staging_lease_destroy_by is None)
        or (
            adoption_status == "pending"
            and (
                not isinstance(staging_lease_id, str)
                or not staging_lease_id
                or staging_lease_destroy_by is None
            )
        )
    ):
        raise ProviderPersistenceError
    health = provider_health(row.get("status"))
    try:
        qualification = qualification_from_row(
            row,
            adapter_id=adapter,
            metadata=(
                qualification_receipt_id,
                qualification_runtime_version,
                qualification_executable_sha256,
                qualification_profile_sha256,
            ),
        )
    except QualificationReceiptPersistenceError as error:
        raise ProviderPersistenceError from error
    if (
        (qualified_at is not None and qualification is None)
        or (
            qualification is not None
            and (
                not is_sha256(qualification.runtime.executable_sha256)
                or not is_sha256(qualification.profile_sha256)
                or not qualification.runtime.runtime_version.startswith("codex-cli-")
            )
        )
        or (
            cleanup_status in {"scheduled", "completed"}
            and (
                health != "revoked"
                or selected_model is not None
                or cleanup_requested_at is None
                or destroy_by is None
            )
        )
        or (
            cleanup_status == "completed"
            and (destroyed_at is None or not isinstance(evidence_sha256, str))
        )
    ):
        raise ProviderPersistenceError
    qualified = qualified_at is not None
    connection = ProviderConnection(
        str(row.get("id")),
        adapter,
        account_id,
        models,
        selected_model,
        health,
        qualified,
        qualified,
        created_at,
        int(revision),
        qualification,
    )
    receipt = cleanup_receipt(
        connection,
        CleanupRowFields(
            cleanup_status,
            cleanup_requested_at,
            destroy_by,
            destroyed_at,
            evidence_sha256,
        ),
    )
    completion_adoption = (
        ProviderCompletionAdoption(
            connection.connection_id,
            staging_lease_id,
            runtime_home_ref,
            staging_lease_destroy_by,
        )
        if adoption_status == "pending"
        and isinstance(staging_lease_id, str)
        and staging_lease_destroy_by is not None
        else None
    )
    return ProviderConnectionSnapshot(
        connection,
        runtime_home_ref,
        receipt,
        cleanup_requested_at if cleanup_status == "scheduled" else None,
        destroy_by if cleanup_status == "scheduled" else None,
        superseded_runtime_home_ref,
        completion_adoption,
    )
