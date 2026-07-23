"""PostgreSQL serialization for immutable provider qualification receipts."""

from __future__ import annotations

from datetime import datetime
from typing import TYPE_CHECKING, cast

from sqlalchemy import text

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.ext.asyncio import AsyncConnection

from services.api.provider_qualification_receipt import (
    QualificationReceipt,
    QualificationReceiptClaim,
    QualificationReceiptSubject,
    qualification_receipt_is_well_formed,
    qualification_receipt_sha256,
)
from services.api.provider_runtime import (
    ProviderConnection,
    ProviderPrincipal,
    ProviderQualificationIdentity,
    ProviderRuntimeIdentity,
)


class QualificationReceiptPersistenceError(ValueError):
    """Reject a receipt that is inconsistent with its provider mutation."""


type QualificationMetadata = tuple[object, object, object, object]


async def append_qualification_receipt(
    database: AsyncConnection,
    principal: ProviderPrincipal,
    connection: ProviderConnection,
    receipt: QualificationReceipt,
) -> None:
    """Append the exact verified receipt before its connection pointer changes."""
    qualification = connection.qualification
    claim = receipt.claim
    subject = claim.subject
    if (
        qualification is None
        or qualification.receipt != receipt
        or qualification.receipt_sha256 != qualification_receipt_sha256(receipt)
        or not qualification_receipt_is_well_formed(receipt)
        or subject.org_id != principal.org_id
        or subject.user_id != principal.user_id
        or subject.connection_id != connection.connection_id
        or subject.connection_revision != connection.revision
        or claim.adapter_id != connection.adapter_id
        or claim.profile_sha256 != qualification.profile_sha256
        or claim.runtime_version != qualification.runtime.runtime_version
        or claim.executable_sha256 != qualification.runtime.executable_sha256
    ):
        raise QualificationReceiptPersistenceError
    result = await database.execute(
        text(
            "INSERT INTO provider_qualification_receipts (id, org_id, "
            "requester_user_id, provider_connection_id, connection_revision, "
            "adapter_id, profile_sha256, cases_sha256, operator_account_ref, "
            "oauth_mode, oauth_provider, runtime_version, executable_sha256, "
            "protocol_attempts, "
            "cleanup_terminal, cleanup_redaction_complete, authority_key_id, "
            "authority_issued_at, authority_algorithm, authority_signature, "
            "receipt_sha256) VALUES "
            "(:id, :org, :user, :connection, :revision, :adapter, :profile, "
            ":cases, :account, :oauth_mode, :oauth_provider, :runtime, :executable, "
            ":attempts, :terminal, :redacted, :key_id, :issued_at, :algorithm, "
            ":signature, :receipt_sha256)"
        ),
        {
            "id": receipt.receipt_id,
            "org": principal.org_id,
            "user": principal.user_id,
            "connection": connection.connection_id,
            "revision": connection.revision,
            "adapter": connection.adapter_id,
            "profile": claim.profile_sha256,
            "cases": claim.cases_sha256,
            "account": claim.operator_account_ref,
            "oauth_mode": claim.oauth_mode,
            "oauth_provider": claim.oauth_provider,
            "runtime": claim.runtime_version,
            "executable": claim.executable_sha256,
            "attempts": claim.protocol_attempts,
            "terminal": claim.cleanup_terminal,
            "redacted": claim.cleanup_redaction_complete,
            "key_id": receipt.key_id,
            "issued_at": receipt.issued_at,
            "algorithm": receipt.algorithm,
            "signature": receipt.signature,
            "receipt_sha256": qualification.receipt_sha256,
        },
    )
    if result.rowcount != 1:
        raise QualificationReceiptPersistenceError


def qualification_from_row(
    row: Mapping[str, object],
    *,
    adapter_id: str,
    metadata: QualificationMetadata,
) -> ProviderQualificationIdentity | None:
    """Reconstruct the exact current receipt selected by connection metadata."""
    receipt_metadata, runtime_metadata, executable_metadata, profile_metadata = metadata
    receipt_id = row.get("qualification_receipt_db_id")
    values = (
        receipt_metadata,
        runtime_metadata,
        executable_metadata,
        profile_metadata,
        receipt_id,
    )
    if not any(value is not None for value in values):
        return None
    if not all(isinstance(value, str) for value in values):
        raise QualificationReceiptPersistenceError
    subject = _subject(row)
    runtime = ProviderRuntimeIdentity(
        adapter_id,
        cast("str", runtime_metadata),
        cast("str", executable_metadata),
    )
    claim = _claim(
        row,
        subject,
        runtime,
        cast("str", profile_metadata),
    )
    issued_at = row.get("qualification_authority_issued_at")
    key_id = row.get("qualification_authority_key_id")
    algorithm = row.get("qualification_authority_algorithm")
    signature = row.get("qualification_authority_signature")
    stored_digest = row.get("qualification_receipt_stored_sha256")
    if (
        receipt_id != receipt_metadata
        or row.get("qualification_adapter_id") != adapter_id
        or row.get("qualification_profile_db_sha256") != profile_metadata
        or row.get("qualification_runtime_db_version") != runtime_metadata
        or row.get("qualification_executable_db_sha256") != executable_metadata
        or not isinstance(issued_at, datetime)
        or not isinstance(key_id, str)
        or not isinstance(algorithm, str)
        or not isinstance(signature, str)
        or not isinstance(stored_digest, str)
    ):
        raise QualificationReceiptPersistenceError
    receipt = QualificationReceipt(
        receipt_id=cast("str", receipt_id),
        issued_at=issued_at,
        key_id=key_id,
        algorithm=algorithm,
        claim=claim,
        signature=signature,
    )
    digest = qualification_receipt_sha256(receipt)
    if not qualification_receipt_is_well_formed(receipt) or digest != stored_digest:
        raise QualificationReceiptPersistenceError
    return ProviderQualificationIdentity(
        runtime=runtime,
        profile_sha256=cast("str", profile_metadata),
        receipt=receipt,
        receipt_sha256=digest,
    )


def qualification_connection_load_sql() -> str:
    """Return the static join used to load current qualification receipts."""
    return (
        "SELECT p.id, p.adapter_id, p.encrypted_runtime_home_ref, "
        "p.superseded_runtime_home_ref, p.account_metadata, p.selected_model, "
        "p.status, p.qualified_at, p.created_at, "
        "q.id::text AS qualification_receipt_db_id, "
        "q.org_id::text AS qualification_org_id, "
        "q.requester_user_id::text AS qualification_user_id, "
        "q.provider_connection_id::text AS qualification_connection_id, "
        "q.connection_revision AS qualification_connection_revision, "
        "q.adapter_id AS qualification_adapter_id, "
        "q.profile_sha256 AS qualification_profile_db_sha256, "
        "q.cases_sha256 AS qualification_cases_sha256, "
        "q.operator_account_ref AS qualification_operator_account_ref, "
        "q.oauth_mode AS qualification_oauth_mode, "
        "q.oauth_provider AS qualification_oauth_provider, "
        "q.runtime_version AS qualification_runtime_db_version, "
        "q.executable_sha256 AS qualification_executable_db_sha256, "
        "q.protocol_attempts AS qualification_protocol_attempts, "
        "q.cleanup_terminal AS qualification_cleanup_terminal, "
        "q.cleanup_redaction_complete AS qualification_cleanup_redaction_complete, "
        "q.authority_key_id AS qualification_authority_key_id, "
        "q.authority_issued_at AS qualification_authority_issued_at, "
        "q.authority_algorithm AS qualification_authority_algorithm, "
        "q.authority_signature AS qualification_authority_signature, "
        "q.receipt_sha256 AS qualification_receipt_stored_sha256 FROM "
        "provider_connections p LEFT JOIN provider_qualification_receipts q ON "
        "q.org_id = p.org_id AND q.requester_user_id = p.requester_user_id AND "
        "q.provider_connection_id = p.id AND q.id = p.qualification_receipt_id "
        "WHERE p.requester_user_id = NULLIF(current_setting('app.user_id', true), "
        "'')::uuid ORDER BY p.created_at, p.id"
    )


def _subject(row: Mapping[str, object]) -> QualificationReceiptSubject:
    org_id = row.get("qualification_org_id")
    user_id = row.get("qualification_user_id")
    connection_id = row.get("qualification_connection_id")
    revision = row.get("qualification_connection_revision")
    if (
        not isinstance(org_id, str)
        or not isinstance(user_id, str)
        or not isinstance(connection_id, str)
        or not isinstance(revision, int)
    ):
        raise QualificationReceiptPersistenceError
    return QualificationReceiptSubject(org_id, user_id, connection_id, revision)


def _claim(
    row: Mapping[str, object],
    subject: QualificationReceiptSubject,
    runtime: ProviderRuntimeIdentity,
    profile_sha256: str,
) -> QualificationReceiptClaim:
    cases = row.get("qualification_cases_sha256")
    account = row.get("qualification_operator_account_ref")
    oauth_mode = row.get("qualification_oauth_mode")
    oauth_provider = row.get("qualification_oauth_provider")
    attempts = row.get("qualification_protocol_attempts")
    terminal = row.get("qualification_cleanup_terminal")
    redacted = row.get("qualification_cleanup_redaction_complete")
    if (
        not isinstance(cases, str)
        or not isinstance(account, str)
        or not isinstance(oauth_mode, str)
        or not isinstance(oauth_provider, str)
        or not isinstance(attempts, int)
        or not isinstance(terminal, bool)
        or not isinstance(redacted, bool)
    ):
        raise QualificationReceiptPersistenceError
    return QualificationReceiptClaim(
        subject=subject,
        profile_sha256=profile_sha256,
        cases_sha256=cases,
        adapter_id=runtime.adapter_id,
        oauth_mode=oauth_mode,
        oauth_provider=oauth_provider,
        operator_account_ref=account,
        runtime_version=runtime.runtime_version,
        executable_sha256=runtime.executable_sha256,
        protocol_attempts=attempts,
        cleanup_terminal=terminal,
        cleanup_redaction_complete=redacted,
    )
