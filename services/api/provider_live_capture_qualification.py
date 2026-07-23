"""Live qualification evaluation, runtime recording, and adopter CAS assembly."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from services.api.provider_live_capture_errors import (
    ERROR_LIVE_QUALIFICATION,
    capture_error,
)
from services.api.provider_live_capture_service import (
    QualificationCaptureAuthority,
    capture_profile,
)
from services.api.provider_live_capture_storage import resolve_capture_target
from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_qualification import QualificationResult, evaluate_profile
from services.api.provider_qualification_receipt import (
    QualificationReceiptSubject,
    qualification_receipt_sha256,
)
from services.api.provider_qualification_writer import (
    QualificationWriter,
    QualificationWriterError,
)
from services.api.provider_runtime import (
    ProviderConnection,
    ProviderPrincipal,
    ProviderQualificationIdentity,
    ProviderRuntimeIdentity,
    ProviderRuntimeService,
)

if TYPE_CHECKING:
    from datetime import datetime

    from services.api.provider_live_capture_cases import CaptureCase
    from services.api.provider_live_capture_sandbox import CodexBinaryPolicy
    from services.api.provider_live_capture_storage import CaptureTargetInput
    from services.api.provider_runtime import Health

_FIRST_QUALIFIED_REVISION: Final = 2


@dataclass(frozen=True, slots=True)
class RuntimeQualificationTarget:
    """One principal-owned connection revision receiving live qualification."""

    runtime: ProviderRuntimeService
    principal: ProviderPrincipal
    connection_id: str
    expected_revision: int


@dataclass(frozen=True, slots=True)
class QualificationAdoptionSnapshot:
    """Mutable provider fields rechecked by the isolated adopter CAS."""

    runtime_home_ref: str
    account_id: str
    eligible_models: tuple[str, ...]
    selected_model: str
    health: Health
    created_at: datetime


def capture_live_qualification(
    cases: tuple[CaptureCase, ...],
    output: CaptureTargetInput,
    policy: CodexBinaryPolicy,
    *,
    authority: QualificationCaptureAuthority | None = None,
) -> QualificationResult:
    """Capture and evaluate evidence through an external receipt authority."""
    target = resolve_capture_target(output)
    receipt = capture_profile(
        cases,
        target,
        policy=policy,
        authority=authority,
    )
    if receipt is None:
        raise capture_error(ERROR_LIVE_QUALIFICATION)
    try:
        result = evaluate_profile(
            target.output.read_bytes(),
            receipt,
            None if authority is None else authority.verifier,
        )
    except OSError as error:
        raise capture_error(ERROR_LIVE_QUALIFICATION) from error
    if not result.live_qualified:
        raise capture_error(ERROR_LIVE_QUALIFICATION)
    return result


def capture_and_record_runtime_qualification(
    cases: tuple[CaptureCase, ...],
    output: CaptureTargetInput,
    policy: CodexBinaryPolicy,
    target: RuntimeQualificationTarget,
    *,
    authority: QualificationCaptureAuthority | None = None,
) -> ProviderConnection:
    """Capture, evaluate, and persist through one principal-scoped runtime call."""
    identity = ProviderRuntimeIdentity(
        "openai_codex",
        policy.expected_runtime_version,
        policy.expected_sha256,
    )
    subject = QualificationReceiptSubject(
        org_id=target.principal.org_id,
        user_id=target.principal.user_id,
        connection_id=target.connection_id,
        connection_revision=target.expected_revision + 1,
    )
    target.runtime.preflight_qualification(
        target.principal,
        target.connection_id,
        target.expected_revision,
        identity,
    )
    if authority is None or authority.subject != subject:
        raise capture_error(ERROR_LIVE_QUALIFICATION)
    result = capture_live_qualification(
        cases,
        output,
        policy,
        authority=authority,
    )
    return target.runtime.record_qualification(
        target.principal,
        target.connection_id,
        result,
        target.expected_revision,
    )


def adopt_live_qualification(
    result: QualificationResult,
    subject: QualificationReceiptSubject,
    writer: QualificationWriter,
    *,
    runtime_identity: ProviderRuntimeIdentity,
    snapshot: QualificationAdoptionSnapshot,
) -> ProviderConnection:
    """Adopt one verified capture through the exact external CAS boundary."""
    require_valid_adoption_target(subject, snapshot)
    receipt = result.receipt
    if (
        receipt is None
        or not result.live_qualified
        or receipt.claim.subject != subject
        or result.adapter != runtime_identity.adapter_id
        or result.runtime_version != runtime_identity.runtime_version
        or result.executable_sha256 != runtime_identity.executable_sha256
    ):
        raise QualificationWriterError
    qualification = ProviderQualificationIdentity(
        runtime_identity,
        result.profile_sha256,
        receipt,
        qualification_receipt_sha256(receipt),
    )
    connection = ProviderConnection(
        connection_id=subject.connection_id,
        adapter_id=runtime_identity.adapter_id,
        account_id=snapshot.account_id,
        eligible_models=snapshot.eligible_models,
        selected_model=snapshot.selected_model,
        health=snapshot.health,
        cleanup_verified=True,
        qualified_live=True,
        created_at=snapshot.created_at,
        revision=subject.connection_revision,
        qualification=qualification,
    )
    writer.adopt(
        ProviderPrincipal(subject.user_id, subject.org_id),
        connection,
        snapshot.runtime_home_ref,
        receipt,
        expected_revision=subject.connection_revision - 1,
    )
    return connection


def require_valid_adoption_target(
    subject: QualificationReceiptSubject,
    snapshot: QualificationAdoptionSnapshot,
) -> None:
    """Reject mutable snapshot drift before capture or authority access."""
    if (
        subject.connection_revision < _FIRST_QUALIFIED_REVISION
        or not snapshot.runtime_home_ref
        or not snapshot.account_id
        or not snapshot.eligible_models
        or len(set(snapshot.eligible_models)) != len(snapshot.eligible_models)
        or any(
            not provider_model_id_is_valid(model) for model in snapshot.eligible_models
        )
        or not provider_model_id_is_valid(snapshot.selected_model)
        or snapshot.selected_model not in snapshot.eligible_models
        or snapshot.health == "revoked"
        or snapshot.created_at.tzinfo is None
    ):
        raise QualificationWriterError
