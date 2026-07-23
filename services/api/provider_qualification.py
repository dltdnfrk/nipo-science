"""Evaluation facade for captured provider qualification profiles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final

from services.api.provider_qualification_json import (
    JsonObject,
    JsonValue,
    QualificationValidationError,
    canonical_object_hash,
)
from services.api.provider_qualification_profile import (
    ATTEMPTS_PER_SESSION,
    LIVE_EVIDENCE_KIND,
    REQUIRED_ADAPTER,
    REQUIRED_SCENARIOS,
    AttemptObservation,
    CleanupReceipt,
    OAuthAttestation,
    ProtocolEvent,
    QualificationProfile,
    SessionObservation,
    parse_profile_json,
)
from services.api.provider_qualification_receipt import (
    QualificationReceipt,
    QualificationReceiptClaim,
    QualificationReceiptSubject,
    QualificationReceiptVerifier,
)

CANONICAL_CASES_SHA256: Final = (
    "aea210e96f0d26df5050ab28eb6fc410c0b61e838d344eeaffe8b5007ed365c9"
)

__all__ = [
    "CANONICAL_CASES_SHA256",
    "AttemptObservation",
    "CleanupReceipt",
    "JsonObject",
    "JsonValue",
    "OAuthAttestation",
    "ProtocolEvent",
    "QualificationProfile",
    "QualificationReceipt",
    "QualificationReceiptClaim",
    "QualificationReceiptSubject",
    "QualificationReceiptVerifier",
    "QualificationResult",
    "QualificationValidationError",
    "SessionObservation",
    "evaluate_profile",
    "parse_profile_json",
    "profile_sha256",
    "qualification_claim",
    "qualification_result_is_verified",
]


@dataclass(frozen=True, slots=True)
class QualificationResult:
    """Contract outcome carrying an independently verifiable authority receipt."""

    contract_valid: bool
    live_qualified: bool
    profile_sha256: str
    evidence_kind: str
    adapter: str
    operator_account_ref: str
    runtime_version: str
    executable_sha256: str
    receipt: QualificationReceipt | None


def evaluate_profile(
    source: str | bytes,
    receipt: QualificationReceipt | None = None,
    verifier: QualificationReceiptVerifier | None = None,
) -> QualificationResult:
    """Evaluate evidence; grant live trust only after public-key verification."""
    profile = parse_profile_json(source)
    digest = profile_sha256(profile)
    live = (
        profile.evidence_kind == LIVE_EVIDENCE_KIND
        and receipt is not None
        and verifier is not None
        and receipt.claim == qualification_claim(profile, receipt.claim.subject)
        and verifier.verify(receipt)
    )
    return QualificationResult(
        contract_valid=True,
        live_qualified=live,
        profile_sha256=digest,
        evidence_kind=profile.evidence_kind,
        adapter=profile.adapter,
        operator_account_ref=profile.operator_account_ref,
        runtime_version=profile.runtime_version,
        executable_sha256=profile.executable_sha256,
        receipt=receipt if live else None,
    )


def qualification_claim(
    profile: QualificationProfile,
    subject: QualificationReceiptSubject,
) -> QualificationReceiptClaim:
    """Build the exact authority claim for one validated live profile."""
    return QualificationReceiptClaim(
        subject=subject,
        profile_sha256=profile_sha256(profile),
        cases_sha256=CANONICAL_CASES_SHA256,
        adapter_id=profile.adapter,
        oauth_mode=profile.oauth.mode,
        oauth_provider=profile.oauth.provider,
        operator_account_ref=profile.operator_account_ref,
        runtime_version=profile.runtime_version,
        executable_sha256=profile.executable_sha256,
        protocol_attempts=len(profile.sessions) * ATTEMPTS_PER_SESSION,
        cleanup_terminal=profile.cleanup.terminal,
        cleanup_redaction_complete=profile.cleanup.redaction_complete,
    )


def qualification_result_is_verified(
    value: QualificationResult | None,
    verifier: QualificationReceiptVerifier | None,
    subject: QualificationReceiptSubject,
) -> bool:
    """Re-verify a result against its exact requester connection revision."""
    if type(value) is not QualificationResult or verifier is None:
        return False
    result = value
    receipt = result.receipt
    if receipt is None:
        return False
    claim = receipt.claim
    expected_attempts = len(REQUIRED_SCENARIOS) * ATTEMPTS_PER_SESSION
    return (
        result.contract_valid
        and result.live_qualified
        and result.evidence_kind == LIVE_EVIDENCE_KIND
        and result.adapter == REQUIRED_ADAPTER
        and claim.subject == subject
        and claim.profile_sha256 == result.profile_sha256
        and claim.cases_sha256 == CANONICAL_CASES_SHA256
        and claim.adapter_id == result.adapter
        and claim.oauth_mode == "official_subscription_oauth"
        and claim.oauth_provider == "openai"
        and claim.operator_account_ref == result.operator_account_ref
        and claim.runtime_version == result.runtime_version
        and claim.executable_sha256 == result.executable_sha256
        and claim.protocol_attempts == expected_attempts
        and claim.cleanup_terminal
        and claim.cleanup_redaction_complete
        and verifier.verify(receipt)
    )


def profile_sha256(profile: QualificationProfile) -> str:
    """Return the canonical SHA-256 digest of a validated profile."""
    return canonical_object_hash(_profile_data(profile))


def _profile_data(profile: QualificationProfile) -> JsonObject:
    return {
        "evidence_kind": profile.evidence_kind,
        "adapter": profile.adapter,
        "oauth": {"mode": profile.oauth.mode, "provider": profile.oauth.provider},
        "runtime_version": profile.runtime_version,
        "executable_sha256": profile.executable_sha256,
        "operator_account_ref": profile.operator_account_ref,
        "sessions": [
            _session_data(session)
            for session in sorted(profile.sessions, key=_session_key)
        ],
        "cleanup": {
            "terminal": profile.cleanup.terminal,
            "redaction_complete": profile.cleanup.redaction_complete,
        },
    }


def _session_key(session: SessionObservation) -> str:
    return session.scenario_id


def _session_data(session: SessionObservation) -> JsonObject:
    return {
        "scenario_id": session.scenario_id,
        "attempts": [
            _attempt_data(attempt)
            for attempt in sorted(session.attempts, key=_attempt_key)
        ],
    }


def _attempt_key(attempt: AttemptObservation) -> str:
    return attempt.attempt_id


def _attempt_data(attempt: AttemptObservation) -> JsonObject:
    return {
        "attempt_id": attempt.attempt_id,
        "events": [{"kind": event.kind} for event in attempt.events],
        "decision_code": attempt.decision_code,
        "scientific_result": dict(attempt.scientific_result),
        "artifact_manifest": dict(attempt.artifact_manifest),
        "evidence_identifiers": list(attempt.evidence_identifiers),
        "limitations": list(attempt.limitations),
        "scientific_hash": attempt.scientific_hash,
        "artifact_hash": attempt.artifact_hash,
    }
