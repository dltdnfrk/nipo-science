"""Strict, offline evaluation of captured provider qualification profiles."""

from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass
from hashlib import sha256
from typing import TYPE_CHECKING, Final, Protocol, TypeGuard, cast

type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)
type JsonObject = dict[str, JsonValue]

if TYPE_CHECKING:
    from collections.abc import Mapping

_CAPTURE_MODULE: Final = "services.api.provider_live_capture"
_CANONICAL_CASES_SHA256: Final = (
    "aea210e96f0d26df5050ab28eb6fc410c0b61e838d344eeaffe8b5007ed365c9"
)


class _CaptureExecutionProofView(Protocol):
    profile_sha256: str
    cases_sha256: str
    account_ref: str
    runtime_version: str
    protocol_attempts: int
    cleanup_terminal: bool
    cleanup_redaction_complete: bool

    def is_capture_issued(self) -> bool:
        """Return whether the production capture boundary issued the proof."""
        ...
_REQUIRED_ADAPTER: Final = "openai_codex"
_LIVE_KIND: Final = "captured_live_profile"
_REQUIRED_EVIDENCE_KINDS: Final[frozenset[str]] = frozenset(
    {"synthetic_contract_fixture", _LIVE_KIND}
)
_REQUIRED_SCENARIOS: Final[frozenset[str]] = frozenset(
    f"GS{number:02d}" for number in range(1, 11)
)
_EVENT_KINDS: Final[frozenset[str]] = frozenset({"start", "delta", "terminal"})
_FORBIDDEN_KEY_PARTS: Final[tuple[str, ...]] = (
    "token",
    "secret",
    "password",
    "credential",
    "authorization",
    "api_key",
    "apikey",
)
_TOKEN_VALUE: Final = re.compile(
    r"(?i)(?:bearer\s+\S+|sk-[a-z0-9_-]{8,}|"
    r"eyj[a-z0-9_-]{8,}\.[a-z0-9_-]+\.[a-z0-9_-]+)"
)
_ATTEMPTS_PER_SESSION: Final = 3
_MINIMUM_EVENTS: Final = 3
_MAX_LIMITATIONS: Final = 3
_MAX_OPAQUE_REF_LENGTH: Final = 256
_RECEIPT_SEAL: Final = object()
_RESULT_SEAL: Final = object()


class QualificationValidationError(ValueError):
    """Raised when qualification evidence is incomplete, unsafe, or malformed."""


@dataclass(frozen=True, slots=True)
class OAuthAttestation:
    """The non-secret OAuth provenance asserted by a profile."""

    mode: str
    provider: str


@dataclass(frozen=True, slots=True)
class ProtocolEvent:
    """One normalized event emitted during a provider attempt."""

    kind: str


@dataclass(frozen=True, slots=True)
class AttemptObservation:
    """Validated output and protocol observations for one attempt."""

    attempt_id: str
    events: tuple[ProtocolEvent, ...]
    decision_code: str
    scientific_result: Mapping[str, JsonValue]
    artifact_manifest: Mapping[str, JsonValue]
    evidence_identifiers: tuple[str, ...]
    limitations: tuple[str, ...]
    scientific_hash: str
    artifact_hash: str


@dataclass(frozen=True, slots=True)
class SessionObservation:
    """All attempts belonging to one required scenario."""

    scenario_id: str
    attempts: tuple[AttemptObservation, ...]


@dataclass(frozen=True, slots=True)
class CleanupReceipt:
    """Terminal cleanup and output-redaction attestations."""

    terminal: bool
    redaction_complete: bool


@dataclass(frozen=True, slots=True)
class QualificationProfile:
    """The fully parsed, offline-verifiable qualification profile."""

    evidence_kind: str
    adapter: str
    oauth: OAuthAttestation
    runtime_version: str
    account_ref: str
    sessions: tuple[SessionObservation, ...]
    cleanup: CleanupReceipt


@dataclass(frozen=True, slots=True)
class QualificationDecision:
    """Validated fields sealed into one evaluator result."""

    contract_valid: bool
    live_qualified: bool
    profile_sha256: str
    evidence_kind: str
    adapter: str
    account_ref: str
    runtime_version: str


@dataclass(frozen=True, slots=True, init=False)
class QualificationResult:
    """The sealed contract and live-trust outcome of profile evaluation."""

    contract_valid: bool
    live_qualified: bool
    profile_sha256: str
    evidence_kind: str
    adapter: str
    account_ref: str
    runtime_version: str
    _seal: object

    def __init__(self, decision: QualificationDecision, seal: object) -> None:
        """Create a result only through the evaluator."""
        if seal is not _RESULT_SEAL:
            raise TypeError(_result_issuance_error())
        object.__setattr__(self, "contract_valid", decision.contract_valid)
        object.__setattr__(self, "live_qualified", decision.live_qualified)
        object.__setattr__(self, "profile_sha256", decision.profile_sha256)
        object.__setattr__(self, "evidence_kind", decision.evidence_kind)
        object.__setattr__(self, "adapter", decision.adapter)
        object.__setattr__(self, "account_ref", decision.account_ref)
        object.__setattr__(self, "runtime_version", decision.runtime_version)
        object.__setattr__(self, "_seal", seal)

    def is_evaluator_issued(self) -> bool:
        """Return whether this exact result retains the evaluator seal."""
        return self._seal is _RESULT_SEAL


@dataclass(frozen=True, slots=True)
class _LiveCaptureBinding:
    """Production facts bound into a sealed live-capture receipt."""

    profile_sha256: str
    cases_sha256: str
    account_ref: str
    runtime_version: str
    protocol_attempts: int
    cleanup: CleanupReceipt


@dataclass(frozen=True, slots=True, init=False)
class LiveCaptureReceipt:
    """A non-forgeable attestation issued only after production capture."""

    profile_sha256: str
    cases_sha256: str
    account_ref: str
    runtime_version: str
    protocol_attempts: int
    cleanup_terminal: bool
    cleanup_redaction_complete: bool
    _integrity: str
    _seal: object

    def __init__(self, binding: _LiveCaptureBinding, seal: object) -> None:
        """Create a receipt only through the qualification issuance factory."""
        if seal is not _RECEIPT_SEAL:
            raise TypeError(_receipt_issuance_error())
        object.__setattr__(self, "profile_sha256", binding.profile_sha256)
        object.__setattr__(self, "cases_sha256", binding.cases_sha256)
        object.__setattr__(self, "account_ref", binding.account_ref)
        object.__setattr__(self, "runtime_version", binding.runtime_version)
        object.__setattr__(self, "protocol_attempts", binding.protocol_attempts)
        object.__setattr__(self, "cleanup_terminal", binding.cleanup.terminal)
        object.__setattr__(
            self,
            "cleanup_redaction_complete",
            binding.cleanup.redaction_complete,
        )
        object.__setattr__(self, "_integrity", _receipt_integrity(binding))
        object.__setattr__(self, "_seal", seal)

    def matches(self, profile: QualificationProfile, digest: str) -> bool:
        """Return whether this intact receipt is bound to ``profile`` and ``digest``."""
        expected_attempts = len(_REQUIRED_SCENARIOS) * _ATTEMPTS_PER_SESSION
        binding = _LiveCaptureBinding(
            profile_sha256=self.profile_sha256,
            cases_sha256=self.cases_sha256,
            account_ref=self.account_ref,
            runtime_version=self.runtime_version,
            protocol_attempts=self.protocol_attempts,
            cleanup=CleanupReceipt(
                terminal=self.cleanup_terminal,
                redaction_complete=self.cleanup_redaction_complete,
            ),
        )
        return (
            self._seal is _RECEIPT_SEAL
            and self._integrity == _receipt_integrity(binding)
            and self.profile_sha256 == digest
            and self.cases_sha256 == _CANONICAL_CASES_SHA256
            and self.account_ref == profile.account_ref
            and self.runtime_version == profile.runtime_version
            and self.protocol_attempts == len(profile.sessions) * _ATTEMPTS_PER_SESSION
            and self.protocol_attempts == expected_attempts
            and self.cleanup_terminal == profile.cleanup.terminal
            and self.cleanup_redaction_complete == profile.cleanup.redaction_complete
        )


def parse_profile_json(source: str | bytes) -> QualificationProfile:
    """Parse and strictly validate JSON without assigning live trust."""
    try:
        decoded = cast("object", json.loads(source))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise QualificationValidationError(_invalid_json_error()) from error
    _reject_sensitive_content(decoded)
    root = _mapping(decoded, "profile")
    _require_exact_keys(root, _profile_keys(), "profile")
    evidence_kind = _string(root["evidence_kind"], "profile.evidence_kind")
    if evidence_kind not in _REQUIRED_EVIDENCE_KINDS:
        raise QualificationValidationError(_unsupported_evidence_kind_error())
    if _string(root["adapter"], "profile.adapter") != _REQUIRED_ADAPTER:
        raise QualificationValidationError(_adapter_error())
    oauth = _parse_oauth(root["oauth"])
    sessions = _parse_sessions(root["sessions"])
    _validate_sessions(sessions)
    cleanup = _parse_cleanup(root["cleanup"])
    if not cleanup.terminal or not cleanup.redaction_complete:
        raise QualificationValidationError(_cleanup_error())
    return QualificationProfile(
        evidence_kind=evidence_kind,
        adapter=_REQUIRED_ADAPTER,
        oauth=oauth,
        runtime_version=_opaque_ref(root["runtime_version"], "profile.runtime_version"),
        account_ref=_opaque_ref(root["account_ref"], "profile.account_ref"),
        sessions=sessions,
        cleanup=cleanup,
    )


def evaluate_profile(
    source: str | bytes, receipt: object | None = None
) -> QualificationResult:
    """Evaluate raw evidence; only a matching sealed receipt grants live trust."""
    profile = parse_profile_json(source)
    digest = profile_sha256(profile)
    live = (
        profile.evidence_kind == _LIVE_KIND
        and type(receipt) is LiveCaptureReceipt
        and receipt.matches(profile, digest)
    )
    return QualificationResult(
        decision=QualificationDecision(
            contract_valid=True,
            live_qualified=live,
            profile_sha256=digest,
            evidence_kind=profile.evidence_kind,
            adapter=profile.adapter,
            account_ref=profile.account_ref,
            runtime_version=profile.runtime_version,
        ),
        seal=_RESULT_SEAL,
    )


def is_issued_qualification_result(value: object) -> TypeGuard[QualificationResult]:
    """Return whether ``value`` is an exact evaluator-issued result instance."""
    return type(value) is QualificationResult and value.is_evaluator_issued()


def profile_sha256(profile: QualificationProfile) -> str:
    """Return the canonical SHA-256 digest of a validated profile."""
    return _object_hash(_profile_data(profile))


def issue_live_capture_receipt_from_capture(
    profile: QualificationProfile,
    cases_sha256: str,
    proof: object,
) -> LiveCaptureReceipt:
    """Issue trust only for facts sealed by the production capture boundary."""
    capture_module = sys.modules.get(_CAPTURE_MODULE)
    proof_type = (
        None
        if capture_module is None
        else capture_module.__dict__.get("CaptureExecutionProof")
    )
    if proof_type is None or type(proof) is not proof_type:
        raise TypeError(_receipt_issuance_error())
    capture_proof = cast("_CaptureExecutionProofView", proof)
    if not capture_proof.is_capture_issued():
        raise TypeError(_receipt_issuance_error())
    expected_attempts = len(profile.sessions) * _ATTEMPTS_PER_SESSION
    if (
        cases_sha256 != _CANONICAL_CASES_SHA256
        or capture_proof.profile_sha256 != profile_sha256(profile)
        or capture_proof.cases_sha256 != _CANONICAL_CASES_SHA256
        or capture_proof.cases_sha256 != cases_sha256
        or capture_proof.account_ref != profile.account_ref
        or capture_proof.runtime_version != profile.runtime_version
        or capture_proof.protocol_attempts != expected_attempts
        or capture_proof.cleanup_terminal != profile.cleanup.terminal
        or capture_proof.cleanup_redaction_complete
        != profile.cleanup.redaction_complete
    ):
        raise TypeError(_receipt_issuance_error())
    binding = _LiveCaptureBinding(
        profile_sha256=capture_proof.profile_sha256,
        cases_sha256=capture_proof.cases_sha256,
        account_ref=capture_proof.account_ref,
        runtime_version=capture_proof.runtime_version,
        protocol_attempts=capture_proof.protocol_attempts,
        cleanup=profile.cleanup,
    )
    return LiveCaptureReceipt(binding=binding, seal=_RECEIPT_SEAL)


def _parse_oauth(value: object) -> OAuthAttestation:
    data = _mapping(value, "profile.oauth")
    _require_exact_keys(data, {"mode", "provider"}, "profile.oauth")
    oauth = OAuthAttestation(
        mode=_string(data["mode"], "profile.oauth.mode"),
        provider=_string(data["provider"], "profile.oauth.provider"),
    )
    if oauth != OAuthAttestation("official_subscription_oauth", "openai"):
        raise QualificationValidationError(_oauth_error())
    return oauth


def _parse_sessions(value: object) -> tuple[SessionObservation, ...]:
    items = _list(value, "profile.sessions")
    return tuple(_parse_session(item, index) for index, item in enumerate(items))


def _parse_session(value: object, index: int) -> SessionObservation:
    label = f"profile.sessions[{index}]"
    data = _mapping(value, label)
    _require_exact_keys(data, {"scenario_id", "attempts"}, label)
    attempts = tuple(
        _parse_attempt(item, index, position)
        for position, item in enumerate(_list(data["attempts"], f"{label}.attempts"))
    )
    return SessionObservation(
        scenario_id=_string(data["scenario_id"], f"{label}.scenario_id"),
        attempts=attempts,
    )


def _parse_attempt(
    value: object, session_index: int, attempt_index: int
) -> AttemptObservation:
    label = f"profile.sessions[{session_index}].attempts[{attempt_index}]"
    data = _mapping(value, label)
    _require_exact_keys(data, _attempt_keys(), label)
    events = tuple(
        ProtocolEvent(_event_kind(item, f"{label}.events[{position}]"))
        for position, item in enumerate(_list(data["events"], f"{label}.events"))
    )
    _validate_events(events, label)
    scientific = _json_object(data["scientific_result"], f"{label}.scientific_result")
    artifact = _json_object(data["artifact_manifest"], f"{label}.artifact_manifest")
    limitations = _string_tuple(data["limitations"], f"{label}.limitations")
    if not limitations or len(limitations) > _MAX_LIMITATIONS:
        raise QualificationValidationError(_bounded_limitations_error(label))
    attempt = AttemptObservation(
        attempt_id=_opaque_ref(data["attempt_id"], f"{label}.attempt_id"),
        events=events,
        decision_code=_string(data["decision_code"], f"{label}.decision_code"),
        scientific_result=scientific,
        artifact_manifest=artifact,
        evidence_identifiers=_string_tuple(
            data["evidence_identifiers"], f"{label}.evidence_identifiers"
        ),
        limitations=limitations,
        scientific_hash=_hash(data["scientific_hash"], f"{label}.scientific_hash"),
        artifact_hash=_hash(data["artifact_hash"], f"{label}.artifact_hash"),
    )
    if (
        attempt.scientific_hash != _object_hash(scientific)
        or attempt.artifact_hash != _object_hash(artifact)
    ):
        raise QualificationValidationError(_object_hash_error(label))
    return attempt


def _parse_cleanup(value: object) -> CleanupReceipt:
    data = _mapping(value, "profile.cleanup")
    _require_exact_keys(data, {"terminal", "redaction_complete"}, "profile.cleanup")
    return CleanupReceipt(
        terminal=_bool(data["terminal"], "profile.cleanup.terminal"),
        redaction_complete=_bool(
            data["redaction_complete"], "profile.cleanup.redaction_complete"
        ),
    )


def _validate_sessions(sessions: tuple[SessionObservation, ...]) -> None:
    identifiers = tuple(session.scenario_id for session in sessions)
    if (
        len(sessions) != len(_REQUIRED_SCENARIOS)
        or frozenset(identifiers) != _REQUIRED_SCENARIOS
    ):
        raise QualificationValidationError(_scenarios_error())
    if len(set(identifiers)) != len(identifiers):
        raise QualificationValidationError(_duplicate_scenarios_error())
    for session in sessions:
        _validate_session_attempts(session)


def _validate_session_attempts(session: SessionObservation) -> None:
    attempts = session.attempts
    if len(attempts) != _ATTEMPTS_PER_SESSION:
        raise QualificationValidationError(
            _attempt_count_error(session.scenario_id)
        )
    if len({attempt.attempt_id for attempt in attempts}) != _ATTEMPTS_PER_SESSION:
        raise QualificationValidationError(
            _duplicate_attempt_error(session.scenario_id)
        )
    baseline = attempts[0]
    for attempt in attempts:
        if _attempt_output(attempt) != _attempt_output(baseline):
            raise QualificationValidationError(
                _deterministic_output_error(session.scenario_id)
            )


def _attempt_output(attempt: AttemptObservation) -> tuple[object, ...]:
    return (
        attempt.decision_code,
        attempt.scientific_result,
        attempt.artifact_manifest,
        attempt.evidence_identifiers,
        attempt.limitations,
        attempt.scientific_hash,
        attempt.artifact_hash,
    )


def _validate_events(events: tuple[ProtocolEvent, ...], label: str) -> None:
    kinds = tuple(event.kind for event in events)
    valid = (
        len(kinds) >= _MINIMUM_EVENTS
        and kinds[0] == "start"
        and kinds[-1] == "terminal"
        and "delta" in kinds[1:-1]
        and all(kind in _EVENT_KINDS for kind in kinds)
        and "start" not in kinds[1:]
        and "terminal" not in kinds[:-1]
    )
    if not valid:
        raise QualificationValidationError(_events_error(label))


def _event_kind(value: object, label: str) -> str:
    data = _mapping(value, label)
    _require_exact_keys(data, {"kind"}, label)
    return _string(data["kind"], f"{label}.kind")


def _profile_data(profile: QualificationProfile) -> JsonObject:
    return {
        "evidence_kind": profile.evidence_kind,
        "adapter": profile.adapter,
        "oauth": {"mode": profile.oauth.mode, "provider": profile.oauth.provider},
        "runtime_version": profile.runtime_version,
        "account_ref": profile.account_ref,
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


def _object_hash(value: Mapping[str, JsonValue]) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    return sha256(encoded.encode()).hexdigest()


def _receipt_integrity(binding: _LiveCaptureBinding) -> str:
    return _object_hash(
        {
            "profile_sha256": binding.profile_sha256,
            "cases_sha256": binding.cases_sha256,
            "account_ref": binding.account_ref,
            "runtime_version": binding.runtime_version,
            "protocol_attempts": binding.protocol_attempts,
            "cleanup_terminal": binding.cleanup.terminal,
            "cleanup_redaction_complete": binding.cleanup.redaction_complete,
        }
    )


def _reject_sensitive_content(value: object, path: str = "profile") -> None:
    mapping = _nested_mapping(value)
    if mapping is not None:
        for key, nested in mapping.items():
            if any(part in key.lower() for part in _FORBIDDEN_KEY_PARTS):
                raise QualificationValidationError(_sensitive_key_error(path))
            _reject_sensitive_content(nested, f"{path}.{key}")
        return
    items = _nested_list(value)
    if items is not None:
        for index, nested in enumerate(items):
            _reject_sensitive_content(nested, f"{path}[{index}]")
        return
    if isinstance(value, str) and _TOKEN_VALUE.search(value):
        raise QualificationValidationError(_token_content_error(path))


def _mapping(value: object, label: str) -> Mapping[str, object]:
    mapping = _nested_mapping(value)
    if mapping is None:
        raise QualificationValidationError(_object_error(label))
    return mapping


def _nested_mapping(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, dict):
        return None
    untyped = cast("dict[object, object]", value)
    result: dict[str, object] = {}
    for key, nested in untyped.items():
        if not isinstance(key, str):
            return None
        result[key] = nested
    return result


def _json_object(value: object, label: str) -> Mapping[str, JsonValue]:
    mapping = _mapping(value, label)
    if not mapping:
        raise QualificationValidationError(_non_empty_object_error(label))
    return cast("Mapping[str, JsonValue]", mapping)


def _list(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        raise QualificationValidationError(_array_error(label))
    return cast("list[object]", value)


def _nested_list(value: object) -> list[object] | None:
    return cast("list[object]", value) if isinstance(value, list) else None


def _string_tuple(value: object, label: str) -> tuple[str, ...]:
    values = tuple(
        _string(item, f"{label}[{index}]")
        for index, item in enumerate(_list(value, label))
    )
    if len(set(values)) != len(values):
        raise QualificationValidationError(_duplicate_values_error(label))
    return values


def _string(value: object, label: str) -> str:
    if not isinstance(value, str) or not value:
        raise QualificationValidationError(_string_error(label))
    return value


def _opaque_ref(value: object, label: str) -> str:
    text = _string(value, label)
    if len(text) > _MAX_OPAQUE_REF_LENGTH or any(
        character.isspace() for character in text
    ):
        raise QualificationValidationError(_opaque_reference_error(label))
    return text


def _hash(value: object, label: str) -> str:
    text = _string(value, label)
    if re.fullmatch(r"[0-9a-f]{64}", text) is None:
        raise QualificationValidationError(_hash_error(label))
    return text


def _bool(value: object, label: str) -> bool:
    if not isinstance(value, bool):
        raise QualificationValidationError(_boolean_error(label))
    return value


def _require_exact_keys(
    data: Mapping[str, object], expected: set[str], label: str
) -> None:
    if set(data) != expected:
        raise QualificationValidationError(_fields_error(label))


def _profile_keys() -> set[str]:
    return {
        "evidence_kind", "adapter", "oauth", "runtime_version", "account_ref",
        "sessions", "cleanup",
    }


def _attempt_keys() -> set[str]:
    return {
        "attempt_id", "events", "decision_code", "scientific_result",
        "artifact_manifest", "evidence_identifiers", "limitations", "scientific_hash",
        "artifact_hash",
    }


def _invalid_json_error() -> str:
    return "profile must be valid JSON"


def _unsupported_evidence_kind_error() -> str:
    return "profile.evidence_kind is unsupported"


def _adapter_error() -> str:
    return "profile.adapter must be openai_codex"


def _oauth_error() -> str:
    return "profile.oauth must attest official OpenAI OAuth"


def _cleanup_error() -> str:
    return "profile.cleanup must be terminal and redacted"


def _scenarios_error() -> str:
    return "profile.sessions must contain exactly GS01 through GS10"


def _duplicate_scenarios_error() -> str:
    return "profile.sessions must not duplicate scenarios"


def _attempt_count_error(name: str) -> str:
    return f"{name} must contain exactly three attempts"


def _duplicate_attempt_error(name: str) -> str:
    return f"{name} has duplicate attempt identifiers"


def _deterministic_output_error(name: str) -> str:
    return f"{name} does not have deterministic evaluated outputs"


def _events_error(label: str) -> str:
    return f"{label}.events must start, delta, and terminate"


def _bounded_limitations_error(label: str) -> str:
    return f"{label}.limitations must be bounded"


def _object_hash_error(label: str) -> str:
    return f"{label} hashes do not match response objects"


def _sensitive_key_error(path: str) -> str:
    return f"{path} uses a forbidden sensitive key"


def _token_content_error(path: str) -> str:
    return f"{path} contains token-shaped content"


def _object_error(label: str) -> str:
    return f"{label} must be an object"


def _non_empty_object_error(label: str) -> str:
    return f"{label} must not be empty"


def _array_error(label: str) -> str:
    return f"{label} must be an array"


def _duplicate_values_error(label: str) -> str:
    return f"{label} must not contain duplicates"


def _string_error(label: str) -> str:
    return f"{label} must be a non-empty string"


def _opaque_reference_error(label: str) -> str:
    return f"{label} must be a compact opaque reference"


def _hash_error(label: str) -> str:
    return f"{label} must be a lowercase SHA-256 digest"


def _boolean_error(label: str) -> str:
    return f"{label} must be a boolean"


def _fields_error(label: str) -> str:
    return f"{label} has unexpected or missing fields"


def _receipt_issuance_error() -> str:
    return "LiveCaptureReceipt is issued only by production capture"

def _result_issuance_error() -> str:
    return "QualificationResult is issued only by evaluate_profile"
