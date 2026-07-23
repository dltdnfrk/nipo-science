"""Domain parsing for offline provider qualification profiles."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

from services.api import provider_qualification_json as profile_json
from services.api.provider_qualification_json import (
    JsonValue,
    QualificationValidationError,
    canonical_object_hash,
    decode_profile_json,
    reject_sensitive_content,
    require_bool,
    require_exact_keys,
    require_json_object,
    require_list,
    require_mapping,
    require_opaque_ref,
    require_sha256,
    require_string,
    require_string_tuple,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

REQUIRED_ADAPTER: Final = "openai_codex"
LIVE_EVIDENCE_KIND: Final = "captured_live_profile"
REQUIRED_SCENARIOS: Final[frozenset[str]] = frozenset(
    f"GS{number:02d}" for number in range(1, 11)
)
ATTEMPTS_PER_SESSION: Final = 3

_REQUIRED_EVIDENCE_KINDS: Final[frozenset[str]] = frozenset(
    {"synthetic_contract_fixture", LIVE_EVIDENCE_KIND}
)
_EVENT_KINDS: Final[frozenset[str]] = frozenset({"start", "delta", "terminal"})
_MINIMUM_EVENTS, _MAX_LIMITATIONS = 3, 3

type AttemptOutputValue = str | Mapping[str, JsonValue] | tuple[str, ...]


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
    executable_sha256: str
    operator_account_ref: str
    sessions: tuple[SessionObservation, ...]
    cleanup: CleanupReceipt


def parse_profile_json(source: str | bytes) -> QualificationProfile:
    """Parse and strictly validate JSON without assigning live trust."""
    decoded = decode_profile_json(source)
    reject_sensitive_content(decoded)
    root = require_mapping(decoded, "profile")
    require_exact_keys(root, profile_json.PROFILE_KEYS, "profile")
    evidence_kind = require_string(root["evidence_kind"], "profile.evidence_kind")
    if evidence_kind not in _REQUIRED_EVIDENCE_KINDS:
        message = "profile.evidence_kind is unsupported"
        raise QualificationValidationError(message)
    if require_string(root["adapter"], "profile.adapter") != REQUIRED_ADAPTER:
        message = "profile.adapter must be openai_codex"
        raise QualificationValidationError(message)
    oauth = _parse_oauth(root["oauth"])
    sessions = _parse_sessions(root["sessions"])
    _validate_sessions(sessions)
    cleanup = _parse_cleanup(root["cleanup"])
    if not cleanup.terminal or not cleanup.redaction_complete:
        message = "profile.cleanup must be terminal and redacted"
        raise QualificationValidationError(message)
    return QualificationProfile(
        evidence_kind=evidence_kind,
        adapter=REQUIRED_ADAPTER,
        oauth=oauth,
        runtime_version=require_opaque_ref(
            root["runtime_version"], "profile.runtime_version"
        ),
        executable_sha256=require_sha256(
            root["executable_sha256"], "profile.executable_sha256"
        ),
        operator_account_ref=require_opaque_ref(
            root["operator_account_ref"], "profile.operator_account_ref"
        ),
        sessions=sessions,
        cleanup=cleanup,
    )


def _parse_oauth(value: JsonValue) -> OAuthAttestation:
    data = require_mapping(value, "profile.oauth")
    require_exact_keys(data, {"mode", "provider"}, "profile.oauth")
    oauth = OAuthAttestation(
        mode=require_string(data["mode"], "profile.oauth.mode"),
        provider=require_string(data["provider"], "profile.oauth.provider"),
    )
    if oauth != OAuthAttestation("official_subscription_oauth", "openai"):
        message = "profile.oauth must attest official OpenAI OAuth"
        raise QualificationValidationError(message)
    return oauth


def _parse_sessions(value: JsonValue) -> tuple[SessionObservation, ...]:
    items = require_list(value, "profile.sessions")
    return tuple(_parse_session(item, index) for index, item in enumerate(items))


def _parse_session(value: JsonValue, index: int) -> SessionObservation:
    label = f"profile.sessions[{index}]"
    data = require_mapping(value, label)
    require_exact_keys(data, {"scenario_id", "attempts"}, label)
    attempts = tuple(
        _parse_attempt(item, index, position)
        for position, item in enumerate(
            require_list(data["attempts"], f"{label}.attempts")
        )
    )
    return SessionObservation(
        scenario_id=require_string(data["scenario_id"], f"{label}.scenario_id"),
        attempts=attempts,
    )


def _parse_attempt(
    value: JsonValue,
    session_index: int,
    attempt_index: int,
) -> AttemptObservation:
    label = f"profile.sessions[{session_index}].attempts[{attempt_index}]"
    data = require_mapping(value, label)
    require_exact_keys(data, profile_json.ATTEMPT_KEYS, label)
    events = tuple(
        ProtocolEvent(_event_kind(item, f"{label}.events[{position}]"))
        for position, item in enumerate(require_list(data["events"], f"{label}.events"))
    )
    _validate_events(events, label)
    scientific = require_json_object(
        data["scientific_result"], f"{label}.scientific_result"
    )
    artifact = require_json_object(
        data["artifact_manifest"], f"{label}.artifact_manifest"
    )
    limitations = require_string_tuple(data["limitations"], f"{label}.limitations")
    if not limitations or len(limitations) > _MAX_LIMITATIONS:
        message = f"{label}.limitations must be bounded"
        raise QualificationValidationError(message)
    attempt = AttemptObservation(
        attempt_id=require_opaque_ref(data["attempt_id"], f"{label}.attempt_id"),
        events=events,
        decision_code=require_string(data["decision_code"], f"{label}.decision_code"),
        scientific_result=scientific,
        artifact_manifest=artifact,
        evidence_identifiers=require_string_tuple(
            data["evidence_identifiers"], f"{label}.evidence_identifiers"
        ),
        limitations=limitations,
        scientific_hash=require_sha256(
            data["scientific_hash"], f"{label}.scientific_hash"
        ),
        artifact_hash=require_sha256(data["artifact_hash"], f"{label}.artifact_hash"),
    )
    if attempt.scientific_hash != canonical_object_hash(
        scientific
    ) or attempt.artifact_hash != canonical_object_hash(artifact):
        message = f"{label} hashes do not match response objects"
        raise QualificationValidationError(message)
    return attempt


def _parse_cleanup(value: JsonValue) -> CleanupReceipt:
    data = require_mapping(value, "profile.cleanup")
    require_exact_keys(data, {"terminal", "redaction_complete"}, "profile.cleanup")
    return CleanupReceipt(
        terminal=require_bool(data["terminal"], "profile.cleanup.terminal"),
        redaction_complete=require_bool(
            data["redaction_complete"], "profile.cleanup.redaction_complete"
        ),
    )


def _validate_sessions(sessions: tuple[SessionObservation, ...]) -> None:
    identifiers = tuple(session.scenario_id for session in sessions)
    if (
        len(sessions) != len(REQUIRED_SCENARIOS)
        or frozenset(identifiers) != REQUIRED_SCENARIOS
    ):
        message = "profile.sessions must contain exactly GS01 through GS10"
        raise QualificationValidationError(message)
    if len(set(identifiers)) != len(identifiers):
        message = "profile.sessions must not duplicate scenarios"
        raise QualificationValidationError(message)
    for session in sessions:
        _validate_session_attempts(session)


def _validate_session_attempts(session: SessionObservation) -> None:
    attempts = session.attempts
    if len(attempts) != ATTEMPTS_PER_SESSION:
        message = f"{session.scenario_id} must contain exactly three attempts"
        raise QualificationValidationError(message)
    if len({attempt.attempt_id for attempt in attempts}) != ATTEMPTS_PER_SESSION:
        message = f"{session.scenario_id} has duplicate attempt identifiers"
        raise QualificationValidationError(message)
    baseline = attempts[0]
    for attempt in attempts:
        if _attempt_output(attempt) != _attempt_output(baseline):
            message = (
                f"{session.scenario_id} does not have deterministic evaluated outputs"
            )
            raise QualificationValidationError(message)


def _attempt_output(attempt: AttemptObservation) -> tuple[AttemptOutputValue, ...]:
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
        message = f"{label}.events must start, delta, and terminate"
        raise QualificationValidationError(message)


def _event_kind(value: JsonValue, label: str) -> str:
    data = require_mapping(value, label)
    require_exact_keys(data, {"kind"}, label)
    return require_string(data["kind"], f"{label}.kind")
