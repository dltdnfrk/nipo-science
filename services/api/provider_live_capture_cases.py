"""Canonical GS01-GS10 case parsing for live provider qualification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Final

from services.api.provider_live_capture_boundary import (
    list_value,
    mapping,
    object_hash,
    read_bounded_external_json,
    text,
)
from services.api.provider_live_capture_errors import (
    ERROR_CASES_INVALID,
    ERROR_CASES_SCENARIOS,
    capture_error,
)
from services.api.provider_qualification import CANONICAL_CASES_SHA256

if TYPE_CHECKING:
    from collections.abc import Mapping

    from services.api.provider_qualification_profile import QualificationProfile

_SCENARIOS: Final = tuple(f"GS{number:02d}" for number in range(1, 11))
_MAX_TEXT: Final = 400
_MAX_LIMITATIONS: Final = 3
_MAX_CASES_BYTES: Final = 64 * 1024
CANONICAL_CASES_PATH: Final = Path(__file__).with_name(
    "provider_qualification_cases.json"
)


@dataclass(frozen=True, slots=True)
class CaptureCase:
    """One bounded, deterministic qualification scenario."""

    scenario_id: str
    requirement: str
    input_text: str
    rubric: str
    decision_code: str
    scientific_result: Mapping[str, object]
    artifact_manifest: Mapping[str, object]
    evidence_identifiers: tuple[str, ...]
    limitations: tuple[str, ...]
    forbidden_sentinels: tuple[str, ...]


def load_cases(path: Path) -> tuple[CaptureCase, ...]:
    """Strictly load the ten bounded, deterministic qualification cases."""
    decoded = read_bounded_external_json(
        path,
        maximum_bytes=_MAX_CASES_BYTES,
        error_message=ERROR_CASES_INVALID,
    )
    root = mapping(decoded, "cases")
    if set(root) != {"cases"}:
        raise capture_error(ERROR_CASES_INVALID)
    items = list_value(root["cases"], "cases.cases")
    cases = tuple(_parse_case(item, index) for index, item in enumerate(items))
    if tuple(case.scenario_id for case in cases) != _SCENARIOS:
        raise capture_error(ERROR_CASES_SCENARIOS)
    if cases_sha256(cases) != CANONICAL_CASES_SHA256:
        raise capture_error(ERROR_CASES_INVALID)
    return cases


def load_canonical_cases() -> tuple[CaptureCase, ...]:
    """Load the production-owned qualification challenge authority."""
    return load_cases(CANONICAL_CASES_PATH)


def profile_matches_cases(
    profile: QualificationProfile,
    cases: tuple[CaptureCase, ...],
) -> bool:
    """Match parsed observations to authority-owned expected outcomes."""
    by_scenario = {case.scenario_id: case for case in cases}
    if len(by_scenario) != len(cases) or len(profile.sessions) != len(cases):
        return False
    for session in profile.sessions:
        case = by_scenario.get(session.scenario_id)
        if case is None:
            return False
        scientific_hash = object_hash(case.scientific_result)
        artifact_hash = object_hash(case.artifact_manifest)
        for number, attempt in enumerate(session.attempts, start=1):
            if (
                attempt.attempt_id != f"{case.scenario_id}-{number}"
                or attempt.decision_code != case.decision_code
                or attempt.scientific_hash != scientific_hash
                or attempt.artifact_hash != artifact_hash
                or attempt.evidence_identifiers != case.evidence_identifiers
                or attempt.limitations != case.limitations
            ):
                return False
    return True


def _parse_case(value: object, index: int) -> CaptureCase:
    label = f"cases.cases[{index}]"
    data = mapping(value, label)
    required = {
        "scenario_id",
        "requirement",
        "input",
        "rubric",
        "decision_code",
        "scientific_result",
        "artifact_manifest",
        "evidence_identifiers",
        "limitations",
        "forbidden_sentinels",
    }
    if set(data) != required:
        raise capture_error(ERROR_CASES_INVALID)
    text_values = (
        text(data["scenario_id"], f"{label}.scenario_id"),
        text(data["requirement"], f"{label}.requirement"),
        text(data["input"], f"{label}.input"),
        text(data["rubric"], f"{label}.rubric"),
        text(data["decision_code"], f"{label}.decision_code"),
    )
    scientific = case_object(data["scientific_result"], f"{label}.scientific_result")
    artifact = case_object(data["artifact_manifest"], f"{label}.artifact_manifest")
    evidence = case_strings(
        data["evidence_identifiers"], f"{label}.evidence_identifiers"
    )
    limitations = case_strings(data["limitations"], f"{label}.limitations")
    sentinels = case_strings(
        data["forbidden_sentinels"], f"{label}.forbidden_sentinels"
    )
    invalid = (
        any(len(item) > _MAX_TEXT or not item.strip() for item in text_values)
        or not evidence
        or not limitations
        or len(limitations) > _MAX_LIMITATIONS
        or not sentinels
    )
    if invalid:
        raise capture_error(ERROR_CASES_INVALID)
    return CaptureCase(
        *text_values,
        scientific,
        artifact,
        evidence,
        limitations,
        sentinels,
    )


def case_object(value: object, label: str) -> Mapping[str, object]:
    """Parse a non-empty object embedded in one qualification case."""
    data = mapping(value, label)
    if not data:
        raise capture_error(ERROR_CASES_INVALID)
    return data


def case_strings(value: object, label: str) -> tuple[str, ...]:
    """Parse one unique, non-empty bounded string vector."""
    values = tuple(text(item, label) for item in list_value(value, label))
    if (
        not values
        or len(set(values)) != len(values)
        or any(not item.strip() or len(item) > _MAX_TEXT for item in values)
    ):
        raise capture_error(ERROR_CASES_INVALID)
    return values


def cases_sha256(cases: tuple[CaptureCase, ...]) -> str:
    """Hash the complete canonical case contract without dropping any field."""
    payload = [
        {
            "scenario_id": case.scenario_id,
            "requirement": case.requirement,
            "input": case.input_text,
            "rubric": case.rubric,
            "decision_code": case.decision_code,
            "scientific_result": dict(case.scientific_result),
            "artifact_manifest": dict(case.artifact_manifest),
            "evidence_identifiers": list(case.evidence_identifiers),
            "limitations": list(case.limitations),
            "forbidden_sentinels": list(case.forbidden_sentinels),
        }
        for case in cases
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()
