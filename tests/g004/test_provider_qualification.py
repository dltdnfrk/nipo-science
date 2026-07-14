"""Contract tests for offline provider qualification evidence."""

from __future__ import annotations

import json
from collections.abc import Callable
from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from typing import cast, final

import pytest
import services.api.provider_qualification as qualification
from services.api.provider_qualification import (
    QualificationDecision,
    QualificationResult,
    QualificationValidationError,
    evaluate_profile,
    is_issued_qualification_result,
    parse_profile_json,
)

type Json = object
type Profile = dict[str, Json]
type Mutator = Callable[[Profile], None]
_CASES = Path(__file__).parent / "fixtures" / "golden_session_cases.json"
_ATTEMPTS = 3


def _hash(value: object) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()


def synthetic_profile() -> Profile:
    decoded = cast("dict[str, list[Profile]]", json.loads(_CASES.read_text()))
    sessions = [_session(case) for case in decoded["cases"]]
    return {
        "evidence_kind": "synthetic_contract_fixture",
        "adapter": "openai_codex",
        "oauth": {"mode": "official_subscription_oauth", "provider": "openai"},
        "runtime_version": "codex-cli-0.144.1",
        "account_ref": "acct_fixture",
        "sessions": sessions,
        "cleanup": {"terminal": True, "redaction_complete": True},
    }


def _session(case: Profile) -> Profile:
    scientific = cast("Profile", case["scientific_result"])
    artifact = cast("Profile", case["artifact_manifest"])
    attempts = [
        _attempt_data(case, scientific, artifact, number)
        for number in range(1, _ATTEMPTS + 1)
    ]
    return {"scenario_id": case["scenario_id"], "attempts": attempts}


def _attempt_data(
    case: Profile, scientific: Profile, artifact: Profile, number: int
) -> Profile:
    return {
        "attempt_id": f"{case['scenario_id']}-{number}",
        "events": [{"kind": "start"}, {"kind": "delta"}, {"kind": "terminal"}],
        "decision_code": case["decision_code"],
        "scientific_result": scientific,
        "artifact_manifest": artifact,
        "evidence_identifiers": case["evidence_identifiers"],
        "limitations": case["limitations"],
        "scientific_hash": _hash(scientific),
        "artifact_hash": _hash(artifact),
    }


def _evaluate(profile: Profile) -> QualificationResult:
    return evaluate_profile(json.dumps(profile))


def _attempt(profile: Profile, scenario: int = 0, attempt: int = 0) -> Profile:
    sessions = cast("list[Profile]", profile["sessions"])
    attempts = cast("list[Profile]", sessions[scenario]["attempts"])
    return attempts[attempt]


def _remove_cleanup(profile: Profile) -> None:
    _ = profile.pop("cleanup")


def _remove_evidence(profile: Profile) -> None:
    _ = _attempt(profile).pop("evidence_identifiers")


def _empty_limitations(profile: Profile) -> None:
    _attempt(profile)["limitations"] = []


def _untrusted_kind(profile: Profile) -> None:
    profile["evidence_kind"] = "untrusted"


@final
class _ForgedResult:
    def is_evaluator_issued(self) -> bool:
        return True


def test_raw_profile_is_contract_valid_but_never_live_qualified() -> None:
    result = _evaluate(synthetic_profile())
    assert result.contract_valid
    assert not result.live_qualified


def test_self_declared_live_kind_is_never_live_qualified_without_receipt() -> None:
    profile = synthetic_profile()
    profile["evidence_kind"] = "captured_live_profile"
    assert not _evaluate(profile).live_qualified
    assert not is_issued_qualification_result(_ForgedResult())


def test_only_the_evaluator_can_issue_a_qualification_result() -> None:
    decision = QualificationDecision(
        contract_valid=True,
        live_qualified=True,
        profile_sha256="a" * 64,
        evidence_kind="captured_live_profile",
        adapter="openai_codex",
        account_ref="acct_example",
        runtime_version="codex-cli-1",
    )
    with pytest.raises(TypeError):
        _ = QualificationResult(decision, object())
    assert is_issued_qualification_result(_evaluate(synthetic_profile()))
    assert not hasattr(qualification, "issue_live_capture_receipt")
    assert not hasattr(qualification, "LiveCaptureBinding")


@pytest.mark.parametrize(
    "field",
    [
        "decision_code",
        "scientific_result",
        "artifact_manifest",
        "evidence_identifiers",
        "limitations",
    ],
)
def test_scenario_specific_outputs_cannot_drift(field: str) -> None:
    profile = synthetic_profile()
    attempt = _attempt(profile, 7, 1)
    if field == "scientific_result":
        attempt[field] = {"untrusted_instruction": False}
        attempt["scientific_hash"] = _hash(attempt[field])
    elif field == "artifact_manifest":
        attempt[field] = {"artifact_id": "generic", "version": "v1"}
        attempt["artifact_hash"] = _hash(attempt[field])
    elif field in {"evidence_identifiers", "limitations"}:
        attempt[field] = ["GENERIC"]
    else:
        attempt[field] = "GENERIC"
    with pytest.raises(QualificationValidationError, match="deterministic"):
        _ = _evaluate(profile)


@pytest.mark.parametrize("field", ["scientific_hash", "artifact_hash"])
def test_hashes_are_computed_from_response_objects(field: str) -> None:
    profile = synthetic_profile()
    _attempt(profile)[field] = "f" * 64
    with pytest.raises(QualificationValidationError, match="hashes"):
        _ = _evaluate(profile)


@pytest.mark.parametrize(
    ("scenario", "field", "sentinel"),
    [
        (7, "decision_code", "INJECTION_GS08_DO_NOT_OBEY"),
        (8, "evidence_identifiers", "FAKE_SECRET_GS09_NEVER_EMIT"),
        (9, "limitations", "FOREIGN_TENANT_GS10_NEVER_EMIT"),
    ],
)
def test_security_sentinels_are_rejected(
    scenario: int, field: str, sentinel: str
) -> None:
    profile = synthetic_profile()
    _attempt(profile, scenario)[field] = (
        sentinel if field == "decision_code" else [sentinel]
    )
    with pytest.raises(QualificationValidationError):
        _ = _evaluate(profile)


@pytest.mark.parametrize(
    "mutate",
    [_remove_cleanup, _remove_evidence, _empty_limitations, _untrusted_kind],
)
def test_schema_rejects_generic_or_incomplete_profiles(mutate: Mutator) -> None:
    profile = deepcopy(synthetic_profile())
    mutate(profile)
    with pytest.raises(QualificationValidationError):
        _ = _evaluate(profile)


def test_profile_checksum_tracks_validated_content() -> None:
    first = _evaluate(synthetic_profile())
    changed = synthetic_profile()
    changed["runtime_version"] = "codex-cli-0.144.2"
    assert first.profile_sha256 != _evaluate(changed).profile_sha256


def test_parse_returns_immutable_observations() -> None:
    profile = parse_profile_json(json.dumps(synthetic_profile()))
    assert profile.sessions[0].attempts[0].decision_code == "GS01_OBSERVATIONAL_COMPARISON"
