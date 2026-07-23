"""Trust-boundary tests for live provider qualification challenges."""

from __future__ import annotations

import json
from pathlib import Path
from typing import cast

import pytest
from services.api.provider_live_capture_cases import load_cases
from services.api.provider_live_capture_errors import CaptureError
from services.api.provider_live_capture_protocol import exec_argv, validate_attempt
from services.api.provider_live_capture_schema import response_schema

_CASES = Path(__file__).parent / "fixtures" / "golden_session_cases.json"
_EVENT_STREAM = (
    '{"type":"thread.started"}\n'
    '{"type":"turn.started"}\n'
    '{"type":"response.output_text.delta"}\n'
    '{"type":"turn.completed"}'
)
_EXPECTED_FIELDS = {
    "decision_code",
    "scientific_result",
    "artifact_manifest",
    "evidence_identifiers",
    "limitations",
}


def _correct_response() -> tuple[object, dict[str, object]]:
    case = load_cases(_CASES)[0]
    return case, {
        "scenario_id": case.scenario_id,
        "decision_code": case.decision_code,
        "scientific_result": json.dumps(
            case.scientific_result,
            sort_keys=True,
            separators=(",", ":"),
        ),
        "artifact_manifest": json.dumps(
            case.artifact_manifest,
            sort_keys=True,
            separators=(",", ":"),
        ),
        "evidence_identifiers": list(case.evidence_identifiers),
        "limitations": list(case.limitations),
    }


def test_model_contract_does_not_disclose_canonical_expected_answers(
    tmp_path: Path,
) -> None:
    # Given: a production qualification case with server-owned expected answers.
    case = load_cases(_CASES)[0]

    # When: the model-facing prompt and response schema are assembled.
    argv = exec_argv(case, tmp_path / "schema.json", tmp_path / "answer.json")
    prompt = cast("dict[str, object]", json.loads(argv[-1]))
    encoded_schema = response_schema(case)

    # Then: only challenge inputs are in the prompt and no answer value is in schema.
    assert _EXPECTED_FIELDS.isdisjoint(prompt)
    assert case.decision_code not in encoded_schema
    assert cast("str", case.scientific_result["comparison"]) not in encoded_schema
    assert cast("str", case.artifact_manifest["artifact_id"]) not in encoded_schema
    assert case.evidence_identifiers[0] not in encoded_schema
    assert case.limitations[0] not in encoded_schema


def test_canonical_structured_answer_passes_independent_validation() -> None:
    # Given: a structured response independently derived from the authority bundle.
    case_value, response = _correct_response()
    case = load_cases(_CASES)[0]
    assert case_value == case

    # When: the response crosses the qualification verifier.
    observed = validate_attempt(case, 1, _EVENT_STREAM, response)

    # Then: authority-owned values, not prompt content, populate the evidence record.
    assert observed["decision_code"] == case.decision_code
    assert observed["scientific_result"] == case.scientific_result
    assert observed["artifact_manifest"] == case.artifact_manifest


@pytest.mark.parametrize(
    ("field", "forged_value"),
    [
        ("decision_code", "Summarize a bounded research observation."),
        ("scientific_result", '{"comparison":"curve_b_greater"}'),
        ("artifact_manifest", '{"artifact_id":"forged","version":"v1"}'),
        ("evidence_identifiers", ["GS01_FORGED_EVIDENCE"]),
        ("limitations", ["State a cautious observational decision."]),
    ],
)
def test_echo_mutation_and_forged_answers_fail_independent_validation(
    field: str,
    forged_value: str | list[str],
) -> None:
    # Given: one structurally valid response with a prompt echo or forged answer.
    case_value, response = _correct_response()
    case = load_cases(_CASES)[0]
    assert case_value == case
    response[field] = forged_value

    # When/Then: the server-owned authority rejects it before evidence publication.
    with pytest.raises(CaptureError, match="safety validation"):
        _ = validate_attempt(case, 1, _EVENT_STREAM, response)


def test_nested_duplicate_key_forgery_fails_before_answer_comparison() -> None:
    # Given: a response whose JSON-encoded scientific object has last-wins ambiguity.
    case_value, response = _correct_response()
    case = load_cases(_CASES)[0]
    assert case_value == case
    response["scientific_result"] = (
        '{"curve_a":0.42,"curve_a":0.39,"curve_b":0.39,'
        '"comparison":"curve_a_greater"}'
    )

    # When/Then: duplicate keys fail at the nested untrusted JSON boundary.
    with pytest.raises(CaptureError, match="response is malformed"):
        _ = validate_attempt(case, 1, _EVENT_STREAM, response)
