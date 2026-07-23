from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from typing import Final

import pytest
from pydantic import TypeAdapter

from science_workbench_science.research_intent import (
    DataOrigin,
    ResearchIntent,
    ResearchIntentError,
    ResearchMode,
    research_intent_from_mapping,
)
from science_workbench_science.vertical import DryLabVertical, FixtureFailure

CSV = "sample,value,calibration\nA,1.25,fixture-cal-1\n"
ROOT = Path(__file__).parents[2]
type JsonValue = (
    None | bool | int | float | str | list[JsonValue] | dict[str, JsonValue]
)
type JsonObject = dict[str, JsonValue]
JSON_OBJECT_ADAPTER: Final[TypeAdapter[JsonObject]] = TypeAdapter(JsonObject)


def _json_object(payload: str | bytes) -> JsonObject:
    return JSON_OBJECT_ADAPTER.validate_json(payload)


def _object_value(value: JsonValue) -> JsonObject:
    assert isinstance(value, dict)
    return value


def _payload(**overrides: object) -> dict[str, object]:
    payload: dict[str, object] = {
        "question": "보정된 관측값을 재현 가능하게 정규화할 수 있는가?",
        "rationale": "반복 분석에서 입력 순서가 결과를 바꾸지 않도록 확인한다.",
        "intended_benefit": "검증 가능한 정규화 기준선을 만든다.",
        "success_criteria": ["동일 입력은 동일 체크섬을 만든다."],
        "constraints": ["비임상 연구 데이터만 사용한다."],
        "stop_conditions": ["보정 메타데이터가 없으면 중단한다."],
        "research_mode": "bounded_agentic",
        "data_origin": "observed",
    }
    payload.update(overrides)
    return payload


def _intent(**overrides: object) -> ResearchIntent:
    return research_intent_from_mapping(_payload(**overrides))


@pytest.mark.parametrize(
    "missing",
    [
        "question",
        "rationale",
        "intended_benefit",
        "success_criteria",
        "constraints",
        "stop_conditions",
        "research_mode",
        "data_origin",
    ],
)
def test_research_intent_requires_every_human_and_validation_field(
    missing: str,
) -> None:
    payload = _payload()
    del payload[missing]

    with pytest.raises(ResearchIntentError, match=r"^research-intent-invalid$"):
        _ = research_intent_from_mapping(payload)


def test_research_intent_uses_openapi_character_limits_for_multibyte_text() -> None:
    accepted = _intent(constraints=("가" * 500,))
    assert accepted.constraints == ("가" * 500,)

    with pytest.raises(ResearchIntentError, match=r"^research-intent-invalid$"):
        _ = _intent(constraints=("가" * 501,))


def test_research_intent_has_one_utf8_canonical_digest() -> None:
    intent = _intent()

    assert intent.sha256 == "60d80404ffbcbf2a738a9e2874376e5b951fc9c506ccfe4329ade98190580fb7"
    assert intent.to_dict()["synthetic_generator_ref"] is None
    assert intent.to_dict()["synthetic_validator_ref"] is None


def test_research_intent_rejects_non_nfc_text_and_normalization_collisions() -> None:
    with pytest.raises(ResearchIntentError, match=r"^research-intent-invalid$"):
        _ = _intent(success_criteria=["é", "e\u0301"])


@pytest.mark.parametrize(
    "update",
    [{"question": "invalid\ud800"}, {"constraints": ["invalid\udfff"]}],
)
def test_research_intent_rejects_lone_unicode_surrogates(
    update: dict[str, object],
) -> None:
    with pytest.raises(ResearchIntentError, match=r"^research-intent-invalid$"):
        _ = _intent(**update)


@pytest.mark.parametrize(
    ("field", "value"),
    [("research_mode", "copilot"), ("data_origin", "observed")],
)
def test_direct_research_intent_construction_rejects_raw_enum_strings(
    field: str,
    value: str,
) -> None:
    with pytest.raises(ResearchIntentError, match=r"^research-intent-invalid$"):
        _ = replace(_intent(), **{field: value})


def test_direct_research_intent_construction_cannot_bypass_validation() -> None:
    with pytest.raises(ResearchIntentError, match=r"^research-intent-invalid$"):
        _ = ResearchIntent(
            question="",
            rationale="",
            intended_benefit="",
            success_criteria=(),
            constraints=(),
            stop_conditions=(),
            research_mode=ResearchMode.COPILOT,
            data_origin=DataOrigin.SYNTHETIC,
            synthetic_generator_ref="same",
            synthetic_validator_ref="same",
        )


@pytest.mark.parametrize(
    "update",
    [
        {"question": " "},
        {"question": " leading"},
        {"question": "\u0085boundary"},
        {"question": "\ufeffboundary"},
        {"success_criteria": ["same", " same "]},
    ],
)
def test_research_intent_rejects_noncanonical_boundary_whitespace(
    update: dict[str, object],
) -> None:
    with pytest.raises(ResearchIntentError, match=r"^research-intent-invalid$"):
        _ = research_intent_from_mapping(_payload(**update))


@pytest.mark.parametrize("data_origin", ["synthetic", "mixed"])
def test_synthetic_data_requires_an_independent_generator_and_validator(
    data_origin: str,
) -> None:
    with pytest.raises(ResearchIntentError, match=r"^research-intent-invalid$"):
        _ = _intent(
            data_origin=data_origin,
            synthetic_generator_ref="model:generator-v1",
            synthetic_validator_ref="model:generator-v1",
        )

    intent = _intent(
        data_origin=data_origin,
        synthetic_generator_ref="model:generator-v1",
        synthetic_validator_ref="model:validator-v2",
    )
    assert intent.data_origin in {DataOrigin.SYNTHETIC, DataOrigin.MIXED}


def test_observed_data_rejects_synthetic_model_references() -> None:
    with pytest.raises(ResearchIntentError, match=r"^research-intent-invalid$"):
        _ = _intent(
            synthetic_generator_ref="model:generator-v1",
            synthetic_validator_ref="model:validator-v2",
        )


def test_action_plan_requires_and_cryptographically_binds_research_intent() -> None:
    missing = DryLabVertical()
    _ = missing.upload("calibrated.csv", CSV)
    with pytest.raises(FixtureFailure, match=r"^research-intent-invalid$"):
        _ = missing.create_plan()

    first = DryLabVertical()
    second = DryLabVertical()
    _ = first.upload("calibrated.csv", CSV)
    _ = second.upload("calibrated.csv", CSV)
    first_intent = _intent()
    second_intent = _intent(question="다른 연구 질문을 검증할 수 있는가?")

    first_plan = first.create_plan(research_intent=first_intent)
    second_plan = second.create_plan(research_intent=second_intent)

    assert first_plan.research_intent_sha256 == first_intent.sha256
    assert first_plan.digest != second_plan.digest
    assert first.read_projection()["research_intent"] == first_intent.to_dict()


def test_action_plan_revalidates_research_intent_at_the_vertical_boundary() -> None:
    vertical = DryLabVertical()
    _ = vertical.upload("calibrated.csv", CSV)
    intent = _intent()
    object.__setattr__(intent, "question", "")

    with pytest.raises(FixtureFailure, match=r"^research-intent-invalid$"):
        _ = vertical.create_plan(research_intent=intent)


def test_research_intent_is_pinned_through_provenance_review_and_export() -> None:
    vertical = DryLabVertical()
    _ = vertical.upload("calibrated.csv", CSV)
    intent = _intent()
    plan = vertical.create_plan(research_intent=intent)
    approval = vertical.approve(plan.digest)
    result = vertical.execute(approval.token)

    provenance = _json_object(result.provenance.content)
    assert provenance["research_intent"] == intent.to_dict()
    assert provenance["research_intent_sha256"] == intent.sha256

    _ = vertical.review()
    export = vertical.export()
    manifest = _json_object(export.manifest)
    assert manifest["research_intent_sha256"] == intent.sha256
    assert export.research_intent_sha256 == intent.sha256
    assert intent.research_mode is ResearchMode.BOUNDED_AGENTIC


def test_normative_contract_requires_why_first_intent_and_data_origin_governance() -> None:
    manifest = _json_object(
        (ROOT / "docs/requirements/requirements.yaml").read_text(encoding="utf-8")
    )
    dry_lab = _object_value(manifest["dry_lab"])
    contract = _object_value(dry_lab["research_intent"])
    assert contract == {
        "approval_binding": "full_canonical_digest",
        "canonicalization": "sorted_keys_compact_nfc_utf8",
        "data_origins": ["observed", "synthetic", "mixed"],
        "fields": [
            "question",
            "rationale",
            "intended_benefit",
            "success_criteria",
            "constraints",
            "stop_conditions",
            "research_mode",
            "data_origin",
        ],
        "optional_references": "explicit_null_when_absent",
        "research_modes": ["ai_for_science", "copilot", "bounded_agentic"],
        "synthetic_data": "distinct_generator_and_validator_required",
    }
    ordered_chain = dry_lab["ordered_chain"]
    assert isinstance(ordered_chain, list)
    assert ordered_chain[:3] == [
        "scientific_input",
        "research_intent",
        "immutable_action_plan",
    ]
    requirements = _json_object(
        (ROOT / "docs/requirements/requirements.yaml").read_text(encoding="utf-8")
    )
    governance = _object_value(requirements["tool_governance"])
    approval_binding = governance["approval_binding"]
    assert isinstance(approval_binding, list)
    assert "research_intent_sha256" in approval_binding
    architecture = _json_object(
        (ROOT / "docs/architecture/architecture.json").read_text(encoding="utf-8")
    )
    contracts = _object_value(architecture["contracts"])
    provenance = _object_value(contracts["artifact_provenance"])
    required_hashes = provenance["required_hashes"]
    assert isinstance(required_hashes, list)
    assert "research_intent" in required_hashes
    threat_model = _json_object(
        (ROOT / "docs/architecture/threat-model.json").read_text(encoding="utf-8")
    )
    threats = threat_model["threats"]
    assert isinstance(threats, list)
    replay = next(
        _object_value(item)
        for item in threats
        if _object_value(item)["id"] == "T10"
    )
    controls = replay["controls"]
    assert isinstance(controls, list)
    assert "research-intent-digest-bound" in controls
    spec = (ROOT / "docs/spec/SPEC-v0.4.md").read_text(encoding="utf-8")
    for phrase in (
        "ResearchIntent",
        "why the research matters",
        "distinct generator and validator",
    ):
        assert phrase in spec
