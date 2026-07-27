from __future__ import annotations

import pytest
from pydantic import ValidationError

from science_workbench_contracts.runs import (
    ResearchIntent,
    RunCreate,
    research_intent_sha256,
)


def test_rejects_client_supplied_org_id() -> None:
    # Given: a client request attempting to select its own tenant.
    fixture = {
        "execution_mode": "local_dry_lab",
        "session_id": "018f47a0-7b9c-7abf-8def-0123456789ab",
        "prompt": "forged",
        "input": {
            "filename": "calibrated.csv",
            "media_type": "text/csv",
            "content": "sample,value,calibration\nA,1.0,c1\n",
        },
        "research_intent": {
            "question": "검증할 수 있는가?",
            "rationale": "재현성을 확인한다.",
            "intended_benefit": "검증 가능한 기준선을 만든다.",
            "success_criteria": ["체크섬이 일치한다."],
            "constraints": ["비임상 연구만 수행한다."],
            "stop_conditions": ["증거가 없으면 중단한다."],
            "research_mode": "copilot",
            "data_origin": "observed",
        },
        "org_id": "018f47a0-7b9c-7abd-8def-0123456789ab",
    }

    # When/Then: strict request parsing rejects the extra authority field.
    with pytest.raises(ValidationError, match="org_id"):
        _ = RunCreate.model_validate(fixture)


def test_run_create_requires_a_complete_research_intent() -> None:
    with pytest.raises(ValidationError, match="research_intent"):
        _ = RunCreate.model_validate(
            {
                "execution_mode": "local_dry_lab",
                "session_id": "018f47a0-7b9c-7abf-8def-0123456789ab",
                "prompt": "분석한다",
                "input": {
                    "filename": "calibrated.csv",
                    "media_type": "text/csv",
                    "content": "sample,value,calibration\nA,1.0,c1\n",
                },
            }
        )


@pytest.mark.parametrize(
    "research_intent_update",
    [
        {"question": "x" * 2_001},
        {"question": " "},
        {"question": "\u0085boundary"},
        {"question": "\ufeffboundary"},
        {"question": "invalid\ud800"},
        {"constraints": ["invalid\udfff"]},
        {"success_criteria": ["same", "same"]},
        {"success_criteria": ["same", " same "]},
        {"constraints": ["가" * 501]},
    ],
)
def test_research_intent_rejects_oversized_or_duplicate_values(
    research_intent_update: dict[str, object],
) -> None:
    intent: dict[str, object] = {
        "question": "검증할 수 있는가?",
        "rationale": "재현성을 확인한다.",
        "intended_benefit": "검증 가능한 기준선을 만든다.",
        "success_criteria": ["체크섬이 일치한다."],
        "constraints": ["비임상 연구만 수행한다."],
        "stop_conditions": ["증거가 없으면 중단한다."],
        "research_mode": "copilot",
        "data_origin": "observed",
    }
    intent.update(research_intent_update)

    with pytest.raises(ValidationError):
        _ = RunCreate.model_validate(
            {
                "execution_mode": "local_dry_lab",
                "session_id": "018f47a0-7b9c-7abf-8def-0123456789ab",
                "prompt": "분석한다",
                "research_intent": intent,
                "input": {
                    "filename": "calibrated.csv",
                    "media_type": "text/csv",
                    "content": "sample,value,calibration\nA,1.0,c1\n",
                },
            }
        )


def test_run_create_separates_local_input_from_provider_execution() -> None:
    research_intent = {
        "question": "검증할 수 있는가?",
        "rationale": "재현성을 확인한다.",
        "intended_benefit": "검증 가능한 기준선을 만든다.",
        "success_criteria": ["체크섬이 일치한다."],
        "constraints": ["비임상 연구만 수행한다."],
        "stop_conditions": ["증거가 없으면 중단한다."],
        "research_mode": "copilot",
        "data_origin": "observed",
    }
    local = {
        "execution_mode": "local_dry_lab",
        "session_id": "018f47a0-7b9c-7abf-8def-0123456789ab",
        "prompt": "분석한다",
        "research_intent": research_intent,
        "input": {
            "filename": "calibrated.csv",
            "media_type": "text/csv",
            "content": "sample,value,calibration\nA,1.0,c1\n",
        },
    }

    assert RunCreate.model_validate(local).execution_mode == "local_dry_lab"
    with pytest.raises(ValidationError):
        _ = RunCreate.model_validate(
            local
            | {
                "provider_connection_id": (
                    "018f47a0-7b9c-7ac0-8def-0123456789ab"
                )
            }
        )

    provider = local | {
        "execution_mode": "provider_model",
        "connection_id": "018f47a0-7b9c-7ac0-8def-0123456789ab",
        "model_id": "codex-mini",
    }
    parsed = RunCreate.model_validate(provider)
    assert parsed.execution_mode == "provider_model"
    assert parsed.research_intent == RunCreate.model_validate(local).research_intent
    with pytest.raises(ValidationError):
        _ = RunCreate.model_validate(
            {
                "execution_mode": "provider_model",
                "session_id": provider["session_id"],
                "connection_id": provider["connection_id"],
                "model_id": provider["model_id"],
            }
        )


def test_research_intent_accepts_multibyte_text_within_openapi_character_limit(
) -> None:
    _ = ResearchIntent.model_validate(
        {
            "question": "검증할 수 있는가?",
            "rationale": "재현성을 확인한다.",
            "intended_benefit": "검증 가능한 기준선을 만든다.",
            "success_criteria": ["체크섬이 일치한다."],
            "constraints": ["가" * 500],
            "stop_conditions": ["증거가 없으면 중단한다."],
            "research_mode": "copilot",
            "data_origin": "observed",
        }
    )


def test_research_intent_uses_unescaped_utf8_canonical_digest() -> None:
    intent = ResearchIntent.model_validate(
        {
            "question": "보정된 관측값을 재현 가능하게 정규화할 수 있는가?",
            "rationale": "반복 분석에서 입력 순서가 결과를 바꾸지 않도록 확인한다.",
            "intended_benefit": "검증 가능한 정규화 기준선을 만든다.",
            "success_criteria": ["동일 입력은 동일 체크섬을 만든다."],
            "constraints": ["비임상 연구 데이터만 사용한다."],
            "stop_conditions": ["보정 메타데이터가 없으면 중단한다."],
            "research_mode": "bounded_agentic",
            "data_origin": "observed",
        }
    )

    assert research_intent_sha256(intent) == (
        "60d80404ffbcbf2a738a9e2874376e5b951fc9c506ccfe4329ade98190580fb7"
    )
    assert intent.model_dump(mode="json")["synthetic_generator_ref"] is None
    assert intent.model_dump(mode="json")["synthetic_validator_ref"] is None


def test_research_intent_digest_bound_collections_are_deeply_immutable() -> None:
    intent = ResearchIntent.model_validate(
        {
            "question": "어떤 분석이 재현 가능한가?",
            "rationale": "검증 가능한 근거가 필요하다.",
            "intended_benefit": "재현 가능한 결론을 만든다.",
            "success_criteria": ["체크섬이 일치한다."],
            "constraints": ["비임상 연구만 수행한다."],
            "stop_conditions": ["증거가 없으면 중단한다."],
            "research_mode": "copilot",
            "data_origin": "observed",
        }
    )
    digest = research_intent_sha256(intent)

    assert isinstance(intent.success_criteria, tuple)
    assert isinstance(hash(intent.success_criteria), int)
    assert research_intent_sha256(intent) == digest


def test_research_intent_rejects_normalization_colliding_items() -> None:
    with pytest.raises(ValidationError):
        _ = ResearchIntent.model_validate(
            {
                "question": "검증할 수 있는가?",
                "rationale": "재현성을 확인한다.",
                "intended_benefit": "검증 가능한 기준선을 만든다.",
                "success_criteria": ["é", "e\u0301"],
                "constraints": ["비임상 연구만 수행한다."],
                "stop_conditions": ["증거가 없으면 중단한다."],
                "research_mode": "copilot",
                "data_origin": "observed",
            }
        )
