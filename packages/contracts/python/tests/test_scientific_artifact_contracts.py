from __future__ import annotations

import json
from pathlib import Path

import pytest
from pydantic import ValidationError

from science_workbench_contracts.dry_lab_contract import DryLabRunContract
from science_workbench_contracts.evidence_ledger import EVIDENCE_LEDGER_COLUMNS
from science_workbench_contracts.reviews_v1 import ReviewerCapabilities
from science_workbench_contracts.skill_manifests import SkillManifest

FIXTURE = Path(__file__).parents[2] / "fixtures" / "gs04-dry-lab-contract.json"
TOP_LEVEL_FIELDS = {
    "contract_version",
    "org_id",
    "project_id",
    "source_run_id",
    "scientific_inputs",
    "action_plan",
    "executions",
    "artifact_versions",
    "outputs",
    "analysis_scope",
    "ledger",
    "provenance",
    "review",
    "skills",
    "export",
    "completed_at",
}


def test_round_trips_shared_gs04_input_to_reviewed_export_chain() -> None:
    # Given: the shared non-clinical GS04 scientific workflow fixture.
    raw = FIXTURE.read_text(encoding="utf-8")

    # When: Pydantic parses, serializes, and reparses the complete chain.
    parsed = DryLabRunContract.model_validate_json(raw)
    reparsed = DryLabRunContract.model_validate_json(parsed.model_dump_json())

    # Then: all immutable chain references and the bounded hypothesis scope survive.
    assert reparsed == parsed
    assert reparsed.analysis_scope.hypothesis_classes == (
        "molecular",
        "optical",
        "experimental_artifact",
    )
    assert reparsed.analysis_scope.conclusion_scope == "non_diagnostic"
    assert set(reparsed.export.selected_artifact_version_ids) == {
        reparsed.outputs.normalized_csv_version_id,
        reparsed.outputs.figure_png_version_id,
        reparsed.outputs.analysis_markdown_version_id,
        reparsed.outputs.ledger_json_version_id,
        reparsed.outputs.ledger_csv_version_id,
    }


def test_exposes_compatible_json_schema_and_required_ledger_columns() -> None:
    # Given: the Pydantic boundary model used by the shared fixture.
    json_schema = DryLabRunContract.model_json_schema()
    json_schema_text = json.dumps(json_schema, sort_keys=True)

    # When: its wire fields and ledger columns are inspected.
    model_fields = set(DryLabRunContract.model_fields)

    # Then: the required surface matches TypeScript and the canonical Ledger order.
    assert json_schema["type"] == "object"
    assert '"required"' in json_schema_text
    assert all(f'"{field}"' in json_schema_text for field in TOP_LEVEL_FIELDS)
    assert model_fields == TOP_LEVEL_FIELDS
    assert EVIDENCE_LEDGER_COLUMNS == (
        "claim_id",
        "claim_text",
        "evidence_kind",
        "source_id",
        "artifact_version_id",
        "execution_id",
        "supporting_sha256",
        "locator",
        "retrieved_at",
    )


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            '"ref_id": "018f47a0-7b9c-7a10-8def-0123456789ab", "sha256": "aaaa',
            '"ref_id": "018f47a0-7b9c-7a10-8def-0123456789ab", "sha256": "baaa',
        ),
        (
            '"ref_id": "018f47a0-7b9c-7a32-8def-0123456789ab", "sha256": "3333',
            '"ref_id": "018f47a0-7b9c-7a32-8def-0123456789ab", "sha256": "4333',
        ),
        (
            '"ref_id": "literature-review@1.0.0", "sha256": "7777',
            '"ref_id": "literature-review@1.0.0", "sha256": "6777',
        ),
        (
            '"supporting_sha256": "bbbb',
            '"supporting_sha256": "abbb',
        ),
        (
            '"runtime_adapter_id": "openai_codex",\n    "runtime_connection_id"',
            '"runtime_adapter_id": "changed",\n    "runtime_connection_id"',
        ),
    ],
)
def test_rejects_tampered_provenance_pin(needle: str, replacement: str) -> None:
    # Given: a valid-format provenance or Ledger checksum changed after execution.
    raw = FIXTURE.read_text(encoding="utf-8")

    # When: the tampered payload reaches the aggregate boundary.
    tampered = raw.replace(needle, replacement, 1)

    # Then: every evidence class is end-to-end bound and rejected.
    with pytest.raises(ValidationError):
        _ = DryLabRunContract.model_validate_json(tampered)


def test_rejects_mutable_duplicate_or_coercive_artifact_version() -> None:
    # Given: one checksum pin or immutability marker altered after the GS04 Run.
    raw = FIXTURE.read_text(encoding="utf-8")
    mutable = raw.replace('"immutable": true', '"immutable": false', 1)
    duplicate_revision = raw.replace(
        '"artifact_id": "018f47a0-7b9c-7a21-8def-0123456789ab"',
        '"artifact_id": "018f47a0-7b9c-7a20-8def-0123456789ab"',
        1,
    )

    coercive = raw.replace('"size_bytes": 128', '"size_bytes": "128"', 1)

    # When/Then: none crosses the strict immutable Version boundary.
    with pytest.raises(ValidationError, match="literal_error"):
        _ = DryLabRunContract.model_validate_json(mutable)
    with pytest.raises(ValidationError, match="revision coordinates"):
        _ = DryLabRunContract.model_validate_json(duplicate_revision)
    with pytest.raises(ValidationError):
        _ = DryLabRunContract.model_validate_json(coercive)


def test_rejects_reviewer_capability_findings_replay_and_invalid_skill() -> None:
    # Given: attempts to grant execution, replay Findings, or load an unknown Skill.
    raw = FIXTURE.read_text(encoding="utf-8")
    replayable_findings = raw.replace(
        '"exactly_once": true', '"exactly_once": false', 1
    )
    invalid_skill_id = raw.replace(
        '"id": "literature-review"', '"id": "clinical-diagnosis"', 1
    )
    valid_skill_hash = '"content_sha256": "' + "7" * 64 + '"'
    invalid_skill_hash = raw.replace(
        valid_skill_hash,
        '"content_sha256": "not-a-sha256"',
        1,
    )

    # When/Then: strict models keep Reviewer capabilities false and Skills canonical.
    capability_escalations = tuple(
        raw.replace(f'"{capability}": false', f'"{capability}": true', 1)
        for capability in ReviewerCapabilities.model_fields
    )
    for candidate in (
        *capability_escalations,
        replayable_findings,
        invalid_skill_id,
        invalid_skill_hash,
    ):
        with pytest.raises(ValidationError):
            _ = DryLabRunContract.model_validate_json(candidate)
    assert set(ReviewerCapabilities.model_fields) >= {
        "network",
        "artifact_write",
        "reexecution",
    }
    assert SkillManifest.model_fields["content_sha256"].is_required()
