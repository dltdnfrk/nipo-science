from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from science_workbench_contracts.dry_lab_contract import DryLabRunContract
from science_workbench_contracts.provenance import provenance_manifest_sha256

from .provenance_digest_mutations import (
    EXPECTED_PROVENANCE_DIGEST,
    PROVENANCE_MUTATION_TARGETS,
    MutationTarget,
    coordinated_mutation,
)

FIXTURE = Path(__file__).parents[2] / "fixtures" / "gs04-dry-lab-contract.json"
VERSION_ONE = "018f47a0-7b9c-7a10-8def-0123456789ab"
OUTPUT_ONE = "018f47a0-7b9c-7a11-8def-0123456789ab"
OTHER_EXECUTION = "018f47a0-7b9c-7aff-8def-0123456789ab"
APPROVED_EXECUTION = "018f47a0-7b9c-7a32-8def-0123456789ab"
HASH_6 = "6" * 64
HASH_9 = "9" * 64
ALL_SKILL_HASHES = (
    '"skill_content_hashes": ['
    '"7777777777777777777777777777777777777777777777777777777777777777", '
    '"8888888888888888888888888888888888888888888888888888888888888888", '
    '"9999999999999999999999999999999999999999999999999999999999999999"]'
)
def _mutate_first_output(raw: str, needle: str, replacement: str) -> str:
    output_marker = '"id": "018f47a0-7b9c-7a11-8def-0123456789ab"'
    prefix, marker, outputs = raw.partition(output_marker)
    return prefix + marker + outputs.replace(needle, replacement, 1)


def test_matches_shared_python_and_typescript_canonical_provenance_digest() -> None:
    # Given: the shared valid GS04 provenance manifest.
    provenance = DryLabRunContract.model_validate_json(
        FIXTURE.read_text(encoding="utf-8")
    ).provenance

    # When: Python canonicalizes and hashes the complete payload.
    digest = provenance_manifest_sha256(provenance)

    # Then: it matches the shared fixture value also asserted by TypeScript.
    assert digest == EXPECTED_PROVENANCE_DIGEST
    assert provenance.manifest_sha256 == EXPECTED_PROVENANCE_DIGEST
    international = provenance.model_copy(update={"runtime_adapter_id": "한글😀"})
    assert provenance_manifest_sha256(international) == (
        "ad225bd977785536450bffe5a25e67b37814074467f15835820787e0a76779be"
    )


@pytest.mark.parametrize("target", PROVENANCE_MUTATION_TARGETS)
def test_rejects_coordinated_provenance_mutation_with_stale_digest(
    target: MutationTarget,
) -> None:
    # Given: every ordinary cross-reference agrees on one coordinated mutation.
    contract = DryLabRunContract.model_validate_json(
        FIXTURE.read_text(encoding="utf-8")
    )
    mutated = coordinated_mutation(contract, target)

    # When/Then: manifest self-verification rejects the stale digest.
    with pytest.raises(ValidationError, match="provenance manifest digest mismatch"):
        _ = DryLabRunContract.model_validate_json(mutated.model_dump_json())


@pytest.mark.parametrize("target", PROVENANCE_MUTATION_TARGETS)
def test_rejects_rehashed_coordinated_provenance_mutation_at_review_pin(
    target: MutationTarget,
) -> None:
    # Given: the attacker recomputes the digest after a coordinated mutation.
    contract = DryLabRunContract.model_validate_json(
        FIXTURE.read_text(encoding="utf-8")
    )
    mutated = coordinated_mutation(contract, target)
    rehashed_provenance = mutated.provenance.model_copy(
        update={"manifest_sha256": provenance_manifest_sha256(mutated.provenance)}
    )
    rehashed = mutated.model_copy(update={"provenance": rehashed_provenance})

    # When/Then: the unchanged immutable Review input pin rejects the manifest.
    with pytest.raises(
        ValidationError,
        match="Run, ActionPlan, and Review digest pins do not match provenance",
    ):
        _ = DryLabRunContract.model_validate_json(rehashed.model_dump_json())


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            '"input_version_ids": ["018f47a0-7b9c-7a10-8def-0123456789ab"]',
            '"input_version_ids": []',
        ),
        (ALL_SKILL_HASHES, '"skill_content_hashes": []'),
        (
            '"source_hashes": []',
            f'"source_hashes": ["{HASH_6}"]',
        ),
        (
            f'"input_version_ids": ["{VERSION_ONE}"]',
            '"input_version_ids": ["018f47a0-7b9c-7a11-8def-0123456789ab"]',
        ),
    ],
)
def test_rejects_incomplete_or_extra_exact_provenance_set(
    needle: str,
    replacement: str,
) -> None:
    # Given: a derived output with an incomplete or extra provenance set.
    raw = FIXTURE.read_text(encoding="utf-8")

    # When: the exact-set mutation reaches the aggregate boundary.
    mutated = _mutate_first_output(raw, needle, replacement)

    # Then: the payload fails closed.
    with pytest.raises(ValidationError, match="complete provenance"):
        _ = DryLabRunContract.model_validate_json(mutated)


def test_rejects_duplicate_provenance_ref_ids() -> None:
    # Given: an input content pin duplicated before its calibration pin.
    raw = FIXTURE.read_text(encoding="utf-8")
    pin = (
        '{"ref_id": "018f47a0-7b9c-7a10-8def-0123456789ab", '
        '"sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    )

    # When: duplicate ref IDs cross the manifest boundary.
    duplicate = raw.replace(pin, f"{pin},\n      {pin}", 1)

    # Then: dictionary collapse cannot hide the duplicate.
    with pytest.raises(ValidationError, match="unique"):
        _ = DryLabRunContract.model_validate_json(duplicate)


def test_rejects_output_skill_hash_subset_and_extra_input_dependency() -> None:
    # Given: one output has a Skill subset or an extra input dependency.
    raw = FIXTURE.read_text(encoding="utf-8")
    subset = _mutate_first_output(
        raw,
        ALL_SKILL_HASHES,
        f'"skill_content_hashes": ["{HASH_9}"]',
    )
    extra = raw.replace(
        f'"input_version_ids": ["{VERSION_ONE}"]',
        "".join(
            (
                f'"input_version_ids": ["{VERSION_ONE}", ',
                f'"{OTHER_EXECUTION}"]',
            )
        ),
        1,
    )

    # When/Then: exact provenance sets reject subset and extra membership.
    with pytest.raises(ValidationError):
        _ = DryLabRunContract.model_validate_json(subset)
    with pytest.raises(ValidationError):
        _ = DryLabRunContract.model_validate_json(extra)


def test_rejects_unapproved_review_execution_pin() -> None:
    # Given: Review pins an unrelated Execution in addition to the approved one.
    raw = FIXTURE.read_text(encoding="utf-8")
    mutated = raw.replace(
        '"pinned_execution_ids": ["018f47a0-7b9c-7a32-8def-0123456789ab"]',
        f'"pinned_execution_ids": ["{APPROVED_EXECUTION}", "{OTHER_EXECUTION}"]',
        1,
    )

    # When/Then: Review execution pins must exactly equal approved Executions.
    with pytest.raises(ValidationError, match="exactly the output versions"):
        _ = DryLabRunContract.model_validate_json(mutated)


def test_rejects_duplicate_aggregate_members_and_unrelated_pins() -> None:
    # Given: duplicate aggregate identities padded with unrelated provenance pins.
    raw = FIXTURE.read_text(encoding="utf-8")
    input_start = raw.index('    {\n      "artifact_version_id":')
    input_end = raw.index("\n    }", input_start) + len("\n    }")
    input_item = raw[input_start:input_end]
    execution_start = raw.index('    {\n      "execution_id":')
    execution_end = raw.index("\n    }", execution_start) + len("\n    }")
    execution_item = raw[execution_start:execution_end]
    duplicate_input = raw.replace(
        input_item, f"{input_item},\n{input_item}", 1
    ).replace(
        '"input_hashes": [',
        "".join(
            (
                f'"input_hashes": [{{"ref_id":"{"0" * 64}","sha256":"{"1" * 64}"}},',
                f'{{"ref_id":"calibration:{"0" * 64}","sha256":"{"2" * 64}"}},',
            )
        ),
        1,
    )
    duplicate_execution = raw.replace(
        execution_item, f"{execution_item},\n{execution_item}", 1
    ).replace(
        '"execution_hashes": [',
        f'"execution_hashes": [{{"ref_id":"{OTHER_EXECUTION}","sha256":"{"3" * 64}"}},',
        1,
    )
    duplicate_review = raw.replace(
        '"pinned_artifact_version_ids": [',
        f'"pinned_artifact_version_ids": ["{OUTPUT_ONE}",',
        1,
    )

    # When/Then: uniqueness and exact expected reference sets fail closed.
    for mutation in (duplicate_input, duplicate_execution, duplicate_review):
        with pytest.raises(ValidationError):
            _ = DryLabRunContract.model_validate_json(mutation)


@pytest.mark.parametrize(
    ("needle", "replacement"),
    [
        (
            '"org_id": "018f47a0-7b9c-7a01-8def-0123456789ab"',
            f'"org_id": "{OTHER_EXECUTION}"',
        ),
        (
            '"project_id": "018f47a0-7b9c-7a03-8def-0123456789ab"',
            f'"project_id": "{OTHER_EXECUTION}"',
        ),
    ],
)
def test_rejects_output_tenant_binding_mutation(needle: str, replacement: str) -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    mutated = _mutate_first_output(raw, needle, replacement)
    with pytest.raises(ValidationError):
        _ = DryLabRunContract.model_validate_json(mutated)


def test_rejects_review_run_aliasing_source_run() -> None:
    raw = FIXTURE.read_text(encoding="utf-8")
    mutated = raw.replace(
        '"run_id": "018f47a0-7b9c-7a41-8def-0123456789ab"',
        '"run_id": "018f47a0-7b9c-7a02-8def-0123456789ab"',
        1,
    )
    with pytest.raises(ValidationError):
        _ = DryLabRunContract.model_validate_json(mutated)
