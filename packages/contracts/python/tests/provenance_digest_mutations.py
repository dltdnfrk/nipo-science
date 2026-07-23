from __future__ import annotations

from typing import TYPE_CHECKING, Final, Literal, assert_never
from uuid import UUID

from science_workbench_contracts.provenance import HashPin

from .provenance_output_digest_mutation import output_mutation

if TYPE_CHECKING:
    from collections.abc import Callable

    from science_workbench_contracts.artifact_versions import ArtifactVersionRecord
    from science_workbench_contracts.dry_lab_contract import DryLabRunContract

TAMPER_HASH: Final = "0" * 64
EXPECTED_PROVENANCE_DIGEST: Final = (
    "094797c44a042da806374f13056648e2571a7a1eb42b7f2eec06912ced09acc1"
)
INPUT_ID: Final = UUID("018f47a0-7b9c-7a10-8def-0123456789ab")
EXECUTION_ID: Final = UUID("018f47a0-7b9c-7a32-8def-0123456789ab")
SKILL_REF: Final = "literature-review@1.0.0"
MutationTarget = Literal[
    "code",
    "environment",
    "source",
    "input",
    "execution",
    "skill",
    "runtime",
    "output",
]
PROVENANCE_MUTATION_TARGETS: Final[tuple[MutationTarget, ...]] = (
    "code",
    "environment",
    "source",
    "input",
    "execution",
    "skill",
    "runtime",
    "output",
)


def _update_outputs(
    contract: DryLabRunContract,
    update: Callable[[ArtifactVersionRecord], ArtifactVersionRecord],
) -> tuple[ArtifactVersionRecord, ...]:
    output_ids = {
        contract.outputs.normalized_csv_version_id,
        contract.outputs.figure_png_version_id,
        contract.outputs.analysis_markdown_version_id,
        contract.outputs.ledger_json_version_id,
        contract.outputs.ledger_csv_version_id,
    }
    return tuple(
        update(version) if version.id in output_ids else version
        for version in contract.artifact_versions
    )


def coordinated_mutation(
    contract: DryLabRunContract,
    target: MutationTarget,
) -> DryLabRunContract:
    match target:
        case "code":
            versions = _update_outputs(
                contract,
                lambda version: version.model_copy(
                    update={"code_sha256": TAMPER_HASH}
                ),
            )
            provenance = contract.provenance.model_copy(
                update={"code_sha256": TAMPER_HASH}
            )
            mutated = contract.model_copy(
                update={"artifact_versions": versions, "provenance": provenance}
            )
        case "environment":
            versions = _update_outputs(
                contract,
                lambda version: version.model_copy(
                    update={"environment_sha256": TAMPER_HASH}
                ),
            )
            provenance = contract.provenance.model_copy(
                update={"environment_sha256": TAMPER_HASH}
            )
            mutated = contract.model_copy(
                update={"artifact_versions": versions, "provenance": provenance}
            )
        case "source":
            versions = _update_outputs(
                contract,
                lambda version: version.model_copy(
                    update={"source_hashes": (TAMPER_HASH,)}
                ),
            )
            provenance = contract.provenance.model_copy(
                update={
                    "source_hashes": (
                        HashPin(ref_id="source:tampered", sha256=TAMPER_HASH),
                    )
                }
            )
            mutated = contract.model_copy(
                update={"artifact_versions": versions, "provenance": provenance}
            )
        case "input":
            versions = tuple(
                version.model_copy(update={"content_sha256": TAMPER_HASH})
                if version.id == INPUT_ID
                else version
                for version in contract.artifact_versions
            )
            pins = tuple(
                pin.model_copy(update={"sha256": TAMPER_HASH})
                if pin.ref_id == str(INPUT_ID)
                else pin
                for pin in contract.provenance.input_hashes
            )
            provenance = contract.provenance.model_copy(update={"input_hashes": pins})
            mutated = contract.model_copy(
                update={"artifact_versions": versions, "provenance": provenance}
            )
        case "execution":
            executions = tuple(
                execution.model_copy(update={"execution_sha256": TAMPER_HASH})
                if execution.execution_id == EXECUTION_ID
                else execution
                for execution in contract.executions
            )
            pins = tuple(
                pin.model_copy(update={"sha256": TAMPER_HASH})
                if pin.ref_id == str(EXECUTION_ID)
                else pin
                for pin in contract.provenance.execution_hashes
            )
            provenance = contract.provenance.model_copy(
                update={"execution_hashes": pins}
            )
            mutated = contract.model_copy(
                update={"executions": executions, "provenance": provenance}
            )
        case "skill":
            versions = _update_outputs(
                contract,
                lambda version: version.model_copy(
                    update={
                        "skill_content_hashes": tuple(
                            TAMPER_HASH if value == "7" * 64 else value
                            for value in version.skill_content_hashes
                        )
                    }
                ),
            )
            skills = tuple(
                skill.model_copy(update={"content_sha256": TAMPER_HASH})
                if skill.id == "literature-review"
                else skill
                for skill in contract.skills
            )
            pins = tuple(
                pin.model_copy(update={"sha256": TAMPER_HASH})
                if pin.ref_id == SKILL_REF
                else pin
                for pin in contract.provenance.skill_hashes
            )
            provenance = contract.provenance.model_copy(update={"skill_hashes": pins})
            mutated = contract.model_copy(
                update={
                    "artifact_versions": versions,
                    "skills": skills,
                    "provenance": provenance,
                }
            )
        case "runtime":
            versions = _update_outputs(
                contract,
                lambda version: version.model_copy(
                    update={"runtime_adapter_id": "tampered_adapter"}
                ),
            )
            provenance = contract.provenance.model_copy(
                update={"runtime_adapter_id": "tampered_adapter"}
            )
            mutated = contract.model_copy(
                update={"artifact_versions": versions, "provenance": provenance}
            )
        case "output":
            mutated = output_mutation(contract, TAMPER_HASH)
        case _:
            assert_never(target)
    return mutated
