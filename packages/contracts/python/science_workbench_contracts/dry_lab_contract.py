from typing import Annotated, Literal, Self

from pydantic import Field, model_validator

from .artifact_versions import ArtifactVersionRecord
from .common import UtcTimestamp, Uuid7
from .dry_lab_integrity import assert_dry_lab_integrity
from .evidence_ledger import EvidenceLedger
from .export_manifest import ExportManifest
from .provenance import ProvenanceManifest
from .reviews_v1 import PersistedReview
from .scientific import (
    ApprovedActionPlanRef,
    ApprovedExecutionRef,
    ScientificInput,
)
from .skill_manifests import SkillManifest
from .task6_common import Task6ContractModel


class DryLabOutputRefs(Task6ContractModel):
    normalized_csv_version_id: Uuid7
    figure_png_version_id: Uuid7
    analysis_markdown_version_id: Uuid7
    ledger_json_version_id: Uuid7
    ledger_csv_version_id: Uuid7


class ProbeAnalysisScope(Task6ContractModel):
    hypothesis_classes: tuple[
        Literal["molecular"],
        Literal["optical"],
        Literal["experimental_artifact"],
    ]
    conclusion_scope: Literal["non_diagnostic"]


class DryLabRunContract(Task6ContractModel):
    contract_version: Literal["1.0.0"]
    org_id: Uuid7
    project_id: Uuid7
    source_run_id: Uuid7
    scientific_inputs: Annotated[tuple[ScientificInput, ...], Field(min_length=1)]
    action_plan: ApprovedActionPlanRef
    executions: Annotated[tuple[ApprovedExecutionRef, ...], Field(min_length=1)]
    artifact_versions: Annotated[
        tuple[ArtifactVersionRecord, ...],
        Field(min_length=6),
    ]
    outputs: DryLabOutputRefs
    analysis_scope: ProbeAnalysisScope
    ledger: EvidenceLedger
    provenance: ProvenanceManifest
    review: PersistedReview
    skills: Annotated[tuple[SkillManifest, ...], Field(min_length=3, max_length=3)]
    export: ExportManifest
    completed_at: UtcTimestamp

    @model_validator(mode="after")
    def validate_integrity(self) -> Self:
        assert_dry_lab_integrity(self)
        return self
