from typing import Literal, Protocol

from .artifact_versions import ArtifactVersionRecord
from .common import Uuid7
from .evidence_ledger import EvidenceLedger
from .export_manifest import ExportManifest
from .provenance import ProvenanceManifest
from .reviews_v1 import PersistedReview
from .scientific import ApprovedActionPlanRef, ApprovedExecutionRef, ScientificInput
from .skill_manifests import SkillManifest


class OutputRefs(Protocol):
    @property
    def normalized_csv_version_id(self) -> Uuid7: ...

    @property
    def figure_png_version_id(self) -> Uuid7: ...

    @property
    def analysis_markdown_version_id(self) -> Uuid7: ...

    @property
    def ledger_json_version_id(self) -> Uuid7: ...

    @property
    def ledger_csv_version_id(self) -> Uuid7: ...


class DryLabIntegrityContract(Protocol):
    @property
    def org_id(self) -> Uuid7: ...

    @property
    def project_id(self) -> Uuid7: ...

    @property
    def source_run_id(self) -> Uuid7: ...

    @property
    def scientific_inputs(self) -> tuple[ScientificInput, ...]: ...

    @property
    def action_plan(self) -> ApprovedActionPlanRef: ...

    @property
    def executions(self) -> tuple[ApprovedExecutionRef, ...]: ...

    @property
    def artifact_versions(self) -> tuple[ArtifactVersionRecord, ...]: ...

    @property
    def outputs(self) -> OutputRefs: ...

    @property
    def ledger(self) -> EvidenceLedger: ...

    @property
    def provenance(self) -> ProvenanceManifest: ...

    @property
    def review(self) -> PersistedReview: ...

    @property
    def skills(self) -> tuple[SkillManifest, ...]: ...

    @property
    def export(self) -> ExportManifest: ...

    def model_dump(self, *, mode: Literal["json"]) -> dict[str, object]:
        """Return the complete canonical model payload."""
        ...
