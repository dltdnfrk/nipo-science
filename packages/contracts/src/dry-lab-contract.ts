import { z } from "zod"

import { ArtifactVersionRecordSchema } from "./artifact-versions"
import { UtcTimestampSchema, Uuid7Schema } from "./common"
import { validateDryLabIntegrity } from "./dry-lab-integrity"
import { EvidenceLedgerSchema } from "./evidence-ledger"
import { ExportManifestSchema } from "./export-manifest"
import { ProvenanceManifestSchema } from "./provenance"
import { PersistedReviewSchema } from "./reviews-v1"
import {
  ApprovedActionPlanRefSchema,
  ApprovedExecutionRefSchema,
  ScientificInputSchema,
} from "./scientific"
import { SkillManifestSchema } from "./skill-manifests"

export const DryLabOutputRefsSchema = z
  .strictObject({
    normalized_csv_version_id: Uuid7Schema,
    figure_png_version_id: Uuid7Schema,
    analysis_markdown_version_id: Uuid7Schema,
    ledger_json_version_id: Uuid7Schema,
    ledger_csv_version_id: Uuid7Schema,
  })
  .readonly()

export const ProbeAnalysisScopeSchema = z
  .strictObject({
    hypothesis_classes: z.tuple([
      z.literal("molecular"),
      z.literal("optical"),
      z.literal("experimental_artifact"),
    ]),
    conclusion_scope: z.literal("non_diagnostic"),
  })
  .readonly()

export const DryLabRunContractCoreSchema = z
  .strictObject({
    contract_version: z.literal("1.0.0"),
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    source_run_id: Uuid7Schema,
    scientific_inputs: z.array(ScientificInputSchema).min(1).readonly(),
    action_plan: ApprovedActionPlanRefSchema,
    executions: z.array(ApprovedExecutionRefSchema).min(1).readonly(),
    artifact_versions: z.array(ArtifactVersionRecordSchema).min(6).readonly(),
    outputs: DryLabOutputRefsSchema,
    analysis_scope: ProbeAnalysisScopeSchema,
    ledger: EvidenceLedgerSchema,
    provenance: ProvenanceManifestSchema,
    review: PersistedReviewSchema,
    skills: z.array(SkillManifestSchema).length(3).readonly(),
    export: ExportManifestSchema,
    completed_at: UtcTimestampSchema,
  })
  .readonly()

export type DryLabRunContractCore = z.infer<typeof DryLabRunContractCoreSchema>

export const DryLabRunContractSchema = DryLabRunContractCoreSchema.superRefine(
  (contract, context) => {
    for (const message of validateDryLabIntegrity(contract)) {
      context.addIssue({ code: "custom", message })
    }
  },
)

export type DryLabRunContract = z.infer<typeof DryLabRunContractSchema>
