import { z } from "zod"

import { NonEmptyTextSchema, Sha256Schema, UtcTimestampSchema, Uuid7Schema } from "./common"

export const EVIDENCE_LEDGER_COLUMNS = [
  "claim_id",
  "claim_text",
  "evidence_kind",
  "source_id",
  "artifact_version_id",
  "execution_id",
  "supporting_sha256",
  "locator",
  "retrieved_at",
] as const

export const EvidenceLedgerRowSchema = z
  .strictObject({
    claim_id: NonEmptyTextSchema,
    claim_text: NonEmptyTextSchema,
    evidence_kind: z.enum(["input", "execution_output", "literature_source"]),
    source_id: NonEmptyTextSchema,
    artifact_version_id: Uuid7Schema,
    execution_id: Uuid7Schema,
    supporting_sha256: Sha256Schema,
    locator: NonEmptyTextSchema,
    retrieved_at: UtcTimestampSchema,
  })
  .readonly()

export const EvidenceLedgerSchema = z
  .strictObject({
    columns: z.tuple([
      z.literal("claim_id"),
      z.literal("claim_text"),
      z.literal("evidence_kind"),
      z.literal("source_id"),
      z.literal("artifact_version_id"),
      z.literal("execution_id"),
      z.literal("supporting_sha256"),
      z.literal("locator"),
      z.literal("retrieved_at"),
    ]),
    rows: z.array(EvidenceLedgerRowSchema).min(1).readonly(),
    json_artifact_version_id: Uuid7Schema,
    csv_artifact_version_id: Uuid7Schema,
  })
  .readonly()

export type EvidenceLedger = z.infer<typeof EvidenceLedgerSchema>
