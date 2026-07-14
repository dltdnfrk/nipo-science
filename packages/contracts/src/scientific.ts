import { z } from "zod"

import { NonEmptyTextSchema, Sha256Schema, UtcTimestampSchema, Uuid7Schema } from "./common"

export const MeasurementUnitSchema = z
  .strictObject({ quantity: NonEmptyTextSchema, ucum_code: NonEmptyTextSchema })
  .readonly()

export const CalibrationContextSchema = z
  .strictObject({
    method: NonEmptyTextSchema,
    reference: NonEmptyTextSchema,
    calibrated_at: UtcTimestampSchema,
    calibration_sha256: Sha256Schema,
  })
  .readonly()

export const ResearchContextSchema = z
  .strictObject({
    purpose: z.literal("research_only"),
    subject_scope: z.literal("non_clinical"),
    description: NonEmptyTextSchema,
  })
  .readonly()

export const ScientificInputSchema = z
  .strictObject({
    artifact_version_id: Uuid7Schema,
    kind: z.enum(["spectrum", "image", "table", "report"]),
    units: z.array(MeasurementUnitSchema).min(1).readonly(),
    calibration: CalibrationContextSchema,
    context: ResearchContextSchema,
  })
  .readonly()

export const ApprovedActionPlanRefSchema = z
  .strictObject({
    action_plan_id: Uuid7Schema,
    version: z.int().min(1),
    digest_sha256: Sha256Schema,
    approval_id: Uuid7Schema,
    approved_at: UtcTimestampSchema,
    immutable: z.literal(true),
  })
  .readonly()

export const ApprovedExecutionRefSchema = z
  .strictObject({
    execution_id: Uuid7Schema,
    action_plan_id: Uuid7Schema,
    approval_id: Uuid7Schema,
    status: z.literal("completed"),
    execution_sha256: Sha256Schema,
  })
  .readonly()

export type ScientificInput = z.infer<typeof ScientificInputSchema>
export type ApprovedActionPlanRef = z.infer<typeof ApprovedActionPlanRefSchema>
export type ApprovedExecutionRef = z.infer<typeof ApprovedExecutionRefSchema>
