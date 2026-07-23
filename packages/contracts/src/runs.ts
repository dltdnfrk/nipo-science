import { createHash } from "node:crypto"

import { z } from "zod"

import { NonEmptyTextSchema, UtcTimestampSchema, Uuid7Schema } from "./common"

export const RunStatusSchema = z.enum([
  "queued",
  "running",
  "awaiting_user",
  "awaiting_approval",
  "completed",
  "failed",
  "cancelled",
])
export const RunEventTypeSchema = z.enum([
  "run.status",
  "message.delta",
  "tool.started",
  "tool.output",
  "tool.completed",
  "approval.required",
  "artifact.saved",
  "review.finding",
  "run.completed",
  "run.failed",
])
export const ResearchModeSchema = z.enum(["ai_for_science", "copilot", "bounded_agentic"])
export const DataOriginSchema = z.enum(["observed", "synthetic", "mixed"])
const characterLength = (value: string): number => Array.from(value).length
const codePointRange = (start: number, end: number): number[] =>
  Array.from({ length: end - start + 1 }, (_, index) => start + index)
const researchBoundaryWhitespace = new Set([
  ...codePointRange(0x0009, 0x000d),
  ...codePointRange(0x001c, 0x0020),
  0x0085,
  0x00a0,
  0x1680,
  ...codePointRange(0x2000, 0x200a),
  0x2028,
  0x2029,
  0x202f,
  0x205f,
  0x3000,
  0xfeff,
])
const canonicalResearchText = (value: string): boolean => {
  const characters = Array.from(value)
  const first = characters[0]?.codePointAt(0)
  const last = characters.at(-1)?.codePointAt(0)
  return (
    first !== undefined &&
    last !== undefined &&
    value.isWellFormed() &&
    value.normalize("NFC") === value &&
    !researchBoundaryWhitespace.has(first) &&
    !researchBoundaryWhitespace.has(last)
  )
}
const ResearchIntentTextSchema = NonEmptyTextSchema.refine(
  (value) => characterLength(value) <= 2_000,
).refine(canonicalResearchText)
const ResearchIntentItemSchema = NonEmptyTextSchema.refine(
  (value) => characterLength(value) <= 500,
).refine(canonicalResearchText)
export const ResearchIntentSchema = z
  .strictObject({
    question: ResearchIntentTextSchema,
    rationale: ResearchIntentTextSchema,
    intended_benefit: ResearchIntentTextSchema,
    success_criteria: z.array(ResearchIntentItemSchema).min(1).max(8).readonly(),
    constraints: z.array(ResearchIntentItemSchema).min(1).max(8).readonly(),
    stop_conditions: z.array(ResearchIntentItemSchema).min(1).max(8).readonly(),
    research_mode: ResearchModeSchema,
    data_origin: DataOriginSchema,
    synthetic_generator_ref: ResearchIntentItemSchema.nullish().transform((value) => value ?? null),
    synthetic_validator_ref: ResearchIntentItemSchema.nullish().transform((value) => value ?? null),
  })
  .superRefine((intent, context) => {
    if (
      [intent.success_criteria, intent.constraints, intent.stop_conditions].some(
        (items) => new Set(items).size !== items.length,
      )
    ) {
      context.addIssue({ code: "custom", message: "research intent items must be unique" })
    }
    const synthetic = intent.data_origin !== "observed"
    if (synthetic !== Boolean(intent.synthetic_generator_ref && intent.synthetic_validator_ref)) {
      context.addIssue({ code: "custom", message: "synthetic provenance mismatch" })
    } else if (synthetic && intent.synthetic_generator_ref === intent.synthetic_validator_ref) {
      context.addIssue({ code: "custom", message: "synthetic validator must be distinct" })
    }
  })
  .readonly()

export type ResearchIntent = z.infer<typeof ResearchIntentSchema>

export function researchIntentSha256(intent: ResearchIntent): string {
  const canonical = JSON.stringify({
    constraints: intent.constraints,
    data_origin: intent.data_origin,
    intended_benefit: intent.intended_benefit,
    question: intent.question,
    rationale: intent.rationale,
    research_mode: intent.research_mode,
    stop_conditions: intent.stop_conditions,
    success_criteria: intent.success_criteria,
    synthetic_generator_ref: intent.synthetic_generator_ref ?? null,
    synthetic_validator_ref: intent.synthetic_validator_ref ?? null,
  })
  return createHash("sha256").update(canonical, "utf8").digest("hex")
}

export const RunInputSchema = z
  .strictObject({
    filename: NonEmptyTextSchema,
    media_type: z.literal("text/csv"),
    content: NonEmptyTextSchema,
  })
  .readonly()
const RunCreateFields = {
  session_id: Uuid7Schema,
  prompt: NonEmptyTextSchema,
  research_intent: ResearchIntentSchema,
  input: RunInputSchema,
} as const
export const RunCreateSchema = z
  .discriminatedUnion("execution_mode", [
    z.strictObject({
      execution_mode: z.literal("local_dry_lab"),
      ...RunCreateFields,
    }),
    z.strictObject({
      execution_mode: z.literal("provider_model"),
      ...RunCreateFields,
      connection_id: Uuid7Schema,
      model_id: NonEmptyTextSchema.refine((value) => characterLength(value) <= 255),
    }),
  ])
  .readonly()
export const RunSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    session_id: Uuid7Schema,
    provider_connection_id: Uuid7Schema,
    retry_of_run_id: Uuid7Schema.nullable(),
    status: RunStatusSchema,
    created_at: UtcTimestampSchema,
    updated_at: UtcTimestampSchema,
  })
  .readonly()
export const RunEventSchema = z
  .strictObject({
    run_id: Uuid7Schema,
    sequence: z.int().min(1),
    type: RunEventTypeSchema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const ApprovalCreateSchema = z
  .strictObject({ approval_digest: z.string().min(32) })
  .readonly()
export const ApprovalSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    run_id: Uuid7Schema,
    requester_id: Uuid7Schema,
    status: z.enum(["pending", "approved", "rejected", "expired", "consumed"]),
    expires_at: UtcTimestampSchema,
  })
  .readonly()
export const RunResponseSchema = z.strictObject({ message: NonEmptyTextSchema }).readonly()
export const RunCancelSchema = z.strictObject({ reason: NonEmptyTextSchema.nullable() }).readonly()
export const RunRetrySchema = z.strictObject({ reason: NonEmptyTextSchema.nullable() }).readonly()

export type Run = z.infer<typeof RunSchema>
export type RunEvent = z.infer<typeof RunEventSchema>
