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

export const RunCreateSchema = z
  .strictObject({
    session_id: Uuid7Schema,
    provider_connection_id: Uuid7Schema,
    prompt: NonEmptyTextSchema,
  })
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
