import { z } from "zod"

import {
  NonEmptyTextSchema,
  ReadonlyJsonValueSchema,
  RevisionSchema,
  Sha256Schema,
  UtcTimestampSchema,
  Uuid7Schema,
} from "../common"
import { ResearchIntentSchema, researchIntentSha256 } from "../runs"
import { containsForbiddenEventData } from "./event-guard"

const RunEventDataSchema = z
  .json()
  .superRefine((data, context) => {
    if (containsForbiddenEventData(data)) {
      context.addIssue({ code: "custom", message: "Run event data contains forbidden semantics" })
    }
  })
  .transform((data) => ReadonlyJsonValueSchema.parse(data))

export const ProtocolRunStatusSchema = z.enum([
  "queued",
  "running",
  "awaiting_user",
  "awaiting_approval",
  "completed",
  "failed",
  "cancelled",
])
export const ExecutionStatusSchema = z.enum([
  "queued",
  "running",
  "completed",
  "failed",
  "cancelled",
])
export const RunEventKindSchema = z.enum([
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

export const ProtocolRunSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    session_id: Uuid7Schema,
    requester_id: Uuid7Schema,
    provider_connection_id: Uuid7Schema,
    retry_of_run_id: Uuid7Schema.nullable().default(null),
    status: ProtocolRunStatusSchema,
    created_at: UtcTimestampSchema,
    updated_at: UtcTimestampSchema,
  })
  .readonly()
export const MessageSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    run_id: Uuid7Schema,
    role: z.enum(["user", "assistant", "tool"]),
    content: z.string(),
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const ProtocolRunEventSchema = z
  .strictObject({
    run_id: Uuid7Schema,
    sequence: z.int().min(1),
    kind: RunEventKindSchema,
    data: RunEventDataSchema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const ActionPlanSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    run_id: Uuid7Schema,
    requester_id: Uuid7Schema,
    research_intent: ResearchIntentSchema,
    research_intent_sha256: Sha256Schema,
    version: z.int().min(1),
    tool: NonEmptyTextSchema,
    arguments: ReadonlyJsonValueSchema,
    arguments_hash: Sha256Schema,
    network_scope: z.array(z.string()).default([]).readonly(),
    secret_scope: z.array(z.string()).default([]).readonly(),
    reason: NonEmptyTextSchema,
    plan_digest: Sha256Schema,
    created_at: UtcTimestampSchema,
  })
  .superRefine((plan, context) => {
    if (plan.research_intent_sha256 !== researchIntentSha256(plan.research_intent)) {
      context.addIssue({ code: "custom", message: "research intent digest mismatch" })
    }
  })
  .readonly()
export const ToolGrantSchema = z
  .strictObject({
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    tool: NonEmptyTextSchema,
    effect: z.enum(["allow", "ask", "deny"]),
  })
  .readonly()
export const ApprovalBindingSchema = z
  .strictObject({
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    run_id: Uuid7Schema,
    requester_id: Uuid7Schema,
    action_plan_id: Uuid7Schema,
    research_intent_sha256: Sha256Schema,
    plan_digest: Sha256Schema,
    tool: NonEmptyTextSchema,
    arguments_hash: Sha256Schema,
    network_scope: z.array(z.string()).default([]).readonly(),
    secret_scope: z.array(z.string()).default([]).readonly(),
    expires_at: UtcTimestampSchema,
  })
  .readonly()
export const ProtocolApprovalSchema = z
  .strictObject({
    id: Uuid7Schema,
    binding: ApprovalBindingSchema,
    digest: Sha256Schema,
    revision: RevisionSchema,
    status: z.enum(["pending", "approved", "rejected", "expired", "consumed"]),
    decided_by: Uuid7Schema.nullable().default(null),
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const ExecutionSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    run_id: Uuid7Schema,
    action_plan_id: Uuid7Schema,
    status: ExecutionStatusSchema,
    attempt_token: z.int().min(1),
    result_ref: NonEmptyTextSchema.nullable().default(null),
    created_at: UtcTimestampSchema,
    updated_at: UtcTimestampSchema,
  })
  .superRefine((execution, context) => {
    if (execution.status === "completed" && execution.result_ref === null) {
      context.addIssue({
        code: "custom",
        message: "completed Execution requires a result reference",
      })
    }
  })
  .readonly()
export const ExecutionLeaseSchema = z
  .strictObject({
    execution_id: Uuid7Schema,
    attempt_token: z.int().min(1),
    heartbeat_at: UtcTimestampSchema,
    expires_at: UtcTimestampSchema,
  })
  .readonly()
export const ToolResultSchema = z
  .strictObject({
    org_id: Uuid7Schema,
    run_id: Uuid7Schema,
    message_id: Uuid7Schema,
    action_id: Uuid7Schema,
    execution_id: Uuid7Schema,
    executor: z.literal("application"),
    result_ref: NonEmptyTextSchema,
    redacted_output: z.string(),
  })
  .readonly()

export type ProtocolRun = z.infer<typeof ProtocolRunSchema>
export type ProtocolRunEvent = z.infer<typeof ProtocolRunEventSchema>
export type ActionPlan = z.infer<typeof ActionPlanSchema>
export type Execution = z.infer<typeof ExecutionSchema>
