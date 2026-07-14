import { z } from "zod"

import { NonEmptyTextSchema, Sha256Schema, UtcTimestampSchema, Uuid7Schema } from "../common"
import { MessageSchema, ToolResultSchema } from "./models"

export const RuntimeTextDeltaSchema = z
  .strictObject({
    kind: z.literal("text_delta"),
    run_id: Uuid7Schema,
    message_id: Uuid7Schema,
    delta: NonEmptyTextSchema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const RuntimeActionProposalSchema = z
  .strictObject({
    kind: z.literal("action_proposal"),
    run_id: Uuid7Schema,
    message_id: Uuid7Schema,
    action_id: Uuid7Schema,
    action_type: z.literal("tool"),
    tool: NonEmptyTextSchema,
    arguments: z.json(),
    arguments_hash: Sha256Schema,
    continuation_token: NonEmptyTextSchema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const RuntimeTerminalSchema = z
  .strictObject({
    kind: z.literal("terminal"),
    run_id: Uuid7Schema,
    outcome: z.enum(["completed", "failed", "cancelled", "unavailable"]),
    detail: NonEmptyTextSchema.nullable().default(null),
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const RuntimeQuotaSchema = z
  .strictObject({
    kind: z.literal("quota"),
    run_id: Uuid7Schema,
    detail: NonEmptyTextSchema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const RuntimeReauthenticationSchema = z
  .strictObject({
    kind: z.literal("reauth_required"),
    run_id: Uuid7Schema,
    detail: NonEmptyTextSchema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const RuntimeEventSchema = z.discriminatedUnion("kind", [
  RuntimeTextDeltaSchema,
  RuntimeActionProposalSchema,
  RuntimeTerminalSchema,
  RuntimeQuotaSchema,
  RuntimeReauthenticationSchema,
])
export const RuntimeStartSchema = z
  .strictObject({
    run_id: Uuid7Schema,
    provider_connection_id: Uuid7Schema,
    message: MessageSchema,
  })
  .superRefine((command, context) => {
    if (command.run_id !== command.message.run_id) {
      context.addIssue({ code: "custom", message: "runtime command references do not correlate" })
    }
  })
  .readonly()
export const RuntimeContinueSchema = z
  .strictObject({
    org_id: Uuid7Schema,
    run_id: Uuid7Schema,
    message_id: Uuid7Schema,
    action_id: Uuid7Schema,
    execution_id: Uuid7Schema,
    continuation_token: NonEmptyTextSchema,
    result: ToolResultSchema,
  })
  .superRefine((command, context) => {
    const result = command.result
    const correlated =
      command.org_id === result.org_id &&
      command.run_id === result.run_id &&
      command.message_id === result.message_id &&
      command.action_id === result.action_id &&
      command.execution_id === result.execution_id
    if (!correlated) {
      context.addIssue({ code: "custom", message: "runtime command references do not correlate" })
    }
  })
  .readonly()
export const RuntimeCancelSchema = z
  .strictObject({ run_id: Uuid7Schema, reason: NonEmptyTextSchema.nullable().default(null) })
  .readonly()

export interface AgentRuntimeAdapter {
  start(
    command: z.infer<typeof RuntimeStartSchema>,
  ): AsyncIterable<z.infer<typeof RuntimeEventSchema>>
  continueWithToolResult(command: z.infer<typeof RuntimeContinueSchema>): Promise<void>
  cancel(command: z.infer<typeof RuntimeCancelSchema>): Promise<void>
}

export type RuntimeEvent = z.infer<typeof RuntimeEventSchema>
