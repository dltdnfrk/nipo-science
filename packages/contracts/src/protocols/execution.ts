import { z } from "zod"

import { NonEmptyTextSchema, UtcTimestampSchema } from "../common"
import { ExecutionLeaseSchema, ExecutionSchema } from "./models"
import { compareUtcTimestamps } from "./timestamps"

export const HEARTBEAT_SECONDS = 15 as const
export const LEASE_SECONDS = 45 as const

export const ExecutionCompletionCommandSchema = z
  .strictObject({
    execution: ExecutionSchema,
    lease: ExecutionLeaseSchema,
    attempt_token: z.int().min(1),
    target: z.enum(["completed", "failed"]),
    result_ref: NonEmptyTextSchema.nullable().default(null),
    occurred_at: UtcTimestampSchema,
  })
  .superRefine((command, context) => {
    const correlated =
      command.execution.id === command.lease.execution_id &&
      command.execution.attempt_token === command.attempt_token &&
      command.lease.attempt_token === command.attempt_token
    const unexpired = compareUtcTimestamps(command.occurred_at, command.lease.expires_at) < 0
    const completedHasResult = command.target !== "completed" || command.result_ref !== null
    if (
      !correlated ||
      !unexpired ||
      command.execution.status !== "running" ||
      !completedHasResult
    ) {
      context.addIssue({ code: "custom", message: "execution lease cannot complete" })
    }
  })
  .readonly()
