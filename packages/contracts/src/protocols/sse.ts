import { z } from "zod"

import { UtcTimestampSchema, Uuid7Schema } from "../common"
import { ProtocolRunEventSchema } from "./models"

export const RunEventWindowSchema = z
  .strictObject({
    run_id: Uuid7Schema,
    oldest_available_sequence: z.int().min(1),
    retention_expires_at: UtcTimestampSchema,
    events: z.array(ProtocolRunEventSchema).readonly(),
  })
  .superRefine((window, context) => {
    const sequences = window.events.map((event) => event.sequence)
    for (const [index, event] of window.events.entries()) {
      const previous = sequences[index - 1]
      if (event.run_id !== window.run_id) {
        context.addIssue({ code: "custom", message: "all events must belong to the replay Run" })
      }
      if (previous !== undefined && event.sequence <= previous) {
        context.addIssue({
          code: "custom",
          message: "event sequence must be unique and increasing",
        })
      }
    }
    const first = sequences[0]
    if (first !== undefined && first < window.oldest_available_sequence) {
      context.addIssue({ code: "custom", message: "events precede the retained sequence" })
    }
  })
  .readonly()

export const ReplayRequestSchema = z
  .strictObject({ last_event_id: z.int().min(0), occurred_at: UtcTimestampSchema })
  .readonly()
export const ReplayBatchSchema = z
  .strictObject({
    status_code: z.literal(200).default(200),
    events: z.array(ProtocolRunEventSchema).readonly(),
  })
  .readonly()
export const ReplayExpiredSchema = z
  .strictObject({
    status_code: z.literal(410).default(410),
    run_id: Uuid7Schema,
    recovery: z.literal("GET_RUN").default("GET_RUN"),
  })
  .readonly()
export const ReplayCursorErrorSchema = z
  .strictObject({
    status_code: z.literal(409).default(409),
    code: z.literal("INVALID_LAST_EVENT_ID").default("INVALID_LAST_EVENT_ID"),
  })
  .readonly()
