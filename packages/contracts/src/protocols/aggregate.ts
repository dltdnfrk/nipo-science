import { z } from "zod"

import { ProtocolRunEventSchema, ProtocolRunSchema } from "./models"
import { compareUtcTimestamps } from "./timestamps"

export const RunAggregateSchema = z
  .strictObject({
    run: ProtocolRunSchema,
    events: z.array(ProtocolRunEventSchema).readonly().default([]),
  })
  .superRefine((aggregate, context) => {
    for (const [index, event] of aggregate.events.entries()) {
      const previous = aggregate.events[index - 1]
      if (event.run_id !== aggregate.run.id) {
        context.addIssue({ code: "custom", message: "all events must belong to the aggregate Run" })
      }
      if (event.sequence !== index + 1) {
        context.addIssue({
          code: "custom",
          message: "event sequence must be contiguous and increasing",
        })
      }
      if (
        previous !== undefined &&
        compareUtcTimestamps(event.created_at, previous.created_at) < 0
      ) {
        context.addIssue({ code: "custom", message: "event timestamps must be monotonic" })
      }
    }
  })
  .readonly()

export type RunAggregate = z.infer<typeof RunAggregateSchema>
