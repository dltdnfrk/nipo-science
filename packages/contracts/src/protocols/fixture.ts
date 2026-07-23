import { z } from "zod"

import {
  ActionPlanSchema,
  ExecutionSchema,
  MessageSchema,
  ProtocolApprovalSchema,
  ProtocolRunSchema,
  ToolGrantSchema,
} from "./models"
import { RuntimeActionProposalSchema, RuntimeContinueSchema, RuntimeEventSchema } from "./runtime"
import { RunEventWindowSchema } from "./sse"

export const ProtocolFixtureSchema = z
  .strictObject({
    run: ProtocolRunSchema,
    messages: z.array(MessageSchema).readonly(),
    event_window: RunEventWindowSchema,
    action_plan: ActionPlanSchema,
    tool_grant: ToolGrantSchema,
    approval: ProtocolApprovalSchema,
    execution: ExecutionSchema,
    runtime_events: z.array(RuntimeEventSchema).readonly(),
    runtime_action_proposal: RuntimeActionProposalSchema,
    runtime_continuation: RuntimeContinueSchema,
  })
  .superRefine((fixture, context) => {
    const { run, action_plan: plan, approval, execution } = fixture
    const binding = approval.binding
    const proposal = fixture.runtime_action_proposal
    const continuation = fixture.runtime_continuation
    const messageIds = new Set(fixture.messages.map((message) => message.id))
    const recordsCorrelate = [
      fixture.messages.every(
        (message) => message.org_id === run.org_id && message.run_id === run.id,
      ),
      fixture.event_window.run_id === run.id,
      fixture.event_window.events.every((event) => event.run_id === run.id),
      fixture.runtime_events.every((event) => event.run_id === run.id),
      fixture.runtime_events.every(
        (event) =>
          !(event.kind === "text_delta" || event.kind === "action_proposal") ||
          messageIds.has(event.message_id),
      ),
      fixture.runtime_events.some((event) => JSON.stringify(event) === JSON.stringify(proposal)),
      plan.org_id === run.org_id,
      plan.run_id === run.id,
      plan.requester_id === run.requester_id,
      fixture.tool_grant.org_id === plan.org_id,
      fixture.tool_grant.project_id === plan.project_id,
      binding.org_id === plan.org_id,
      binding.project_id === plan.project_id,
      binding.run_id === plan.run_id,
      binding.requester_id === plan.requester_id,
      binding.action_plan_id === plan.id,
      binding.research_intent_sha256 === plan.research_intent_sha256,
      binding.plan_digest === plan.plan_digest,
      execution.org_id === run.org_id,
      execution.run_id === run.id,
      execution.action_plan_id === plan.id,
      proposal.run_id === run.id,
      messageIds.has(proposal.message_id),
      continuation.org_id === run.org_id,
      continuation.run_id === run.id,
      continuation.message_id === proposal.message_id,
      continuation.action_id === proposal.action_id,
      continuation.execution_id === execution.id,
      continuation.result.execution_id === execution.id,
    ].every(Boolean)
    if (!recordsCorrelate) {
      context.addIssue({ code: "custom", message: "protocol fixture references do not correlate" })
    }
  })
  .readonly()

export type ProtocolFixture = z.infer<typeof ProtocolFixtureSchema>
