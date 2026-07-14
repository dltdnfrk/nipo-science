import { z } from "zod"

import { RevisionSchema, UtcTimestampSchema, Uuid7Schema } from "../common"
import { ActionPlanSchema, ApprovalBindingSchema, ToolGrantSchema } from "./models"

export const ToolEvaluationContextSchema = z
  .strictObject({
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    run_id: Uuid7Schema,
    requester_id: Uuid7Schema,
  })
  .readonly()
export const ToolGrantEvaluationCommandSchema = z
  .strictObject({
    grant: ToolGrantSchema,
    plan: ActionPlanSchema,
    context: ToolEvaluationContextSchema,
  })
  .superRefine((command, context) => {
    const { grant, plan } = command
    const authority = command.context
    const matches =
      grant.org_id === authority.org_id &&
      grant.project_id === authority.project_id &&
      plan.org_id === authority.org_id &&
      plan.project_id === authority.project_id &&
      plan.run_id === authority.run_id &&
      plan.requester_id === authority.requester_id &&
      grant.tool === plan.tool
    if (!matches) {
      context.addIssue({ code: "custom", message: "Tool Grant context does not match" })
    }
  })
  .readonly()
export const ApprovalConsumeCasSchema = z
  .strictObject({
    approval_id: Uuid7Schema,
    expected_revision: RevisionSchema,
    expected_status: z.literal("approved"),
    presented_binding: ApprovalBindingSchema,
    presented_plan: ActionPlanSchema,
    occurred_at: UtcTimestampSchema,
  })
  .superRefine((command, context) => {
    const plan = command.presented_plan
    const binding = command.presented_binding
    const matches =
      binding.org_id === plan.org_id &&
      binding.project_id === plan.project_id &&
      binding.run_id === plan.run_id &&
      binding.requester_id === plan.requester_id &&
      binding.action_plan_id === plan.id &&
      binding.plan_digest === plan.plan_digest &&
      binding.tool === plan.tool &&
      binding.arguments_hash === plan.arguments_hash &&
      JSON.stringify(binding.network_scope) === JSON.stringify(plan.network_scope) &&
      JSON.stringify(binding.secret_scope) === JSON.stringify(plan.secret_scope)
    if (!matches) {
      context.addIssue({ code: "custom", message: "Approval binding does not match ActionPlan" })
    }
  })
  .readonly()
