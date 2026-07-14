import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { RunAggregateSchema } from "../src/index"
import { ExecutionCompletionCommandSchema } from "../src/protocols/execution"
import { ProtocolFixtureSchema } from "../src/protocols/fixture"
import {
  ApprovalConsumeCasSchema,
  ToolGrantEvaluationCommandSchema,
} from "../src/protocols/governance"
import {
  ActionPlanSchema,
  ApprovalBindingSchema,
  ExecutionSchema,
  ProtocolRunEventSchema,
  ProtocolRunSchema,
} from "../src/protocols/models"
import { RuntimeCancelSchema, RuntimeContinueSchema } from "../src/protocols/runtime"
import {
  ReplayBatchSchema,
  ReplayCursorErrorSchema,
  ReplayExpiredSchema,
  RunEventWindowSchema,
} from "../src/protocols/sse"

const fixturePath = fileURLToPath(new URL("../fixtures/run-runtime-protocol.json", import.meta.url))
const rawFixture: unknown = JSON.parse(readFileSync(fixturePath, "utf8"))
const fixture = ProtocolFixtureSchema.parse(rawFixture)

describe("Run and runtime protocol contracts", () => {
  it("round trips the shared protocol fixture through Zod", () => {
    // Given: the same external JSON consumed by Pydantic.
    // When: Zod parses, serializes, and reparses the boundary.
    // Then: tenant, Run, Execution, and runtime relationships survive.
    expect(ProtocolFixtureSchema.parse(JSON.parse(JSON.stringify(fixture)))).toEqual(fixture)
    expect(fixture.execution.run_id).toBe(fixture.run.id)
    expect(Object.isFrozen(fixture.action_plan)).toBe(true)
  })

  it("rejects duplicate or decreasing event sequence", () => {
    // Given: a valid fixture whose durable events are reversed.
    const window = { ...fixture.event_window, events: [...fixture.event_window.events].reverse() }

    // When: Zod validates the replay window.
    // Then: monotonic ordering is mandatory.
    expect(RunEventWindowSchema.safeParse(window).success).toBe(false)
  })

  it("rejects provider-specific runtime fields", () => {
    // Given: a neutral runtime event polluted with a provider field.
    const firstEvent = fixture.runtime_events[0]
    expect(firstEvent).toBeDefined()
    if (firstEvent === undefined) return
    const runtimeEvents = [{ ...firstEvent, provider: "vendor" }]

    // When: the strict fixture boundary parses the polluted event.
    const result = ProtocolFixtureSchema.safeParse({ ...fixture, runtime_events: runtimeEvents })

    // Then: provider-specific core types fail closed.
    expect(result.success).toBe(false)
  })

  it("accepts tool-result continuation only from the application", () => {
    // Given: a continuation claiming provider-side tool execution.
    const invalid = {
      ...fixture.runtime_continuation,
      result: {
        ...fixture.runtime_continuation.result,
        executor: "provider",
      },
    }

    // When: the runtime continuation boundary parses it.
    // Then: application ownership is enforced structurally.
    expect(RuntimeContinueSchema.safeParse(invalid).success).toBe(false)
  })

  it("rejects monetary and automatic fallback fields", () => {
    // Given: a Run polluted with forbidden governance semantics.
    const run = { ...fixture.run, cost: 1, fallback_provider_connection_id: fixture.run.id }

    // When: the strict protocol fixture parses it.
    // Then: neither monetary fields nor fallback selection enter the core contract.
    expect(ProtocolFixtureSchema.safeParse({ ...fixture, run }).success).toBe(false)
  })

  it("rejects cross-record references and forbidden nested event keys", () => {
    // Given: a cross-Run message and recursively nested forbidden event data.
    const messages = fixture.messages.map((message) => ({
      ...message,
      run_id: fixture.approval.id,
    }))
    const event = {
      ...fixture.event_window.events[0],
      data: { result: { fallback_provider_connection_id: fixture.run.provider_connection_id } },
    }
    const credentialKeys =
      "Authorization|proxy-authorization|access_token|refresh.token|api-key|X API KEY|cookie|Set_Cookie|client.secret|bearer-token|service_token|db-credentials|password|db-password|PASSWD|user.passwd|secret|build-secret|private_key|signing.private-key|client_password|ssh-private-key|password.value|secret.value|private_key_pem|passwordless_secret|secretory_password|ｃｏｓｔ|ｐｒｏｖｉｄｅｒ＿ｆａｌｌｂａｃｋ|ｐａｓｓｗｏｒｄ|ａｐｉ＿ｋｅｙ".split(
        "|",
      )

    // When: strict Zod boundaries parse both attacks.
    // Then: correlation and recursive semantic-key validation fail closed.
    expect(ProtocolFixtureSchema.safeParse({ ...fixture, messages }).success).toBe(false)
    expect(ProtocolRunEventSchema.safeParse(event).success).toBe(false)
    for (const key of credentialKeys) {
      const credential = { ...event, data: { result: [{ [key]: "<redacted>" }] } }
      expect(ProtocolRunEventSchema.safeParse(credential).success).toBe(false)
    }
    const benignKeys =
      "tokenization_method|secretory_pathway|secretome_score|passwordless_method|ｓｅｃｒｅｔｏｒｙ＿ｐａｔｈｗａｙ|단백질_농도".split(
        "|",
      )
    for (const key of benignKeys) {
      const benign = { ...event, data: { analysis: [{ [key]: "measured" }] } }
      expect(ProtocolRunEventSchema.safeParse(benign).success).toBe(true)
    }
    const placeholder = "x".repeat(24)
    const secretValues = [
      `Bearer ${placeholder}`,
      `Authorization: Basic ${"eHh4".repeat(6)}`,
      `client_secret=${placeholder}`,
      `api-key: ${placeholder}`,
      `sk-${placeholder}`,
      `ghp_${placeholder}`,
      `AKIA${"A".repeat(16)}`,
      `${"-".repeat(5)}BEGIN PRIVATE KEY${"-".repeat(5)}`,
      `Ｂｅａｒｅｒ ${placeholder}`,
    ]
    for (const value of secretValues) {
      const secret = { ...event, data: { analysis: [{ message: value }] } }
      expect(ProtocolRunEventSchema.safeParse(secret).success).toBe(false)
    }
    const benignValues = [
      "Ordinary scientific prose about secretory pathways.",
      "Bearer <redacted>",
      "client_secret=<redacted>",
      "sk-short",
      `https://example.test/sk-${placeholder}`,
      "a".repeat(64),
      "018f47a0-7b9c-7abe-8def-0123456789ab",
      `error: invalid sk-${placeholder}`,
    ]
    for (const value of benignValues) {
      const benign = { ...event, data: { analysis: [{ message: value }] } }
      expect(ProtocolRunEventSchema.safeParse(benign).success).toBe(true)
    }
  })

  it("enforces strict wire values, defaults, review event, CAS, and lease expiry", () => {
    // Given: shared records at strict/default/CAS/lease boundaries.
    const event = fixture.event_window.events[0]
    const strictSequence = ProtocolRunEventSchema.safeParse({ ...event, sequence: "7" })
    const reviewEvent = ProtocolRunEventSchema.safeParse({ ...event, kind: "review.finding" })
    const plan = ActionPlanSchema.parse({
      ...fixture.action_plan,
      network_scope: undefined,
      secret_scope: undefined,
    })
    const cancel = RuntimeCancelSchema.parse({ run_id: fixture.run.id })
    const cas = ApprovalConsumeCasSchema.parse({
      approval_id: fixture.approval.id,
      expected_revision: fixture.approval.revision,
      expected_status: "approved",
      presented_binding: fixture.approval.binding,
      presented_plan: fixture.action_plan,
      occurred_at: fixture.run.updated_at,
    })
    // When/Then: strict rejection, defaults, frozen CAS, and lease expiry align.
    expect(strictSequence.success).toBe(false)
    expect(reviewEvent.success).toBe(true)
    expect(plan.network_scope).toEqual([])
    expect(plan.secret_scope).toEqual([])
    expect(cancel.reason).toBeNull()
    expect(Object.isFrozen(cas)).toBe(true)
  })

  it("rejects cross-context grants and alternate approval plans", () => {
    // Given: valid governance records mutated to another Project.
    const project_id = fixture.approval.id
    const context = {
      org_id: fixture.run.org_id,
      project_id,
      run_id: fixture.run.id,
      requester_id: fixture.run.requester_id,
    }
    const alternatePlan = { ...fixture.action_plan, project_id, plan_digest: "e".repeat(64) }

    // When: Tool Grant and Approval CAS boundaries parse the attacks.
    const grant = ToolGrantEvaluationCommandSchema.safeParse({
      grant: fixture.tool_grant,
      plan: fixture.action_plan,
      context,
    })
    const approval = ApprovalConsumeCasSchema.safeParse({
      approval_id: fixture.approval.id,
      expected_revision: fixture.approval.revision,
      expected_status: "approved",
      presented_binding: fixture.approval.binding,
      presented_plan: alternatePlan,
      occurred_at: fixture.run.updated_at,
    })

    // Then: neither cross-context authorization nor alternate plan is accepted.
    expect(grant.success).toBe(false)
    expect(approval.success).toBe(false)
  })

  it("rejects escaped forbidden keys and all foreign continuation context", () => {
    // Given: escaped semantic keys and a continuation with foreign organization context.
    const event = fixture.event_window.events[0]
    const escapedKeys = ['cost"marker', 'provider"fallback', 'fallback"provider']
    const continuation = { ...fixture.runtime_continuation, org_id: fixture.approval.id }

    // When/Then: structural key checks and full result correlation reject each attack.
    for (const key of escapedKeys) {
      expect(ProtocolRunEventSchema.safeParse({ ...event, data: { [key]: 1 } }).success).toBe(false)
    }
    expect(RuntimeContinueSchema.safeParse(continuation).success).toBe(false)
  })

  it("aligns nullable and replay defaults with Python", () => {
    // Given: shared records with every cross-language default omitted.
    const run = ProtocolRunSchema.parse({ ...fixture.run, retry_of_run_id: undefined })
    const binding = ApprovalBindingSchema.parse({
      ...fixture.approval.binding,
      network_scope: undefined,
      secret_scope: undefined,
    })

    // When/Then: Zod materializes the same defaults as Pydantic.
    expect(run.retry_of_run_id).toBeNull()
    expect(binding.network_scope).toEqual([])
    expect(binding.secret_scope).toEqual([])
    expect(ReplayBatchSchema.parse({ events: [] }).status_code).toBe(200)
    expect(ReplayExpiredSchema.parse({ run_id: fixture.run.id })).toMatchObject({
      status_code: 410,
      recovery: "GET_RUN",
    })
    expect(ReplayCursorErrorSchema.parse({})).toMatchObject({
      status_code: 409,
      code: "INVALID_LAST_EVENT_ID",
    })
  })

  it("rejects malformed Run aggregates", () => {
    // Given: valid events attacked by a foreign Run, sequence gap, or reversed time.
    const [first, second] = fixture.event_window.events
    expect(first).toBeDefined()
    expect(second).toBeDefined()
    if (first === undefined || second === undefined) return
    const attacks = [
      [first, { ...second, run_id: fixture.approval.id }],
      [first, { ...second, sequence: 3 }],
      [
        { ...first, created_at: second.created_at },
        { ...second, created_at: first.created_at },
      ],
      [
        { ...first, created_at: "2026-07-13T10:00:00.0009Z" },
        { ...second, created_at: "2026-07-13T10:00:00.0001Z" },
      ],
    ]

    // When/Then: every aggregate invariant matches Python and fails closed.
    for (const events of attacks) {
      expect(RunAggregateSchema.safeParse({ run: fixture.run, events }).success).toBe(false)
    }
    const equalMixedPrecisionEvents = [
      { ...first, created_at: "2026-07-13T10:00Z" },
      { ...second, created_at: "2026-07-13T10:00:00Z" },
    ]
    const equalTimes = { run: fixture.run, events: equalMixedPrecisionEvents }
    expect(RunAggregateSchema.safeParse(equalTimes).success).toBe(true)
  })

  it("requires a result only for completed Executions", () => {
    // Given: terminal Execution and completion-command payloads without a result.
    const completed = { ...fixture.execution, status: "completed", result_ref: null }
    const failed = { ...fixture.execution, status: "failed", result_ref: null }
    const command = {
      execution: fixture.execution,
      lease: {
        execution_id: fixture.execution.id,
        attempt_token: fixture.execution.attempt_token,
        heartbeat_at: fixture.execution.updated_at,
        expires_at: "2026-07-13T10:01:00Z",
      },
      attempt_token: fixture.execution.attempt_token,
      target: "completed",
      result_ref: null,
      occurred_at: fixture.execution.updated_at,
    }
    const fractionalExpiry = {
      ...command,
      result_ref: "artifact-version:1",
      occurred_at: "2026-07-13T10:00:01.1Z",
      lease: { ...command.lease, expires_at: "2026-07-13T10:00:01Z" },
    }
    const equalMixedPrecisionExpiry = {
      ...fractionalExpiry,
      occurred_at: "2026-07-13T10:00:01.000Z",
    }
    const equalOptionalSecondsExpiry = {
      ...fractionalExpiry,
      occurred_at: "2026-07-13T10:00Z",
      lease: { ...command.lease, expires_at: "2026-07-13T10:00:00Z" },
    }

    // When/Then: completed rejects null while failed preserves the nullable wire shape.
    expect(ExecutionSchema.safeParse(completed).success).toBe(false)
    expect(ExecutionSchema.safeParse(failed).success).toBe(true)
    expect(ExecutionCompletionCommandSchema.safeParse(command).success).toBe(false)
    expect(ExecutionCompletionCommandSchema.safeParse(fractionalExpiry).success).toBe(false)
    expect(ExecutionCompletionCommandSchema.safeParse(equalMixedPrecisionExpiry).success).toBe(
      false,
    )
    expect(ExecutionCompletionCommandSchema.safeParse(equalOptionalSecondsExpiry).success).toBe(
      false,
    )
  })
})
