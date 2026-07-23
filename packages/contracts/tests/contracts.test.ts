import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

import { ProjectCreateSchema } from "../src/auth"
import { ContractRoundTripSchema } from "../src/fixtures"
import { OpenApiDocumentSchema } from "../src/openapi"
import { ResearchIntentSchema, RunCreateSchema, researchIntentSha256 } from "../src/runs"

const fixturePath = fileURLToPath(new URL("../fixtures/auth-run-artifact.json", import.meta.url))
const openApiPath = fileURLToPath(new URL("../openapi/openapi.json", import.meta.url))

describe("shared contracts", () => {
  it("round trips auth to Run to Artifact when parsing the shared JSON fixture", () => {
    // Given: representative JSON shared with the Python Pydantic suite.
    const raw: unknown = JSON.parse(readFileSync(fixturePath, "utf8"))

    // When: Zod parses, serializes, and reparses the external payload.
    const parsed = ContractRoundTripSchema.parse(raw)
    const reparsed = ContractRoundTripSchema.parse(JSON.parse(JSON.stringify(parsed)))

    // Then: tenant and provenance relationships survive the round trip.
    expect(reparsed).toEqual(parsed)
    expect(reparsed.run.org_id).toBe(reparsed.auth.org_id)
    expect(reparsed.artifact_version.producing_run_id).toBe(reparsed.run.id)
  })

  it("parses the OpenAPI document and exposes matching runtime components", () => {
    // Given: the checked-in OpenAPI JSON boundary.
    const raw: unknown = JSON.parse(readFileSync(openApiPath, "utf8"))

    // When: the TypeScript OpenAPI boundary schema parses it.
    const parsed = OpenApiDocumentSchema.parse(raw)

    // Then: the representative runtime components and tenant rule are present.
    expect(parsed["x-tenancy"].cross_tenant_status).toBe(404)
    expect(parsed.components.schemas).toHaveProperty("AuthContext")
    expect(parsed.components.schemas).toHaveProperty("Run")
    expect(parsed.components.schemas).toHaveProperty("ArtifactVersion")
    expect(parsed.components.schemas).toHaveProperty("ArtifactVersionRecord")
    expect(parsed.components.schemas).toHaveProperty("PersistedReview")
    expect(parsed.components.schemas).toHaveProperty("ReviewFinding")
    expect(parsed.components.schemas).toHaveProperty("ExportManifest")
    const serialized = JSON.stringify(raw)
    expect(serialized).toContain("#/components/schemas/ArtifactVersionRecord")
    expect(serialized).toContain("#/components/schemas/PersistedReview")
    expect(serialized).toContain("#/components/schemas/ReviewFinding")
    expect(serialized).toContain("#/components/schemas/ExportManifest")
  })

  it("rejects client supplied tenant authority", () => {
    // Given: creation payloads with forged org_id authority.
    const project = { name: "forged", org_id: "018f47a0-7b9c-7abd-8def-0123456789ab" }
    const run = {
      execution_mode: "local_dry_lab",
      session_id: "018f47a0-7b9c-7abf-8def-0123456789ab",
      prompt: "forged",
      input: {
        filename: "calibrated.csv",
        media_type: "text/csv",
        content: "sample,value,calibration\nA,1.0,c1\n",
      },
      research_intent: {
        question: "검증할 수 있는가?",
        rationale: "재현성을 확인한다.",
        intended_benefit: "검증 가능한 기준선을 만든다.",
        success_criteria: ["체크섬이 일치한다."],
        constraints: ["비임상 연구만 수행한다."],
        stop_conditions: ["증거가 없으면 중단한다."],
        research_mode: "copilot",
        data_origin: "observed",
      },
      org_id: "018f47a0-7b9c-7abd-8def-0123456789ab",
    }

    // When: each strict request boundary attempts to parse it.
    const projectResult = ProjectCreateSchema.safeParse(project)
    const runResult = RunCreateSchema.safeParse(run)

    // Then: neither boundary accepts client tenant authority.
    expect(projectResult.success).toBe(false)
    expect(runResult.success).toBe(false)
  })

  it("requires a complete human-owned research intent for every Run", () => {
    const run = {
      execution_mode: "local_dry_lab",
      session_id: "018f47a0-7b9c-7abf-8def-0123456789ab",
      prompt: "분석한다",
      input: {
        filename: "calibrated.csv",
        media_type: "text/csv",
        content: "sample,value,calibration\nA,1.0,c1\n",
      },
    }

    expect(RunCreateSchema.safeParse(run).success).toBe(false)
  })

  it.each([
    { question: "x".repeat(2_001) },
    { question: " " },
    { question: "\u0085boundary" },
    { question: "\ufeffboundary" },
    { question: "invalid\ud800" },
    { constraints: ["invalid\udfff"] },
    { success_criteria: ["same", "same"] },
    { success_criteria: ["same", " same "] },
    { constraints: ["가".repeat(501)] },
  ])("rejects oversized or duplicate ResearchIntent values", (update) => {
    const intent = {
      question: "검증할 수 있는가?",
      rationale: "재현성을 확인한다.",
      intended_benefit: "검증 가능한 기준선을 만든다.",
      success_criteria: ["체크섬이 일치한다."],
      constraints: ["비임상 연구만 수행한다."],
      stop_conditions: ["증거가 없으면 중단한다."],
      research_mode: "copilot",
      data_origin: "observed",
      ...update,
    }
    const run = {
      execution_mode: "local_dry_lab",
      session_id: "018f47a0-7b9c-7abf-8def-0123456789ab",
      prompt: "분석한다",
      research_intent: intent,
      input: {
        filename: "calibrated.csv",
        media_type: "text/csv",
        content: "sample,value,calibration\nA,1.0,c1\n",
      },
    }

    expect(RunCreateSchema.safeParse(run).success).toBe(false)
  })

  it("uses OpenAPI character limits for multibyte ResearchIntent text", () => {
    const intent = {
      question: "검증할 수 있는가?",
      rationale: "재현성을 확인한다.",
      intended_benefit: "검증 가능한 기준선을 만든다.",
      success_criteria: ["체크섬이 일치한다."],
      constraints: ["가".repeat(500)],
      stop_conditions: ["증거가 없으면 중단한다."],
      research_mode: "copilot",
      data_origin: "observed",
    }

    expect(
      RunCreateSchema.safeParse({
        execution_mode: "local_dry_lab",
        session_id: "018f47a0-7b9c-7abf-8def-0123456789ab",
        prompt: "분석한다",
        research_intent: intent,
        input: {
          filename: "calibrated.csv",
          media_type: "text/csv",
          content: "sample,value,calibration\nA,1.0,c1\n",
        },
      }).success,
    ).toBe(true)
  })

  it("requires the same complete intent input for local and provider execution", () => {
    const local = {
      execution_mode: "local_dry_lab",
      session_id: "018f47a0-7b9c-7abf-8def-0123456789ab",
      prompt: "분석한다",
      research_intent: {
        question: "검증할 수 있는가?",
        rationale: "재현성을 확인한다.",
        intended_benefit: "검증 가능한 기준선을 만든다.",
        success_criteria: ["체크섬이 일치한다."],
        constraints: ["비임상 연구만 수행한다."],
        stop_conditions: ["증거가 없으면 중단한다."],
        research_mode: "copilot",
        data_origin: "observed",
      },
      input: {
        filename: "calibrated.csv",
        media_type: "text/csv",
        content: "sample,value,calibration\nA,1.0,c1\n",
      },
    }

    expect(RunCreateSchema.safeParse(local).success).toBe(true)
    expect(
      RunCreateSchema.safeParse({
        ...local,
        provider_connection_id: "018f47a0-7b9c-7ac0-8def-0123456789ab",
      }).success,
    ).toBe(false)
    expect(
      RunCreateSchema.safeParse({
        ...local,
        execution_mode: "provider_model",
        connection_id: "018f47a0-7b9c-7ac0-8def-0123456789ab",
        model_id: "codex-mini",
      }).success,
    ).toBe(true)
    expect(
      RunCreateSchema.safeParse({
        execution_mode: "provider_model",
        session_id: local.session_id,
        connection_id: "018f47a0-7b9c-7ac0-8def-0123456789ab",
        model_id: "codex-mini",
      }).success,
    ).toBe(false)
  })

  it("uses the shared unescaped UTF-8 canonical ResearchIntent digest", () => {
    const intent = ResearchIntentSchema.parse({
      question: "보정된 관측값을 재현 가능하게 정규화할 수 있는가?",
      rationale: "반복 분석에서 입력 순서가 결과를 바꾸지 않도록 확인한다.",
      intended_benefit: "검증 가능한 정규화 기준선을 만든다.",
      success_criteria: ["동일 입력은 동일 체크섬을 만든다."],
      constraints: ["비임상 연구 데이터만 사용한다."],
      stop_conditions: ["보정 메타데이터가 없으면 중단한다."],
      research_mode: "bounded_agentic",
      data_origin: "observed",
    })

    expect(researchIntentSha256(intent)).toBe(
      "60d80404ffbcbf2a738a9e2874376e5b951fc9c506ccfe4329ade98190580fb7",
    )
    expect(intent.synthetic_generator_ref).toBeNull()
    expect(intent.synthetic_validator_ref).toBeNull()
  })

  it("deep-freezes ResearchIntent collections bound to the approval digest", () => {
    const intent = ResearchIntentSchema.parse({
      question: "어떤 분석이 재현 가능한가?",
      rationale: "검증 가능한 근거가 필요하다.",
      intended_benefit: "재현 가능한 결론을 만든다.",
      success_criteria: ["체크섬이 일치한다."],
      constraints: ["비임상 연구만 수행한다."],
      stop_conditions: ["증거가 없으면 중단한다."],
      research_mode: "copilot",
      data_origin: "observed",
    })
    const digest = researchIntentSha256(intent)

    expect(Object.isFrozen(intent.success_criteria)).toBe(true)
    expect(Reflect.set(intent.success_criteria, 0, "검증 후 변경")).toBe(false)
    expect(researchIntentSha256(intent)).toBe(digest)
  })

  it("rejects NFC-normalization-colliding ResearchIntent items", () => {
    expect(
      ResearchIntentSchema.safeParse({
        question: "검증할 수 있는가?",
        rationale: "재현성을 확인한다.",
        intended_benefit: "검증 가능한 기준선을 만든다.",
        success_criteria: ["é", "e\u0301"],
        constraints: ["비임상 연구만 수행한다."],
        stop_conditions: ["증거가 없으면 중단한다."],
        research_mode: "copilot",
        data_origin: "observed",
      }).success,
    ).toBe(false)
  })
})
