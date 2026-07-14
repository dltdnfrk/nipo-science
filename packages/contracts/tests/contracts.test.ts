import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

import { ProjectCreateSchema } from "../src/auth"
import { ContractRoundTripSchema } from "../src/fixtures"
import { OpenApiDocumentSchema } from "../src/openapi"
import { RunCreateSchema } from "../src/runs"

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
      session_id: "018f47a0-7b9c-7abf-8def-0123456789ab",
      provider_connection_id: "018f47a0-7b9c-7ac0-8def-0123456789ab",
      prompt: "forged",
      org_id: "018f47a0-7b9c-7abd-8def-0123456789ab",
    }

    // When: each strict request boundary attempts to parse it.
    const projectResult = ProjectCreateSchema.safeParse(project)
    const runResult = RunCreateSchema.safeParse(run)

    // Then: neither boundary accepts client tenant authority.
    expect(projectResult.success).toBe(false)
    expect(runResult.success).toBe(false)
  })
})
