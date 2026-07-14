import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

import {
  ArtifactAttachmentCommandSchema,
  ArtifactAttachmentStateSchema,
  ArtifactVersionCreateCommandSchema,
  ArtifactVersionRecordSchema,
  applyArtifactAttachmentCas,
  createArtifactVersionCas,
} from "../src/artifact-versions"
import { DryLabRunContractSchema } from "../src/dry-lab-contract"

const fixturePath = fileURLToPath(
  new URL("../fixtures/gs04-dry-lab-contract.json", import.meta.url),
)
const ARTIFACT_ID = "018f47a0-7b9c-7a20-8def-0123456789ab"
const ORG_ID = "018f47a0-7b9c-7a01-8def-0123456789ab"
const PROJECT_ID = "018f47a0-7b9c-7a03-8def-0123456789ab"
const VERSION_ONE = "018f47a0-7b9c-7a10-8def-0123456789ab"
const VERSION_TWO = "018f47a0-7b9c-7a11-8def-0123456789ab"

describe("Artifact CAS and Export safety", () => {
  it("applies attach and detach with compare and swap", () => {
    // Given: an immutable attachment state at revision one.
    const state = ArtifactAttachmentStateSchema.parse({
      artifact_id: ARTIFACT_ID,
      org_id: ORG_ID,
      project_id: PROJECT_ID,
      revision: 1,
      version_ids: [VERSION_ONE],
    })
    const attach = ArtifactAttachmentCommandSchema.parse({
      operation: "attach",
      base_revision: 1,
      version_id: VERSION_TWO,
      version_org_id: ORG_ID,
      version_project_id: PROJECT_ID,
      version_artifact_id: ARTIFACT_ID,
    })

    // When: the current revision attaches and then detaches a Version.
    const attached = applyArtifactAttachmentCas(state, attach)
    if (!attached.ok) throw new Error(`unexpected CAS rejection: ${attached.reason}`)
    const detach = ArtifactAttachmentCommandSchema.parse({
      operation: "detach",
      base_revision: 2,
      version_id: VERSION_ONE,
    })
    const detached = applyArtifactAttachmentCas(attached.state, detach)

    // Then: each operation creates a new revision without mutating prior state.
    expect(detached.ok).toBe(true)
    expect(state).toEqual({
      artifact_id: ARTIFACT_ID,
      org_id: ORG_ID,
      project_id: PROJECT_ID,
      revision: 1,
      version_ids: [VERSION_ONE],
    })
    if (!detached.ok) throw new Error(`unexpected CAS rejection: ${detached.reason}`)
    expect(detached.state).toEqual({
      artifact_id: ARTIFACT_ID,
      org_id: ORG_ID,
      project_id: PROJECT_ID,
      revision: 3,
      version_ids: [VERSION_TWO],
    })
  })

  it("rejects stale compare and swap without state change", () => {
    // Given: a revision-two state and stale revision-one attach command.
    const state = ArtifactAttachmentStateSchema.parse({
      artifact_id: ARTIFACT_ID,
      org_id: ORG_ID,
      project_id: PROJECT_ID,
      revision: 2,
      version_ids: [VERSION_ONE],
    })
    const command = ArtifactAttachmentCommandSchema.parse({
      operation: "attach",
      base_revision: 1,
      version_id: VERSION_TWO,
      version_org_id: ORG_ID,
      version_project_id: PROJECT_ID,
      version_artifact_id: ARTIFACT_ID,
    })

    // When: compare-and-swap evaluates the stale command.
    const result = applyArtifactAttachmentCas(state, command)

    // Then: it returns a typed conflict and preserves the attachment state.
    expect(result).toEqual({ ok: false, reason: "stale_revision" })
    expect(state).toEqual({
      artifact_id: ARTIFACT_ID,
      org_id: ORG_ID,
      project_id: PROJECT_ID,
      revision: 2,
      version_ids: [VERSION_ONE],
    })
  })

  it("rejects duplicate attachment and invalid attach/detach targets", () => {
    // Given: duplicate state plus commands for an existing and an absent Version.
    const duplicate = ArtifactAttachmentStateSchema.safeParse({
      artifact_id: ARTIFACT_ID,
      org_id: ORG_ID,
      project_id: PROJECT_ID,
      revision: 1,
      version_ids: [VERSION_ONE, VERSION_ONE],
    })
    const state = ArtifactAttachmentStateSchema.parse({
      artifact_id: ARTIFACT_ID,
      org_id: ORG_ID,
      project_id: PROJECT_ID,
      revision: 1,
      version_ids: [VERSION_ONE],
    })

    // When: attach and detach target invalid state.
    const attached = applyArtifactAttachmentCas(
      state,
      ArtifactAttachmentCommandSchema.parse({
        operation: "attach",
        base_revision: 1,
        version_id: VERSION_ONE,
        version_org_id: ORG_ID,
        version_project_id: PROJECT_ID,
        version_artifact_id: ARTIFACT_ID,
      }),
    )
    const detached = applyArtifactAttachmentCas(
      state,
      ArtifactAttachmentCommandSchema.parse({
        operation: "detach",
        base_revision: 1,
        version_id: VERSION_TWO,
      }),
    )
    const crossTenant = applyArtifactAttachmentCas(
      state,
      ArtifactAttachmentCommandSchema.parse({
        operation: "attach",
        base_revision: 1,
        version_id: VERSION_TWO,
        version_org_id: VERSION_TWO,
        version_project_id: PROJECT_ID,
        version_artifact_id: ARTIFACT_ID,
      }),
    )

    // Then: all invalid operations reject without mutation.
    expect(duplicate.success).toBe(false)
    expect(attached).toEqual({ ok: false, reason: "already_attached" })
    expect(detached).toEqual({ ok: false, reason: "not_attached" })
    expect(crossTenant).toEqual({ ok: false, reason: "context_mismatch" })
  })

  it("creates monotonic Artifact Version and rejects stale base", () => {
    // Given: immutable Version 1 and a same-Artifact Version 2 successor.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const current = contract.artifact_versions[0]
    const template = contract.artifact_versions[1]
    if (current === undefined || template === undefined) throw new Error("fixture versions missing")
    const successor = { ...current, id: template.id, version: 2, content_sha256: "b".repeat(64) }
    const command = ArtifactVersionCreateCommandSchema.parse({
      base_version_id: current.id,
      next_version: successor,
    })

    // When: current and stale bases attempt CAS creation.
    const created = createArtifactVersionCas(current, command)
    const stale = createArtifactVersionCas(current, { ...command, base_version_id: template.id })

    // Then: V1 remains immutable, V2 is monotonic, and stale base rejects.
    expect(created.ok).toBe(true)
    expect(current.content_sha256).toBe("a".repeat(64))
    expect(stale).toEqual({ ok: false, reason: "stale_base" })
  })

  it("rejects cross-org, same-ID, and backdated successor", () => {
    // Given: successor candidates change tenant, reuse ID, or predate Version 1.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const current = contract.artifact_versions[0]
    const template = contract.artifact_versions[1]
    if (current === undefined || template === undefined) throw new Error("fixture versions missing")
    const valid = { ...current, id: template.id, version: 2 }
    const candidates = [
      ArtifactVersionRecordSchema.parse({ ...valid, org_id: template.runtime_connection_id }),
      ArtifactVersionRecordSchema.parse({ ...valid, id: current.id }),
      ArtifactVersionRecordSchema.parse({ ...valid, created_at: "2026-07-13T09:59:59Z" }),
    ]

    // When: CAS evaluates each invalid successor.
    const results = candidates.map((next_version) =>
      createArtifactVersionCas(current, { base_version_id: current.id, next_version }),
    )

    // Then: tenant, identity, and timestamp monotonicity all fail closed.
    expect(results.every((result) => !result.ok && result.reason === "invalid_successor")).toBe(
      true,
    )
  })
})
