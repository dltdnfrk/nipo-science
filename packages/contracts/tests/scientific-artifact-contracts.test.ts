import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"
import { z } from "zod"

import { DryLabRunContractSchema } from "../src/dry-lab-contract"
import { EVIDENCE_LEDGER_COLUMNS } from "../src/evidence-ledger"
import { ReviewerCapabilitiesSchema } from "../src/reviews-v1"
import { SkillManifestSchema } from "../src/skill-manifests"

const fixturePath = fileURLToPath(
  new URL("../fixtures/gs04-dry-lab-contract.json", import.meta.url),
)
const TOP_LEVEL_FIELDS = [
  "contract_version",
  "org_id",
  "project_id",
  "source_run_id",
  "scientific_inputs",
  "action_plan",
  "executions",
  "artifact_versions",
  "outputs",
  "analysis_scope",
  "ledger",
  "provenance",
  "review",
  "skills",
  "export",
  "completed_at",
] as const

describe("scientific artifact contract", () => {
  it("round trips the shared GS04 input to reviewed export chain", () => {
    // Given: the shared non-clinical GS04 scientific workflow fixture.
    const raw: unknown = JSON.parse(readFileSync(fixturePath, "utf8"))

    // When: Zod parses, serializes, and reparses the complete chain.
    const parsed = DryLabRunContractSchema.parse(raw)
    const reparsed = DryLabRunContractSchema.parse(JSON.parse(JSON.stringify(parsed)))

    // Then: immutable chain references and the bounded hypothesis scope survive.
    expect(reparsed).toEqual(parsed)
    expect(reparsed.analysis_scope.hypothesis_classes).toEqual([
      "molecular",
      "optical",
      "experimental_artifact",
    ])
    expect(reparsed.analysis_scope.conclusion_scope).toBe("non_diagnostic")
    expect(new Set(reparsed.export.selected_artifact_version_ids)).toEqual(
      new Set(Object.values(reparsed.outputs)),
    )
  })

  it("exposes compatible JSON Schema and required Ledger columns", () => {
    // Given: the Zod boundary schema shared with Pydantic.
    const jsonSchema = z.toJSONSchema(DryLabRunContractSchema)

    // When: its required wire fields and Ledger columns are inspected.
    const required = jsonSchema.required ?? []

    // Then: both match the canonical cross-language contract.
    expect(jsonSchema.type).toBe("object")
    expect(new Set(required)).toEqual(new Set(TOP_LEVEL_FIELDS))
    expect(EVIDENCE_LEDGER_COLUMNS).toEqual([
      "claim_id",
      "claim_text",
      "evidence_kind",
      "source_id",
      "artifact_version_id",
      "execution_id",
      "supporting_sha256",
      "locator",
      "retrieved_at",
    ])
  })

  it.each([
    [
      '"ref_id": "018f47a0-7b9c-7a10-8def-0123456789ab", "sha256": "aaaa',
      '"ref_id": "018f47a0-7b9c-7a10-8def-0123456789ab", "sha256": "baaa',
    ],
    [
      '"ref_id": "018f47a0-7b9c-7a32-8def-0123456789ab", "sha256": "3333',
      '"ref_id": "018f47a0-7b9c-7a32-8def-0123456789ab", "sha256": "4333',
    ],
    [
      '"ref_id": "literature-review@1.0.0", "sha256": "7777',
      '"ref_id": "literature-review@1.0.0", "sha256": "6777',
    ],
    ['"supporting_sha256": "bbbb', '"supporting_sha256": "abbb'],
    [
      '"runtime_adapter_id": "openai_codex",\n    "runtime_connection_id"',
      '"runtime_adapter_id": "changed",\n    "runtime_connection_id"',
    ],
  ])("rejects tampered integrity pin %s", (needle, replacement) => {
    // Given: a valid-format provenance or Ledger checksum changed after execution.
    const raw = readFileSync(fixturePath, "utf8")
    const tampered = raw.replace(needle, replacement)

    // When: the tampered payload reaches the aggregate boundary.
    const result = DryLabRunContractSchema.safeParse(JSON.parse(tampered))

    // Then: every evidence class is end-to-end bound and rejected.
    expect(result.success).toBe(false)
  })

  it("rejects mutable, duplicate, or coercive Artifact Version", () => {
    // Given: immutable/version/type invariants altered after the GS04 Run.
    const raw = readFileSync(fixturePath, "utf8")
    const mutable = raw.replace('"immutable": true', '"immutable": false')
    const duplicateRevision = raw.replace(
      '"artifact_id": "018f47a0-7b9c-7a21-8def-0123456789ab"',
      '"artifact_id": "018f47a0-7b9c-7a20-8def-0123456789ab"',
    )

    // When: each mutated payload reaches the Zod boundary.
    const immutableResult = DryLabRunContractSchema.safeParse(JSON.parse(mutable))
    const versionResult = DryLabRunContractSchema.safeParse(JSON.parse(duplicateRevision))
    const coerciveResult = DryLabRunContractSchema.safeParse(
      JSON.parse(raw.replace('"size_bytes": 128', '"size_bytes": "128"')),
    )

    // Then: neither payload crosses the immutable provenance boundary.
    expect(immutableResult.success).toBe(false)
    expect(versionResult.success).toBe(false)
    expect(coerciveResult.success).toBe(false)
  })

  it("rejects Reviewer capability, findings replay, and invalid Skill pins", () => {
    // Given: attempts to grant Reviewer execution, replay findings, or load an unknown Skill.
    const raw = readFileSync(fixturePath, "utf8")
    const capabilities = [
      "runner",
      "python",
      "bash",
      "connector",
      "network",
      "artifact_write",
      "tool_execute",
      "version_update",
      "reexecution",
    ]
    const candidates = [
      ...capabilities.map((capability) =>
        raw.replace(`"${capability}": false`, `"${capability}": true`),
      ),
      raw.replace('"exactly_once": true', '"exactly_once": false'),
      raw.replace('"id": "literature-review"', '"id": "clinical-diagnosis"'),
      raw.replace(
        '"content_sha256": "7777777777777777777777777777777777777777777777777777777777777777"',
        '"content_sha256": "not-a-sha256"',
      ),
    ]

    // When: strict Reviewer and Skill boundaries parse the candidates.
    const results = candidates.map((candidate) =>
      DryLabRunContractSchema.safeParse(JSON.parse(candidate)),
    )

    // Then: every escalation or invalid pin is rejected.
    expect(results.every((result) => !result.success)).toBe(true)
    expect(ReviewerCapabilitiesSchema.safeParse({}).success).toBe(false)
    expect(SkillManifestSchema.safeParse({}).success).toBe(false)
  })
})
