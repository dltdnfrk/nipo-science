import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

import { DryLabRunContractSchema } from "../src/dry-lab-contract"
import { provenanceManifestSha256 } from "../src/provenance"
import {
  coordinatedProvenanceMutation,
  EXPECTED_PROVENANCE_DIGEST,
  PROVENANCE_MUTATION_TARGETS,
} from "./provenance-manifest-mutations"

const fixturePath = fileURLToPath(
  new URL("../fixtures/gs04-dry-lab-contract.json", import.meta.url),
)

function mutateFirstOutput(raw: string, needle: string, replacement: string): string {
  const marker = '"id": "018f47a0-7b9c-7a11-8def-0123456789ab"'
  const markerIndex = raw.indexOf(marker)
  if (markerIndex < 0) throw new Error("fixture output marker missing")
  const outputIndex = markerIndex + marker.length
  return raw.slice(0, outputIndex) + raw.slice(outputIndex).replace(needle, replacement)
}

describe("DryLab integrity attacks", () => {
  it("matches the shared Python and TypeScript canonical provenance digest", () => {
    // Given: the shared valid GS04 provenance manifest.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))

    // When: TypeScript canonicalizes and hashes the complete payload.
    const digest = provenanceManifestSha256(contract.provenance)

    // Then: it matches the shared fixture value also asserted by Python.
    expect(digest).toBe(EXPECTED_PROVENANCE_DIGEST)
    expect(contract.provenance.manifest_sha256).toBe(EXPECTED_PROVENANCE_DIGEST)
    expect(provenanceManifestSha256({ ...contract.provenance, runtime_adapter_id: "한글😀" })).toBe(
      "ad225bd977785536450bffe5a25e67b37814074467f15835820787e0a76779be",
    )
  })

  it.each(
    PROVENANCE_MUTATION_TARGETS,
  )("rejects coordinated %s mutation with stale digest", (target) => {
    // Given: every ordinary cross-reference agrees on one coordinated mutation.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const mutated = coordinatedProvenanceMutation(contract, target)

    // When: its stale provenance digest reaches the parsing boundary.
    const result = DryLabRunContractSchema.safeParse(mutated)

    // Then: manifest self-verification rejects the altered payload.
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues.map((issue) => issue.message)).toContain(
        "provenance manifest digest mismatch",
      )
    }
  })

  it.each(
    PROVENANCE_MUTATION_TARGETS,
  )("rejects rehashed coordinated %s mutation at Review pin", (target) => {
    // Given: the attacker recomputes the digest after a coordinated mutation.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const mutated = coordinatedProvenanceMutation(contract, target)
    const rehashed = {
      ...mutated,
      provenance: {
        ...mutated.provenance,
        manifest_sha256: provenanceManifestSha256(mutated.provenance),
      },
    }

    // When: the rehashed payload reaches the immutable Review boundary.
    const result = DryLabRunContractSchema.safeParse(rehashed)

    // Then: the unchanged Review input pin rejects the new manifest.
    expect(result.success).toBe(false)
    if (!result.success) {
      expect(result.error.issues.map((issue) => issue.message)).toContain(
        "Run, ActionPlan, and Review digest pins do not match provenance",
      )
    }
  })

  it.each([
    ['"input_version_ids": ["018f47a0-7b9c-7a10-8def-0123456789ab"]', '"input_version_ids": []'],
    [
      '"skill_content_hashes": ["7777777777777777777777777777777777777777777777777777777777777777", "8888888888888888888888888888888888888888888888888888888888888888", "9999999999999999999999999999999999999999999999999999999999999999"]',
      '"skill_content_hashes": []',
    ],
    [
      '"source_hashes": []',
      '"source_hashes": ["6666666666666666666666666666666666666666666666666666666666666666"]',
    ],
    [
      '"input_version_ids": ["018f47a0-7b9c-7a10-8def-0123456789ab"]',
      '"input_version_ids": ["018f47a0-7b9c-7a11-8def-0123456789ab"]',
    ],
  ])("rejects incomplete or extra exact provenance set %s", (needle, replacement) => {
    // Given: a derived output with an incomplete or extra provenance set.
    const raw = readFileSync(fixturePath, "utf8")

    // When: the exact-set mutation reaches the aggregate boundary.
    const result = DryLabRunContractSchema.safeParse(
      JSON.parse(mutateFirstOutput(raw, needle, replacement)),
    )

    // Then: the payload fails closed.
    expect(result.success).toBe(false)
  })

  it("rejects duplicate provenance ref IDs", () => {
    // Given: an input content pin duplicated before its calibration pin.
    const raw = readFileSync(fixturePath, "utf8")
    const pin =
      '{"ref_id": "018f47a0-7b9c-7a10-8def-0123456789ab", "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}'
    const duplicate = raw.replace(pin, `${pin},\n      ${pin}`)

    // When: duplicate ref IDs cross the manifest boundary.
    const result = DryLabRunContractSchema.safeParse(JSON.parse(duplicate))

    // Then: Map collapse cannot hide the duplicate.
    expect(result.success).toBe(false)
  })

  it("rejects unreviewed extra Export and aliased required output", () => {
    // Given: an input Version added to Export, or Ledger CSV aliased to normalized CSV.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const raw = JSON.stringify(contract)
    const extraEntry = `"artifact_entries":[{"path":"artifacts/input.csv","artifact_version_id":"${contract.scientific_inputs[0]?.artifact_version_id}","sha256":"${"a".repeat(64)}","media_type":"text/csv","entry_kind":"file"},`
    const unreviewed = raw
      .replace(
        '"selected_artifact_version_ids":[',
        `"selected_artifact_version_ids":["${contract.scientific_inputs[0]?.artifact_version_id}",`,
      )
      .replace('"artifact_entries":[', extraEntry)
    const aliased = raw.replace(
      `"ledger_csv_version_id":"${contract.outputs.ledger_csv_version_id}"`,
      `"ledger_csv_version_id":"${contract.outputs.normalized_csv_version_id}"`,
    )

    // When: coordinated selection and output aliasing reach the aggregate boundary.
    const unreviewedResult = DryLabRunContractSchema.safeParse(JSON.parse(unreviewed))
    const aliasResult = DryLabRunContractSchema.safeParse(JSON.parse(aliased))

    // Then: only distinct Review-pinned outputs may be exported.
    expect(unreviewedResult.success).toBe(false)
    expect(aliasResult.success).toBe(false)
  })

  it("rejects an unapproved Review execution pin", () => {
    // Given: Review pins an unrelated Execution in addition to the approved one.
    const raw = readFileSync(fixturePath, "utf8")
    const mutated = raw.replace(
      '"pinned_execution_ids": ["018f47a0-7b9c-7a32-8def-0123456789ab"]',
      '"pinned_execution_ids": ["018f47a0-7b9c-7a32-8def-0123456789ab", "018f47a0-7b9c-7aff-8def-0123456789ab"]',
    )

    // When: the expanded Review pin set reaches the aggregate boundary.
    const result = DryLabRunContractSchema.safeParse(JSON.parse(mutated))

    // Then: Review execution pins must exactly equal approved Executions.
    expect(result.success).toBe(false)
  })

  it("rejects duplicate aggregate members and unrelated provenance pins", () => {
    // Given: duplicate aggregate identities padded with unrelated pins.
    const raw = readFileSync(fixturePath, "utf8")
    const input = raw.match(
      / {4}\{\n {6}"artifact_version_id": "018f47a0-7b9c-7a10-8def-0123456789ab"[\s\S]*?\n {4}\}/,
    )?.[0]
    const execution = raw.match(
      / {4}\{\n {6}"execution_id": "018f47a0-7b9c-7a32-8def-0123456789ab"[\s\S]*?\n {4}\}/,
    )?.[0]
    if (input === undefined || execution === undefined) throw new Error("fixture member missing")
    const duplicateInput = raw
      .replace(input, `${input},\n${input}`)
      .replace(
        '"input_hashes": [',
        `"input_hashes": [{"ref_id":"${"0".repeat(64)}","sha256":"${"1".repeat(64)}"},{"ref_id":"calibration:${"0".repeat(64)}","sha256":"${"2".repeat(64)}"},`,
      )
    const duplicateExecution = raw
      .replace(execution, `${execution},\n${execution}`)
      .replace(
        '"execution_hashes": [',
        `"execution_hashes": [{"ref_id":"018f47a0-7b9c-7aff-8def-0123456789ab","sha256":"${"3".repeat(64)}"},`,
      )
    const duplicateReviewPin = raw.replace(
      '"pinned_artifact_version_ids": [',
      '"pinned_artifact_version_ids": ["018f47a0-7b9c-7a11-8def-0123456789ab",',
    )

    // When: each coordinated mutation reaches the aggregate boundary.
    const results = [duplicateInput, duplicateExecution, duplicateReviewPin].map((value) =>
      DryLabRunContractSchema.safeParse(JSON.parse(value)),
    )

    // Then: uniqueness and exact expected reference sets fail closed.
    expect(results.every((result) => !result.success)).toBe(true)
  })

  it.each([
    [
      '"org_id": "018f47a0-7b9c-7a01-8def-0123456789ab"',
      '"org_id": "018f47a0-7b9c-7aff-8def-0123456789ab"',
    ],
    [
      '"project_id": "018f47a0-7b9c-7a03-8def-0123456789ab"',
      '"project_id": "018f47a0-7b9c-7aff-8def-0123456789ab"',
    ],
  ])("rejects output tenant binding mutation %s", (needle, replacement) => {
    const raw = readFileSync(fixturePath, "utf8")
    const result = DryLabRunContractSchema.safeParse(
      JSON.parse(mutateFirstOutput(raw, needle, replacement)),
    )
    expect(result.success).toBe(false)
  })

  it("rejects a Review execution Run that aliases its source Run", () => {
    const raw = readFileSync(fixturePath, "utf8")
    const mutated = raw.replace(
      '"run_id": "018f47a0-7b9c-7a41-8def-0123456789ab"',
      '"run_id": "018f47a0-7b9c-7a02-8def-0123456789ab"',
    )
    expect(DryLabRunContractSchema.safeParse(JSON.parse(mutated)).success).toBe(false)
  })
})
