import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

import { DryLabRunContractSchema } from "../src/dry-lab-contract"
import { ExportManifestSchema } from "../src/export-manifest"

const fixturePath = fileURLToPath(
  new URL("../fixtures/gs04-dry-lab-contract.json", import.meta.url),
)
const VERSION_TWO = "018f47a0-7b9c-7a11-8def-0123456789ab"

describe("Export manifest attacks", () => {
  it.each([
    ['"path":"artifacts/normalized.csv"', '"path":"../escape"'],
    ['"path":"artifacts/normalized.csv"', '"path":"/absolute.csv"'],
    ['"entry_kind":"file"', '"entry_kind":"symlink"'],
    ['"path":"artifacts/normalized.csv"', '"path":"manifest.json"'],
    ['"path":"artifacts/normalized.csv"', '"path":"manifest.json/evil"'],
    ['"path":"artifacts/normalized.csv"', '"path":"provenance"'],
    ['"path":"artifacts/normalized.csv"', '"path":"review"'],
    ['"path":"artifacts/normalized.csv"', '"path":"CON.txt"'],
    ['"path":"artifacts/normalized.csv"', '"path":"manifest.json."'],
    ['"path":"artifacts/figure.png"', '"path":"artifacts/normalized.csv/child"'],
  ])("rejects unsafe Export mutation %s", (needle, replacement) => {
    // Given: a valid Export with one unsafe path or link mutation.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const rawExport = JSON.stringify(contract.export).replace(needle, replacement)

    // When: the mutated Export reaches the boundary.
    const result = ExportManifestSchema.safeParse(JSON.parse(rawExport))

    // Then: unsafe content is rejected before pack construction.
    expect(result.success).toBe(false)
  })

  it("rejects normalized collision and unselected-latest race", () => {
    // Given: a selected manifest changed to collide or resolve an unselected latest Version.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const rawExport = JSON.stringify(contract.export)
    const collision = rawExport.replace("artifacts/figure.png", "ARTIFACTS/normalized.csv")
    const rogueVersionId = "018f47a0-7b9c-7aff-8def-0123456789ab"
    const unselected = {
      ...contract,
      export: {
        ...contract.export,
        selected_artifact_version_ids: contract.export.selected_artifact_version_ids.map(
          (versionId) => (versionId === VERSION_TWO ? rogueVersionId : versionId),
        ),
        artifact_entries: contract.export.artifact_entries.map((entry) =>
          entry.artifact_version_id === VERSION_TWO
            ? { ...entry, artifact_version_id: rogueVersionId }
            : entry,
        ),
      },
    }
    const unicodeCollision = rawExport
      .replace("artifacts/normalized.csv", "artifacts/Straße.csv")
      .replace("artifacts/figure.png", "ARTIFACTS/STRASSE.CSV")

    // When: each race-prone manifest reaches the boundary.
    const collisionResult = ExportManifestSchema.safeParse(JSON.parse(collision))
    const unselectedResult = DryLabRunContractSchema.safeParse(unselected)
    const unicodeResult = ExportManifestSchema.safeParse(JSON.parse(unicodeCollision))

    // Then: both fail closed.
    expect(collisionResult.success).toBe(false)
    expect(unselectedResult.success).toBe(false)
    expect(unicodeResult.success).toBe(false)
  })
})
