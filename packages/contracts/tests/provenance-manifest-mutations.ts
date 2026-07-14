import type { ArtifactVersionRecord } from "../src/artifact-versions"
import type { DryLabRunContractCore } from "../src/dry-lab-contract"

export const EXPECTED_PROVENANCE_DIGEST =
  "23574897dc448a252838e01001c18eea5c87414e073f476d2cdc4bc518d5c157"
const TAMPER_HASH = "0".repeat(64)
const INPUT_ID = "018f47a0-7b9c-7a10-8def-0123456789ab"
const EXECUTION_ID = "018f47a0-7b9c-7a32-8def-0123456789ab"
const SKILL_REF = "literature-review@1.0.0"
export const PROVENANCE_MUTATION_TARGETS = [
  "code",
  "environment",
  "source",
  "input",
  "execution",
  "skill",
  "runtime",
  "output",
] as const
type MutationTarget = (typeof PROVENANCE_MUTATION_TARGETS)[number]

function updateOutputs(
  contract: DryLabRunContractCore,
  update: (version: ArtifactVersionRecord) => ArtifactVersionRecord,
): readonly ArtifactVersionRecord[] {
  const outputIds = new Set(Object.values(contract.outputs))
  return contract.artifact_versions.map((version) =>
    outputIds.has(version.id) ? update(version) : version,
  )
}

export function coordinatedProvenanceMutation(
  contract: DryLabRunContractCore,
  target: MutationTarget,
): DryLabRunContractCore {
  switch (target) {
    case "code":
      return {
        ...contract,
        artifact_versions: updateOutputs(contract, (version) => ({
          ...version,
          code_sha256: TAMPER_HASH,
        })),
        provenance: { ...contract.provenance, code_sha256: TAMPER_HASH },
      }
    case "environment":
      return {
        ...contract,
        artifact_versions: updateOutputs(contract, (version) => ({
          ...version,
          environment_sha256: TAMPER_HASH,
        })),
        provenance: { ...contract.provenance, environment_sha256: TAMPER_HASH },
      }
    case "source":
      return {
        ...contract,
        artifact_versions: updateOutputs(contract, (version) => ({
          ...version,
          source_hashes: [TAMPER_HASH],
        })),
        provenance: {
          ...contract.provenance,
          source_hashes: [{ ref_id: "source:tampered", sha256: TAMPER_HASH }],
        },
      }
    case "input":
      return {
        ...contract,
        artifact_versions: contract.artifact_versions.map((version) =>
          version.id === INPUT_ID ? { ...version, content_sha256: TAMPER_HASH } : version,
        ),
        provenance: {
          ...contract.provenance,
          input_hashes: contract.provenance.input_hashes.map((pin) =>
            pin.ref_id === INPUT_ID ? { ...pin, sha256: TAMPER_HASH } : pin,
          ),
        },
      }
    case "execution":
      return {
        ...contract,
        executions: contract.executions.map((execution) =>
          execution.execution_id === EXECUTION_ID
            ? { ...execution, execution_sha256: TAMPER_HASH }
            : execution,
        ),
        provenance: {
          ...contract.provenance,
          execution_hashes: contract.provenance.execution_hashes.map((pin) =>
            pin.ref_id === EXECUTION_ID ? { ...pin, sha256: TAMPER_HASH } : pin,
          ),
        },
      }
    case "skill":
      return {
        ...contract,
        artifact_versions: updateOutputs(contract, (version) => ({
          ...version,
          skill_content_hashes: version.skill_content_hashes.map((hash) =>
            hash === "7".repeat(64) ? TAMPER_HASH : hash,
          ),
        })),
        skills: contract.skills.map((skill) =>
          skill.id === "literature-review" ? { ...skill, content_sha256: TAMPER_HASH } : skill,
        ),
        provenance: {
          ...contract.provenance,
          skill_hashes: contract.provenance.skill_hashes.map((pin) =>
            pin.ref_id === SKILL_REF ? { ...pin, sha256: TAMPER_HASH } : pin,
          ),
        },
      }
    case "runtime":
      return {
        ...contract,
        artifact_versions: updateOutputs(contract, (version) => ({
          ...version,
          runtime_adapter_id: "tampered_adapter",
        })),
        provenance: { ...contract.provenance, runtime_adapter_id: "tampered_adapter" },
      }
    case "output": {
      const outputId = contract.outputs.normalized_csv_version_id
      return {
        ...contract,
        artifact_versions: contract.artifact_versions.map((version) =>
          version.id === outputId ? { ...version, content_sha256: TAMPER_HASH } : version,
        ),
        ledger: {
          ...contract.ledger,
          rows: contract.ledger.rows.map((row) =>
            row.artifact_version_id === outputId ? { ...row, supporting_sha256: TAMPER_HASH } : row,
          ),
        },
        provenance: {
          ...contract.provenance,
          output_hashes: contract.provenance.output_hashes.map((pin) =>
            pin.ref_id === outputId ? { ...pin, sha256: TAMPER_HASH } : pin,
          ),
        },
        export: {
          ...contract.export,
          artifact_entries: contract.export.artifact_entries.map((entry) =>
            entry.artifact_version_id === outputId ? { ...entry, sha256: TAMPER_HASH } : entry,
          ),
        },
      }
    }
  }
}
