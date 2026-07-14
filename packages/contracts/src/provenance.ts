import { createHash } from "node:crypto"

import { z } from "zod"

import { NonEmptyTextSchema, Sha256Schema, Uuid7Schema } from "./common"

export const HashPinSchema = z
  .strictObject({ ref_id: NonEmptyTextSchema, sha256: Sha256Schema })
  .readonly()

type HashPin = z.infer<typeof HashPinSchema>

function canonicalPins(pins: readonly HashPin[]): readonly HashPin[] {
  return pins.map((pin) => ({ ref_id: pin.ref_id, sha256: pin.sha256 }))
}

const PROVENANCE_MANIFEST_FIELDS = {
  source_run_id: Uuid7Schema,
  action_plan_sha256: Sha256Schema,
  code_sha256: Sha256Schema,
  environment_sha256: Sha256Schema,
  runtime_adapter_id: NonEmptyTextSchema,
  runtime_connection_id: Uuid7Schema,
  input_hashes: z.array(HashPinSchema).min(1).readonly(),
  execution_hashes: z.array(HashPinSchema).min(1).readonly(),
  output_hashes: z.array(HashPinSchema).min(1).readonly(),
  skill_hashes: z.array(HashPinSchema).min(1).readonly(),
  source_hashes: z.array(HashPinSchema).readonly(),
} as const

export const ProvenanceManifestPayloadSchema = z.strictObject(PROVENANCE_MANIFEST_FIELDS).readonly()

export type ProvenanceManifestPayload = z.infer<typeof ProvenanceManifestPayloadSchema>

export function provenanceManifestSha256(manifest: ProvenanceManifestPayload): string {
  const canonical = JSON.stringify({
    action_plan_sha256: manifest.action_plan_sha256,
    code_sha256: manifest.code_sha256,
    environment_sha256: manifest.environment_sha256,
    execution_hashes: canonicalPins(manifest.execution_hashes),
    input_hashes: canonicalPins(manifest.input_hashes),
    output_hashes: canonicalPins(manifest.output_hashes),
    runtime_adapter_id: manifest.runtime_adapter_id,
    runtime_connection_id: manifest.runtime_connection_id,
    skill_hashes: canonicalPins(manifest.skill_hashes),
    source_hashes: canonicalPins(manifest.source_hashes),
    source_run_id: manifest.source_run_id,
  }).replace(
    /[\u007f-\uffff]/g,
    (value) => `\\u${value.charCodeAt(0).toString(16).padStart(4, "0")}`,
  )
  return createHash("sha256").update(canonical, "utf8").digest("hex")
}

export const ProvenanceManifestSchema = z
  .strictObject({ ...PROVENANCE_MANIFEST_FIELDS, manifest_sha256: Sha256Schema })
  .superRefine((manifest, context) => {
    const pinGroups = [
      manifest.input_hashes,
      manifest.execution_hashes,
      manifest.output_hashes,
      manifest.skill_hashes,
      manifest.source_hashes,
    ]
    if (pinGroups.some((pins) => new Set(pins.map((pin) => pin.ref_id)).size !== pins.length)) {
      context.addIssue({
        code: "custom",
        message: "provenance ref_id values must be unique within each pin class",
      })
    }
    if (manifest.manifest_sha256 !== provenanceManifestSha256(manifest)) {
      context.addIssue({ code: "custom", message: "provenance manifest digest mismatch" })
    }
  })
  .readonly()

export type ProvenanceManifest = z.infer<typeof ProvenanceManifestSchema>
