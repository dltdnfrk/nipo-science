import { z } from "zod"

import { NonEmptyTextSchema, Sha256Schema, UtcTimestampSchema, Uuid7Schema } from "./common"

const RESERVED_EXPORT_ROOTS = new Set(["manifest.json", "checksums.sha256", "provenance", "review"])
const WINDOWS_DEVICE_NAMES = new Set([
  "con",
  "prn",
  "aux",
  "nul",
  ...Array.from({ length: 9 }, (_, index) => `com${index + 1}`),
  ...Array.from({ length: 9 }, (_, index) => `lpt${index + 1}`),
])

function normalizedExportPath(path: string): string {
  return path.normalize("NFKC").toLowerCase()
}

export const SafeExportPathSchema = NonEmptyTextSchema.refine((path) => {
  if (!/^[A-Za-z0-9._/-]+$/.test(path)) return false
  if (path.startsWith("/") || path.startsWith("\\") || /^[A-Za-z]:/.test(path)) return false
  if (path.includes("\\")) return false
  return path.split("/").every((segment) => {
    const base = segment.split(".")[0]?.toLowerCase()
    return (
      segment !== "" &&
      segment !== "." &&
      segment !== ".." &&
      !segment.endsWith(".") &&
      base !== undefined &&
      !WINDOWS_DEVICE_NAMES.has(base)
    )
  })
}, "export path must be a safe relative POSIX path")

export const ExportArtifactEntrySchema = z
  .strictObject({
    path: SafeExportPathSchema,
    artifact_version_id: Uuid7Schema,
    sha256: Sha256Schema,
    media_type: NonEmptyTextSchema,
    entry_kind: z.literal("file"),
  })
  .readonly()

export const ExportManifestSchema = z
  .strictObject({
    id: Uuid7Schema,
    source_run_id: Uuid7Schema,
    review_id: Uuid7Schema,
    research_intent_sha256: Sha256Schema,
    selected_artifact_version_ids: z.array(Uuid7Schema).min(1).readonly(),
    artifact_entries: z.array(ExportArtifactEntrySchema).min(1).readonly(),
    manifest_path: z.literal("manifest.json"),
    checksums_path: z.literal("checksums.sha256"),
    provenance_path: z.literal("provenance/manifest.json"),
    action_plan_path: z.literal("provenance/action-plan.json"),
    review_path: z.literal("review/review.json"),
    created_at: UtcTimestampSchema,
  })
  .superRefine((manifest, context) => {
    const selected = new Set(manifest.selected_artifact_version_ids)
    const entryVersions = new Set(
      manifest.artifact_entries.map((entry) => entry.artifact_version_id),
    )
    if (
      selected.size !== manifest.selected_artifact_version_ids.length ||
      entryVersions.size !== selected.size ||
      entryVersions.size !== manifest.artifact_entries.length
    ) {
      context.addIssue({
        code: "custom",
        message: "selected version IDs must be unique and exported exactly once",
      })
    }
    for (const versionId of entryVersions) {
      if (!selected.has(versionId))
        context.addIssue({ code: "custom", message: "entry uses an unselected version" })
    }
    const normalizedPaths = manifest.artifact_entries.map((entry) =>
      normalizedExportPath(entry.path),
    )
    const reservedRoots = [...RESERVED_EXPORT_ROOTS].map(normalizedExportPath)
    if (
      normalizedPaths.some((path) =>
        reservedRoots.some((root) => path === root || path.startsWith(`${root}/`)),
      )
    ) {
      context.addIssue({
        code: "custom",
        message: "artifact entry collides with a reserved pack path",
      })
    }
    if (new Set(normalizedPaths).size !== normalizedPaths.length) {
      context.addIssue({ code: "custom", message: "export paths collide after normalization" })
    }
    if (
      normalizedPaths.some((path, index) =>
        normalizedPaths.some(
          (other, otherIndex) => index !== otherIndex && other.startsWith(`${path}/`),
        ),
      )
    ) {
      context.addIssue({ code: "custom", message: "export file and directory paths collide" })
    }
  })

export type ExportManifest = z.infer<typeof ExportManifestSchema>
