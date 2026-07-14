import { z } from "zod"

import {
  NonEmptyTextSchema,
  RevisionSchema,
  Sha256Schema,
  UtcTimestampSchema,
  Uuid7Schema,
} from "./common"

export const ArtifactVersionRecordSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    artifact_id: Uuid7Schema,
    version: RevisionSchema,
    content_sha256: Sha256Schema,
    size_bytes: z.int().min(0),
    media_type: NonEmptyTextSchema,
    producing_execution_id: Uuid7Schema,
    environment_sha256: Sha256Schema,
    input_version_ids: z.array(Uuid7Schema).readonly(),
    code_sha256: Sha256Schema,
    runtime_adapter_id: NonEmptyTextSchema,
    runtime_connection_id: Uuid7Schema,
    skill_content_hashes: z.array(Sha256Schema).readonly(),
    source_hashes: z.array(Sha256Schema).readonly(),
    immutable: z.literal(true),
    created_at: UtcTimestampSchema,
  })
  .readonly()

export const ArtifactAttachmentStateSchema = z
  .strictObject({
    artifact_id: Uuid7Schema,
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    revision: RevisionSchema,
    version_ids: z.array(Uuid7Schema).readonly(),
  })
  .readonly()
  .refine((state) => new Set(state.version_ids).size === state.version_ids.length, {
    message: "attached Artifact Version IDs must be unique",
  })

export const ArtifactAttachmentCommandSchema = z.discriminatedUnion("operation", [
  z
    .strictObject({
      operation: z.literal("attach"),
      base_revision: RevisionSchema,
      version_id: Uuid7Schema,
      version_org_id: Uuid7Schema,
      version_project_id: Uuid7Schema,
      version_artifact_id: Uuid7Schema,
    })
    .readonly(),
  z
    .strictObject({
      operation: z.literal("detach"),
      base_revision: RevisionSchema,
      version_id: Uuid7Schema,
    })
    .readonly(),
])

export type ArtifactVersionRecord = z.infer<typeof ArtifactVersionRecordSchema>
export type ArtifactAttachmentState = z.infer<typeof ArtifactAttachmentStateSchema>
export type ArtifactAttachmentCommand = z.infer<typeof ArtifactAttachmentCommandSchema>
export type ArtifactAttachmentResult =
  | { readonly ok: true; readonly state: ArtifactAttachmentState }
  | {
      readonly ok: false
      readonly reason: "stale_revision" | "context_mismatch" | "already_attached" | "not_attached"
    }

export const ArtifactVersionCreateCommandSchema = z
  .strictObject({ base_version_id: Uuid7Schema, next_version: ArtifactVersionRecordSchema })
  .readonly()

export type ArtifactVersionCreateCommand = z.infer<typeof ArtifactVersionCreateCommandSchema>
export type ArtifactVersionCreateResult =
  | {
      readonly ok: true
      readonly previous: ArtifactVersionRecord
      readonly created: ArtifactVersionRecord
    }
  | { readonly ok: false; readonly reason: "stale_base" | "invalid_successor" }

export function createArtifactVersionCas(
  current: ArtifactVersionRecord,
  command: ArtifactVersionCreateCommand,
): ArtifactVersionCreateResult {
  if (command.base_version_id !== current.id) return { ok: false, reason: "stale_base" }
  if (
    command.next_version.org_id !== current.org_id ||
    command.next_version.project_id !== current.project_id ||
    command.next_version.artifact_id !== current.artifact_id ||
    command.next_version.id === current.id ||
    command.next_version.version !== current.version + 1 ||
    command.next_version.created_at < current.created_at
  ) {
    return { ok: false, reason: "invalid_successor" }
  }
  return Object.freeze({ ok: true, previous: current, created: command.next_version })
}

export function applyArtifactAttachmentCas(
  state: ArtifactAttachmentState,
  command: ArtifactAttachmentCommand,
): ArtifactAttachmentResult {
  if (command.base_revision !== state.revision) return { ok: false, reason: "stale_revision" }
  switch (command.operation) {
    case "attach": {
      if (
        command.version_org_id !== state.org_id ||
        command.version_project_id !== state.project_id ||
        command.version_artifact_id !== state.artifact_id
      )
        return { ok: false, reason: "context_mismatch" }
      if (state.version_ids.includes(command.version_id))
        return { ok: false, reason: "already_attached" }
      const attached = ArtifactAttachmentStateSchema.parse({
        ...state,
        revision: state.revision + 1,
        version_ids: [...state.version_ids, command.version_id],
      })
      return {
        ok: true,
        state: attached,
      }
    }
    case "detach": {
      if (!state.version_ids.includes(command.version_id))
        return { ok: false, reason: "not_attached" }
      const detached = ArtifactAttachmentStateSchema.parse({
        ...state,
        revision: state.revision + 1,
        version_ids: state.version_ids.filter((versionId) => versionId !== command.version_id),
      })
      return Object.freeze({
        ok: true,
        state: detached,
      })
    }
  }
}
