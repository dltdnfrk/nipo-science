import { z } from "zod"

import {
  NonEmptyTextSchema,
  RevisionSchema,
  Sha256Schema,
  UtcTimestampSchema,
  Uuid7Schema,
} from "./common"

export const ArtifactCreateSchema = z
  .strictObject({ project_id: Uuid7Schema, name: NonEmptyTextSchema })
  .readonly()
export const ArtifactSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    name: NonEmptyTextSchema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const ArtifactVersionCreateSchema = z
  .strictObject({
    base_version: RevisionSchema,
    checksum_sha256: Sha256Schema,
    size_bytes: z.int().min(0),
    media_type: NonEmptyTextSchema,
    producing_run_id: Uuid7Schema,
  })
  .readonly()
export const ArtifactVersionSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    artifact_id: Uuid7Schema,
    version: RevisionSchema,
    checksum_sha256: Sha256Schema,
    size_bytes: z.int().min(0),
    media_type: NonEmptyTextSchema,
    producing_run_id: Uuid7Schema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const ReviewCreateSchema = z
  .strictObject({
    source_run_id: Uuid7Schema,
    artifact_version_ids: z.array(Uuid7Schema).default([]).readonly(),
    execution_ids: z.array(Uuid7Schema).default([]).readonly(),
  })
  .refine(
    (review) => review.artifact_version_ids.length > 0 || review.execution_ids.length > 0,
    "Review requires Artifact Version or Execution pins",
  )
  .readonly()
export const ReviewSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    source_run_id: Uuid7Schema,
    run_id: Uuid7Schema,
    status: z.enum(["queued", "running", "completed", "failed"]),
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const ExportCreateSchema = z
  .strictObject({ artifact_version_ids: z.array(Uuid7Schema).min(1) })
  .readonly()
export const ExportSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    status: z.enum(["queued", "running", "completed", "failed"]),
    artifact_version_ids: z.array(Uuid7Schema).readonly(),
    created_at: UtcTimestampSchema,
  })
  .readonly()

export const ProviderConnectionCreateSchema = z
  .strictObject({
    adapter_id: z.enum([
      "openai_codex",
      "anthropic_claude_code",
      "xai_grok_build",
      "moonshot_kimi_code",
    ]),
  })
  .readonly()
export const ProviderConnectionSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    requester_user_id: Uuid7Schema,
    adapter_id: z.enum([
      "openai_codex",
      "anthropic_claude_code",
      "xai_grok_build",
      "moonshot_kimi_code",
      "zai_glm",
    ]),
    status: z.enum(["pending", "healthy", "reauth_required", "revoked", "unsupported_auth"]),
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const DeletionCreateSchema = z.strictObject({ project_id: Uuid7Schema }).readonly()
export const DeletionRequestSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    status: z.enum(["queued", "running", "completed", "held", "failed"]),
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const LegalHoldStatusSchema = z
  .strictObject({ org_id: Uuid7Schema, active: z.boolean(), updated_at: UtcTimestampSchema })
  .readonly()

export type ArtifactVersion = z.infer<typeof ArtifactVersionSchema>
export type Review = z.infer<typeof ReviewSchema>
