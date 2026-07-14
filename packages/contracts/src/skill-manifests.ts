import { z } from "zod"

import { NonEmptyTextSchema, Sha256Schema, Uuid7Schema } from "./common"

export const CANONICAL_SKILL_IDS = [
  "literature-review",
  "source-attribution",
  "probe-diagnostic",
] as const

export const SkillNeedsSchema = z
  .strictObject({
    tools: z.array(NonEmptyTextSchema).readonly(),
    connectors: z.array(NonEmptyTextSchema).readonly(),
    network_hosts: z.array(NonEmptyTextSchema).readonly(),
    secret_names: z.array(NonEmptyTextSchema).readonly(),
    kernel: z.boolean(),
  })
  .readonly()

export const SkillManifestSchema = z
  .strictObject({
    id: z.enum(CANONICAL_SKILL_IDS),
    project_id: Uuid7Schema,
    run_id: Uuid7Schema,
    version: z.string().regex(/^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/),
    content_sha256: Sha256Schema,
    kernel_sha256: Sha256Schema.nullable(),
    needs: SkillNeedsSchema,
  })
  .readonly()
  .refine((manifest) => manifest.needs.kernel === (manifest.kernel_sha256 !== null), {
    message: "kernel hash must be present exactly when a Skill needs a kernel",
  })

export type SkillManifest = z.infer<typeof SkillManifestSchema>
