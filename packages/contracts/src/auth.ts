import { z } from "zod"

import { NonEmptyTextSchema, RevisionSchema, UtcTimestampSchema, Uuid7Schema } from "./common"

export const MagicLinkRequestSchema = z.strictObject({ email: z.email() }).readonly()
export const MagicLinkExchangeSchema = z
  .strictObject({ token: NonEmptyTextSchema, state: NonEmptyTextSchema })
  .readonly()

export const AuthContextSchema = z
  .strictObject({
    user_id: Uuid7Schema,
    org_id: Uuid7Schema,
    email: z.email(),
    role: z.enum(["owner", "member"]),
    csrf_token: NonEmptyTextSchema,
    expires_at: UtcTimestampSchema,
  })
  .readonly()

export const OrganizationSchema = z
  .strictObject({ id: Uuid7Schema, name: NonEmptyTextSchema, created_at: UtcTimestampSchema })
  .readonly()
export const ProjectCreateSchema = z.strictObject({ name: NonEmptyTextSchema }).readonly()
export const ProjectSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    name: NonEmptyTextSchema,
    revision: RevisionSchema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const SessionCreateSchema = z
  .strictObject({ project_id: Uuid7Schema, title: NonEmptyTextSchema })
  .readonly()
export const SessionSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    title: NonEmptyTextSchema,
    revision: RevisionSchema,
    created_at: UtcTimestampSchema,
  })
  .readonly()
export const UploadCreateSchema = z
  .strictObject({
    project_id: Uuid7Schema,
    filename: NonEmptyTextSchema,
    media_type: NonEmptyTextSchema,
  })
  .readonly()
export const UploadSchema = z
  .strictObject({
    id: Uuid7Schema,
    org_id: Uuid7Schema,
    project_id: Uuid7Schema,
    filename: NonEmptyTextSchema,
    status: z.enum(["pending", "clean", "rejected"]),
    created_at: UtcTimestampSchema,
  })
  .readonly()

export type AuthContext = z.infer<typeof AuthContextSchema>
export type ProjectCreate = z.infer<typeof ProjectCreateSchema>
