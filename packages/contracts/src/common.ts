import { z } from "zod"

export const Uuid7Schema = z
  .string()
  .regex(/^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/)
  .brand<"Uuid7">()

export const UtcTimestampSchema = z.iso
  .datetime({ offset: false })
  .regex(/Z$/)
  .brand<"UtcTimestamp">()
export const NonEmptyTextSchema = z.string().min(1)
export const Sha256Schema = z.string().regex(/^[0-9a-f]{64}$/)
export const RevisionSchema = z.int().min(1)

export interface ReadonlyJsonArray extends ReadonlyArray<ReadonlyJsonValue> {}
export interface ReadonlyJsonObject {
  readonly [key: string]: ReadonlyJsonValue
}
export type ReadonlyJsonValue =
  | null
  | boolean
  | number
  | string
  | ReadonlyJsonArray
  | ReadonlyJsonObject

export const ReadonlyJsonValueSchema: z.ZodType<ReadonlyJsonValue> = z.lazy(() =>
  z.union([
    z.null(),
    z.boolean(),
    z.number(),
    z.string(),
    z.array(ReadonlyJsonValueSchema).readonly(),
    z.record(z.string(), ReadonlyJsonValueSchema).readonly(),
  ]),
)

export type Uuid7 = z.infer<typeof Uuid7Schema>
export type UtcTimestamp = z.infer<typeof UtcTimestampSchema>
