import { z } from "zod"

const ResponseSchema = z.looseObject({
  $ref: z.string().optional(),
  description: z.string().optional(),
})
const OperationSchema = z.looseObject({
  "x-tenant-scoped": z.boolean().optional(),
  "x-mutation-protection": z.boolean().optional(),
  parameters: z.array(z.looseObject({ $ref: z.string().optional() })).optional(),
  responses: z.record(z.string(), ResponseSchema),
})
const PathItemSchema = z.looseObject({
  get: OperationSchema.optional(),
  post: OperationSchema.optional(),
  patch: OperationSchema.optional(),
  delete: OperationSchema.optional(),
})

export const OpenApiDocumentSchema = z
  .looseObject({
    openapi: z.literal("3.1.1"),
    "x-tenancy": z.object({
      org_id: z.literal("server-derived"),
      client_authority: z.literal(false),
      cross_tenant_status: z.literal(404),
    }),
    "x-auth-contract": z.object({
      cookie_name: z.literal("__Host-swb_session"),
      host_only: z.literal(true),
      secure: z.literal(true),
      http_only: z.literal(true),
      csrf_header: z.literal("X-CSRF-Token"),
      origin_required: z.literal(true),
      fetch_metadata_header: z.literal("Sec-Fetch-Site"),
      fetch_metadata_allowed: z.tuple([z.literal("same-origin")]),
    }),
    paths: z.record(z.string().startsWith("/api/v1/"), PathItemSchema),
    components: z.looseObject({
      securitySchemes: z.object({
        HostSession: z.looseObject({
          name: z.literal("__Host-swb_session"),
          "x-host-only": z.literal(true),
          "x-secure": z.literal(true),
          "x-http-only": z.literal(true),
        }),
      }),
      schemas: z.record(z.string(), z.unknown()),
    }),
  })
  .readonly()

export type OpenApiDocument = z.infer<typeof OpenApiDocumentSchema>
