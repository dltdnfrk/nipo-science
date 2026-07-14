import { z } from "zod"

import { ArtifactVersionSchema } from "./artifacts"
import { AuthContextSchema } from "./auth"
import { RunSchema } from "./runs"

export const ContractRoundTripSchema = z
  .strictObject({
    auth: AuthContextSchema,
    run: RunSchema,
    artifact_version: ArtifactVersionSchema,
  })
  .readonly()

export type ContractRoundTrip = z.infer<typeof ContractRoundTripSchema>
