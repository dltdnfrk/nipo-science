import { readFileSync } from "node:fs"
import { fileURLToPath } from "node:url"
import { describe, expect, it } from "vitest"

import { ReviewCreateSchema } from "../src/artifacts"
import { DryLabRunContractSchema } from "../src/dry-lab-contract"
import * as reviewerContracts from "../src/reviews-v1"
import {
  InMemoryReviewFindingsStore,
  PersistedReviewSchema,
  ReviewFindingSchema,
  SubmitFindingsCommandSchema,
  submitFindingsOnce,
} from "../src/reviews-v1"

const fixturePath = fileURLToPath(
  new URL("../fixtures/gs04-dry-lab-contract.json", import.meta.url),
)

describe("Review Findings CAS", () => {
  it("submits Review Findings exactly once", () => {
    // Given: a running persisted Review with no prior submission.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const submission = contract.review.submission
    if (submission === null) throw new Error("fixture submission missing")
    const pending = PersistedReviewSchema.parse({
      ...contract.review,
      status: "running",
      submission: null,
    })

    const store = new InMemoryReviewFindingsStore([pending])
    const command = SubmitFindingsCommandSchema.parse({
      review_id: pending.id,
      expected_revision: pending.revision,
      submission,
    })

    // When: two workers submit the same command captured from the pending snapshot.
    const first = submitFindingsOnce(store, command)
    if (!first.ok) throw new Error(`unexpected Review rejection: ${first.reason}`)
    const second = submitFindingsOnce(store, command)

    // Then: only the first submission completes the Review.
    expect(first.review.status).toBe("completed")
    expect(first.review.revision).toBe(pending.revision + 1)
    expect(Object.isFrozen(first.review)).toBe(true)
    expect(second).toEqual({ ok: false, reason: "stale_revision" })
  })

  it("requires actor and reason for rebutted or accepted-risk findings", () => {
    // Given: a valid Finding without disposition audit fields.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const submission = contract.review.submission
    if (submission === null) throw new Error("fixture submission missing")
    const finding = submission.findings[0]
    if (finding === undefined) throw new Error("fixture finding missing")

    // When: the status is changed to a disposition requiring an audit trail.
    const missingAudit = ReviewFindingSchema.safeParse({ ...finding, status: "accepted_risk" })
    const audited = ReviewFindingSchema.safeParse({
      ...finding,
      status: "accepted_risk",
      disposition_actor_id: contract.review.run_id,
      disposition_reason: "The documented research limitation is accepted.",
    })

    // Then: only the actor-and-reason-bound disposition is accepted.
    expect(missingAudit.success).toBe(false)
    expect(audited.success).toBe(true)
  })

  it("accepts execution-only persisted Review pins", () => {
    // Given: a completed Review with its Artifact pins omitted.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))
    const executionOnly = { ...contract.review, pinned_artifact_version_ids: [] }

    // When: execution-only and evidence-free forms cross the boundary.
    const accepted = PersistedReviewSchema.safeParse(executionOnly)
    const empty = PersistedReviewSchema.safeParse({ ...executionOnly, pinned_execution_ids: [] })

    // Then: one evidence class is sufficient, but empty pinning is invalid.
    expect(accepted.success).toBe(true)
    expect(empty.success).toBe(false)
    expect(
      ReviewCreateSchema.safeParse({
        source_run_id: contract.review.source_run_id,
        execution_ids: contract.review.pinned_execution_ids,
      }).success,
    ).toBe(true)
    expect(
      ReviewCreateSchema.safeParse({ source_run_id: contract.review.source_run_id }).success,
    ).toBe(false)
  })

  it("rejects premature submission and exposes no Reviewer execution API", () => {
    // Given: a running Review that already carries Findings.
    const contract = DryLabRunContractSchema.parse(JSON.parse(readFileSync(fixturePath, "utf8")))

    // When: the invalid lifecycle and Reviewer exports are inspected.
    const premature = PersistedReviewSchema.safeParse({ ...contract.review, status: "running" })
    const exportNames = new Set(Object.keys(reviewerContracts))

    // Then: lifecycle rejects and no execution/write capability is representable.
    expect(premature.success).toBe(false)
    expect(
      [...exportNames].some((name) => /^(run|execute|reexecute|writeArtifact)$/.test(name)),
    ).toBe(false)
  })
})
