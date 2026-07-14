import { z } from "zod"

import {
  NonEmptyTextSchema,
  RevisionSchema,
  Sha256Schema,
  UtcTimestampSchema,
  Uuid7Schema,
} from "./common"

export const ReviewerCapabilitiesSchema = z
  .strictObject({
    runner: z.literal(false),
    python: z.literal(false),
    bash: z.literal(false),
    connector: z.literal(false),
    network: z.literal(false),
    artifact_write: z.literal(false),
    tool_execute: z.literal(false),
    version_update: z.literal(false),
    reexecution: z.literal(false),
  })
  .readonly()

export const ReviewFindingSchema = z
  .strictObject({
    id: Uuid7Schema,
    rule_id: z.enum(["RV01", "RV02", "RV03", "RV04", "RV05"]),
    verdict: z.enum(["pass", "warn", "fail", "inconclusive"]),
    status: z.enum(["open", "resolved", "rebutted", "accepted_risk"]),
    artifact_version_ids: z.array(Uuid7Schema).min(1).readonly(),
    execution_ids: z.array(Uuid7Schema).readonly(),
    message: NonEmptyTextSchema,
    disposition_actor_id: Uuid7Schema.nullable().default(null),
    disposition_reason: NonEmptyTextSchema.nullable().default(null),
  })
  .superRefine((finding, context) => {
    switch (finding.status) {
      case "rebutted":
      case "accepted_risk":
        if (finding.disposition_actor_id === null || finding.disposition_reason === null) {
          context.addIssue({
            code: "custom",
            message: "disposition actor and reason are required",
          })
        }
        break
      case "open":
      case "resolved":
        if (finding.disposition_actor_id !== null || finding.disposition_reason !== null) {
          context.addIssue({
            code: "custom",
            message: "disposition audit is forbidden for this status",
          })
        }
        break
      default:
        return finding.status satisfies never
    }
  })
  .readonly()

export const FindingsSubmissionSchema = z
  .strictObject({
    submission_id: Uuid7Schema,
    exactly_once: z.literal(true),
    submitted_at: UtcTimestampSchema,
    findings: z.array(ReviewFindingSchema).min(1).readonly(),
  })
  .readonly()

export const PersistedReviewSchema = z
  .strictObject({
    id: Uuid7Schema,
    revision: RevisionSchema,
    run_id: Uuid7Schema,
    source_run_id: Uuid7Schema,
    status: z.enum(["queued", "running", "completed", "failed"]),
    pinned_artifact_version_ids: z.array(Uuid7Schema).readonly(),
    pinned_execution_ids: z.array(Uuid7Schema).readonly(),
    pinned_input_sha256: Sha256Schema,
    reviewer_capabilities: ReviewerCapabilitiesSchema,
    submission: FindingsSubmissionSchema.nullable(),
    created_at: UtcTimestampSchema,
  })
  .readonly()
  .superRefine((review, context) => {
    if (
      review.pinned_artifact_version_ids.length === 0 &&
      review.pinned_execution_ids.length === 0
    ) {
      context.addIssue({
        code: "custom",
        message: "Review requires Artifact Version or Execution pins",
      })
    }
    if ((review.status === "completed") !== (review.submission !== null)) {
      context.addIssue({
        code: "custom",
        message: "Findings submission exists exactly when Review is completed",
      })
    }
  })

export type PersistedReview = z.infer<typeof PersistedReviewSchema>
export type FindingsSubmission = z.infer<typeof FindingsSubmissionSchema>
export const SubmitFindingsCommandSchema = z
  .strictObject({
    review_id: Uuid7Schema,
    expected_revision: RevisionSchema,
    submission: FindingsSubmissionSchema,
  })
  .readonly()
export type SubmitFindingsCommand = z.infer<typeof SubmitFindingsCommandSchema>
export type SubmitFindingsResult =
  | { readonly ok: true; readonly review: PersistedReview }
  | {
      readonly ok: false
      readonly reason:
        | "review_not_found"
        | "stale_revision"
        | "findings_already_submitted"
        | "review_not_running"
    }

export interface ReviewFindingsStore {
  compareAndSubmit(command: SubmitFindingsCommand): SubmitFindingsResult
}

export class InMemoryReviewFindingsStore implements ReviewFindingsStore {
  private readonly records = new Map<string, PersistedReview>()

  constructor(reviews: readonly PersistedReview[]) {
    for (const review of reviews) {
      const validated = PersistedReviewSchema.parse(review)
      this.records.set(validated.id, validated)
    }
  }

  compareAndSubmit(command: SubmitFindingsCommand): SubmitFindingsResult {
    const review = this.records.get(command.review_id)
    if (review === undefined) return Object.freeze({ ok: false, reason: "review_not_found" })
    if (command.expected_revision !== review.revision)
      return Object.freeze({ ok: false, reason: "stale_revision" })
    if (review.submission !== null)
      return Object.freeze({ ok: false, reason: "findings_already_submitted" })
    if (review.status !== "running")
      return Object.freeze({ ok: false, reason: "review_not_running" })
    const updated = PersistedReviewSchema.parse({
      ...review,
      revision: review.revision + 1,
      status: "completed",
      submission: command.submission,
    })
    this.records.set(review.id, updated)
    return Object.freeze({ ok: true, review: updated })
  }
}

export function submitFindingsOnce(
  store: ReviewFindingsStore,
  command: SubmitFindingsCommand,
): SubmitFindingsResult {
  return store.compareAndSubmit(command)
}
