from __future__ import annotations

from typing import Annotated, Literal

from pydantic import Field

from .common import (
    ContractModel,
    NonEmptyText,
    UtcTimestamp,
    Uuid7,
)

RunStatus = Literal[
    "queued",
    "running",
    "awaiting_user",
    "awaiting_approval",
    "completed",
    "failed",
    "cancelled",
]
RunEventType = Literal[
    "run.status",
    "message.delta",
    "tool.started",
    "tool.output",
    "tool.completed",
    "approval.required",
    "artifact.saved",
    "review.finding",
    "run.completed",
    "run.failed",
]


class RunCreate(ContractModel):
    session_id: Uuid7
    provider_connection_id: Uuid7
    prompt: NonEmptyText


class Run(ContractModel):
    id: Uuid7
    org_id: Uuid7
    session_id: Uuid7
    provider_connection_id: Uuid7
    retry_of_run_id: Uuid7 | None = None
    status: RunStatus
    created_at: UtcTimestamp
    updated_at: UtcTimestamp


class RunEvent(ContractModel):
    run_id: Uuid7
    sequence: Annotated[int, Field(ge=1)]
    type: RunEventType
    created_at: UtcTimestamp


class ApprovalCreate(ContractModel):
    approval_digest: Annotated[str, Field(min_length=32)]


class Approval(ContractModel):
    id: Uuid7
    org_id: Uuid7
    run_id: Uuid7
    requester_id: Uuid7
    status: Literal["pending", "approved", "rejected", "expired", "consumed"]
    expires_at: UtcTimestamp


class RunResponse(ContractModel):
    message: NonEmptyText


class RunCancel(ContractModel):
    reason: NonEmptyText | None = None


class RunRetry(ContractModel):
    reason: NonEmptyText | None = None
