from __future__ import annotations

import hashlib
import json
import unicodedata
from typing import Annotated, Literal

from pydantic import AfterValidator, Field, model_validator

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
ResearchMode = Literal["ai_for_science", "copilot", "bounded_agentic"]
DataOrigin = Literal["observed", "synthetic", "mixed"]
_SYNTHETIC_PROVENANCE_MISMATCH = "synthetic provenance mismatch"
_RESEARCH_INTENT_DUPLICATE = "research intent items must be unique"
_RESEARCH_INTENT_NONCANONICAL = "research intent text must be boundary-trimmed"
_RESEARCH_BOUNDARY_WHITESPACE = frozenset(
    (
        *range(0x0009, 0x000E),
        *range(0x001C, 0x0021),
        0x0085,
        0x00A0,
        0x1680,
        *range(0x2000, 0x200B),
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
        0xFEFF,
    )
)


def _canonical_research_text(value: str) -> str:
    if (
        not value
        or unicodedata.normalize("NFC", value) != value
        or ord(value[0]) in _RESEARCH_BOUNDARY_WHITESPACE
        or ord(value[-1]) in _RESEARCH_BOUNDARY_WHITESPACE
    ):
        raise ValueError(_RESEARCH_INTENT_NONCANONICAL)
    return value


ResearchIntentText = Annotated[
    str,
    Field(min_length=1, max_length=2_000),
    AfterValidator(_canonical_research_text),
]
ResearchIntentItem = Annotated[
    str,
    Field(min_length=1, max_length=500),
    AfterValidator(_canonical_research_text),
]


class ResearchIntent(ContractModel):
    question: ResearchIntentText
    rationale: ResearchIntentText
    intended_benefit: ResearchIntentText
    success_criteria: Annotated[
        tuple[ResearchIntentItem, ...], Field(min_length=1, max_length=8)
    ]
    constraints: Annotated[
        tuple[ResearchIntentItem, ...], Field(min_length=1, max_length=8)
    ]
    stop_conditions: Annotated[
        tuple[ResearchIntentItem, ...], Field(min_length=1, max_length=8)
    ]
    research_mode: ResearchMode
    data_origin: DataOrigin
    synthetic_generator_ref: ResearchIntentItem | None = None
    synthetic_validator_ref: ResearchIntentItem | None = None

    @model_validator(mode="after")
    def validate_synthetic_provenance(self) -> ResearchIntent:
        if any(
            len(items) != len(set(items))
            for items in (
                self.success_criteria,
                self.constraints,
                self.stop_conditions,
            )
        ):
            raise ValueError(_RESEARCH_INTENT_DUPLICATE)
        synthetic = self.data_origin != "observed"
        references_present = (
            self.synthetic_generator_ref is not None
            and self.synthetic_validator_ref is not None
        )
        if synthetic != references_present or (
            synthetic
            and self.synthetic_generator_ref == self.synthetic_validator_ref
        ):
            raise ValueError(_SYNTHETIC_PROVENANCE_MISMATCH)
        return self


def research_intent_sha256(intent: ResearchIntent) -> str:
    payload = json.dumps(
        intent.model_dump(mode="json"),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


class RunInput(ContractModel):
    filename: NonEmptyText
    media_type: Literal["text/csv"]
    content: NonEmptyText


class RunCreate(ContractModel):
    execution_mode: Literal["local_dry_lab", "provider_model"]
    session_id: Uuid7
    prompt: NonEmptyText
    research_intent: ResearchIntent
    input: RunInput
    connection_id: Uuid7 | None = None
    model_id: Annotated[str, Field(min_length=1, max_length=255)] | None = None

    @model_validator(mode="after")
    def validate_execution_target(self) -> RunCreate:
        provider_target = self.connection_id is not None and self.model_id is not None
        if (self.execution_mode == "provider_model") != provider_target:
            message = "execution target mismatch"
            raise ValueError(message)
        return self


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
