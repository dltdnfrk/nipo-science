from typing import Annotated, ClassVar, Final, Literal, Self

from pydantic import ConfigDict, Field, field_validator, model_validator
from pydantic_core import PydanticCustomError

from science_workbench_contracts.common import (
    ContractModel,
    FrozenJsonValue,
    NonEmptyText,
    Revision,
    Sha256,
    UtcTimestamp,
    Uuid7,
    json_projection,
)
from science_workbench_contracts.runs import (
    ResearchIntent,
)
from science_workbench_contracts.runs import (
    research_intent_sha256 as compute_research_intent_sha256,
)

from .event_guard import (
    FORBIDDEN_EVENT_ERROR,
    FORBIDDEN_EVENT_MESSAGE,
    contains_forbidden_event_data,
)

RUN_AGGREGATE_TENANT_ERROR: Final = "run_aggregate_tenant"
RUN_AGGREGATE_TENANT_MESSAGE: Final = "all events must belong to the aggregate Run"
RUN_AGGREGATE_ORDER_ERROR: Final = "run_aggregate_order"
RUN_AGGREGATE_ORDER_MESSAGE: Final = "event sequence must be contiguous and increasing"
RUN_AGGREGATE_TIME_ERROR: Final = "run_aggregate_time"
RUN_AGGREGATE_TIME_MESSAGE: Final = "event timestamps must be monotonic"
COMPLETED_EXECUTION_RESULT_ERROR: Final = "completed_execution_result"
COMPLETED_EXECUTION_RESULT_MESSAGE: Final = (
    "completed Execution requires a result reference"
)
RESEARCH_INTENT_DIGEST_ERROR: Final = "research_intent_digest"
RESEARCH_INTENT_DIGEST_MESSAGE: Final = "research intent digest mismatch"


class ProtocolModel(ContractModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        extra="forbid", frozen=True, strict=True
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
ExecutionStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
ApprovalStatus = Literal["pending", "approved", "rejected", "expired", "consumed"]
ToolGrantEffect = Literal["allow", "ask", "deny"]
RunEventKind = Literal[
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


class RunRecord(ProtocolModel):
    id: Uuid7
    org_id: Uuid7
    session_id: Uuid7
    requester_id: Uuid7
    provider_connection_id: Uuid7
    retry_of_run_id: Uuid7 | None = None
    status: RunStatus
    created_at: UtcTimestamp
    updated_at: UtcTimestamp


class Message(ProtocolModel):
    id: Uuid7
    org_id: Uuid7
    run_id: Uuid7
    role: Literal["user", "assistant", "tool"]
    content: str
    created_at: UtcTimestamp


class RunEvent(ProtocolModel):
    run_id: Uuid7
    sequence: Annotated[int, Field(ge=1)]
    kind: RunEventKind
    data: FrozenJsonValue
    created_at: UtcTimestamp

    @field_validator("data")
    @classmethod
    def reject_forbidden_semantics(cls, value: FrozenJsonValue) -> FrozenJsonValue:
        if contains_forbidden_event_data(json_projection(value)):
            raise PydanticCustomError(FORBIDDEN_EVENT_ERROR, FORBIDDEN_EVENT_MESSAGE)
        return value


class RunAggregate(ProtocolModel):
    run: RunRecord
    events: tuple[RunEvent, ...] = ()

    @model_validator(mode="after")
    def valid_event_history(self) -> Self:
        if any(event.run_id != self.run.id for event in self.events):
            raise PydanticCustomError(
                RUN_AGGREGATE_TENANT_ERROR, RUN_AGGREGATE_TENANT_MESSAGE
            )
        sequences = tuple(event.sequence for event in self.events)
        if sequences != tuple(range(1, len(self.events) + 1)):
            raise PydanticCustomError(
                RUN_AGGREGATE_ORDER_ERROR, RUN_AGGREGATE_ORDER_MESSAGE
            )
        timestamps = tuple(event.created_at for event in self.events)
        if timestamps != tuple(sorted(timestamps)):
            raise PydanticCustomError(
                RUN_AGGREGATE_TIME_ERROR, RUN_AGGREGATE_TIME_MESSAGE
            )
        return self


class ActionPlan(ProtocolModel):
    id: Uuid7
    org_id: Uuid7
    project_id: Uuid7
    run_id: Uuid7
    requester_id: Uuid7
    research_intent: ResearchIntent
    research_intent_sha256: Sha256
    version: Annotated[int, Field(ge=1)]
    tool: NonEmptyText
    arguments: FrozenJsonValue
    arguments_hash: Sha256
    network_scope: tuple[str, ...] = ()
    secret_scope: tuple[str, ...] = ()
    reason: NonEmptyText
    plan_digest: Sha256
    created_at: UtcTimestamp

    @model_validator(mode="after")
    def valid_research_intent_digest(self) -> Self:
        if self.research_intent_sha256 != compute_research_intent_sha256(
            self.research_intent
        ):
            raise PydanticCustomError(
                RESEARCH_INTENT_DIGEST_ERROR,
                RESEARCH_INTENT_DIGEST_MESSAGE,
            )
        return self


class ToolGrant(ProtocolModel):
    org_id: Uuid7
    project_id: Uuid7
    tool: NonEmptyText
    effect: ToolGrantEffect


class ApprovalBinding(ProtocolModel):
    org_id: Uuid7
    project_id: Uuid7
    run_id: Uuid7
    requester_id: Uuid7
    action_plan_id: Uuid7
    research_intent_sha256: Sha256
    plan_digest: Sha256
    tool: NonEmptyText
    arguments_hash: Sha256
    network_scope: tuple[str, ...] = ()
    secret_scope: tuple[str, ...] = ()
    expires_at: UtcTimestamp


class ApprovalRecord(ProtocolModel):
    id: Uuid7
    binding: ApprovalBinding
    digest: Sha256
    revision: Revision
    status: ApprovalStatus
    decided_by: Uuid7 | None = None
    created_at: UtcTimestamp


class ExecutionRecord(ProtocolModel):
    id: Uuid7
    org_id: Uuid7
    run_id: Uuid7
    action_plan_id: Uuid7
    status: ExecutionStatus
    attempt_token: Annotated[int, Field(ge=1)]
    result_ref: NonEmptyText | None = None
    created_at: UtcTimestamp
    updated_at: UtcTimestamp

    @model_validator(mode="after")
    def completed_has_result(self) -> Self:
        if self.status == "completed" and self.result_ref is None:
            raise PydanticCustomError(
                COMPLETED_EXECUTION_RESULT_ERROR,
                COMPLETED_EXECUTION_RESULT_MESSAGE,
            )
        return self


class ExecutionLease(ProtocolModel):
    execution_id: Uuid7
    attempt_token: Annotated[int, Field(ge=1)]
    heartbeat_at: UtcTimestamp
    expires_at: UtcTimestamp


class ToolResult(ProtocolModel):
    org_id: Uuid7
    run_id: Uuid7
    message_id: Uuid7
    action_id: Uuid7
    execution_id: Uuid7
    executor: Literal["application"]
    result_ref: NonEmptyText
    redacted_output: str
