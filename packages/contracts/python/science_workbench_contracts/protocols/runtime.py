from collections.abc import AsyncIterator
from dataclasses import dataclass
from typing import Annotated, Final, Literal, Protocol, Self, override

from pydantic import Field, JsonValue, model_validator
from pydantic_core import PydanticCustomError

from science_workbench_contracts.common import NonEmptyText, Sha256, UtcTimestamp, Uuid7

from .approval import canonical_arguments_hash
from .models import Message, ProtocolModel, ToolResult

RuntimeErrorCategory = Literal[
    "quota", "reauth_required", "cancelled", "unavailable", "failed"
]
RuntimeTerminalOutcome = Literal["completed", "failed", "cancelled", "unavailable"]
RUNTIME_CORRELATION_ERROR: Final = "runtime_correlation"
RUNTIME_CORRELATION_MESSAGE: Final = "runtime command references do not correlate"


class RuntimeTextDelta(ProtocolModel):
    kind: Literal["text_delta"] = "text_delta"
    run_id: Uuid7
    message_id: Uuid7
    delta: NonEmptyText
    created_at: UtcTimestamp


class RuntimeActionProposal(ProtocolModel):
    kind: Literal["action_proposal"] = "action_proposal"
    run_id: Uuid7
    message_id: Uuid7
    action_id: Uuid7
    action_type: Literal["tool"] = "tool"
    tool: NonEmptyText
    arguments: JsonValue
    arguments_hash: Sha256
    continuation_token: NonEmptyText
    created_at: UtcTimestamp


class RuntimeTerminal(ProtocolModel):
    kind: Literal["terminal"] = "terminal"
    run_id: Uuid7
    outcome: RuntimeTerminalOutcome
    detail: NonEmptyText | None = None
    created_at: UtcTimestamp


class RuntimeQuota(ProtocolModel):
    kind: Literal["quota"] = "quota"
    run_id: Uuid7
    detail: NonEmptyText
    created_at: UtcTimestamp


class RuntimeReauthentication(ProtocolModel):
    kind: Literal["reauth_required"] = "reauth_required"
    run_id: Uuid7
    detail: NonEmptyText
    created_at: UtcTimestamp


RuntimeEvent = Annotated[
    RuntimeTextDelta
    | RuntimeActionProposal
    | RuntimeTerminal
    | RuntimeQuota
    | RuntimeReauthentication,
    Field(discriminator="kind"),
]


class RuntimeStart(ProtocolModel):
    run_id: Uuid7
    provider_connection_id: Uuid7
    message: Message

    @model_validator(mode="after")
    def correlated_message(self) -> Self:
        if self.message.run_id != self.run_id:
            raise PydanticCustomError(
                RUNTIME_CORRELATION_ERROR, RUNTIME_CORRELATION_MESSAGE
            )
        return self


class RuntimeContinue(ProtocolModel):
    org_id: Uuid7
    run_id: Uuid7
    message_id: Uuid7
    action_id: Uuid7
    execution_id: Uuid7
    continuation_token: NonEmptyText
    result: ToolResult

    @model_validator(mode="after")
    def correlated_result(self) -> Self:
        command_context = (
            self.org_id,
            self.run_id,
            self.message_id,
            self.action_id,
            self.execution_id,
        )
        result_context = (
            self.result.org_id,
            self.result.run_id,
            self.result.message_id,
            self.result.action_id,
            self.result.execution_id,
        )
        if command_context != result_context:
            raise PydanticCustomError(
                RUNTIME_CORRELATION_ERROR, RUNTIME_CORRELATION_MESSAGE
            )
        return self


class RuntimeCancel(ProtocolModel):
    run_id: Uuid7
    reason: NonEmptyText | None = None


class RuntimeErrorSignal(ProtocolModel):
    run_id: Uuid7
    category: RuntimeErrorCategory
    detail: NonEmptyText
    created_at: UtcTimestamp


@dataclass(frozen=True, slots=True)
class RuntimeProtocolError(Exception):
    code: Literal["ACTION_ARGUMENTS_HASH_MISMATCH"]

    @override
    def __str__(self) -> str:
        return self.code


class AgentRuntimeAdapter(Protocol):
    def start(self, command: RuntimeStart) -> AsyncIterator[RuntimeEvent]: ...

    async def continue_with_tool_result(self, command: RuntimeContinue) -> None: ...

    async def cancel(self, command: RuntimeCancel) -> None: ...


def validate_action_proposal(proposal: RuntimeActionProposal) -> None:
    if canonical_arguments_hash(proposal.arguments) != proposal.arguments_hash:
        raise RuntimeProtocolError(code="ACTION_ARGUMENTS_HASH_MISMATCH")


def normalize_runtime_error(signal: RuntimeErrorSignal) -> RuntimeEvent:
    event: dict[RuntimeErrorCategory, RuntimeEvent] = {
        "quota": RuntimeQuota(
            run_id=signal.run_id,
            detail=signal.detail,
            created_at=signal.created_at,
        ),
        "reauth_required": RuntimeReauthentication(
            run_id=signal.run_id,
            detail=signal.detail,
            created_at=signal.created_at,
        ),
        "cancelled": RuntimeTerminal(
            run_id=signal.run_id,
            outcome="cancelled",
            detail=signal.detail,
            created_at=signal.created_at,
        ),
        "unavailable": RuntimeTerminal(
            run_id=signal.run_id,
            outcome="unavailable",
            detail=signal.detail,
            created_at=signal.created_at,
        ),
        "failed": RuntimeTerminal(
            run_id=signal.run_id,
            outcome="failed",
            detail=signal.detail,
            created_at=signal.created_at,
        ),
    }
    return event[signal.category]
