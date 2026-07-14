from datetime import timedelta
from typing import Final, Literal, Self

from pydantic import model_validator
from pydantic_core import PydanticCustomError

from science_workbench_contracts.common import NonEmptyText, UtcTimestamp

from .models import (
    COMPLETED_EXECUTION_RESULT_ERROR,
    COMPLETED_EXECUTION_RESULT_MESSAGE,
    ExecutionLease,
    ExecutionRecord,
    ExecutionStatus,
    ProtocolModel,
)
from .state import ProtocolTransitionError

HEARTBEAT_SECONDS: Final = 15
LEASE_SECONDS: Final = 45
EXECUTION_TRANSITIONS: Final[dict[ExecutionStatus, frozenset[ExecutionStatus]]] = {
    "queued": frozenset({"running", "failed", "cancelled"}),
    "running": frozenset({"completed", "failed", "cancelled"}),
    "completed": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}


class ExecutionTransitionCommand(ProtocolModel):
    execution: ExecutionRecord
    target: ExecutionStatus
    occurred_at: UtcTimestamp


class ExecutionCompletionCommand(ProtocolModel):
    execution: ExecutionRecord
    lease: ExecutionLease
    attempt_token: int
    target: Literal["completed", "failed"]
    result_ref: NonEmptyText | None = None
    occurred_at: UtcTimestamp

    @model_validator(mode="after")
    def completed_has_result(self) -> Self:
        if self.target == "completed" and self.result_ref is None:
            raise PydanticCustomError(
                COMPLETED_EXECUTION_RESULT_ERROR,
                COMPLETED_EXECUTION_RESULT_MESSAGE,
            )
        return self


class HeartbeatCommand(ProtocolModel):
    lease: ExecutionLease
    attempt_token: int
    occurred_at: UtcTimestamp


def transition_execution(command: ExecutionTransitionCommand) -> ExecutionRecord:
    current = command.execution.status
    if command.target not in EXECUTION_TRANSITIONS[current]:
        raise ProtocolTransitionError(
            code="INVALID_EXECUTION_TRANSITION",
            current=current,
            requested=command.target,
        )
    return ExecutionRecord.model_validate(
        {
            **command.execution.model_dump(),
            "status": command.target,
            "updated_at": command.occurred_at,
        }
    )


def lease_execution(
    execution: ExecutionRecord, occurred_at: UtcTimestamp
) -> ExecutionLease:
    if execution.status != "running":
        raise ProtocolTransitionError(
            code="INVALID_EXECUTION_TRANSITION",
            current=execution.status,
            requested="lease",
        )
    return ExecutionLease(
        execution_id=execution.id,
        attempt_token=execution.attempt_token,
        heartbeat_at=occurred_at,
        expires_at=occurred_at + timedelta(seconds=LEASE_SECONDS),
    )


def heartbeat_execution(command: HeartbeatCommand) -> ExecutionLease:
    if command.attempt_token != command.lease.attempt_token:
        raise ProtocolTransitionError(
            code="STALE_ATTEMPT_TOKEN",
            current=str(command.lease.attempt_token),
            requested=str(command.attempt_token),
        )
    if command.occurred_at >= command.lease.expires_at:
        raise ProtocolTransitionError(
            code="LEASE_EXPIRED",
            current=command.lease.expires_at.isoformat(),
            requested=command.occurred_at.isoformat(),
        )
    return ExecutionLease(
        execution_id=command.lease.execution_id,
        attempt_token=command.attempt_token,
        heartbeat_at=command.occurred_at,
        expires_at=command.occurred_at + timedelta(seconds=LEASE_SECONDS),
    )


def complete_execution(command: ExecutionCompletionCommand) -> ExecutionRecord:
    if command.lease.execution_id != command.execution.id:
        raise ProtocolTransitionError(
            code="LEASE_EXECUTION_MISMATCH",
            current=str(command.execution.id),
            requested=str(command.lease.execution_id),
        )
    if (
        command.attempt_token != command.execution.attempt_token
        or command.attempt_token != command.lease.attempt_token
    ):
        raise ProtocolTransitionError(
            code="STALE_ATTEMPT_TOKEN",
            current=str(command.execution.attempt_token),
            requested=str(command.attempt_token),
        )
    if command.occurred_at >= command.lease.expires_at:
        raise ProtocolTransitionError(
            code="LEASE_EXPIRED",
            current=command.lease.expires_at.isoformat(),
            requested=command.occurred_at.isoformat(),
        )
    return transition_execution(
        ExecutionTransitionCommand(
            execution=command.execution.model_copy(
                update={"result_ref": command.result_ref}
            ),
            target=command.target,
            occurred_at=command.occurred_at,
        )
    )
