from dataclasses import dataclass
from typing import Final, Literal, override

from science_workbench_contracts.common import UtcTimestamp, Uuid7

from .models import (
    ProtocolModel,
    RunAggregate,
    RunEvent,
    RunRecord,
    RunStatus,
)

RUN_TRANSITIONS: Final[dict[RunStatus, frozenset[RunStatus]]] = {
    "queued": frozenset({"running", "failed", "cancelled"}),
    "running": frozenset(
        {"awaiting_user", "awaiting_approval", "completed", "failed", "cancelled"}
    ),
    "awaiting_user": frozenset({"running", "failed", "cancelled"}),
    "awaiting_approval": frozenset({"running", "failed", "cancelled"}),
    "completed": frozenset(),
    "failed": frozenset(),
    "cancelled": frozenset(),
}
TERMINAL_RUN_STATUSES: Final[frozenset[RunStatus]] = frozenset(
    {"completed", "failed", "cancelled"}
)


@dataclass(frozen=True, slots=True)
class ProtocolTransitionError(Exception):
    code: Literal[
        "INVALID_RUN_TRANSITION",
        "INVALID_EXECUTION_TRANSITION",
        "STALE_ATTEMPT_TOKEN",
        "LEASE_EXPIRED",
        "LEASE_EXECUTION_MISMATCH",
        "RUN_ID_REUSED",
    ]
    current: str
    requested: str
    status_code: Literal[409] = 409

    @override
    def __str__(self) -> str:
        return f"{self.code}: {self.current} -> {self.requested}"


class RunTransitionCommand(ProtocolModel):
    aggregate: RunAggregate
    target: RunStatus
    occurred_at: UtcTimestamp


class RunCommit(ProtocolModel):
    aggregate: RunAggregate
    event: RunEvent | None


class RetryRunCommand(ProtocolModel):
    original: RunRecord
    new_run_id: Uuid7
    occurred_at: UtcTimestamp


class RetryRunResult(ProtocolModel):
    run: RunRecord
    replayed_execution_ids: tuple[Uuid7, ...] = ()


def transition_run(command: RunTransitionCommand) -> RunCommit:
    aggregate = RunAggregate.model_validate(command.aggregate.model_dump())
    current = aggregate.run.status
    if command.target not in RUN_TRANSITIONS[current]:
        raise ProtocolTransitionError(
            code="INVALID_RUN_TRANSITION", current=current, requested=command.target
        )
    run = aggregate.run.model_copy(
        update={"status": command.target, "updated_at": command.occurred_at}
    )
    sequence = aggregate.events[-1].sequence + 1 if aggregate.events else 1
    kind = (
        "run.completed"
        if command.target == "completed"
        else "run.failed"
        if command.target == "failed"
        else "run.status"
    )
    event = RunEvent(
        run_id=run.id,
        sequence=sequence,
        kind=kind,
        data={"status": command.target},
        created_at=command.occurred_at,
    )
    return RunCommit(
        aggregate=RunAggregate(run=run, events=(*aggregate.events, event)),
        event=event,
    )


def cancel_run(aggregate: RunAggregate, occurred_at: UtcTimestamp) -> RunCommit:
    if aggregate.run.status in {"completed", "failed", "cancelled"}:
        return RunCommit(aggregate=aggregate, event=None)
    return transition_run(
        RunTransitionCommand(
            aggregate=aggregate, target="cancelled", occurred_at=occurred_at
        )
    )


def retry_run(command: RetryRunCommand) -> RetryRunResult:
    if command.original.status not in TERMINAL_RUN_STATUSES:
        raise ProtocolTransitionError(
            code="INVALID_RUN_TRANSITION",
            current=command.original.status,
            requested="retry",
        )
    if command.new_run_id == command.original.id:
        raise ProtocolTransitionError(
            code="RUN_ID_REUSED",
            current=str(command.original.id),
            requested="new Run ID",
        )
    run = command.original.model_copy(
        update={
            "id": command.new_run_id,
            "retry_of_run_id": command.original.id,
            "status": "queued",
            "created_at": command.occurred_at,
            "updated_at": command.occurred_at,
        }
    )
    return RetryRunResult(run=run)
