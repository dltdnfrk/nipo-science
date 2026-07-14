from typing import Annotated, Final, Literal, Self

from pydantic import Field, model_validator
from pydantic_core import PydanticCustomError

from science_workbench_contracts.common import UtcTimestamp, Uuid7

from .models import ProtocolModel, RunEvent

RUN_EVENT_TENANT_ERROR: Final = "run_event_tenant"
RUN_EVENT_TENANT_MESSAGE: Final = "all events must belong to the replay Run"
RUN_EVENT_ORDER_ERROR: Final = "run_event_order"
RUN_EVENT_ORDER_MESSAGE: Final = "event sequence must be unique and increasing"
RUN_EVENT_RETENTION_ERROR: Final = "run_event_retention"
RUN_EVENT_RETENTION_MESSAGE: Final = "events precede the retained sequence"


class RunEventWindow(ProtocolModel):
    run_id: Uuid7
    oldest_available_sequence: Annotated[int, Field(ge=1)]
    retention_expires_at: UtcTimestamp
    events: tuple[RunEvent, ...]

    @model_validator(mode="after")
    def ordered_for_one_run(self) -> Self:
        sequences = tuple(event.sequence for event in self.events)
        if any(event.run_id != self.run_id for event in self.events):
            raise PydanticCustomError(RUN_EVENT_TENANT_ERROR, RUN_EVENT_TENANT_MESSAGE)
        if sequences != tuple(sorted(set(sequences))):
            raise PydanticCustomError(RUN_EVENT_ORDER_ERROR, RUN_EVENT_ORDER_MESSAGE)
        if sequences and sequences[0] < self.oldest_available_sequence:
            raise PydanticCustomError(
                RUN_EVENT_RETENTION_ERROR, RUN_EVENT_RETENTION_MESSAGE
            )
        return self


class ReplayRequest(ProtocolModel):
    last_event_id: Annotated[int, Field(ge=0)]
    occurred_at: UtcTimestamp


class ReplayBatch(ProtocolModel):
    status_code: Literal[200] = 200
    events: tuple[RunEvent, ...]


class ReplayExpired(ProtocolModel):
    status_code: Literal[410] = 410
    run_id: Uuid7
    recovery: Literal["GET_RUN"] = "GET_RUN"


class ReplayCursorError(ProtocolModel):
    status_code: Literal[409] = 409
    code: Literal["INVALID_LAST_EVENT_ID"] = "INVALID_LAST_EVENT_ID"


type ReplayResult = ReplayBatch | ReplayExpired | ReplayCursorError


def replay_events(window: RunEventWindow, request: ReplayRequest) -> ReplayResult:
    if request.occurred_at >= window.retention_expires_at:
        return ReplayExpired(run_id=window.run_id)
    if request.last_event_id < window.oldest_available_sequence - 1:
        return ReplayExpired(run_id=window.run_id)
    latest = window.events[-1].sequence if window.events else 0
    if request.last_event_id > latest:
        return ReplayCursorError()
    return ReplayBatch(
        events=tuple(
            event for event in window.events if event.sequence > request.last_event_id
        )
    )
