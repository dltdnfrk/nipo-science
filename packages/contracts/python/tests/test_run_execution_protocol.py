from itertools import product
from uuid import UUID

import pytest
from pydantic import ValidationError

from science_workbench_contracts.protocols.execution_state import (
    EXECUTION_TRANSITIONS,
    HEARTBEAT_SECONDS,
    LEASE_SECONDS,
    ExecutionCompletionCommand,
    ExecutionTransitionCommand,
    HeartbeatCommand,
    complete_execution,
    heartbeat_execution,
    lease_execution,
    transition_execution,
)
from science_workbench_contracts.protocols.models import (
    ExecutionRecord,
    ExecutionStatus,
    RunAggregate,
    RunStatus,
)
from science_workbench_contracts.protocols.state import (
    RUN_TRANSITIONS,
    ProtocolTransitionError,
    RetryRunCommand,
    RunTransitionCommand,
    cancel_run,
    retry_run,
    transition_run,
)

from .protocol_fixtures import NOW, execution, later, protocol_fixture, run_aggregate

RUN_CASES = tuple(product(RUN_TRANSITIONS, RUN_TRANSITIONS))
EXECUTION_CASES = tuple(product(EXECUTION_TRANSITIONS, EXECUTION_TRANSITIONS))
OTHER_RUN = UUID("018f47a0-7b9c-7ae1-8def-0123456789ab")


@pytest.mark.parametrize(("current", "target"), RUN_CASES)
def test_run_transition_matrix_is_exhaustive(
    current: RunStatus, target: RunStatus
) -> None:
    # Given: every pair in the closed Run state set.
    command = RunTransitionCommand(
        aggregate=run_aggregate(current), target=target, occurred_at=NOW
    )

    # When/Then: exactly the declared legal edges commit state and event atomically.
    if target in RUN_TRANSITIONS[current]:
        committed = transition_run(command)
        assert committed.aggregate.run.status == target
        assert committed.event == committed.aggregate.events[-1]
    else:
        with pytest.raises(ProtocolTransitionError, match="INVALID_RUN_TRANSITION"):
            _ = transition_run(command)


@pytest.mark.parametrize(("current", "target"), EXECUTION_CASES)
def test_execution_transition_matrix_is_exhaustive(
    current: ExecutionStatus, target: ExecutionStatus
) -> None:
    # Given: every pair in the closed Execution state set.
    current_execution = execution(current)
    if target == "completed":
        current_execution = current_execution.model_copy(
            update={"result_ref": "artifact-version:1"}
        )
    command = ExecutionTransitionCommand(
        execution=current_execution, target=target, occurred_at=NOW
    )

    # When/Then: only declared Execution edges produce a new immutable snapshot.
    if target in EXECUTION_TRANSITIONS[current]:
        assert transition_execution(command).status == target
    else:
        with pytest.raises(
            ProtocolTransitionError, match="INVALID_EXECUTION_TRANSITION"
        ):
            _ = transition_execution(command)


def test_cancel_is_idempotent_when_repeated() -> None:
    # Given: a running Run.
    first = cancel_run(run_aggregate("running"), NOW)

    # When: cancellation is delivered again.
    second = cancel_run(first.aggregate, later(1))

    # Then: no second event or state mutation is produced.
    assert second.event is None
    assert second.aggregate == first.aggregate


def test_retry_creates_new_run_without_replaying_executions() -> None:
    # Given: a failed Run and a distinct server-generated ID.
    original = run_aggregate("failed").run
    new_id = protocol_fixture().approval.id

    # When: retry is requested.
    result = retry_run(
        RetryRunCommand(original=original, new_run_id=new_id, occurred_at=NOW)
    )

    # Then: identity is new, provenance points backward, and side effects are empty.
    assert result.run.id != original.id
    assert result.run.retry_of_run_id == original.id
    assert result.replayed_execution_ids == ()


@pytest.mark.parametrize("status", ["queued", "running"])
def test_retry_rejects_non_terminal_runs(status: RunStatus) -> None:
    # Given: a Run that has not reached an explicit terminal state.
    original = run_aggregate(status).run

    # When/Then: retry cannot fork active or pending work.
    with pytest.raises(ProtocolTransitionError, match="INVALID_RUN_TRANSITION"):
        _ = retry_run(
            RetryRunCommand(
                original=original,
                new_run_id=protocol_fixture().approval.id,
                occurred_at=NOW,
            )
        )


@pytest.mark.parametrize("attack", ["foreign_run", "sequence_gap", "time_reversal"])
def test_run_aggregate_rejects_malformed_event_history(attack: str) -> None:
    # Given: two valid events altered along one aggregate invariant.
    fixture = protocol_fixture()
    first, second = fixture.event_window.events
    if attack == "foreign_run":
        second = second.model_copy(update={"run_id": OTHER_RUN})
    elif attack == "sequence_gap":
        second = second.model_copy(update={"sequence": 3})
    else:
        second = second.model_copy(update={"created_at": first.created_at})
        first = first.model_copy(update={"created_at": later(1)})

    # When/Then: tenant, contiguity, and monotonic time attacks fail closed.
    with pytest.raises(ValidationError):
        _ = RunAggregate.model_validate({"run": fixture.run, "events": (first, second)})


def test_transition_revalidates_an_unsafe_run_aggregate() -> None:
    # Given: an aggregate constructed unsafely with a foreign Run event.
    fixture = protocol_fixture()
    event = fixture.event_window.events[0].model_copy(update={"run_id": OTHER_RUN})
    malformed = RunAggregate.model_construct(run=fixture.run, events=(event,))

    # When/Then: the authoritative transition rejects the malformed history.
    with pytest.raises(ValidationError):
        _ = transition_run(
            RunTransitionCommand(
                aggregate=malformed,
                target="completed",
                occurred_at=NOW,
            )
        )


def test_completed_execution_requires_result_but_failed_may_omit_it() -> None:
    # Given: otherwise valid completed and failed Execution payloads.
    current = execution("running")
    completed = {**current.model_dump(), "status": "completed", "result_ref": None}
    failed = {**current.model_dump(), "status": "failed", "result_ref": None}

    # When/Then: only completed work requires a durable result reference.
    with pytest.raises(ValidationError):
        _ = ExecutionRecord.model_validate(completed)
    assert ExecutionRecord.model_validate(failed).result_ref is None


def test_completion_command_rejects_missing_completed_result() -> None:
    # Given: a live lease and a completion without a durable result reference.
    current = execution("running")

    # When/Then: the command fails at its boundary before transition.
    with pytest.raises(ValidationError):
        _ = ExecutionCompletionCommand(
            execution=current,
            lease=lease_execution(current, NOW),
            attempt_token=current.attempt_token,
            target="completed",
            result_ref=None,
            occurred_at=NOW,
        )


def test_failed_completion_may_omit_result() -> None:
    # Given: a live Execution completing unsuccessfully without an artifact.
    current = execution("running")

    # When: the matching attempt reports failure.
    completed = complete_execution(
        ExecutionCompletionCommand(
            execution=current,
            lease=lease_execution(current, NOW),
            attempt_token=current.attempt_token,
            target="failed",
            result_ref=None,
            occurred_at=NOW,
        )
    )

    # Then: failure is terminal without inventing a result reference.
    assert completed.status == "failed"
    assert completed.result_ref is None


def test_heartbeat_uses_fifteen_second_cadence_and_forty_five_second_lease() -> None:
    # Given: a running Execution lease.
    lease = lease_execution(execution("running"), NOW)

    # When: its prescribed heartbeat arrives.
    renewed = heartbeat_execution(
        HeartbeatCommand(
            lease=lease,
            attempt_token=lease.attempt_token,
            occurred_at=later(HEARTBEAT_SECONDS),
        )
    )

    # Then: ownership extends exactly one 45-second lease window.
    assert LEASE_SECONDS == 45
    assert (renewed.expires_at - renewed.heartbeat_at).total_seconds() == LEASE_SECONDS


def test_stale_attempt_token_cannot_complete_execution() -> None:
    # Given: attempt two owns a running Execution.
    current = execution("running", attempt_token=2)
    command = ExecutionCompletionCommand(
        execution=current,
        lease=lease_execution(current, NOW),
        attempt_token=1,
        target="completed",
        result_ref="artifact-version:1",
        occurred_at=NOW,
    )

    # When/Then: fenced completion rejects attempt one.
    with pytest.raises(
        ProtocolTransitionError, match="STALE_ATTEMPT_TOKEN"
    ) as captured:
        _ = complete_execution(command)
    assert captured.value.status_code == 409


def test_expired_matching_lease_cannot_complete_and_queued_cannot_lease() -> None:
    # Given: a matching-token lease at its exact expiry boundary.
    current = execution("running", attempt_token=2)
    lease = lease_execution(current, NOW)
    command = ExecutionCompletionCommand(
        execution=current,
        lease=lease,
        attempt_token=2,
        target="completed",
        result_ref="artifact-version:1",
        occurred_at=lease.expires_at,
    )

    # When/Then: expiry and leasing non-running work both fail closed.
    with pytest.raises(ProtocolTransitionError, match="LEASE_EXPIRED"):
        _ = complete_execution(command)
    with pytest.raises(ProtocolTransitionError, match="INVALID_EXECUTION_TRANSITION"):
        _ = lease_execution(execution("queued"), NOW)
