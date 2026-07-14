from pathlib import Path
from typing import Literal

import pytest
from pydantic import ValidationError

from science_workbench_contracts.protocols.fixture import ProtocolFixture
from science_workbench_contracts.protocols.runtime import (
    AgentRuntimeAdapter,
    RuntimeActionProposal,
    RuntimeErrorCategory,
    RuntimeErrorSignal,
    RuntimeProtocolError,
    RuntimeQuota,
    RuntimeReauthentication,
    RuntimeTerminal,
    normalize_runtime_error,
    validate_action_proposal,
)
from science_workbench_contracts.protocols.sse import (
    ReplayBatch,
    ReplayExpired,
    ReplayRequest,
    RunEventWindow,
    replay_events,
)
from science_workbench_contracts.protocols.state import (
    RunTransitionCommand,
    transition_run,
)

from .protocol_fixtures import FIXTURE_PATH, NOW, later, protocol_fixture, run_aggregate


def test_shared_runtime_fixture_round_trips_through_pydantic() -> None:
    # Given: the cross-language Run/runtime JSON fixture.
    raw = FIXTURE_PATH.read_text(encoding="utf-8")

    # When: Pydantic parses, serializes, and reparses the boundary.
    parsed = ProtocolFixture.model_validate_json(raw)
    reparsed = ProtocolFixture.model_validate_json(parsed.model_dump_json())

    # Then: all immutable protocol records survive exactly.
    assert reparsed == parsed


def test_transactional_transitions_append_strictly_monotonic_events() -> None:
    # Given: a queued aggregate and a complete legal lifecycle.
    aggregate = run_aggregate("queued")
    lifecycle = ("running", "awaiting_user", "running", "completed")

    # When: each compare-and-swap transition commits.
    for offset, target in enumerate(lifecycle, start=1):
        aggregate = transition_run(
            RunTransitionCommand(
                aggregate=aggregate, target=target, occurred_at=later(offset)
            )
        ).aggregate

    # Then: each state change owns one increasing event in the same snapshot.
    assert tuple(event.sequence for event in aggregate.events) == (1, 2, 3, 4)
    assert aggregate.events[-1].kind == "run.completed"


@pytest.mark.parametrize("size", range(1, 33))
def test_event_window_accepts_every_increasing_sequence_prefix(size: int) -> None:
    # Given: a generated monotonic event prefix.
    fixture = protocol_fixture()
    first = fixture.event_window.events[0]
    events = tuple(
        first.model_copy(update={"sequence": sequence})
        for sequence in range(1, size + 1)
    )

    # When: the boundary parses the event window.
    window = RunEventWindow(
        run_id=fixture.run.id,
        oldest_available_sequence=1,
        retention_expires_at=fixture.event_window.retention_expires_at,
        events=events,
    )

    # Then: the sequence property is preserved.
    assert len(window.events) == size


@pytest.mark.parametrize("sequences", [(2, 1), (1, 1), (3, 2, 4)])
def test_event_window_rejects_illegal_ordering(sequences: tuple[int, ...]) -> None:
    # Given: duplicate or decreasing event sequences.
    fixture = protocol_fixture()
    first = fixture.event_window.events[0]
    events = tuple(first.model_copy(update={"sequence": value}) for value in sequences)

    # When/Then: boundary parsing fails closed.
    with pytest.raises(ValidationError, match="unique and increasing"):
        _ = RunEventWindow(
            run_id=fixture.run.id,
            oldest_available_sequence=1,
            retention_expires_at=fixture.event_window.retention_expires_at,
            events=events,
        )


@pytest.mark.parametrize(("cursor", "expected"), [(0, (1, 2)), (1, (2,)), (2, ())])
def test_last_event_id_replays_strictly_after_cursor(
    cursor: int, expected: tuple[int, ...]
) -> None:
    # Given: durable events and every valid Last-Event-ID boundary.
    window = protocol_fixture().event_window

    # When: SSE reconnect requests replay.
    result = replay_events(window, ReplayRequest(last_event_id=cursor, occurred_at=NOW))

    # Then: no Run is created and only later events are returned.
    assert isinstance(result, ReplayBatch)
    assert tuple(event.sequence for event in result.events) == expected


def test_expired_replay_returns_410_get_run_recovery() -> None:
    # Given: a request after durable event retention expired.
    window = protocol_fixture().event_window
    request = ReplayRequest(last_event_id=0, occurred_at=window.retention_expires_at)

    # When: replay is attempted.
    result = replay_events(window, request)

    # Then: the client receives 410 and terminal recovery direction.
    assert isinstance(result, ReplayExpired)
    assert result.status_code == 410
    assert result.recovery == "GET_RUN"


@pytest.mark.parametrize(
    ("category", "event_type", "outcome"),
    [
        ("quota", RuntimeQuota, None),
        ("reauth_required", RuntimeReauthentication, None),
        ("cancelled", RuntimeTerminal, "cancelled"),
        ("unavailable", RuntimeTerminal, "unavailable"),
        ("failed", RuntimeTerminal, "failed"),
    ],
)
def test_provider_errors_normalize_to_stable_neutral_events(
    category: RuntimeErrorCategory,
    event_type: type[RuntimeQuota | RuntimeReauthentication | RuntimeTerminal],
    outcome: Literal["cancelled", "unavailable", "failed"] | None,
) -> None:
    # Given: each provider-neutral adapter error category.
    run_id = protocol_fixture().run.id
    signal = RuntimeErrorSignal(
        run_id=run_id, category=category, detail="runtime signal", created_at=NOW
    )

    # When: the runtime boundary normalizes it.
    event = normalize_runtime_error(signal)

    # Then: stable quota, reauth, or terminal semantics are emitted.
    assert isinstance(event, event_type)
    if isinstance(event, RuntimeTerminal):
        assert event.outcome == outcome


def test_action_proposal_hash_mutation_fails_before_application_execution() -> None:
    # Given: a parsed action proposal with mutated arguments.
    proposal = protocol_fixture().runtime_events[1]
    assert isinstance(proposal, RuntimeActionProposal)
    mutated = proposal.model_copy(update={"arguments": {"query": "changed"}})

    # When/Then: canonical hash verification rejects the proposal.
    with pytest.raises(RuntimeProtocolError, match="ACTION_ARGUMENTS_HASH_MISMATCH"):
        validate_action_proposal(mutated)


def test_runtime_adapter_has_no_tool_execution_capability_or_monetary_fields() -> None:
    # Given: the provider-neutral adapter protocol and shared fixture.
    adapter_surface = set(AgentRuntimeAdapter.__dict__)
    raw = Path(FIXTURE_PATH).read_text(encoding="utf-8")

    # When/Then: providers can start, continue, cancel, but never execute tools.
    assert {"start", "continue_with_tool_result", "cancel"} <= adapter_surface
    assert "execute_tool" not in adapter_surface
    assert "cost" not in raw.lower()
