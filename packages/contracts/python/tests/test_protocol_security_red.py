from dataclasses import fields
from uuid import UUID

import pytest
from pydantic import ValidationError

from science_workbench_contracts.protocols.approval import ApprovalConsumeCommand
from science_workbench_contracts.protocols.execution_state import (
    ExecutionCompletionCommand,
)
from science_workbench_contracts.protocols.models import ApprovalBinding, RunEvent
from science_workbench_contracts.protocols.runtime import (
    RuntimeCancel,
    RuntimeContinue,
    RuntimeTerminal,
)

from .protocol_fixtures import protocol_fixture

PLACEHOLDER_TOKEN = "x" * 24


def test_security_review_requires_bound_cas_and_lease_fields() -> None:
    # Given: the security review's required protocol fields.
    approval_fields = set(ApprovalBinding.model_fields)
    consume_fields = {field.name for field in fields(ApprovalConsumeCommand)}
    completion_fields = set(ExecutionCompletionCommand.model_fields)
    continuation_fields = set(RuntimeContinue.model_fields)

    # When/Then: plan binding, CAS, lease, and correlation fields all exist.
    assert {"project_id", "action_plan_id", "plan_digest"} <= approval_fields
    assert {"approval_id", "expected_revision", "expected_status"} <= consume_fields
    assert "lease" in completion_fields
    assert {"org_id", "message_id", "action_id", "execution_id"} <= continuation_fields


def test_security_review_rejects_cross_run_fixture() -> None:
    # Given: a valid fixture with a cross-Run Message reference.
    fixture = protocol_fixture()
    other_run = UUID("018f47a0-7b9c-7aff-8def-0123456789ab")
    message = fixture.messages[0].model_copy(update={"run_id": other_run})

    # When/Then: aggregate correlation fails closed.
    with pytest.raises(ValidationError):
        _ = type(fixture).model_validate(
            {**fixture.model_dump(), "messages": (message,)}
        )


@pytest.mark.parametrize(
    "key",
    [
        "cost",
        "estimatedCostUsd",
        'cost"marker',
        "fallback_provider_connection_id",
        "providerFallback",
        'provider"fallback',
        'fallback"provider',
        "Authorization",
        "proxy-authorization",
        "access_token",
        "refresh.token",
        "api-key",
        "X API KEY",
        "cookie",
        "Set_Cookie",
        "client.secret",
        "bearer-token",
        "service_token",
        "db-credentials",
        "password",
        "db-password",
        "PASSWD",
        "user.passwd",
        "secret",
        "build-secret",
        "private_key",
        "signing.private-key",
        "client_password",
        "ssh-private-key",
        "password.value",
        "secret.value",
        "private_key_pem",
        "passwordless_secret",
        "secretory_password",
        "\uff43\uff4f\uff53\uff54",
        "\uff50\uff52\uff4f\uff56\uff49\uff44\uff45\uff52\uff3f\uff46\uff41\uff4c\uff4c\uff42\uff41\uff43\uff4b",
        "\uff50\uff41\uff53\uff53\uff57\uff4f\uff52\uff44",
        "\uff41\uff50\uff49\uff3f\uff4b\uff45\uff59",
    ],
)
def test_security_review_rejects_nested_forbidden_event_key(key: str) -> None:
    # Given: monetary or provider-fallback semantics nested in event data.
    event = protocol_fixture().event_window.events[0]

    # When/Then: recursive event-data validation fails closed.
    with pytest.raises(ValidationError):
        _ = RunEvent.model_validate(
            {**event.model_dump(), "data": {"result": [{key: "<redacted>"}]}}
        )


@pytest.mark.parametrize(
    "key",
    [
        "tokenization_method",
        "secretory_pathway",
        "secretome_score",
        "passwordless_method",
        "\uff53\uff45\uff43\uff52\uff45\uff54\uff4f\uff52\uff59\uff3f\uff50\uff41\uff54\uff48\uff57\uff41\uff59",
        "\ub2e8\ubc31\uc9c8_\ub18d\ub3c4",
        "refresh_rate",
    ],
)
def test_security_review_allows_benign_scientific_event_key(key: str) -> None:
    # Given: a scientific field whose name is not credential material.
    event = protocol_fixture().event_window.events[0]

    # When/Then: recursive security validation preserves the benign data.
    parsed = RunEvent.model_validate(
        {**event.model_dump(), "data": {"analysis": [{key: "measured"}]}}
    )
    assert parsed.model_dump(mode="json")["data"] == {
        "analysis": [{key: "measured"}]
    }


@pytest.mark.parametrize(
    "value",
    [
        f"Bearer {PLACEHOLDER_TOKEN}",
        f"Authorization: Basic {'eHh4' * 6}",
        f"client_secret={PLACEHOLDER_TOKEN}",
        f"api-key: {PLACEHOLDER_TOKEN}",
        f"sk-{PLACEHOLDER_TOKEN}",
        f"ghp_{PLACEHOLDER_TOKEN}",
        "AKIA" + ("A" * 16),
        ("-" * 5) + "BEGIN PRIVATE KEY" + ("-" * 5),
        "\uff22\uff45\uff41\uff52\uff45\uff52 " + PLACEHOLDER_TOKEN,
    ],
)
def test_security_review_rejects_nested_secret_shaped_value(value: str) -> None:
    # Given: credential-shaped scalar material under a neutral nested key.
    event = protocol_fixture().event_window.events[0]

    # When/Then: recursive value validation rejects the scalar.
    with pytest.raises(ValidationError):
        _ = RunEvent.model_validate(
            {**event.model_dump(), "data": {"analysis": [{"message": value}]}}
        )


@pytest.mark.parametrize(
    "value",
    [
        "Ordinary scientific prose about secretory pathways.",
        "Bearer <redacted>",
        "client_secret=<redacted>",
        "sk-short",
        f"https://example.test/sk-{PLACEHOLDER_TOKEN}",
        "a" * 64,
        "018f47a0-7b9c-7abe-8def-0123456789ab",
        f"error: invalid sk-{PLACEHOLDER_TOKEN}",
    ],
)
def test_security_review_allows_benign_secret_like_value(value: str) -> None:
    # Given: benign prose, placeholders, identifiers, or error text.
    event = protocol_fixture().event_window.events[0]

    # When/Then: value validation preserves the scalar unchanged.
    parsed = RunEvent.model_validate(
        {**event.model_dump(), "data": {"analysis": [{"message": value}]}}
    )
    assert parsed.model_dump(mode="json")["data"] == {
        "analysis": [{"message": value}]
    }


def test_strict_wire_defaults_and_review_finding_event_are_aligned() -> None:
    # Given: strict numeric input, omitted nullable/default fields, and finding data.
    fixture = protocol_fixture()
    event = fixture.event_window.events[0]
    plan_data = fixture.action_plan.model_dump(
        exclude={"network_scope", "secret_scope"}
    )

    # When/Then: coercion fails while shared defaults and review event parse.
    with pytest.raises(ValidationError):
        _ = RunEvent.model_validate({**event.model_dump(), "sequence": "7"})
    plan = type(fixture.action_plan).model_validate(plan_data)
    cancel = RuntimeCancel.model_validate({"run_id": fixture.run.id})
    terminal = RuntimeTerminal.model_validate(
        {
            "run_id": fixture.run.id,
            "outcome": "failed",
            "created_at": fixture.run.updated_at,
        }
    )
    finding = RunEvent.model_validate({**event.model_dump(), "kind": "review.finding"})
    assert plan.network_scope == ()
    assert plan.secret_scope == ()
    assert cancel.reason is None
    assert terminal.detail is None
    assert finding.kind == "review.finding"


def test_runtime_continuation_rejects_cross_execution_and_fixture_org() -> None:
    # Given: mismatched continuation result and Execution organization references.
    fixture = protocol_fixture()
    other_id = UUID("018f47a0-7b9c-7afe-8def-0123456789ab")
    continuation = fixture.runtime_continuation
    result = continuation.result.model_copy(update={"execution_id": other_id})
    execution = fixture.execution.model_copy(update={"org_id": other_id})

    # When/Then: command-local and aggregate correlations both reject.
    with pytest.raises(ValidationError):
        _ = RuntimeContinue.model_validate(
            {**continuation.model_dump(), "result": result}
        )
    with pytest.raises(ValidationError):
        _ = type(fixture).model_validate(
            {**fixture.model_dump(), "execution": execution}
        )


@pytest.mark.parametrize("field", ["org_id", "run_id", "message_id", "action_id"])
def test_runtime_continuation_rejects_foreign_context(field: str) -> None:
    # Given: a continuation whose command context differs from its application result.
    continuation = protocol_fixture().runtime_continuation
    other_id = UUID("018f47a0-7b9c-7afe-8def-0123456789ab")

    # When/Then: every cross-context continuation fails at its own boundary.
    with pytest.raises(ValidationError, match="runtime command references"):
        _ = RuntimeContinue.model_validate(
            continuation.model_copy(update={field: other_id}).model_dump()
        )


def test_fixture_rejects_text_delta_for_unknown_message() -> None:
    # Given: a text delta referring to a Message outside the fixture.
    fixture = protocol_fixture()
    delta = fixture.runtime_events[0].model_copy(
        update={"message_id": fixture.approval.id}
    )

    # When/Then: aggregate runtime-to-Message correlation fails closed.
    with pytest.raises(ValidationError, match="protocol fixture references"):
        _ = type(fixture).model_validate(
            {
                **fixture.model_dump(),
                "runtime_events": (delta, *fixture.runtime_events[1:]),
            }
        )
