from uuid import UUID

import pytest

from science_workbench_contracts.protocols.approval import (
    ApprovalConsumeCommand,
    ApprovalProtocolError,
    ToolEvaluationContext,
    ToolGrantEvaluationCommand,
    action_plan_digest,
    consume_approval,
    evaluate_tool_grant,
)
from science_workbench_contracts.protocols.approval_store import (
    InMemoryApprovalConsumptionStore,
)

from .protocol_fixtures import NOW, protocol_fixture

SIGNING_KEY = b"test-signing-key"
OTHER_PROJECT = UUID("018f47a0-7b9c-7ae0-8def-0123456789ab")
OTHER_RUN = UUID("018f47a0-7b9c-7ae1-8def-0123456789ab")
OTHER_USER = UUID("018f47a0-7b9c-7ae2-8def-0123456789ab")
OTHER_ORG = UUID("018f47a0-7b9c-7ae3-8def-0123456789ab")
OTHER_APPROVAL = UUID("018f47a0-7b9c-7ae4-8def-0123456789ab")


def test_cross_project_self_digested_plan_and_stale_cas_are_rejected() -> None:
    # Given: a valid approval command plus a self-digested alternate Project plan.
    fixture = protocol_fixture()
    approval = fixture.approval
    command = ApprovalConsumeCommand(
        approval_id=approval.id,
        expected_revision=approval.revision,
        expected_status="approved",
        presented_binding=approval.binding,
        presented_plan=fixture.action_plan,
        signing_key=SIGNING_KEY,
        occurred_at=NOW,
    )
    store = InMemoryApprovalConsumptionStore((approval,))
    consumed = consume_approval(store, command)
    assert consumed.revision == approval.revision + 1
    alternate = fixture.action_plan.model_copy(update={"project_id": OTHER_PROJECT})
    alternate = alternate.model_copy(
        update={"plan_digest": action_plan_digest(alternate)}
    )

    # When/Then: stale CAS and a recomputed alternate plan both fail.
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_REVISION_CONFLICT"):
        _ = consume_approval(store, command)
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_BINDING_MISMATCH"):
        _ = consume_approval(
            InMemoryApprovalConsumptionStore((approval,)),
            ApprovalConsumeCommand(
                approval_id=approval.id,
                expected_revision=approval.revision,
                expected_status="approved",
                presented_binding=approval.binding,
                presented_plan=alternate,
                signing_key=SIGNING_KEY,
                occurred_at=NOW,
            ),
        )


def test_distinct_approval_ids_cannot_consume_one_binding_twice() -> None:
    # Given: one binding was consumed under the first of two Approval IDs.
    fixture = protocol_fixture()
    first = fixture.approval
    second = first.model_copy(update={"id": OTHER_APPROVAL})
    store = InMemoryApprovalConsumptionStore((first, second))
    _ = consume_approval(
        store,
        ApprovalConsumeCommand(
            approval_id=first.id,
            expected_revision=first.revision,
            expected_status="approved",
            presented_binding=first.binding,
            presented_plan=fixture.action_plan,
            signing_key=SIGNING_KEY,
            occurred_at=NOW,
        ),
    )

    # When/Then: the second ID cannot authorize the already-consumed binding.
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_ALREADY_CONSUMED"):
        _ = consume_approval(
            store,
            ApprovalConsumeCommand(
                approval_id=second.id,
                expected_revision=second.revision,
                expected_status="approved",
                presented_binding=second.binding,
                presented_plan=fixture.action_plan,
                signing_key=SIGNING_KEY,
                occurred_at=NOW,
            ),
        )


def test_approval_store_rejects_duplicate_record_ids() -> None:
    # Given: conflicting snapshots for the same Approval ID.
    approval = protocol_fixture().approval
    consumed = approval.model_copy(update={"status": "consumed", "digest": "e" * 64})

    # When/Then: initialization fails closed instead of silently choosing one.
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_DUPLICATE_ID"):
        _ = InMemoryApprovalConsumptionStore((consumed, approval))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("org_id", OTHER_ORG),
        ("project_id", OTHER_PROJECT),
        ("run_id", OTHER_RUN),
        ("requester_id", OTHER_USER),
    ],
)
def test_tool_grant_rejects_cross_context(field: str, value: UUID) -> None:
    # Given: a valid plan evaluated under a mismatched authority context.
    fixture = protocol_fixture()
    context = ToolEvaluationContext(
        org_id=fixture.run.org_id,
        project_id=fixture.action_plan.project_id,
        run_id=fixture.run.id,
        requester_id=fixture.run.requester_id,
    ).model_copy(update={field: value})

    # When/Then: grant evaluation rejects the context before authorization.
    with pytest.raises(ApprovalProtocolError, match="TOOL_GRANT_MISMATCH"):
        _ = evaluate_tool_grant(
            ToolGrantEvaluationCommand(
                grant=fixture.tool_grant,
                plan=fixture.action_plan,
                context=context,
            )
        )
