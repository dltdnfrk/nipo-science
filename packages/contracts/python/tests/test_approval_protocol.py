from datetime import datetime
from itertools import product
from uuid import UUID

import pytest
from pydantic import ValidationError

from science_workbench_contracts.protocols.approval import (
    APPROVAL_TRANSITIONS,
    ApprovalActor,
    ApprovalConsumeCommand,
    ApprovalDecisionCommand,
    ApprovalProtocolError,
    ToolAllowed,
    ToolApprovalRequired,
    ToolDenied,
    ToolEvaluationContext,
    ToolGrantEvaluationCommand,
    approval_digest,
    canonical_arguments_hash,
    consume_approval,
    decide_approval,
    ensure_approval_transition,
    evaluate_tool_grant,
)
from science_workbench_contracts.protocols.approval_store import (
    InMemoryApprovalConsumptionStore,
)
from science_workbench_contracts.protocols.models import ApprovalStatus, ToolGrantEffect

from .protocol_fixtures import NOW, later, protocol_fixture

SIGNING_KEY = b"test-signing-key"
OTHER_ORG = UUID("018f47a0-7b9c-7ae0-8def-0123456789ab")
OTHER_RUN = UUID("018f47a0-7b9c-7ae1-8def-0123456789ab")
OTHER_USER = UUID("018f47a0-7b9c-7ae2-8def-0123456789ab")
type BindingMutation = UUID | str | tuple[str, ...] | datetime
APPROVAL_CASES = tuple(product(APPROVAL_TRANSITIONS, APPROVAL_TRANSITIONS))


@pytest.mark.parametrize(("current", "target"), APPROVAL_CASES)
def test_approval_transition_matrix_is_exhaustive(
    current: ApprovalStatus, target: ApprovalStatus
) -> None:
    # Given: every pair in the closed Approval state set.
    is_legal = target in APPROVAL_TRANSITIONS[current]

    # When/Then: exactly the declared Approval edges are accepted.
    if is_legal:
        ensure_approval_transition(current, target)
    else:
        with pytest.raises(ApprovalProtocolError, match="INVALID_APPROVAL_TRANSITION"):
            ensure_approval_transition(current, target)


def test_canonical_arguments_hash_is_order_independent_for_json_objects() -> None:
    # Given: many equivalent objects built in opposite insertion orders.
    pairs = tuple((index, f"value-{index}") for index in range(64))

    # When: each pair is canonicalized in both orders.
    hashes = tuple(
        (
            canonical_arguments_hash({"number": number, "text": text}),
            canonical_arguments_hash({"text": text, "number": number}),
        )
        for number, text in pairs
    )

    # Then: ordering never changes the canonical digest.
    assert all(left == right for left, right in hashes)


@pytest.mark.parametrize(
    ("effect", "result_type"),
    [
        ("allow", ToolAllowed),
        ("ask", ToolApprovalRequired),
        ("deny", ToolDenied),
    ],
)
def test_tool_grant_effects_are_closed_and_side_effect_free(
    effect: ToolGrantEffect,
    result_type: type[ToolAllowed | ToolApprovalRequired | ToolDenied],
) -> None:
    # Given: an immutable valid ActionPlan and each Tool Grant effect.
    fixture = protocol_fixture()
    grant = fixture.tool_grant.model_copy(update={"effect": effect})
    context = ToolEvaluationContext(
        org_id=fixture.run.org_id,
        project_id=fixture.action_plan.project_id,
        run_id=fixture.run.id,
        requester_id=fixture.run.requester_id,
    )

    # When: application policy evaluates the proposal.
    result = evaluate_tool_grant(
        ToolGrantEvaluationCommand(
            grant=grant, plan=fixture.action_plan, context=context
        )
    )

    # Then: policy returns authorization only and creates no Execution record.
    assert isinstance(result, result_type)
    assert not hasattr(result, "execution_id")


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("org_id", OTHER_ORG),
        ("project_id", OTHER_ORG),
        ("run_id", OTHER_RUN),
        ("requester_id", OTHER_USER),
        ("action_plan_id", OTHER_RUN),
        ("plan_digest", "e" * 64),
        ("tool", "python.execute"),
        ("arguments_hash", "f" * 64),
        ("network_scope", ("example.test",)),
        ("secret_scope", ("credential:1",)),
        ("expires_at", later(5000)),
    ],
)
def test_approval_digest_rejects_every_bound_field_mutation(
    field: str, value: BindingMutation
) -> None:
    # Given: an approved exact one-use binding.
    fixture = protocol_fixture()
    approval = fixture.approval
    mutated = approval.binding.model_copy(update={field: value})

    # When/Then: any bound-field mutation invalidates consumption.
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_BINDING_MISMATCH"):
        _ = consume_approval(
            InMemoryApprovalConsumptionStore((approval,)),
            ApprovalConsumeCommand(
                approval_id=approval.id,
                expected_revision=approval.revision,
                expected_status="approved",
                presented_binding=mutated,
                presented_plan=fixture.action_plan,
                signing_key=SIGNING_KEY,
                occurred_at=NOW,
            ),
        )


def test_approval_replay_and_expiry_are_rejected() -> None:
    # Given: one exact approval is consumed once.
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
    assert consumed.status == "consumed"

    # When/Then: replay and expiry each fail before creating an Execution.
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_REVISION_CONFLICT"):
        _ = consume_approval(store, command)
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_EXPIRED"):
        _ = consume_approval(
            InMemoryApprovalConsumptionStore((approval,)),
            ApprovalConsumeCommand(
                approval_id=approval.id,
                expected_revision=approval.revision,
                expected_status="approved",
                presented_binding=approval.binding,
                presented_plan=fixture.action_plan,
                signing_key=SIGNING_KEY,
                occurred_at=later(4000),
            ),
        )


def test_approval_digest_mutation_is_rejected() -> None:
    # Given: an approved record whose stored digest was changed.
    fixture = protocol_fixture()
    approval = fixture.approval.model_copy(update={"digest": "f" * 64})

    # When/Then: digest verification rejects it before Execution creation.
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_DIGEST_MISMATCH"):
        _ = consume_approval(
            InMemoryApprovalConsumptionStore((approval,)),
            ApprovalConsumeCommand(
                approval_id=approval.id,
                expected_revision=approval.revision,
                expected_status="approved",
                presented_binding=approval.binding,
                presented_plan=fixture.action_plan,
                signing_key=SIGNING_KEY,
                occurred_at=NOW,
            ),
        )


def test_cross_tenant_actor_cannot_approve() -> None:
    # Given: a pending request and an actor from another organization.
    fixture = protocol_fixture()
    pending = fixture.approval.model_copy(update={"status": "pending"})
    actor = ApprovalActor(org_id=OTHER_ORG, user_id=OTHER_USER, role="owner")

    # When/Then: cross-tenant approval is rejected.
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_ACTOR_FORBIDDEN"):
        _ = decide_approval(
            ApprovalDecisionCommand(
                approval=pending, actor=actor, decision="approved", occurred_at=NOW
            )
        )


def test_owner_may_reject_but_never_approve_another_requester() -> None:
    # Given: a same-tenant Owner who is not the requester.
    fixture = protocol_fixture()
    pending = fixture.approval.model_copy(update={"status": "pending"})
    actor = ApprovalActor(
        org_id=pending.binding.org_id, user_id=OTHER_USER, role="owner"
    )

    # When: the Owner rejects the request.
    rejected = decide_approval(
        ApprovalDecisionCommand(
            approval=pending, actor=actor, decision="rejected", occurred_at=NOW
        )
    )

    # Then: rejection succeeds while approval remains forbidden.
    assert rejected.status == "rejected"
    with pytest.raises(ApprovalProtocolError, match="APPROVAL_ACTOR_FORBIDDEN"):
        _ = decide_approval(
            ApprovalDecisionCommand(
                approval=pending, actor=actor, decision="approved", occurred_at=NOW
            )
        )


def test_action_plan_and_approval_are_frozen_and_digest_verified() -> None:
    # Given: parsed immutable protocol records.
    fixture = protocol_fixture()

    # When/Then: mutation is blocked and the approval digest is exact.
    with pytest.raises(ValidationError):
        fixture.action_plan.version = 2
    assert (
        approval_digest(fixture.approval.binding, SIGNING_KEY)
        == fixture.approval.digest
    )
