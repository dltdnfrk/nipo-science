import hashlib
import hmac
import json
from dataclasses import dataclass
from typing import Final, Literal, Protocol, override

from pydantic import JsonValue

from science_workbench_contracts.common import UtcTimestamp, Uuid7

from .models import (
    ActionPlan,
    ApprovalBinding,
    ApprovalRecord,
    ApprovalStatus,
    ProtocolModel,
    ToolGrant,
    ToolGrantEffect,
)

APPROVAL_TRANSITIONS: Final[dict[ApprovalStatus, frozenset[ApprovalStatus]]] = {
    "pending": frozenset({"approved", "rejected", "expired"}),
    "approved": frozenset({"consumed", "expired"}),
    "rejected": frozenset(),
    "expired": frozenset(),
    "consumed": frozenset(),
}


@dataclass(frozen=True, slots=True)
class ApprovalProtocolError(Exception):
    code: Literal[
        "INVALID_APPROVAL_TRANSITION",
        "APPROVAL_ACTOR_FORBIDDEN",
        "APPROVAL_EXPIRED",
        "APPROVAL_BINDING_MISMATCH",
        "APPROVAL_DIGEST_MISMATCH",
        "APPROVAL_ID_MISMATCH",
        "APPROVAL_DUPLICATE_ID",
        "APPROVAL_REVISION_CONFLICT",
        "APPROVAL_ALREADY_CONSUMED",
        "ACTION_PLAN_MUTATED",
        "TOOL_GRANT_MISMATCH",
    ]

    @override
    def __str__(self) -> str:
        return self.code


class ApprovalActor(ProtocolModel):
    org_id: Uuid7
    user_id: Uuid7
    role: Literal["owner", "member"]


class ApprovalDecisionCommand(ProtocolModel):
    approval: ApprovalRecord
    actor: ApprovalActor
    decision: Literal["approved", "rejected"]
    occurred_at: UtcTimestamp


@dataclass(frozen=True, slots=True)
class ApprovalConsumeCommand:
    approval_id: Uuid7
    expected_revision: int
    expected_status: Literal["approved"]
    presented_binding: ApprovalBinding
    presented_plan: ActionPlan
    signing_key: bytes
    occurred_at: UtcTimestamp


class ApprovalConsumptionStore(Protocol):
    def compare_and_consume(
        self, command: ApprovalConsumeCommand
    ) -> ApprovalRecord: ...


class ToolEvaluationContext(ProtocolModel):
    org_id: Uuid7
    project_id: Uuid7
    run_id: Uuid7
    requester_id: Uuid7


class ToolGrantEvaluationCommand(ProtocolModel):
    grant: ToolGrant
    plan: ActionPlan
    context: ToolEvaluationContext


@dataclass(frozen=True, slots=True)
class ToolAllowed:
    action_plan_id: Uuid7
    executor: Literal["application"] = "application"


@dataclass(frozen=True, slots=True)
class ToolApprovalRequired:
    action_plan_id: Uuid7


@dataclass(frozen=True, slots=True)
class ToolDenied:
    action_plan_id: Uuid7


type ToolAuthorization = ToolAllowed | ToolApprovalRequired | ToolDenied


def ensure_approval_transition(current: ApprovalStatus, target: ApprovalStatus) -> None:
    if target not in APPROVAL_TRANSITIONS[current]:
        raise ApprovalProtocolError(code="INVALID_APPROVAL_TRANSITION")


def canonical_arguments_hash(arguments: JsonValue) -> str:
    encoded = json.dumps(
        arguments,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(encoded).hexdigest()


def approval_digest(binding: ApprovalBinding, signing_key: bytes) -> str:
    payload = binding.model_dump_json().encode()
    return hmac.new(signing_key, payload, hashlib.sha256).hexdigest()


def action_plan_digest(plan: ActionPlan) -> str:
    payload = json.dumps(
        plan.model_dump(mode="json", exclude={"plan_digest"}),
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    return hashlib.sha256(payload).hexdigest()


def evaluate_tool_grant(command: ToolGrantEvaluationCommand) -> ToolAuthorization:
    grant = command.grant
    plan = command.plan
    context = command.context
    grant_context = (grant.org_id, grant.project_id)
    plan_context = (plan.org_id, plan.project_id, plan.run_id, plan.requester_id)
    expected_grant_context = (context.org_id, context.project_id)
    expected_plan_context = (
        context.org_id,
        context.project_id,
        context.run_id,
        context.requester_id,
    )
    if (
        grant_context != expected_grant_context
        or plan_context != expected_plan_context
        or grant.tool != plan.tool
    ):
        raise ApprovalProtocolError(code="TOOL_GRANT_MISMATCH")
    if canonical_arguments_hash(plan.arguments) != plan.arguments_hash:
        raise ApprovalProtocolError(code="ACTION_PLAN_MUTATED")
    if action_plan_digest(plan) != plan.plan_digest:
        raise ApprovalProtocolError(code="ACTION_PLAN_MUTATED")
    authorization: dict[ToolGrantEffect, ToolAuthorization] = {
        "allow": ToolAllowed(action_plan_id=plan.id),
        "ask": ToolApprovalRequired(action_plan_id=plan.id),
        "deny": ToolDenied(action_plan_id=plan.id),
    }
    return authorization[grant.effect]


def binding_for_plan(plan: ActionPlan, expires_at: UtcTimestamp) -> ApprovalBinding:
    return ApprovalBinding(
        org_id=plan.org_id,
        project_id=plan.project_id,
        run_id=plan.run_id,
        requester_id=plan.requester_id,
        action_plan_id=plan.id,
        plan_digest=plan.plan_digest,
        tool=plan.tool,
        arguments_hash=plan.arguments_hash,
        network_scope=plan.network_scope,
        secret_scope=plan.secret_scope,
        expires_at=expires_at,
    )


def decide_approval(command: ApprovalDecisionCommand) -> ApprovalRecord:
    approval = command.approval
    ensure_approval_transition(approval.status, command.decision)
    if command.occurred_at >= approval.binding.expires_at:
        raise ApprovalProtocolError(code="APPROVAL_EXPIRED")
    if command.actor.org_id != approval.binding.org_id:
        raise ApprovalProtocolError(code="APPROVAL_ACTOR_FORBIDDEN")
    requester = command.actor.user_id == approval.binding.requester_id
    owner_rejection = command.actor.role == "owner" and command.decision == "rejected"
    if not requester and not owner_rejection:
        raise ApprovalProtocolError(code="APPROVAL_ACTOR_FORBIDDEN")
    return approval.model_copy(
        update={
            "status": command.decision,
            "decided_by": command.actor.user_id,
            "revision": approval.revision + 1,
        }
    )


def validated_approval_consumption(
    approval: ApprovalRecord, command: ApprovalConsumeCommand
) -> ApprovalRecord:
    if approval.id != command.approval_id:
        raise ApprovalProtocolError(code="APPROVAL_ID_MISMATCH")
    if approval.revision != command.expected_revision:
        raise ApprovalProtocolError(code="APPROVAL_REVISION_CONFLICT")
    if approval.status != command.expected_status:
        raise ApprovalProtocolError(code="INVALID_APPROVAL_TRANSITION")
    ensure_approval_transition(approval.status, "consumed")
    if command.occurred_at >= approval.binding.expires_at:
        raise ApprovalProtocolError(code="APPROVAL_EXPIRED")
    plan = command.presented_plan
    expected_binding = binding_for_plan(plan, command.presented_binding.expires_at)
    if (
        action_plan_digest(plan) != plan.plan_digest
        or canonical_arguments_hash(plan.arguments) != plan.arguments_hash
        or approval.binding != command.presented_binding
        or expected_binding != command.presented_binding
    ):
        raise ApprovalProtocolError(code="APPROVAL_BINDING_MISMATCH")
    expected = approval_digest(approval.binding, command.signing_key)
    if not hmac.compare_digest(approval.digest, expected):
        raise ApprovalProtocolError(code="APPROVAL_DIGEST_MISMATCH")
    return approval.model_copy(
        update={"status": "consumed", "revision": approval.revision + 1}
    )


def consume_approval(
    store: ApprovalConsumptionStore, command: ApprovalConsumeCommand
) -> ApprovalRecord:
    return store.compare_and_consume(command)
