from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from inspect import signature
from threading import Barrier
from typing import Literal

import pytest
from services.api.tool_governance import (
    JsonObject,
    JsonValue,
    ToolExecutionContext,
    ToolGovernance,
    ToolGrant,
    ToolPrincipal,
    ToolRequest,
    canonical_arguments_hash,
)

from science_workbench_contracts.runs import ResearchIntent

NOW = datetime(2026, 7, 13, tzinfo=UTC)


def test_tool_request_requires_research_intent() -> None:
    assert "research_intent" in signature(ToolRequest).parameters


def test_approval_ttl_is_explicit_application_policy() -> None:
    time = NOW
    governance = ToolGovernance(
        approval_ttl=timedelta(seconds=2),
        clock=lambda: time,
    )
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "ask",
            frozenset({"public-search"}),
        )
    )
    register_tool(governance, [])

    pending = governance.execute(principal(), request())
    assert pending.receipt.plan_id is not None
    time = NOW + timedelta(seconds=3)

    assert (
        governance.approve(principal(), pending.receipt.plan_id).code
        == "PLAN_UNAVAILABLE"
    )


@pytest.mark.parametrize("approval_ttl", [timedelta(0), timedelta(seconds=-1)])
def test_approval_policy_rejects_nonpositive_ttl(
    approval_ttl: timedelta,
) -> None:
    with pytest.raises(ValueError, match="approval_ttl must be positive"):
        _ = ToolGovernance(approval_ttl=approval_ttl)


@pytest.mark.parametrize(
    ("expires_at", "message"),
    [
        (NOW - timedelta(microseconds=1), "expires_at must be in the future"),
        (NOW, "expires_at must be in the future"),
        (
            NOW + timedelta(minutes=5, microseconds=1),
            "expires_at exceeds approval_ttl",
        ),
        (NOW + timedelta(days=3650), "expires_at exceeds approval_ttl"),
    ],
)
def test_caller_expiry_obeys_future_and_approval_ttl_boundaries(
    expires_at: datetime,
    message: str,
) -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "ask",
            frozenset({"public-search"}),
        )
    )
    register_tool(governance, [])

    with pytest.raises(ValueError, match=message):
        _ = governance.execute(principal(), request(), expires_at=expires_at)


def test_exact_approval_ttl_boundary_preserves_bound_scopes() -> None:
    governance = service()
    network_scopes = frozenset({"public-search"})
    secret_scopes = frozenset({"literature-key"})
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "ask",
            network_scopes,
            secret_scopes,
        )
    )
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    register_tool(governance, calls)
    tool_request = request(network=network_scopes, secrets=secret_scopes)

    pending = governance.execute(
        principal(), tool_request, expires_at=NOW + timedelta(minutes=5)
    )

    assert pending.receipt.plan_id is not None
    plan = governance.plan(principal(), pending.receipt.plan_id)
    assert plan is not None
    assert plan.expires_at == NOW + timedelta(minutes=5)
    assert plan.network_scopes == network_scopes
    assert plan.secret_scopes == secret_scopes
    assert governance.approve(principal(), plan.id).code == "PLAN_APPROVED"
    assert governance.consume(principal(), tool_request, plan.id).receipt.code == (
        "PLAN_CONSUMED"
    )
    assert len(calls) == 1


def principal(*, requester: str = "user-a", owner: bool = False) -> ToolPrincipal:
    return ToolPrincipal("org-a", "project-a", requester, owner)


def request(
    *,
    run: str = "run-a",
    tool: str = "literature.search",
    arguments: JsonObject | None = None,
    network: frozenset[str] | None = None,
    secrets: frozenset[str] | None = None,
) -> ToolRequest:
    default_arguments: JsonObject = {"query": "minerals"}
    request_arguments: JsonValue = (
        default_arguments if arguments is None else arguments
    )
    default_network: frozenset[str] = frozenset({"public-search"})
    default_secrets: frozenset[str] = frozenset()
    intent = ResearchIntent(
        question="Which mineral evidence should be reviewed?",
        rationale="The researcher needs bounded primary evidence.",
        intended_benefit="A reproducible evidence review.",
        success_criteria=("At least one relevant primary source is found.",),
        constraints=("Use only the approved public literature scope.",),
        stop_conditions=("Stop at the bounded result limit.",),
        research_mode="copilot",
        data_origin="observed",
    )
    return ToolRequest(
        run,
        tool,
        request_arguments,
        intent,
        (
            default_network if network is None else network,
            default_secrets if secrets is None else secrets,
        ),
    )


def service() -> ToolGovernance:
    return ToolGovernance(
        approval_ttl=timedelta(minutes=5),
        clock=lambda: NOW,
    )


def register_tool(
    governance: ToolGovernance, calls: list[tuple[JsonValue, ToolExecutionContext]]
) -> None:
    governance.register_tool(
        "literature.search",
        lambda arguments, context: calls.append((arguments, context)),
    )




@pytest.mark.parametrize(
    ("effect", "code", "count"),
    [("allow", "TOOL_ALLOWED", 1), ("deny", "TOOL_DENIED", 0)],
)
def test_allow_and_deny_are_application_side(
    effect: Literal["allow", "deny"], code: str, count: int
) -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            effect,
            frozenset({"public-search"}),
        )
    )
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    register_tool(governance, calls)

    result = governance.execute(principal(), request())

    assert result.receipt.code == code
    assert len(calls) == count
    assert result.provider_request.built_in_tools == ()


def test_default_deny_and_scope_rejection_have_zero_side_effects() -> None:
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    no_grant_governance = service()
    register_tool(no_grant_governance, calls)
    no_grant = no_grant_governance.execute(principal(), request())
    governance = service()
    register_tool(governance, calls)
    governance.set_grant(ToolGrant("org-a", "project-a", "literature.search", "allow"))
    excessive_scope = governance.execute(principal(), request())

    assert no_grant.receipt.code == "TOOL_DENIED"
    assert excessive_scope.receipt.code == "TOOL_DENIED"
    assert calls == []


def test_canonical_hash_is_invariant_to_object_key_order() -> None:
    first: JsonObject = {"a": [1, {"b": True}], "z": "x"}
    second: JsonObject = {"z": "x", "a": [1, {"b": True}]}

    assert canonical_arguments_hash(first) == canonical_arguments_hash(second)


def test_ask_requires_requester_approval_then_consumes_once() -> None:
    governance = service()
    governance.set_grant(ToolGrant("org-a", "project-a", "literature.search", "ask", frozenset({"public-search"})))
    tool_request = request()
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    register_tool(governance, calls)

    pending = governance.execute(
        principal(), tool_request, expires_at=NOW + timedelta(minutes=1)
    )
    assert pending.receipt.code == "APPROVAL_REQUIRED"
    assert pending.receipt.plan_id is not None
    plan_id = pending.receipt.plan_id
    assert governance.approve(principal(), plan_id).code == "PLAN_APPROVED"
    assert governance.consume(principal(), tool_request, plan_id).receipt.code == "PLAN_CONSUMED"
    assert governance.consume(principal(), tool_request, plan_id).receipt.code == "PLAN_UNAVAILABLE"
    assert len(calls) == 1


def test_owner_can_reject_another_requester_but_cannot_approve() -> None:
    governance = service()
    governance.set_grant(ToolGrant("org-a", "project-a", "literature.search", "ask", frozenset({"public-search"})))
    register_tool(governance, [])
    pending = governance.execute(
        principal(), request(), expires_at=NOW + timedelta(minutes=1)
    )
    assert pending.receipt.plan_id is not None

    owner = principal(requester="owner", owner=True)
    assert governance.approve(owner, pending.receipt.plan_id).code == "PLAN_UNAVAILABLE"
    assert governance.reject(owner, pending.receipt.plan_id).code == "PLAN_REJECTED"


@pytest.mark.parametrize(
    "attacker_request",
    [
        request(run="run-b"),
        request(tool="other.tool"),
        request(arguments={"query": "altered"}),
        request(network=frozenset()),
    ],
)
def test_mutated_binding_cannot_consume(attacker_request: ToolRequest) -> None:
    governance = service()
    governance.set_grant(ToolGrant("org-a", "project-a", "literature.search", "ask", frozenset({"public-search"})))
    original = request()
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    register_tool(governance, calls)
    pending = governance.execute(
        principal(), original, expires_at=NOW + timedelta(minutes=1)
    )
    assert pending.receipt.plan_id is not None
    assert governance.approve(principal(), pending.receipt.plan_id).code == "PLAN_APPROVED"

    result = governance.consume(principal(), attacker_request, pending.receipt.plan_id)

    assert result.receipt.code == "PLAN_UNAVAILABLE"
    assert calls == []


def test_mutated_research_intent_cannot_consume_an_approved_plan() -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "ask",
            frozenset({"public-search"}),
        )
    )
    original = request()
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    register_tool(governance, calls)
    pending = governance.execute(principal(), original)
    assert pending.receipt.plan_id is not None
    assert governance.approve(principal(), pending.receipt.plan_id).code == "PLAN_APPROVED"

    altered_intent = original.research_intent.model_copy(
        update={"question": "A different human-owned question"}
    )
    altered = ToolRequest(
        original.run_id,
        original.tool,
        original.arguments,
        altered_intent,
        (original.network_scopes, original.secret_scopes),
    )
    result = governance.consume(principal(), altered, pending.receipt.plan_id)

    assert result.receipt.code == "PLAN_UNAVAILABLE"
    assert calls == []


def test_expired_and_foreign_plan_ids_are_indistinguishable_and_safe() -> None:
    time = NOW
    governance = ToolGovernance(
        approval_ttl=timedelta(minutes=5),
        clock=lambda: time,
    )
    governance.set_grant(ToolGrant("org-a", "project-a", "literature.search", "ask", frozenset({"public-search"})))
    register_tool(governance, [])
    pending = governance.execute(
        principal(), request(), expires_at=NOW + timedelta(seconds=1)
    )
    assert pending.receipt.plan_id is not None
    time = NOW + timedelta(seconds=2)
    foreign = ToolPrincipal("org-b", "project-b", "user-b")

    assert governance.approve(principal(), pending.receipt.plan_id).code == "PLAN_UNAVAILABLE"
    assert governance.approve(foreign, pending.receipt.plan_id).code == "PLAN_UNAVAILABLE"
    assert governance.approve(foreign, "missing").code == "PLAN_UNAVAILABLE"


def test_concurrent_approval_has_one_winner() -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "ask",
            frozenset({"public-search"}),
        )
    )
    register_tool(governance, [])
    pending = governance.execute(
        principal(),
        request(),
        expires_at=NOW + timedelta(minutes=1),
    )
    assert pending.receipt.plan_id is not None
    barrier = Barrier(2)

    def approve() -> str:
        _ = barrier.wait()
        return governance.approve(principal(), pending.receipt.plan_id or "").code

    def approve_worker(_: int) -> str:
        return approve()

    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(pool.map(approve_worker, range(2)))

    assert sorted(codes) == ["PLAN_APPROVED", "PLAN_UNAVAILABLE"]



def test_concurrent_consumption_executes_once() -> None:
    governance = service()
    governance.set_grant(ToolGrant("org-a", "project-a", "literature.search", "ask", frozenset({"public-search"})))
    tool_request = request()
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    register_tool(governance, calls)
    pending = governance.execute(
        principal(), tool_request, expires_at=NOW + timedelta(minutes=1)
    )
    assert pending.receipt.plan_id is not None
    assert governance.approve(principal(), pending.receipt.plan_id).code == "PLAN_APPROVED"
    barrier = Barrier(2)

    def consume() -> str:
        _ = barrier.wait()
        return governance.consume(
            principal(), tool_request, pending.receipt.plan_id or ""
        ).receipt.code

    def consume_worker(_: int) -> str:
        return consume()

    with ThreadPoolExecutor(max_workers=2) as pool:
        codes = list(pool.map(consume_worker, range(2)))

    assert sorted(codes) == ["PLAN_CONSUMED", "PLAN_UNAVAILABLE"]
    assert len(calls) == 1


def test_audit_receipts_do_not_expose_arguments_or_secret_scope() -> None:
    governance = service()
    governance.set_grant(ToolGrant("org-a", "project-a", "literature.search", "allow", secret_scopes=frozenset({"vault-entry"})))
    register_tool(governance, [])
    result = governance.execute(
        principal(),
        request(
            network=frozenset(),
            secrets=frozenset({"vault-entry"}),
            arguments={"credential": "sensitive-value"},
        ),
    )

    assert "sensitive-value" not in repr(result.receipt)
    assert "vault-entry" not in repr(result.receipt)


def test_approved_arguments_and_scopes_are_sealed_to_registered_handler() -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "ask",
            frozenset({"public-search"}),
            frozenset({"vault-entry"}),
        )
    )
    original: JsonObject = {"query": {"terms": ["minerals"]}}
    tool_request = request(
        arguments=original,
        secrets=frozenset({"vault-entry"}),
    )
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    register_tool(governance, calls)

    pending = governance.execute(
        principal(), tool_request, expires_at=NOW + timedelta(minutes=1)
    )
    assert pending.receipt.plan_id is not None
    nested_query = original["query"]
    assert isinstance(nested_query, dict)
    terms = nested_query["terms"]
    assert isinstance(terms, list)
    terms.append("mutated")
    assert governance.approve(principal(), pending.receipt.plan_id).code == "PLAN_APPROVED"

    result = governance.consume(principal(), tool_request, pending.receipt.plan_id)

    assert result.receipt.code == "PLAN_CONSUMED"
    assert calls == [
        (
            {"query": {"terms": ["minerals"]}},
            ToolExecutionContext(
                "org-a",
                "project-a",
                "run-a",
                "user-a",
                frozenset({"public-search"}),
                frozenset({"vault-entry"}),
            ),
        )
    ]


def test_missing_or_wrong_tool_registration_invokes_nothing() -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "allow",
            frozenset({"public-search"}),
        )
    )
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    governance.register_tool(
        "other.tool",
        lambda arguments, context: calls.append((arguments, context)),
    )

    result = governance.execute(principal(), request())

    assert result.receipt.code == "TOOL_DENIED"
    assert calls == []


def test_registration_cannot_substitute_an_existing_tool_handler() -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "allow",
            frozenset({"public-search"}),
        )
    )
    approved_calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    substituted_calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    register_tool(governance, approved_calls)
    governance.register_tool(
        "literature.search",
        lambda arguments, context: substituted_calls.append((arguments, context)),
    )

    result = governance.execute(principal(), request())

    assert result.receipt.code == "TOOL_ALLOWED"
    assert len(approved_calls) == 1
    assert substituted_calls == []


def test_ask_plan_seals_all_tool_registration() -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "ask",
            frozenset({"public-search"}),
        )
    )
    register_tool(governance, [])

    pending = governance.execute(principal(), request())

    assert pending.receipt.code == "APPROVAL_REQUIRED"
    assert pending.receipt.plan_id is not None
    plan = governance.plan(principal(), pending.receipt.plan_id)
    assert plan is not None
    registry_identity = plan.registry_identity
    with pytest.raises(RuntimeError, match="registry is sealed"):
        register_tool(governance, [])
    with pytest.raises(RuntimeError, match="registry is sealed"):
        governance.register_tool("new.tool", lambda arguments, context: None)
    assert governance.plan(principal(), pending.receipt.plan_id) == plan
    assert plan.registry_identity == registry_identity


def test_allow_execution_seals_all_tool_registration() -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "allow",
            frozenset({"public-search"}),
        )
    )
    register_tool(governance, [])

    assert governance.execute(principal(), request()).receipt.code == "TOOL_ALLOWED"

    with pytest.raises(RuntimeError, match="registry is sealed"):
        governance.register_tool("new.tool", lambda arguments, context: None)


def test_plan_binds_frozen_registry_identity_and_consume_checks_it() -> None:
    governance = service()
    governance.set_grant(
        ToolGrant(
            "org-a",
            "project-a",
            "literature.search",
            "ask",
            frozenset({"public-search"}),
        )
    )
    calls: list[tuple[JsonValue, ToolExecutionContext]] = []
    register_tool(governance, calls)
    tool_request = request()
    pending = governance.execute(principal(), tool_request)
    assert pending.receipt.plan_id is not None
    plan = governance.plan(principal(), pending.receipt.plan_id)
    assert plan is not None
    assert governance.approve(principal(), pending.receipt.plan_id).code == "PLAN_APPROVED"

    assert plan.registry_identity
    with pytest.raises(RuntimeError, match="registry is sealed"):
        governance.register_tool("new.tool", lambda arguments, context: None)
