"""Application-side tool authorization and one-use plan approval enforcement."""

from __future__ import annotations

import json
import math
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from threading import Lock
from types import MappingProxyType
from typing import Final, Literal, cast, final
from uuid import uuid4

from science_workbench_contracts.runs import ResearchIntent, research_intent_sha256

type ToolEffect = Literal["allow", "ask", "deny"]
type PlanStatus = Literal["pending", "approved", "rejected", "expired", "consumed"]
type JsonObject = dict[str, JsonValue]
type JsonValue = None | bool | int | float | str | list[JsonValue] | JsonObject
type ToolHandler = Callable[[JsonValue, ToolExecutionContext], object]
type Clock = Callable[[], datetime]
type ToolScopePair = tuple[frozenset[str], frozenset[str]]

_EFFECTS: Final[frozenset[str]] = frozenset({"allow", "ask", "deny"})
_PENDING: Final[PlanStatus] = "pending"
_APPROVED: Final[PlanStatus] = "approved"
_REJECTED: Final[PlanStatus] = "rejected"
_EXPIRED: Final[PlanStatus] = "expired"
_CONSUMED: Final[PlanStatus] = "consumed"
_INVALID_EFFECT_MESSAGE: Final = "effect must be allow, ask, or deny"
_PROVIDER_BUILT_IN_TOOLS_MESSAGE: Final = "provider built-in tools are prohibited"
_EXPIRED_AT_FUTURE_MESSAGE: Final = "expires_at must be in the future"
_EXPIRES_AT_TTL_MESSAGE: Final = "expires_at exceeds approval_ttl"
_FINITE_JSON_NUMBERS_MESSAGE: Final = "arguments must contain finite JSON numbers"
_REGISTRY_SEALED_MESSAGE: Final = "application tool registry is sealed"
_JSON_VALUES_MESSAGE: Final = "arguments must be JSON values"
_TIMEZONE_AWARE_TEMPLATE: Final = "{} must be timezone-aware"
_NONEMPTY_IDENTIFIER_TEMPLATE: Final = "{} must not be empty"
_NONEMPTY_SCOPE_TEMPLATE: Final = "{} contains an empty scope"
_POSITIVE_APPROVAL_TTL_MESSAGE: Final = "approval_ttl must be positive"


@dataclass(frozen=True, slots=True)
class ToolPrincipal:
    """Authenticated actor scoped to exactly one organization and project."""

    organization_id: str
    project_id: str
    requester_id: str
    is_owner: bool = False

    def __post_init__(self) -> None:
        """Validate the principal's immutable tenant and requester identifiers."""
        _require_identifier(self.organization_id, "organization_id")
        _require_identifier(self.project_id, "project_id")
        _require_identifier(self.requester_id, "requester_id")


@dataclass(frozen=True, slots=True)
class ToolGrant:
    """Project policy for a single application-owned tool."""

    organization_id: str
    project_id: str
    tool: str
    effect: ToolEffect
    network_scopes: frozenset[str] = frozenset()
    secret_scopes: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        """Validate the grant's immutable policy fields and scope sets."""
        _require_identifier(self.organization_id, "organization_id")
        _require_identifier(self.project_id, "project_id")
        _require_identifier(self.tool, "tool")
        if self.effect not in _EFFECTS:
            raise _value_error(_INVALID_EFFECT_MESSAGE)
        object.__setattr__(self, "network_scopes", frozenset(self.network_scopes))
        object.__setattr__(self, "secret_scopes", frozenset(self.secret_scopes))
        _validate_scopes(self.network_scopes, "network_scopes")
        _validate_scopes(self.secret_scopes, "secret_scopes")


@dataclass(frozen=True, slots=True, init=False)
class ToolRequest:
    """A tool action whose canonical arguments and scopes are bound into a plan."""

    run_id: str
    tool: str
    network_scopes: frozenset[str]
    secret_scopes: frozenset[str]
    research_intent_sha256: str
    _canonical_arguments: str = field(repr=False)
    _arguments_hash: str = field(repr=False)
    _canonical_research_intent: str = field(repr=False)

    def __init__(
        self,
        run_id: str,
        tool: str,
        arguments: JsonValue,
        research_intent: ResearchIntent,
        scopes: ToolScopePair | None = None,
    ) -> None:
        """Capture arguments as immutable canonical JSON at request construction."""
        _require_identifier(run_id, "run_id")
        _require_identifier(tool, "tool")
        canonical_arguments = _canonical_arguments(arguments)
        canonical_network_scopes = frozenset[str]() if scopes is None else scopes[0]
        canonical_secret_scopes = frozenset[str]() if scopes is None else scopes[1]
        _validate_scopes(canonical_network_scopes, "network_scopes")
        _validate_scopes(canonical_secret_scopes, "secret_scopes")
        object.__setattr__(self, "run_id", run_id)
        object.__setattr__(self, "tool", tool)
        object.__setattr__(self, "network_scopes", canonical_network_scopes)
        object.__setattr__(self, "secret_scopes", canonical_secret_scopes)
        object.__setattr__(
            self, "research_intent_sha256", research_intent_sha256(research_intent)
        )
        object.__setattr__(self, "_canonical_arguments", canonical_arguments)
        object.__setattr__(
            self,
            "_canonical_research_intent",
            research_intent.model_dump_json(),
        )
        object.__setattr__(
            self,
            "_arguments_hash",
            sha256(canonical_arguments.encode("utf-8")).hexdigest(),
        )

    @property
    def arguments(self) -> JsonValue:
        """Return a fresh decoded copy of the immutable approved arguments."""
        return _decode_arguments(self._canonical_arguments)

    @property
    def arguments_hash(self) -> str:
        """Return the canonical, deterministic digest of the JSON arguments."""
        return self._arguments_hash

    @property
    def research_intent(self) -> ResearchIntent:
        """Return a validated copy of the immutable human-owned intent."""
        return ResearchIntent.model_validate_json(self._canonical_research_intent)


@dataclass(frozen=True, slots=True)
class ProviderRuntimeRequest:
    """Runtime surface deliberately unable to carry provider-built-in tools."""

    built_in_tools: tuple[()] = ()

    def __post_init__(self) -> None:
        """Reject any provider-built-in tool capability."""
        if self.built_in_tools:
            raise _value_error(_PROVIDER_BUILT_IN_TOOLS_MESSAGE)


@dataclass(frozen=True, slots=True)
class PlanApproval:
    """Immutable authorization binding; state changes create a replacement record."""

    id: str
    organization_id: str
    project_id: str
    run_id: str
    requester_id: str
    tool: str
    registry_identity: str
    canonical_research_intent: str = field(repr=False)
    research_intent_sha256: str
    canonical_arguments: str = field(repr=False)
    arguments_hash: str
    network_scopes: frozenset[str]
    secret_scopes: frozenset[str]
    expires_at: datetime
    status: PlanStatus = _PENDING


@dataclass(frozen=True, slots=True)
class AuditReceipt:
    """Redacted, stable application audit outcome without arguments or scopes."""

    code: str
    action: Literal["denied", "allowed", "pending", "approved", "rejected", "consumed"]
    plan_id: str | None = None


@dataclass(frozen=True, slots=True)
class ToolExecutionResult:
    """Policy result; callers never receive provider tool capabilities."""

    receipt: AuditReceipt
    provider_request: ProviderRuntimeRequest

@dataclass(frozen=True, slots=True)
class ToolExecutionContext:
    """Authorization context for a registered application tool handler."""

    organization_id: str
    project_id: str
    run_id: str
    requester_id: str
    network_scopes: frozenset[str]
    secret_scopes: frozenset[str]

    def __post_init__(self) -> None:
        """Canonicalize the context scope sets into immutable values."""
        object.__setattr__(self, "network_scopes", frozenset(self.network_scopes))
        object.__setattr__(self, "secret_scopes", frozenset(self.secret_scopes))




@final
class ApplicationToolRegistry:
    """Application-owned exact-id handler registry."""

    def __init__(self) -> None:
        """Initialize an empty registry."""
        self._handlers: Mapping[str, ToolHandler] = {}
        self._identity: str | None = None

    def register(self, tool: str, handler: ToolHandler) -> None:
        """Register the single handler permitted for an exact application tool id."""
        _require_identifier(tool, "tool")
        if self._identity is not None:
            raise RuntimeError(_REGISTRY_SEALED_MESSAGE)
        handlers = cast("dict[str, ToolHandler]", self._handlers)
        _ = handlers.setdefault(tool, handler)

    def seal(self) -> str:
        """Freeze handlers and return the identity of their exact registered ids."""
        if self._identity is None:
            tool_set = json.dumps(sorted(self._handlers), separators=(",", ":"))
            self._identity = sha256(tool_set.encode("utf-8")).hexdigest()
            self._handlers = MappingProxyType(dict(self._handlers))
        return self._identity

    @property
    def identity(self) -> str | None:
        """Return the immutable registry identity once execution has begun."""
        return self._identity

    def has(self, tool: str) -> bool:
        """Return whether an exact application tool handler is registered."""
        return tool in self._handlers

    def invoke(
        self, tool: str, canonical_arguments: str, context: ToolExecutionContext
    ) -> bool:
        """Invoke only the registered matching handler with fresh approved data."""
        handler = self._handlers.get(tool)
        if handler is None:
            return False
        _ = handler(_decode_arguments(canonical_arguments), context)
        return True



@final
class ToolGovernance:
    """Thread-safe in-memory policy boundary for application-owned tool execution."""

    def __init__(
        self,
        *,
        approval_ttl: timedelta,
        clock: Clock | None = None,
    ) -> None:
        """Initialize the store with explicit approval expiry policy and clock."""
        if approval_ttl <= timedelta(0):
            raise _value_error(_POSITIVE_APPROVAL_TTL_MESSAGE)
        self._approval_ttl = approval_ttl
        self._clock = _utc_now if clock is None else clock
        self._lock = Lock()
        self._grants: dict[tuple[str, str, str], ToolGrant] = {}
        self._plans: dict[str, PlanApproval] = {}
        self._registry = ApplicationToolRegistry()

    def set_grant(self, grant: ToolGrant) -> None:
        """Install or replace a project-scoped policy."""
        with self._lock:
            self._grants[(grant.organization_id, grant.project_id, grant.tool)] = grant

    def register_tool(self, tool: str, handler: ToolHandler) -> None:
        """Register an application-owned handler for exact-id invocation."""
        with self._lock:
            self._registry.register(tool, handler)

    def execute(
        self,
        principal: ToolPrincipal,
        request: ToolRequest,
        *,
        expires_at: datetime | None = None,
    ) -> ToolExecutionResult:
        """Apply default-deny policy and invoke only a registered matching tool."""
        with self._lock:
            grant = self._matching_grant(principal, request)
            if (
                grant is None
                or grant.effect == "deny"
                or not _scopes_allowed(grant, request)
            ):
                return _result("TOOL_DENIED", "denied")
            registry_identity = self._registry.seal()
            if grant.effect == "ask":
                expiry = _normalized_expiry(
                    expires_at,
                    self._clock(),
                    self._approval_ttl,
                )
                plan = PlanApproval(
                    id=uuid4().hex,
                    organization_id=principal.organization_id,
                    project_id=principal.project_id,
                    run_id=request.run_id,
                    requester_id=principal.requester_id,
                    tool=request.tool,
                    registry_identity=registry_identity,
                    canonical_research_intent=request.research_intent.model_dump_json(),
                    research_intent_sha256=request.research_intent_sha256,
                    canonical_arguments=_canonical_arguments(request.arguments),
                    arguments_hash=request.arguments_hash,
                    network_scopes=request.network_scopes,
                    secret_scopes=request.secret_scopes,
                    expires_at=expiry,
                )
                self._plans[plan.id] = plan
                return _result("APPROVAL_REQUIRED", "pending", plan.id)
            if not self._registry.has(request.tool):
                return _result("TOOL_DENIED", "denied")
            context = ToolExecutionContext(
                principal.organization_id,
                principal.project_id,
                request.run_id,
                principal.requester_id,
                request.network_scopes,
                request.secret_scopes,
            )
        invoked = self._invoke(
            request.tool, _canonical_arguments(request.arguments), context
        )
        if not invoked:
            return _result("TOOL_DENIED", "denied")
        return _result("TOOL_ALLOWED", "allowed")

    def approve(self, principal: ToolPrincipal, plan_id: str) -> AuditReceipt:
        """Approve a pending plan only when its requester presents the same tenant."""
        with self._lock:
            plan = self._accessible_plan(principal, plan_id)
            if plan is None or plan.requester_id != principal.requester_id:
                return AuditReceipt("PLAN_UNAVAILABLE", "denied")
            if _is_expired(plan, self._clock()):
                self._plans[plan.id] = replace(plan, status=_EXPIRED)
                return AuditReceipt("PLAN_UNAVAILABLE", "denied")
            if plan.status != _PENDING:
                return AuditReceipt("PLAN_UNAVAILABLE", "denied")
            self._plans[plan.id] = replace(plan, status=_APPROVED)
            return AuditReceipt("PLAN_APPROVED", "approved", plan.id)

    def reject(self, principal: ToolPrincipal, plan_id: str) -> AuditReceipt:
        """Reject a pending plan as its requester or as an owner in the same tenant."""
        with self._lock:
            plan = self._accessible_plan(principal, plan_id)
            if plan is None:
                return AuditReceipt("PLAN_UNAVAILABLE", "denied")
            may_reject = (
                plan.requester_id == principal.requester_id or principal.is_owner
            )
            if (
                not may_reject
                or _is_expired(plan, self._clock())
                or plan.status != _PENDING
            ):
                return AuditReceipt("PLAN_UNAVAILABLE", "denied")
            self._plans[plan.id] = replace(plan, status=_REJECTED)
            return AuditReceipt("PLAN_REJECTED", "rejected", plan.id)

    def consume(
        self,
        principal: ToolPrincipal,
        request: ToolRequest,
        plan_id: str,
    ) -> ToolExecutionResult:
        """Consume a matching approved plan before registered tool invocation."""
        with self._lock:
            plan = self._accessible_plan(principal, plan_id)
            if plan is None or not _matches_binding(plan, principal, request):
                return _result("PLAN_UNAVAILABLE", "denied")
            if _is_expired(plan, self._clock()):
                self._plans[plan.id] = replace(plan, status=_EXPIRED)
                return _result("PLAN_UNAVAILABLE", "denied")
            if (
                plan.status != _APPROVED
                or plan.registry_identity != self._registry.identity
                or not self._registry.has(plan.tool)
            ):
                return _result("PLAN_UNAVAILABLE", "denied")
            self._plans[plan.id] = replace(plan, status=_CONSUMED)
            context = ToolExecutionContext(
                plan.organization_id,
                plan.project_id,
                plan.run_id,
                plan.requester_id,
                plan.network_scopes,
                plan.secret_scopes,
            )
        invoked = self._invoke(plan.tool, plan.canonical_arguments, context)
        if not invoked:
            return _result("PLAN_UNAVAILABLE", "denied")
        return _result("PLAN_CONSUMED", "consumed", plan_id)

    def plan(self, principal: ToolPrincipal, plan_id: str) -> PlanApproval | None:
        """Return a plan in its tenant without exposing foreign identifiers."""
        with self._lock:
            return self._accessible_plan(principal, plan_id)

    def _matching_grant(
        self, principal: ToolPrincipal, request: ToolRequest
    ) -> ToolGrant | None:
        return self._grants.get(
            (principal.organization_id, principal.project_id, request.tool)
        )

    def _accessible_plan(
        self, principal: ToolPrincipal, plan_id: str
    ) -> PlanApproval | None:
        plan = self._plans.get(plan_id)
        if plan is None:
            return None
        if (
            plan.organization_id != principal.organization_id
            or plan.project_id != principal.project_id
        ):
            return None
        return plan

    def _invoke(
        self,
        tool: str,
        canonical_arguments: str,
        context: ToolExecutionContext,
    ) -> bool:
        """Invoke the sealed registry with an immutable authorization context."""
        return self._registry.invoke(tool, canonical_arguments, context)


def canonical_arguments_hash(arguments: JsonValue) -> str:
    """Hash canonical JSON so semantically equivalent object key order is invariant."""
    return sha256(_canonical_arguments(arguments).encode("utf-8")).hexdigest()


def _canonical_arguments(arguments: JsonValue) -> str:
    """Validate and serialize JSON into its immutable canonical representation."""
    _validate_json(arguments)
    return json.dumps(
        arguments,
        allow_nan=False,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def _decode_arguments(canonical_arguments: str) -> JsonValue:
    """Decode a fresh JSON value from canonical immutable storage."""
    return cast("JsonValue", json.loads(canonical_arguments))


def _result(
    code: str,
    action: Literal["denied", "allowed", "pending", "approved", "rejected", "consumed"],
    plan_id: str | None = None,
) -> ToolExecutionResult:
    return ToolExecutionResult(
        AuditReceipt(code, action, plan_id),
        ProviderRuntimeRequest(),
    )


def _matches_binding(
    plan: PlanApproval,
    principal: ToolPrincipal,
    request: ToolRequest,
) -> bool:
    return (
        plan.organization_id == principal.organization_id
        and plan.project_id == principal.project_id
        and plan.run_id == request.run_id
        and plan.requester_id == principal.requester_id
        and plan.tool == request.tool
        and plan.research_intent_sha256 == request.research_intent_sha256
        and plan.arguments_hash == request.arguments_hash
        and plan.network_scopes == request.network_scopes
        and plan.secret_scopes == request.secret_scopes
    )


def _scopes_allowed(grant: ToolGrant, request: ToolRequest) -> bool:
    return (
        request.network_scopes <= grant.network_scopes
        and request.secret_scopes <= grant.secret_scopes
    )


def _is_expired(plan: PlanApproval, now: datetime) -> bool:
    return plan.expires_at <= _require_aware(now, "clock result")


def _normalized_expiry(
    expires_at: datetime | None,
    now: datetime,
    approval_ttl: timedelta,
) -> datetime:
    current = _require_aware(now, "clock result")
    if expires_at is None:
        return current + approval_ttl
    expiry = _require_aware(expires_at, "expires_at")
    if expiry <= current:
        raise _value_error(_EXPIRED_AT_FUTURE_MESSAGE)
    if expiry > current + approval_ttl:
        raise _value_error(_EXPIRES_AT_TTL_MESSAGE)
    return expiry


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _require_aware(value: datetime, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise _value_error(_timezone_aware_message(field))
    return value.astimezone(UTC)


def _require_identifier(value: str, field: str) -> None:
    if not value.strip():
        raise _value_error(_nonempty_identifier_message(field))


def _validate_scopes(scopes: frozenset[str], field: str) -> None:
    if any(not scope.strip() for scope in scopes):
        raise _value_error(_nonempty_scope_message(field))


def _validate_json(value: JsonValue) -> None:
    if value is None or isinstance(value, (bool, int, str)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise _value_error(_FINITE_JSON_NUMBERS_MESSAGE)
        return
    if isinstance(value, list):
        for item in value:
            _validate_json(item)
        return
    for item in value.values():
        _validate_json(item)


def _value_error(message: str) -> ValueError:
    return ValueError(message)


def _timezone_aware_message(field: str) -> str:
    return _TIMEZONE_AWARE_TEMPLATE.format(field)


def _nonempty_identifier_message(field: str) -> str:
    return _NONEMPTY_IDENTIFIER_TEMPLATE.format(field)


def _nonempty_scope_message(field: str) -> str:
    return _NONEMPTY_SCOPE_TEMPLATE.format(field)
