"""Stable contracts for qualified provider Run dispatch."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from services.api.provider_runtime_contracts import (
    DispatchAuthorization,
    ProviderPrincipal,
    ProviderRuntimeError,
)

type DispatchWireValue = (
    None
    | bool
    | int
    | float
    | str
    | list[DispatchWireValue]
    | dict[str, DispatchWireValue]
)

_ERROR_DISPATCH = "provider_dispatch_failed"


class ProviderRunDispatchError(ProviderRuntimeError):
    """Stable failure when a qualified Run cannot be atomically created."""

    def __init__(self) -> None:
        """Hide transport and storage details behind one caller-safe code."""
        super().__init__(_ERROR_DISPATCH)


@dataclass(frozen=True, slots=True)
class ProviderRunDispatchRequest:
    """Approved identifiers needed to create one requester-owned model Run."""

    run_id: str
    session_id: str
    connection_id: str
    model_id: str
    action_plan_digest: str
    research_intent_sha256: str


@dataclass(frozen=True, slots=True)
class DispatchedProviderRun:
    """Persisted Run identity and its exact immutable qualification snapshot."""

    run_id: str
    authorization: DispatchAuthorization


class ProviderRunDispatcher(Protocol):
    """Create one qualified provider Run without exposing persistence credentials."""

    def dispatch(
        self,
        principal: ProviderPrincipal,
        request: ProviderRunDispatchRequest,
    ) -> DispatchedProviderRun:
        """Persist one exact Run or fail without a partial authorization."""
        ...


def provider_run_dispatch_request_object(
    request: ProviderRunDispatchRequest,
) -> dict[str, DispatchWireValue]:
    """Encode the identifier object nested in one dispatch wire request."""
    return {
        "run_id": request.run_id,
        "session_id": request.session_id,
        "connection_id": request.connection_id,
        "model_id": request.model_id,
        "action_plan_digest": request.action_plan_digest,
        "research_intent_sha256": request.research_intent_sha256,
    }
