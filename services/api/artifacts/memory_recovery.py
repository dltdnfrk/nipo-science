"""Explicit process-local Artifact recovery adapter for unit tests."""

import hashlib
from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import dataclass
from threading import RLock
from typing import final
from uuid import UUID

from .models import ArtifactScope, WatcherClaim, WatcherOutput
from .recovery import (
    ArtifactReconciliation,
    CompletedArtifactCommit,
    PendingArtifactCommit,
)


@dataclass(frozen=True, slots=True)
class _OutputState:
    output: WatcherOutput
    claim_token: UUID | None = None
    consumed_token: UUID | None = None


@final
class InMemoryArtifactRecovery:
    """Keep recovery state in one explicitly non-durable process map."""

    def __init__(self) -> None:
        """Initialize process-local recovery maps."""
        self._outputs: dict[str, _OutputState] = {}
        self._reconciliations: dict[str, ArtifactReconciliation] = {}
        self._lock = RLock()

    @contextmanager
    def locked(self, reference: str) -> Generator[None, None, None]:
        """Serialize transitions inside this local adapter."""
        del reference
        with self._lock:
            yield

    def register_output(self, output: WatcherOutput) -> bool:
        """Register one output when its opaque reference is unused."""
        with self._lock:
            if output.reference in self._outputs:
                return False
            self._outputs[output.reference] = _OutputState(output)
            return True

    def resolve_output(
        self, scope: ArtifactScope, execution_id: UUID, reference: str
    ) -> WatcherOutput | None:
        """Resolve only an available output in the exact caller scope."""
        with self._lock:
            state = self._outputs.get(reference)
            return (
                state.output
                if state is not None and _claimable(state, scope, execution_id)
                else None
            )

    def claim_output(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
        token: UUID,
    ) -> WatcherClaim | None:
        """Fence an available exact-scope output with one claim token."""
        with self._lock:
            state = self._outputs.get(reference)
            if state is None or not _claimable(state, scope, execution_id):
                return None
            self._outputs[reference] = _OutputState(state.output, token)
            return WatcherClaim(reference=reference, token=token, output=state.output)

    def claim_pending(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        pending: PendingArtifactCommit,
    ) -> bool:
        """Atomically fence an output and persist its exact commit intent."""
        reference = pending.claim.reference
        with self._lock:
            state = self._outputs.get(reference)
            if (
                state is None
                or not _claimable(state, scope, execution_id)
                or state.output != pending.claim.output
            ):
                return False
            self._outputs[reference] = _OutputState(
                state.output,
                claim_token=pending.claim.token,
            )
            self._reconciliations[reference] = pending
            return True

    def release_claim(self, claim: WatcherClaim) -> bool:
        """Release an active claim when no commit intent exists."""
        with self._lock:
            state = self._outputs.get(claim.reference)
            if state is None:
                return False
            if state.consumed_token == claim.token:
                return state.output == claim.output
            if not self._active_without_reconciliation(state, claim):
                return False
            self._outputs[claim.reference] = _OutputState(state.output)
            return True

    def finalize_claim(self, claim: WatcherClaim) -> bool:
        """Consume an active claim when no commit intent exists."""
        with self._lock:
            state = self._outputs.get(claim.reference)
            if state is None:
                return False
            if state.consumed_token == claim.token:
                return state.output == claim.output
            if not self._active_without_reconciliation(state, claim):
                return False
            self._outputs[claim.reference] = _OutputState(
                state.output, consumed_token=claim.token
            )
            return True

    def reconciliation(self, reference: str) -> ArtifactReconciliation | None:
        """Read one exact reconciliation record."""
        with self._lock:
            return self._reconciliations.get(reference)

    def save_completed(self, pending: PendingArtifactCommit) -> bool:
        """Atomically consume a claim and persist its exact result."""
        completed = _completed(pending)
        with self._lock:
            state = self._outputs.get(pending.claim.reference)
            current = self._reconciliations.get(pending.claim.reference)
            if state is None:
                return False
            if current == completed:
                return state.consumed_token == pending.claim.token
            if current != pending or not _active_claim(state, pending.claim):
                return False
            self._outputs[pending.claim.reference] = _OutputState(
                state.output, consumed_token=pending.claim.token
            )
            self._reconciliations[pending.claim.reference] = completed
            return True

    def discard_pending(self, pending: PendingArtifactCommit) -> bool:
        """Atomically release a rejected claim and remove its intent."""
        with self._lock:
            state = self._outputs.get(pending.claim.reference)
            current = self._reconciliations.get(pending.claim.reference)
            if state is None:
                return False
            if current is None and state.claim_token is None:
                return True
            if current != pending or not _active_claim(state, pending.claim):
                return False
            self._outputs[pending.claim.reference] = _OutputState(state.output)
            del self._reconciliations[pending.claim.reference]
            return True

    def _active_without_reconciliation(
        self, state: _OutputState, claim: WatcherClaim
    ) -> bool:
        return (
            _active_claim(state, claim) and claim.reference not in self._reconciliations
        )


def _claimable(state: _OutputState, scope: ArtifactScope, execution_id: UUID) -> bool:
    output = state.output
    return (
        state.claim_token is None
        and state.consumed_token is None
        and output.org_id == scope.org_id
        and output.project_id == scope.project_id
        and output.requester_id == scope.requester_id
        and output.execution_id == execution_id
        and hashlib.sha256(output.payload).hexdigest() == output.content_sha256
    )


def _active_claim(state: _OutputState | None, claim: WatcherClaim) -> bool:
    return (
        state is not None
        and state.claim_token == claim.token
        and state.output == claim.output
    )


def _completed(pending: PendingArtifactCommit) -> CompletedArtifactCommit:
    return CompletedArtifactCommit(
        scope=pending.scope, draft=pending.draft, version=pending.version
    )
