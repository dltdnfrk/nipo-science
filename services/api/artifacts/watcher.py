"""Execution-bound Output Watcher registration outside the sandbox."""

import hashlib
from threading import RLock
from typing import final
from uuid import UUID

from .models import (
    ArtifactError,
    ArtifactErrorCode,
    ArtifactScope,
    IdFactory,
    WatcherClaim,
    WatcherOutput,
)


@final
class OutputWatcher:
    """Register checksummed bytes only for trusted execution scopes."""

    def __init__(
        self,
        ids: IdFactory,
        executions: frozenset[tuple[UUID, UUID, UUID, UUID, str, UUID]],
    ) -> None:
        """Initialize an empty registry and trusted execution inventory."""
        self._ids = ids
        self._executions = {
            (org_id, project_id, requester_id, execution_id): (
                runtime_adapter_id,
                runtime_connection_id,
            )
            for (
                org_id,
                project_id,
                requester_id,
                execution_id,
                runtime_adapter_id,
                runtime_connection_id,
            ) in executions
        }
        self._outputs: dict[str, WatcherOutput] = {}
        self._claimed: dict[str, UUID] = {}
        self._consumed: dict[str, UUID] = {}
        self._lock = RLock()

    def register(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        payload: bytes,
        media_type: str,
    ) -> str:
        """Register bytes under a server-generated opaque reference."""
        execution_key = (
            scope.org_id,
            scope.project_id,
            scope.requester_id,
            execution_id,
        )
        binding = self._executions.get(execution_key)
        if binding is None or not media_type.strip():
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
        runtime_adapter_id, runtime_connection_id = binding
        reference = f"watcher/{self._ids.new_uuid7()}"
        output = WatcherOutput(
            reference=reference,
            org_id=scope.org_id,
            project_id=scope.project_id,
            requester_id=scope.requester_id,
            execution_id=execution_id,
            runtime_adapter_id=runtime_adapter_id,
            runtime_connection_id=runtime_connection_id,
            payload=payload,
            content_sha256=hashlib.sha256(payload).hexdigest(),
            media_type=media_type.strip().lower(),
        )
        with self._lock:
            if reference in self._outputs:
                raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
            self._outputs[reference] = output
        return reference

    def resolve(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
    ) -> WatcherOutput:
        """Resolve only an exact tenant-, project-, and execution-bound reference."""
        with self._lock:
            return self._resolve_locked(scope, execution_id, reference)

    def claim(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
    ) -> WatcherClaim:
        """Exclusively claim a registered output before Version commit."""
        with self._lock:
            output = self._resolve_locked(scope, execution_id, reference)
            token = self._ids.new_uuid7()
            self._claimed[reference] = token
            return WatcherClaim(reference=reference, token=token, output=output)

    def release(self, claim: WatcherClaim) -> None:
        """Release a claim after a rejected atomic Version transition."""
        with self._lock:
            if self._consumed.get(claim.reference) == claim.token:
                return
            if self._claimed.get(claim.reference) != claim.token:
                raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
            del self._claimed[claim.reference]

    def finalize(self, claim: WatcherClaim) -> None:
        """Make a successfully committed watcher reference non-replayable."""
        with self._lock:
            if self._consumed.get(claim.reference) == claim.token:
                return
            if self._claimed.get(claim.reference) != claim.token:
                raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
            del self._claimed[claim.reference]
            self._consumed[claim.reference] = claim.token

    def _resolve_locked(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
    ) -> WatcherOutput:
        output = self._outputs.get(reference)
        if (
            output is None
            or reference in self._claimed
            or reference in self._consumed
            or output.org_id != scope.org_id
            or output.project_id != scope.project_id
            or output.requester_id != scope.requester_id
            or output.execution_id != execution_id
        ):
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
        return output
