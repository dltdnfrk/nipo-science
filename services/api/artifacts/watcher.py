"""Execution-bound Output Watcher registration outside the sandbox."""

import hashlib
from typing import Final, final
from uuid import UUID

from .models import (
    MAX_ARTIFACT_OUTPUT_BYTES,
    ArtifactError,
    ArtifactErrorCode,
    ArtifactScope,
    ArtifactVersion,
    IdFactory,
    VersionDraft,
    WatcherClaim,
    WatcherOutput,
)
from .recovery import ArtifactRecovery, PendingArtifactCommit

SAFE_ARTIFACT_MEDIA_TYPES: Final[frozenset[str]] = frozenset(
    {
        "application/json",
        "application/octet-stream",
        "application/pdf",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "image/jpeg",
        "image/png",
        "image/tiff",
        "text/csv",
        "text/markdown",
        "text/plain",
        "text/tab-separated-values",
    }
)


@final
class OutputWatcher:
    """Register checksummed bytes only for trusted execution scopes."""

    def __init__(
        self,
        ids: IdFactory,
        executions: frozenset[tuple[UUID, UUID, UUID, UUID, str, UUID]],
        recovery: ArtifactRecovery,
    ) -> None:
        """Bind trusted executions to an explicitly selected recovery authority."""
        self._ids = ids
        self._recovery = recovery
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

    @property
    def recovery(self) -> ArtifactRecovery:
        """Expose the exact authority shared with ArtifactService."""
        return self._recovery

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
        if (
            binding is None
            or media_type not in SAFE_ARTIFACT_MEDIA_TYPES
            or len(payload) > MAX_ARTIFACT_OUTPUT_BYTES
        ):
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
            media_type=media_type,
        )
        if not self._recovery.register_output(output):
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
        return reference

    def resolve(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
    ) -> WatcherOutput:
        """Resolve only an exact tenant-, project-, and execution-bound reference."""
        output = self._recovery.resolve_output(scope, execution_id, reference)
        if output is None:
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
        return output

    def claim(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
    ) -> WatcherClaim:
        """Exclusively claim a registered output before Version commit."""
        claim = self._recovery.claim_output(
            scope,
            execution_id,
            reference,
            self._ids.new_uuid7(),
        )
        if claim is None:
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
        return claim

    def prepare_commit(
        self,
        scope: ArtifactScope,
        draft: VersionDraft,
        version: ArtifactVersion,
        output: WatcherOutput,
    ) -> PendingArtifactCommit:
        """Atomically claim an output together with its exact commit intent."""
        claim = WatcherClaim(
            reference=draft.watcher_reference,
            token=self._ids.new_uuid7(),
            output=output,
        )
        pending = PendingArtifactCommit(
            scope=scope,
            draft=draft,
            claim=claim,
            version=version,
        )
        if not self._recovery.claim_pending(
            scope,
            draft.producing_execution_id,
            pending,
        ):
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
        return pending

    def release(self, claim: WatcherClaim) -> None:
        """Release a claim after a rejected atomic Version transition."""
        if not self._recovery.release_claim(claim):
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)

    def finalize(self, claim: WatcherClaim) -> None:
        """Make a successfully committed watcher reference non-replayable."""
        if not self._recovery.finalize_claim(claim):
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
