"""Private filesystem persistence for Artifact recovery authority state."""

from contextlib import AbstractContextManager
from pathlib import Path
from typing import final
from uuid import UUID

from .file_recovery_storage import FileRecoveryState, FileRecoveryStorage
from .models import ArtifactScope, WatcherClaim, WatcherOutput
from .recovery import (
    ArtifactReconciliation,
    CompletedArtifactCommit,
    PendingArtifactCommit,
)


@final
class FileArtifactRecovery:
    """Persist each output and its commit fence as one atomic private record."""

    def __init__(self, root: Path, *, integrity_key: bytes) -> None:
        """Bind an explicit private root; callers own its durable lifecycle."""
        self._storage = FileRecoveryStorage(root, integrity_key=integrity_key)

    def locked(self, reference: str) -> AbstractContextManager[None]:
        """Serialize recovery transitions across adapter instances."""
        return self._storage.locked(reference)

    def register_output(self, output: WatcherOutput) -> bool:
        """Persist one new output record under its opaque reference."""
        with self.locked(output.reference):
            if self._storage.read(output.reference) is not None:
                return False
            self._storage.write(FileRecoveryState(output=output))
            return True

    def resolve_output(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
    ) -> WatcherOutput | None:
        """Resolve only an available output in the exact caller scope."""
        with self.locked(reference):
            state = self._storage.read(reference)
            if state is None or not _claimable(state, scope, execution_id):
                return None
            return state.output

    def claim_output(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        reference: str,
        token: UUID,
    ) -> WatcherClaim | None:
        """Persist a fenced claim for one available exact-scope output."""
        with self.locked(reference):
            state = self._storage.read(reference)
            if state is None or not _claimable(state, scope, execution_id):
                return None
            self._storage.write(state.model_copy(update={"claim_token": token}))
            return WatcherClaim(reference=reference, token=token, output=state.output)

    def claim_pending(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
        pending: PendingArtifactCommit,
    ) -> bool:
        """Atomically fence an output and persist its exact commit intent."""
        reference = pending.claim.reference
        with self.locked(reference):
            state = self._storage.read(reference)
            if (
                state is None
                or not _claimable(state, scope, execution_id)
                or state.output != pending.claim.output
            ):
                return False
            self._storage.write(
                state.model_copy(
                    update={
                        "claim_token": pending.claim.token,
                        "reconciliation": pending,
                    }
                )
            )
            return True

    def release_claim(self, claim: WatcherClaim) -> bool:
        """Release an exact active claim when no commit intent exists."""
        with self.locked(claim.reference):
            state = self._storage.read(claim.reference)
            if state is None:
                return False
            if state.consumed_token == claim.token:
                return state.output == claim.output
            if not _active_claim(state, claim) or state.reconciliation is not None:
                return False
            self._storage.write(state.model_copy(update={"claim_token": None}))
            return True

    def finalize_claim(self, claim: WatcherClaim) -> bool:
        """Persist a non-replayable fence when no commit intent exists."""
        with self.locked(claim.reference):
            state = self._storage.read(claim.reference)
            if state is None:
                return False
            if state.consumed_token == claim.token:
                return state.output == claim.output
            if not _active_claim(state, claim) or state.reconciliation is not None:
                return False
            self._storage.write(
                state.model_copy(
                    update={"claim_token": None, "consumed_token": claim.token}
                )
            )
            return True

    def reconciliation(self, reference: str) -> ArtifactReconciliation | None:
        """Load one integrity-checked reconciliation result."""
        with self.locked(reference):
            state = self._storage.read(reference)
            return None if state is None else state.reconciliation

    def save_completed(self, pending: PendingArtifactCommit) -> bool:
        """Atomically consume a claim and persist its exact Version result."""
        completed = _completed(pending)
        with self.locked(pending.claim.reference):
            state = self._storage.read(pending.claim.reference)
            if state is None:
                return False
            if state.reconciliation == completed:
                return state.consumed_token == pending.claim.token
            if state.reconciliation != pending or not _active_claim(
                state, pending.claim
            ):
                return False
            self._storage.write(
                state.model_copy(
                    update={
                        "claim_token": None,
                        "consumed_token": pending.claim.token,
                        "reconciliation": completed,
                    }
                )
            )
            return True

    def discard_pending(self, pending: PendingArtifactCommit) -> bool:
        """Atomically release a rejected claim and remove its intent."""
        with self.locked(pending.claim.reference):
            state = self._storage.read(pending.claim.reference)
            if state is None:
                return False
            if state.reconciliation is None and state.claim_token is None:
                return True
            if state.reconciliation != pending or not _active_claim(
                state, pending.claim
            ):
                return False
            self._storage.write(
                state.model_copy(update={"claim_token": None, "reconciliation": None})
            )
            return True


def _claimable(
    state: FileRecoveryState,
    scope: ArtifactScope,
    execution_id: UUID,
) -> bool:
    output = state.output
    return (
        state.claim_token is None
        and state.consumed_token is None
        and state.reconciliation is None
        and output.org_id == scope.org_id
        and output.project_id == scope.project_id
        and output.requester_id == scope.requester_id
        and output.execution_id == execution_id
    )


def _active_claim(state: FileRecoveryState, claim: WatcherClaim) -> bool:
    return state.claim_token == claim.token and state.output == claim.output


def _completed(pending: PendingArtifactCommit) -> CompletedArtifactCommit:
    return CompletedArtifactCommit(
        scope=pending.scope,
        draft=pending.draft,
        version=pending.version,
    )
