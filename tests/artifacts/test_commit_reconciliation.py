from typing import final, override
from uuid import UUID

import pytest
from services.api.artifacts import (
    ArtifactCommitError,
    ArtifactError,
    ArtifactErrorCode,
    ArtifactScope,
    ArtifactService,
    ArtifactVersion,
    InMemoryArtifactStore,
    StoreOutcome,
    VersionDraft,
)

from .support import (
    EXECUTION_A,
    ORG_A,
    ORG_B,
    PROJECT_A,
    PROJECT_B,
    RUNTIME_CONNECTION,
    SCOPE_A,
    SESSION_A,
    SESSION_B,
    SHA_A,
    SHA_B,
    SequenceIds,
    artifact_ids,
    build_service,
)


@final
class CommitFailureStore(InMemoryArtifactStore):
    def __init__(self) -> None:
        super().__init__(
            projects=frozenset({(ORG_A, PROJECT_A), (ORG_B, PROJECT_B)}),
            sessions=frozenset(
                {(ORG_A, PROJECT_A, SESSION_A), (ORG_B, PROJECT_B, SESSION_B)}
            ),
        )
        self.fail_next_commit = True

    @override
    def commit_version(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        if self.fail_next_commit:
            self.fail_next_commit = False
            raise ArtifactCommitError
        return super().commit_version(scope, base_version_no, version, payload)


@final
class PostCommitFailureStore(InMemoryArtifactStore):
    def __init__(self) -> None:
        super().__init__(
            projects=frozenset({(ORG_A, PROJECT_A), (ORG_B, PROJECT_B)}),
            sessions=frozenset(
                {(ORG_A, PROJECT_A, SESSION_A), (ORG_B, PROJECT_B, SESSION_B)}
            ),
        )
        self.fail_after_commit = False

    @override
    def commit_version(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        outcome = super().commit_version(scope, base_version_no, version, payload)
        if self.fail_after_commit:
            self.fail_after_commit = False
            raise ArtifactCommitError
        return outcome

    @override
    def version(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> ArtifactVersion | None:
        record = super().version(scope, version_id)
        if record is None:
            return None
        return record.model_copy(
            update={"input_version_ids": tuple(sorted(record.input_version_ids))}
        )


def draft(
    artifact_id: UUID,
    base_version_no: int,
    watcher_reference: str,
    input_version_ids: tuple[UUID, ...] = (),
) -> VersionDraft:
    return VersionDraft.model_validate(
        {
            "artifact_id": artifact_id,
            "base_version_no": base_version_no,
            "watcher_reference": watcher_reference,
            "producing_execution_id": EXECUTION_A,
            "environment_sha256": SHA_A,
            "code_sha256": SHA_B,
            "runtime_adapter_id": "openai_codex",
            "runtime_connection_id": RUNTIME_CONNECTION,
            "skill_content_hashes": (SHA_A,),
            "source_hashes": (SHA_B,),
            "input_version_ids": input_version_ids,
        }
    )


def test_commit_exception_releases_the_exact_watcher_claim() -> None:
    _, _, watcher, clock = build_service()
    store = CommitFailureStore()
    service = ArtifactService(
        store=store,
        watcher=watcher,
        ids=SequenceIds(artifact_ids(140, 8)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )
    artifact = service.create_artifact(SCOPE_A, "Retryable output")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"durable", "text/plain")

    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, draft(artifact.id, 0, reference))

    version = service.create_version(SCOPE_A, draft(artifact.id, 0, reference))
    assert version.version_no == 1
    assert service.read_content(SCOPE_A, version.id) == b"durable"


def test_ambiguous_commit_canonicalizes_lineage_and_prevents_replay() -> None:
    _, _, watcher, clock = build_service()
    store = PostCommitFailureStore()
    service = ArtifactService(
        store=store,
        watcher=watcher,
        ids=SequenceIds(artifact_ids(150, 16)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )
    source = service.create_artifact(SCOPE_A, "Lineage inputs")
    source_ref = watcher.register(SCOPE_A, EXECUTION_A, b"one", "text/plain")
    first = service.create_version(SCOPE_A, draft(source.id, 0, source_ref))
    source_ref = watcher.register(SCOPE_A, EXECUTION_A, b"two", "text/plain")
    second = service.create_version(SCOPE_A, draft(source.id, 1, source_ref))
    artifact = service.create_artifact(SCOPE_A, "Committed output")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"once", "text/plain")
    supplied = (second.id, first.id)
    store.fail_after_commit = True

    version = service.create_version(
        SCOPE_A,
        draft(artifact.id, 0, reference, supplied),
    )

    assert version.input_version_ids == tuple(sorted(supplied))
    assert store.version_count(SCOPE_A, artifact.id) == 1
    with pytest.raises(ArtifactError) as replayed:
        _ = service.create_version(SCOPE_A, draft(artifact.id, 1, reference))
    assert replayed.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID
