import hashlib
import os
import socket
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from time import monotonic
from typing import ClassVar, final, override
from uuid import UUID

import pytest
from services.api.artifacts import (
    MAX_ARTIFACT_OUTPUT_BYTES,
    ArtifactCommitError,
    ArtifactError,
    ArtifactErrorCode,
    ArtifactRecovery,
    ArtifactRecoveryError,
    ArtifactScope,
    ArtifactService,
    ArtifactVersion,
    FileArtifactRecovery,
    InMemoryArtifactStore,
    OutputWatcher,
    StoreOutcome,
    VersionDraft,
)
from services.api.artifacts.file_recovery_storage import (
    MAX_RECOVERY_RECORD_BYTES,
    FileRecoveryState,
    FileRecoveryStorage,
    recovery_record_bytes_limit,
)
from services.api.artifacts.recovery import PendingArtifactCommit
from services.api.artifacts.store_contract import ArtifactStoreError

from .support import (
    EXECUTION_A,
    ORG_A,
    ORG_B,
    PROJECT_A,
    PROJECT_B,
    RECOVERY_INTEGRITY_KEY,
    RUNTIME_CONNECTION,
    SCOPE_A,
    SESSION_A,
    SESSION_B,
    SHA_A,
    SHA_B,
    FixedClock,
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


@final
class IndeterminateCommitStore(InMemoryArtifactStore):
    def __init__(self, *, commit_before_failure: bool, failed_reads: int) -> None:
        super().__init__(
            projects=frozenset({(ORG_A, PROJECT_A), (ORG_B, PROJECT_B)}),
            sessions=frozenset(
                {(ORG_A, PROJECT_A, SESSION_A), (ORG_B, PROJECT_B, SESSION_B)}
            ),
        )
        self.commit_before_failure = commit_before_failure
        self.failed_reads = failed_reads
        self.fail_commit_once = True

    @override
    def commit_version(
        self,
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        if not self.fail_commit_once:
            return super().commit_version(scope, base_version_no, version, payload)
        self.fail_commit_once = False
        if self.commit_before_failure:
            _ = super().commit_version(scope, base_version_no, version, payload)
        raise ArtifactCommitError

    @override
    def version(
        self,
        scope: ArtifactScope,
        version_id: UUID,
    ) -> ArtifactVersion | None:
        if self.failed_reads:
            self.failed_reads -= 1
            raise ArtifactStoreError
        return super().version(scope, version_id)


@final
class ObjectKeyFailureStore(InMemoryArtifactStore):
    fail_object_key_once: ClassVar[bool] = True

    def __init__(self) -> None:
        super().__init__(
            projects=frozenset({(ORG_A, PROJECT_A), (ORG_B, PROJECT_B)}),
            sessions=frozenset(
                {(ORG_A, PROJECT_A, SESSION_A), (ORG_B, PROJECT_B, SESSION_B)}
            ),
        )
        type(self).fail_object_key_once = True

    @staticmethod
    @override
    def object_key(scope: ArtifactScope, content_sha256: str) -> str:
        if ObjectKeyFailureStore.fail_object_key_once:
            ObjectKeyFailureStore.fail_object_key_once = False
            raise ArtifactStoreError
        return InMemoryArtifactStore.object_key(scope, content_sha256)


def reconciliation_service(
    store: InMemoryArtifactStore,
) -> tuple[ArtifactService, OutputWatcher]:
    _, _, watcher, clock = build_service()
    return (
        ArtifactService(
            store=store,
            watcher=watcher,
            ids=SequenceIds(artifact_ids(170, 24)),
            clock=clock,
            download_signing_key=bytes(range(32)),
        ),
        watcher,
    )


def restart_watcher(
    recovery: ArtifactRecovery,
    *,
    id_start: int,
) -> OutputWatcher:
    return OutputWatcher(
        ids=SequenceIds(artifact_ids(id_start, 8)),
        executions=frozenset(
            {
                (
                    ORG_A,
                    PROJECT_A,
                    SCOPE_A.requester_id,
                    EXECUTION_A,
                    "openai_codex",
                    RUNTIME_CONNECTION,
                )
            }
        ),
        recovery=recovery,
    )


def durable_recovery(root: Path) -> FileArtifactRecovery:
    return FileArtifactRecovery(
        root,
        integrity_key=RECOVERY_INTEGRITY_KEY,
    )


def local_store() -> InMemoryArtifactStore:
    return InMemoryArtifactStore(
        projects=frozenset({(ORG_A, PROJECT_A), (ORG_B, PROJECT_B)}),
        sessions=frozenset(
            {(ORG_A, PROJECT_A, SESSION_A), (ORG_B, PROJECT_B, SESSION_B)}
        ),
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


@pytest.mark.parametrize("commit_before_failure", [False, True])
def test_indeterminate_commit_preserves_output_for_exact_retry(
    commit_before_failure: bool,
) -> None:
    store = IndeterminateCommitStore(
        commit_before_failure=commit_before_failure,
        failed_reads=1,
    )
    service, watcher = reconciliation_service(store)
    artifact = service.create_artifact(SCOPE_A, "Indeterminate output")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"recoverable", "text/plain")
    request = draft(artifact.id, 0, reference)

    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)

    recovered = service.create_version(SCOPE_A, request)
    assert store.version_count(SCOPE_A, artifact.id) == 1
    assert service.read_content(SCOPE_A, recovered.id) == b"recoverable"


def test_reconciliation_survives_repeated_read_failures() -> None:
    store = IndeterminateCommitStore(commit_before_failure=False, failed_reads=2)
    service, watcher = reconciliation_service(store)
    artifact = service.create_artifact(SCOPE_A, "Repeated reads")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"still here", "text/plain")
    request = draft(artifact.id, 0, reference)

    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)
    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)

    recovered = service.create_version(SCOPE_A, request)
    assert service.read_content(SCOPE_A, recovered.id) == b"still here"


def test_pending_reconciliation_survives_service_and_watcher_restart(
    tmp_path: Path,
) -> None:
    store = IndeterminateCommitStore(commit_before_failure=False, failed_reads=1)
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    clock = FixedClock()
    service = ArtifactService(
        store=store,
        watcher=watcher,
        ids=SequenceIds(artifact_ids(220, 8)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )
    artifact = service.create_artifact(SCOPE_A, "Restart recovery")
    reference = watcher.register(
        SCOPE_A,
        EXECUTION_A,
        b"persist me\x00\xff",
        "application/octet-stream",
    )
    request = draft(artifact.id, 0, reference)

    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)

    restarted_watcher = restart_watcher(
        durable_recovery(recovery_root),
        id_start=230,
    )
    restarted = ArtifactService(
        store=store,
        watcher=restarted_watcher,
        ids=SequenceIds(artifact_ids(240, 8)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )

    recovered = restarted.create_version(SCOPE_A, request)
    assert store.version_count(SCOPE_A, artifact.id) == 1
    assert restarted.read_content(SCOPE_A, recovered.id) == b"persist me\x00\xff"
    conflicting = request.model_copy(update={"environment_sha256": "c" * 64})
    with pytest.raises(ArtifactError) as rejected:
        _ = restarted.create_version(SCOPE_A, conflicting)
    assert rejected.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID


def test_interrupted_pending_write_does_not_leave_an_orphan_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = local_store()
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    clock = FixedClock()
    service = ArtifactService(
        store=store,
        watcher=watcher,
        ids=SequenceIds(artifact_ids(220, 8)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )
    artifact = service.create_artifact(SCOPE_A, "Atomic intent")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"recover", "text/plain")
    request = draft(artifact.id, 0, reference)
    original_write = FileRecoveryStorage.write
    interrupted = False

    def interrupt_pending_write(
        storage: FileRecoveryStorage,
        state: FileRecoveryState,
    ) -> None:
        nonlocal interrupted
        match state.reconciliation:
            case PendingArtifactCommit() if not interrupted:
                interrupted = True
                raise ArtifactRecoveryError
            case _:
                original_write(storage, state)

    monkeypatch.setattr(FileRecoveryStorage, "write", interrupt_pending_write)
    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)
    monkeypatch.undo()
    restarted = ArtifactService(
        store=store,
        watcher=restart_watcher(durable_recovery(recovery_root), id_start=230),
        ids=SequenceIds(artifact_ids(240, 8)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )

    recovered = restarted.create_version(SCOPE_A, request)
    assert restarted.read_content(SCOPE_A, recovered.id) == b"recover"


def test_installed_pending_survives_directory_fsync_failure(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = local_store()
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    clock = FixedClock()
    service = ArtifactService(
        store=store,
        watcher=watcher,
        ids=SequenceIds(artifact_ids(220, 8)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )
    artifact = service.create_artifact(SCOPE_A, "Installed intent")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"recover", "text/plain")
    request = draft(artifact.id, 0, reference)
    original_fsync = os.fsync
    fsync_calls = 0

    def fail_directory_fsync(descriptor: int) -> None:
        nonlocal fsync_calls
        fsync_calls += 1
        if fsync_calls == 2:
            raise OSError
        original_fsync(descriptor)

    monkeypatch.setattr(os, "fsync", fail_directory_fsync)
    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)
    monkeypatch.undo()
    restarted = ArtifactService(
        store=store,
        watcher=restart_watcher(durable_recovery(recovery_root), id_start=230),
        ids=SequenceIds(artifact_ids(240, 8)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )

    recovered = restarted.create_version(SCOPE_A, request)
    assert restarted.read_content(SCOPE_A, recovered.id) == b"recover"


def test_completed_reconciliation_is_idempotent_after_full_restart(
    tmp_path: Path,
) -> None:
    store = local_store()
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    clock = FixedClock()
    service = ArtifactService(
        store=store,
        watcher=watcher,
        ids=SequenceIds(artifact_ids(220, 8)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )
    artifact = service.create_artifact(SCOPE_A, "Completed recovery")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"once", "text/plain")
    request = draft(artifact.id, 0, reference)
    created = service.create_version(SCOPE_A, request)
    restarted_watcher = restart_watcher(
        durable_recovery(recovery_root),
        id_start=230,
    )
    restarted = ArtifactService(
        store=store,
        watcher=restarted_watcher,
        ids=SequenceIds(artifact_ids(240, 8)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )

    recovered = restarted.create_version(SCOPE_A, request)
    assert recovered == created
    assert store.version_count(SCOPE_A, artifact.id) == 1
    with pytest.raises(ArtifactError) as replayed:
        _ = restarted_watcher.claim(SCOPE_A, EXECUTION_A, reference)
    assert replayed.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID


def test_file_recovery_rejects_tampered_payload_record_after_restart(
    tmp_path: Path,
) -> None:
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"sealed", "text/plain")
    record = next((recovery_root / "records").glob("*.json"))
    encoded = record.read_bytes()
    _ = record.write_bytes(encoded.replace(b"c2VhbGVk", b"c2VhbGVl", 1))
    restarted = restart_watcher(durable_recovery(recovery_root), id_start=220)

    with pytest.raises(ArtifactRecoveryError):
        _ = restarted.resolve(SCOPE_A, EXECUTION_A, reference)


def test_file_recovery_rejects_forged_record_with_recomputed_plain_hash(
    tmp_path: Path,
) -> None:
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"sealed", "text/plain")
    record = next((recovery_root / "records").glob("*.json"))
    encoded = record.read_bytes()
    forged = encoded.replace(b"c2VhbGVk", b"Zm9yZ2Vk", 1).replace(
        hashlib.sha256(b"sealed").hexdigest().encode(),
        hashlib.sha256(b"forged").hexdigest().encode(),
        1,
    )
    marker = b',"integrity_hmac_sha256":"'
    body_end = forged.index(marker)
    body = forged[len(b'{"body":') : body_end]
    forged = (
        forged[: body_end + len(marker)]
        + hashlib.sha256(body).hexdigest().encode()
        + b'"}'
    )
    _ = record.write_bytes(forged)
    restarted = restart_watcher(durable_recovery(recovery_root), id_start=220)

    with pytest.raises(ArtifactRecoveryError):
        _ = restarted.resolve(SCOPE_A, EXECUTION_A, reference)


def test_file_recovery_rejects_symlinked_record_after_restart(
    tmp_path: Path,
) -> None:
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"sealed", "text/plain")
    record = next((recovery_root / "records").glob("*.json"))
    external = tmp_path / "external-record.json"
    _ = record.replace(external)
    record.symlink_to(external)
    restarted = restart_watcher(durable_recovery(recovery_root), id_start=220)

    with pytest.raises(ArtifactRecoveryError):
        _ = restarted.resolve(SCOPE_A, EXECUTION_A, reference)


def test_file_recovery_rejects_fifo_without_blocking_global_lock(
    tmp_path: Path,
) -> None:
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"sealed", "text/plain")
    record = next((recovery_root / "records").glob("*.json"))
    record.unlink()
    os.mkfifo(record)
    restarted = restart_watcher(durable_recovery(recovery_root), id_start=220)
    started = monotonic()

    with pytest.raises(ArtifactRecoveryError):
        _ = restarted.resolve(SCOPE_A, EXECUTION_A, reference)

    assert monotonic() - started < 0.5


def test_file_recovery_rejects_unix_socket_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"sealed", "text/plain")
    record = next((recovery_root / "records").glob("*.json"))
    record.unlink()
    restarted = restart_watcher(durable_recovery(recovery_root), id_start=220)
    monkeypatch.chdir(tmp_path)
    socket_path = Path("recovery.sock")

    with socket.socket(socket.AF_UNIX) as endpoint:
        endpoint.bind(str(socket_path))
        _ = socket_path.replace(record)
        with pytest.raises(ArtifactRecoveryError):
            _ = restarted.resolve(SCOPE_A, EXECUTION_A, reference)


def test_file_recovery_rejects_device_mode_record(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"sealed", "text/plain")
    restarted = restart_watcher(durable_recovery(recovery_root), id_start=220)
    original_fstat = os.fstat

    def device_metadata(descriptor: int) -> os.stat_result:
        metadata = list(original_fstat(descriptor))
        metadata[stat.ST_MODE] = stat.S_IFCHR | 0o600
        return os.stat_result(metadata)

    monkeypatch.setattr(os, "fstat", device_metadata)

    with pytest.raises(ArtifactRecoveryError):
        _ = restarted.resolve(SCOPE_A, EXECUTION_A, reference)


def test_file_recovery_read_is_bounded_by_shared_payload_limit(
    tmp_path: Path,
) -> None:
    recovery_root = tmp_path / "artifact-recovery"
    watcher = restart_watcher(durable_recovery(recovery_root), id_start=210)
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"sealed", "text/plain")
    record = next((recovery_root / "records").glob("*.json"))
    with record.open("wb") as oversized:
        _ = oversized.truncate(MAX_RECOVERY_RECORD_BYTES + 1)
    restarted = restart_watcher(durable_recovery(recovery_root), id_start=220)

    with pytest.raises(ArtifactRecoveryError):
        _ = restarted.resolve(SCOPE_A, EXECUTION_A, reference)


def test_recovery_bound_covers_base64_pending_at_max_output_size() -> None:
    encoded_payload = 4 * ((MAX_ARTIFACT_OUTPUT_BYTES + 2) // 3)

    assert (
        recovery_record_bytes_limit(MAX_ARTIFACT_OUTPUT_BYTES)
        == MAX_RECOVERY_RECORD_BYTES
    )
    assert 2 * encoded_payload < MAX_RECOVERY_RECORD_BYTES


def test_conflicting_draft_cannot_replace_pending_exact_retry() -> None:
    store = IndeterminateCommitStore(commit_before_failure=False, failed_reads=1)
    service, watcher = reconciliation_service(store)
    artifact = service.create_artifact(SCOPE_A, "Pinned retry")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"pinned", "text/plain")
    request = draft(artifact.id, 0, reference)
    conflicting = request.model_copy(update={"environment_sha256": "c" * 64})

    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)
    with pytest.raises(ArtifactError) as rejected:
        _ = service.create_version(SCOPE_A, conflicting)
    assert rejected.value.code is ArtifactErrorCode.WATCHER_REFERENCE_INVALID

    recovered = service.create_version(SCOPE_A, request)
    assert service.read_content(SCOPE_A, recovered.id) == b"pinned"


def test_competing_exact_retries_return_one_reconciled_version() -> None:
    store = IndeterminateCommitStore(commit_before_failure=True, failed_reads=1)
    service, watcher = reconciliation_service(store)
    artifact = service.create_artifact(SCOPE_A, "Concurrent retry")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"once", "text/plain")
    request = draft(artifact.id, 0, reference)

    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)

    def retry(worker_index: int) -> ArtifactVersion:
        del worker_index
        return service.create_version(SCOPE_A, request)

    with ThreadPoolExecutor(max_workers=2) as executor:
        versions = tuple(executor.map(retry, range(2)))

    assert versions[0] == versions[1]
    assert store.version_count(SCOPE_A, artifact.id) == 1


def test_pre_intent_construction_failure_leaves_watcher_reference_available() -> None:
    store = ObjectKeyFailureStore()
    service, watcher = reconciliation_service(store)
    artifact = service.create_artifact(SCOPE_A, "Claim guard")
    reference = watcher.register(SCOPE_A, EXECUTION_A, b"retry", "text/plain")
    request = draft(artifact.id, 0, reference)

    with pytest.raises(ArtifactStoreError):
        _ = service.create_version(SCOPE_A, request)

    recovered = service.create_version(SCOPE_A, request)
    assert service.read_content(SCOPE_A, recovered.id) == b"retry"
