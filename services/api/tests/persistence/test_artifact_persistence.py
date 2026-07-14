from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, final
from uuid import UUID

import pytest

from services.api.artifacts import (
    ArtifactCommitError,
    ArtifactError,
    ArtifactErrorCode,
    ArtifactScope,
    ArtifactService,
    OutputWatcher,
    PostgresArtifactStore,
    PrivateBlobStore,
    VersionDraft,
)
from services.api.artifacts.store_contract import BlobWriteError
from services.api.tests.persistence.postgres_harness import database_url_asyncpg, psql
from services.api.tests.persistence.test_rls import ORG_A, PROJECT_A, USER_A
from services.api.tests.persistence.test_rls_contracts import (
    EXECUTION as EXECUTION_A,
)
from services.api.tests.persistence.test_rls_contracts import (
    PROVIDER as RUNTIME_CONNECTION,
)
from services.api.tests.persistence.test_rls_contracts import (
    SHA as SHA_A,
)
from services.api.tests.persistence.test_rls_contracts import seed_artifact_version

if TYPE_CHECKING:
    from pathlib import Path

pytestmark = pytest.mark.usefixtures("migrated_database")
SIGNING_KEY: Final = bytes(range(32))
SHA_B: Final = "b" * 64
SCOPE_A: Final = ArtifactScope(
    org_id=UUID(ORG_A),
    project_id=UUID(PROJECT_A),
    requester_id=UUID(USER_A),
)


@final
class FixedClock:
    def now(self) -> datetime:
        return datetime(2026, 7, 13, 6, tzinfo=UTC)


@final
class SequenceIds:
    def __init__(self, values: tuple[UUID, ...]) -> None:
        self._values = iter(values)

    def new_uuid7(self) -> UUID:
        return next(self._values)


def artifact_ids(start: int, count: int) -> tuple[UUID, ...]:
    return tuple(
        UUID(f"018f47a0-7b9c-7c{start + offset:02x}-8def-0123456789ab")
        for offset in range(count)
    )


def build_artifact_service(
    root: Path,
    *,
    id_start: int = 200,
    watcher_start: int = 180,
) -> tuple[ArtifactService, PostgresArtifactStore, OutputWatcher]:
    store = PostgresArtifactStore(database_url_asyncpg(), PrivateBlobStore(root))
    watcher = OutputWatcher(
        ids=SequenceIds(artifact_ids(watcher_start, 16)),
        executions=frozenset(
            {
                (
                    SCOPE_A.org_id,
                    SCOPE_A.project_id,
                    SCOPE_A.requester_id,
                    UUID(EXECUTION_A),
                    "openai_codex",
                    UUID(RUNTIME_CONNECTION),
                )
            }
        ),
    )
    return (
        ArtifactService(
            store=store,
            watcher=watcher,
            ids=SequenceIds(artifact_ids(id_start, 24)),
            clock=FixedClock(),
            download_signing_key=SIGNING_KEY,
        ),
        store,
        watcher,
    )


def version_draft(artifact_id: UUID, reference: str, base: int) -> VersionDraft:
    return VersionDraft.model_validate(
        {
            "artifact_id": artifact_id,
            "base_version_no": base,
            "watcher_reference": reference,
            "producing_execution_id": UUID(EXECUTION_A),
            "environment_sha256": SHA_A,
            "code_sha256": SHA_B,
            "runtime_adapter_id": "openai_codex",
            "runtime_connection_id": UUID(RUNTIME_CONNECTION),
            "skill_content_hashes": (SHA_A,),
            "source_hashes": (SHA_B,),
            "input_version_ids": (),
        }
    )


def test_postgres_versions_and_private_blobs_survive_adapter_restart(
    tmp_path: Path,
) -> None:
    seed_artifact_version()
    service, _, watcher = build_artifact_service(tmp_path)
    artifact = service.create_artifact(SCOPE_A, "Durable probe output")
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"persistent",
        "text/plain",
    )
    version = service.create_version(SCOPE_A, version_draft(artifact.id, reference, 0))

    restarted = PostgresArtifactStore(
        database_url_asyncpg(),
        PrivateBlobStore(tmp_path),
    )

    assert restarted.version(SCOPE_A, version.id) == version
    assert restarted.read_content(SCOPE_A, version.id) == b"persistent"
    assert version.object_key.endswith(version.content_sha256)


def test_postgres_store_uses_requester_scoped_rls_context(tmp_path: Path) -> None:
    seed_artifact_version()
    service, _, _ = build_artifact_service(tmp_path, id_start=220)
    other_requester = ArtifactScope(
        org_id=SCOPE_A.org_id,
        project_id=SCOPE_A.project_id,
        requester_id=UUID("018f47a0-7b9c-7a05-8def-0123456789ab"),
    )

    artifact = service.create_artifact(SCOPE_A, "Scoped")

    assert artifact.project_id == SCOPE_A.project_id
    with pytest.raises(ArtifactError) as rejected:
        _ = service.create_artifact(other_requester, "No active membership")
    assert rejected.value.code is ArtifactErrorCode.NOT_FOUND


def test_download_redemption_rechecks_archive_under_project_lock(
    tmp_path: Path,
) -> None:
    seed_artifact_version()
    service, _, watcher = build_artifact_service(tmp_path, id_start=230)
    artifact = service.create_artifact(SCOPE_A, "Atomic redemption")
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"authorized before archive",
        "text/plain",
    )
    version = service.create_version(SCOPE_A, version_draft(artifact.id, reference, 0))
    download = service.issue_download(SCOPE_A, version.id, timedelta(minutes=1))
    _ = psql(
        f"UPDATE projects SET archived_at = CURRENT_TIMESTAMP WHERE id = '{PROJECT_A}'"
    )
    try:
        with pytest.raises(ArtifactError) as rejected:
            _ = service.redeem_download(SCOPE_A, download.token)
        assert rejected.value.code is ArtifactErrorCode.PROJECT_ARCHIVED
    finally:
        _ = psql(f"UPDATE projects SET archived_at = NULL WHERE id = '{PROJECT_A}'")


def test_compensation_failure_is_reconciled_and_releases_watcher_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_artifact_version()
    service, store, watcher = build_artifact_service(tmp_path, id_start=130)
    artifact = service.create_artifact(SCOPE_A, "Compensation retry")
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"first",
        "text/plain",
    )
    first = service.create_version(SCOPE_A, version_draft(artifact.id, reference, 0))
    retry_reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"second after compensation",
        "text/plain",
    )
    retry_service = ArtifactService(
        store=store,
        watcher=watcher,
        ids=SequenceIds((first.id, *artifact_ids(240, 4))),
        clock=FixedClock(),
        download_signing_key=SIGNING_KEY,
    )
    retry_draft = version_draft(artifact.id, retry_reference, 1)

    def fail_discard(blob_store: PrivateBlobStore, object_key: str) -> None:
        del blob_store, object_key
        raise BlobWriteError

    monkeypatch.setattr(PrivateBlobStore, "discard", fail_discard)
    with pytest.raises(ArtifactCommitError):
        _ = retry_service.create_version(SCOPE_A, retry_draft)

    monkeypatch.undo()
    second = retry_service.create_version(SCOPE_A, retry_draft)
    assert second.version_no == 2
    assert (
        retry_service.read_content(SCOPE_A, second.id) == b"second after compensation"
    )


def test_postgres_row_lock_allows_exactly_one_concurrent_base(tmp_path: Path) -> None:
    seed_artifact_version()
    first, _, first_watcher = build_artifact_service(
        tmp_path,
        id_start=140,
        watcher_start=100,
    )
    second, _, second_watcher = build_artifact_service(
        tmp_path,
        id_start=160,
        watcher_start=80,
    )
    artifact = first.create_artifact(SCOPE_A, "Concurrent durable output")
    first_reference = first_watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"first",
        "text/plain",
    )
    second_reference = second_watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"second",
        "text/plain",
    )

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (
            pool.submit(
                first.create_version,
                SCOPE_A,
                version_draft(artifact.id, first_reference, 0),
            ),
            pool.submit(
                second.create_version,
                SCOPE_A,
                version_draft(artifact.id, second_reference, 0),
            ),
        )

    outcomes: list[int | ArtifactErrorCode] = []
    for future in futures:
        try:
            outcomes.append(future.result().version_no)
        except ArtifactError as error:
            outcomes.append(error.code)
    assert sorted(str(outcome) for outcome in outcomes) == [
        "1",
        str(ArtifactErrorCode.STALE_BASE),
    ]
