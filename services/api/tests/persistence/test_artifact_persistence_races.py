from __future__ import annotations

import hashlib
import os
import stat
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Final
from uuid import UUID

import pytest

from services.api.artifacts import (
    ArtifactCommitError,
    ArtifactError,
    ArtifactErrorCode,
    StoreOutcome,
)
from services.api.tests.persistence.postgres_harness import psql
from services.api.tests.persistence.test_artifact_persistence import (
    SCOPE_A,
    build_artifact_service,
    version_draft,
)
from services.api.tests.persistence.test_rls import (
    ORG_A,
    PROJECT_A,
    USER_A,
    app_principal_sql,
)
from services.api.tests.persistence.test_rls_contracts import (
    ARTIFACT,
    PROVIDER,
    SESSION,
    SHA,
    VERSION,
    seed_artifact_version,
)
from services.api.tests.persistence.test_rls_contracts import (
    EXECUTION as EXECUTION_A,
)

pytestmark = pytest.mark.usefixtures("migrated_database")
DIRECT_ARCHIVED_VERSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e70"


def test_failed_metadata_insert_compensates_new_private_blob(tmp_path: Path) -> None:
    seed_artifact_version()
    service, store, watcher = build_artifact_service(
        tmp_path,
        id_start=40,
        watcher_start=20,
    )
    artifact = service.create_artifact(SCOPE_A, "Compensated output")
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"valid",
        "text/plain",
    )
    first = service.create_version(SCOPE_A, version_draft(artifact.id, reference, 0))
    payload = b"must-not-orphan"
    digest = hashlib.sha256(payload).hexdigest()
    duplicate_id = first.model_copy(
        update={
            "version_no": 2,
            "object_key": store.object_key(SCOPE_A, digest),
            "content_sha256": digest,
            "size_bytes": len(payload),
        }
    )
    before = frozenset(path for path in tmp_path.rglob("*") if path.is_file())

    outcome = store.commit_version(SCOPE_A, 1, duplicate_id, payload)

    after = frozenset(path for path in tmp_path.rglob("*") if path.is_file())
    assert outcome is StoreOutcome.INVALID_LINEAGE
    assert after == before


def test_filesystem_failure_removes_pending_blob_and_releases_claim(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_artifact_version()
    service, _, watcher = build_artifact_service(tmp_path, id_start=50)
    artifact = service.create_artifact(SCOPE_A, "Filesystem recovery")
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"retryable filesystem output",
        "text/plain",
    )
    original_fsync = os.fsync

    def fail_fsync(descriptor: int) -> None:
        del descriptor
        message = "injected fsync failure"
        raise OSError(message)

    monkeypatch.setattr(os, "fsync", fail_fsync)
    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, version_draft(artifact.id, reference, 0))
    assert tuple(path for path in tmp_path.rglob("*") if path.is_file()) == ()

    monkeypatch.setattr(os, "fsync", original_fsync)
    version = service.create_version(
        SCOPE_A,
        version_draft(artifact.id, reference, 0),
    )
    assert service.read_content(SCOPE_A, version.id) == b"retryable filesystem output"


@pytest.mark.parametrize("failure_point", ["link", "directory_fsync"])
def test_blob_publication_failure_never_commits_metadata_and_exact_retry_is_unique(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    failure_point: str,
) -> None:
    seed_artifact_version()
    id_start = 52 if failure_point == "link" else 56
    service, _, watcher = build_artifact_service(tmp_path, id_start=id_start)
    artifact = service.create_artifact(SCOPE_A, "Durable publication retry")
    payload = f"durable publication boundary:{failure_point}".encode()
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        payload,
        "text/plain",
    )
    request = version_draft(artifact.id, reference, 0)
    original_fsync = os.fsync
    original_link = os.link
    link_completed = False
    failed = False

    def fail_selected_link(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal failed, link_completed
        if failure_point == "link" and not failed:
            failed = True
            message = "injected final link failure"
            raise OSError(message)
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )
        link_completed = True

    def fail_selected_fsync(descriptor: int) -> None:
        nonlocal failed
        if (
            failure_point == "directory_fsync"
            and link_completed
            and not failed
            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
        ):
            failed = True
            message = "injected final directory fsync failure"
            raise OSError(message)
        original_fsync(descriptor)

    monkeypatch.setattr(os, "link", fail_selected_link)
    monkeypatch.setattr(os, "fsync", fail_selected_fsync)

    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)

    assert failed
    assert psql(
        "SELECT count(*) FROM artifact_versions WHERE artifact_id = "
        f"'{artifact.id}'"
    ).stdout.strip() == "0"
    assert not tuple(path for path in tmp_path.rglob("*") if path.is_file())

    recovered = service.create_version(SCOPE_A, request)
    replayed = service.create_version(SCOPE_A, request)
    assert recovered == replayed
    assert service.read_content(SCOPE_A, recovered.id) == payload
    assert psql(
        "SELECT count(*) FROM artifact_versions WHERE artifact_id = "
        f"'{artifact.id}'"
    ).stdout.strip() == "1"
    blob_files = tuple(path for path in tmp_path.rglob("*") if path.is_file())
    assert len(blob_files) == 1
    assert not tuple(tmp_path.rglob("*.pending"))


def test_recovery_rename_failure_precedes_metadata_and_allows_exact_retry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seed_artifact_version()
    service, _, watcher = build_artifact_service(tmp_path, id_start=54)
    artifact = service.create_artifact(SCOPE_A, "Recovery publication retry")
    payload = b"recovery rename retry"
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        payload,
        "text/plain",
    )
    request = version_draft(artifact.id, reference, 0)
    original_replace = Path.replace
    fail_once = True

    def fail_first_replace(source: Path, target: Path) -> Path:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            message = "injected recovery rename failure"
            raise OSError(message)
        return original_replace(source, target)

    monkeypatch.setattr(Path, "replace", fail_first_replace)

    with pytest.raises(ArtifactCommitError):
        _ = service.create_version(SCOPE_A, request)

    assert psql(
        "SELECT count(*) FROM artifact_versions WHERE artifact_id = "
        f"'{artifact.id}'"
    ).stdout.strip() == "0"
    assert not tuple(path for path in tmp_path.rglob("*") if path.is_file())

    recovered = service.create_version(SCOPE_A, request)
    replayed = service.create_version(SCOPE_A, request)
    assert recovered == replayed
    assert service.read_content(SCOPE_A, recovered.id) == payload
    assert psql(
        "SELECT count(*) FROM artifact_versions WHERE artifact_id = "
        f"'{artifact.id}'"
    ).stdout.strip() == "1"


def test_archived_project_blocks_durable_session_attachment(tmp_path: Path) -> None:
    seed_artifact_version()
    _ = psql(f"UPDATE projects SET archived_at = NULL WHERE id = '{PROJECT_A}'")
    service, _, watcher = build_artifact_service(
        tmp_path,
        id_start=60,
        watcher_start=40,
    )
    artifact = service.create_artifact(SCOPE_A, "Archive association")
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"archived",
        "text/plain",
    )
    version = service.create_version(SCOPE_A, version_draft(artifact.id, reference, 0))
    _ = psql(
        f"UPDATE projects SET archived_at = CURRENT_TIMESTAMP WHERE id = '{PROJECT_A}'"
    )
    try:
        with pytest.raises(ArtifactError) as rejected:
            _ = service.attach_session(SCOPE_A, UUID(SESSION), version.id)
        assert rejected.value.code is ArtifactErrorCode.PROJECT_ARCHIVED
    finally:
        _ = psql(f"UPDATE projects SET archived_at = NULL WHERE id = '{PROJECT_A}'")


def test_archived_project_blocks_durable_version_and_blob_write(tmp_path: Path) -> None:
    seed_artifact_version()
    _ = psql(f"UPDATE projects SET archived_at = NULL WHERE id = '{PROJECT_A}'")
    service, _, watcher = build_artifact_service(
        tmp_path,
        id_start=70,
        watcher_start=50,
    )
    artifact = service.create_artifact(SCOPE_A, "Archive version")
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"blocked",
        "text/plain",
    )
    _ = psql(
        f"UPDATE projects SET archived_at = CURRENT_TIMESTAMP WHERE id = '{PROJECT_A}'"
    )
    try:
        with pytest.raises(ArtifactError) as rejected:
            _ = service.create_version(
                SCOPE_A,
                version_draft(artifact.id, reference, 0),
            )
        files = tuple(path for path in tmp_path.rglob("*") if path.is_file())
        assert rejected.value.code is ArtifactErrorCode.PROJECT_ARCHIVED
        assert files == ()
    finally:
        _ = psql(f"UPDATE projects SET archived_at = NULL WHERE id = '{PROJECT_A}'")


def test_archived_session_blocks_versions_and_associations(tmp_path: Path) -> None:
    seed_artifact_version()
    service, _, watcher = build_artifact_service(
        tmp_path,
        id_start=75,
        watcher_start=55,
    )
    artifact = service.create_artifact(SCOPE_A, "Archived Session output")
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"inactive session",
        "text/plain",
    )
    _ = psql(
        f"UPDATE sessions SET archived_at = CURRENT_TIMESTAMP WHERE id = '{SESSION}'"
    )
    principal = "SET ROLE science_workbench_app; " + app_principal_sql(ORG_A, USER_A)
    try:
        with pytest.raises(ArtifactError) as version_rejected:
            _ = service.create_version(
                SCOPE_A,
                version_draft(artifact.id, reference, 0),
            )
        assert version_rejected.value.code is ArtifactErrorCode.INVALID_LINEAGE
        assert tuple(path for path in tmp_path.rglob("*") if path.is_file()) == ()

        with pytest.raises(ArtifactError) as association_rejected:
            _ = service.attach_session(SCOPE_A, UUID(SESSION), UUID(VERSION))
        assert association_rejected.value.code is ArtifactErrorCode.NOT_FOUND

        direct_association = psql(
            principal + "INSERT INTO session_artifact_versions "
            "(org_id, project_id, session_id, artifact_version_id, revision) "
            f"VALUES ('{ORG_A}', '{PROJECT_A}', '{SESSION}', '{VERSION}', 1)",
            check=False,
        )
        assert direct_association.returncode != 0
        assert "artifact association scope is inactive" in direct_association.stderr

        direct = psql(
            principal
            + "INSERT INTO artifact_versions (id, org_id, project_id, artifact_id, "
            "producing_execution_id, runtime_connection_id, version, object_key, "
            "content_sha256, size_bytes, media_type, environment_sha256, "
            "code_sha256, runtime_adapter_id, skill_content_hashes, source_hashes) "
            f"VALUES ('{DIRECT_ARCHIVED_VERSION}', '{ORG_A}', '{PROJECT_A}', "
            f"'{ARTIFACT}', '{EXECUTION_A}', '{PROVIDER}', 2, "
            f"'org/{ORG_A}/project/{PROJECT_A}/sha256/{'c' * 64}', "
            f"'{'c' * 64}', 1, 'text/plain', '{SHA}', '{SHA}', "
            "'openai_codex', '{}', '{}')",
            check=False,
        )
        assert direct.returncode != 0
        assert "artifact version scope mismatch" in direct.stderr
    finally:
        _ = psql(f"UPDATE sessions SET archived_at = NULL WHERE id = '{SESSION}'")


def test_concurrent_durable_session_attachment_has_stable_duplicate(
    tmp_path: Path,
) -> None:
    seed_artifact_version()
    _ = psql(f"UPDATE projects SET archived_at = NULL WHERE id = '{PROJECT_A}'")
    first, _, watcher = build_artifact_service(
        tmp_path,
        id_start=80,
        watcher_start=60,
    )
    second, _, _ = build_artifact_service(
        tmp_path,
        id_start=100,
        watcher_start=120,
    )
    artifact = first.create_artifact(SCOPE_A, "Concurrent association")
    reference = watcher.register(
        SCOPE_A,
        UUID(EXECUTION_A),
        b"association",
        "text/plain",
    )
    version = first.create_version(SCOPE_A, version_draft(artifact.id, reference, 0))

    with ThreadPoolExecutor(max_workers=2) as pool:
        futures = (
            pool.submit(first.attach_session, SCOPE_A, UUID(SESSION), version.id),
            pool.submit(second.attach_session, SCOPE_A, UUID(SESSION), version.id),
        )
    outcomes: list[int | ArtifactErrorCode] = []
    for future in futures:
        try:
            outcomes.append(future.result().revision)
        except ArtifactError as error:
            outcomes.append(error.code)
    assert sorted(str(outcome) for outcome in outcomes) == [
        "1",
        str(ArtifactErrorCode.ASSOCIATION_EXISTS),
    ]
