import hashlib
import os
import stat
from pathlib import Path
from typing import Final

import pytest
from services.api.artifacts import PrivateBlobStore
from services.api.artifacts.store_contract import BlobIntegrityError, BlobWriteError

ORG_ID: Final = "018f47a0-7b9c-7a01-8def-0123456789ab"
PROJECT_ID: Final = "018f47a0-7b9c-7a02-8def-0123456789ab"


def object_key(payload: bytes) -> tuple[str, str]:
    digest = hashlib.sha256(payload).hexdigest()
    return f"org/{ORG_ID}/project/{PROJECT_ID}/sha256/{digest}", digest


def test_private_root_creation_syncs_each_new_directory_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    original_mkdir = os.mkdir
    original_fsync = os.fsync

    def trace_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        original_mkdir(path, mode, dir_fd=dir_fd)
        events.append("mkdir")

    def trace_fsync(descriptor: int) -> None:
        assert stat.S_ISDIR(os.fstat(descriptor).st_mode)
        events.append("dir_fsync")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "mkdir", trace_mkdir)
    monkeypatch.setattr(os, "fsync", trace_fsync)

    root = tmp_path / "authority" / "nested" / "blobs"
    _ = PrivateBlobStore(root)

    mkdir_indices = [index for index, event in enumerate(events) if event == "mkdir"]
    assert len(mkdir_indices) == 3
    for position, mkdir_index in enumerate(mkdir_indices):
        boundary = (
            mkdir_indices[position + 1]
            if position + 1 < len(mkdir_indices)
            else len(events)
        )
        assert events[mkdir_index + 1 : boundary].count("dir_fsync") >= 2
    assert all(
        stat.S_IMODE(directory.stat().st_mode) == 0o700
        for directory in (root, root.parent, root.parent.parent)
    )


def test_private_root_fsync_failure_is_retryable(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "authority" / "blobs"
    original_fsync = os.fsync
    original_mkdir = os.mkdir
    directory_created = False
    fail_once = True

    def track_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal directory_created
        original_mkdir(path, mode, dir_fd=dir_fd)
        directory_created = True

    def fail_first_fsync(descriptor: int) -> None:
        nonlocal fail_once
        if directory_created and fail_once:
            fail_once = False
            message = "injected root fsync failure"
            raise OSError(message)
        original_fsync(descriptor)

    monkeypatch.setattr(os, "mkdir", track_mkdir)
    monkeypatch.setattr(os, "fsync", fail_first_fsync)
    with pytest.raises(BlobWriteError):
        _ = PrivateBlobStore(root)

    assert directory_created
    assert not fail_once
    store = PrivateBlobStore(root)
    payload = b"root retry"
    key, digest = object_key(payload)
    assert store.put(key, payload, digest)


def test_symlinked_object_parent_never_escapes_private_root(tmp_path: Path) -> None:
    root = tmp_path / "blobs"
    store = PrivateBlobStore(root)
    outside = tmp_path / "outside"
    outside.mkdir()
    (root / "org").symlink_to(outside, target_is_directory=True)
    payload = b"must stay confined"
    key, digest = object_key(payload)

    with pytest.raises(BlobIntegrityError):
        _ = store.put(key, payload, digest)

    assert not tuple(path for path in outside.rglob("*") if path.is_file())
