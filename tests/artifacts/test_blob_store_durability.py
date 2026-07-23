import hashlib
import os
import stat
from pathlib import Path
from typing import Final

import pytest
from services.api.artifacts import PrivateBlobStore
from services.api.artifacts.store_contract import BlobWriteError

ORG_ID: Final = "018f47a0-7b9c-7a01-8def-0123456789ab"
PROJECT_ID: Final = "018f47a0-7b9c-7a02-8def-0123456789ab"


def object_key(payload: bytes) -> tuple[str, str]:
    digest = hashlib.sha256(payload).hexdigest()
    return f"org/{ORG_ID}/project/{PROJECT_ID}/sha256/{digest}", digest


def test_new_blob_syncs_data_and_every_directory_entry_before_return(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = PrivateBlobStore(tmp_path / "blobs")
    payload = b"crash durable bytes"
    key, digest = object_key(payload)
    events: list[str] = []
    original_mkdir = os.mkdir
    original_fsync = os.fsync
    original_link = os.link
    original_unlink = os.unlink

    def trace_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        original_mkdir(path, mode, dir_fd=dir_fd)
        events.append("mkdir")

    def trace_fsync(descriptor: int) -> None:
        kind = "dir_fsync" if stat.S_ISDIR(os.fstat(descriptor).st_mode) else "data_fsync"
        events.append(kind)
        original_fsync(descriptor)

    def trace_link(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        events.append("link")
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    def trace_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        events.append("unlink")
        original_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "mkdir", trace_mkdir)
    monkeypatch.setattr(os, "fsync", trace_fsync)
    monkeypatch.setattr(os, "link", trace_link)
    monkeypatch.setattr(os, "unlink", trace_unlink)

    assert store.put(key, payload, digest)

    link_index = events.index("link")
    unlink_index = events.index("unlink", link_index)
    assert events[:link_index].count("mkdir") == 5
    assert events[:link_index].count("dir_fsync") >= 5
    assert events.index("data_fsync") < link_index
    assert "dir_fsync" in events[unlink_index + 1 :]
    final = tmp_path / "blobs" / Path(key)
    assert stat.S_IMODE(final.stat().st_mode) == 0o600
    directory = final.parent
    while directory != tmp_path / "blobs":
        assert stat.S_IMODE(directory.stat().st_mode) == 0o700
        directory = directory.parent


def test_discard_syncs_removed_directory_entry(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = PrivateBlobStore(tmp_path / "blobs")
    payload = b"rolled back bytes"
    key, digest = object_key(payload)
    assert store.put(key, payload, digest)
    events: list[str] = []
    original_fsync = os.fsync
    original_unlink = os.unlink

    def trace_fsync(descriptor: int) -> None:
        if stat.S_ISDIR(os.fstat(descriptor).st_mode):
            events.append("dir_fsync")
        original_fsync(descriptor)

    def trace_unlink(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        dir_fd: int | None = None,
    ) -> None:
        events.append("unlink")
        original_unlink(path, dir_fd=dir_fd)

    monkeypatch.setattr(os, "fsync", trace_fsync)
    monkeypatch.setattr(os, "unlink", trace_unlink)

    store.discard(key)

    assert events == ["unlink", "dir_fsync"]
    assert not tuple(path for path in tmp_path.rglob("*") if path.is_file())


def test_link_failure_cleans_pending_and_exact_retry_stores_one_blob(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = PrivateBlobStore(tmp_path / "blobs")
    payload = b"retry exactly once"
    key, digest = object_key(payload)
    original_link = os.link
    fail_once = True

    def fail_first_link(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal fail_once
        if fail_once:
            fail_once = False
            message = "injected link failure"
            raise OSError(message)
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )

    monkeypatch.setattr(os, "link", fail_first_link)

    with pytest.raises(BlobWriteError):
        _ = store.put(key, payload, digest)
    assert not tuple(path for path in tmp_path.rglob("*") if path.is_file())

    assert store.put(key, payload, digest)
    assert not store.put(key, payload, digest)
    files = tuple(path for path in tmp_path.rglob("*") if path.is_file())
    assert len(files) == 1
    assert files[0].read_bytes() == payload
    assert not tuple(tmp_path.rglob("*.pending"))


def test_final_directory_fsync_failure_rolls_back_new_hardlink(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    store = PrivateBlobStore(tmp_path / "blobs")
    payload = b"rollback final link"
    key, digest = object_key(payload)
    original_fsync = os.fsync
    original_link = os.link
    link_completed = False
    fail_once = True

    def trace_link(
        source: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        destination: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        *,
        src_dir_fd: int | None = None,
        dst_dir_fd: int | None = None,
        follow_symlinks: bool = True,
    ) -> None:
        nonlocal link_completed
        original_link(
            source,
            destination,
            src_dir_fd=src_dir_fd,
            dst_dir_fd=dst_dir_fd,
            follow_symlinks=follow_symlinks,
        )
        link_completed = True

    def fail_final_directory_fsync(descriptor: int) -> None:
        nonlocal fail_once
        if (
            link_completed
            and fail_once
            and stat.S_ISDIR(os.fstat(descriptor).st_mode)
        ):
            fail_once = False
            message = "injected final directory fsync failure"
            raise OSError(message)
        original_fsync(descriptor)

    monkeypatch.setattr(os, "link", trace_link)
    monkeypatch.setattr(os, "fsync", fail_final_directory_fsync)

    with pytest.raises(BlobWriteError):
        _ = store.put(key, payload, digest)

    assert not fail_once
    assert not tuple(path for path in tmp_path.rglob("*") if path.is_file())
    assert store.put(key, payload, digest)
    assert not store.put(key, payload, digest)
    assert len(tuple(path for path in tmp_path.rglob("*") if path.is_file())) == 1

