import os
from pathlib import Path
from typing import Final

import pytest
from services.api.artifacts import ArtifactRecoveryError, FileArtifactRecovery

from .support import RECOVERY_INTEGRITY_KEY

_LOCK_NAME: Final = ".authority.lock"


def _descriptor_name(
    descriptor: int,
    targets: tuple[tuple[str, Path], ...],
) -> str:
    metadata = os.fstat(descriptor)
    for name, path in targets:
        try:
            target = path.stat()
        except FileNotFoundError:
            continue
        if (metadata.st_dev, metadata.st_ino) == (target.st_dev, target.st_ino):
            return name
    return "other"


def test_recovery_first_use_syncs_root_records_and_lock_entries(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "artifact-recovery"
    records = root / "records"
    lock = root / _LOCK_NAME
    targets = (
        ("parent", root.parent),
        ("root", root),
        ("records", records),
        ("lock", lock),
    )
    events: list[str] = []
    original_mkdir = os.mkdir
    original_open = os.open
    original_fsync = os.fsync

    def trace_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        original_mkdir(path, mode, dir_fd=dir_fd)
        events.append("mkdir")

    def trace_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT and Path(os.fsdecode(path)).name == _LOCK_NAME:
            events.append("create:lock")
        return descriptor

    def trace_fsync(descriptor: int) -> None:
        events.append(f"fsync:{_descriptor_name(descriptor, targets)}")
        original_fsync(descriptor)

    monkeypatch.setattr(os, "mkdir", trace_mkdir)
    monkeypatch.setattr(os, "open", trace_open)
    monkeypatch.setattr(os, "fsync", trace_fsync)

    _ = FileArtifactRecovery(root, integrity_key=RECOVERY_INTEGRITY_KEY)

    root_create, records_create = (
        index for index, event in enumerate(events) if event == "mkdir"
    )
    lock_create = events.index("create:lock")
    assert {"fsync:root", "fsync:parent"} <= set(
        events[root_create + 1 : records_create]
    )
    assert {"fsync:records", "fsync:root"} <= set(
        events[records_create + 1 : lock_create]
    )
    assert events[lock_create + 1 :] == ["fsync:lock", "fsync:root"]


@pytest.mark.parametrize("entry", ["root", "records", "lock"])
def test_recovery_first_use_parent_fsync_failure_is_retryable(
    entry: str,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "artifact-recovery"
    records = root / "records"
    lock = root / _LOCK_NAME
    targets = (
        ("parent", root.parent),
        ("root", root),
        ("records", records),
        ("lock", lock),
    )
    expected_parent = {"root": "parent", "records": "root", "lock": "root"}
    original_mkdir = os.mkdir
    original_open = os.open
    original_fsync = os.fsync
    active_entry = ""
    fail_once = True

    def track_mkdir(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> None:
        nonlocal active_entry
        original_mkdir(path, mode, dir_fd=dir_fd)
        metadata = os.stat(path, dir_fd=dir_fd, follow_symlinks=False)
        for name, target in targets:
            current = target.stat()
            if (metadata.st_dev, metadata.st_ino) == (
                current.st_dev,
                current.st_ino,
            ):
                active_entry = name
                return

    def track_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal active_entry
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if flags & os.O_CREAT and Path(os.fsdecode(path)).name == _LOCK_NAME:
            active_entry = "lock"
        return descriptor

    def fail_parent_fsync(descriptor: int) -> None:
        nonlocal fail_once
        if (
            fail_once
            and active_entry == entry
            and _descriptor_name(descriptor, targets) == expected_parent[entry]
        ):
            fail_once = False
            message = f"injected {entry} parent fsync failure"
            raise OSError(message)
        original_fsync(descriptor)

    monkeypatch.setattr(os, "mkdir", track_mkdir)
    monkeypatch.setattr(os, "open", track_open)
    monkeypatch.setattr(os, "fsync", fail_parent_fsync)

    with pytest.raises(ArtifactRecoveryError):
        _ = FileArtifactRecovery(root, integrity_key=RECOVERY_INTEGRITY_KEY)

    assert not fail_once
    _ = FileArtifactRecovery(root, integrity_key=RECOVERY_INTEGRITY_KEY)
    assert records.is_dir()
    assert lock.is_file()
