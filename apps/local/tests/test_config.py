"""Local layout tests: the data root must never be readable by another account."""

import os
import stat
from pathlib import Path

from nipo_local.config import resolve_paths


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


def test_ensure_creates_an_owner_only_root_and_blob_directory(tmp_path: Path) -> None:
    paths = resolve_paths(tmp_path / "root")
    paths.ensure()
    assert _mode(paths.root) == 0o700
    assert _mode(paths.blobs) == 0o700


def test_a_permissive_umask_cannot_widen_the_layout(tmp_path: Path) -> None:
    previous = os.umask(0o000)
    try:
        paths = resolve_paths(tmp_path / "root")
        paths.ensure()
    finally:
        _ = os.umask(previous)
    assert _mode(paths.root) == 0o700
    assert _mode(paths.blobs) == 0o700


def test_ensure_repairs_a_root_created_before_the_rule(tmp_path: Path) -> None:
    root = tmp_path / "root"
    root.mkdir()
    root.chmod(0o755)
    blobs = root / "blobs"
    blobs.mkdir()
    blobs.chmod(0o755)

    paths = resolve_paths(root)
    paths.ensure()

    assert _mode(paths.root) == 0o700
    assert _mode(paths.blobs) == 0o700


def test_ensure_is_idempotent_and_preserves_existing_content(tmp_path: Path) -> None:
    paths = resolve_paths(tmp_path / "root")
    paths.ensure()
    kept = paths.blobs / "keep.bin"
    _ = kept.write_bytes(b"payload")

    paths.ensure()

    assert kept.read_bytes() == b"payload"
    assert _mode(paths.root) == 0o700
