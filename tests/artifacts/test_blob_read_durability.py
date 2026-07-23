import hashlib
import os
from pathlib import Path
from typing import Final

import pytest
from services.api.artifacts import MAX_ARTIFACT_OUTPUT_BYTES, PrivateBlobStore
from services.api.artifacts.store_contract import BlobIntegrityError

ORG_ID: Final = "018f47a0-7b9c-7a01-8def-0123456789ab"
PROJECT_ID: Final = "018f47a0-7b9c-7a02-8def-0123456789ab"


def object_key(payload: bytes) -> tuple[str, str]:
    digest = hashlib.sha256(payload).hexdigest()
    return f"org/{ORG_ID}/project/{PROJECT_ID}/sha256/{digest}", digest


def test_read_keeps_the_exact_opened_file_during_concurrent_replacement(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "blobs"
    store = PrivateBlobStore(root)
    payload = b"descriptor-stable payload"
    key, digest = object_key(payload)
    assert store.put(key, payload, digest)
    final = root / Path(key)
    replacement = final.with_name("replacement")
    replacement_payload = b"ordinary replacement bytes"
    _ = replacement.write_bytes(replacement_payload)
    original_open = os.open
    replaced = False

    def replace_after_open(
        path: str | bytes | os.PathLike[str] | os.PathLike[bytes],
        flags: int,
        mode: int = 0o777,
        *,
        dir_fd: int | None = None,
    ) -> int:
        nonlocal replaced
        descriptor = original_open(path, flags, mode, dir_fd=dir_fd)
        if path == final.name and dir_fd is not None and not replaced:
            os.rename(
                replacement.name,
                final.name,
                src_dir_fd=dir_fd,
                dst_dir_fd=dir_fd,
            )
            replaced = True
        return descriptor

    monkeypatch.setattr(os, "open", replace_after_open)

    assert store.read(key) == payload
    assert replaced
    assert final.read_bytes() == replacement_payload


def test_oversized_blob_is_rejected_from_fstat_without_reading_bytes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    root = tmp_path / "blobs"
    store = PrivateBlobStore(root)
    payload = b"bounded payload"
    key, digest = object_key(payload)
    assert store.put(key, payload, digest)
    final = root / Path(key)
    with final.open("r+b") as output:
        _ = output.truncate(MAX_ARTIFACT_OUTPUT_BYTES + 1)
    path_read_attempted = False

    def reject_path_read(path: Path) -> bytes:
        nonlocal path_read_attempted
        del path
        path_read_attempted = True
        message = "oversized path read must not occur"
        raise AssertionError(message)

    monkeypatch.setattr(Path, "read_bytes", reject_path_read)

    with pytest.raises(BlobIntegrityError):
        _ = store.read(key)
    assert not path_read_attempted


def test_in_bound_corrupt_blob_still_fails_checksum_validation(tmp_path: Path) -> None:
    root = tmp_path / "blobs"
    store = PrivateBlobStore(root)
    payload = b"checksum-owned payload"
    key, digest = object_key(payload)
    assert store.put(key, payload, digest)
    final = root / Path(key)
    with final.open("r+b") as output:
        _ = output.write(b"same-size-corruption!!")

    with pytest.raises(BlobIntegrityError):
        _ = store.read(key)
