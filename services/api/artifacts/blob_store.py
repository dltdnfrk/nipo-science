"""Private immutable filesystem content-addressed blob adapter."""

import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Final, final

from .blob_filesystem import (
    discard_regular_file,
    open_blob_directory,
    prepare_private_root,
    publish_blob,
    read_bounded_file,
)
from .store_contract import BlobIntegrityError, BlobWriteError

OBJECT_KEY_PATTERN: Final = re.compile(
    r"^org/[0-9a-f-]{36}/project/[0-9a-f-]{36}/sha256/[0-9a-f]{64}$"
)


@final
class PrivateBlobStore:
    """Persist content-addressed bytes below one owner-private root."""

    def __init__(self, root: Path) -> None:
        """Create or validate a non-symlink private storage root."""
        self._root = prepare_private_root(root)

    def put(self, object_key: str, payload: bytes, expected_sha256: str) -> bool:
        """Create one immutable object or verify an identical existing object."""
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise BlobIntegrityError
        relative = self._relative(object_key)
        try:
            directory = open_blob_directory(
                self._root,
                relative.parts[:-1],
                create=True,
            )
        except BlobIntegrityError:
            raise
        except OSError as error:
            raise BlobWriteError from error
        name = relative.name
        try:
            return publish_blob(directory, name, payload)
        finally:
            os.close(directory)

    def read(self, object_key: str) -> bytes:
        """Read one regular non-symlink object and verify its key digest."""
        relative = self._relative(object_key)
        try:
            directory = open_blob_directory(
                self._root,
                relative.parts[:-1],
                create=False,
            )
        except FileNotFoundError as error:
            raise BlobIntegrityError from error
        try:
            payload = read_bounded_file(directory, relative.name)
        finally:
            os.close(directory)
        expected = relative.name
        if hashlib.sha256(payload).hexdigest() != expected:
            raise BlobIntegrityError
        return payload

    def discard(self, object_key: str) -> None:
        """Remove one exact object during metadata rollback compensation."""
        relative = self._relative(object_key)
        discard_regular_file(self._root, relative.parts[:-1], relative.name)

    @staticmethod
    def _relative(object_key: str) -> PurePosixPath:
        if OBJECT_KEY_PATTERN.fullmatch(object_key) is None:
            raise BlobIntegrityError
        return PurePosixPath(object_key)
