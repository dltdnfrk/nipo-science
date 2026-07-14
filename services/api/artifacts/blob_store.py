"""Private immutable filesystem content-addressed blob adapter."""

import hashlib
import os
import re
from pathlib import Path, PurePosixPath
from typing import Final, final
from uuid import uuid4

from .store_contract import BlobIntegrityError, BlobWriteError

OBJECT_KEY_PATTERN: Final = re.compile(
    r"^org/[0-9a-f-]{36}/project/[0-9a-f-]{36}/sha256/[0-9a-f]{64}$"
)


@final
class PrivateBlobStore:
    """Persist content-addressed bytes below one owner-private root."""

    def __init__(self, root: Path) -> None:
        """Create or validate a non-symlink private storage root."""
        if root.is_symlink():
            raise BlobIntegrityError
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        root.chmod(0o700)
        self._root = root.resolve(strict=True)

    def put(self, object_key: str, payload: bytes, expected_sha256: str) -> bool:
        """Create one immutable object or verify an identical existing object."""
        if hashlib.sha256(payload).hexdigest() != expected_sha256:
            raise BlobIntegrityError
        path = self._path(object_key)
        pending = path.with_name(f".{path.name}.{uuid4().hex}.pending")
        try:
            path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            self._reject_symlink_chain(path.parent)
            descriptor = os.open(
                pending,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL,
                0o600,
            )
            with os.fdopen(descriptor, "wb") as stream:
                _ = stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            try:
                os.link(pending, path)
            except FileExistsError:
                if self.read(object_key) != payload:
                    raise BlobIntegrityError from None
                return False
            else:
                return True
        except OSError as error:
            raise BlobWriteError from error
        finally:
            try:
                pending.unlink(missing_ok=True)
            except OSError as error:
                raise BlobWriteError from error

    def read(self, object_key: str) -> bytes:
        """Read one regular non-symlink object and verify its key digest."""
        path = self._path(object_key)
        if path.is_symlink() or not path.is_file():
            raise BlobIntegrityError
        payload = path.read_bytes()
        expected = PurePosixPath(object_key).name
        if hashlib.sha256(payload).hexdigest() != expected:
            raise BlobIntegrityError
        return payload

    def discard(self, object_key: str) -> None:
        """Remove one exact object during metadata rollback compensation."""
        path = self._path(object_key)
        if path.is_symlink():
            raise BlobIntegrityError
        try:
            path.unlink(missing_ok=True)
        except OSError as error:
            raise BlobWriteError from error

    def _path(self, object_key: str) -> Path:
        if OBJECT_KEY_PATTERN.fullmatch(object_key) is None:
            raise BlobIntegrityError
        relative = PurePosixPath(object_key)
        path = self._root.joinpath(*relative.parts)
        if not path.is_relative_to(self._root):
            raise BlobIntegrityError
        return path

    def _reject_symlink_chain(self, directory: Path) -> None:
        current = directory
        while current != self._root:
            if current.is_symlink():
                raise BlobIntegrityError
            current = current.parent
