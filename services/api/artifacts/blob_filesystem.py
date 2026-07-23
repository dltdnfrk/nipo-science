"""Descriptor-confined durable filesystem operations for private blobs."""

import errno
import os
import stat
from contextlib import suppress
from pathlib import Path
from typing import Final
from uuid import uuid4

from .models import MAX_ARTIFACT_OUTPUT_BYTES
from .store_contract import BlobIntegrityError, BlobWriteError

DIRECTORY_MODE: Final = 0o700
FILE_MODE: Final = 0o600
DIRECTORY_FLAGS: Final = (
    os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW
)
PENDING_FLAGS: Final = (
    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW
)
_READ_FLAGS: Final = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK
_UNSAFE_PATH_ERRORS: Final = frozenset({errno.ELOOP, errno.ENOTDIR})


def prepare_private_root(root: Path) -> Path:
    """Create and sync one owner-private absolute root without following links."""
    if root.is_symlink():
        raise BlobIntegrityError
    try:
        absolute = root.resolve(strict=False)
    except OSError as error:
        raise BlobWriteError from error
    if absolute == Path(absolute.anchor):
        raise BlobIntegrityError
    try:
        directory = _walk_absolute(absolute, create=True, sync_entries=True)
        try:
            if stat.S_IMODE(os.fstat(directory).st_mode) != DIRECTORY_MODE:
                os.fchmod(directory, DIRECTORY_MODE)
                os.fsync(directory)
        finally:
            os.close(directory)
    except BlobIntegrityError:
        raise
    except OSError as error:
        raise BlobWriteError from error
    return absolute


def publish_blob(directory: int, name: str, payload: bytes) -> bool:
    """Publish bytes by an exclusive hard link and sync or roll back the entry."""
    pending = f".{name}.{uuid4().hex}.pending"
    pending_present = False
    final_created = False
    try:
        descriptor = os.open(
            pending,
            PENDING_FLAGS,
            FILE_MODE,
            dir_fd=directory,
        )
        pending_present = True
        with os.fdopen(descriptor, "wb") as stream:
            os.fchmod(stream.fileno(), FILE_MODE)
            _ = stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(
                pending,
                name,
                src_dir_fd=directory,
                dst_dir_fd=directory,
                follow_symlinks=False,
            )
        except FileExistsError:
            if read_exact_file(directory, name, len(payload)) != payload:
                raise BlobIntegrityError from None
            created = False
        else:
            created = True
            final_created = True
        os.unlink(pending, dir_fd=directory)
        pending_present = False
        os.fsync(directory)
    except OSError as error:
        if final_created:
            try:
                os.unlink(name, dir_fd=directory)
                os.fsync(directory)
            except OSError as rollback_error:
                raise BlobWriteError from rollback_error
        raise BlobWriteError from error
    else:
        return created
    finally:
        try:
            if pending_present:
                os.unlink(pending, dir_fd=directory)
                os.fsync(directory)
        except OSError as error:
            raise BlobWriteError from error


def open_blob_directory(root: Path, parts: tuple[str, ...], *, create: bool) -> int:
    """Open an object directory by descriptors and durably create missing entries."""
    directory = _walk_absolute(root, create=False, sync_entries=False)
    try:
        for part in parts:
            created = False
            try:
                next_directory = os.open(part, DIRECTORY_FLAGS, dir_fd=directory)
            except FileNotFoundError:
                if not create:
                    raise
                try:
                    os.mkdir(part, DIRECTORY_MODE, dir_fd=directory)
                except FileExistsError:
                    pass
                else:
                    created = True
                next_directory = os.open(part, DIRECTORY_FLAGS, dir_fd=directory)
            if stat.S_IMODE(os.fstat(next_directory).st_mode) != DIRECTORY_MODE:
                os.fchmod(next_directory, DIRECTORY_MODE)
                os.fsync(next_directory)
            if created:
                os.fsync(next_directory)
                os.fsync(directory)
            os.close(directory)
            directory = next_directory
    except BaseException as error:
        os.close(directory)
        _raise_unsafe_path(error)
        raise
    return directory


def read_exact_file(directory: int, name: str, expected_size: int) -> bytes:
    """Read one exact-size regular file without following a final link."""
    payload = _read_regular_file(directory, name, expected_size)
    if len(payload) != expected_size:
        raise BlobIntegrityError
    return payload


def read_bounded_file(directory: int, name: str) -> bytes:
    """Read one regular Artifact blob within the shared durable payload limit."""
    try:
        return _read_regular_file(directory, name, MAX_ARTIFACT_OUTPUT_BYTES)
    except FileNotFoundError as error:
        raise BlobIntegrityError from error


def _read_regular_file(directory: int, name: str, maximum_size: int) -> bytes:
    try:
        descriptor = os.open(name, _READ_FLAGS, dir_fd=directory)
    except OSError as error:
        if error.errno == errno.ELOOP:
            raise BlobIntegrityError from error
        raise
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size > maximum_size:
            raise BlobIntegrityError
        with os.fdopen(descriptor, "rb", closefd=False) as stream:
            payload = stream.read(maximum_size + 1)
        if len(payload) > maximum_size:
            raise BlobIntegrityError
        return payload
    finally:
        os.close(descriptor)


def discard_regular_file(root: Path, parts: tuple[str, ...], name: str) -> None:
    """Unlink and sync one exact regular object, rejecting substituted entries."""
    try:
        directory = open_blob_directory(root, parts, create=False)
    except FileNotFoundError:
        return
    except BlobIntegrityError:
        raise
    except OSError as error:
        raise BlobWriteError from error
    try:
        try:
            descriptor = os.open(name, _READ_FLAGS, dir_fd=directory)
        except FileNotFoundError:
            return
        except OSError as error:
            if error.errno == errno.ELOOP:
                raise BlobIntegrityError from error
            raise
        try:
            metadata = os.fstat(descriptor)
            current = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or (metadata.st_dev, metadata.st_ino)
                != (current.st_dev, current.st_ino)
            ):
                raise BlobIntegrityError
        finally:
            os.close(descriptor)
        try:
            os.unlink(name, dir_fd=directory)
        except FileNotFoundError:
            return
        os.fsync(directory)
    except OSError as error:
        raise BlobWriteError from error
    finally:
        os.close(directory)


def _walk_absolute(path: Path, *, create: bool, sync_entries: bool) -> int:
    directory = os.open(os.sep, DIRECTORY_FLAGS)
    try:
        for part in path.parts[1:]:
            try:
                next_directory = os.open(part, DIRECTORY_FLAGS, dir_fd=directory)
            except FileNotFoundError:
                if not create:
                    raise
                with suppress(FileExistsError):
                    os.mkdir(part, DIRECTORY_MODE, dir_fd=directory)
                next_directory = os.open(part, DIRECTORY_FLAGS, dir_fd=directory)
                os.fchmod(next_directory, DIRECTORY_MODE)
            if sync_entries:
                os.fsync(next_directory)
                os.fsync(directory)
            os.close(directory)
            directory = next_directory
    except BaseException as error:
        os.close(directory)
        _raise_unsafe_path(error)
        raise
    return directory


def _raise_unsafe_path(error: BaseException) -> None:
    if isinstance(error, OSError) and error.errno in _UNSAFE_PATH_ERRORS:
        raise BlobIntegrityError from error
