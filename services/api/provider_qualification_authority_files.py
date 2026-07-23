"""Race-resistant filesystem checks for qualification authority inputs."""

from __future__ import annotations

import os
import stat
from contextlib import ExitStack
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final

_WRITE_BY_OTHERS: Final = stat.S_IWGRP | stat.S_IWOTH
_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)
_FILE_FLAGS: Final = (
    os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from pathlib import Path


class UnsafeAuthorityPathError(RuntimeError):
    """Raised when authority material is reachable through an unsafe path."""


@dataclass(frozen=True, slots=True)
class AuthoritySocketIdentity:
    """Stable filesystem identity for one Unix-domain authority socket."""

    device: int
    inode: int


def read_secure_authority_file(path: Path, *, maximum_bytes: int) -> bytes:
    """Read one pinned regular file through no-follow directory descriptors."""
    with ExitStack() as stack:
        parent_fd, name = _open_secure_parent(path, stack)
        descriptor = os.open(name, _FILE_FLAGS, dir_fd=parent_fd)
        _ = stack.callback(os.close, descriptor)
        opened = os.fstat(descriptor)
        _require_secure_entry(opened, stat.S_ISREG)
        source = bytearray()
        while len(source) <= maximum_bytes:
            block = os.read(descriptor, min(4096, maximum_bytes + 1 - len(source)))
            if not block:
                break
            source.extend(block)
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        if (
            len(source) > maximum_bytes
            or linked.st_dev != opened.st_dev
            or linked.st_ino != opened.st_ino
        ):
            raise UnsafeAuthorityPathError
        return bytes(source)


def inspect_secure_authority_socket(path: Path) -> AuthoritySocketIdentity:
    """Return a socket identity only through a protected parent chain."""
    with ExitStack() as stack:
        parent_fd, name = _open_secure_parent(path, stack)
        linked = os.stat(name, dir_fd=parent_fd, follow_symlinks=False)
        _require_secure_entry(linked, stat.S_ISSOCK)
        return AuthoritySocketIdentity(linked.st_dev, linked.st_ino)


def require_connected_unix_socket(descriptor: int) -> None:
    """Reject a transport descriptor that is not a connected socket object."""
    if not stat.S_ISSOCK(os.fstat(descriptor).st_mode):
        raise UnsafeAuthorityPathError


def _open_secure_parent(path: Path, stack: ExitStack) -> tuple[int, str]:
    if (
        not path.is_absolute()
        or not path.name
        or any(component in {".", ".."} for component in path.parts[1:])
    ):
        raise UnsafeAuthorityPathError
    root_fd = os.open(os.path.sep, _DIRECTORY_FLAGS)
    _ = stack.callback(os.close, root_fd)
    _require_secure_directory(os.fstat(root_fd))
    parent_fd = root_fd
    for component in path.parts[1:-1]:
        descriptor = os.open(component, _DIRECTORY_FLAGS, dir_fd=parent_fd)
        _ = stack.callback(os.close, descriptor)
        _require_secure_directory(os.fstat(descriptor))
        parent_fd = descriptor
    return parent_fd, path.name


def _require_secure_directory(metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {
        0,
        os.geteuid(),
    }:
        raise UnsafeAuthorityPathError
    writable = bool(metadata.st_mode & _WRITE_BY_OTHERS)
    protected_shared_root = metadata.st_uid == 0 and bool(
        metadata.st_mode & stat.S_ISVTX
    )
    if writable and not protected_shared_root:
        raise UnsafeAuthorityPathError


def _require_secure_entry(
    metadata: os.stat_result,
    expected_kind: Callable[[int], bool],
) -> None:
    if (
        not expected_kind(metadata.st_mode)
        or metadata.st_uid not in {0, os.geteuid()}
        or metadata.st_mode & _WRITE_BY_OTHERS
    ):
        raise UnsafeAuthorityPathError
