"""Immutable executable admission and staging for Codex live capture."""

from __future__ import annotations

import os
import re
import stat
import tempfile
from contextlib import contextmanager
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from pathlib import Path
from typing import TYPE_CHECKING, Final

from services.api.provider_live_capture_errors import (
    ERROR_BINARY_CHANGED,
    ERROR_BINARY_INVALID,
    ERROR_BINARY_STAGING,
    capture_error,
)
from services.api.provider_live_capture_storage import require_private_scratch_root

if TYPE_CHECKING:
    from collections.abc import Generator

_READ_CHUNK_BYTES: Final = 1024 * 1024
_PRIVATE_DIRECTORY_MODE: Final = 0o700
_PRIVATE_EXECUTABLE_MODE: Final = 0o500
_PRIVATE_COPY_MODE: Final = 0o600
_BINARY_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")
OPERATOR_ACCOUNT_REF_GRAMMAR: Final = r"acct_[A-Za-z0-9_-]{1,128}"
_ACCOUNT_REF: Final = re.compile(rf"^{OPERATOR_ACCOUNT_REF_GRAMMAR}$")


@dataclass(frozen=True, slots=True)
class CodexBinaryPolicy:
    """Executable identity policy plus an operator-supplied account label.

    ``operator_account_ref`` is policy metadata. It is neither inferred from
    Codex output nor evidence that Codex authenticated a provider account.
    """

    executable: Path
    expected_sha256: str
    operator_account_ref: str
    owner_uid: int
    expected_runtime_version: str

    def validate(self) -> Path:
        """Revalidate canonical path, owner, mode, and bytes before staging."""
        path = self.executable
        if (
            not path.is_absolute()
            or not _BINARY_SHA256.fullmatch(self.expected_sha256)
            or not operator_account_ref_is_valid(self.operator_account_ref)
            or self.owner_uid < 0
            or not self.expected_runtime_version.startswith("codex-cli-")
        ):
            raise capture_error(ERROR_BINARY_INVALID)
        try:
            file_stat = path.lstat()
            resolved = path.resolve(strict=True)
        except OSError as error:
            raise capture_error(ERROR_BINARY_INVALID) from error
        if (
            resolved != path
            or stat.S_ISLNK(file_stat.st_mode)
            or not stat.S_ISREG(file_stat.st_mode)
            or file_stat.st_uid != self.owner_uid
            or not file_stat.st_mode & stat.S_IXUSR
            or file_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH)
        ):
            raise capture_error(ERROR_BINARY_INVALID)
        observed_sha256 = executable_sha256(path, file_stat)
        if not compare_digest(observed_sha256, self.expected_sha256):
            raise capture_error(ERROR_BINARY_CHANGED)
        return path


def executable_sha256(path: Path, expected_stat: os.stat_result) -> str:
    """Hash one already-identified regular file and detect replacement while read."""
    digest = sha256()
    try:
        with path.open("rb") as handle:
            opened_stat = os.fstat(handle.fileno())
            if (
                opened_stat.st_dev != expected_stat.st_dev
                or opened_stat.st_ino != expected_stat.st_ino
                or not stat.S_ISREG(opened_stat.st_mode)
            ):
                raise capture_error(ERROR_BINARY_CHANGED)
            for chunk in iter(lambda: handle.read(_READ_CHUNK_BYTES), b""):
                digest.update(chunk)
        final_stat = path.lstat()
    except OSError as error:
        raise capture_error(ERROR_BINARY_CHANGED) from error
    if (
        final_stat.st_dev != expected_stat.st_dev
        or final_stat.st_ino != expected_stat.st_ino
        or final_stat.st_size != expected_stat.st_size
        or final_stat.st_mtime_ns != expected_stat.st_mtime_ns
    ):
        raise capture_error(ERROR_BINARY_CHANGED)
    return digest.hexdigest()


def operator_account_ref_is_valid(value: str) -> bool:
    """Return whether policy metadata matches the one canonical account grammar."""
    return _ACCOUNT_REF.fullmatch(value) is not None


@contextmanager
def staged_executable(
    policy: CodexBinaryPolicy,
    scratch_root: Path,
) -> Generator[Path]:
    """Yield a private immutable copy of the admitted executable bytes."""
    source = policy.validate()
    scratch_root = prepare_private_cache_root(scratch_root)
    try:
        with tempfile.TemporaryDirectory(
            prefix="codex-executable-", dir=scratch_root
        ) as directory:
            base = Path(directory)
            base.chmod(_PRIVATE_DIRECTORY_MODE)
            yield _copy_validated_executable(source, policy, base)
    except OSError as error:
        raise capture_error(ERROR_BINARY_STAGING) from error


def prepare_private_cache_root(scratch_root: Path) -> Path:
    """Revalidate and return the deployment-supplied transient-work root."""
    try:
        return require_private_scratch_root(scratch_root)
    except OSError as error:
        raise capture_error(ERROR_BINARY_STAGING) from error


def _copy_validated_executable(
    source: Path,
    policy: CodexBinaryPolicy,
    directory: Path,
) -> Path:
    source_stat = source.lstat()
    source_fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    pending = directory / "codex.pending"
    staged = directory / "codex"
    digest = sha256()
    try:
        opened_stat = os.fstat(source_fd)
        if not _same_executable(source_stat, opened_stat, policy.owner_uid):
            raise capture_error(ERROR_BINARY_CHANGED)
        destination_fd = os.open(
            pending,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL,
            _PRIVATE_COPY_MODE,
        )
        try:
            while chunk := os.read(source_fd, _READ_CHUNK_BYTES):
                digest.update(chunk)
                _write_all(destination_fd, chunk)
            os.fsync(destination_fd)
            os.fchmod(destination_fd, _PRIVATE_EXECUTABLE_MODE)
            os.fsync(destination_fd)
        finally:
            os.close(destination_fd)
    finally:
        os.close(source_fd)
    final_source_stat = source.lstat()
    if not _same_executable(
        source_stat, final_source_stat, policy.owner_uid
    ) or not compare_digest(digest.hexdigest(), policy.expected_sha256):
        raise capture_error(ERROR_BINARY_CHANGED)
    _ = pending.replace(staged)
    _sync_directory(directory)
    staged_stat = staged.lstat()
    if (
        not stat.S_ISREG(staged_stat.st_mode)
        or staged_stat.st_uid != os.getuid()
        or staged_stat.st_nlink != 1
        or stat.S_IMODE(staged_stat.st_mode) != _PRIVATE_EXECUTABLE_MODE
        or not compare_digest(
            executable_sha256(staged, staged_stat),
            policy.expected_sha256,
        )
    ):
        raise capture_error(ERROR_BINARY_STAGING)
    return staged


def _same_executable(
    expected: os.stat_result,
    observed: os.stat_result,
    owner_uid: int,
) -> bool:
    return (
        stat.S_ISREG(observed.st_mode)
        and observed.st_uid == owner_uid
        and observed.st_dev == expected.st_dev
        and observed.st_ino == expected.st_ino
        and observed.st_size == expected.st_size
        and observed.st_mtime_ns == expected.st_mtime_ns
    )


def _write_all(file_descriptor: int, value: bytes) -> None:
    offset = 0
    while offset < len(value):
        offset += os.write(file_descriptor, value[offset:])


def _sync_directory(directory: Path) -> None:
    directory_fd = os.open(
        directory,
        os.O_RDONLY | getattr(os, "O_DIRECTORY", 0),
    )
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
