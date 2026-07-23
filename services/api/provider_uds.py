"""Bounded Unix-domain transport for isolated provider capability processes."""

from __future__ import annotations

import json
import os
import socket
import socketserver
import stat
import time
from contextlib import ExitStack
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, cast, final, override

from services.api.provider_qualification_authority_files import (
    UnsafeAuthorityPathError,
    inspect_secure_authority_socket,
    require_connected_unix_socket,
)
from services.api.provider_runtime import ProviderRuntimeError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping
    from pathlib import Path

MAX_PROVIDER_UDS_MESSAGE_BYTES: Final = 64 * 1024
PROVIDER_UDS_SERVER_READ_TIMEOUT_SECONDS: Final = 2.0
_MAX_TIMEOUT_SECONDS: Final = 120.0
_MAX_SOCKET_PATH_BYTES: Final = 100
_DIRECTORY_FLAGS: Final = (
    os.O_RDONLY
    | getattr(os, "O_CLOEXEC", 0)
    | getattr(os, "O_DIRECTORY", 0)
    | getattr(os, "O_NOFOLLOW", 0)
)


class ProviderUdsError(RuntimeError):
    """Reject unsafe endpoints, malformed messages, and failed local transport."""


@dataclass(frozen=True, slots=True)
class ProviderUdsClientConfig:
    """Non-secret endpoint settings safe for an ordinary product process."""

    socket_path: Path
    timeout_seconds: float = 30.0

    def __post_init__(self) -> None:
        """Bound timeouts and require an absolute deployment-controlled path."""
        if (
            not self.socket_path.is_absolute()
            or len(os.fsencode(self.socket_path)) > _MAX_SOCKET_PATH_BYTES
            or not 0 < self.timeout_seconds <= _MAX_TIMEOUT_SECONDS
        ):
            raise ProviderUdsError


def provider_uds_request(
    config: ProviderUdsClientConfig,
    request: Mapping[str, object],
) -> Mapping[str, object]:
    """Exchange one canonical JSON request with a protected local service."""
    payload = canonical_provider_json(request)
    if len(payload) + 1 > MAX_PROVIDER_UDS_MESSAGE_BYTES:
        raise ProviderUdsError
    try:
        expected_socket = inspect_secure_authority_socket(config.socket_path)
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
            connection.settimeout(config.timeout_seconds)
            connection.connect(os.fspath(config.socket_path))
            require_connected_unix_socket(connection.fileno())
            if inspect_secure_authority_socket(config.socket_path) != expected_socket:
                raise ProviderUdsError
            connection.sendall(payload + b"\n")
            response = _receive_line(connection)
            if inspect_secure_authority_socket(config.socket_path) != expected_socket:
                raise ProviderUdsError
    except (OSError, TimeoutError, UnsafeAuthorityPathError) as error:
        raise ProviderUdsError from error
    return strict_provider_json(response)


def canonical_provider_json(value: object) -> bytes:
    """Encode one deterministic protocol object without insignificant bytes."""
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def strict_provider_json(source: bytes) -> Mapping[str, object]:
    """Decode one bounded object while rejecting duplicate and non-string keys."""
    if len(source) > MAX_PROVIDER_UDS_MESSAGE_BYTES:
        raise ProviderUdsError

    def pairs(items: list[tuple[str, object]]) -> dict[str, object]:
        result: dict[str, object] = {}
        for key, value in items:
            if key in result:
                raise ProviderUdsError
            result[key] = value
        return result

    try:
        value = cast("object", json.loads(source, object_pairs_hook=pairs))
    except (json.JSONDecodeError, UnicodeDecodeError) as error:
        raise ProviderUdsError from error
    if not isinstance(value, dict) or not all(
        isinstance(key, str) for key in cast("dict[object, object]", value)
    ):
        raise ProviderUdsError
    return cast("dict[str, object]", value)


def validate_provider_uds_socket(path: Path) -> None:
    """Require a non-symlink socket owned by root or the current service user."""
    try:
        identity = inspect_secure_authority_socket(path)
        linked = path.lstat()
    except (OSError, UnsafeAuthorityPathError) as error:
        raise ProviderUdsError from error
    if (
        stat.S_ISLNK(linked.st_mode)
        or linked.st_dev != identity.device
        or linked.st_ino != identity.inode
        or linked.st_mode & 0o077
    ):
        raise ProviderUdsError


@final
class SecureProviderUnixServer(socketserver.UnixStreamServer):
    """Own one mode-0600 socket and a single bounded request handler."""

    allow_reuse_address = False

    def __init__(
        self,
        socket_path: Path,
        operation: Callable[[bytes], bytes],
    ) -> None:
        """Bind atomically without replacing any pre-existing filesystem entry."""
        _validate_socket_parent(socket_path)
        if socket_path.exists() or socket_path.is_symlink():
            raise ProviderUdsError
        self._socket_path = socket_path
        self._operation = operation
        previous_umask = os.umask(0o177)
        try:
            super().__init__(os.fspath(socket_path), _ProviderUdsHandler)
        except OSError as error:
            raise ProviderUdsError from error
        finally:
            _ = os.umask(previous_umask)
        try:
            socket_path.chmod(0o600)
            validate_provider_uds_socket(socket_path)
            self._socket_inode = socket_path.stat().st_ino
        except Exception:
            super().server_close()
            _ = socket_path.unlink(missing_ok=True)
            raise

    def execute(self, source: bytes) -> bytes:
        """Run the service-specific strict schema operation."""
        return self._operation(source)

    @override
    def server_close(self) -> None:
        """Close and unlink only the exact socket inode created by this server."""
        super().server_close()
        try:
            current = self._socket_path.lstat()
        except OSError:
            return
        if stat.S_ISSOCK(current.st_mode) and current.st_ino == self._socket_inode:
            _ = self._socket_path.unlink()


class _ProviderUdsHandler(socketserver.BaseRequestHandler):
    @override
    def handle(self) -> None:
        connection = cast("socket.socket", self.request)
        try:
            source = _receive_line(
                connection,
                read_timeout_seconds=PROVIDER_UDS_SERVER_READ_TIMEOUT_SECONDS,
            )
            response = _bounded_response(
                cast("SecureProviderUnixServer", self.server).execute(source)
            )
        except (OSError, RuntimeError, ValueError, ProviderRuntimeError):
            response = canonical_provider_json(
                {"schema_version": 1, "error": "request_rejected"}
            )
        try:
            connection.sendall(response + b"\n")
        except OSError:
            return


def _receive_line(
    connection: socket.socket,
    *,
    read_timeout_seconds: float | None = None,
) -> bytes:
    original_timeout = connection.gettimeout()
    deadline = (
        time.monotonic() + read_timeout_seconds
        if read_timeout_seconds is not None
        else None
    )
    chunks = bytearray()
    try:
        while len(chunks) < MAX_PROVIDER_UDS_MESSAGE_BYTES:
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise ProviderUdsError
                connection.settimeout(remaining)
            item = connection.recv(
                min(4096, MAX_PROVIDER_UDS_MESSAGE_BYTES - len(chunks))
            )
            if not item:
                break
            chunks.extend(item)
            newline = chunks.find(b"\n")
            if newline >= 0:
                if newline != len(chunks) - 1:
                    raise ProviderUdsError
                return bytes(chunks[:newline])
        raise ProviderUdsError
    finally:
        if deadline is not None:
            connection.settimeout(original_timeout)


def _bounded_response(response: bytes) -> bytes:
    if len(response) + 1 > MAX_PROVIDER_UDS_MESSAGE_BYTES:
        raise ProviderUdsError
    return response


def _validate_socket_parent(path: Path) -> None:
    if (
        not path.is_absolute()
        or not path.name
        or len(os.fsencode(path)) > _MAX_SOCKET_PATH_BYTES
        or any(component in {".", ".."} for component in path.parts[1:])
    ):
        raise ProviderUdsError
    try:
        with ExitStack() as stack:
            descriptor = os.open(os.path.sep, _DIRECTORY_FLAGS)
            _ = stack.callback(os.close, descriptor)
            _require_secure_directory(os.fstat(descriptor))
            for component in path.parts[1:-1]:
                descriptor = os.open(
                    component,
                    _DIRECTORY_FLAGS,
                    dir_fd=descriptor,
                )
                _ = stack.callback(os.close, descriptor)
                _require_secure_directory(os.fstat(descriptor))
    except OSError as error:
        raise ProviderUdsError from error


def _require_secure_directory(metadata: os.stat_result) -> None:
    if not stat.S_ISDIR(metadata.st_mode) or metadata.st_uid not in {
        0,
        os.geteuid(),
    }:
        raise ProviderUdsError
    writable = bool(metadata.st_mode & 0o022)
    if writable and not (
        metadata.st_uid == 0 and bool(metadata.st_mode & stat.S_ISVTX)
    ):
        raise ProviderUdsError
