"""Bounded argv-only Codex process invocation for live capture."""

from __future__ import annotations

import os
import signal
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol

import anyio

from services.api.provider_live_capture_errors import (
    ERROR_BINARY_INVALID,
    ERROR_BINARY_POLICY,
    ERROR_CAPTURE_ROOTS,
    ERROR_OUTPUT_ENCODING,
    ERROR_OUTPUT_LIMIT,
    capture_error,
)
from services.api.provider_live_capture_sandbox import (
    CodexBinaryPolicy,
    staged_executable,
)

if TYPE_CHECKING:
    from collections.abc import Sequence
    from pathlib import Path

    from anyio.abc import ByteReceiveStream, Process

_CLEANUP_TIMEOUT_SECONDS: Final = 2
_MAX_STDOUT_BYTES: Final = 8 * 1024 * 1024
_MAX_STDERR_BYTES: Final = 1024 * 1024
_TIMEOUT_RETURN_CODE: Final = 124
_OUTPUT_LIMIT_RETURN_CODE: Final = 125
_DECODE_FAILURE_RETURN_CODE: Final = 126


@dataclass(frozen=True, slots=True)
class InvocationResult:
    """The normalized result of one argv-only Codex invocation."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False
    output_limited: bool = False
    decode_failed: bool = False


class CodexInvocation(Protocol):
    """Injectable, argv-only boundary around the Codex executable."""

    def run(self, argv: Sequence[str], timeout_seconds: int) -> InvocationResult:
        """Run ``argv`` with the supplied timeout."""
        ...


class CodexCliInvocation:
    """Production boundary which neither reads nor copies credentials."""

    def __init__(
        self,
        policy: CodexBinaryPolicy | None = None,
        *,
        scratch_root: Path | None = None,
        _pinned_executable: Path | None = None,
    ) -> None:
        """Retain an explicit policy; a missing policy always fails closed."""
        self._policy: CodexBinaryPolicy | None = policy
        self._scratch_root: Path | None = scratch_root
        self._pinned_executable: Path | None = _pinned_executable

    def run(self, argv: Sequence[str], timeout_seconds: int) -> InvocationResult:
        """Run Codex using its scrubbed inherited OAuth environment."""
        if self._policy is None:
            raise capture_error(ERROR_BINARY_POLICY)
        command = tuple(argv)
        if not command or command[0] != "codex":
            raise capture_error(ERROR_BINARY_INVALID)
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in {"HOME", "LANG", "LC_ALL", "TMPDIR"}
        }
        if self._pinned_executable is not None:
            return invoke_staged(
                self._pinned_executable,
                command,
                environment,
                timeout_seconds,
            )
        if self._scratch_root is None:
            raise capture_error(ERROR_CAPTURE_ROOTS)
        with staged_executable(self._policy, self._scratch_root) as executable:
            return invoke_staged(
                executable,
                command,
                environment,
                timeout_seconds,
            )


def invoke_staged(
    executable: Path,
    command: tuple[str, ...],
    environment: dict[str, str],
    timeout_seconds: int,
) -> InvocationResult:
    """Invoke the staged binary through the shared AnyIO module seam."""
    return anyio.run(
        run_process,
        (str(executable), *command[1:]),
        environment,
        timeout_seconds,
    )


async def run_process(
    argv: tuple[str, ...], environment: dict[str, str], timeout_seconds: int
) -> InvocationResult:
    """Execute and fully reap one isolated process with bounded output."""
    process = await anyio.open_process(
        argv,
        stdin=None,
        env=environment,
        start_new_session=True,
    )
    stdout: list[bytes] = []
    stderr: list[bytes] = []
    output_limited = anyio.Event()
    returncode = -1
    try:
        with anyio.fail_after(timeout_seconds):
            async with anyio.create_task_group() as task_group:
                _ = task_group.start_soon(
                    _drain_stream,
                    process.stdout,
                    stdout,
                    _MAX_STDOUT_BYTES,
                    process,
                    output_limited,
                )
                _ = task_group.start_soon(
                    _drain_stream,
                    process.stderr,
                    stderr,
                    _MAX_STDERR_BYTES,
                    process,
                    output_limited,
                )
                returncode = await process.wait()
    except TimeoutError:
        _kill_process_group(process)
        await _reap_process(process)
        return InvocationResult(_TIMEOUT_RETURN_CODE, "", "timeout", timed_out=True)
    await process.aclose()
    if output_limited.is_set():
        return InvocationResult(
            _OUTPUT_LIMIT_RETURN_CODE,
            "",
            ERROR_OUTPUT_LIMIT,
            output_limited=True,
        )
    try:
        stdout_text = _decode_output(b"".join(stdout))
        stderr_text = _decode_output(b"".join(stderr))
    except UnicodeDecodeError:
        return InvocationResult(
            _DECODE_FAILURE_RETURN_CODE,
            "",
            ERROR_OUTPUT_ENCODING,
            decode_failed=True,
        )
    return InvocationResult(returncode, stdout_text, stderr_text)


async def _drain_stream(
    stream: ByteReceiveStream | None,
    chunks: list[bytes],
    limit: int,
    process: Process,
    output_limited: anyio.Event,
) -> None:
    """Drain one stream up to its byte ceiling and terminate on overflow."""
    if stream is None:
        return
    size = 0
    async for chunk in stream:
        remaining = limit - size
        if len(chunk) > remaining:
            if remaining > 0:
                chunks.append(chunk[:remaining])
            output_limited.set()
            _kill_process_group(process)
            return
        chunks.append(chunk)
        size += len(chunk)


def _kill_process_group(process: Process) -> None:
    """Kill the process and all descendants which inherited its pipes."""
    try:
        if os.name == "posix":
            os.killpg(process.pid, signal.SIGKILL)
        else:
            process.kill()
    except ProcessLookupError:
        pass


async def _reap_process(process: Process) -> None:
    """Bound cleanup even when a killed child left inherited pipes open."""
    with anyio.CancelScope(shield=True):
        with anyio.move_on_after(_CLEANUP_TIMEOUT_SECONDS):
            _ = await process.wait()
        with anyio.move_on_after(_CLEANUP_TIMEOUT_SECONDS):
            await process.aclose()


def _decode_output(value: bytes | None) -> str:
    return "" if value is None else value.decode()
