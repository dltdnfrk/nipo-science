"""Fixed, source-pinned SECURITY evidence producer."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import re
import selectors
import stat
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, BinaryIO, Final, Protocol

from tools.platform_policy.ci_contract import (
    EvidenceIntegrityError,
    RequiredSecurityCaseBinding,
    require_evidence_sanitized,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence


@dataclass(frozen=True, slots=True)
class SecurityCase:
    """One immutable High-threat adversarial test selection."""

    threat_id: str
    case_name: str
    node: str
    denial_observation_index: int
    postcondition_observation_index: int


SECURITY_CASES: tuple[SecurityCase, ...] = (
    SecurityCase(
        "T07",
        "malicious-files-and-archives",
        "tests/upload/test_ingestion.py::test_ingest_rolls_back_earlier_valid_files_when_later_file_fails",
        0,
        1,
    ),
    SecurityCase(
        "T08",
        "sandbox-escape",
        "tests/g002/test_vertical.py::test_failures_stop_without_execution_artifacts[_egress_request-egress-requested-0]",
        0,
        1,
    ),
    SecurityCase(
        "T09",
        "lease-fencing",
        "tests/g002/test_vertical.py::test_failures_stop_without_execution_artifacts[_stale_lease-stale-lease-0]",
        0,
        1,
    ),
    SecurityCase(
        "T10",
        "approval-replay",
        "tests/g002/test_vertical.py::test_approval_replay_has_no_second_execution_or_retry",
        0,
        1,
    ),
    SecurityCase(
        "T11",
        "export-traversal",
        "packages/contracts/python/tests/test_export_manifest_attacks.py::test_rejects_normalized_collision_and_unselected_latest_race",
        1,
        3,
    ),
    SecurityCase(
        "T12",
        "deletion-resurrection",
        "tests/platform/test_g005_recovery_contract.py::test_pre_tombstone_backup_blocks_visibility_and_released_hold_allows_purge",
        0,
        2,
    ),
    SecurityCase(
        "T13",
        "supply-chain",
        "tests/platform/test_static_checks.py::test_security_floating_workflow_action_is_rejected",
        0,
        1,
    ),
)

_CASE_MARKER = b"SECURITY_CASE="
_EVIDENCE_MARKER = b"SECURITY_EVIDENCE="
_PASSED = re.compile(rb"(?:^|\s)(\d+) passed(?:[,\s]|$)")
_CASE_TIMEOUT_SECONDS = 60.0
_GATE_TIMEOUT_SECONDS = 15 * 60.0
_OUTPUT_LIMIT_BYTES = 1_000_000
_READ_CHUNK_BYTES = 65_536
_SAFE_ENVIRONMENT_KEYS = ("HOME", "LANG", "LC_ALL", "PATH", "TZ")
_CASE_NODE_UNSAFE = "SECURITY case node is unsafe"
_CASE_SOURCE_UNSAFE = "SECURITY case source is unsafe"
_CASE_SOURCE_CHANGED = "SECURITY case source changed during binding"
_CASE_SOURCE_INVALID = "SECURITY case source is invalid"
_CASE_FUNCTION_AMBIGUOUS = "SECURITY case test function is ambiguous"
_CASE_OBSERVATIONS_INCOMPLETE = "SECURITY case observations are incomplete"
_CASE_OBSERVATIONS_SAME = "SECURITY case observations must be distinct"
PROCESS_FACTORY: Final[type[subprocess.Popen[bytes]]] = subprocess.Popen


@dataclass(frozen=True, slots=True)
class ChildResult:
    """Bounded result from one fixed SECURITY child process."""

    returncode: int | None
    output: bytes
    failure: str | None = None


class Runner(Protocol):
    """Fixed subprocess seam for isolated SECURITY test nodes."""

    def __call__(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> ChildResult:
        """Run one fixed argv command with bounded output and lifetime."""
        ...


def child_environment(source: Mapping[str, str]) -> dict[str, str]:
    """Return the narrow environment permitted to reach SECURITY children."""
    return {key: source[key] for key in _SAFE_ENVIRONMENT_KEYS if key in source}


def _terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate and reap the child process group, including descendant processes."""
    with suppress(ProcessLookupError):
        os.killpg(process.pid, 9)
    with suppress(subprocess.TimeoutExpired):
        _ = process.wait(timeout=1)


def _capture_bounded_output(
    process: subprocess.Popen[bytes],
    selector: selectors.BaseSelector,
    deadline: float,
    output_limit_bytes: int,
) -> ChildResult:
    """Read one child pipe until completion, timeout, or the byte ceiling."""
    if process.stdout is None:
        return ChildResult(None, b"", "SECURITY child has no stdout pipe")
    output = bytearray()
    _ = selector.register(process.stdout, selectors.EVENT_READ)
    try:
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return ChildResult(
                    process.returncode,
                    bytes(output),
                    "SECURITY child timed out",
                )
            for key, _ in selector.select(remaining):
                chunk = os.read(key.fd, _READ_CHUNK_BYTES)
                if not chunk:
                    _ = selector.unregister(key.fileobj)
                    continue
                if len(output) + len(chunk) > output_limit_bytes:
                    return ChildResult(
                        process.returncode,
                        bytes(output),
                        "SECURITY child exceeded output limit",
                    )
                output.extend(chunk)
        returncode = process.wait(timeout=max(deadline - time.monotonic(), 0))
    except (OSError, KeyError) as error:
        return ChildResult(
            process.returncode,
            bytes(output),
            f"SECURITY child failed: {error}",
        )
    except subprocess.TimeoutExpired:
        return ChildResult(
            process.returncode,
            bytes(output),
            "SECURITY child timed out",
        )
    return ChildResult(returncode, bytes(output))


def bounded_run(
    argv: tuple[str, ...],
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
) -> ChildResult:
    """Stream one child process under strict output, process-group, and time bounds."""
    try:
        process = PROCESS_FACTORY(
            argv,
            cwd=cwd,
            env=dict(environment),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as error:
        return ChildResult(None, b"", f"SECURITY child could not start: {error}")

    deadline = time.monotonic() + timeout_seconds
    selector = selectors.DefaultSelector()
    try:
        return _capture_bounded_output(
            process,
            selector,
            deadline,
            output_limit_bytes,
        )
    finally:
        selector.close()
        if process.stdout is not None:
            process.stdout.close()
        _terminate_process_group(process)


DEFAULT_RUNNER = bounded_run


def security_case_bindings(
    checkout: Path | None = None,
) -> tuple[RequiredSecurityCaseBinding, ...]:
    """Bind every exact test node to its source and two semantic observations."""
    root = checkout or Path(__file__).resolve().parents[2]
    return tuple(_case_binding(root, case) for case in SECURITY_CASES)


def _tamper_stat_signature(
    result: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    """Tamper signature for the read-back TOCTOU check, excluding access time.

    Reading the source legitimately updates atime on relatime mounts (fresh CI
    checkouts), and a full stat_result comparison misreported that as
    tampering. Identity (dev/ino), link count, mode, size, and mtime still pin
    replace/append/chmod races.
    """
    return (
        result.st_dev,
        result.st_ino,
        result.st_mode,
        result.st_nlink,
        result.st_size,
        result.st_mtime_ns,
    )


def _case_binding(root: Path, case: SecurityCase) -> RequiredSecurityCaseBinding:
    path_text, separator, node_text = case.node.partition("::")
    relative = PurePosixPath(path_text)
    function_name = node_text.partition("[")[0]
    if (
        separator != "::"
        or not function_name.isidentifier()
        or relative.is_absolute()
        or ".." in relative.parts
    ):
        raise ValueError(_CASE_NODE_UNSAFE)
    path = root.joinpath(*relative.parts)
    before = path.stat(follow_symlinks=False)
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError(_CASE_SOURCE_UNSAFE)
    source = path.read_bytes()
    after = path.stat(follow_symlinks=False)
    if _tamper_stat_signature(after) != _tamper_stat_signature(before):
        raise ValueError(_CASE_SOURCE_CHANGED)
    try:
        syntax = ast.parse(source, filename=path_text)
    except (SyntaxError, ValueError):
        raise ValueError(_CASE_SOURCE_INVALID) from None
    matches = tuple(
        node
        for node in syntax.body
        if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        and node.name == function_name
    )
    if len(matches) != 1:
        raise ValueError(_CASE_FUNCTION_AMBIGUOUS)
    test_node = matches[0]
    observations = _semantic_observations(test_node)
    try:
        denial = observations[case.denial_observation_index]
        postcondition = observations[case.postcondition_observation_index]
    except IndexError:
        raise ValueError(_CASE_OBSERVATIONS_INCOMPLETE) from None
    if denial is postcondition:
        raise ValueError(_CASE_OBSERVATIONS_SAME)
    return RequiredSecurityCaseBinding(
        threat_id=case.threat_id,
        case_id=case.node,
        source_sha256=hashlib.sha256(source).hexdigest(),
        test_sha256=_syntax_sha256("test", test_node),
        denial_observation_sha256=_syntax_sha256("denial", denial),
        postcondition_observation_sha256=_syntax_sha256(
            "postcondition", postcondition
        ),
    )


def _semantic_observations(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[ast.AST, ...]:
    observations: list[ast.AST] = []

    def visit(node: ast.AST) -> None:
        for child in ast.iter_child_nodes(node):
            if isinstance(child, ast.Assert):
                observations.append(child)
                continue
            if isinstance(child, ast.With | ast.AsyncWith) and any(
                isinstance(descendant, ast.Attribute)
                and descendant.attr == "raises"
                for item in child.items
                for descendant in ast.walk(item.context_expr)
            ):
                observations.append(child)
                continue
            if isinstance(
                child,
                ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef | ast.Lambda,
            ):
                continue
            visit(child)

    visit(function)
    return tuple(observations)


def _syntax_sha256(kind: str, node: ast.AST) -> str:
    canonical = ast.dump(node, annotate_fields=True, include_attributes=False)
    return hashlib.sha256(f"{kind}\0{canonical}".encode()).hexdigest()


def _select_case(selector: str | None) -> tuple[SecurityCase, ...]:
    if selector is None:
        return SECURITY_CASES
    selected = tuple(
        case for case in SECURITY_CASES if selector in {case.threat_id, case.case_name}
    )
    if len(selected) != 1:
        message = f"unknown SECURITY case: {selector}"
        raise ValueError(message)
    return selected


def _sanitized_child_output(result: ChildResult) -> bytes:
    output = result.output
    require_evidence_sanitized(output)
    if any(
        line.startswith((_CASE_MARKER, _EVIDENCE_MARKER))
        for line in output.splitlines()
    ):
        msg = "selected SECURITY test emitted a reserved evidence marker"
        raise ValueError(msg)
    return output


def _passed_once(output: bytes) -> bool:
    return sum(int(match.group(1)) for match in _PASSED.finditer(output)) == 1


def _write(stream: BinaryIO, content: bytes) -> None:
    written = stream.write(content)
    if written != len(content):
        message = "SECURITY evidence stream write was incomplete"
        raise OSError(message)
    if content and not content.endswith(b"\n"):
        newline_written = stream.write(b"\n")
        if newline_written != 1:
            message = "SECURITY evidence stream newline write was incomplete"
            raise OSError(message)


def run_security_gate(  # noqa: PLR0911 - Every unsafe branch exits immediately.
    selector: str | None = None,
    *,
    runner: Runner = DEFAULT_RUNNER,
    stream: BinaryIO | None = None,
    checkout: Path | None = None,
) -> int:
    """Run fixed pytest nodes and emit evidence only for observed one-test passes."""
    selected = _select_case(selector)
    checkout_root = checkout or Path(__file__).resolve().parents[2]
    output_stream = stream or sys.stdout.buffer
    case_lines: list[bytes] = []
    gate_deadline = time.monotonic() + _GATE_TIMEOUT_SECONDS
    environment = child_environment(os.environ)
    for case in selected:
        remaining = gate_deadline - time.monotonic()
        if remaining <= 0:
            _write(output_stream, b"SECURITY gate timed out")
            return 1
        try:
            binding = _case_binding(checkout_root, case)
        except ValueError as error:
            _write(output_stream, str(error).encode())
            return 1
        argv = (sys.executable, "-m", "pytest", "-q", case.node)
        result = runner(
            argv,
            checkout_root,
            environment,
            min(_CASE_TIMEOUT_SECONDS, remaining),
            _OUTPUT_LIMIT_BYTES,
        )
        try:
            output = _sanitized_child_output(result)
        except (EvidenceIntegrityError, ValueError) as error:
            _write(output_stream, str(error).encode())
            return 1
        if result.failure is not None:
            _write(output_stream, output)
            _write(output_stream, result.failure.encode())
            return 1
        if result.returncode != 0 or not _passed_once(output):
            _write(output_stream, output)
            return 1
        try:
            if _case_binding(checkout_root, case) != binding:
                _write(output_stream, b"SECURITY case source changed during execution")
                return 1
        except ValueError as error:
            _write(output_stream, str(error).encode())
            return 1
        payload = json.dumps(
            {**binding.model_dump(mode="json"), "outcome": "passed"},
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        line = _CASE_MARKER + payload + b"\n"
        _write(output_stream, line)
        case_lines.append(line)
    mappings = [
        {
            "evidence_root_sha256": hashlib.sha256(line).hexdigest(),
            "job": "SECURITY",
            "positive_case_count": 1,
            "threat_id": case.threat_id,
        }
        for case, line in zip(selected, case_lines, strict=True)
    ]
    _write(
        output_stream,
        _EVIDENCE_MARKER
        + json.dumps(mappings, separators=(",", ":"), sort_keys=True).encode()
        + b"\n",
    )
    return 0


class _Arguments(argparse.Namespace):
    """Typed command-line values accepted by the SECURITY producer."""

    selector: str | None

    def __init__(self) -> None:
        super().__init__()
        self.selector = None


def main(argv: Sequence[str] | None = None) -> int:
    """Run the immutable SECURITY catalog from the command line."""
    parser = argparse.ArgumentParser(description=__doc__)
    case_argument = parser.add_argument("--case", dest="selector")
    if case_argument.dest != "selector":
        parser.error("SECURITY case selector is misconfigured")
    arguments = _Arguments()
    parsed = parser.parse_args(argv, arguments)
    if parsed is not arguments:
        parser.error("SECURITY argument parsing did not preserve its typed namespace")
    try:
        return run_security_gate(arguments.selector)
    except ValueError as error:
        parser.error(str(error))


if __name__ == "__main__":
    raise SystemExit(main())
