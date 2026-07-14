"""Fixed, source-pinned SECURITY evidence producer."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import selectors
import subprocess
import sys
import time
from contextlib import suppress
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Final, Protocol

from tools.platform_policy.ci_contract import (
    EvidenceIntegrityError,
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


SECURITY_CASES: tuple[SecurityCase, ...] = (
    SecurityCase(
        "T01",
        "tenant-escape",
        "tests/g003/test_auth_tenancy.py::test_tenant_resources_hide_foreign_and_archived_parents",
    ),
    SecurityCase(
        "T02",
        "oauth-token-theft",
        "tests/g004/test_provider_http.py::test_provider_lifecycle_is_same_origin_idempotent_and_redacted",
    ),
    SecurityCase(
        "T03",
        "provider-tool-bypass",
        "tests/g004/test_tool_governance.py::test_default_deny_and_scope_rejection_have_zero_side_effects",
    ),
    SecurityCase(
        "T04",
        "vendor-runtime-compromise",
        "tests/g004/test_provider_qualification.py::test_raw_profile_is_contract_valid_but_never_live_qualified",
    ),
    SecurityCase(
        "T05",
        "prompt-injection",
        "tests/g004/test_provider_qualification.py::test_security_sentinels_are_rejected[7-decision_code-INJECTION_GS08_DO_NOT_OBEY]",
    ),
    SecurityCase(
        "T06",
        "ssrf",
        "tests/artifact_ui/test_artifact_http_security.py::test_host_alias_body_bounds_and_cross_org_download_are_denied",
    ),
    SecurityCase(
        "T07",
        "malicious-files-and-archives",
        "tests/upload/test_ingestion.py::test_ingest_rolls_back_earlier_valid_files_when_later_file_fails",
    ),
    SecurityCase(
        "T08",
        "sandbox-escape",
        "tests/g002/test_vertical.py::test_failures_stop_without_execution_artifacts[_egress_request-egress-requested-0]",
    ),
    SecurityCase(
        "T09",
        "lease-fencing",
        "tests/g002/test_vertical.py::test_failures_stop_without_execution_artifacts[_stale_lease-stale-lease-0]",
    ),
    SecurityCase(
        "T10",
        "approval-replay",
        "tests/g002/test_vertical.py::test_approval_replay_has_no_second_execution_or_retry",
    ),
    SecurityCase(
        "T11",
        "export-traversal",
        "packages/contracts/python/tests/test_export_manifest_attacks.py::test_rejects_normalized_collision_and_unselected_latest_race",
    ),
    SecurityCase(
        "T12",
        "deletion-resurrection",
        "tests/platform/test_g005_recovery_contract.py::test_pre_tombstone_backup_blocks_visibility_and_released_hold_allows_purge",
    ),
    SecurityCase(
        "T13",
        "supply-chain",
        "tests/platform/test_static_checks.py::test_security_floating_workflow_action_is_rejected",
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


def run_security_gate(
    selector: str | None = None,
    *,
    runner: Runner = DEFAULT_RUNNER,
    stream: BinaryIO | None = None,
) -> int:
    """Run fixed pytest nodes and emit evidence only for observed one-test passes."""
    selected = _select_case(selector)
    checkout = Path(__file__).resolve().parents[2]
    output_stream = stream or sys.stdout.buffer
    case_lines: list[bytes] = []
    gate_deadline = time.monotonic() + _GATE_TIMEOUT_SECONDS
    environment = child_environment(os.environ)
    for case in selected:
        remaining = gate_deadline - time.monotonic()
        if remaining <= 0:
            _write(output_stream, b"SECURITY gate timed out")
            return 1
        argv = (sys.executable, "-m", "pytest", "-q", case.node)
        result = runner(
            argv,
            checkout,
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
        payload = json.dumps(
            {"case_id": case.node, "outcome": "passed", "threat_id": case.threat_id},
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
