"""Focused tests for the fixed SECURITY evidence producer."""

from __future__ import annotations

import hashlib
import io
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Protocol

import pytest
from pydantic import TypeAdapter
from tools.platform_policy.ci_contract import (
    CiJob,
    EvidenceIntegrityError,
    GateResult,
    RequiredSecurityCatalog,
    SecurityEvidenceMapping,
    parse_security_evidence_output,
    rederive_gate_count,
)
from tools.platform_policy.security_gate import (
    SECURITY_CASES,
    ChildResult,
    bounded_run,
    child_environment,
    run_security_gate,
)

if TYPE_CHECKING:
    from collections.abc import Mapping


class CallableRunner(Protocol):
    def __call__(
        self,
        argv: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> ChildResult: ...


def _runner(
    argv: tuple[str, ...],
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: float,
    output_limit_bytes: int,
) -> ChildResult:
    _ = argv, cwd, environment, timeout_seconds, output_limit_bytes
    return ChildResult(0, b"1 passed in 0.01s\n")


def _fixed_runner(completed: ChildResult) -> CallableRunner:
    def runner(
        argv: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> ChildResult:
        _ = argv, cwd, environment, timeout_seconds, output_limit_bytes
        return completed

    return runner


def _catalog() -> RequiredSecurityCatalog:
    return RequiredSecurityCatalog(
        high_threat_ids=tuple(case.threat_id for case in SECURITY_CASES),
        source_root_sha256="0" * 64,
    )


def _output() -> bytes:
    stream = io.BytesIO()
    assert run_security_gate(runner=_runner, stream=stream) == 0
    return stream.getvalue()


def test_gate_emits_one_observed_case_per_catalog_threat() -> None:
    output = _output()

    mappings = parse_security_evidence_output(_catalog(), output)

    assert tuple(mapping.threat_id for mapping in mappings) == tuple(
        case.threat_id for case in SECURITY_CASES
    )
    assert all(mapping.positive_case_count == 1 for mapping in mappings)
    assert sum(mapping.positive_case_count for mapping in mappings) == len(
        SECURITY_CASES
    )
    assert len({mapping.evidence_root_sha256 for mapping in mappings}) == len(
        SECURITY_CASES
    )


def test_gate_uses_the_immutable_exact_node_argv() -> None:
    observed: list[tuple[str, ...]] = []

    def runner(
        argv: tuple[str, ...],
        cwd: Path,
        environment: Mapping[str, str],
        timeout_seconds: float,
        output_limit_bytes: int,
    ) -> ChildResult:
        _ = cwd, environment, timeout_seconds, output_limit_bytes
        observed.append(argv)
        return _runner(argv, cwd, environment, timeout_seconds, output_limit_bytes)

    assert run_security_gate(runner=runner, stream=io.BytesIO()) == 0

    assert observed == [
        (sys.executable, "-m", "pytest", "-q", case.node) for case in SECURITY_CASES
    ]


def test_gate_fails_closed_for_failed_vacuous_or_reserved_child_output() -> None:
    failed = ChildResult(1, b"1 failed\n")
    vacuous = ChildResult(0, b"no tests ran\n")
    forged = ChildResult(0, b'SECURITY_CASE={"case_id":"x"}\n')

    assert (
        run_security_gate("T01", runner=_fixed_runner(failed), stream=io.BytesIO()) == 1
    )
    assert (
        run_security_gate("T01", runner=_fixed_runner(vacuous), stream=io.BytesIO())
        == 1
    )
    assert (
        run_security_gate("T01", runner=_fixed_runner(forged), stream=io.BytesIO()) == 1
    )


def test_gate_accepts_exact_case_names_and_rejects_unknown_case() -> None:
    assert (
        run_security_gate("provider-tool-bypass", runner=_runner, stream=io.BytesIO())
        == 0
    )
    with pytest.raises(ValueError, match="unknown SECURITY case"):
        _ = run_security_gate("not-a-threat", runner=_runner, stream=io.BytesIO())


def test_parser_rejects_forged_root_count_duplicate_id_and_wrong_order() -> None:
    output = _output()
    marker = b"SECURITY_EVIDENCE="
    evidence_line = next(
        line for line in output.splitlines() if line.startswith(marker)
    )
    mapping_adapter = TypeAdapter(list[SecurityEvidenceMapping])
    mappings = mapping_adapter.validate_json(evidence_line[len(marker) :])

    forged_root = mappings.copy()
    forged_root[0] = forged_root[0].model_copy(
        update={"evidence_root_sha256": "0" * 64}
    )
    forged_count = mappings.copy()
    forged_count[0] = forged_count[0].model_copy(update={"positive_case_count": 2})
    wrong_order = list(reversed(mappings))
    first_case = next(
        line for line in output.splitlines() if line.startswith(b"SECURITY_CASE=")
    )
    duplicate = output.replace(first_case, first_case + b"\n" + first_case, 1)

    for forged in (forged_root, forged_count, wrong_order):
        encoded = (
            b"["
            + b",".join(mapping.model_dump_json().encode() for mapping in forged)
            + b"]"
        )
        candidate = output.replace(evidence_line, marker + encoded, 1)
        with pytest.raises(EvidenceIntegrityError):
            _ = parse_security_evidence_output(_catalog(), candidate)
    with pytest.raises(EvidenceIntegrityError):
        _ = parse_security_evidence_output(_catalog(), duplicate)


def test_security_count_ignores_generic_markers_and_requires_structured_cases() -> None:
    output = _output() + b"Ran 100 tests\nCHECKS_EXECUTED=100\n"
    record = GateResult(
        job=CiJob.SECURITY,
        executed_count=len(SECURITY_CASES),
        output_sha256=hashlib.sha256(output).hexdigest(),
        argv=("security-gate",),
    )

    rederive_gate_count(record, output)

    forged = output.replace(b"SECURITY_CASE=", b"", 1)
    with pytest.raises(EvidenceIntegrityError):
        rederive_gate_count(record, forged)


def test_every_fixed_node_is_collectable_without_docker() -> None:
    root = Path(__file__).parents[2]
    for case in SECURITY_CASES:
        result = bounded_run(
            (sys.executable, "-m", "pytest", "--collect-only", "-q", case.node),
            root,
            child_environment({}),
            60,
            1_000_000,
        )
        assert result.failure is None
        assert result.returncode == 0, result.output.decode(errors="replace")


def test_bounded_runner_fails_on_timeout_and_output_limit(tmp_path: Path) -> None:
    timeout = bounded_run(
        (sys.executable, "-c", "import time; time.sleep(10)"),
        tmp_path,
        {},
        0.01,
        1024,
    )
    overflow = bounded_run(
        (sys.executable, "-c", "import sys; sys.stdout.write('x' * 2048)"),
        tmp_path,
        {},
        1,
        1024,
    )

    assert timeout.failure == "SECURITY child timed out"
    assert overflow.failure == "SECURITY child exceeded output limit"
    stream = io.BytesIO()
    assert run_security_gate("T01", runner=_fixed_runner(timeout), stream=stream) == 1
    assert b"SECURITY_CASE=" not in stream.getvalue()


def test_bounded_runner_reaps_closed_pipe_hanging_process_tree(tmp_path: Path) -> None:
    script = (
        "import os, subprocess, sys, time; "
        "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(10)']); "
        "os.close(sys.stdout.fileno()); time.sleep(10)"
    )

    result = bounded_run((sys.executable, "-c", script), tmp_path, {}, 0.01, 1024)

    assert result.failure == "SECURITY child timed out"


def test_child_environment_excludes_authority_secrets() -> None:
    source = {
        "PATH": "/usr/bin",
        "HOME": "/var/empty/security-home",
        "CI_AUTHORITY_TOKEN": "must-not-reach-child",
        "GITHUB_TOKEN": "must-not-reach-child",
    }

    environment = child_environment(source)

    assert environment == {"PATH": "/usr/bin", "HOME": "/var/empty/security-home"}
    assert "CI_AUTHORITY_TOKEN" not in environment
    assert "GITHUB_TOKEN" not in environment
