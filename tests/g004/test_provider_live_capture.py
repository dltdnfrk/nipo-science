"""Fail-closed tests for the Codex live qualification capture harness."""

from __future__ import annotations

import json
import runpy
import sys
import tempfile
import time
from dataclasses import replace
from pathlib import Path
from typing import TYPE_CHECKING, cast

import pytest
from services.api.provider_live_capture import (
    CaptureCase,
    CaptureError,
    CaptureExecutionProof,
    CodexCliInvocation,
    InvocationResult,
    capture_profile,
    load_cases,
)
from services.api.provider_qualification import (
    LiveCaptureReceipt,
    QualificationProfile,
    evaluate_profile,
    is_issued_qualification_result,
    issue_live_capture_receipt_from_capture,
    parse_profile_json,
)

if TYPE_CHECKING:
    from collections.abc import Iterator, Sequence

_FIXTURE = Path(__file__).parent / "fixtures" / "golden_session_cases.json"
_ROOT = Path(__file__).resolve().parents[2]
_CAPTURE_TEST_CACHE = _ROOT / ".cache" / "provider-live-capture-tests"


@pytest.fixture
def capture_path() -> Iterator[Path]:
    _CAPTURE_TEST_CACHE.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(dir=_CAPTURE_TEST_CACHE) as directory:
        yield Path(directory)


class FakeInvocation:
    def __init__(self, mode: str = "ok") -> None:
        self.mode: str = mode
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], timeout_seconds: int) -> InvocationResult:
        del timeout_seconds
        command = tuple(argv)
        self.calls.append(command)
        login = self._login_result(command)
        if login is not None:
            return login
        version = self._version_result(command)
        if version is not None:
            return version
        failure = self._failure_result()
        if failure is not None:
            return failure
        return self._attempt_result(command)

    def _login_result(self, command: tuple[str, ...]) -> InvocationResult | None:
        if command != ("codex", "login", "status"):
            return None
        return InvocationResult(
            1 if self.mode == "login" else 0,
            "Logged in with ChatGPT",
            "",
        )

    def _version_result(self, command: tuple[str, ...]) -> InvocationResult | None:
        if command != ("codex", "--version"):
            return None
        return InvocationResult(
            1 if self.mode == "version" else 0,
            "codex-cli 0.144.1",
            "",
        )

    def _failure_result(self) -> InvocationResult | None:
        if self.mode not in {"timeout", "nonzero"}:
            return None
        return InvocationResult(1, "", "", self.mode == "timeout")

    def _attempt_result(self, command: tuple[str, ...]) -> InvocationResult:
        response = self._response(command)
        output_from_command = Path(command[command.index("--output-last-message") + 1])
        output_relative = output_from_command.resolve().relative_to(_ROOT)
        output = Path(__file__).resolve().parents[2] / output_relative
        _ = output.write_text(json.dumps(response), encoding="utf-8")
        return InvocationResult(0, self._event_stream(), "")

    def _response(self, command: tuple[str, ...]) -> dict[str, object]:
        response_prompt = cast("dict[str, object]", json.loads(command[-1]))
        response = {
            key: response_prompt[key]
            for key in (
                "scenario_id",
                "decision_code",
                "scientific_result",
                "artifact_manifest",
                "evidence_identifiers",
                "limitations",
            )
        }
        self._apply_response_mode(response)
        return response

    def _apply_response_mode(self, response: dict[str, object]) -> None:
        replacements: dict[str, tuple[str, object]] = {
            "wrong_scenario": ("scenario_id", "GS99"),
            "generic_decision": ("decision_code", "GENERIC"),
            "generic_result": ("scientific_result", {"result": "generic"}),
            "empty_evidence": ("evidence_identifiers", []),
            "empty_limitations": ("limitations", []),
            "GS08": ("decision_code", "INJECTION_GS08_DO_NOT_OBEY"),
            "GS09": ("evidence_identifiers", ["FAKE_SECRET_GS09_NEVER_EMIT"]),
            "GS10": ("limitations", ["FOREIGN_TENANT_GS10_NEVER_EMIT"]),
        }
        if self.mode == "malformed":
            response.clear()
            response["broken"] = True
        elif replacement := replacements.get(self.mode):
            key, value = replacement
            response[key] = value

    def _event_stream(self) -> str:
        if self.mode == "missing_event":
            return '{"type":"thread.started"}\n{"type":"turn.completed"}'
        if self.mode == "error_event":
            return '{"type":"thread.started"}\n{"type":"error"}'
        return (
            '{"type":"thread.started"}\n'
            '{"type":"turn.started"}\n'
            '{"type":"response.output_text.delta"}\n'
            '{"type":"turn.completed"}'
        )


def test_injected_capture_is_synthetic_and_never_live_qualified(
    capture_path: Path,
) -> None:
    runner = FakeInvocation()
    output = capture_path / "profile.json"
    receipt = capture_profile(load_cases(_FIXTURE), output, runner)
    profile = cast("dict[str, object]", json.loads(output.read_text(encoding="utf-8")))
    result = evaluate_profile(output.read_bytes(), receipt)
    assert receipt is None
    assert not result.live_qualified
    assert profile["evidence_kind"] == "synthetic_contract_fixture"
    sessions = cast("list[dict[str, object]]", profile["sessions"])
    assert len(sessions) == 10
    assert all(len(cast("list[object]", session["attempts"])) == 3 for session in sessions)
    assert "response.output_text.delta" not in output.read_text(encoding="utf-8")
    assert len(runner.calls) == 32


def test_production_capture_issues_live_receipt_only_after_publish(
    capture_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeInvocation()

    def run(
        unused_self: CodexCliInvocation, argv: Sequence[str], timeout_seconds: int
    ) -> InvocationResult:
        del unused_self
        return fake.run(argv, timeout_seconds)

    monkeypatch.setattr(CodexCliInvocation, "run", run)
    output = capture_path / "profile.json"
    receipt = capture_profile(load_cases(_FIXTURE), output)

    assert receipt is not None
    assert output.exists()
    result = evaluate_profile(output.read_bytes(), receipt)
    assert result.live_qualified
    assert is_issued_qualification_result(result)
    profile = parse_profile_json(output.read_bytes())
    with pytest.raises(TypeError, match="issued only by production capture"):
        _ = CaptureExecutionProof(profile, "a" * 64, object())
    with pytest.raises(TypeError, match="issued only by production capture"):
        _ = issue_live_capture_receipt_from_capture(profile, "a" * 64, object())


@pytest.mark.parametrize(
    "mode",
    [
        "login",
        "version",
        "missing_event",
        "error_event",
        "malformed",
        "wrong_scenario",
        "generic_decision",
        "generic_result",
        "empty_evidence",
        "empty_limitations",
        "GS08",
        "GS09",
        "GS10",
        "timeout",
        "nonzero",
    ],
)
def test_failures_never_publish_profile(capture_path: Path, mode: str) -> None:
    output = capture_path / "profile.json"
    with pytest.raises(CaptureError):
        _ = capture_profile(load_cases(_FIXTURE), output, FakeInvocation(mode))
    assert not output.exists()


def test_exec_argv_has_required_isolation_flags(capture_path: Path) -> None:
    runner = FakeInvocation()
    _ = capture_profile(
        load_cases(_FIXTURE),
        capture_path / "profile.json",
        runner,
    )
    execution = runner.calls[2]
    assert execution[:2] == ("codex", "exec")
    assert "--ignore-user-config" in execution
    assert "--ignore-rules" in execution
    assert "--ephemeral" in execution
    sandbox_index = execution.index("--sandbox")
    assert execution[sandbox_index : sandbox_index + 2] == (
        "--sandbox",
        "read-only",
    )
    assert "--json" in execution
    assert "--output-schema" in execution
    assert "--output-last-message" in execution
    assert "--skip-git-repo-check" in execution


def test_production_invocation_uses_argv_and_scrubbed_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(
        function: object,
        argv: tuple[str, ...],
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> InvocationResult:
        observed["function"] = function
        observed["argv"] = argv
        observed["environment"] = environment
        observed["timeout_seconds"] = timeout_seconds
        return InvocationResult(0, "ok", "")

    monkeypatch.setenv("OPENAI_API_KEY", "must-not-pass")
    monkeypatch.setattr("services.api.provider_live_capture.anyio.run", fake_run)
    result = CodexCliInvocation().run(("codex", "--version"), 1)
    environment = cast("dict[str, str]", observed["environment"])
    assert observed["argv"] == ("codex", "--version")
    assert observed["timeout_seconds"] == 1
    assert "OPENAI_API_KEY" not in environment
    assert result.stdout == "ok"


def test_production_invocation_enforces_timeout() -> None:
    started = time.monotonic()
    result = CodexCliInvocation().run(
        (sys.executable, "-c", "import time; time.sleep(60)"),
        1,
    )
    elapsed = time.monotonic() - started
    assert result.timed_out
    assert result.returncode == 124
    assert elapsed < 5
@pytest.mark.parametrize(
    "field",
    [
        "scenario_id",
        "requirement",
        "input_text",
        "rubric",
        "decision_code",
        "scientific_result",
        "artifact_manifest",
        "evidence_identifiers",
        "limitations",
        "forbidden_sentinels",
    ],
)
def test_mutated_golden_case_is_rejected_before_codex_invocation(
    capture_path: Path, field: str
) -> None:
    cases = list(load_cases(_FIXTURE))
    cases[0] = _mutated_case(cases[0], field)
    runner = FakeInvocation()

    with pytest.raises(CaptureError, match="capture cases are invalid"):
        _ = capture_profile(tuple(cases), capture_path / "profile.json", runner)

    assert runner.calls == []
    assert not (capture_path / "profile.json").exists()


def _mutated_case(case: CaptureCase, field: str) -> CaptureCase:
    if field in {
        "scenario_id",
        "requirement",
        "input_text",
        "rubric",
        "decision_code",
    }:
        return replace(case, **{field: f"{getattr(case, field)} changed"})
    if field == "scientific_result":
        return replace(
            case,
            scientific_result={**case.scientific_result, "changed": True},
        )
    if field == "artifact_manifest":
        return replace(
            case,
            artifact_manifest={**case.artifact_manifest, "changed": True},
        )
    if field == "evidence_identifiers":
        return replace(
            case,
            evidence_identifiers=(*case.evidence_identifiers, "changed"),
        )
    if field == "limitations":
        return replace(case, limitations=(*case.limitations, "changed"))
    return replace(
        case,
        forbidden_sentinels=(*case.forbidden_sentinels, "changed"),
    )


def test_module_execution_uses_canonical_capture_proof_type(
    capture_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeInvocation()
    issued: list[LiveCaptureReceipt] = []
    original_issue = issue_live_capture_receipt_from_capture

    def run_process(
        unused_function: object,
        argv: tuple[str, ...],
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> InvocationResult:
        del unused_function, environment
        return fake.run(argv, timeout_seconds)

    def issue(
        profile: QualificationProfile, cases_sha256: str, proof: object
    ) -> LiveCaptureReceipt:
        receipt = original_issue(profile, cases_sha256, proof)
        issued.append(receipt)
        return receipt

    original_capture_module = sys.modules[
        "services.api.provider_live_capture"
    ]
    monkeypatch.setattr("services.api.provider_live_capture.anyio.run", run_process)
    monkeypatch.setattr(
        "services.api.provider_qualification.issue_live_capture_receipt_from_capture",
        issue,
    )
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "provider_live_capture",
            "--cases",
            str(_FIXTURE),
            "--output",
            str(capture_path / "profile.json"),
        ],
    )
    with monkeypatch.context() as context:
        context.delitem(sys.modules, "services.api.provider_live_capture")
        with pytest.raises(SystemExit) as exit_status:
            _ = runpy.run_module(
                "services.api.provider_live_capture",
                run_name="__main__",
                alter_sys=True,
            )

    assert exit_status.value.code == 0
    assert len(issued) == 1
    assert evaluate_profile(
        (capture_path / "profile.json").read_bytes(), issued[0]
    ).live_qualified
    assert sys.modules["services.api.provider_live_capture"] is original_capture_module
