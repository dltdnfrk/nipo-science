"""Fail-closed capture of live OpenAI Codex qualification evidence."""

from __future__ import annotations

import argparse
import json
import os
import re
import signal
import sys
import tempfile
from collections.abc import Mapping
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Final, Protocol, cast, final

import anyio

from services.api.provider_qualification import (
    LiveCaptureReceipt,
    QualificationProfile,
    issue_live_capture_receipt_from_capture,
    parse_profile_json,
    profile_sha256,
)

if __name__ == "__main__":
    _ = sys.modules.setdefault(
        "services.api.provider_live_capture",
        sys.modules[__name__],
    )

if TYPE_CHECKING:
    from collections.abc import Sequence

    from anyio.abc import ByteReceiveStream, Process

_CANONICAL_CASES_SHA256: Final = (
    "aea210e96f0d26df5050ab28eb6fc410c0b61e838d344eeaffe8b5007ed365c9"
)
_SCENARIOS: Final = tuple(f"GS{number:02d}" for number in range(1, 11))
_CAPTURE_PROOF_SEAL: Final = object()
_CAPTURE_PROOF_ERROR: Final = (
    "CaptureExecutionProof is issued only by production capture"
)


@dataclass(frozen=True, slots=True, init=False)
@final
class CaptureExecutionProof:
    """Opaque proof created only after a production capture is published."""

    profile_sha256: str
    cases_sha256: str
    account_ref: str
    runtime_version: str
    protocol_attempts: int
    cleanup_terminal: bool
    cleanup_redaction_complete: bool
    _seal: object

    def __init__(
        self,
        profile: QualificationProfile,
        cases_sha256: str,
        seal: object,
    ) -> None:
        """Bind the already-published production capture facts."""
        if seal is not _CAPTURE_PROOF_SEAL:
            raise TypeError(_CAPTURE_PROOF_ERROR)
        object.__setattr__(self, "profile_sha256", profile_sha256(profile))
        object.__setattr__(self, "cases_sha256", cases_sha256)
        object.__setattr__(self, "account_ref", profile.account_ref)
        object.__setattr__(self, "runtime_version", profile.runtime_version)
        object.__setattr__(
            self,
            "protocol_attempts",
            len(profile.sessions) * _ATTEMPTS,
        )
        object.__setattr__(self, "cleanup_terminal", profile.cleanup.terminal)
        object.__setattr__(
            self,
            "cleanup_redaction_complete",
            profile.cleanup.redaction_complete,
        )
        object.__setattr__(self, "_seal", seal)

    def is_capture_issued(self) -> bool:
        """Return whether this exact proof retains the capture seal."""
        return self._seal is _CAPTURE_PROOF_SEAL


def is_issued_capture_execution_proof(value: object) -> bool:
    """Return whether production capture issued this exact proof."""
    return type(value) is CaptureExecutionProof and value.is_capture_issued()
_ATTEMPTS: Final = 3
_TIMEOUT_SECONDS: Final = 90
_CLEANUP_TIMEOUT_SECONDS: Final = 2
_MAX_TEXT: Final = 400
_MAX_VERSION_TEXT: Final = 256
_MAX_VERSION_PARTS: Final = 2
_MAX_LIMITATIONS: Final = 3
_SENSITIVE_VALUE: Final = re.compile(
    r"(?i)(?:bearer\s+\S+|sk-[a-z0-9_-]{8,}|"
    r"eyj[a-z0-9_-]{8,}\.[a-z0-9_-]+\.[a-z0-9_-]+)"
)
_ERROR_CASES_INVALID: Final = "capture cases are invalid"
_ERROR_CASES_SCENARIOS: Final = (
    "capture cases must be exactly GS01 through GS10"
)
_ERROR_OUTPUT_EXISTS: Final = "capture output already exists"
_ERROR_OUTPUT_BOUNDARY: Final = "capture output must remain inside the workspace"
_ERROR_TEMPORARY_CLEANUP: Final = "capture temporary cleanup failed"
_ERROR_VERSION_INVALID: Final = "codex version is invalid"
_ERROR_SENSITIVE_OUTPUT: Final = "codex emitted sensitive output"
_ERROR_OFFICIAL_LOGIN: Final = "official ChatGPT login is required"
_ERROR_RESPONSE_MALFORMED: Final = "codex response is malformed"
_ERROR_FORBIDDEN_CONTENT: Final = "codex response contains forbidden content"
_ERROR_SAFETY_VALIDATION: Final = "codex response failed safety validation"
_ERROR_PROTOCOL_MALFORMED: Final = "codex protocol is malformed"
_ERROR_PROTOCOL_FAILED: Final = "codex protocol failed"
_ERROR_PROTOCOL_INCOMPLETE: Final = "codex protocol is incomplete"
_PROMPT_INSTRUCTION: Final = (
    "Return only the exact JSON contract; research-only, non-clinical analysis."
)
_WORKSPACE_ROOT: Final = Path(__file__).resolve().parents[2]
_CAPTURE_CACHE_ROOT: Final = _WORKSPACE_ROOT / ".cache" / "provider-live-capture"


class CaptureError(RuntimeError):
    """Stable failure which guarantees no live profile was published."""


@dataclass(frozen=True, slots=True)
class CaptureCase:
    """One bounded, deterministic qualification scenario."""

    scenario_id: str
    requirement: str
    input_text: str
    rubric: str
    decision_code: str
    scientific_result: Mapping[str, object]
    artifact_manifest: Mapping[str, object]
    evidence_identifiers: tuple[str, ...]
    limitations: tuple[str, ...]
    forbidden_sentinels: tuple[str, ...]

@dataclass(frozen=True, slots=True)
class InvocationResult:
    """The normalized result of one argv-only Codex invocation."""

    returncode: int
    stdout: str
    stderr: str
    timed_out: bool = False


class CodexInvocation(Protocol):
    """Injectable, argv-only boundary around the Codex executable."""

    def run(self, argv: Sequence[str], timeout_seconds: int) -> InvocationResult:
        """Run ``argv`` with the supplied timeout."""
        ...


class CodexCliInvocation:
    """Production boundary which neither reads nor copies credentials."""

    def run(self, argv: Sequence[str], timeout_seconds: int) -> InvocationResult:
        """Run Codex using its scrubbed inherited OAuth environment."""
        environment = {
            key: value
            for key, value in os.environ.items()
            if key in {"HOME", "LANG", "LC_ALL", "PATH", "TMPDIR"}
        }
        return anyio.run(
            _run_process,
            tuple(argv),
            environment,
            timeout_seconds,
        )


async def _run_process(
    argv: tuple[str, ...], environment: dict[str, str], timeout_seconds: int
) -> InvocationResult:
    process = await anyio.open_process(
        argv,
        stdin=None,
        env=environment,
        start_new_session=True,
    )
    stdout: list[bytes] = []
    stderr: list[bytes] = []
    returncode = -1
    try:
        with anyio.fail_after(timeout_seconds):
            async with anyio.create_task_group() as task_group:
                _ = task_group.start_soon(_drain_stream, process.stdout, stdout)
                _ = task_group.start_soon(_drain_stream, process.stderr, stderr)
                returncode = await process.wait()
    except TimeoutError:
        _kill_process_group(process)
        await _reap_process(process)
        return InvocationResult(124, "", "timeout", timed_out=True)
    await process.aclose()
    return InvocationResult(
        returncode,
        _decode_output(b"".join(stdout)),
        _decode_output(b"".join(stderr)),
    )


async def _drain_stream(
    stream: ByteReceiveStream | None, chunks: list[bytes]
) -> None:
    """Drain one process output stream while the process runs."""
    if stream is not None:
        chunks.extend([chunk async for chunk in stream])


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


def load_cases(path: Path) -> tuple[CaptureCase, ...]:
    """Strictly load the ten bounded, deterministic qualification cases."""
    try:
        decoded = cast("object", json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _capture_error(_ERROR_CASES_INVALID) from error
    root = _mapping(decoded, "cases")
    if set(root) != {"cases"}:
        raise _capture_error(_ERROR_CASES_INVALID)
    items = _list(root["cases"], "cases.cases")
    cases = tuple(_parse_case(item, index) for index, item in enumerate(items))
    if tuple(case.scenario_id for case in cases) != _SCENARIOS:
        raise _capture_error(_ERROR_CASES_SCENARIOS)
    if _cases_sha256(cases) != _CANONICAL_CASES_SHA256:
        raise _capture_error(_ERROR_CASES_INVALID)
    return cases


def capture_profile(
    cases: tuple[CaptureCase, ...],
    output: Path,
    invocation: CodexInvocation | None = None,
) -> LiveCaptureReceipt | None:
    """Capture 30 verified attempts; only the production boundary issues trust."""
    try:
        output_relative = output.resolve().relative_to(_WORKSPACE_ROOT)
    except ValueError as error:
        raise _capture_error(_ERROR_OUTPUT_BOUNDARY) from error
    output = _WORKSPACE_ROOT / output_relative
    if output.exists():
        raise _capture_error(_ERROR_OUTPUT_EXISTS)
    if _cases_sha256(cases) != _CANONICAL_CASES_SHA256:
        raise _capture_error(_ERROR_CASES_INVALID)
    runner = invocation if invocation is not None else CodexCliInvocation()
    login = _run(runner, ("codex", "login", "status"), "login status")
    login_status = "\n".join(part for part in (login.stdout, login.stderr) if part)
    _require_official_login(login_status)
    version = _run(runner, ("codex", "--version"), "version").stdout.strip()
    if not version or len(version) > _MAX_VERSION_TEXT or _contains_sensitive(version):
        raise _capture_error(_ERROR_VERSION_INVALID)
    runtime_version = _runtime_version_ref(version)
    account_ref = "acct_" + sha256(login_status.encode()).hexdigest()
    sessions = _capture_sessions(cases, runner)
    profile = {
        "evidence_kind": (
            "captured_live_profile"
            if type(runner) is CodexCliInvocation
            else "synthetic_contract_fixture"
        ),
        "adapter": "openai_codex",
        "oauth": {"mode": "official_subscription_oauth", "provider": "openai"},
        "runtime_version": runtime_version,
        "account_ref": account_ref,
        "sessions": sessions,
        "cleanup": {"terminal": True, "redaction_complete": True},
    }
    serialized = json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n"
    _atomic_publish(output_relative, serialized)
    if type(runner) is not CodexCliInvocation:
        return None
    profile_observation = parse_profile_json(serialized)
    proof = CaptureExecutionProof(
        profile_observation,
        _cases_sha256(cases),
        _CAPTURE_PROOF_SEAL,
    )
    return issue_live_capture_receipt_from_capture(
        profile_observation,
        _cases_sha256(cases),
        proof,
    )


def _capture_sessions(
    cases: tuple[CaptureCase, ...], runner: CodexInvocation
) -> list[dict[str, object]]:
    sessions: list[dict[str, object]] = []
    try:
        _CAPTURE_CACHE_ROOT.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(
            prefix="codex-live-capture-", dir=_CAPTURE_CACHE_ROOT
        ) as directory:
            base = Path(directory)
            schema_path = base / "response-schema.json"
            _ = schema_path.write_text(_response_schema(), encoding="utf-8")
            sessions.extend(
                _capture_case(case, runner, base, schema_path) for case in cases
            )
    except OSError as error:
        raise _capture_error(_ERROR_TEMPORARY_CLEANUP) from error
    return sessions


def _capture_case(
    case: CaptureCase, runner: CodexInvocation, base: Path, schema_path: Path
) -> dict[str, object]:
    attempts = [
        _capture_attempt(case, number, runner, base, schema_path)
        for number in range(1, _ATTEMPTS + 1)
    ]
    return {"scenario_id": case.scenario_id, "attempts": attempts}


def _capture_attempt(
    case: CaptureCase,
    number: int,
    runner: CodexInvocation,
    base: Path,
    schema_path: Path,
) -> dict[str, object]:
    last_message = base / f"{case.scenario_id}-{number}.json"
    result = _run(
        runner,
        _exec_argv(case, schema_path, last_message),
        "qualification attempt",
    )
    final = _read_final(last_message, result.stdout)
    return _validate_attempt(case, number, result.stdout, final)


def _runtime_version_ref(value: str) -> str:
    parts = value.split()
    if len(parts) != _MAX_VERSION_PARTS or parts[0] != "codex-cli":
        raise _capture_error(_ERROR_VERSION_INVALID)
    return "-".join(parts)


def _parse_case(value: object, index: int) -> CaptureCase:
    label = f"cases.cases[{index}]"
    data = _mapping(value, label)
    required = {
        "scenario_id", "requirement", "input", "rubric", "decision_code",
        "scientific_result", "artifact_manifest", "evidence_identifiers",
        "limitations", "forbidden_sentinels",
    }
    if set(data) != required:
        raise _capture_error(_ERROR_CASES_INVALID)
    text_values = (
        _text(data["scenario_id"], f"{label}.scenario_id"),
        _text(data["requirement"], f"{label}.requirement"),
        _text(data["input"], f"{label}.input"),
        _text(data["rubric"], f"{label}.rubric"),
        _text(data["decision_code"], f"{label}.decision_code"),
    )
    scientific = _case_object(
        data["scientific_result"], f"{label}.scientific_result"
    )
    artifact = _case_object(data["artifact_manifest"], f"{label}.artifact_manifest")
    evidence = _case_strings(
        data["evidence_identifiers"], f"{label}.evidence_identifiers"
    )
    limitations = _case_strings(data["limitations"], f"{label}.limitations")
    sentinels = _case_strings(
        data["forbidden_sentinels"], f"{label}.forbidden_sentinels"
    )
    invalid = (
        any(len(item) > _MAX_TEXT or not item.strip() for item in text_values)
        or not evidence
        or not limitations
        or len(limitations) > _MAX_LIMITATIONS
        or not sentinels
    )
    if invalid:
        raise _capture_error(_ERROR_CASES_INVALID)
    return CaptureCase(
        *text_values,
        scientific,
        artifact,
        evidence,
        limitations,
        sentinels,
    )


def _case_object(value: object, label: str) -> Mapping[str, object]:
    data = _mapping(value, label)
    if not data:
        raise _capture_error(_ERROR_CASES_INVALID)
    return data


def _case_strings(value: object, label: str) -> tuple[str, ...]:
    values = tuple(_text(item, label) for item in _list(value, label))
    if not values or len(set(values)) != len(values) or any(
        not item.strip() or len(item) > _MAX_TEXT for item in values
    ):
        raise _capture_error(_ERROR_CASES_INVALID)
    return values


def _exec_argv(case: CaptureCase, schema: Path, last_message: Path) -> tuple[str, ...]:
    prompt = json.dumps(
        {
            "scenario_id": case.scenario_id,
            "requirement": case.requirement,
            "input": case.input_text,
            "rubric": case.rubric,
            "decision_code": case.decision_code,
            "scientific_result": case.scientific_result,
            "artifact_manifest": case.artifact_manifest,
            "evidence_identifiers": case.evidence_identifiers,
            "limitations": case.limitations,
            "instruction": _PROMPT_INSTRUCTION,
        },
        sort_keys=True,
    )
    return (
        "codex", "exec", "--ignore-user-config", "--ignore-rules", "--ephemeral",
        "--sandbox", "read-only", "--json", "--output-schema", str(schema),
        "--output-last-message", str(last_message), "--skip-git-repo-check", prompt,
    )


def _run(
    runner: CodexInvocation, argv: tuple[str, ...], purpose: str
) -> InvocationResult:
    result = runner.run(argv, _TIMEOUT_SECONDS)
    if result.timed_out or result.returncode != 0:
        message = f"codex {purpose} failed"
        raise _capture_error(message)
    if _contains_sensitive(result.stderr):
        raise _capture_error(_ERROR_SENSITIVE_OUTPUT)
    return result


def _require_official_login(status: str) -> None:
    normalized = status.lower()
    if (
        _contains_sensitive(status)
        or "chatgpt" not in normalized
        or "logged in" not in normalized
    ):
        raise _capture_error(_ERROR_OFFICIAL_LOGIN)


def _read_final(path: Path, stream: str) -> object:
    if _contains_sensitive(stream):
        raise _capture_error(_ERROR_SENSITIVE_OUTPUT)
    try:
        return cast("object", json.loads(path.read_text(encoding="utf-8")))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise _capture_error(_ERROR_RESPONSE_MALFORMED) from error


def _validate_attempt(
    case: CaptureCase, number: int, stream: str, final: object
) -> dict[str, object]:
    forbidden = any(
        sentinel in stream or _contains_value(final, sentinel)
        for sentinel in case.forbidden_sentinels
    )
    if forbidden:
        raise _capture_error(_ERROR_FORBIDDEN_CONTENT)
    events = _parse_events(stream)
    response = _mapping(final, "response")
    _validate_response(case, response)
    scientific = _case_object(
        response["scientific_result"], "response.scientific_result"
    )
    artifact = _case_object(response["artifact_manifest"], "response.artifact_manifest")
    return {
        "attempt_id": f"{case.scenario_id}-{number}",
        "events": [{"kind": kind} for kind in events],
        "decision_code": case.decision_code,
        "scientific_result": scientific,
        "artifact_manifest": artifact,
        "evidence_identifiers": list(case.evidence_identifiers),
        "limitations": list(case.limitations),
        "scientific_hash": _object_hash(scientific),
        "artifact_hash": _object_hash(artifact),
    }


def _validate_response(case: CaptureCase, response: Mapping[str, object]) -> None:
    required = {
        "scenario_id", "decision_code", "scientific_result", "artifact_manifest",
        "evidence_identifiers", "limitations",
    }
    if set(response) != required:
        raise _capture_error(_ERROR_RESPONSE_MALFORMED)
    if (
        response.get("scenario_id") != case.scenario_id
        or response.get("decision_code") != case.decision_code
        or response.get("scientific_result") != case.scientific_result
        or response.get("artifact_manifest") != case.artifact_manifest
        or tuple(
            _case_strings(
                response["evidence_identifiers"], "response.evidence_identifiers"
            )
        )
        != case.evidence_identifiers
        or tuple(_case_strings(response["limitations"], "response.limitations"))
        != case.limitations
        or _contains_sensitive(json.dumps(response, sort_keys=True))
    ):
        raise _capture_error(_ERROR_SAFETY_VALIDATION)


def _parse_events(stream: str) -> tuple[str, ...]:
    seen = {"thread": False, "turn": False, "terminal": False, "delta": False}
    normalized: list[str] = []
    for line in stream.splitlines():
        event = _parse_event(line)
        event_type = _text(event.get("type"), "event.type")
        _record_event(event, event_type, seen, normalized)
    if not all(seen.values()):
        raise _capture_error(_ERROR_PROTOCOL_INCOMPLETE)
    return tuple(normalized)


def _parse_event(line: str) -> Mapping[str, object]:
    try:
        return _mapping(cast("object", json.loads(line)), "event")
    except (json.JSONDecodeError, CaptureError) as error:
        raise _capture_error(_ERROR_PROTOCOL_MALFORMED) from error


def _record_event(
    event: Mapping[str, object],
    event_type: str,
    seen: dict[str, bool],
    normalized: list[str],
) -> None:
    if "error" in event_type or "failed" in event_type:
        raise _capture_error(_ERROR_PROTOCOL_FAILED)
    if event_type == "thread.started":
        seen["thread"] = True
    elif event_type == "turn.started":
        seen["turn"] = True
        normalized.append("start")
    elif event_type == "turn.completed":
        seen["terminal"] = True
        normalized.append("terminal")
    elif event_type.endswith(".delta") or (
        event_type == "item.completed" and _agent_message(event)
    ):
        seen["delta"] = True
        normalized.append("delta")


def _agent_message(event: Mapping[str, object]) -> bool:
    item = _nested_mapping(event.get("item"))
    return item is not None and item.get("type") in {
        "agent_message",
        "assistant_message",
    }


def _response_schema() -> str:
    properties: dict[str, object] = {
        "scenario_id": {"type": "string"},
        "decision_code": {"type": "string", "minLength": 1, "maxLength": _MAX_TEXT},
        "scientific_result": {"type": "object", "minProperties": 1},
        "artifact_manifest": {"type": "object", "minProperties": 1},
        "evidence_identifiers": {
            "type": "array", "minItems": 1, "items": {"type": "string", "minLength": 1}
        },
        "limitations": {
            "type": "array", "minItems": 1, "maxItems": 3,
            "items": {"type": "string", "minLength": 1},
        },
    }
    return json.dumps(
        {
            "type": "object",
            "additionalProperties": False,
            "required": list(properties),
            "properties": properties,
        },
        sort_keys=True,
    )


def _atomic_publish(output_relative: Path, content: str) -> None:
    guarded_relative = (
        Path(__file__).resolve().parents[2] / output_relative
    ).resolve().relative_to(Path(__file__).resolve().parents[2])
    output = Path(__file__).resolve().parents[2] / guarded_relative
    output.parent.mkdir(parents=True, exist_ok=True)
    if output.exists():
        raise _capture_error(_ERROR_OUTPUT_EXISTS)
    descriptor, temporary = tempfile.mkstemp(prefix=".capture-", dir=output.parent)
    temporary_relative = Path(temporary).resolve().relative_to(_WORKSPACE_ROOT)
    temporary_path = Path(__file__).resolve().parents[2] / temporary_relative
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            _ = handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            _ = os.link(temporary_path, output)
        except FileExistsError as error:
            raise _capture_error(_ERROR_OUTPUT_EXISTS) from error
    finally:
        _ = temporary_path.unlink(missing_ok=True)


def _contains_value(value: object, needle: str) -> bool:
    if isinstance(value, str):
        return needle in value
    mapping = _nested_mapping(value)
    if mapping is not None:
        return any(_contains_value(item, needle) for item in mapping.values())
    items = _nested_list(value)
    if items is not None:
        return any(_contains_value(item, needle) for item in items)
    return False


def _contains_sensitive(value: str) -> bool:
    return bool(_SENSITIVE_VALUE.search(value))


def _capture_error(message: str) -> CaptureError:
    return CaptureError(message)
def _object_hash(value: Mapping[str, object]) -> str:
    return sha256(
        json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode()
    ).hexdigest()


def _cases_sha256(cases: tuple[CaptureCase, ...]) -> str:
    payload = [
        {
            "scenario_id": case.scenario_id,
            "requirement": case.requirement,
            "input": case.input_text,
            "rubric": case.rubric,
            "decision_code": case.decision_code,
            "scientific_result": dict(case.scientific_result),
            "artifact_manifest": dict(case.artifact_manifest),
            "evidence_identifiers": list(case.evidence_identifiers),
            "limitations": list(case.limitations),
            "forbidden_sentinels": list(case.forbidden_sentinels),
        }
        for case in cases
    ]
    encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
    return sha256(encoded).hexdigest()




def _mapping(value: object, label: str) -> Mapping[str, object]:
    mapping = _nested_mapping(value)
    if mapping is None:
        message = f"{label} is malformed"
        raise _capture_error(message)
    return mapping


def _nested_mapping(value: object) -> Mapping[str, object] | None:
    if not isinstance(value, Mapping):
        return None
    mapping = cast("Mapping[object, object]", value)
    if not all(isinstance(key, str) for key in mapping):
        return None
    return cast("Mapping[str, object]", mapping)


def _list(value: object, label: str) -> list[object]:
    items = _nested_list(value)
    if items is None:
        message = f"{label} is malformed"
        raise _capture_error(message)
    return items


def _nested_list(value: object) -> list[object] | None:
    if not isinstance(value, list):
        return None
    return cast("list[object]", value)


def _text(value: object, label: str) -> str:
    if not isinstance(value, str):
        message = f"{label} is malformed"
        raise _capture_error(message)
    return value


class _CliArguments(argparse.Namespace):
    def __init__(self) -> None:
        super().__init__()
        self.cases: Path = Path()
        self.output: Path = Path()


def main() -> int:
    """Capture a profile from the command-line cases and output paths."""
    parser = argparse.ArgumentParser()
    _ = parser.add_argument("--cases", required=True, type=Path)
    _ = parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args(namespace=_CliArguments())
    cases = arguments.cases
    output = arguments.output
    try:
        _ = capture_profile(load_cases(cases), output)
    except CaptureError as error:
        parser.error(str(error))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
