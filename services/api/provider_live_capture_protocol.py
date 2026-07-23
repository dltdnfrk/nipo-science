"""Closed response schema and Codex event protocol validation."""

from __future__ import annotations

import json
import stat
from typing import TYPE_CHECKING, Final

from services.api.provider_live_capture_boundary import (
    contains_sensitive,
    contains_value,
    decode_external_json,
    mapping,
    nested_mapping,
    object_hash,
    read_bounded_external_json,
    text,
)
from services.api.provider_live_capture_cases import (
    CaptureCase,
    case_object,
    case_strings,
)
from services.api.provider_live_capture_errors import (
    ERROR_FINAL_LIMIT,
    ERROR_FORBIDDEN_CONTENT,
    ERROR_OFFICIAL_LOGIN,
    ERROR_OUTPUT_ENCODING,
    ERROR_OUTPUT_LIMIT,
    ERROR_PROTOCOL_FAILED,
    ERROR_PROTOCOL_INCOMPLETE,
    ERROR_PROTOCOL_MALFORMED,
    ERROR_RESPONSE_MALFORMED,
    ERROR_SAFETY_VALIDATION,
    ERROR_SENSITIVE_OUTPUT,
    CaptureError,
    capture_error,
)

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from services.api.provider_live_capture_invocation import (
        CodexInvocation,
        InvocationResult,
    )

_TIMEOUT_SECONDS: Final = 90
_MAX_FINAL_BYTES: Final = 256 * 1024
_MAX_STDOUT_BYTES: Final = 8 * 1024 * 1024
_MAX_EMBEDDED_OBJECT_BYTES: Final = 64 * 1024
_PROMPT_INSTRUCTION: Final = (
    "Return only the structured response required by the output schema. Encode "
    "scientific_result and artifact_manifest as JSON object strings. Perform "
    "research-only, non-clinical analysis."
)


def exec_argv(
    case: CaptureCase,
    schema: Path,
    last_message: Path,
) -> tuple[str, ...]:
    """Build the isolated argv contract for one qualification attempt."""
    prompt = json.dumps(
        {
            "scenario_id": case.scenario_id,
            "requirement": case.requirement,
            "input": case.input_text,
            "rubric": case.rubric,
            "instruction": _PROMPT_INSTRUCTION,
        },
        sort_keys=True,
    )
    return (
        "codex",
        "exec",
        "--ignore-user-config",
        "--ignore-rules",
        "--ephemeral",
        "--sandbox",
        "read-only",
        "--json",
        "--output-schema",
        str(schema),
        "--output-last-message",
        str(last_message),
        "--skip-git-repo-check",
        prompt,
    )


def run_codex(
    runner: CodexInvocation,
    argv: tuple[str, ...],
    purpose: str,
) -> InvocationResult:
    """Normalize one successful Codex protocol invocation or fail closed."""
    result = runner.run(argv, _TIMEOUT_SECONDS)
    if result.output_limited:
        raise capture_error(ERROR_OUTPUT_LIMIT)
    if result.decode_failed:
        raise capture_error(ERROR_OUTPUT_ENCODING)
    if result.timed_out or result.returncode != 0:
        message = f"codex {purpose} failed"
        raise capture_error(message)
    if contains_sensitive(result.stderr):
        raise capture_error(ERROR_SENSITIVE_OUTPUT)
    return result


def require_official_login(result: InvocationResult) -> None:
    """Admit only the exact official ChatGPT login-status contract."""
    status = result.stderr.strip()
    if (
        result.stdout
        or status != "Logged in using ChatGPT"
        or contains_sensitive(status)
    ):
        raise capture_error(ERROR_OFFICIAL_LOGIN)


def read_final(path: Path, stream: str) -> object:
    """Read a bounded regular final-response file after stream redaction checks."""
    if contains_sensitive(stream):
        raise capture_error(ERROR_SENSITIVE_OUTPUT)
    try:
        final_stat = path.lstat()
        if (
            not stat.S_ISREG(final_stat.st_mode)
            or stat.S_ISLNK(final_stat.st_mode)
            or final_stat.st_size > _MAX_FINAL_BYTES
        ):
            raise capture_error(ERROR_FINAL_LIMIT)
        return read_bounded_external_json(
            path,
            maximum_bytes=_MAX_FINAL_BYTES,
            error_message=ERROR_RESPONSE_MALFORMED,
        )
    except CaptureError:
        raise
    except OSError as error:
        raise capture_error(ERROR_RESPONSE_MALFORMED) from error


def validate_attempt(
    case: CaptureCase,
    number: int,
    stream: str,
    final: object,
) -> dict[str, object]:
    """Validate one final response and return its normalized evidence record."""
    forbidden = any(
        sentinel in stream or contains_value(final, sentinel)
        for sentinel in case.forbidden_sentinels
    )
    if forbidden:
        raise capture_error(ERROR_FORBIDDEN_CONTENT)
    events = _parse_events(stream)
    response = mapping(final, "response")
    scientific = _response_object(
        response.get("scientific_result"),
        "response.scientific_result",
    )
    artifact = _response_object(
        response.get("artifact_manifest"),
        "response.artifact_manifest",
    )
    evidence = case_strings(
        response.get("evidence_identifiers"),
        "response.evidence_identifiers",
    )
    limitations = case_strings(
        response.get("limitations"),
        "response.limitations",
    )
    decision = text(response.get("decision_code"), "response.decision_code")
    _validate_response(
        case,
        response,
        decision,
        scientific,
        artifact,
        evidence,
        limitations,
    )
    return {
        "attempt_id": f"{case.scenario_id}-{number}",
        "events": [{"kind": kind} for kind in events],
        "decision_code": decision,
        "scientific_result": scientific,
        "artifact_manifest": artifact,
        "evidence_identifiers": list(evidence),
        "limitations": list(limitations),
        "scientific_hash": object_hash(scientific),
        "artifact_hash": object_hash(artifact),
    }


def _validate_response(
    case: CaptureCase,
    response: Mapping[str, object],
    decision: str,
    scientific: Mapping[str, object],
    artifact: Mapping[str, object],
    evidence: tuple[str, ...],
    limitations: tuple[str, ...],
) -> None:
    required = {
        "scenario_id",
        "decision_code",
        "scientific_result",
        "artifact_manifest",
        "evidence_identifiers",
        "limitations",
    }
    if set(response) != required:
        raise capture_error(ERROR_RESPONSE_MALFORMED)
    if (
        response.get("scenario_id") != case.scenario_id
        or decision != case.decision_code
        or object_hash(scientific) != object_hash(case.scientific_result)
        or object_hash(artifact) != object_hash(case.artifact_manifest)
        or evidence != case.evidence_identifiers
        or limitations != case.limitations
        or contains_sensitive(json.dumps(response, sort_keys=True))
    ):
        raise capture_error(ERROR_SAFETY_VALIDATION)


def _response_object(value: object, label: str) -> Mapping[str, object]:
    encoded = text(value, label)
    try:
        decoded = decode_external_json(
            encoded.encode(),
            maximum_bytes=_MAX_EMBEDDED_OBJECT_BYTES,
            error_message=ERROR_RESPONSE_MALFORMED,
        )
    except UnicodeEncodeError as error:
        raise capture_error(ERROR_RESPONSE_MALFORMED) from error
    return case_object(decoded, label)


def _parse_events(stream: str) -> tuple[str, ...]:
    seen = {"thread": False, "turn": False, "terminal": False, "delta": False}
    normalized: list[str] = []
    for line in stream.splitlines():
        event = _parse_event(line)
        _record_event(event, text(event.get("type"), "event.type"), seen, normalized)
    if not all(seen.values()):
        raise capture_error(ERROR_PROTOCOL_INCOMPLETE)
    return tuple(normalized)


def _parse_event(line: str) -> Mapping[str, object]:
    try:
        return mapping(
            decode_external_json(
                line.encode(),
                maximum_bytes=_MAX_STDOUT_BYTES,
                error_message=ERROR_PROTOCOL_MALFORMED,
            ),
            "event",
        )
    except (UnicodeEncodeError, CaptureError) as error:
        raise capture_error(ERROR_PROTOCOL_MALFORMED) from error


def _record_event(
    event: Mapping[str, object],
    event_type: str,
    seen: dict[str, bool],
    normalized: list[str],
) -> None:
    if "error" in event_type or "failed" in event_type:
        raise capture_error(ERROR_PROTOCOL_FAILED)
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
    item = nested_mapping(event.get("item"))
    return item is not None and item.get("type") in {
        "agent_message",
        "assistant_message",
    }
