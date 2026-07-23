"""Profile capture orchestration over admitted cases and invocation boundaries."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from hashlib import sha256
from pathlib import Path
from typing import TYPE_CHECKING, Final

from services.api.provider_live_capture_boundary import (
    contains_sensitive,
)
from services.api.provider_live_capture_cases import CaptureCase, cases_sha256
from services.api.provider_live_capture_errors import (
    ERROR_BINARY_INVALID,
    ERROR_BINARY_POLICY,
    ERROR_CASES_INVALID,
    ERROR_LIVE_QUALIFICATION,
    ERROR_OUTPUT_EXISTS,
    ERROR_TEMPORARY_CLEANUP,
    ERROR_VERSION_INVALID,
    capture_error,
)
from services.api.provider_live_capture_invocation import (
    CodexCliInvocation,
    CodexInvocation,
)
from services.api.provider_live_capture_protocol import (
    exec_argv,
    read_final,
    require_official_login,
    run_codex,
    validate_attempt,
)
from services.api.provider_live_capture_sandbox import (
    CodexBinaryPolicy,
    prepare_private_cache_root,
    staged_executable,
)
from services.api.provider_live_capture_schema import response_schema
from services.api.provider_live_capture_storage import (
    CaptureRoots,
    CaptureTargetInput,
    atomic_publish,
    resolve_capture_target,
)
from services.api.provider_qualification import (
    CANONICAL_CASES_SHA256,
    parse_profile_json,
    qualification_claim,
)

if TYPE_CHECKING:
    from services.api.provider_qualification_receipt import (
        QualificationReceipt,
        QualificationReceiptIssuer,
        QualificationReceiptSubject,
        QualificationReceiptVerifier,
    )

_ATTEMPTS: Final = 3
_MAX_VERSION_TEXT: Final = 256
_MAX_VERSION_PARTS: Final = 2


@dataclass(frozen=True, slots=True)
class _CaptureRuntimeEvidence:
    production_capture: bool
    operator_account_ref: str | None
    executable_sha256: str
    expected_runtime_version: str | None


@dataclass(frozen=True, slots=True)
class QualificationCaptureAuthority:
    """External issuer and public verifier scoped to one connection revision."""

    subject: QualificationReceiptSubject
    issuer: QualificationReceiptIssuer
    verifier: QualificationReceiptVerifier


@dataclass(frozen=True, slots=True)
class _CaptureExecutionContext:
    runner: CodexInvocation
    evidence: _CaptureRuntimeEvidence
    authority: QualificationCaptureAuthority | None


@dataclass(frozen=True, slots=True)
class _CaseExecution:
    runner: CodexInvocation
    base: Path
    schema_path: Path


def capture_profile(
    cases: tuple[CaptureCase, ...],
    target: CaptureTargetInput,
    invocation: CodexInvocation | None = None,
    *,
    policy: CodexBinaryPolicy | None = None,
    authority: QualificationCaptureAuthority | None = None,
) -> QualificationReceipt | None:
    """Capture 30 attempts and request external authority for live evidence."""
    resolved_target = resolve_capture_target(target)
    output = resolved_target.output
    if output.exists():
        raise capture_error(ERROR_OUTPUT_EXISTS)
    if cases_sha256(cases) != CANONICAL_CASES_SHA256:
        raise capture_error(ERROR_CASES_INVALID)
    if invocation is None:
        if policy is None:
            raise capture_error(ERROR_BINARY_POLICY)
        if authority is None:
            raise capture_error(ERROR_LIVE_QUALIFICATION)
        with staged_executable(policy, resolved_target.roots.scratch) as executable:
            return _capture_profile_with_runner(
                cases,
                output,
                resolved_target.roots,
                _CaptureExecutionContext(
                    CodexCliInvocation(
                        policy,
                        scratch_root=resolved_target.roots.scratch,
                        _pinned_executable=executable,
                    ),
                    _CaptureRuntimeEvidence(
                        production_capture=True,
                        operator_account_ref=policy.operator_account_ref,
                        executable_sha256=policy.expected_sha256,
                        expected_runtime_version=policy.expected_runtime_version,
                    ),
                    authority,
                ),
            )
    if policy is not None:
        raise capture_error(ERROR_BINARY_INVALID)
    return _capture_profile_with_runner(
        cases,
        output,
        resolved_target.roots,
        _CaptureExecutionContext(
            invocation,
            _CaptureRuntimeEvidence(
                production_capture=False,
                operator_account_ref=None,
                executable_sha256=sha256(b"synthetic_contract_fixture").hexdigest(),
                expected_runtime_version=None,
            ),
            None,
        ),
    )


def _capture_profile_with_runner(
    cases: tuple[CaptureCase, ...],
    output: Path,
    roots: CaptureRoots,
    context: _CaptureExecutionContext,
) -> QualificationReceipt | None:
    login = run_codex(
        context.runner,
        ("codex", "login", "status"),
        "login status",
    )
    require_official_login(login)
    operator_account_ref = context.evidence.operator_account_ref
    if operator_account_ref is None:
        operator_account_ref = (
            "acct_synthetic_" + sha256(login.stderr.encode()).hexdigest()
        )
    version = run_codex(
        context.runner,
        ("codex", "--version"),
        "version",
    ).stdout.strip()
    if not version or len(version) > _MAX_VERSION_TEXT or contains_sensitive(version):
        raise capture_error(ERROR_VERSION_INVALID)
    runtime_version = _runtime_version_ref(version)
    if (
        context.evidence.expected_runtime_version is not None
        and runtime_version != context.evidence.expected_runtime_version
    ):
        raise capture_error(ERROR_VERSION_INVALID)
    profile = {
        "evidence_kind": (
            "captured_live_profile"
            if context.evidence.production_capture
            else "synthetic_contract_fixture"
        ),
        "adapter": "openai_codex",
        "oauth": {"mode": "official_subscription_oauth", "provider": "openai"},
        "runtime_version": runtime_version,
        "executable_sha256": context.evidence.executable_sha256,
        "operator_account_ref": operator_account_ref,
        "sessions": _capture_sessions(cases, context.runner, roots.scratch),
        "cleanup": {"terminal": True, "redaction_complete": True},
    }
    serialized = json.dumps(profile, sort_keys=True, separators=(",", ":")) + "\n"
    atomic_publish(roots, output, serialized)
    if not context.evidence.production_capture:
        return None
    if context.authority is None:
        raise capture_error(ERROR_LIVE_QUALIFICATION)
    observation = parse_profile_json(serialized)
    return context.authority.issuer.issue(
        qualification_claim(observation, context.authority.subject)
    )


def _capture_sessions(
    cases: tuple[CaptureCase, ...],
    runner: CodexInvocation,
    scratch_root: Path,
) -> list[dict[str, object]]:
    sessions: list[dict[str, object]] = []
    try:
        scratch_root = prepare_private_cache_root(scratch_root)
        with tempfile.TemporaryDirectory(
            prefix="codex-live-capture-", dir=scratch_root
        ) as directory:
            base = Path(directory)
            sessions.extend(_capture_case(case, runner, base) for case in cases)
    except OSError as error:
        raise capture_error(ERROR_TEMPORARY_CLEANUP) from error
    return sessions


def _capture_case(
    case: CaptureCase,
    runner: CodexInvocation,
    base: Path,
) -> dict[str, object]:
    schema_path = base / f"{case.scenario_id}-response-schema.json"
    _ = schema_path.write_text(response_schema(case), encoding="utf-8")
    execution = _CaseExecution(runner, base, schema_path)
    attempts = [
        _capture_attempt(case, number, execution) for number in range(1, _ATTEMPTS + 1)
    ]
    return {"scenario_id": case.scenario_id, "attempts": attempts}


def _capture_attempt(
    case: CaptureCase,
    number: int,
    execution: _CaseExecution,
) -> dict[str, object]:
    last_message = execution.base / f"{case.scenario_id}-{number}.json"
    result = run_codex(
        execution.runner,
        exec_argv(case, execution.schema_path, last_message),
        "qualification attempt",
    )
    final = read_final(last_message, result.stdout)
    return validate_attempt(case, number, result.stdout, final)


def _runtime_version_ref(value: str) -> str:
    parts = value.split()
    if len(parts) != _MAX_VERSION_PARTS or parts[0] != "codex-cli":
        raise capture_error(ERROR_VERSION_INVALID)
    return "-".join(parts)
