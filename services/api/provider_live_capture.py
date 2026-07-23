"""Backward-compatible façade for live OpenAI Codex qualification capture."""

from __future__ import annotations

import anyio as _anyio

from services.api import provider_live_capture_cases as _cases
from services.api import provider_live_capture_errors as _errors
from services.api import provider_live_capture_invocation as _invocation
from services.api import provider_live_capture_qualification as _qualification
from services.api import provider_live_capture_runtime_policy as _runtime_policy
from services.api import provider_live_capture_sandbox as _sandbox
from services.api import provider_live_capture_schema as _schema
from services.api import provider_live_capture_service as _service
from services.api.provider_live_capture_cli import run_cli

anyio = _anyio
CaptureCase = _cases.CaptureCase
CaptureError = _errors.CaptureError
CodexBinaryPolicy = _sandbox.CodexBinaryPolicy
CodexCliInvocation = _invocation.CodexCliInvocation
CodexInvocation = _invocation.CodexInvocation
InvocationResult = _invocation.InvocationResult
QualificationAdoptionSnapshot = _qualification.QualificationAdoptionSnapshot
QualificationCaptureAuthority = _service.QualificationCaptureAuthority
RuntimeQualificationTarget = _qualification.RuntimeQualificationTarget
ApprovedRuntimePolicy = _runtime_policy.ApprovedRuntimePolicy
adopt_live_qualification = _qualification.adopt_live_qualification
capture_and_record_runtime_qualification = (
    _qualification.capture_and_record_runtime_qualification
)
capture_live_qualification = _qualification.capture_live_qualification
capture_profile = _service.capture_profile
load_approved_runtime_policy = _runtime_policy.load_approved_runtime_policy
load_cases = _cases.load_cases
_require_valid_adoption_target = _qualification.require_valid_adoption_target
_response_schema = _schema.response_schema
_run_process = _invocation.run_process


def main() -> int:
    """Capture a profile from the command-line cases and output paths."""
    return run_cli(load_approved_runtime_policy)


if __name__ == "__main__":
    raise SystemExit(main())
