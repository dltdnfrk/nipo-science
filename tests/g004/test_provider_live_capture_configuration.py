from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

import pytest
from services.api.provider_live_capture import CaptureError, capture_profile, load_cases

if TYPE_CHECKING:
    from collections.abc import Sequence

    from services.api.provider_live_capture_invocation import InvocationResult

_CASES = Path(__file__).parent / "fixtures" / "golden_session_cases.json"


class _ForbiddenInvocation:
    def run(self, argv: Sequence[str], timeout_seconds: int) -> InvocationResult:
        del argv, timeout_seconds
        raise AssertionError


def test_capture_requires_deployment_roots_without_checkout_fallback(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("PROVIDER_LIVE_CAPTURE_OUTPUT_ROOT", raising=False)
    monkeypatch.delenv("PROVIDER_LIVE_CAPTURE_SCRATCH_ROOT", raising=False)

    with pytest.raises(
        CaptureError,
        match="capture roots must be absolute owner-private directories",
    ):
        _ = capture_profile(
            load_cases(_CASES),
            tmp_path / "profile.json",
            _ForbiddenInvocation(),
        )


def test_capture_rejects_non_private_deployment_root_before_invocation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    output_root = tmp_path / "output"
    scratch_root = tmp_path / "scratch"
    output_root.mkdir(mode=0o700)
    scratch_root.mkdir(mode=0o700)
    output_root.chmod(0o755)
    monkeypatch.setenv("PROVIDER_LIVE_CAPTURE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("PROVIDER_LIVE_CAPTURE_SCRATCH_ROOT", str(scratch_root))

    with pytest.raises(
        CaptureError,
        match="capture roots must be absolute owner-private directories",
    ):
        _ = capture_profile(
            load_cases(_CASES),
            output_root / "profile.json",
            _ForbiddenInvocation(),
        )
