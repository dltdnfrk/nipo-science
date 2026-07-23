from __future__ import annotations

import re
import struct
import zlib
from concurrent.futures import ThreadPoolExecutor
from contextlib import suppress
from datetime import UTC, datetime, timedelta
from threading import Barrier, BrokenBarrierError
from typing import TYPE_CHECKING

import pytest

from science_workbench_science.research_intent import (
    ResearchIntent,
    research_intent_from_mapping,
)
from science_workbench_science.vertical import DryLabVertical, FixtureFailure

if TYPE_CHECKING:
    from collections.abc import Callable
CSV = "sample,value,calibration\nA,1.25,fixture-cal-1\nB,2.5,fixture-cal-1\n"


def _intent() -> ResearchIntent:
    return research_intent_from_mapping(
        {
            "question": "보정된 관측값을 재현 가능하게 정규화할 수 있는가?",
            "rationale": "반복 분석에서 입력 순서가 결과를 바꾸지 않도록 확인한다.",
            "intended_benefit": "검증 가능한 정규화 기준선을 만든다.",
            "success_criteria": ["동일 입력은 동일 체크섬을 만든다."],
            "constraints": ["비임상 연구 데이터만 사용한다."],
            "stop_conditions": ["보정 메타데이터가 없으면 중단한다."],
            "research_mode": "bounded_agentic",
            "data_origin": "observed",
        }
    )


def _executed() -> DryLabVertical:
    vertical = DryLabVertical()
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())
    approval = vertical.approve(plan.digest)
    _ = vertical.execute(approval.token)
    return vertical


def _malformed_upload(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", "sample,value\nA,1.0\n")


def _missing_calibration(vertical: DryLabVertical) -> None:
    _ = vertical.upload(
        "calibrated.csv",
        "sample,value,calibration\nA,1.0,\n",
    )


def _unsafe_filename(vertical: DryLabVertical) -> None:
    _ = vertical.upload("../calibrated.csv", CSV)


def _egress_request(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", CSV, request="network egress")


def _package_install_request(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", CSV, request="pip install package")


def _stale_lease(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", CSV)
    _ = vertical.create_plan(research_intent=_intent(), lease_id="stale")


def _infinite_value(vertical: DryLabVertical) -> None:
    _ = vertical.upload(
        "calibrated.csv",
        "sample,value,calibration\nA,inf,fixture-cal-1\n",
    )


def _nan_value(vertical: DryLabVertical) -> None:
    _ = vertical.upload(
        "calibrated.csv",
        "sample,value,calibration\nA,nan,fixture-cal-1\n",
    )


def _approval_replay(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())
    approval = vertical.approve(plan.digest)
    _ = vertical.execute(approval.token)
    _ = vertical.execute(approval.token)


def _cancel_before_execution(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())
    approval = vertical.approve(plan.digest)
    _ = vertical.execute(approval.token, request="cancel")


def _kernel_loss_before_execution(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())
    approval = vertical.approve(plan.digest)
    _ = vertical.execute(approval.token, request="kernel loss")


@pytest.mark.parametrize("plan_digest", ["", "not-the-current-plan", "계획"])
def test_approve_requires_exact_plan_digest(plan_digest: str) -> None:
    vertical = DryLabVertical()
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())

    with pytest.raises(FixtureFailure, match=r"^approval-plan-mismatch$"):
        _ = vertical.approve(plan_digest)

    assert vertical.approve(plan.digest).plan_digest == plan.digest


@pytest.mark.parametrize(
    ("request_text", "code"),
    [
        ("cancel", "cancelled-before-execution"),
        ("kernel loss", "kernel-lost-before-execution"),
    ],
)
def test_cancel_and_kernel_loss_consume_the_one_use_approval(
    request_text: str, code: str
) -> None:
    vertical = DryLabVertical()
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())
    approval = vertical.approve(plan.digest)

    with pytest.raises(FixtureFailure, match=rf"^{code}$"):
        _ = vertical.execute(approval.token, request=request_text)
    with pytest.raises(FixtureFailure, match=r"^approval-replayed$"):
        _ = vertical.execute(approval.token)

    assert vertical.read_projection()["artifacts"] == []


def test_equivalent_runs_have_pinned_deterministic_outputs_and_cleanup() -> None:
    first = _executed()
    second = _executed()

    first_state = first.read_projection()
    second_state = second.read_projection()
    plan_digest = first_state["plan_digest"]
    assert plan_digest is not None
    assert [item["sha256"] for item in first_state["artifacts"]] == [
        item["sha256"] for item in second_state["artifacts"]
    ]
    assert {item["category"] for item in first_state["artifacts"]} == {
        "normalized-csv",
        "png-preview",
        "markdown-report",
        "evidence-ledger",
        "provenance",
    }
    png = first.read_artifact("preview.png")
    assert png is not None
    assert png.startswith(b"\x89PNG\r\n\x1a\n")
    decoded = zlib.decompress(png[41:-12])
    assert len(set(decoded)) > 8
    assert struct.unpack(">II", png[16:24]) == (320, 180)

    review = first.review()
    receipt = first.export()
    cleanup = first.cleanup()
    assert review.verified
    assert receipt.action_plan_digest == plan_digest
    assert receipt.review_pins == review.pinned_hashes
    assert cleanup.removed_runtime_data
    assert cleanup.preserved_artifact_hashes == tuple(
        item["sha256"] for item in first_state["artifacts"]
    )
    assert first.read_projection()["child_succeeded"]
    cleaned_state = first.read_projection()
    assert cleaned_state["stage"] == "cleanup"
    assert cleaned_state["plan_digest"] is None
    assert first._upload is None  # pyright: ignore[reportPrivateUsage]
    assert first._plan is None  # pyright: ignore[reportPrivateUsage]
    assert first._approval is None  # pyright: ignore[reportPrivateUsage]
    assert first.read_artifact("normalized.csv") is not None


def test_reject_and_cancel_are_terminal_without_execution_side_effects() -> None:
    rejected = DryLabVertical()
    _ = rejected.upload("calibrated.csv", CSV)
    _ = rejected.create_plan(research_intent=_intent())
    rejected.reject()

    assert rejected.read_projection()["stage"] == "reject"
    assert rejected.read_projection()["artifacts"] == []
    with pytest.raises(FixtureFailure, match=r"^invalid-order$"):
        _ = rejected.execute()

    cancelled = DryLabVertical()
    _ = cancelled.upload("calibrated.csv", CSV)
    plan = cancelled.create_plan(research_intent=_intent())
    approval = cancelled.approve(plan.digest)
    cancelled.cancel()

    assert cancelled.read_projection()["stage"] == "cancel"
    assert cancelled.read_projection()["artifacts"] == []
    with pytest.raises(FixtureFailure, match=r"^invalid-order$"):
        _ = cancelled.execute(approval.token)


def test_approval_expires_from_the_authoritative_clock() -> None:
    now = [datetime(2026, 7, 16, 1, 0, tzinfo=UTC)]
    vertical = DryLabVertical(lambda: now[0])
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())
    approval = vertical.approve(plan.digest)

    assert approval.expires_at == now[0] + timedelta(minutes=10)
    assert vertical.read_projection()["approval_expires_at"] == (
        "2026-07-16T01:10:00Z"
    )

    now[0] += timedelta(minutes=10)

    assert vertical.read_projection()["stage"] == "expire"
    with pytest.raises(FixtureFailure, match=r"^approval-expired$"):
        _ = vertical.execute(approval.token)
    assert vertical.read_projection()["artifacts"] == []


@pytest.mark.parametrize(
    ("operation", "code", "expected_artifact_count"),
    [
        (_malformed_upload, "malformed-csv", 0),
        (_missing_calibration, "missing-calibration", 0),
        (_unsafe_filename, "unsafe-filename", 0),
        (_infinite_value, "nonfinite-data", 0),
        (_nan_value, "nonfinite-data", 0),
        (_egress_request, "egress-requested", 0),
        (_package_install_request, "package-install-requested", 0),
        (_stale_lease, "stale-lease", 0),
        (_cancel_before_execution, "cancelled-before-execution", 0),
        (_kernel_loss_before_execution, "kernel-lost-before-execution", 0),
        (_approval_replay, "approval-replayed", 5),
    ],
)
def test_failures_stop_without_execution_artifacts(
    operation: Callable[[DryLabVertical], object],
    code: str,
    expected_artifact_count: int,
) -> None:
    vertical = DryLabVertical()
    with pytest.raises(FixtureFailure, match=rf"^{re.escape(code)}$"):
        _ = operation(vertical)
    assert len(vertical.read_projection()["artifacts"]) == expected_artifact_count
    assert vertical.read_projection()["child_succeeded"] is (
        expected_artifact_count == 5
    )


def test_approval_replay_has_no_second_execution_or_retry() -> None:
    vertical = DryLabVertical()
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())
    approval = vertical.approve(plan.digest)
    _ = vertical.execute(approval.token)
    hashes = vertical.read_projection()["artifacts"]
    with pytest.raises(FixtureFailure, match=r"^approval-replayed$"):
        _ = vertical.execute(approval.token)
    assert vertical.read_projection()["artifacts"] == hashes


@pytest.mark.parametrize("approval_token", [None, "", "not-the-approved-token", "토큰"])
def test_execute_requires_the_exact_non_empty_approval_token_without_consuming_it(
    approval_token: str | None,
) -> None:
    """Reject every absent or invalid token while preserving the valid approval."""
    vertical = DryLabVertical()
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())
    approval = vertical.approve(plan.digest)

    with pytest.raises(FixtureFailure, match=r"^approval-token-mismatch$"):
        _ = vertical.execute(approval_token)

    assert vertical.read_projection()["artifacts"] == []
    assert vertical.execute(approval.token).child_succeeded


def test_concurrent_execute_claims_the_one_use_approval_exactly_once(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Permit one of two synchronized callers and reject the other as replay."""
    vertical = DryLabVertical()
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan(research_intent=_intent())
    approval = vertical.approve(plan.digest)
    barrier = Barrier(2)
    reject_request = vertical._reject_request  # pyright: ignore[reportPrivateUsage]

    def synchronize_before_claim(request: str) -> None:
        with suppress(BrokenBarrierError):
            _ = barrier.wait(timeout=0.25)
        reject_request(request)

    monkeypatch.setattr(vertical, "_reject_request", synchronize_before_claim)

    def execute(worker_index: int) -> str:
        del worker_index
        try:
            _ = vertical.execute(approval.token)
        except FixtureFailure as error:
            return error.code
        return "success"

    with ThreadPoolExecutor(max_workers=2) as executor:
        outcomes = sorted(executor.map(execute, range(2)))

    assert outcomes == ["approval-replayed", "success"]
    assert len(vertical.read_projection()["artifacts"]) == 5
