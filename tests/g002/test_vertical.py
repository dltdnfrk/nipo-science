from __future__ import annotations

import re
import struct
import zlib
from typing import TYPE_CHECKING

import pytest

from science_workbench_science.vertical import DryLabVertical, FixtureFailure

if TYPE_CHECKING:
    from collections.abc import Callable
CSV = "sample,value,calibration\nA,1.25,fixture-cal-1\nB,2.5,fixture-cal-1\n"


def _executed() -> DryLabVertical:
    vertical = DryLabVertical()
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan()
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
    _ = vertical.create_plan(lease_id="stale")


def _approval_replay(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan()
    approval = vertical.approve(plan.digest)
    _ = vertical.execute(approval.token)
    _ = vertical.execute(approval.token)


def _cancel_before_execution(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan()
    approval = vertical.approve(plan.digest)
    _ = vertical.execute(approval.token, request="cancel")


def _kernel_loss_before_execution(vertical: DryLabVertical) -> None:
    _ = vertical.upload("calibrated.csv", CSV)
    plan = vertical.create_plan()
    approval = vertical.approve(plan.digest)
    _ = vertical.execute(approval.token, request="kernel loss")



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
    assert zlib.decompress(png[41:-12]) != b"\x00" * 14
    assert struct.unpack(">II", png[16:24]) == (2, 2)

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


@pytest.mark.parametrize(
    ("operation", "code", "expected_artifact_count"),
    [
        (_malformed_upload, "malformed-csv", 0),
        (_missing_calibration, "missing-calibration", 0),
        (_unsafe_filename, "unsafe-filename", 0),
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
    plan = vertical.create_plan()
    approval = vertical.approve(plan.digest)
    _ = vertical.execute(approval.token)
    hashes = vertical.read_projection()["artifacts"]
    with pytest.raises(FixtureFailure, match=r"^approval-replayed$"):
        _ = vertical.execute(approval.token)
    assert vertical.read_projection()["artifacts"] == hashes
