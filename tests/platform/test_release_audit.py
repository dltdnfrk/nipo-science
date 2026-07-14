from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError
from tools.platform_policy import ci_contract
from tools.platform_policy.release_audit import (
    ReleaseAuditRequest,
    build_incomplete_receipt,
    receipt_document,
    write_receipt,
)
from tools.platform_policy.release_contract import (
    NFR_REQUIREMENT_IDS,
    REQUIRED_EXTERNAL_CONTROL_IDS,
    ReleaseContractError,
    ReleaseReceipt,
    load_json_object,
)


@pytest.fixture(autouse=True)
def active_session(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("GJC_SESSION_ID", "active")


def workspace(tmp_path: Path) -> tuple[Path, Path]:
    root = tmp_path / "repo"
    science = root / "science-workbench"
    repository = Path(__file__).parents[2]
    (science / "docs/requirements").mkdir(parents=True)
    (root / "drylab").mkdir()
    (root / "ontologylab").mkdir()
    (root / ".gjc/_session-active/ultragoal").mkdir(parents=True)
    (science / ".ci").mkdir()
    _ = (science / ".ci/ci-contract.json").write_bytes(
        (repository / ".ci/ci-contract.json").read_bytes()
    )
    _ = (science / "docs/requirements/requirements.yaml").write_bytes(
        (repository / "docs/requirements/requirements.yaml").read_bytes()
    )
    _ = (science / "uv.lock").write_text("dependency authority\n")
    _ = (science / "pyproject.toml").write_text("[project]\nname = 'audit'\n")
    goals = root / ".gjc/_session-active/ultragoal/goals.json"
    _ = goals.write_text(
        '{"state_revision":7,"goals":['
        '{"id":"G001","status":"complete","title":"done","objective":"done","createdAt":"2026-07-14"},'
        '{"id":"G002","status":"pending","title":"later","objective":"later story","createdAt":"2026-07-14"}'
        "]}"
    )
    _ = (science / "tracked.txt").write_text("source")
    _ = (root / "drylab/tracked.txt").write_text("dry")
    _ = (root / "ontologylab/tracked.txt").write_text("ontology")
    return science, goals


def audit_request(science: Path) -> ReleaseAuditRequest:
    return ReleaseAuditRequest(
        workspace=science,
        release_id="G006",
        run_id="run",
        attempt_id="attempt",
    )


def test_audit_is_explicitly_incomplete_with_exact_inventory(tmp_path: Path) -> None:
    science, _goals = workspace(tmp_path)
    first = build_incomplete_receipt(audit_request(science))
    second = build_incomplete_receipt(audit_request(science))
    missing = set(first.missing_or_failed_controls)
    assert first.outcome == "incomplete"
    assert "ci-job:lint" in missing
    assert set(REQUIRED_EXTERNAL_CONTROL_IDS) <= missing
    assert {f"nfr-observation:{item}" for item in NFR_REQUIREMENT_IDS} <= missing
    assert {
        "cleanup",
        "manual-qa",
        "independent-code-review",
        "dual-visual-review",
    } <= missing
    assert "normative-requirement:F01" in missing
    assert "durable-goal:G002" in missing
    assert "durable-goal:G001" not in missing
    assert first.authority.session_id == "active"
    assert first.authority.lease_generation == str(first.authority.goals_state_revision)
    assert receipt_document(first) == receipt_document(second)
    assert {
        "absent-authority:fixture",
        "absent-authority:revision",
        "absent-authority:external-anchor",
        "dirty-source",
        "unverified-revision",
    } <= missing


def test_audit_rejects_wrong_workspace_requirements_and_malformed_goals(
    tmp_path: Path,
) -> None:
    science, goals = workspace(tmp_path)
    with pytest.raises(ValueError, match="canonical science-workbench"):
        _ = build_incomplete_receipt(audit_request(science.parent))
    wrong_requirements = science / "other.yaml"
    _ = wrong_requirements.write_text("{}")
    with pytest.raises(ValueError, match="requirements path"):
        _ = build_incomplete_receipt(
            ReleaseAuditRequest(
                workspace=science,
                release_id="G006",
                run_id="run",
                attempt_id="attempt",
                requirements_path=wrong_requirements,
            )
        )
    _ = goals.write_text('{"state_revision":7,"goals":[{"id":"G001"}]}')
    with pytest.raises(ReleaseContractError, match="malformed durable"):
        _ = build_incomplete_receipt(audit_request(science))
    goals.unlink()
    goals.symlink_to(science)
    with pytest.raises(ReleaseContractError, match="goals authority"):
        _ = build_incomplete_receipt(audit_request(science))


def test_audit_rejects_alternate_session_and_workspace_alias(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    science, goals = workspace(tmp_path)
    receipt = build_incomplete_receipt(audit_request(science))
    alternate = science.parent / ".gjc/_session-alternate/ultragoal"
    alternate.mkdir(parents=True)
    _ = (alternate / "goals.json").write_text(goals.read_text())
    monkeypatch.setenv("GJC_SESSION_ID", "alternate")
    with pytest.raises(ReleaseContractError, match="stale active session authority"):
        _ = write_receipt(
            receipt,
            science / "artifacts/ulw-g006/release.json",
            science / "artifacts/ulw-g006",
        )
    alternate_receipt = build_incomplete_receipt(audit_request(science))
    assert alternate_receipt.authority.goals_sha256 == receipt.authority.goals_sha256
    workspace_alias = tmp_path / "science-workbench"
    workspace_alias.symlink_to(science, target_is_directory=True)
    with pytest.raises(ValueError, match="canonical science-workbench"):
        _ = build_incomplete_receipt(audit_request(workspace_alias))


def test_write_rechecks_supervisor_selected_goals(tmp_path: Path) -> None:
    science, goals = workspace(tmp_path)
    receipt = build_incomplete_receipt(audit_request(science))
    _ = goals.write_text(
        '{"state_revision":8,"goals":['
        '{"id":"G001","status":"complete","title":"done","objective":"done","createdAt":"2026-07-14"},'
        '{"id":"G002","status":"pending","title":"later","objective":"later story","createdAt":"2026-07-14"},'
        '{"id":"G003","status":"pending","title":"new","objective":"new story","createdAt":"2026-07-14"}'
        "]}"
    )
    with pytest.raises(ReleaseContractError, match="stale goals authority"):
        _ = write_receipt(
            receipt,
            science / "artifacts/ulw-g006/release.json",
            science / "artifacts/ulw-g006",
        )


def test_audit_includes_later_goals_and_absent_authorities(tmp_path: Path) -> None:
    science, goals = workspace(tmp_path)
    _ = (science / "uv.lock").unlink()
    _ = (science / "pyproject.toml").unlink()
    _ = goals.write_text(
        '{"state_revision":8,"goals":['
        '{"id":"G001","status":"complete","title":"done","objective":"done","createdAt":"2026-07-14"},'
        '{"id":"G002","status":"pending","title":"later","objective":"later story","createdAt":"2026-07-14"},'
        '{"id":"G003","status":"blocked","title":"later","objective":"later story","createdAt":"2026-07-14"}'
        "]}"
    )
    missing = set(
        build_incomplete_receipt(audit_request(science)).missing_or_failed_controls
    )
    assert {
        "absent-authority:dependency",
        "absent-authority:fixture",
        "absent-authority:toolchain",
        "absent-authority:revision",
        "absent-authority:external-anchor",
        "durable-goal:G002",
        "durable-goal:G003",
    } <= missing


def test_receipt_write_is_confined_and_non_overwriting(tmp_path: Path) -> None:
    science, _goals = workspace(tmp_path)
    receipt = build_incomplete_receipt(audit_request(science))
    artifacts = science / "artifacts" / "ulw-g006"
    destination = artifacts / "release.json"
    assert write_receipt(receipt, destination, artifacts) == destination
    payload = load_json_object(destination)
    receipt_payload = payload.get("receipt")
    assert isinstance(receipt_payload, dict)
    assert receipt_payload.get("outcome") == "incomplete"
    with pytest.raises(ValueError, match="artifact root"):
        _ = write_receipt(receipt, destination, science / "artifacts" / "wrong")
    with pytest.raises(ValueError, match="artifact path must remain"):
        _ = write_receipt(receipt, tmp_path / "outside.json", artifacts)
    with pytest.raises(FileExistsError):
        _ = write_receipt(receipt, destination, artifacts)
    with pytest.raises(ValueError, match="direct child"):
        _ = write_receipt(receipt, artifacts / "nested/release.json", artifacts)
    outside = tmp_path / "outside-hardlink.json"
    _ = outside.write_text("preserve")
    hardlink = artifacts / "hardlink.json"
    os.link(outside, hardlink)
    with pytest.raises(FileExistsError):
        _ = write_receipt(receipt, hardlink, artifacts)
    assert outside.read_text() == "preserve"
    hardlink.unlink()
    fifo = artifacts / "fifo.json"
    os.mkfifo(fifo)
    with pytest.raises(FileExistsError):
        _ = write_receipt(receipt, fifo, artifacts)


@pytest.mark.parametrize("path", ["tracked.txt", "../drylab/tracked.txt"])
def test_write_rejects_current_source_or_sibling_drift(
    tmp_path: Path, path: str
) -> None:
    science, _goals = workspace(tmp_path)
    receipt = build_incomplete_receipt(audit_request(science))
    target = (
        science / path
        if not path.startswith("..")
        else science.parent / "drylab/tracked.txt"
    )
    _ = target.write_text("drift")
    with pytest.raises(ReleaseContractError, match="stale receipt authority"):
        _ = write_receipt(
            receipt,
            science / "artifacts/ulw-g006/release.json",
            science / "artifacts/ulw-g006",
        )


def test_write_rejects_artifact_topology_mutation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    science, _goals = workspace(tmp_path)
    receipt = build_incomplete_receipt(audit_request(science))
    artifacts = science / "artifacts/ulw-g006"
    original = ci_contract.write_confined_file

    def mutate(directory_fd: int, name: str, content: bytes) -> None:
        original(directory_fd, name, content)
        _ = (artifacts / "unexpected.json").write_text("mutation")

    monkeypatch.setattr(ci_contract, "write_confined_file", mutate)
    with pytest.raises(ReleaseContractError, match="artifact topology changed"):
        _ = write_receipt(receipt, artifacts / "release.json", artifacts)


def test_write_rejects_post_create_tampering(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    science, _goals = workspace(tmp_path)
    receipt = build_incomplete_receipt(audit_request(science))
    artifacts = science / "artifacts/ulw-g006"
    original = ci_contract.write_confined_file

    def tamper(directory_fd: int, name: str, content: bytes) -> None:
        original(directory_fd, name, content)
        _ = (artifacts / name).write_text("tampered")

    monkeypatch.setattr(ci_contract, "write_confined_file", tamper)
    with pytest.raises(
        ReleaseContractError, match="receipt artifact changed during write"
    ):
        _ = write_receipt(receipt, artifacts / "release.json", artifacts)


def test_audit_success_copy_cannot_round_trip_as_receipt(tmp_path: Path) -> None:
    science, _goals = workspace(tmp_path)
    incomplete = build_incomplete_receipt(audit_request(science))
    copied = incomplete.model_copy(update={"outcome": "success"})
    with pytest.raises(ValidationError, match=r"failure.*incomplete"):
        _ = ReleaseReceipt.model_validate(copied.model_dump())
