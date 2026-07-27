"""SPEC-v0.5 section 15 clean-machine chain driver.

Runs the complete local chain outside any test fixture, from a real
measurement file on disk to an independently verified Export Pack, inside a
fresh data root: measurement file -> typed loader -> ResearchIntent ->
immutable ActionPlan + one-use approval -> deterministic in-process execution
-> four immutable Artifact Versions -> provenance recomputation -> trace-only
Review -> Export Pack -> verification from the extracted bytes alone.

Determinism is observed by running the produce stage in three separate
interpreter processes with distinct PYTHONHASHSEED values and comparing every
recorded digest. Invoke from the repository root:

    PYTHONPATH="apps/local:packages/science:packages/contracts/python:." \
        .venv/bin/python tools/evidence/clean-machine-chain/run_chain.py
"""

# ruff: noqa: S603 - the only subprocess is this interpreter re-running itself.

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from typing import cast
from uuid import UUID

SPECTRUM_CSV = (
    "wavelength,intensity\n"
    "500,0.08\n"
    "510,0.21\n"
    "520,0.44\n"
    "530,0.71\n"
    "540,0.52\n"
    "550,0.33\n"
    "560,0.18\n"
    "570,0.12\n"
    "580,0.07\n"
)
CALIBRATION_DIGEST = hashlib.sha256(b"clean-machine-chain calibration").hexdigest()
LINEAGE_UUID7 = "018f47a0-7b9c-7aaa-8def-0123456789ab"
SPECTRUM_MANIFEST = (
    'manifest_version = "nipo.local.input-manifest.v1"\n'
    'kind = "spectrum"\n'
    "\n"
    "[scope]\n"
    "research_only = true\n"
    "non_clinical = true\n"
    "\n"
    "[[units]]\n"
    'quantity = "wavelength"\n'
    'ucum_code = "nm"\n'
    "\n"
    "[[units]]\n"
    'quantity = "intensity"\n'
    'ucum_code = "1"\n'
    "\n"
    "[calibration]\n"
    'method = "two-point NIST-traceable"\n'
    'reference = "SRM 2242a"\n'
    "calibrated_at = 2026-07-20T09:30:00Z\n"
    f'calibration_sha256 = "{CALIBRATION_DIGEST}"\n'
    "\n"
    "[lineage]\n"
    f'version_ids = ["{LINEAGE_UUID7}"]\n'
)
PACK_ID = UUID("018f47a0-7b9c-7ef0-8def-0123456789ab")
SESSION_ID = UUID("018f47a0-7b9c-7dd0-8def-0123456789ab")
EXPORTED_AT = datetime(2026, 7, 27, 5, 6, 7, tzinfo=UTC)


def _canonical(value: object) -> bytes:
    return json.dumps(
        value, ensure_ascii=True, sort_keys=True, separators=(",", ":")
    ).encode("utf-8")


def _write_measurement(directory: Path) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    data = directory / "bench-530nm-spectrum.csv"
    _ = data.write_text(SPECTRUM_CSV, encoding="utf-8")
    _ = (directory / "bench-530nm-spectrum.csv.manifest.toml").write_text(
        SPECTRUM_MANIFEST, encoding="utf-8"
    )
    return data


def _intent() -> object:
    from science_workbench_science import DataOrigin, ResearchIntent, ResearchMode

    return ResearchIntent(
        question="Is the corrected 530 nm emission maximum reproducible?",
        rationale="A stable corrected maximum justifies a targeted replicate.",
        intended_benefit="Avoid bench time on a non-reproducible band.",
        success_criteria=("A corrected local maximum is reported near 530 nm.",),
        constraints=("Observed calibrated spectra only.",),
        stop_conditions=("Stop when calibration metadata is absent.",),
        research_mode=ResearchMode.AI_FOR_SCIENCE,
        data_origin=DataOrigin.OBSERVED,
    )


def produce(root: Path) -> dict[str, object]:
    """Run the chain once in a fresh data root and return observed digests."""
    from nipo_local.config import resolve_paths
    from nipo_local.exportpack import (
        AttestedInputs,
        ExportRequest,
        entries_for_run,
        export_run,
    )
    from nipo_local.loaders import load_probe
    from nipo_local.reviewrun import ReviewJob, review_run
    from nipo_local.store import ExecutionInputKind, LocalArtifactStore, SessionRecord
    from nipo_local.workbench import (
        approve_analysis,
        assemble_artifact_runtime,
        environment_facts,
        run_analysis,
    )
    from services.api.artifacts.models import SessionArtifactLink
    from services.api.artifacts.runtime import SystemClock, Uuid7Factory

    measurement = _write_measurement(root / "inbox")
    source = load_probe(spectrum=measurement)
    intent = _intent()
    paths = resolve_paths(root / "data")
    with LocalArtifactStore(paths) as store:
        runtime = assemble_artifact_runtime(store, paths, session_id=SESSION_ID)
        _ = store.create_session(
            runtime.scope,
            SessionRecord(
                id=SESSION_ID,
                org_id=runtime.scope.org_id,
                project_id=runtime.scope.project_id,
                title="clean-machine 530 nm band",
                created_at=EXPORTED_AT,
                last_active_at=EXPORTED_AT,
            ),
        )
        approved = approve_analysis(runtime, intent)
        if approved.plan.research_intent_sha256 != intent.sha256:  # type: ignore[attr-defined]
            msg = "approval does not bind the intent digest"
            raise AssertionError(msg)
        run = run_analysis(runtime, intent, source, approved)
        digests: dict[str, object] = {
            "input_sha256": run.provenance.input_sha256,
            "research_intent_sha256": run.provenance.research_intent_sha256,
            "environment_sha256": run.provenance.environment_sha256,
        }
        for record in run.outputs:
            payload = store.read_content(runtime.scope, record.version.id)
            if payload is None:
                msg = f"missing payload for {record.role}"
                raise AssertionError(msg)
            digests[record.role] = hashlib.sha256(payload).hexdigest()
        for record in run.outputs:
            _ = store.attach_session(
                runtime.scope,
                SessionArtifactLink(
                    org_id=runtime.scope.org_id,
                    project_id=runtime.scope.project_id,
                    session_id=SESSION_ID,
                    artifact_version_id=record.version.id,
                    revision=1,
                    created_at=EXPORTED_AT,
                ),
            )
        reviewed = review_run(
            ReviewJob(
                store=store,
                scope=runtime.scope,
                ids=Uuid7Factory(),
                clock=SystemClock(),
            ),
            run.run_id,
        )
        intent_json = store.execution_input(
            runtime.scope, runtime.execution_id, ExecutionInputKind.RESEARCH_INTENT
        )
        input_json = store.execution_input(
            runtime.scope, runtime.execution_id, ExecutionInputKind.SCIENTIFIC_INPUT
        )
        entries = entries_for_run(store, runtime.scope, run.run_id)
        archive = root / "reproducibility-pack.zip"
        selection = tuple(
            UUID(value)
            for value in sorted(
                str(entry.artifact_version_id)
                for entry in entries
                if entry.artifact_version_id is not None
            )
        )
        pack = export_run(
            store,
            runtime.scope,
            paths,
            ExportRequest(
                pack_id=PACK_ID,
                run_id=run.run_id,
                selection=selection,
                entries=entries,
                created_at=EXPORTED_AT,
                attested=AttestedInputs(
                    research_intent_json=intent_json or b"",
                    scientific_input_json=input_json or b"",
                    environment_facts=environment_facts(),
                ),
            ),
            archive,
        )
        return {
            "digests": digests,
            "review_state": reviewed.review.state.value,
            "review_rules": [item.rule_id.value for item in reviewed.findings],
            "review_verdicts": [item.verdict.value for item in reviewed.findings],
            "manifest_sha256": pack.manifest_sha256,
            "archive": str(archive),
        }


def verify_pack(archive: Path, destination: Path) -> dict[str, object]:
    """Verify the pack from its extracted bytes alone."""
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as opened:
        for name in opened.namelist():
            if name.startswith("/") or ".." in Path(name).parts:
                msg = f"unsafe member: {name}"
                raise AssertionError(msg)
        opened.extractall(destination)
    manifest_bytes = (destination / "manifest.json").read_bytes()
    manifest = cast("dict[str, object]", json.loads(manifest_bytes))
    if manifest_bytes != _canonical(manifest):
        msg = "manifest is not canonical by its own rule"
        raise AssertionError(msg)
    recomputed: dict[str, str] = {}
    for line in (destination / "checksums.sha256").read_text("utf-8").splitlines():
        digest, _, name = line.partition("  ")
        member = destination / name
        observed = hashlib.sha256(member.read_bytes()).hexdigest()
        if observed != digest:
            msg = f"checksum mismatch: {name}"
            raise AssertionError(msg)
        recomputed[name] = digest
    entries = cast("list[dict[str, object]]", manifest["entries"])
    for entry in entries:
        path = str(entry["path"])
        payload = (destination / path).read_bytes()
        if hashlib.sha256(payload).hexdigest() != entry["sha256"]:
            msg = f"manifest digest mismatch: {path}"
            raise AssertionError(msg)
    provenance = cast(
        "dict[str, object]",
        json.loads((destination / "provenance.json").read_bytes()),
    )
    execution = cast("dict[str, object]", provenance["execution"])
    for member, key in (
        ("research-intent.json", "research_intent_sha256"),
        ("scientific-input.json", "input_sha256"),
        ("environment.json", "environment_sha256"),
    ):
        observed = hashlib.sha256((destination / member).read_bytes()).hexdigest()
        if observed != execution[key]:
            msg = f"attested digest mismatch: {member}"
            raise AssertionError(msg)
    review = cast(
        "dict[str, object]", json.loads((destination / "review.json").read_bytes())
    )
    run_record = cast(
        "dict[str, object]",
        json.loads((destination / "run-record.json").read_bytes()),
    )
    return {
        "members_verified": len(recomputed),
        "manifest_sha256": recomputed["manifest.json"],
        "execution_isolation": execution["execution_isolation"],
        "review_state": review["state"],
        "run_state": run_record["state"],
    }


def main() -> int:
    """Drive one verified chain run plus a three-seed determinism observation."""
    if len(sys.argv) == 3 and sys.argv[1] == "--produce":
        result = produce(Path(sys.argv[2]))
        _ = sys.stdout.write(json.dumps(result, sort_keys=True))
        return 0
    report: dict[str, object] = {
        "procedure": "SPEC-v0.5 section 15 clean-machine chain",
        "executed_at_utc": datetime.now(tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ"),
    }
    runs: list[dict[str, object]] = []
    with tempfile.TemporaryDirectory() as scratch:
        for seed in ("0", "1", "12345"):
            root = Path(scratch) / f"machine-{seed}"
            environment = {
                **{
                    key: value
                    for key, value in os.environ.items()
                    if key in {"HOME", "LANG", "PATH", "PYTHONPATH", "TZ"}
                },
                "PYTHONHASHSEED": seed,
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            completed = subprocess.run(
                (sys.executable, __file__, "--produce", str(root)),
                check=True,
                capture_output=True,
                env=environment,
                timeout=600,
            )
            produced = cast(
                "dict[str, object]", json.loads(completed.stdout.decode())
            )
            produced["hash_seed"] = seed
            verified = verify_pack(
                Path(str(produced.pop("archive"))), root / "verify"
            )
            produced["verification"] = verified
            runs.append(produced)
    # LN02 and the chain contract require byte-identical CSV, PNG, and
    # Markdown; the evidence ledger binds its own execution identity and is
    # deliberately excluded, but must exist in every run.
    deterministic_roles = (
        "csv",
        "png",
        "markdown",
        "input_sha256",
        "research_intent_sha256",
        "environment_sha256",
    )
    digest_sets = {
        json.dumps(
            {key: cast("dict[str, object]", run["digests"])[key] for key in deterministic_roles},
            sort_keys=True,
        )
        for run in runs
    }
    ledgers_committed = all(
        cast("dict[str, object]", run["digests"]).get("ledger") for run in runs
    )
    report["runs"] = runs
    report["deterministic_roles"] = list(deterministic_roles)
    report["byte_identical_across_interpreters"] = len(digest_sets) == 1
    report["ledger_committed_in_every_run"] = ledgers_committed
    passed = len(digest_sets) == 1 and ledgers_committed
    _ = sys.stdout.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
