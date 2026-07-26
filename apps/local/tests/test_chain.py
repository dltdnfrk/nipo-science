"""The whole local dry-lab chain, from a file on disk to a verified pack.

Nine components were individually green while nothing joined them. This module
walks the ordered chain SPEC-v0.5 section 1 defines, once, end to end:

    measurement file + sidecar manifest
      -> loaders.load_probe
      -> ResearchIntent
      -> ActionPlan
      -> one-use approval
      -> run
      -> four immutable Artifact Versions
      -> persisted Review
      -> Export Pack

and then verifies the pack from its extracted bytes alone -- recomputing every
digest with a canonical-JSON implementation written out here rather than
imported, so the pack is checked the way a third party without this repository
would check it.

The input is a real file with real bytes, not a hand-built `ProbeInput`. That
matters: the loader is what turns declared units and calibration into the
typed input whose canonical serialization `input_sha256` is taken over, so a
chain assembled in memory would skip the stage where a real researcher starts.
"""

import hashlib
import json
import os
import subprocess
import sys
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast
from uuid import UUID

import pytest
from services.api.artifacts.models import ArtifactScope, SessionArtifactLink
from services.api.artifacts.runtime import SystemClock, Uuid7Factory
from services.api.artifacts.store_contract import StoreOutcome

from nipo_local.config import LocalPaths, resolve_paths
from nipo_local.exportpack import (
    AttestedInputs,
    ExportEntry,
    ExportRequest,
    entries_for_run,
    export_run,
)
from nipo_local.loaders import load_probe
from nipo_local.reviewrun import ReviewJob, review_run
from nipo_local.runsurface import StoreRunSurface
from nipo_local.store import ExecutionInputKind, LocalArtifactStore, SessionRecord
from nipo_local.workbench import (
    approve_analysis,
    assemble_artifact_runtime,
    environment_facts,
    read_run_record,
    run_analysis,
)
from science_workbench_science import DataOrigin, ResearchIntent, ResearchMode

PACK_ID: Final = UUID("018f47a0-7b9c-7eee-8def-0123456789ab")
SESSION_ID: Final = UUID("018f47a0-7b9c-7ddd-8def-0123456789ab")
LINEAGE_UUID7: Final = "018f47a0-7b9c-7aaa-8def-0123456789ab"
CALIBRATION_DIGEST: Final = "c" * 64
EXPORTED_AT: Final = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)

CHAIN_ROLES: Final = ["csv", "png", "markdown", "ledger"]
RULE_IDS: Final = ["RV01", "RV02", "RV03", "RV04", "RV05"]

# A real two-column spectrum with a resolvable corrected maximum near 430 nm.
SPECTRUM_CSV: Final = (
    "wavelength,intensity\n"
    "400,0.10\n"
    "410,0.35\n"
    "420,0.20\n"
    "430,0.55\n"
    "440,0.25\n"
    "450,0.30\n"
    "460,0.15\n"
)

SPECTRUM_MANIFEST: Final = (
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
    "calibrated_at = 2026-01-04T09:30:00Z\n"
    f'calibration_sha256 = "{CALIBRATION_DIGEST}"\n'
    "\n"
    "[lineage]\n"
    f'version_ids = ["{LINEAGE_UUID7}"]\n'
)

INTENT: Final = ResearchIntent(
    question="Does the calibrated 430 nm band persist across replicate runs?",
    rationale="A stable corrected maximum would justify a targeted follow-up.",
    intended_benefit="Avoid bench time spent on non-reproducible bands.",
    success_criteria=("A corrected local maximum is reported near 430 nm.",),
    constraints=("Observed calibrated spectra only.",),
    stop_conditions=("Stop when calibration metadata is absent.",),
    research_mode=ResearchMode.AI_FOR_SCIENCE,
    data_origin=DataOrigin.OBSERVED,
)

# Run in a child interpreter, so determinism is asserted across processes and
# hash seeds rather than across two calls that share a warm import cache.
CHAIN_SCRIPT: Final = """
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import test_chain as chain
from nipo_local.config import resolve_paths
from nipo_local.loaders import load_probe
from nipo_local.store import LocalArtifactStore
from nipo_local.workbench import (
    approve_analysis,
    assemble_artifact_runtime,
    run_analysis,
)

with tempfile.TemporaryDirectory() as directory:
    root = Path(directory)
    measurement = chain.write_measurement(root / "inbox")
    paths = resolve_paths(root / "data")
    with LocalArtifactStore(paths) as store:
        runtime = assemble_artifact_runtime(store, paths)
        source = load_probe(spectrum=measurement)
        run = run_analysis(
            runtime, chain.INTENT, source, approve_analysis(runtime, chain.INTENT)
        )
        digests = {"input_sha256": run.provenance.input_sha256}
        for record in run.outputs:
            payload = runtime.service.read_content(runtime.scope, record.version.id)
            digests[record.role] = hashlib.sha256(payload).hexdigest()
        sys.stdout.write(json.dumps(digests))
"""


def write_measurement(directory: Path) -> Path:
    """Write one real measurement file and its sidecar manifest to disk."""
    directory.mkdir(parents=True, exist_ok=True)
    data = directory / "probe-spectrum.csv"
    _ = data.write_text(SPECTRUM_CSV, encoding="utf-8")
    _ = (directory / "probe-spectrum.csv.manifest.toml").write_text(
        SPECTRUM_MANIFEST,
        encoding="utf-8",
    )
    return data


def canonical(value: object) -> bytes:
    """Re-implement the canonical rule the pack states, without importing it."""
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def as_mapping(value: object) -> dict[str, object]:
    """Narrow one decoded JSON value to an object."""
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


def as_sequence(value: object) -> list[object]:
    """Narrow one decoded JSON value to an array."""
    assert isinstance(value, list)
    return cast("list[object]", value)


@pytest.fixture(name="paths")
def paths_fixture(tmp_path: Path) -> LocalPaths:
    return resolve_paths(tmp_path / "data")


@pytest.fixture(name="store")
def store_fixture(paths: LocalPaths) -> Iterator[LocalArtifactStore]:
    with LocalArtifactStore(paths) as opened:
        yield opened


def _session(scope: ArtifactScope) -> SessionRecord:
    """Register the one Session this chain's work belongs to."""
    return SessionRecord(
        id=SESSION_ID,
        org_id=scope.org_id,
        project_id=scope.project_id,
        title="calibrated 430 nm band",
        created_at=EXPORTED_AT,
        last_active_at=EXPORTED_AT,
    )


def _link(scope: ArtifactScope, version_id: UUID) -> SessionArtifactLink:
    """Associate one published Version with that Session."""
    return SessionArtifactLink(
        org_id=scope.org_id,
        project_id=scope.project_id,
        session_id=SESSION_ID,
        artifact_version_id=version_id,
        revision=1,
        created_at=EXPORTED_AT,
    )


def _selection(entries: Sequence[ExportEntry]) -> tuple[UUID, ...]:
    """State the pinned selection the way a caller must: sorted and explicit."""
    return tuple(
        UUID(value)
        for value in sorted(
            str(entry.artifact_version_id)
            for entry in entries
            if entry.artifact_version_id is not None
        )
    )


def _extract(archive: Path, destination: Path) -> Path:
    """Unpack one pack, refusing any member the archive should not carry."""
    destination.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(archive) as opened:
        for name in opened.namelist():
            assert not name.startswith("/")
            assert ".." not in Path(name).parts
        opened.extractall(destination)
    return destination


def test_the_whole_chain_runs_from_a_file_on_disk_to_a_verified_pack(  # noqa: PLR0915
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    """Walk every stage once and verify the pack from its own bytes."""
    # 1. A real measurement file with declared units, calibration and origin.
    measurement = write_measurement(tmp_path / "inbox")
    assert measurement.is_file()

    # 2. It loads into a typed scientific input through the real loader.
    source = load_probe(spectrum=measurement)
    assert source.spectrum is not None
    assert len(source.spectrum.wavelengths) == 7
    assert source.spectrum.metadata.calibration is not None
    assert source.spectrum.metadata.calibration.calibration_sha256 == (
        CALIBRATION_DIGEST
    )

    # 3. An immutable ActionPlan binds this exact intent, and 4. its one-use
    #    approval authorizes exactly one execution. The work belongs to one
    #    Session, which is the last step of the ownership chain the association
    #    below is checked against.
    runtime = assemble_artifact_runtime(store, paths, session_id=SESSION_ID)
    assert store.create_session(runtime.scope, _session(runtime.scope)) is (
        StoreOutcome.CREATED
    )
    approved = approve_analysis(runtime, INTENT)
    assert approved.plan.research_intent_sha256 == INTENT.sha256
    assert approved.approval.consumed_at is None

    # 5. The approved plan runs and commits four immutable Versions.
    run = run_analysis(runtime, INTENT, source, approved)
    assert [item.role for item in run.outputs] == CHAIN_ROLES
    assert [item.version.version_no for item in run.outputs] == [1, 1, 1, 1]
    for record in run.outputs:
        payload = store.read_content(runtime.scope, record.version.id)
        assert payload is not None
        assert hashlib.sha256(payload).hexdigest() == record.version.content_sha256

    # The approval is spent and the Run is closed `completed` in the durable
    # authority as well as in its mirror.
    spent = store.plan_approval(runtime.scope, approved.approval.id)
    assert spent is not None
    assert spent.consumed_at is not None
    row = store.run(runtime.scope, run.run_id)
    assert row is not None
    assert row.state.value == "completed"
    mirror = read_run_record(paths, runtime.execution_id)
    assert mirror is not None
    assert mirror["state"] == "completed"
    assert store.unfinished_runs(runtime.scope) == ()

    # The bound Run surface reports the same state and the recorded isolation.
    projected = StoreRunSurface(store).read_run(runtime.scope, run.run_id)
    assert projected is not None
    assert projected["state"] == "completed"
    assert projected["execution_isolation"] == "in_process"

    # 6. Provenance pins the input, intent, code, and environment digests.
    assert (
        run.provenance.input_sha256
        == hashlib.sha256(source.model_dump_json().encode()).hexdigest()
    )
    assert (
        run.provenance.research_intent_sha256
        == hashlib.sha256(INTENT.canonical_bytes).hexdigest()
    )
    assert (
        run.provenance.environment_sha256
        == hashlib.sha256(canonical(dict(environment_facts()))).hexdigest()
    )

    # 6b. The ownership chain reaches the Session, so every published Version
    #     can be associated with the Session that commissioned the work.
    row = store.run(runtime.scope, run.run_id)
    assert row is not None
    assert row.session_id == UUID("018f47a0-7b9c-7ddd-8def-0123456789ab")
    for record in run.outputs:
        assert store.attach_session(
            runtime.scope,
            _link(runtime.scope, record.version.id),
        ) is (StoreOutcome.CREATED)

    # 7. A persisted Review verifies the pinned record without re-executing.
    reviewed = review_run(
        ReviewJob(
            store=store,
            scope=runtime.scope,
            ids=Uuid7Factory(),
            clock=SystemClock(),
        ),
        run.run_id,
    )
    assert reviewed.review.state.value == "completed"
    assert [item.rule_id.value for item in reviewed.findings] == RULE_IDS
    assert {item.verdict.value for item in reviewed.findings} <= {
        "pass",
        "warn",
        "fail",
        "inconclusive",
    }
    assert set(reviewed.review.pinned_artifact_version_ids) == {
        item.version.id for item in run.outputs
    }
    # Reviewing wrote no Version: the chain is still exactly four.
    assert len(store.run_outputs(runtime.scope, run.run_id)) == 4

    # 8. Export pins the selected Versions and writes a checksummed pack. The
    #    two attested documents are read back out of the store rather than
    #    handed over from this test's own objects: that is the whole point of
    #    persisting them, and it is exactly what an exporter running long after
    #    the run -- holding a data root and nothing else -- has available.
    intent_json = store.execution_input(
        runtime.scope,
        runtime.execution_id,
        ExecutionInputKind.RESEARCH_INTENT,
    )
    input_json = store.execution_input(
        runtime.scope,
        runtime.execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
    )
    assert intent_json == INTENT.canonical_bytes
    assert input_json == source.model_dump_json().encode()
    entries = entries_for_run(store, runtime.scope, run.run_id)
    archive = tmp_path / "reproducibility-pack.zip"
    pack = export_run(
        store,
        runtime.scope,
        paths,
        ExportRequest(
            pack_id=PACK_ID,
            run_id=run.run_id,
            selection=_selection(entries),
            entries=entries,
            created_at=EXPORTED_AT,
            attested=AttestedInputs(
                research_intent_json=intent_json,
                scientific_input_json=input_json,
                environment_facts=environment_facts(),
            ),
        ),
        archive,
    )
    assert archive.is_file()

    # ---- From here on, only the extracted bytes are used. ----
    extracted = _extract(archive, tmp_path / "verify")

    manifest_bytes = (extracted / "manifest.json").read_bytes()
    manifest = as_mapping(cast("object", json.loads(manifest_bytes)))
    checksum_lines = (extracted / "checksums.sha256").read_text("utf-8").splitlines()

    # Every checksum line names a member that exists and hashes to that value.
    recomputed: dict[str, str] = {}
    for line in checksum_lines:
        digest, _, name = line.partition("  ")
        member = extracted / name
        assert member.is_file(), name
        assert hashlib.sha256(member.read_bytes()).hexdigest() == digest, name
        recomputed[name] = digest
    assert sorted(recomputed) == sorted(
        line.partition("  ")[2] for line in checksum_lines
    )
    assert recomputed["manifest.json"] == hashlib.sha256(manifest_bytes).hexdigest()
    assert recomputed["manifest.json"] == pack.manifest_sha256

    # The manifest's own entry digests agree with the bytes and with the
    # checksum file: three independent statements of the same fact.
    manifest_entries = [as_mapping(item) for item in as_sequence(manifest["entries"])]
    artifacts = [
        item for item in manifest_entries if item["kind"] == "artifact_version"
    ]
    assert len(artifacts) == 4
    assert sorted(str(item["path"]) for item in artifacts) == [
        "artifacts/analysis-report.md",
        "artifacts/evidence-ledger.json",
        "artifacts/hypothesis-table.csv",
        "artifacts/spectrum-plot.png",
    ]
    # `manifest.json` records no digest of itself: its digest appears once, in
    # `checksums.sha256`, which is the only member no manifest line covers.
    listed = {str(item["path"]) for item in manifest_entries}
    assert listed == set(recomputed) - {"manifest.json"}
    assert "manifest.json" not in listed
    for entry in manifest_entries:
        path = str(entry["path"])
        payload = (extracted / path).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == entry["sha256"], path
        assert recomputed[path] == entry["sha256"], path
        assert int(cast("int", entry["size_bytes"])) == len(payload), path

    # The manifest is canonical by its own stated rule.
    assert manifest_bytes == canonical(manifest)

    # The attested bytes recompute the digests the execution pinned.
    provenance = as_mapping(
        cast("object", json.loads((extracted / "provenance.json").read_bytes()))
    )
    execution = as_mapping(provenance["execution"])
    assert (
        hashlib.sha256((extracted / "research-intent.json").read_bytes()).hexdigest()
        == execution["research_intent_sha256"]
    )
    assert (
        hashlib.sha256((extracted / "scientific-input.json").read_bytes()).hexdigest()
        == execution["input_sha256"]
    )
    assert (
        hashlib.sha256((extracted / "environment.json").read_bytes()).hexdigest()
        == execution["environment_sha256"]
    )

    # The pack states the isolation it cannot claim away.
    assert execution["execution_isolation"] == "in_process"

    # The Review status travelled with the pack and records a verdict.
    review = as_mapping(
        cast("object", json.loads((extracted / "review.json").read_bytes()))
    )
    assert review["state"] == "completed"
    findings = [as_mapping(item) for item in as_sequence(review["findings"])]
    assert [item["rule_id"] for item in findings] == RULE_IDS
    assert all(
        str(item["verdict"]) in {"pass", "warn", "fail", "inconclusive"}
        for item in findings
    )

    # The run record in the pack agrees with the durable authority.
    run_record = as_mapping(
        cast("object", json.loads((extracted / "run-record.json").read_bytes()))
    )
    assert run_record["state"] == "completed"
    assert run_record["run_id"] == str(run.run_id)

    # The approved plan and the pinned intent digest are both present.
    plan = as_mapping(
        cast("object", json.loads((extracted / "action-plan.json").read_bytes()))
    )
    assert plan["research_intent_sha256"] == INTENT.sha256
    assert manifest["research_intent_sha256"] == INTENT.sha256

    # No credential material of any kind reached the pack.
    for member in pack.members:
        assert b"BEGIN" not in member.payload[:64] or member.path.endswith(".png")
    assert not any(
        member.path in {"credentials.json", "download-signing.key"}
        for member in pack.members
    )


def test_the_chain_is_byte_identical_across_separate_interpreters(
    tmp_path: Path,
) -> None:
    """Prove determinism survives the loader, the run, and differing seeds."""
    seeds = ("0", "1", "12345")
    results: list[Mapping[str, str]] = []
    for seed in seeds:
        environment = {
            **os.environ,
            "PYTHONHASHSEED": seed,
            "PYTHONDONTWRITEBYTECODE": "1",
            "PYTHONPATH": os.pathsep.join(
                [
                    *(entry for entry in sys.path if entry),
                    str(Path(__file__).parent),
                ]
            ),
        }
        completed = subprocess.run(
            [sys.executable, "-c", CHAIN_SCRIPT],
            check=False,
            capture_output=True,
            text=True,
            env=environment,
            cwd=tmp_path,
            timeout=300,
        )
        assert completed.returncode == 0, completed.stderr
        results.append(
            cast("Mapping[str, str]", json.loads(completed.stdout)),
        )

    first = results[0]
    assert sorted(first) == ["csv", "input_sha256", "ledger", "markdown", "png"]
    for index, other in enumerate(results[1:], start=1):
        # The ledger binds itself to its own execution identity, so it is
        # excluded; every other output must be byte-identical.
        for role in ("csv", "png", "markdown", "input_sha256"):
            assert other[role] == first[role], f"{role} differs at seed {seeds[index]}"
        assert other["ledger"] != "", "the ledger must still have been committed"


def test_the_loader_is_what_produces_the_pinned_input_digest(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    """A changed measurement byte must move the digest the chain pins."""
    first = write_measurement(tmp_path / "one")
    second_dir = tmp_path / "two"
    second_dir.mkdir()
    second = second_dir / "probe-spectrum.csv"
    _ = second.write_text(SPECTRUM_CSV.replace("430,0.55", "430,0.56"), "utf-8")
    _ = (second_dir / "probe-spectrum.csv.manifest.toml").write_text(
        SPECTRUM_MANIFEST,
        encoding="utf-8",
    )

    one = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        one,
        INTENT,
        load_probe(spectrum=first),
        approve_analysis(one, INTENT),
    )
    two = assemble_artifact_runtime(store, paths)
    edited = run_analysis(
        two,
        INTENT,
        load_probe(spectrum=second),
        approve_analysis(two, INTENT),
    )

    assert original.provenance.input_sha256 != edited.provenance.input_sha256
    # The report embeds the input digest and the ledger pins it, so a changed
    # measurement byte necessarily moves both artifacts.
    assert (
        original.markdown.version.content_sha256
        != edited.markdown.version.content_sha256
    )
    assert (
        original.ledger.version.content_sha256 != edited.ledger.version.content_sha256
    )
    # Both chains stand on their own: neither overwrote the other.
    assert original.csv.artifact.id != edited.csv.artifact.id
    for run in (original, edited):
        for record in run.outputs:
            stored = store.version(_scope(one.scope), record.version.id)
            assert stored is not None
            assert stored.content_sha256 == record.version.content_sha256


def _scope(scope: ArtifactScope) -> ArtifactScope:
    """Return the scope unchanged, named so the read intent is explicit."""
    return scope
