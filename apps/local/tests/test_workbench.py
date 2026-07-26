"""Behavioural tests for the local science-to-Artifact workbench slice.

Provenance assertions here deliberately recompute digests from primary sources
(the science package files on disk, the input bytes, the installed distribution
metadata) instead of comparing a stored value against the same in-memory value
the producer wrote. Literal expectations are spelled out rather than imported
from the module under test, so a mutated constant cannot satisfy its own
assertion.
"""

import hashlib
import json
import os
import stat
import subprocess
import sys
import threading
from collections.abc import Iterator
from contextlib import closing
from datetime import UTC, datetime, timedelta
from importlib.metadata import version as distribution_version
from importlib.util import find_spec
from pathlib import Path
from sqlite3 import connect
from typing import Final, cast
from uuid import UUID

import pytest
from services.api.artifacts.models import (
    ArtifactError,
    ArtifactErrorCode,
    ArtifactScope,
    ArtifactVersion,
    SessionArtifactLink,
)
from services.api.artifacts.store_contract import (
    ArtifactCommitError,
    ArtifactStoreError,
    StoreOutcome,
)

from nipo_local.config import (
    LOCAL_RUNTIME_ADAPTER_ID,
    LOCAL_RUNTIME_CONNECTION_ID,
    LocalPaths,
    resolve_paths,
)
from nipo_local.store import (
    ActionPlanRecord,
    ApprovalOutcome,
    ExecutionInputKind,
    LocalArtifactStore,
    PlanApprovalRecord,
    SessionRecord,
)
from nipo_local.workbench import (
    ActionPlanError,
    ApprovedPlan,
    CorrectionTarget,
    CorrectionTargetError,
    LocalArtifactRuntime,
    PlanApprovalError,
    WorkbenchRejection,
    WorkbenchRun,
    WorkbenchRunError,
    approve_action_plan,
    approve_analysis,
    assemble_artifact_runtime,
    canonical_sha256,
    code_sha256,
    correct_analysis,
    correction_targets,
    create_action_plan,
    environment_facts,
    load_download_signing_key,
    local_scope,
    read_run_record,
    run_analysis,
    run_record_path,
    signing_key_path,
)
from science_workbench_science import (
    CalibrationMetadata,
    DataOrigin,
    InputMetadata,
    MeasurementUnit,
    OutcomeStatus,
    ProbeInput,
    ResearchIntent,
    ResearchMode,
    SpectrumInput,
    TableInput,
)

COUNT_QUERY: Final = (
    "SELECT (SELECT COUNT(*) FROM artifacts), (SELECT COUNT(*) FROM artifact_versions)"
)
LINEAGE: Final = (UUID("018f47a0-7b9c-7aaa-8def-0123456789ab"),)
REPLAY_EXECUTION: Final = UUID("018f47a0-7b9c-7bbb-8def-0123456789ab")
CALIBRATED_AT: Final = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
SPECTRUM_UNITS: Final = (
    MeasurementUnit(quantity="wavelength", ucum_code="nm"),
    MeasurementUnit(quantity="intensity", ucum_code="1"),
)
TABLE_UNITS: Final = (MeasurementUnit(quantity="mass", ucum_code="mg"),)
WAVELENGTHS: Final = (400.0, 410.0, 420.0, 430.0, 440.0, 450.0, 460.0)
DESCENDING: Final = (460.0, 450.0, 440.0, 430.0, 420.0, 410.0, 400.0)
INTENSITIES: Final = (0.10, 0.35, 0.20, 0.55, 0.25, 0.30, 0.15)

CHAIN_ROLES: Final = ["csv", "png", "markdown", "ledger"]
CHAIN_MEDIA_TYPES: Final = (
    "text/csv",
    "image/png",
    "text/markdown",
    "application/json",
)
CHAIN_NAMES: Final = (
    "hypothesis-table.csv",
    "spectrum-plot.png",
    "analysis-report.md",
    "evidence-ledger.json",
)
BRANCH_ORDER: Final = ("molecular", "optical", "experimental_artifact")
PEAK_ROWS: Final = (
    "| 1 | 410 | 0.241667 | 0.158334 |",
    "| 3 | 430 | 0.425000 | 0.308333 |",
    "| 5 | 450 | 0.158333 | 0.041666 |",
)
DETERMINISTIC_ROLES: Final = ("csv", "png", "markdown")
OWNER_ONLY: Final = 0o600
KEY_LENGTH: Final = 32
SHA256_LENGTH: Final = 64
HASH_SEEDS: Final = ("0", "1", "12345")
WORKERS: Final = 4
RACE_TRIALS: Final = 24

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

# Exactly one field differs from INTENT, which is the whole point: one edited
# field must change the canonical digest and therefore invalidate an approval.
EDITED_INTENT: Final = ResearchIntent(
    question="Does the calibrated 430 nm band persist across replicate runs?",
    rationale="A stable corrected maximum would justify a targeted follow-up.",
    intended_benefit="Avoid bench time spent on non-reproducible bands.",
    success_criteria=("A corrected local maximum is reported near 430 nm.",),
    constraints=("Observed calibrated spectra only.",),
    stop_conditions=("Stop when calibration metadata is missing.",),
    research_mode=ResearchMode.AI_FOR_SCIENCE,
    data_origin=DataOrigin.OBSERVED,
)

DETERMINISM_SCRIPT: Final = """
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import test_workbench as fixtures
from nipo_local.config import resolve_paths
from nipo_local.store import LocalArtifactStore
from nipo_local.workbench import (
    approve_analysis,
    assemble_artifact_runtime,
    run_analysis,
)

with tempfile.TemporaryDirectory() as directory:
    paths = resolve_paths(Path(directory))
    with LocalArtifactStore(paths) as store:
        runtime = assemble_artifact_runtime(store, paths)
        approved = approve_analysis(runtime, fixtures.INTENT)
        run = run_analysis(
            runtime, fixtures.INTENT, fixtures.spectrum_probe(), approved
        )
        digests = {}
        for record in run.outputs:
            payload = runtime.service.read_content(runtime.scope, record.version.id)
            digests[record.role] = hashlib.sha256(payload).hexdigest()
        sys.stdout.write(json.dumps(digests))
"""


def _metadata(
    units: tuple[MeasurementUnit, ...],
    calibration_sha256: str = "c" * 64,
) -> InputMetadata:
    return InputMetadata(
        units=units,
        calibration=CalibrationMetadata(
            method="two-point-standard",
            reference="NIST-SRM-2242",
            calibrated_at=CALIBRATED_AT,
            calibration_sha256=calibration_sha256,
        ),
        lineage_version_ids=LINEAGE,
        research_only=True,
        non_clinical=True,
    )


def spectrum_probe(
    wavelengths: tuple[float, ...] = WAVELENGTHS,
    calibration_sha256: str = "c" * 64,
) -> ProbeInput:
    """Build the shared calibrated spectrum input, also used by subprocesses."""
    return ProbeInput(
        spectrum=SpectrumInput(
            wavelengths=wavelengths,
            intensities=INTENSITIES,
            metadata=_metadata(SPECTRUM_UNITS, calibration_sha256),
        )
    )


def table_probe() -> ProbeInput:
    """Build a valid table-only input, which yields no spectrum plot."""
    return ProbeInput(
        table=TableInput(
            columns=("mass",),
            rows=((1.5,), (2.5,)),
            metadata=_metadata(TABLE_UNITS),
        )
    )


def _counts(paths: LocalPaths) -> tuple[int, int]:
    with closing(connect(paths.database)) as connection:
        return cast("tuple[int, int]", connection.execute(COUNT_QUERY).fetchone())


TABLE_COUNTS: Final = {
    "action_plans": "SELECT COUNT(*) FROM action_plans",
    "plan_approvals": "SELECT COUNT(*) FROM plan_approvals",
    "runs": "SELECT COUNT(*) FROM runs",
    "executions": "SELECT COUNT(*) FROM executions",
    "execution_inputs": "SELECT COUNT(*) FROM execution_inputs",
    "run_outputs": "SELECT COUNT(*) FROM run_outputs",
}


def _table_count(paths: LocalPaths, table: str) -> int:
    with closing(connect(paths.database)) as connection:
        row = cast(
            "tuple[object, ...]",
            connection.execute(TABLE_COUNTS[table]).fetchone(),
        )
    return cast("int", row[0])


def _approved(
    runtime: LocalArtifactRuntime,
    intent: ResearchIntent = INTENT,
) -> ApprovedPlan:
    """Create and approve one plan, the precondition every run now needs."""
    return approve_analysis(runtime, intent)


def _consumed(
    store: LocalArtifactStore,
    runtime: LocalArtifactRuntime,
    approved: ApprovedPlan,
) -> datetime | None:
    """Return when this approval was consumed, or None while it is unspent."""
    stored = store.plan_approval(runtime.scope, approved.approval.id)
    assert stored is not None
    return stored.consumed_at


def _blob_files(paths: LocalPaths) -> list[Path]:
    return sorted(item for item in paths.blobs.rglob("*") if item.is_file())


def _read(
    runtime: LocalArtifactRuntime,
    version_id: UUID,
) -> tuple[ArtifactVersion, bytes]:
    return runtime.service.read_active_content(runtime.scope, version_id)


def _ledger_of(runtime: LocalArtifactRuntime, version_id: UUID) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(_read(runtime, version_id)[1]))


def _record(runtime: LocalArtifactRuntime) -> dict[str, object]:
    stored = read_run_record(runtime.paths, runtime.execution_id)
    assert stored is not None
    return dict(stored)


def _committed_roles(record: dict[str, object]) -> list[object]:
    entries = cast("list[dict[str, object]]", record["committed_outputs"])
    assert [entry["sequence"] for entry in entries] == list(range(1, len(entries) + 1))
    return [entry["role"] for entry in entries]


def _installed_code_sha256() -> str:
    science = find_spec("science_workbench_science")
    module = find_spec("nipo_local.workbench")
    assert science is not None
    assert science.origin is not None
    assert module is not None
    assert module.origin is not None
    return code_sha256(Path(science.origin).parent, Path(module.origin).resolve())


def _concurrent_keys(paths: LocalPaths, workers: int) -> list[bytes]:
    barrier = threading.Barrier(workers)
    lock = threading.Lock()
    keys: list[bytes] = []

    def worker() -> None:
        _ = barrier.wait()
        key = load_download_signing_key(paths)
        with lock:
            keys.append(key)

    threads = [threading.Thread(target=worker) for _ in range(workers)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    return keys


def _child_digests(seed: str) -> dict[str, str]:
    environment = {
        **os.environ,
        "PYTHONHASHSEED": seed,
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONPATH": os.pathsep.join(
            [*(entry for entry in sys.path if entry), str(Path(__file__).parent)]
        ),
    }
    completed = subprocess.run(
        [sys.executable, "-c", DETERMINISM_SCRIPT],
        check=False,
        capture_output=True,
        text=True,
        env=environment,
        timeout=300,
    )
    assert completed.returncode == 0, completed.stderr
    return cast("dict[str, str]", json.loads(completed.stdout))


@pytest.fixture(name="paths")
def paths_fixture(tmp_path: Path) -> LocalPaths:
    return resolve_paths(tmp_path)


@pytest.fixture(name="store")
def store_fixture(paths: LocalPaths) -> Iterator[LocalArtifactStore]:
    with LocalArtifactStore(paths) as opened:
        yield opened


def test_run_persists_four_readable_versions(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    assert [item.role for item in run.outputs] == CHAIN_ROLES
    assert tuple(item.name for item in run.outputs) == CHAIN_NAMES
    assert tuple(item.version.media_type for item in run.outputs) == CHAIN_MEDIA_TYPES
    assert _counts(paths) == (4, 4)
    for record in run.outputs:
        version, payload = _read(runtime, record.version.id)
        assert version == record.version
        assert hashlib.sha256(payload).hexdigest() == version.content_sha256
        assert version.size_bytes == len(payload)
        assert version.version_no == 1
        assert version.artifact_id == record.artifact.id
        assert version.producing_execution_id == runtime.execution_id
        assert version.runtime_adapter_id == LOCAL_RUNTIME_ADAPTER_ID
        assert version.runtime_connection_id == LOCAL_RUNTIME_CONNECTION_ID
        assert version.skill_content_hashes == ()
        assert version.source_hashes == (run.provenance.input_sha256, INTENT.sha256)
        assert version.object_key == LocalArtifactStore.object_key(
            runtime.scope,
            version.content_sha256,
        )


def test_completed_run_record_pins_the_publication_order(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    record = _record(runtime)
    assert record["state"] == "completed"
    assert record["failure"] is None
    assert record["execution_isolation"] == "in_process"
    assert record["producing_execution_id"] == str(runtime.execution_id)
    assert _committed_roles(record) == CHAIN_ROLES
    entries = cast("list[dict[str, object]]", record["committed_outputs"])
    assert [entry["version_id"] for entry in entries] == [
        str(item.version.id) for item in run.outputs
    ]


def test_run_persists_exactly_the_science_package_bytes(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    assert _read(runtime, run.csv.version.id)[1] == run.analysis.hypothesis_table_csv
    assert _read(runtime, run.png.version.id)[1] == run.analysis.spectrum_plot_png


def test_markdown_reports_the_input_digest_and_ordered_branches(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    expected_input = hashlib.sha256(
        spectrum_probe().model_dump_json().encode()
    ).hexdigest()

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    text = _read(runtime, run.markdown.version.id)[1].decode()
    assert text.startswith("# Local deterministic analysis report")
    assert f"- Canonical digest: `{expected_input}`" in text
    assert f"- Canonical digest: `{INTENT.sha256}`" in text
    branch_positions = [text.index(f"### {branch} (") for branch in BRANCH_ORDER]
    assert branch_positions == sorted(branch_positions)
    peak_positions = [text.index(row) for row in PEAK_ROWS]
    assert peak_positions == sorted(peak_positions)


def test_ledger_derives_from_the_three_earlier_versions(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    derived = (run.csv.version.id, run.png.version.id, run.markdown.version.id)
    assert run.ledger.version.input_version_ids == tuple(sorted(derived))
    assert run.csv.version.input_version_ids == ()
    assert run.png.version.input_version_ids == ()
    assert run.markdown.version.input_version_ids == ()
    assert runtime.service.lineage(runtime.scope, run.ledger.version.id) == tuple(
        sorted(derived)
    )


def test_identical_runs_produce_identical_csv_and_markdown(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_runtime = assemble_artifact_runtime(store, paths)
    second_runtime = assemble_artifact_runtime(store, paths)

    first = run_analysis(
        first_runtime, INTENT, spectrum_probe(), _approved(first_runtime)
    )
    second = run_analysis(
        second_runtime, INTENT, spectrum_probe(), _approved(second_runtime)
    )

    assert first.provenance.execution_id != second.provenance.execution_id
    for role in DETERMINISTIC_ROLES:
        left = next(item for item in first.outputs if item.role == role)
        right = next(item for item in second.outputs if item.role == role)
        assert left.version.id != right.version.id
        assert left.version.content_sha256 == right.version.content_sha256
        left_payload = _read(first_runtime, left.version.id)[1]
        right_payload = _read(second_runtime, right.version.id)[1]
        assert left_payload == right_payload
    assert first.ledger.version.content_sha256 != second.ledger.version.content_sha256


def test_determinism_survives_separate_interpreters_and_hash_seeds() -> None:
    results = [_child_digests(seed) for seed in HASH_SEEDS]

    assert len(results) == len(HASH_SEEDS)
    for role in DETERMINISTIC_ROLES:
        assert len({digests[role] for digests in results}) == 1
    assert len({digests["ledger"] for digests in results}) == len(HASH_SEEDS)


def test_ledger_pins_the_hashes_the_store_actually_holds(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    ledger = _ledger_of(runtime, run.ledger.version.id)
    assert ledger["schema"] == "nipo.local.evidence-ledger.v1"
    assert ledger["research_intent_sha256"] == INTENT.sha256
    assert ledger["input_sha256"] == run.provenance.input_sha256
    assert ledger["producing_execution_id"] == str(runtime.execution_id)
    assert ledger["runtime_adapter_id"] == LOCAL_RUNTIME_ADAPTER_ID
    assert ledger["runtime_connection_id"] == str(LOCAL_RUNTIME_CONNECTION_ID)
    assert ledger["code_sha256"] == _installed_code_sha256()
    assert ledger["environment_sha256"] == canonical_sha256(environment_facts())
    entries = cast("list[dict[str, object]]", ledger["outputs"])
    assert [entry["role"] for entry in entries] == ["csv", "png", "markdown"]
    for entry in entries:
        version, payload = _read(runtime, UUID(cast("str", entry["version_id"])))
        assert entry["artifact_id"] == str(version.artifact_id)
        assert entry["content_sha256"] == hashlib.sha256(payload).hexdigest()
        assert entry["content_sha256"] == version.content_sha256
        assert entry["media_type"] == version.media_type
        assert entry["size_bytes"] == len(payload)
        assert entry["input_version_ids"] == [
            str(value) for value in version.input_version_ids
        ]


def test_ledger_records_the_upstream_evidence_lineage(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    ledger = _ledger_of(runtime, run.ledger.version.id)
    evidence = cast("list[dict[str, object]]", ledger["science_evidence"])
    lineage = [str(value) for value in LINEAGE]
    assert [entry["branch"] for entry in evidence] == list(BRANCH_ORDER)
    assert evidence[0]["source_version_ids"] == lineage
    assert evidence[2]["source_version_ids"] == lineage
    assert (
        evidence[0]["supporting_sha256"] == run.analysis.evidence[0].supporting_sha256
    )


def test_ledger_discloses_the_absent_isolation_and_skill_hashes(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    ledger = _ledger_of(runtime, run.ledger.version.id)
    assert ledger["execution_isolation"] == "in_process"
    assert ledger["skill_content_hashes"] == []
    assert "no Skill content hash exists" in cast("str", ledger["skill_content_note"])


def test_code_digest_tracks_every_science_source(tmp_path: Path) -> None:
    root = tmp_path / "science_tree"
    root.mkdir()
    _ = (root / "__init__.py").write_text('"""package."""\n', encoding="utf-8")
    _ = (root / "analysis.py").write_text("VALUE = 1\n", encoding="utf-8")
    module = tmp_path / "workbench.py"
    _ = module.write_text("MODULE = 1\n", encoding="utf-8")

    original = code_sha256(root, module)
    _ = (root / "analysis.py").write_text("VALUE = 2\n", encoding="utf-8")
    changed_science = code_sha256(root, module)
    _ = module.write_text("MODULE = 2\n", encoding="utf-8")
    changed_module = code_sha256(root, module)

    assert len({original, changed_science, changed_module}) == 3
    assert len(original) == SHA256_LENGTH


def test_published_code_digest_matches_the_installed_science_sources(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    expected = _installed_code_sha256()
    assert run.provenance.code_sha256 == expected
    for record in run.outputs:
        assert record.version.code_sha256 == expected


def test_environment_digest_covers_every_byte_shaping_dependency(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The key set is a literal rather than something derived from the module.
    # Deriving it would let the digest silently narrow: dropping `pydantic`
    # would still satisfy an assertion built from whatever `environment_facts`
    # happened to return, which is exactly how the gap survived before.
    facts = environment_facts()

    assert sorted(facts) == [
        "implementation",
        "pillow",
        "platform",
        "pydantic",
        "pydantic-core",
        "python",
    ]
    assert facts["python"] == ".".join(str(part) for part in sys.version_info[:3])
    assert facts["implementation"] == sys.implementation.name
    assert facts["platform"] == sys.platform
    for distribution in ("pillow", "pydantic", "pydantic-core"):
        assert facts[distribution] == distribution_version(distribution)

    runtime = assemble_artifact_runtime(store, paths)
    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    assert run.provenance.environment_sha256 == canonical_sha256(facts)
    for record in run.outputs:
        assert record.version.environment_sha256 == canonical_sha256(facts)


def test_the_serializer_behind_the_input_digest_is_inside_the_environment_digest(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # `input_sha256` is taken over `ProbeInput.model_dump_json()`, so a
    # pydantic upgrade can move that digest -- and the markdown and ledger
    # bytes derived from it -- while the interpreter version is unchanged. An
    # environment digest that did not move with it would be provenance that
    # silently disagrees with the artifacts pinned beside it.
    runtime = assemble_artifact_runtime(store, paths)
    source = spectrum_probe()
    run = run_analysis(runtime, INTENT, source, _approved(runtime))

    assert (
        run.provenance.input_sha256
        == hashlib.sha256(source.model_dump_json().encode()).hexdigest()
    )

    facts = dict(environment_facts())
    narrowed = {
        key: value
        for key, value in facts.items()
        if key not in {"pydantic", "pydantic-core"}
    }
    upgraded = {**facts, "pydantic-core": "0.0.0-not-the-installed-one"}

    # Covering the serializer is what makes these three digests differ.
    assert canonical_sha256(facts) != canonical_sha256(narrowed)
    assert canonical_sha256(facts) != canonical_sha256(upgraded)
    assert run.provenance.environment_sha256 == canonical_sha256(facts)

    # The digest the run pinned really is embedded in the ledger bytes, so a
    # narrowed environment digest would ship inside an artifact.
    ledger = _ledger_of(runtime, run.ledger.version.id)
    assert ledger["environment_sha256"] == canonical_sha256(facts)
    assert ledger["input_sha256"] == run.provenance.input_sha256


def test_input_digest_covers_calibration_and_is_not_the_intent_digest(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    other = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))
    recalibrated = run_analysis(
        other,
        INTENT,
        spectrum_probe(calibration_sha256="d" * 64),
        _approved(other),
    )

    assert run.provenance.input_sha256 != INTENT.sha256
    assert run.provenance.input_sha256 != recalibrated.provenance.input_sha256
    assert (
        run.provenance.input_sha256
        == hashlib.sha256(spectrum_probe().model_dump_json().encode()).hexdigest()
    )
    assert run.csv.version.source_hashes[0] == run.provenance.input_sha256


def test_signing_key_is_created_once_with_owner_only_permissions(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _ = assemble_artifact_runtime(store, paths)

    key_path = signing_key_path(paths)
    created = key_path.read_bytes()
    assert stat.S_IMODE(key_path.stat().st_mode) == OWNER_ONLY
    assert len(created) == KEY_LENGTH

    _ = assemble_artifact_runtime(store, paths)

    assert key_path.read_bytes() == created
    assert load_download_signing_key(paths) == created


def test_signing_keys_differ_between_installations(tmp_path: Path) -> None:
    first = load_download_signing_key(resolve_paths(tmp_path / "one"))
    second = load_download_signing_key(resolve_paths(tmp_path / "two"))

    assert first != second
    assert len(first) == KEY_LENGTH
    assert len(second) == KEY_LENGTH


def test_concurrent_first_use_never_observes_a_partial_signing_key(
    tmp_path: Path,
) -> None:
    disagreements = 0
    truncated = 0
    for trial in range(RACE_TRIALS):
        paths = resolve_paths(tmp_path / f"install-{trial}")
        keys = _concurrent_keys(paths, WORKERS)
        disagreements += len(set(keys)) - 1
        truncated += sum(len(key) != KEY_LENGTH for key in keys)
        assert signing_key_path(paths).read_bytes() == keys[0]

    assert disagreements == 0
    assert truncated == 0


def test_rejected_input_surfaces_the_science_outcome_and_writes_nothing(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)

    with pytest.raises(WorkbenchRunError) as rejection:
        _ = run_analysis(runtime, INTENT, spectrum_probe(DESCENDING), approved)

    assert rejection.value.code is WorkbenchRejection.SCIENCE_REJECTED
    assert rejection.value.status is OutcomeStatus.INVALID_DATA
    assert "spectrum_shape_invalid" in {issue.code for issue in rejection.value.issues}
    assert _counts(paths) == (0, 0)
    assert _blob_files(paths) == []
    assert read_run_record(paths, runtime.execution_id) is None
    # Invalid input is refused before any Run exists and before the approval
    # is spent, so a corrected retry can still use it.
    assert _table_count(paths, "runs") == 0
    assert _table_count(paths, "executions") == 0
    assert _consumed(store, runtime, approved) is None


def test_input_without_a_spectrum_is_refused_before_any_write(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    with pytest.raises(WorkbenchRunError) as rejection:
        _ = run_analysis(runtime, INTENT, table_probe(), _approved(runtime))

    assert rejection.value.code is WorkbenchRejection.SPECTRUM_REQUIRED
    assert rejection.value.status is OutcomeStatus.VALID
    assert _counts(paths) == (0, 0)
    assert _blob_files(paths) == []
    assert read_run_record(paths, runtime.execution_id) is None


def test_unwritable_blob_directory_leaves_a_failed_run_record(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    paths.blobs.chmod(0o500)
    try:
        with pytest.raises(ArtifactStoreError):
            _ = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))
    finally:
        paths.blobs.chmod(0o700)

    record = _record(runtime)
    assert record["state"] == "failed"
    assert _committed_roles(record) == []
    assert _counts(paths)[1] == 0
    assert _blob_files(paths) == []


def test_project_archived_mid_chain_leaves_a_failed_run_record(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    original = store.commit_version
    calls = 0

    def archiving_commit(
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        nonlocal calls
        outcome = original(scope, base_version_no, version, payload)
        calls += 1
        if calls == 2:
            store.archive_project(runtime.scope)
        return outcome

    monkeypatch.setattr(store, "commit_version", archiving_commit)

    with pytest.raises(ArtifactError):
        _ = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    record = _record(runtime)
    assert record["state"] == "failed"
    assert _committed_roles(record) == ["csv", "png"]
    assert cast("dict[str, object]", record["failure"])["error"] == "ArtifactError"


def test_failed_ledger_commit_leaves_a_failed_run_record(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    original = store.commit_version
    calls = 0

    def failing_commit(
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        nonlocal calls
        calls += 1
        if calls == len(CHAIN_ROLES):
            raise ArtifactCommitError
        return original(scope, base_version_no, version, payload)

    monkeypatch.setattr(store, "commit_version", failing_commit)

    with pytest.raises(ArtifactCommitError):
        _ = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    record = _record(runtime)
    assert record["state"] == "failed"
    assert _committed_roles(record) == ["csv", "png", "markdown"]
    failure = cast("dict[str, object]", record["failure"])
    assert failure["error"] == "ArtifactCommitError"
    assert _counts(paths) == (4, 3)


def test_a_rejected_registration_creates_no_artifact_identity(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    original = runtime.watcher.register
    calls = 0

    def failing_register(
        scope: ArtifactScope,
        execution_id: UUID,
        payload: bytes,
        media_type: str,
    ) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
        return original(scope, execution_id, payload, media_type)

    monkeypatch.setattr(runtime.watcher, "register", failing_register)

    with pytest.raises(ArtifactError):
        _ = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    record = _record(runtime)
    assert record["state"] == "failed"
    assert _committed_roles(record) == ["csv"]
    assert _counts(paths) == (1, 1)


def test_a_produced_execution_id_publishes_at_most_one_chain(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first = assemble_artifact_runtime(store, paths, execution_id=REPLAY_EXECUTION)
    _ = run_analysis(first, INTENT, spectrum_probe(), _approved(first))
    replay = assemble_artifact_runtime(store, paths, execution_id=REPLAY_EXECUTION)
    # A fresh plan and approval, so only the execution fence can refuse this.
    second_approval = _approved(replay)

    with pytest.raises(WorkbenchRunError) as rejection:
        _ = run_analysis(replay, INTENT, spectrum_probe(), second_approval)

    assert rejection.value.code is WorkbenchRejection.EXECUTION_REPLAYED
    assert _counts(paths) == (4, 4)
    assert _record(first)["state"] == "completed"
    assert _table_count(paths, "executions") == 1
    # The refused claim rolled back, so the second approval is still unspent.
    assert _consumed(store, replay, second_approval) is None


def test_persisted_versions_are_downloadable_within_their_scope(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    signed = runtime.service.issue_download(
        runtime.scope,
        run.csv.version.id,
        timedelta(minutes=1),
    )
    assert runtime.service.redeem_download(runtime.scope, signed.token) == (
        run.analysis.hypothesis_table_csv
    )


def _run_rows(paths: LocalPaths) -> list[tuple[object, ...]]:
    with closing(connect(paths.database)) as connection:
        return cast(
            "list[tuple[object, ...]]",
            connection.execute(
                "SELECT state, error_type, error_code FROM runs"
            ).fetchall(),
        )


def _assert_published_nothing(paths: LocalPaths) -> None:
    """Assert that no Artifact, Version, blob, or execution was created."""
    assert _counts(paths) == (0, 0)
    assert _blob_files(paths) == []
    assert _table_count(paths, "executions") == 0
    assert _table_count(paths, "run_outputs") == 0


def test_a_run_without_a_usable_approval_publishes_nothing(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)
    # Spend the approval on a different Run, so the one under test is holding
    # an approval that has already been used exactly once.
    spender = assemble_artifact_runtime(store, paths)
    _ = run_analysis(spender, INTENT, spectrum_probe(), approved)
    before = sorted(_blob_files(paths))

    with pytest.raises(PlanApprovalError) as refusal:
        _ = run_analysis(runtime, INTENT, spectrum_probe(), approved)

    assert refusal.value.outcome is ApprovalOutcome.REPLAYED
    # The first chain is untouched; the refused one added nothing at all.
    assert _counts(paths) == (4, 4)
    assert sorted(_blob_files(paths)) == before
    assert _table_count(paths, "executions") == 1
    assert _table_count(paths, "run_outputs") == 4
    assert read_run_record(paths, runtime.execution_id) is None
    assert ("failed", "PlanApprovalError", "replayed") in _run_rows(paths)


def test_editing_any_intent_field_invalidates_the_approval(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)
    assert EDITED_INTENT.sha256 != INTENT.sha256
    assert EDITED_INTENT.question == INTENT.question

    with pytest.raises(PlanApprovalError) as refusal:
        _ = run_analysis(runtime, EDITED_INTENT, spectrum_probe(), approved)

    assert refusal.value.outcome is ApprovalOutcome.DIGEST_MISMATCH
    _assert_published_nothing(paths)
    assert read_run_record(paths, runtime.execution_id) is None
    assert _run_rows(paths) == [("failed", "PlanApprovalError", "digest_mismatch")]
    # The approval was never spent, so the original intent still runs.
    assert _consumed(store, runtime, approved) is None
    honest = assemble_artifact_runtime(store, paths)
    run = run_analysis(honest, INTENT, spectrum_probe(), approved)
    assert len(run.outputs) == 4


def test_an_expired_approval_publishes_nothing(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = approve_analysis(runtime, INTENT, timedelta(microseconds=1))

    with pytest.raises(PlanApprovalError) as refusal:
        _ = run_analysis(runtime, INTENT, spectrum_probe(), approved)

    assert refusal.value.outcome is ApprovalOutcome.EXPIRED
    _assert_published_nothing(paths)
    assert _run_rows(paths) == [("failed", "PlanApprovalError", "expired")]
    assert _consumed(store, runtime, approved) is None


def test_a_completed_run_is_queryable_as_durable_rows(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)

    run = run_analysis(runtime, INTENT, spectrum_probe(), approved)

    row = store.run(runtime.scope, run.run_id)
    assert row is not None
    assert row.state.value == "completed"
    assert row.error_type is None
    assert row.plan_id == approved.plan.id
    assert row.approval_id == approved.approval.id
    assert row.requester_id == runtime.scope.requester_id
    execution = store.execution(runtime.scope, runtime.execution_id)
    assert execution is not None
    assert execution.run_id == run.run_id
    assert execution.execution_isolation == "in_process"
    assert execution.research_intent_sha256 == INTENT.sha256
    assert execution.input_sha256 == run.provenance.input_sha256
    outputs = store.run_outputs(runtime.scope, run.run_id)
    assert [item.sequence for item in outputs] == [1, 2, 3, 4]
    assert [item.role for item in outputs] == CHAIN_ROLES
    assert [item.artifact_version_id for item in outputs] == [
        item.version.id for item in run.outputs
    ]
    assert [item.content_sha256 for item in outputs] == [
        item.version.content_sha256 for item in run.outputs
    ]
    spent = store.plan_approval(runtime.scope, approved.approval.id)
    assert spent is not None
    assert spent.consumed_by_run_id == run.run_id
    assert store.unfinished_runs(runtime.scope) == ()


def test_a_truncated_chain_is_queryable_as_a_failed_run(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)
    original = store.commit_version
    calls = 0

    def failing_commit(
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        nonlocal calls
        calls += 1
        if calls == len(CHAIN_ROLES):
            raise ArtifactCommitError
        return original(scope, base_version_no, version, payload)

    monkeypatch.setattr(store, "commit_version", failing_commit)

    with pytest.raises(ArtifactCommitError):
        _ = run_analysis(runtime, INTENT, spectrum_probe(), approved)

    monkeypatch.undo()
    execution = store.execution(runtime.scope, runtime.execution_id)
    assert execution is not None
    row = store.run(runtime.scope, execution.run_id)
    assert row is not None
    assert row.state.value == "failed"
    assert row.error_type == "ArtifactCommitError"
    outputs = store.run_outputs(runtime.scope, execution.run_id)
    assert [item.sequence for item in outputs] == [1, 2, 3]
    assert [item.role for item in outputs] == ["csv", "png", "markdown"]
    # The queryable rows and the mirrored file tell the same truncation story.
    record = _record(runtime)
    assert record["state"] == "failed"
    assert record["run_id"] == str(execution.run_id)
    assert _committed_roles(record) == ["csv", "png", "markdown"]
    assert store.unfinished_runs(runtime.scope) == ()


def test_the_mirror_pins_the_plan_and_approval_that_authorized_the_chain(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)

    run = run_analysis(runtime, INTENT, spectrum_probe(), approved)

    record = _record(runtime)
    assert record["schema"] == "nipo.local.run-record.v2"
    assert record["run_id"] == str(run.run_id)
    assert record["action_plan_id"] == str(approved.plan.id)
    assert record["plan_approval_id"] == str(approved.approval.id)
    assert record["action_plan_sha256"] == approved.plan.plan_sha256
    assert record["research_intent_sha256"] == INTENT.sha256
    assert record["execution_isolation"] == "in_process"
    entries = cast("list[dict[str, object]]", record["committed_outputs"])
    stored = store.run_outputs(runtime.scope, run.run_id)
    assert [entry["version_id"] for entry in entries] == [
        str(item.artifact_version_id) for item in stored
    ]
    assert [entry["sequence"] for entry in entries] == [
        item.sequence for item in stored
    ]


def test_a_pre_existing_mirror_refuses_the_run_and_marks_it_failed(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)
    directory = paths.root / "runs"
    directory.mkdir(parents=True, exist_ok=True)
    foreign = run_record_path(paths, runtime.execution_id)
    _ = foreign.write_bytes(b'{"schema":"foreign"}')

    with pytest.raises(WorkbenchRunError) as rejection:
        _ = run_analysis(runtime, INTENT, spectrum_probe(), approved)

    assert rejection.value.code is WorkbenchRejection.EXECUTION_REPLAYED
    # A mirror belonging to another execution is never written over.
    assert foreign.read_bytes() == b'{"schema":"foreign"}'
    assert _counts(paths) == (0, 0)
    assert _blob_files(paths) == []
    assert _table_count(paths, "run_outputs") == 0
    assert _run_rows(paths) == [("failed", "WorkbenchRunError", "execution_replayed")]
    assert _consumed(store, runtime, approved) is not None


def test_an_approval_binds_exactly_one_immutable_plan_and_requester(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    plan = create_action_plan(runtime, INTENT)
    approval = approve_action_plan(runtime, plan)

    assert isinstance(plan, ActionPlanRecord)
    assert isinstance(approval, PlanApprovalRecord)
    assert plan.research_intent_sha256 == INTENT.sha256
    assert plan.requester_id == runtime.scope.requester_id
    assert approval.approver_id == plan.requester_id
    assert approval.plan_sha256 == plan.plan_sha256
    assert approval.consumed_at is None
    assert approval.expires_at > approval.granted_at

    with pytest.raises(ActionPlanError) as refusal:
        _ = approve_action_plan(runtime, plan)

    assert refusal.value.code is WorkbenchRejection.APPROVAL_REJECTED
    assert refusal.value.outcome is StoreOutcome.ASSOCIATION_EXISTS
    assert _table_count(paths, "plan_approvals") == 1


def _fail_at_blob_directory(store: LocalArtifactStore, paths: LocalPaths) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    paths.blobs.chmod(0o500)
    try:
        with pytest.raises(ArtifactStoreError):
            _ = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))
    finally:
        paths.blobs.chmod(0o700)


def _fail_at_ledger(store: LocalArtifactStore, paths: LocalPaths) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)
    original = store.commit_version
    calls = 0

    def failing_commit(
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        nonlocal calls
        calls += 1
        if calls == len(CHAIN_ROLES):
            raise ArtifactCommitError
        return original(scope, base_version_no, version, payload)

    store.commit_version = failing_commit  # type: ignore[method-assign]
    try:
        with pytest.raises(ArtifactCommitError):
            _ = run_analysis(runtime, INTENT, spectrum_probe(), approved)
    finally:
        del store.commit_version  # type: ignore[method-assign]


def _fail_at_archive(store: LocalArtifactStore, paths: LocalPaths) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)
    original = store.commit_version
    calls = 0

    def archiving_commit(
        scope: ArtifactScope,
        base_version_no: int,
        version: ArtifactVersion,
        payload: bytes,
    ) -> StoreOutcome:
        nonlocal calls
        outcome = original(scope, base_version_no, version, payload)
        calls += 1
        if calls == 2:
            store.archive_project(runtime.scope)
        return outcome

    store.commit_version = archiving_commit  # type: ignore[method-assign]
    try:
        with pytest.raises(ArtifactError):
            _ = run_analysis(runtime, INTENT, spectrum_probe(), approved)
    finally:
        del store.commit_version  # type: ignore[method-assign]


def _fail_at_registration(store: LocalArtifactStore, paths: LocalPaths) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)
    original = runtime.watcher.register
    calls = 0

    def failing_register(
        scope: ArtifactScope,
        execution_id: UUID,
        payload: bytes,
        media_type: str,
    ) -> str:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
        return original(scope, execution_id, payload, media_type)

    runtime.watcher.register = failing_register  # type: ignore[method-assign]
    with pytest.raises(ArtifactError):
        _ = run_analysis(runtime, INTENT, spectrum_probe(), approved)


def _fail_at_mirror(store: LocalArtifactStore, paths: LocalPaths) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)
    directory = paths.root / "runs"
    directory.mkdir(parents=True, exist_ok=True)
    _ = run_record_path(paths, runtime.execution_id).write_bytes(b"{}")
    with pytest.raises(WorkbenchRunError):
        _ = run_analysis(runtime, INTENT, spectrum_probe(), approved)


def _fail_at_approval(store: LocalArtifactStore, paths: LocalPaths) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    approved = _approved(runtime)
    with pytest.raises(PlanApprovalError):
        _ = run_analysis(runtime, EDITED_INTENT, spectrum_probe(), approved)


def test_no_failure_path_leaves_a_run_unmarked(tmp_path: Path) -> None:
    injections = (
        _fail_at_approval,
        _fail_at_mirror,
        _fail_at_blob_directory,
        _fail_at_registration,
        _fail_at_ledger,
        _fail_at_archive,
    )

    for index, inject in enumerate(injections):
        paths = resolve_paths(tmp_path / f"install-{index}")
        with LocalArtifactStore(paths) as store:
            inject(store, paths)

            # The invariant under test: whatever escaped, the Run is terminal
            # in the durable authority, so no chain is left looking live.
            assert store.unfinished_runs(local_scope()) == ()
            states = {row[0] for row in _run_rows(paths)}
            assert states == {"failed"}


def test_a_plan_for_a_different_intent_carries_a_different_digest(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)

    original = create_action_plan(runtime, INTENT)
    edited = create_action_plan(runtime, EDITED_INTENT)

    assert original.research_intent_sha256 != edited.research_intent_sha256
    assert original.plan_sha256 != edited.plan_sha256
    assert _table_count(paths, "action_plans") == 2
    stored = store.action_plan(runtime.scope, original.id)
    assert stored == original


# ------------------------------------------- sessions and canonical inputs --
#
# Two provenance gaps were disclosed rather than hidden: a Run carried no
# Session, so a published Version's ownership chain stopped one step short of
# the Session it would be attached to, and only the digests of the
# `ResearchIntent` and the scientific input were stored, so neither document
# could travel in an Export Pack. These tests drive the producing path that
# closes both.


def _live_session(runtime: LocalArtifactRuntime, session_id: UUID) -> None:
    """Register one live Session in this runtime's Project."""
    assert runtime.store.create_session(
        runtime.scope,
        SessionRecord(
            id=session_id,
            org_id=runtime.scope.org_id,
            project_id=runtime.scope.project_id,
            title="probe review",
            created_at=CALIBRATED_AT,
            last_active_at=CALIBRATED_AT,
        ),
    ) is (StoreOutcome.CREATED)


def _link_to(
    runtime: LocalArtifactRuntime, session_id: UUID, version_id: UUID
) -> SessionArtifactLink:
    """Build one association request for this runtime's Project."""
    return SessionArtifactLink(
        org_id=runtime.scope.org_id,
        project_id=runtime.scope.project_id,
        session_id=session_id,
        artifact_version_id=version_id,
        revision=1,
        created_at=CALIBRATED_AT,
    )


def test_a_run_binds_its_versions_to_the_session_it_was_assembled_with(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # End to end: the runtime names a Session, the Run records it, and every
    # Version the run published can then be associated with exactly that
    # Session. Before this the last link did not exist and the association was
    # refused for every Version the workbench produced.
    session_id = UUID("018f47a0-7b9c-7ccc-8def-0123456789ab")
    runtime = assemble_artifact_runtime(store, paths)
    _live_session(runtime, session_id)
    bound = assemble_artifact_runtime(store, paths, session_id=session_id)

    run = run_analysis(bound, INTENT, spectrum_probe(), _approved(bound))

    row = store.run(bound.scope, run.run_id)
    assert row is not None
    assert row.session_id == UUID("018f47a0-7b9c-7ccc-8def-0123456789ab")
    for record in run.outputs:
        assert store.attach_session(
            bound.scope,
            _link_to(bound, session_id, record.version.id),
        ) is (StoreOutcome.CREATED)
    assert runtime.session_id is None


def test_a_run_assembled_without_a_session_still_publishes_its_chain(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Running outside any Session is a supported local workflow and must keep
    # working. What it cannot do is acquire an association afterwards: the
    # ownership chain has no last link, and absence is refused rather than
    # read as agreement with whatever Session is offered.
    session_id = UUID("018f47a0-7b9c-7ccc-8def-0123456789ab")
    runtime = assemble_artifact_runtime(store, paths)
    _live_session(runtime, session_id)

    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    assert [item.role for item in run.outputs] == CHAIN_ROLES
    row = store.run(runtime.scope, run.run_id)
    assert row is not None
    assert row.session_id is None
    assert store.attach_session(
        runtime.scope,
        _link_to(runtime, session_id, run.csv.version.id),
    ) is (StoreOutcome.NOT_FOUND)


def test_a_run_naming_an_unusable_session_publishes_nothing(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The Session is never registered, so queuing the Run is refused before any
    # Artifact identity, Version, blob, or mirror exists and the approval stays
    # unspent.
    runtime = assemble_artifact_runtime(
        store,
        paths,
        session_id=UUID("018f47a0-7b9c-7ccc-8def-0123456789ab"),
    )
    approved = _approved(runtime)

    with pytest.raises(ActionPlanError) as rejection:
        _ = run_analysis(runtime, INTENT, spectrum_probe(), approved)

    assert rejection.value.code is WorkbenchRejection.RUN_REJECTED
    assert rejection.value.outcome is StoreOutcome.NOT_FOUND
    assert _counts(paths) == (0, 0)
    assert _table_count(paths, "runs") == 0
    assert _blob_files(paths) == []
    assert read_run_record(paths, runtime.execution_id) is None
    assert _consumed(store, runtime, approved) is None


def test_a_run_persists_the_canonical_intent_and_input_bytes(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The bytes are recomputed here from the primary sources -- the intent
    # object and the input object -- rather than read back out of the producer,
    # and they are checked against the digests the execution pinned. A reader
    # holding only these two documents can now recompute both digests, which is
    # exactly what a pack could not offer before.
    runtime = assemble_artifact_runtime(store, paths)
    source = spectrum_probe()

    run = run_analysis(runtime, INTENT, source, _approved(runtime))

    intent_bytes = store.execution_input(
        runtime.scope,
        runtime.execution_id,
        ExecutionInputKind.RESEARCH_INTENT,
    )
    input_bytes = store.execution_input(
        runtime.scope,
        runtime.execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
    )
    assert intent_bytes == INTENT.canonical_bytes
    assert input_bytes == source.model_dump_json().encode()
    assert intent_bytes is not None
    assert input_bytes is not None
    assert (
        hashlib.sha256(intent_bytes).hexdigest()
        == run.provenance.research_intent_sha256
    )
    assert hashlib.sha256(input_bytes).hexdigest() == run.provenance.input_sha256
    execution = store.execution(runtime.scope, runtime.execution_id)
    assert execution is not None
    assert hashlib.sha256(intent_bytes).hexdigest() == execution.research_intent_sha256
    assert hashlib.sha256(input_bytes).hexdigest() == execution.input_sha256
    assert _table_count(paths, "execution_inputs") == 2


def test_a_correction_persists_the_corrected_input_under_its_own_execution(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A correction is a run in every respect, so it records its own canonical
    # bytes against its own execution and leaves the earlier ones untouched.
    first_runtime = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        first_runtime,
        INTENT,
        spectrum_probe(),
        _approved(first_runtime),
    )

    second_runtime, corrected = _corrected(store, paths, original)

    first = store.execution_input(
        first_runtime.scope,
        first_runtime.execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
    )
    second = store.execution_input(
        second_runtime.scope,
        second_runtime.execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
    )
    assert first == spectrum_probe().model_dump_json().encode()
    assert second == (
        spectrum_probe(calibration_sha256="d" * 64).model_dump_json().encode()
    )
    assert first != second
    assert second is not None
    assert hashlib.sha256(second).hexdigest() == corrected.provenance.input_sha256
    assert _table_count(paths, "execution_inputs") == 4


def test_a_refused_input_record_fails_the_run_before_anything_is_published(
    store: LocalArtifactStore,
    paths: LocalPaths,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A chain that quietly continued would publish four Versions whose two most
    # important digests silently stay self-reported in every pack. It must stop
    # instead, and it stops before the first Artifact identity exists.
    runtime = assemble_artifact_runtime(store, paths)

    def refusing_record(
        scope: ArtifactScope,
        execution_id: UUID,
        kind: ExecutionInputKind,
        payload: bytes,
    ) -> StoreOutcome:
        del scope, execution_id, kind, payload
        return StoreOutcome.INVALID_LINEAGE

    monkeypatch.setattr(store, "record_execution_input", refusing_record)

    with pytest.raises(ArtifactStoreError):
        _ = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    record = _record(runtime)
    assert record["state"] == "failed"
    assert _committed_roles(record) == []
    assert cast("dict[str, object]", record["failure"])["error"] == "RunRecordError"
    assert cast("dict[str, object]", record["failure"])["code"] == "invalid_lineage"
    assert _counts(paths) == (0, 0)
    assert _blob_files(paths) == []
    assert _table_count(paths, "execution_inputs") == 0


def test_the_persisted_input_bytes_are_the_ones_the_digest_was_taken_over(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A changed measurement byte moves the pinned digest, and the bytes stored
    # beside it move with it. If the producer serialized twice and the two
    # calls could disagree, this is where that would show.
    runtime = assemble_artifact_runtime(store, paths)
    edited = spectrum_probe(calibration_sha256="d" * 64)

    run = run_analysis(runtime, INTENT, edited, _approved(runtime))

    stored = store.execution_input(
        runtime.scope,
        runtime.execution_id,
        ExecutionInputKind.SCIENTIFIC_INPUT,
    )
    assert stored == edited.model_dump_json().encode()
    assert stored != spectrum_probe().model_dump_json().encode()
    assert stored is not None
    assert hashlib.sha256(stored).hexdigest() == run.provenance.input_sha256


# ------------------------------------------------------------- corrections --
#
# `_publish` always passed `base_version_no=0` and minted a fresh Artifact per
# output, so the CAS versioning `store.py` fully supports was never exercised
# by a producer: every Artifact in the product had exactly one Version. These
# tests cover the path that produces Version 2 and, above all, that producing
# it leaves Version 1 byte-identical.


def _corrected(
    store: LocalArtifactStore,
    paths: LocalPaths,
    original: WorkbenchRun,
) -> tuple[LocalArtifactRuntime, WorkbenchRun]:
    """Re-run the analysis against corrected input and publish Version 2."""
    runtime = assemble_artifact_runtime(store, paths)
    targets = correction_targets(store, runtime.scope, original.run_id)
    corrected = correct_analysis(
        runtime,
        INTENT,
        spectrum_probe(calibration_sha256="d" * 64),
        _approved(runtime),
        targets,
    )
    return runtime, corrected


def test_a_correction_commits_version_two_of_the_same_artifacts(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_runtime = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        first_runtime,
        INTENT,
        spectrum_probe(),
        _approved(first_runtime),
    )

    _, corrected = _corrected(store, paths, original)

    assert [item.version.version_no for item in original.outputs] == [1, 1, 1, 1]
    assert [item.version.version_no for item in corrected.outputs] == [2, 2, 2, 2]
    assert [item.artifact.id for item in corrected.outputs] == [
        item.artifact.id for item in original.outputs
    ]
    assert [item.role for item in corrected.outputs] == CHAIN_ROLES
    # Four Artifacts, eight Versions: a correction extends a lineage rather
    # than starting a parallel one.
    assert _counts(paths) == (4, 8)


def test_a_correction_leaves_version_one_byte_identical(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_runtime = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        first_runtime,
        INTENT,
        spectrum_probe(),
        _approved(first_runtime),
    )
    before = {
        item.role: _read(first_runtime, item.version.id) for item in original.outputs
    }

    _, corrected = _corrected(store, paths, original)

    for item in original.outputs:
        version, payload = _read(first_runtime, item.version.id)
        recorded, original_payload = before[item.role]
        # The bytes, the digest, the size, and the whole Version row are
        # unchanged. A correction is a new Version, never an overwrite.
        assert payload == original_payload
        assert hashlib.sha256(payload).hexdigest() == item.version.content_sha256
        assert version == recorded == item.version
        assert version.version_no == 1
    # The corrected input really produced different bytes, so the preserved
    # digests are a real preservation rather than an accidental match.
    changed = {item.role: item.version.content_sha256 for item in corrected.outputs}
    kept = {item.role: item.version.content_sha256 for item in original.outputs}
    assert changed["ledger"] != kept["ledger"]
    assert changed["markdown"] != kept["markdown"]


def test_a_correction_is_a_new_run_and_a_new_execution(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_runtime = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        first_runtime,
        INTENT,
        spectrum_probe(),
        _approved(first_runtime),
    )

    second_runtime, corrected = _corrected(store, paths, original)

    assert corrected.run_id != original.run_id
    assert second_runtime.execution_id != first_runtime.execution_id
    assert _table_count(paths, "runs") == 2
    assert _table_count(paths, "executions") == 2
    assert _table_count(paths, "run_outputs") == 8
    assert store.unfinished_runs(local_scope()) == ()
    for identifier in (original.run_id, corrected.run_id):
        record = store.run(local_scope(), identifier)
        assert record is not None
        assert record.state.value == "completed"
    # Both chains are separately readable, which is what makes the correction
    # auditable rather than a silent replacement.
    assert _record(second_runtime)["state"] == "completed"
    assert _record(first_runtime)["state"] == "completed"


def test_a_correction_records_its_own_provenance_on_version_two(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_runtime = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        first_runtime,
        INTENT,
        spectrum_probe(),
        _approved(first_runtime),
    )

    second_runtime, corrected = _corrected(store, paths, original)

    assert corrected.provenance.input_sha256 != original.provenance.input_sha256
    for item in corrected.outputs:
        assert item.version.producing_execution_id == second_runtime.execution_id
        assert item.version.source_hashes == (
            corrected.provenance.input_sha256,
            INTENT.sha256,
        )
    ledger = _ledger_of(second_runtime, corrected.ledger.version.id)
    assert ledger["producing_execution_id"] == str(second_runtime.execution_id)
    assert ledger["input_sha256"] == corrected.provenance.input_sha256
    # The ledger pins the three outputs committed before it, each at Version 2.
    entries = cast("list[dict[str, object]]", ledger["outputs"])
    assert [entry["role"] for entry in entries] == ["csv", "png", "markdown"]
    assert [entry["version_no"] for entry in entries] == [2, 2, 2]
    assert [entry["version_id"] for entry in entries] == [
        str(item.version.id) for item in corrected.outputs[:3]
    ]


def test_a_correction_against_a_stale_base_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Two corrections of the same Version cannot both win: the second is a
    # compare-and-swap against a base that is no longer the head.
    first_runtime = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        first_runtime,
        INTENT,
        spectrum_probe(),
        _approved(first_runtime),
    )
    stale = correction_targets(store, first_runtime.scope, original.run_id)
    _ = _corrected(store, paths, original)

    third = assemble_artifact_runtime(store, paths)
    with pytest.raises(ArtifactError) as raised:
        _ = correct_analysis(
            third,
            INTENT,
            spectrum_probe(calibration_sha256="e" * 64),
            _approved(third),
            stale,
        )

    assert raised.value.code is ArtifactErrorCode.STALE_BASE
    # The refused correction published nothing and left the lineage at two.
    assert _counts(paths) == (4, 8)
    assert store.unfinished_runs(local_scope()) == ()


def test_a_partial_correction_is_refused_before_anything_is_claimed(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A correction of some outputs would leave the Artifact set describing two
    # different executions at once -- a corrected CSV beside an uncorrected
    # report.
    first_runtime = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        first_runtime,
        INTENT,
        spectrum_probe(),
        _approved(first_runtime),
    )
    targets = correction_targets(store, first_runtime.scope, original.run_id)

    second = assemble_artifact_runtime(store, paths)
    approved = _approved(second)
    with pytest.raises(CorrectionTargetError) as raised:
        _ = correct_analysis(
            second,
            INTENT,
            spectrum_probe(calibration_sha256="d" * 64),
            approved,
            targets[:3],
        )

    assert raised.value.code is WorkbenchRejection.CORRECTION_INCOMPLETE
    assert _counts(paths) == (4, 4)
    assert _table_count(paths, "runs") == 1
    assert _table_count(paths, "executions") == 1
    # The approval was not spent, so the researcher can retry with a whole set.
    assert _consumed(store, second, approved) is None


def test_a_correction_naming_an_unknown_artifact_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_runtime = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        first_runtime,
        INTENT,
        spectrum_probe(),
        _approved(first_runtime),
    )
    targets = correction_targets(store, first_runtime.scope, original.run_id)
    invented = (
        CorrectionTarget(
            role=targets[0].role,
            artifact_id=UUID("018f47a0-7b9c-7ccc-8def-0123456789ab"),
            base_version_no=1,
        ),
        *targets[1:],
    )

    second = assemble_artifact_runtime(store, paths)
    with pytest.raises(CorrectionTargetError) as raised:
        _ = correct_analysis(
            second,
            INTENT,
            spectrum_probe(calibration_sha256="d" * 64),
            approve_analysis(second, INTENT),
            invented,
        )

    assert raised.value.code is WorkbenchRejection.CORRECTION_TARGET_MISSING
    # No parallel Artifact was minted to stand in for the missing one.
    assert _counts(paths)[0] == 4


def test_correction_targets_read_the_versions_the_run_recorded(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime = assemble_artifact_runtime(store, paths)
    run = run_analysis(runtime, INTENT, spectrum_probe(), _approved(runtime))

    targets = correction_targets(store, runtime.scope, run.run_id)

    assert [item.role for item in targets] == CHAIN_ROLES
    assert [item.artifact_id for item in targets] == [
        item.artifact.id for item in run.outputs
    ]
    assert [item.base_version_no for item in targets] == [1, 1, 1, 1]


def test_a_correction_can_itself_be_corrected(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_runtime = assemble_artifact_runtime(store, paths)
    original = run_analysis(
        first_runtime,
        INTENT,
        spectrum_probe(),
        _approved(first_runtime),
    )
    _, second = _corrected(store, paths, original)

    third_runtime = assemble_artifact_runtime(store, paths)
    third = correct_analysis(
        third_runtime,
        INTENT,
        spectrum_probe(calibration_sha256="e" * 64),
        _approved(third_runtime),
        correction_targets(store, third_runtime.scope, second.run_id),
    )

    assert [item.version.version_no for item in third.outputs] == [3, 3, 3, 3]
    assert _counts(paths) == (4, 12)
    # Every earlier Version is still readable at its own digest.
    for run in (original, second):
        for item in run.outputs:
            version, payload = _read(first_runtime, item.version.id)
            assert hashlib.sha256(payload).hexdigest() == item.version.content_sha256
            assert version.version_no == item.version.version_no
