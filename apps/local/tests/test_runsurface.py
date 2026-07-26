"""Tests for the Run surface bound to the durable `runs` tables.

The seam existed and answered `501`; the rows existed and were never read.
These tests exercise the join over a real store and a real published chain,
and they assert typed fields rather than substrings of messages -- a message
carrying `tmp_path` contains this test's own function name and has produced
false passes elsewhere in this repository.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast
from uuid import UUID

import pytest
from services.api.artifacts.models import ArtifactScope

from nipo_local.config import DEFAULT_PROJECT_ID, LocalPaths, resolve_paths
from nipo_local.runsurface import StoreRunSurface, run_projection
from nipo_local.store import (
    LocalArtifactStore,
    RunCompletion,
    RunRecord,
    RunState,
)
from nipo_local.workbench import (
    LocalArtifactRuntime,
    WorkbenchRun,
    approve_analysis,
    assemble_artifact_runtime,
    local_scope,
    run_analysis,
)
from science_workbench_science import (
    CalibrationMetadata,
    DataOrigin,
    InputMetadata,
    MeasurementUnit,
    ProbeInput,
    ResearchIntent,
    ResearchMode,
    SpectrumInput,
)

WAVELENGTHS: Final = (400.0, 410.0, 420.0, 430.0, 440.0, 450.0, 460.0)
INTENSITIES: Final = (0.10, 0.35, 0.20, 0.55, 0.25, 0.30, 0.15)
CALIBRATED_AT: Final = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
ABSENT_EXECUTION: Final = UUID("018f47a0-7b9c-7fff-8def-0123456789ab")

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


def probe(wavelengths: tuple[float, ...] = WAVELENGTHS) -> ProbeInput:
    """Build the calibrated spectrum these tests analyse."""
    return ProbeInput(
        spectrum=SpectrumInput(
            wavelengths=wavelengths,
            intensities=INTENSITIES,
            metadata=InputMetadata(
                units=(
                    MeasurementUnit(quantity="wavelength", ucum_code="nm"),
                    MeasurementUnit(quantity="intensity", ucum_code="1"),
                ),
                calibration=CalibrationMetadata(
                    method="two-point-standard",
                    reference="NIST-SRM-2242",
                    calibrated_at=CALIBRATED_AT,
                    calibration_sha256="c" * 64,
                ),
                lineage_version_ids=(UUID("018f47a0-7b9c-7aaa-8def-0123456789ab"),),
                research_only=True,
                non_clinical=True,
            ),
        )
    )


@pytest.fixture(name="paths")
def paths_fixture(tmp_path: Path) -> LocalPaths:
    return resolve_paths(tmp_path)


@pytest.fixture(name="store")
def store_fixture(paths: LocalPaths) -> Iterator[LocalArtifactStore]:
    with LocalArtifactStore(paths) as opened:
        yield opened


def published(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> tuple[LocalArtifactRuntime, WorkbenchRun]:
    """Publish one real four-output chain and return it."""
    runtime = assemble_artifact_runtime(store, paths)
    approved = approve_analysis(runtime, INTENT)
    return runtime, run_analysis(runtime, INTENT, probe(), approved)


def test_a_published_run_projects_its_state_and_ordered_outputs(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)
    surface = StoreRunSurface(store)

    record = surface.read_run(runtime.scope, run.run_id)

    assert record is not None
    assert record["state"] == "completed"
    assert record["run_id"] == str(run.run_id)
    assert record["producing_execution_id"] == str(runtime.execution_id)
    assert record["failure"] is None
    outputs = cast("list[dict[str, object]]", record["committed_outputs"])
    assert [item["sequence"] for item in outputs] == [1, 2, 3, 4]
    assert [item["role"] for item in outputs] == ["csv", "png", "markdown", "ledger"]
    assert [item["content_sha256"] for item in outputs] == [
        item.version.content_sha256 for item in run.outputs
    ]
    assert [item["version_id"] for item in outputs] == [
        str(item.version.id) for item in run.outputs
    ]


def test_the_projection_reports_the_digests_the_execution_pinned(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)
    surface = StoreRunSurface(store)

    record = surface.read_run(runtime.scope, run.run_id)

    assert record is not None
    assert record["input_sha256"] == run.provenance.input_sha256
    assert record["code_sha256"] == run.provenance.code_sha256
    assert record["environment_sha256"] == run.provenance.environment_sha256
    assert record["research_intent_sha256"] == INTENT.sha256


def test_the_projection_discloses_the_recorded_isolation_verbatim(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)
    surface = StoreRunSurface(store)

    record = surface.read_run(runtime.scope, run.run_id)

    assert record is not None
    assert record["execution_isolation"] == "in_process"
    assert surface.execution_isolation(runtime.scope, runtime.execution_id) == (
        "in_process"
    )


def test_an_execution_this_installation_cannot_answer_for_reports_none(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A null must stay reachable with the surface bound: the front end renders
    # its "assume nothing" disclosure for it, and defaulting to `in_process`
    # here would be a fabricated confinement claim.
    runtime, _ = published(store, paths)
    surface = StoreRunSurface(store)

    assert surface.execution_isolation(runtime.scope, ABSENT_EXECUTION) is None


def test_a_run_that_never_claimed_an_execution_reports_no_isolation(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope = local_scope(DEFAULT_PROJECT_ID)
    runtime, _ = published(store, paths)
    moment = datetime.now(UTC)
    queued = RunRecord(
        id=runtime.ids.new_uuid7(),
        org_id=scope.org_id,
        project_id=scope.project_id,
        plan_id=runtime.ids.new_uuid7(),
        approval_id=runtime.ids.new_uuid7(),
        requester_id=scope.requester_id,
        state=RunState.QUEUED,
        research_intent_sha256=INTENT.sha256,
        created_at=moment,
        updated_at=moment,
    )
    projection = run_projection(queued, None, ())

    assert projection["execution_isolation"] is None
    assert projection["producing_execution_id"] is None
    assert projection["input_sha256"] is None
    assert projection["committed_outputs"] == []


def test_a_failed_run_is_listed_beside_a_completed_one(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A listing that showed only completed chains would hide exactly the
    # truncation the Run record exists to make visible.
    runtime, completed = published(store, paths)
    dead = _dead_run(store, paths)

    listed = StoreRunSurface(store).list_runs(runtime.scope)

    states = {str(item["run_id"]): item["state"] for item in listed}
    assert states[str(dead)] == "failed"
    assert states[str(completed.run_id)] == "completed"
    failed = next(item for item in listed if item["run_id"] == str(dead))
    assert failed["failure"] == {"error": "ArtifactStoreError", "code": "blocked"}
    # It never claimed an execution, so it discloses no isolation and no
    # digests rather than borrowing the completed run's.
    assert failed["execution_isolation"] is None
    assert failed["producing_execution_id"] is None
    assert failed["committed_outputs"] == []


def _dead_run(store: LocalArtifactStore, paths: LocalPaths) -> UUID:
    """Queue one Run against a real approval and close it `failed`."""
    runtime = assemble_artifact_runtime(store, paths)
    approved = approve_analysis(runtime, INTENT)
    moment = datetime.now(UTC)
    run = RunRecord(
        id=runtime.ids.new_uuid7(),
        org_id=runtime.scope.org_id,
        project_id=runtime.scope.project_id,
        plan_id=approved.plan.id,
        approval_id=approved.approval.id,
        requester_id=runtime.scope.requester_id,
        state=RunState.QUEUED,
        research_intent_sha256=INTENT.sha256,
        created_at=moment,
        updated_at=moment,
    )
    assert str(store.create_run(runtime.scope, run)) == "created"
    outcome = store.finish_run(
        runtime.scope,
        RunCompletion(
            run_id=run.id,
            state=RunState.FAILED,
            finished_at=moment,
            error_type="ArtifactStoreError",
            error_code="blocked",
        ),
    )
    assert str(outcome) == "created"
    return run.id


def test_listing_is_newest_first(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, first = published(store, paths)
    second_runtime = assemble_artifact_runtime(store, paths)
    second = run_analysis(
        second_runtime,
        INTENT,
        probe((405.0, 415.0, 425.0, 435.0, 445.0, 455.0, 465.0)),
        approve_analysis(second_runtime, INTENT),
    )

    listed = StoreRunSurface(store).list_runs(runtime.scope)

    assert [item["run_id"] for item in listed] == [
        str(second.run_id),
        str(first.run_id),
    ]


def test_an_unknown_run_is_none_rather_than_an_empty_projection(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, _ = published(store, paths)

    assert StoreRunSurface(store).read_run(runtime.scope, ABSENT_EXECUTION) is None


def test_a_run_of_another_project_is_not_visible(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)
    other = ArtifactScope(
        org_id=runtime.scope.org_id,
        project_id=UUID("01900000-0000-7000-8000-00000000000f"),
        requester_id=runtime.scope.requester_id,
    )

    surface = StoreRunSurface(store)

    assert surface.read_run(other, run.run_id) is None
    assert surface.list_runs(other) == ()


def test_the_surface_exposes_no_write_capability(
    store: LocalArtifactStore,
) -> None:
    # Structural, not conventional: binding the Run surface must not turn a
    # read of a Run into a way to write one.
    surface = StoreRunSurface(store)

    reachable = {name for name in dir(surface) if not name.startswith("_")}
    assert reachable == {"execution_isolation", "list_runs", "read_run"}
    for forbidden in (
        "create_run",
        "start_run",
        "finish_run",
        "commit_version",
        "append_run_output",
        "open_review",
    ):
        assert not hasattr(surface, forbidden)
