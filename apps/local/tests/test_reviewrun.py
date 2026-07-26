"""Tests for persisting one trace-only Review over a real published chain.

`reviewer.py` was complete and `store.py` could persist a Review; nothing
joined them. These tests exercise that join against a real store and a real
run, and assert typed fields rather than message substrings.
"""

from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path
from typing import Final
from uuid import UUID

import pytest
from services.api.artifacts.runtime import SystemClock, Uuid7Factory

from nipo_local.config import LocalPaths, resolve_paths
from nipo_local.reviewer import RULE_COVERAGE, IdentifierResolution, summary_verdict
from nipo_local.reviewrun import (
    ReviewJob,
    ReviewRejection,
    ReviewRejectionError,
    persisted_review,
    review_run,
)
from nipo_local.store import (
    LocalArtifactStore,
    ReviewVerdict,
)
from nipo_local.workbench import (
    LocalArtifactRuntime,
    WorkbenchRun,
    approve_analysis,
    assemble_artifact_runtime,
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
ABSENT_RUN: Final = UUID("018f47a0-7b9c-7fff-8def-0123456789ab")
RULE_IDS: Final = ["RV01", "RV02", "RV03", "RV04", "RV05"]

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
    wavelengths: tuple[float, ...] = WAVELENGTHS,
) -> tuple[LocalArtifactRuntime, WorkbenchRun]:
    """Publish one real four-output chain and return it."""
    runtime = assemble_artifact_runtime(store, paths)
    approved = approve_analysis(runtime, INTENT)
    return runtime, run_analysis(runtime, INTENT, probe(wavelengths), approved)


def job(store: LocalArtifactStore, runtime: LocalArtifactRuntime) -> ReviewJob:
    """Bind one Review to the store, scope, ids, and clock it needs."""
    return ReviewJob(
        store=store,
        scope=runtime.scope,
        ids=Uuid7Factory(),
        clock=SystemClock(),
    )


def test_reviewing_a_run_records_one_finding_per_rule(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)

    persisted = review_run(job(store, runtime), run.run_id)

    assert [item.rule_id.value for item in persisted.findings] == RULE_IDS
    assert [item.sequence for item in persisted.findings] == [1, 2, 3, 4, 5]
    assert {item.status.value for item in persisted.findings} == {"open"}
    assert persisted.review.state.value == "completed"
    assert persisted.review.findings_submitted_at is not None
    assert persisted.review.source_run_id == run.run_id


def test_a_review_pins_exactly_the_versions_and_execution_the_run_committed(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)

    persisted = review_run(job(store, runtime), run.run_id)

    assert set(persisted.review.pinned_artifact_version_ids) == {
        item.version.id for item in run.outputs
    }
    assert persisted.review.pinned_execution_ids == (runtime.execution_id,)
    # The pins are stored sorted and duplicate-free, so no caller can reorder
    # the same evidence into a second digest.
    rendered = [str(value) for value in persisted.review.pinned_artifact_version_ids]
    assert rendered == sorted(set(rendered))


def test_the_pinned_digest_is_server_derived_from_those_pins(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)

    persisted = review_run(job(store, runtime), run.run_id)

    assert (
        persisted.review.pinned_input_sha256
        == LocalArtifactStore.pinned_input_digest(
            runtime.scope,
            run.run_id,
            persisted.review.pinned_artifact_version_ids,
            persisted.review.pinned_execution_ids,
        )
    )


def test_reviewing_twice_returns_the_same_review(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)

    first = review_run(job(store, runtime), run.run_id)
    second = review_run(job(store, runtime), run.run_id)

    assert second.review.id == first.review.id
    assert second.review.pinned_input_sha256 == first.review.pinned_input_sha256
    assert [item.id for item in second.findings] == [item.id for item in first.findings]


def test_two_different_runs_get_two_different_reviews(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    first_runtime, first = published(store, paths)
    second_runtime, second = published(
        store,
        paths,
        (405.0, 415.0, 425.0, 435.0, 445.0, 455.0, 465.0),
    )

    one = review_run(job(store, first_runtime), first.run_id)
    two = review_run(job(store, second_runtime), second.run_id)

    assert one.review.id != two.review.id
    assert one.review.pinned_input_sha256 != two.review.pinned_input_sha256


def test_rv02_is_inconclusive_offline_and_never_a_manufactured_pass(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)

    persisted = review_run(job(store, runtime), run.run_id)

    rv02 = next(item for item in persisted.findings if item.rule_id.value == "RV02")
    assert rv02.verdict in {ReviewVerdict.PASS, ReviewVerdict.INCONCLUSIVE}
    # The default resolver reaches nothing, so a `fail` here would be invented.
    assert rv02.verdict is not ReviewVerdict.FAIL
    assert str(IdentifierResolution.UNREACHABLE) == "unreachable"


def test_a_resolver_that_cannot_reach_anything_yields_inconclusive_not_pass(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    class Citing:
        """Answer every identifier as unreachable, as an offline machine does."""

        def resolve(self, identifier: object) -> IdentifierResolution:
            """Report the identifier as unreachable."""
            del identifier
            return IdentifierResolution.UNREACHABLE

    runtime, run = published(store, paths)

    persisted = review_run(
        ReviewJob(
            store=store,
            scope=runtime.scope,
            ids=Uuid7Factory(),
            clock=SystemClock(),
            resolver=Citing(),
        ),
        run.run_id,
    )

    rv02 = next(item for item in persisted.findings if item.rule_id.value == "RV02")
    assert rv02.verdict is not ReviewVerdict.FAIL


def test_the_summary_verdict_never_reports_pass_over_an_inconclusive(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)

    persisted = review_run(job(store, runtime), run.run_id)

    verdict = summary_verdict(item.verdict for item in persisted.findings)
    if any(item.verdict is ReviewVerdict.INCONCLUSIVE for item in persisted.findings):
        assert verdict is not ReviewVerdict.PASS
    assert summary_verdict(()) is ReviewVerdict.INCONCLUSIVE
    assert summary_verdict((ReviewVerdict.PASS, ReviewVerdict.INCONCLUSIVE)) is (
        ReviewVerdict.INCONCLUSIVE
    )
    assert summary_verdict((ReviewVerdict.WARN, ReviewVerdict.FAIL)) is (
        ReviewVerdict.FAIL
    )


def test_reading_a_review_before_one_exists_is_none_not_an_empty_pass(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # "No findings" must never be reachable as a way of saying "reviewed and
    # nothing was wrong".
    runtime, run = published(store, paths)

    assert persisted_review(store, runtime.scope, run.run_id) is None

    _ = review_run(job(store, runtime), run.run_id)
    found = persisted_review(store, runtime.scope, run.run_id)

    assert found is not None
    assert len(found.findings) == 5


def test_reading_is_idempotent_and_writes_nothing(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)
    first = review_run(job(store, runtime), run.run_id)

    one = persisted_review(store, runtime.scope, run.run_id)
    two = persisted_review(store, runtime.scope, run.run_id)

    assert one is not None
    assert two is not None
    assert one.review == two.review == first.review
    assert one.findings == two.findings


def test_reviewing_an_unknown_run_is_refused_with_a_typed_reason(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, _ = published(store, paths)

    with pytest.raises(ReviewRejectionError) as raised:
        _ = review_run(job(store, runtime), ABSENT_RUN)

    assert raised.value.reason is ReviewRejection.RUN_NOT_FOUND


def test_a_review_writes_no_version_and_leaves_the_chain_at_four(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    runtime, run = published(store, paths)
    before = [
        (item.version.id, item.version.content_sha256, item.version.version_no)
        for item in run.outputs
    ]

    _ = review_run(job(store, runtime), run.run_id)

    after = [store.version(runtime.scope, identifier) for identifier, _, _ in before]
    assert all(item is not None for item in after)
    assert [
        (item.id, item.content_sha256, item.version_no)
        for item in after
        if item is not None
    ] == before
    assert len(store.run_outputs(runtime.scope, run.run_id)) == 4


def test_every_rule_publishes_both_what_it_checked_and_what_it_did_not() -> None:
    # A rule whose limits were empty would let a surface present a narrow
    # check as a broad one without any code changing.
    assert [item.rule_id.value for item in RULE_COVERAGE] == RULE_IDS
    for item in RULE_COVERAGE:
        assert item.statement.strip() != ""
        assert len(item.checks) >= 1
        assert len(item.limits) >= 1
        assert all(line.strip() != "" for line in item.checks)
        assert all(line.strip() != "" for line in item.limits)


def test_the_two_structurally_limited_rules_say_what_they_cannot_establish() -> None:
    coverage = {item.rule_id.value: item for item in RULE_COVERAGE}

    rv01 = " ".join(coverage["RV01"].limits)
    rv02 = " ".join(coverage["RV02"].limits)

    # RV01: peak values live only in the report, so they cannot be traced to
    # an independent pinned artifact.
    assert "스펙트럼 산출물" in rv01
    assert "독립" in rv01
    # RV02: no claim-to-identifier link exists in the data model.
    assert "특정 주장" in rv02
    assert "오프라인" in rv02
