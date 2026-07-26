"""Behavioural tests for the persisted, trace-only Reviewer.

Findings are asserted on their typed `rule_id`, `verdict`, and `code`, never on
message text. A message carries values and identifiers, and `tmp_path` embeds
the test's own function name, so a substring assertion over a message can pass
because of the path it happens to contain rather than the behaviour it claims
to check. Literal expectations are spelled out rather than imported from the
modules under test, so a mutated constant cannot satisfy its own assertion.
"""

import ast
import hashlib
import json
import sqlite3
from collections.abc import Callable, Iterable, Iterator
from contextlib import closing
from dataclasses import fields, is_dataclass, replace
from datetime import UTC, datetime
from enum import Enum
from pathlib import Path
from typing import Final, cast, final, override
from uuid import UUID

import pytest
import review_corpus
from pydantic import BaseModel
from services.api.artifacts.models import ArtifactScope
from services.api.artifacts.store_contract import StoreOutcome

import nipo_local.reviewer as reviewer_module
from nipo_local.config import LocalPaths, resolve_paths
from nipo_local.reviewer import (
    RULE_COVERAGE,
    CitedIdentifier,
    FindingCode,
    IdentifierResolution,
    IdentifierResolver,
    OfflineIdentifierResolver,
    Reviewer,
    ReviewOutcome,
    RuleFinding,
    findings_submission,
    parse_hypothesis_table,
    parse_report,
)
from nipo_local.store import (
    ContentState,
    FindingStatus,
    LocalArtifactStore,
    PinnedRunEvidence,
    ReviewFindingRecord,
    ReviewRecord,
    ReviewRuleId,
    ReviewState,
    ReviewVerdict,
)
from nipo_local.workbench import (
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

REVIEWER_SOURCE: Final = (
    Path(__file__).resolve().parents[1] / "nipo_local" / "reviewer.py"
)

CALIBRATED_AT: Final = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
REVIEWED_AT: Final = datetime(2026, 7, 14, 9, tzinfo=UTC)
LATER_AT: Final = datetime(2026, 7, 14, 10, tzinfo=UTC)
LINEAGE: Final = (UUID("018f47a0-7b9c-7aaa-8def-0123456789ab"),)
REVIEW_ID: Final = UUID("019f0000-0000-7000-8000-00000000d001")
OTHER_REVIEW_ID: Final = UUID("019f0000-0000-7000-8000-00000000d002")
FINDING_IDS: Final = (
    UUID("019f0000-0000-7000-8000-00000000f001"),
    UUID("019f0000-0000-7000-8000-00000000f002"),
    UUID("019f0000-0000-7000-8000-00000000f003"),
    UUID("019f0000-0000-7000-8000-00000000f004"),
    UUID("019f0000-0000-7000-8000-00000000f005"),
)
SECOND_FINDING_IDS: Final = (
    UUID("019f0000-0000-7000-8000-00000000e001"),
    UUID("019f0000-0000-7000-8000-00000000e002"),
    UUID("019f0000-0000-7000-8000-00000000e003"),
    UUID("019f0000-0000-7000-8000-00000000e004"),
    UUID("019f0000-0000-7000-8000-00000000e005"),
)
UNPINNED_VERSION: Final = UUID("019f0000-0000-7000-8000-0000000000aa")

WAVELENGTHS: Final = (400.0, 410.0, 420.0, 430.0, 440.0, 450.0, 460.0)
INTENSITIES: Final = (0.10, 0.35, 0.20, 0.55, 0.25, 0.30, 0.15)
SPECTRUM_UNITS: Final = (
    MeasurementUnit(quantity="wavelength", ucum_code="nm"),
    MeasurementUnit(quantity="intensity", ucum_code="1"),
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

# The measured result of the corpus in this repository, recorded as a literal.
# The threshold is the specification's; the equality is what was observed, so a
# regression that merely stays above 0.90 still fails this suite.
#
# The one allowed false positive is `clean-heat-treatment-control`. RV05 is a
# lexical scan and cannot read context, so a materials-science control that
# says "heat treatment" is reported as a boundary breach. That is a measured
# cost of the rule as designed, disclosed in its published limits, and it is
# counted here rather than defined away.
EXPECTED_CORPUS_CASES: Final = 41
EXPECTED_PLANTED: Final = 22
EXPECTED_CAUGHT: Final = 22
EXPECTED_CLEAN: Final = 13
EXPECTED_FALSE_POSITIVES: Final = 1
EXPECTED_DISCLOSED_LIMITS: Final = 6
REQUIRED_CATCH_RATE: Final = 0.90
ALLOWED_FALSE_POSITIVE_RATE: Final = 0.10
CITED_DOI_CASE: Final = "clean-unreachable-doi"

# Modules whose presence in the Reviewer would give it a way to execute code,
# reach a network, touch the filesystem, or open a database.
FORBIDDEN_MODULES: Final = frozenset(
    {
        "asyncio",
        "code",
        "codeop",
        "ctypes",
        "http",
        "httpx",
        "importlib",
        "multiprocessing",
        "os",
        "pickle",
        "pty",
        "requests",
        "runpy",
        "shutil",
        "socket",
        "sqlite3",
        "ssl",
        "subprocess",
        "sys",
        "urllib",
    }
)

FORBIDDEN_BUILTINS: Final = frozenset(
    {
        "__import__",
        "compile",
        "eval",
        "exec",
        "getattr",
        "globals",
        "input",
        "open",
        "setattr",
    }
)

# Callables that would let a holder execute, publish, or mutate durable state.
FORBIDDEN_METHODS: Final = frozenset(
    {
        "append_run_output",
        "archive_project",
        "attach_session",
        "commit",
        "commit_version",
        "connect",
        "create_artifact",
        "create_run",
        "create_version",
        "execute",
        "executemany",
        "executescript",
        "finish_run",
        "issue_download",
        "mkdir",
        "open_review",
        "popen",
        "prepare_commit",
        "publish",
        "read_content",
        "redeem_content",
        "redeem_download",
        "spawn",
        "start_run",
        "submit_review_findings",
        "sweep_unreferenced_blobs",
        "system",
        "unlink",
        "write",
        "write_bytes",
        "write_text",
    }
)

# The only names the Reviewer may import from the store: data declarations.
ALLOWED_STORE_IMPORTS: Final = frozenset(
    {
        "ContentState",
        "FindingStatus",
        "PinnedOutput",
        "PinnedRunEvidence",
        "ReviewFindingRecord",
        "ReviewRecord",
        "ReviewRuleId",
        "ReviewSubmission",
        "ReviewVerdict",
    }
)

ROW_COUNT_QUERIES: Final = (
    "SELECT COUNT(*) FROM artifacts",
    "SELECT COUNT(*) FROM artifact_versions",
    "SELECT COUNT(*) FROM version_inputs",
    "SELECT COUNT(*) FROM runs",
    "SELECT COUNT(*) FROM executions",
    "SELECT COUNT(*) FROM run_outputs",
    "SELECT COUNT(*) FROM action_plans",
    "SELECT COUNT(*) FROM plan_approvals",
    "SELECT COUNT(*) FROM reviews",
    "SELECT COUNT(*) FROM review_findings",
)


@final
class _StubResolver(IdentifierResolver):
    def __init__(self, outcome: IdentifierResolution) -> None:
        self.outcome: IdentifierResolution = outcome
        self.seen: list[CitedIdentifier] = []

    @override
    def resolve(self, identifier: CitedIdentifier) -> IdentifierResolution:
        self.seen.append(identifier)
        return self.outcome


@pytest.fixture(name="paths")
def paths_fixture(tmp_path: Path) -> LocalPaths:
    return resolve_paths(tmp_path)


@pytest.fixture(name="store")
def store_fixture(paths: LocalPaths) -> Iterator[LocalArtifactStore]:
    with LocalArtifactStore(paths) as opened:
        yield opened


def _probe() -> ProbeInput:
    return ProbeInput(
        spectrum=SpectrumInput(
            wavelengths=WAVELENGTHS,
            intensities=INTENSITIES,
            metadata=InputMetadata(
                units=SPECTRUM_UNITS,
                calibration=CalibrationMetadata(
                    method="two-point-standard",
                    reference="NIST-SRM-2242",
                    calibrated_at=CALIBRATED_AT,
                    calibration_sha256="c" * 64,
                ),
                lineage_version_ids=LINEAGE,
                research_only=True,
                non_clinical=True,
            ),
        )
    )


def _published(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> tuple[ArtifactScope, UUID, PinnedRunEvidence]:
    runtime = assemble_artifact_runtime(store, paths)
    run = run_analysis(runtime, INTENT, _probe(), approve_analysis(runtime, INTENT))
    evidence = store.pinned_run_evidence(runtime.scope, run.run_id)
    assert evidence is not None
    return runtime.scope, run.run_id, evidence


def _queued_review(
    scope: ArtifactScope,
    evidence: PinnedRunEvidence,
    review_id: UUID = REVIEW_ID,
) -> ReviewRecord:
    versions = tuple(sorted(evidence.artifact_version_ids, key=str))
    executions = tuple(sorted(evidence.execution_ids, key=str))
    return ReviewRecord(
        id=review_id,
        org_id=scope.org_id,
        project_id=scope.project_id,
        source_run_id=evidence.run.id,
        state=ReviewState.QUEUED,
        pinned_input_sha256=LocalArtifactStore.pinned_input_digest(
            scope,
            evidence.run.id,
            versions,
            executions,
        ),
        pinned_artifact_version_ids=versions,
        pinned_execution_ids=executions,
        created_at=REVIEWED_AT,
        updated_at=REVIEWED_AT,
    )


def _case(case_id: str) -> review_corpus.CorpusCase:
    return next(item for item in review_corpus.CORPUS if item.case_id == case_id)


def _reviewed(evidence: PinnedRunEvidence, case_id: str) -> ReviewOutcome:
    case = _case(case_id)
    return Reviewer(case.mutate(evidence), case.resolver).review()


def _rule(outcome: ReviewOutcome, rule: ReviewRuleId) -> RuleFinding:
    return next(item for item in outcome.findings if item.rule_id is rule)


def _verdicts(evidence: PinnedRunEvidence) -> dict[ReviewRuleId, ReviewVerdict]:
    return {item.rule_id: item.verdict for item in Reviewer(evidence).review().findings}


def _codes(evidence: PinnedRunEvidence) -> dict[ReviewRuleId, FindingCode]:
    return {item.rule_id: item.code for item in Reviewer(evidence).review().findings}


def _swapped(payload: bytes | None) -> bytes:
    """Change one byte without changing the length of the payload."""
    assert payload is not None
    return payload[:-1] + (b"." if payload.endswith(b"!") else b"!")


def _blob_path(paths: LocalPaths, digest: str) -> Path:
    return paths.blobs / digest[:2] / digest[2:4] / digest


def _durable_state(paths: LocalPaths) -> tuple[object, ...]:
    with closing(sqlite3.connect(paths.database)) as connection:
        rows = tuple(
            cast(
                "tuple[object, ...]",
                connection.execute(query).fetchone(),
            )
            for query in ROW_COUNT_QUERIES
        )
    blobs = tuple(
        sorted(
            (path.name, hashlib.sha256(path.read_bytes()).hexdigest())
            for path in paths.blobs.rglob("*")
            if path.is_file()
        )
    )
    return (rows, blobs)


def _reachable(root: object, limit: int = 20_000) -> list[object]:
    """Walk every object reachable from `root` by ordinary attribute access."""
    seen: set[int] = {id(root)}
    order: list[object] = [root]
    queue: list[object] = [root]
    while queue and len(order) < limit:
        current = queue.pop()
        for child in _children(current):
            if id(child) in seen:
                continue
            seen.add(id(child))
            order.append(child)
            queue.append(child)
    return order


def _children(value: object) -> list[object]:
    if isinstance(value, (str, bytes, int, float, bool, type(None), Enum)):
        return []
    if isinstance(value, (tuple, list, set, frozenset)):
        return list(cast("Iterable[object]", value))
    if isinstance(value, dict):
        mapping = cast("dict[object, object]", value)
        return [*mapping.keys(), *mapping.values()]
    return _attribute_children(value)


def _attribute_names(value: object) -> list[str]:
    if isinstance(value, BaseModel):
        return list(type(value).model_fields)
    if is_dataclass(value) and not isinstance(value, type):
        return [item.name for item in fields(value)]
    declared = cast("tuple[str, ...]", getattr(type(value), "__slots__", ()))
    names = list(declared)
    if hasattr(value, "__dict__"):
        names.extend(cast("dict[str, object]", vars(value)))
    return names


def _attribute_children(value: object) -> list[object]:
    children: list[object] = []
    for name in _attribute_names(value):
        try:
            child = cast("object", object.__getattribute__(value, name))
        except AttributeError:
            continue
        children.append(child)
    return children


def _insert_finding() -> Callable[[LocalArtifactStore, ReviewFindingRecord], None]:
    return cast(
        "Callable[[LocalArtifactStore, ReviewFindingRecord], None]",
        vars(LocalArtifactStore)["_insert_finding_locked"],
    )


def _module_source() -> ast.Module:
    return ast.parse(REVIEWER_SOURCE.read_bytes())


# --------------------------------------------------------------------------
# Structural incapability: the Reviewer cannot execute or write, by absence.
# --------------------------------------------------------------------------


def test_reviewer_source_imports_no_execution_or_network_module() -> None:
    imported: set[str] = set()
    for node in ast.walk(_module_source()):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module is not None:
            imported.add(node.module.split(".")[0])

    assert imported & FORBIDDEN_MODULES == set()
    assert "hashlib" in imported


def test_reviewer_source_calls_no_evaluation_builtin() -> None:
    called = {
        node.func.id
        for node in ast.walk(_module_source())
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert called & FORBIDDEN_BUILTINS == set()


def test_reviewer_imports_only_data_declarations_from_the_store() -> None:
    imported: set[str] = set()
    for node in ast.walk(_module_source()):
        if isinstance(node, ast.ImportFrom) and node.module == "store":
            imported.update(alias.name for alias in node.names)

    assert imported == ALLOWED_STORE_IMPORTS
    for name in imported:
        obj = cast("object", getattr(reviewer_module, name))
        assert not any(
            callable(getattr(obj, method, None)) for method in FORBIDDEN_METHODS
        )


def test_reviewer_instance_reaches_no_write_or_execute_capability(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    subject = Reviewer(evidence)

    graph = _reachable(subject)
    offenders = [
        (type(item).__name__, method)
        for item in graph
        for method in FORBIDDEN_METHODS
        if callable(getattr(item, method, None))
    ]

    assert offenders == []
    # The walk must actually have descended, or the emptiness proves nothing.
    reached = {type(item).__name__ for item in graph}
    assert "RunRecord" in reached
    assert "ExecutionRecord" in reached
    assert "PinnedOutput" in reached
    assert "ArtifactVersion" in reached
    assert "LocalArtifactStore" not in reached


def test_reviewer_instance_cannot_be_given_a_store_after_construction(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    subject = Reviewer(evidence)

    assert not hasattr(subject, "__dict__")
    with pytest.raises(AttributeError):
        subject.store = store  # pyright: ignore[reportAttributeAccessIssue]


def test_reviewing_tampered_evidence_changes_no_durable_state(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run_id, _ = _published(store, paths)
    figure = next(
        item for item in store.run_outputs(scope, run_id) if item.role == "png"
    )
    _ = _blob_path(paths, figure.content_sha256).write_bytes(b"not the figure")
    tampered = store.pinned_run_evidence(scope, run_id)
    assert tampered is not None
    before = _durable_state(paths)

    outcome = Reviewer(tampered).review()

    assert outcome.verdict is ReviewVerdict.FAIL
    assert _durable_state(paths) == before


# --------------------------------------------------------------------------
# Rule behaviour over pinned evidence.
# --------------------------------------------------------------------------


def test_clean_run_passes_every_rule(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)

    outcome = Reviewer(evidence).review()

    assert outcome.verdict is ReviewVerdict.PASS
    assert [item.rule_id for item in outcome.findings] == [
        ReviewRuleId.RV01,
        ReviewRuleId.RV02,
        ReviewRuleId.RV03,
        ReviewRuleId.RV04,
        ReviewRuleId.RV05,
    ]
    assert {item.verdict for item in outcome.findings} == {ReviewVerdict.PASS}


def test_artifact_tampered_after_commit_reports_fail(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run_id, evidence = _published(store, paths)
    report = next(item for item in evidence.outputs if item.role == "markdown")
    assert report.version is not None
    _ = _blob_path(paths, report.version.content_sha256).write_bytes(b"# rewritten")
    tampered = store.pinned_run_evidence(scope, run_id)
    assert tampered is not None

    assert (
        next(item for item in tampered.outputs if item.role == "markdown").content_state
        is ContentState.TAMPERED
    )
    verdicts = _verdicts(tampered)
    assert verdicts[ReviewRuleId.RV03] is ReviewVerdict.FAIL
    assert _codes(tampered)[ReviewRuleId.RV03] is (
        FindingCode.RV03_CONTENT_DIGEST_MISMATCH
    )


def test_the_reviewer_re_verifies_bytes_the_capture_handed_it(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The store verifies content against its digest before handing it over, so
    # this disagreement cannot arise through `pinned_run_evidence` today. The
    # Reviewer must still refuse it: trusting the capture would make the whole
    # RV03 checksum correspondence conditional on a component it does not own.
    _, _, evidence = _published(store, paths)
    smuggled = replace(
        evidence,
        outputs=tuple(
            replace(item, content=_swapped(item.content))
            if item.role == "markdown"
            else item
            for item in evidence.outputs
        ),
    )

    verdicts = _verdicts(smuggled)

    report = next(item for item in smuggled.outputs if item.role == "markdown")
    assert report.content is not None
    assert report.content_state is ContentState.AVAILABLE
    assert report.version is not None
    assert report.version.content_sha256 == report.recorded_sha256
    # Equal length on purpose, so only the recomputed digest can catch this.
    assert report.version.size_bytes == len(report.content)
    assert verdicts[ReviewRuleId.RV03] is ReviewVerdict.FAIL
    assert _codes(smuggled)[ReviewRuleId.RV03] is (
        FindingCode.RV03_CONTENT_DIGEST_MISMATCH
    )


def test_the_same_review_identity_cannot_cover_two_pinned_evidence_sets(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, first = _published(store, paths)
    _, _, second = _published(store, paths)
    opened = _queued_review(scope, first)
    assert store.open_review(scope, opened) is StoreOutcome.CREATED
    collision = _queued_review(scope, second)

    assert collision.pinned_input_sha256 != opened.pinned_input_sha256
    assert store.open_review(scope, collision) is StoreOutcome.ASSOCIATION_EXISTS

    stored = store.review(scope, REVIEW_ID)
    assert stored is not None
    assert stored.source_run_id == first.run.id
    assert store.review_for_pinned_inputs(scope, collision.pinned_input_sha256) is None


def test_unreachable_identifier_is_inconclusive_not_pass_or_fail(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    cited = _case(CITED_DOI_CASE).mutate(evidence)

    outcome = Reviewer(cited, OfflineIdentifierResolver()).review()
    finding = _rule(outcome, ReviewRuleId.RV02)

    assert finding.verdict is ReviewVerdict.INCONCLUSIVE
    assert finding.code is FindingCode.RV02_IDENTIFIER_UNREACHABLE
    assert finding.verdict is not ReviewVerdict.PASS
    assert outcome.verdict is ReviewVerdict.INCONCLUSIVE


def test_identifier_that_does_not_support_its_claim_fails(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    cited = _case(CITED_DOI_CASE).mutate(evidence)
    resolver = _StubResolver(IdentifierResolution.UNSUPPORTED)

    outcome = Reviewer(cited, resolver).review()
    finding = _rule(outcome, ReviewRuleId.RV02)

    assert finding.verdict is ReviewVerdict.FAIL
    assert finding.code is FindingCode.RV02_IDENTIFIER_UNSUPPORTED
    assert [item.value for item in resolver.seen] == ["10.1234/nipo.demo.2026"]


def test_resolved_supporting_identifier_passes(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    cited = _case(CITED_DOI_CASE).mutate(evidence)

    outcome = Reviewer(cited, _StubResolver(IdentifierResolution.SUPPORTED)).review()
    finding = _rule(outcome, ReviewRuleId.RV02)

    assert finding.verdict is ReviewVerdict.PASS
    assert finding.code is FindingCode.RV02_IDENTIFIERS_SUPPORT_CLAIMS


def test_missing_pinned_content_is_inconclusive_never_pass(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run_id, evidence = _published(store, paths)
    for output in evidence.outputs:
        assert output.version is not None
        _blob_path(paths, output.version.content_sha256).unlink()
    stripped = store.pinned_run_evidence(scope, run_id)
    assert stripped is not None

    outcome = Reviewer(stripped).review()

    assert {item.content_state for item in stripped.outputs} == {ContentState.ABSENT}
    assert ReviewVerdict.PASS not in {item.verdict for item in outcome.findings}
    assert outcome.verdict is ReviewVerdict.INCONCLUSIVE
    assert {item.code for item in outcome.findings} == {
        FindingCode.RV01_EVIDENCE_UNAVAILABLE,
        FindingCode.RV02_EVIDENCE_UNAVAILABLE,
        FindingCode.RV03_EVIDENCE_UNAVAILABLE,
        FindingCode.RV04_EVIDENCE_UNAVAILABLE,
        FindingCode.RV05_EVIDENCE_UNAVAILABLE,
    }


@pytest.mark.parametrize(
    ("case_id", "rule", "code"),
    [
        (
            "rv01-numeric-claim-unsupported",
            ReviewRuleId.RV01,
            FindingCode.RV01_CLAIM_UNSUPPORTED,
        ),
        (
            "rv01-wavelength-off-by-one-digit",
            ReviewRuleId.RV01,
            FindingCode.RV01_CLAIM_UNSUPPORTED,
        ),
        (
            "rv01-missingness-off-by-one-digit",
            ReviewRuleId.RV01,
            FindingCode.RV01_CLAIM_UNSUPPORTED,
        ),
        (
            "rv01-peak-count-inflated",
            ReviewRuleId.RV01,
            FindingCode.RV01_CLAIM_UNSUPPORTED,
        ),
        (
            "rv01-peak-row-dropped-count-kept",
            ReviewRuleId.RV01,
            FindingCode.RV01_CLAIM_UNSUPPORTED,
        ),
        (
            "rv02-one-of-three-identifiers-unsupported",
            ReviewRuleId.RV02,
            FindingCode.RV02_IDENTIFIER_UNSUPPORTED,
        ),
        (
            "rv03-ledger-figure-digest-rewritten",
            ReviewRuleId.RV03,
            FindingCode.RV03_LEDGER_MISMATCH,
        ),
        (
            "rv03-ledger-media-type-drift",
            ReviewRuleId.RV03,
            FindingCode.RV03_LEDGER_MISMATCH,
        ),
        (
            "rv03-ledger-version-no-off-by-one",
            ReviewRuleId.RV03,
            FindingCode.RV03_LEDGER_MISMATCH,
        ),
        (
            "rv03-ledger-omits-the-figure",
            ReviewRuleId.RV03,
            FindingCode.RV03_LEDGER_MISMATCH,
        ),
        (
            "rv03-ledger-overstates-isolation",
            ReviewRuleId.RV03,
            FindingCode.RV03_LEDGER_MISMATCH,
        ),
        (
            "rv03-code-digest-drift",
            ReviewRuleId.RV03,
            FindingCode.RV03_PROVENANCE_MISMATCH,
        ),
        (
            "rv03-report-input-digest-off-by-one",
            ReviewRuleId.RV03,
            FindingCode.RV03_PROVENANCE_MISMATCH,
        ),
        (
            "rv04-evidence-level-escalated",
            ReviewRuleId.RV04,
            FindingCode.RV04_EVIDENCE_LEVEL_ESCALATED,
        ),
        (
            "rv04-report-state-escalated",
            ReviewRuleId.RV04,
            FindingCode.RV04_EVIDENCE_LEVEL_ESCALATED,
        ),
        (
            "rv04-report-state-escalated-by-one-step",
            ReviewRuleId.RV04,
            FindingCode.RV04_EVIDENCE_LEVEL_ESCALATED,
        ),
        (
            "rv05-clinical-claim",
            ReviewRuleId.RV05,
            FindingCode.RV05_CLINICAL_LANGUAGE,
        ),
        (
            "rv05-dosing-instruction-in-a-control",
            ReviewRuleId.RV05,
            FindingCode.RV05_CLINICAL_LANGUAGE,
        ),
        (
            "rv05-scope-marker-dropped",
            ReviewRuleId.RV05,
            FindingCode.RV05_SCOPE_MARKER_MISSING,
        ),
        (
            "rv05-branch-limitation-dropped",
            ReviewRuleId.RV05,
            FindingCode.RV05_SCOPE_MARKER_MISSING,
        ),
    ],
)
def test_planted_defect_is_caught_by_its_own_rule(
    store: LocalArtifactStore,
    paths: LocalPaths,
    case_id: str,
    rule: ReviewRuleId,
    code: FindingCode,
) -> None:
    _, _, evidence = _published(store, paths)

    outcome = _reviewed(evidence, case_id)
    finding = next(item for item in outcome.findings if item.rule_id is rule)

    assert finding.verdict is ReviewVerdict.FAIL
    assert finding.code is code
    assert outcome.verdict is ReviewVerdict.FAIL


def test_a_counterfactual_publication_is_not_also_a_checksum_defect(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    case = _case("rv01-numeric-claim-unsupported")

    verdicts = _verdicts(case.mutate(evidence))

    assert verdicts[ReviewRuleId.RV01] is ReviewVerdict.FAIL
    assert verdicts[ReviewRuleId.RV03] is ReviewVerdict.PASS
    assert verdicts[ReviewRuleId.RV04] is ReviewVerdict.PASS
    assert verdicts[ReviewRuleId.RV05] is ReviewVerdict.PASS


def test_understated_evidence_level_warns_rather_than_fails(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    understated = review_corpus.republish_text(
        evidence,
        "markdown",
        "### molecular (plausible)",
        "### molecular (insufficient)",
    )

    verdicts = _verdicts(understated)

    assert verdicts[ReviewRuleId.RV04] is ReviewVerdict.WARN
    assert _codes(understated)[ReviewRuleId.RV04] is (
        FindingCode.RV04_STATE_UNDERSTATED
    )


def test_the_product_safety_markers_are_not_read_as_violations(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    report = next(item for item in evidence.outputs if item.role == "markdown")
    assert report.content is not None
    parsed = parse_report(report.content)
    assert parsed is not None

    assert "non_diagnostic" in report.content.decode()
    assert all(item.conclusion_scope == "non_diagnostic" for item in parsed.branches)
    assert _verdicts(evidence)[ReviewRuleId.RV05] is ReviewVerdict.PASS


def test_report_and_table_parse_the_pinned_bytes(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    report = next(item for item in evidence.outputs if item.role == "markdown")
    table = next(item for item in evidence.outputs if item.role == "csv")
    assert report.content is not None
    assert table.content is not None

    parsed = parse_report(report.content)
    rows = parse_hypothesis_table(table.content)

    assert parsed is not None
    assert rows is not None
    assert [item.branch for item in parsed.branches] == [
        "molecular",
        "optical",
        "experimental_artifact",
    ]
    assert parsed.declared_peaks == 3
    assert parsed.peak_rows == 3
    assert [row.state for row in rows] == ["plausible", "insufficient", "observed"]


# --------------------------------------------------------------------------
# Persistence: pinned inputs, deduplication, exactly-once findings.
# --------------------------------------------------------------------------


def test_review_tables_are_strict(paths: LocalPaths) -> None:
    with LocalArtifactStore(paths):
        pass
    with closing(sqlite3.connect(paths.database)) as connection:
        rows = cast(
            "list[tuple[str, str]]",
            connection.execute(
                "SELECT name, sql FROM sqlite_master WHERE type = 'table' "
                "AND name IN ('reviews', 'review_findings')"
            ).fetchall(),
        )

    assert sorted(name for name, _ in rows) == ["review_findings", "reviews"]
    assert all(statement.rstrip().endswith("STRICT") for _, statement in rows)


def test_open_review_refuses_a_caller_chosen_pinned_digest(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    review = _queued_review(scope, evidence)
    forged = review.model_copy(update={"pinned_input_sha256": "a" * 64})

    assert store.open_review(scope, forged) is StoreOutcome.NOT_FOUND
    assert store.review(scope, review.id) is None


def test_open_review_deduplicates_by_pinned_input_digest(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    first = _queued_review(scope, evidence)
    second = _queued_review(scope, evidence, OTHER_REVIEW_ID)

    assert store.open_review(scope, first) is StoreOutcome.CREATED
    assert store.open_review(scope, second) is StoreOutcome.ASSOCIATION_EXISTS
    assert store.review(scope, OTHER_REVIEW_ID) is None
    assert store.review_for_pinned_inputs(
        scope, first.pinned_input_sha256
    ) == store.review(scope, REVIEW_ID)


def test_pinned_digest_ignores_pin_order_and_repetition(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    versions = tuple(sorted(evidence.artifact_version_ids, key=str))
    run_id = evidence.run.id

    straight = LocalArtifactStore.pinned_input_digest(
        scope, run_id, versions, evidence.execution_ids
    )
    shuffled = LocalArtifactStore.pinned_input_digest(
        scope, run_id, tuple(reversed(versions)) + versions[:1], evidence.execution_ids
    )

    assert straight == shuffled
    assert len(straight) == 64


def test_findings_are_submitted_exactly_once(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    review = _queued_review(scope, evidence)
    assert store.open_review(scope, review) is StoreOutcome.CREATED
    assert store.start_review(scope, review.id, REVIEWED_AT) is StoreOutcome.CREATED
    outcome = Reviewer(evidence).review()
    first = findings_submission(review, outcome, FINDING_IDS, REVIEWED_AT)
    second = findings_submission(review, outcome, SECOND_FINDING_IDS, LATER_AT)

    assert store.submit_review_findings(scope, first) is StoreOutcome.CREATED
    assert (
        store.submit_review_findings(scope, second) is StoreOutcome.ASSOCIATION_EXISTS
    )

    stored = store.review_findings(scope, review.id)
    assert [item.id for item in stored] == list(FINDING_IDS)
    completed = store.review(scope, review.id)
    assert completed is not None
    assert completed.state is ReviewState.COMPLETED
    assert completed.findings_submitted_at == REVIEWED_AT


def test_a_second_submission_is_refused_by_the_schema_alone(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    review = _queued_review(scope, evidence)
    assert store.open_review(scope, review) is StoreOutcome.CREATED
    assert store.start_review(scope, review.id, REVIEWED_AT) is StoreOutcome.CREATED
    outcome = Reviewer(evidence).review()
    submission = findings_submission(review, outcome, FINDING_IDS, REVIEWED_AT)
    assert store.submit_review_findings(scope, submission) is StoreOutcome.CREATED

    # Bypass the store's own guard and try to write the same rules a second
    # time: the schema alone must refuse it.
    repeat = findings_submission(review, outcome, SECOND_FINDING_IDS, LATER_AT)
    with pytest.raises(sqlite3.IntegrityError):
        _insert_finding()(store, repeat.findings[0])


def test_findings_may_not_widen_the_pinned_evidence_set(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    review = _queued_review(scope, evidence)
    assert store.open_review(scope, review) is StoreOutcome.CREATED
    assert store.start_review(scope, review.id, REVIEWED_AT) is StoreOutcome.CREATED
    submission = findings_submission(
        review, Reviewer(evidence).review(), FINDING_IDS, REVIEWED_AT
    )
    widened = submission.model_copy(
        update={
            "findings": (
                submission.findings[0].model_copy(
                    update={"artifact_version_ids": (UNPINNED_VERSION,)}
                ),
                *submission.findings[1:],
            )
        }
    )

    assert store.submit_review_findings(scope, widened) is StoreOutcome.NOT_FOUND
    assert store.review_findings(scope, review.id) == ()


def test_findings_cannot_be_submitted_before_the_review_runs(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    review = _queued_review(scope, evidence)
    assert store.open_review(scope, review) is StoreOutcome.CREATED
    submission = findings_submission(
        review, Reviewer(evidence).review(), FINDING_IDS, REVIEWED_AT
    )

    assert store.submit_review_findings(scope, submission) is StoreOutcome.STALE
    assert store.review_findings(scope, review.id) == ()


def test_inconclusive_is_persisted_as_inconclusive(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run_id, evidence = _published(store, paths)
    review = _queued_review(scope, evidence)
    assert store.open_review(scope, review) is StoreOutcome.CREATED
    assert store.start_review(scope, review.id, REVIEWED_AT) is StoreOutcome.CREATED
    for output in evidence.outputs:
        assert output.version is not None
        _blob_path(paths, output.version.content_sha256).unlink()
    stripped = store.pinned_run_evidence(scope, run_id)
    assert stripped is not None
    submission = findings_submission(
        review, Reviewer(stripped).review(), FINDING_IDS, REVIEWED_AT
    )

    assert store.submit_review_findings(scope, submission) is StoreOutcome.CREATED

    stored = store.review_findings(scope, review.id)
    assert {item.verdict for item in stored} == {ReviewVerdict.INCONCLUSIVE}
    assert {item.status for item in stored} == {FindingStatus.OPEN}
    assert len(stored) == 5


def test_a_failed_review_records_a_non_secret_reason(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    review = _queued_review(scope, evidence)
    assert store.open_review(scope, review) is StoreOutcome.CREATED

    assert (
        store.fail_review(scope, review.id, LATER_AT, "evidence_unreadable")
        is StoreOutcome.CREATED
    )

    failed = store.review(scope, review.id)
    assert failed is not None
    assert failed.state is ReviewState.FAILED
    assert failed.error_type == "evidence_unreadable"
    assert failed.findings_submitted_at is None
    assert (
        store.fail_review(scope, review.id, LATER_AT, "evidence_unreadable")
        is StoreOutcome.STALE
    )


def test_a_review_cannot_pin_evidence_that_does_not_exist(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    versions = tuple(
        sorted((*evidence.artifact_version_ids, UNPINNED_VERSION), key=str)
    )
    review = _queued_review(scope, evidence).model_copy(
        update={
            "pinned_artifact_version_ids": versions,
            "pinned_input_sha256": LocalArtifactStore.pinned_input_digest(
                scope, evidence.run.id, versions, evidence.execution_ids
            ),
        }
    )

    assert store.open_review(scope, review) is StoreOutcome.INVALID_LINEAGE
    assert store.review(scope, review.id) is None


def test_review_state_advances_only_from_queued(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    review = _queued_review(scope, evidence)
    assert store.open_review(scope, review) is StoreOutcome.CREATED

    assert store.start_review(scope, review.id, REVIEWED_AT) is StoreOutcome.CREATED
    assert store.start_review(scope, review.id, LATER_AT) is StoreOutcome.STALE

    running = store.review(scope, review.id)
    assert running is not None
    assert running.state is ReviewState.RUNNING
    assert running.updated_at == REVIEWED_AT


def test_findings_submission_refuses_a_mismatched_identity_count(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    review = _queued_review(scope, evidence)

    with pytest.raises(ValueError, match="finding identifier"):
        _ = findings_submission(
            review, Reviewer(evidence).review(), FINDING_IDS[:2], REVIEWED_AT
        )


def test_a_refused_review_writes_nothing_at_all(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, _, evidence = _published(store, paths)
    before = _durable_state(paths)
    forged = _queued_review(scope, evidence).model_copy(
        update={"pinned_input_sha256": "b" * 64}
    )

    assert store.open_review(scope, forged) is StoreOutcome.NOT_FOUND

    with closing(sqlite3.connect(paths.database)) as connection:
        reviews = cast(
            "tuple[int]",
            connection.execute("SELECT COUNT(*) FROM reviews").fetchone(),
        )
    assert reviews == (0,)
    assert _durable_state(paths) == before


# --------------------------------------------------------------------------
# Measured catch rate over the versioned corpus.
# --------------------------------------------------------------------------


def test_corpus_catch_rate_is_measured_not_asserted(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)

    score = review_corpus.score_corpus(evidence)

    assert score.corpus_version == "nipo.local.review-corpus.v2"
    assert len(score.results) == EXPECTED_CORPUS_CASES
    assert score.planted == EXPECTED_PLANTED
    assert score.clean == EXPECTED_CLEAN
    assert score.disclosed_limits == EXPECTED_DISCLOSED_LIMITS
    assert score.missed == ()
    assert score.caught == EXPECTED_CAUGHT
    assert score.false_positives == EXPECTED_FALSE_POSITIVES
    assert score.catch_rate >= REQUIRED_CATCH_RATE
    assert score.false_positive_rate <= ALLOWED_FALSE_POSITIVE_RATE


def test_the_measured_false_positive_is_explained_by_a_published_limit(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A false positive that no published limit explains would be an undisclosed
    # defect wearing an allowance. This one is named in RV05's own coverage.
    _, _, evidence = _published(store, paths)
    rv05 = next(item for item in RULE_COVERAGE if item.rule_id is ReviewRuleId.RV05)

    score = review_corpus.score_corpus(evidence)
    offenders = [item.case.case_id for item in score.results if item.false_positive]

    assert offenders == ["clean-heat-treatment-control"]
    assert "heat treatment" in " ".join(rv05.limits)


def test_every_corpus_case_reaches_the_summary_verdict_it_declared(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # `expected_verdict` used to be documentation nothing checked, so a case
    # could drift into a different outcome and still be counted as scored.
    _, _, evidence = _published(store, paths)

    score = review_corpus.score_corpus(evidence)

    assert score.wrong_summary_verdict == ()


def test_every_review_rule_is_exercised_by_the_corpus() -> None:
    covered = {
        case.expected_rule for case in review_corpus.CORPUS if case.expected_rule
    }

    assert covered == {
        ReviewRuleId.RV01,
        ReviewRuleId.RV02,
        ReviewRuleId.RV03,
        ReviewRuleId.RV04,
        ReviewRuleId.RV05,
    }


def test_every_rule_carries_both_a_planted_case_and_a_clean_measurement(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # A rule with planted cases only measures catching and never measures
    # over-reporting, which is how a checker reaches a perfect catch rate by
    # failing everything.
    _, _, evidence = _published(store, paths)
    score = review_corpus.score_corpus(evidence)

    planted_rules = {
        item.case.expected_rule
        for item in score.results
        if item.case.kind is review_corpus.CaseKind.PLANTED
    }
    clean_passes: set[ReviewRuleId] = set()
    for case in review_corpus.CORPUS:
        if case.kind is not review_corpus.CaseKind.CLEAN:
            continue
        outcome = Reviewer(case.mutate(evidence), case.resolver).review()
        clean_passes.update(
            finding.rule_id
            for finding in outcome.findings
            if finding.verdict is ReviewVerdict.PASS
        )

    assert planted_rules == clean_passes
    assert len(planted_rules) == len(RULE_COVERAGE)


def test_a_disclosed_limit_is_not_caught_and_names_its_own_disclosure(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # This is what makes RULE_COVERAGE a measurement instead of prose. Each
    # case that the Reviewer structurally cannot see must point at the exact
    # published limit that says so, and must still not be caught.
    _, _, evidence = _published(store, paths)
    coverage = {item.rule_id: item for item in RULE_COVERAGE}

    score = review_corpus.score_corpus(evidence)
    limits = [
        item
        for item in score.results
        if item.case.kind is review_corpus.CaseKind.DISCLOSED_LIMIT
    ]

    assert score.overstated_limits == ()
    assert len(limits) == EXPECTED_DISCLOSED_LIMITS
    for item in limits:
        rule = item.case.expected_rule
        assert rule is not None
        published = " ".join(coverage[rule].limits)
        assert item.case.limit_evidence != ()
        for sentence in item.case.limit_evidence:
            assert sentence in published
        assert item.rule_verdict is not ReviewVerdict.FAIL


def test_deleting_a_published_limit_would_leave_its_corpus_case_unexplained(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The disclosure is load-bearing: no corpus case may cite a limit that is
    # not literally present, so narrowing a limit to claim broader coverage
    # fails here rather than shipping.
    _, _, evidence = _published(store, paths)
    published = {item.rule_id: " ".join(item.limits) for item in RULE_COVERAGE}
    del evidence

    uncited = [
        case.case_id
        for case in review_corpus.CORPUS
        if case.expected_rule is not None
        for sentence in case.limit_evidence
        if sentence not in published[case.expected_rule]
    ]

    assert uncited == []


def test_an_inconclusive_clean_case_is_not_a_false_positive(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)

    score = review_corpus.score_corpus(evidence)
    unreachable = next(
        item for item in score.results if item.case.case_id == "clean-unreachable-doi"
    )

    assert unreachable.verdict is ReviewVerdict.INCONCLUSIVE
    assert unreachable.false_positive is False
    assert unreachable.case.planted is False


def test_every_corpus_mutation_actually_changes_the_evidence(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)

    changed = {
        case.case_id
        for case in review_corpus.CORPUS
        if case.mutate(evidence) != evidence
    }

    assert changed == {
        case.case_id
        for case in review_corpus.CORPUS
        if case.case_id != "clean-spectrum-run"
    }


def test_ledger_bytes_round_trip_through_the_corpus_canonicalizer(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    ledger = next(item for item in evidence.outputs if item.role == "ledger")
    assert ledger.content is not None

    rebuilt = review_corpus.ledger_bytes(
        cast("dict[str, object]", json.loads(ledger.content))
    )

    assert rebuilt == ledger.content


# --------------------------------------------------------------------------
# Defects the expanded corpus exposed. Each is proven general rather than
# fixed for the single case that found it.
# --------------------------------------------------------------------------


def _ledger_edit(
    evidence: PinnedRunEvidence,
    edit: Callable[[dict[str, object]], None],
) -> PinnedRunEvidence:
    return review_corpus.republish_ledger(evidence, edit)


def _entries(document: dict[str, object], key: str) -> list[dict[str, object]]:
    return review_corpus.ledger_entries(document, key)


@pytest.mark.parametrize(
    ("written", "checked"),
    [
        ("(doi:10.1234/nipo.demo.2026)", "10.1234/nipo.demo.2026"),
        ("See doi:10.1234/nipo.demo.2026.", "10.1234/nipo.demo.2026"),
        ("doi:10.1234/paper(rev2)", "10.1234/paper(rev2)"),
        ("(doi:10.1234/paper(rev2))", "10.1234/paper(rev2)"),
        ("[doi:10.1234/nipo.demo.2026]", "10.1234/nipo.demo.2026"),
    ],
)
def test_a_cited_doi_is_checked_as_the_value_the_author_wrote(
    store: LocalArtifactStore,
    paths: LocalPaths,
    written: str,
    checked: str,
) -> None:
    # A DOI suffix may legitimately contain parentheses, so only an unbalanced
    # closer is dropped. Asking a resolver about a value nobody cited turns a
    # correct citation into an unsupported one.
    _, _, evidence = _published(store, paths)
    cited = review_corpus.republish_text(
        evidence,
        "markdown",
        "- Rationale: ",
        f"- Rationale: {written} ",
    )
    resolver = _StubResolver(IdentifierResolution.SUPPORTED)

    outcome = Reviewer(cited, resolver).review()

    assert [item.value for item in resolver.seen] == [checked]
    assert _rule(outcome, ReviewRuleId.RV02).verdict is ReviewVerdict.PASS


@pytest.mark.parametrize(
    "declaration",
    [
        "non_diagnostic",
        "non-diagnostic",
        "non-clinical",
        "nonclinical",
        "non-therapeutic",
        "non-treatment",
        "non patient",
        "non-medication",
    ],
)
def test_a_negated_boundary_term_declares_a_limit_rather_than_crossing_it(
    store: LocalArtifactStore,
    paths: LocalPaths,
    declaration: str,
) -> None:
    # Negation is derived from the boundary vocabulary itself, so it can never
    # fall behind it. An enumerated list did, and read the product's own
    # `non-therapeutic` wording as a violation.
    _, _, evidence = _published(store, paths)
    declared = review_corpus.republish_text(
        evidence,
        "markdown",
        "- Research-support output only.",
        f"- Research-support output only; {declaration} use.",
    )

    assert _verdicts(declared)[ReviewRuleId.RV05] is ReviewVerdict.PASS


def test_an_unnegated_term_beside_a_negated_one_is_still_a_breach(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)
    mixed = review_corpus.republish_text(
        evidence,
        "markdown",
        "- Research-support output only.",
        "- Research-support, non-therapeutic output; confirms the diagnosis.",
    )

    assert _verdicts(mixed)[ReviewRuleId.RV05] is ReviewVerdict.FAIL
    assert _codes(mixed)[ReviewRuleId.RV05] is FindingCode.RV05_CLINICAL_LANGUAGE


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("media_type", "application/octet-stream"),
        ("size_bytes", 1),
        ("version_no", 9),
        ("content_sha256", "a" * 64),
        ("version_id", "019f0000-0000-7000-8000-0000000000bb"),
    ],
)
@pytest.mark.parametrize("role", ["csv", "png", "markdown"])
def test_any_ledger_field_disagreeing_with_the_versions_is_reported(
    store: LocalArtifactStore,
    paths: LocalPaths,
    role: str,
    field: str,
    value: object,
) -> None:
    # `media_type` was parsed and then never compared, so a ledger describing
    # the figure as a table read as corresponding. The comparison is now over
    # every field the ledger and the Version both carry.
    _, _, evidence = _published(store, paths)

    def edit(document: dict[str, object]) -> None:
        for entry in _entries(document, "outputs"):
            if entry.get("role") == role:
                entry[field] = value

    drifted = _ledger_edit(evidence, edit)

    assert _verdicts(drifted)[ReviewRuleId.RV03] is ReviewVerdict.FAIL


@pytest.mark.parametrize("role", ["csv", "png", "markdown"])
def test_a_ledger_omitting_any_published_output_is_reported(
    store: LocalArtifactStore,
    paths: LocalPaths,
    role: str,
) -> None:
    # A ledger that says nothing about a published output disagrees with the
    # Versions exactly as much as one that says something wrong.
    _, _, evidence = _published(store, paths)

    def edit(document: dict[str, object]) -> None:
        document["outputs"] = [
            entry
            for entry in _entries(document, "outputs")
            if entry.get("role") != role
        ]

    omitted = _ledger_edit(evidence, edit)

    assert _verdicts(omitted)[ReviewRuleId.RV03] is ReviewVerdict.FAIL
    assert _codes(omitted)[ReviewRuleId.RV03] is FindingCode.RV03_LEDGER_MISMATCH


def test_the_ledger_not_listing_itself_is_not_an_omission(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # The ledger is committed last and cannot contain its own digest, so its
    # absence from its own output list is the producer's shape.
    _, _, evidence = _published(store, paths)
    published = {item.role for item in evidence.outputs}
    listed = {
        cast("str", entry["role"])
        for entry in _entries(review_corpus.ledger_document(evidence), "outputs")
    }

    assert "ledger" in published
    assert "ledger" not in listed
    assert _verdicts(evidence)[ReviewRuleId.RV03] is ReviewVerdict.PASS


def _unknown_ledger_kind(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    def edit(document: dict[str, object]) -> None:
        for entry in _entries(document, "science_evidence"):
            if entry.get("branch") == "optical":
                entry["evidence_kind"] = "clinical_confirmation"

    return _ledger_edit(evidence, edit)


def _unknown_ledger_branch(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    def edit(document: dict[str, object]) -> None:
        for entry in _entries(document, "science_evidence"):
            if entry.get("branch") == "optical":
                entry["branch"] = "thermal"

    return _ledger_edit(evidence, edit)


def _unknown_report_state(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    return review_corpus.republish_text(
        evidence,
        "markdown",
        "### molecular (plausible)",
        "### molecular (confirmed)",
    )


def _unknown_source_state(evidence: PinnedRunEvidence) -> PinnedRunEvidence:
    return review_corpus.republish_text(
        evidence,
        "csv",
        "molecular,plausible,",
        "molecular,confirmed,",
    )


@pytest.mark.parametrize(
    "mutate",
    [
        _unknown_ledger_kind,
        _unknown_ledger_branch,
        _unknown_report_state,
        _unknown_source_state,
    ],
)
def test_a_level_no_pinned_vocabulary_ranks_is_inconclusive_never_safe(
    store: LocalArtifactStore,
    paths: LocalPaths,
    mutate: Callable[[PinnedRunEvidence], PinnedRunEvidence],
) -> None:
    # An unrecognized level used to be ranked at zero, which reads the
    # strongest possible claim as the weakest: a ledger deriving a
    # `clinical_confirmation` passed, and a report stating `confirmed` was
    # reported as *understating* its own evidence.
    _, _, evidence = _published(store, paths)
    unrankable = mutate(evidence)

    verdicts = _verdicts(unrankable)

    assert verdicts[ReviewRuleId.RV04] is ReviewVerdict.INCONCLUSIVE
    assert _codes(unrankable)[ReviewRuleId.RV04] is FindingCode.RV04_LEVEL_UNRANKABLE
    assert verdicts[ReviewRuleId.RV04] is not ReviewVerdict.PASS
    assert verdicts[ReviewRuleId.RV04] is not ReviewVerdict.WARN


def test_a_report_branch_the_pinned_table_never_carried_is_inconclusive(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    _, _, evidence = _published(store, paths)

    outcome = _reviewed(evidence, "limit-rv04-branch-absent-from-the-pinned-table")
    finding = _rule(outcome, ReviewRuleId.RV04)

    assert finding.verdict is ReviewVerdict.INCONCLUSIVE
    assert finding.code is FindingCode.RV04_LEVEL_UNRANKABLE
    assert outcome.verdict is ReviewVerdict.INCONCLUSIVE


def test_a_rankable_escalation_outranks_an_unrankable_sibling(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    # Reporting "cannot rank" must not swallow a real escalation sitting
    # beside it in the same Review.
    _, _, evidence = _published(store, paths)
    escalated = review_corpus.republish_text(
        evidence,
        "markdown",
        "### optical (insufficient)",
        "### optical (plausible)",
    )
    both = _unknown_ledger_branch(escalated)

    verdicts = _verdicts(both)

    assert verdicts[ReviewRuleId.RV04] is ReviewVerdict.FAIL
    assert _codes(both)[ReviewRuleId.RV04] is (
        FindingCode.RV04_EVIDENCE_LEVEL_ESCALATED
    )


def test_the_reviewer_module_binds_no_producing_path_at_all() -> None:
    # The Reviewer traces pinned evidence; it never reaches a producing path.
    for name in (
        "LocalArtifactStore",
        "ArtifactService",
        "OutputWatcher",
        "analyze_probe",
        "approve_analysis",
        "run_analysis",
    ):
        assert not hasattr(reviewer_module, name)
