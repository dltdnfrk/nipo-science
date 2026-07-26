"""Behavioural tests for the reproducibility Export Pack.

Every claim about a pack is checked the way a stranger would check it: the
archive is written to a real filesystem, extracted with a stdlib reader into a
fresh directory, and every digest is recomputed from the extracted bytes. No
assertion in the round-trip path compares against a value the exporter kept in
memory, because agreeing with itself is not evidence.

Rejections are asserted on `ExportError.reason.value`, a closed typed field
compared against a spelled-out literal. Messages are never matched: `tmp_path`
embeds the test's own function name, so a substring assertion over a message
can pass because of the path it happens to carry rather than the behaviour it
claims to check. Literal expectations are written out rather than imported
from the module under test, so a renamed or mutated constant cannot satisfy
its own assertion.
"""

import hashlib
import json
import os
import stat
import subprocess
import sys
import unicodedata
import zipfile
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Final, cast
from uuid import UUID

import pytest
from services.api.artifacts.models import ArtifactRecord, ArtifactScope, ArtifactVersion
from services.api.artifacts.store_contract import BlobIntegrityError, StoreOutcome

from nipo_local.config import LOCAL_RUNTIME_CONNECTION_ID, LocalPaths, resolve_paths
from nipo_local.exportpack import (
    AttestedInputs,
    ExportEntry,
    ExportError,
    ExportPack,
    ExportRequest,
    build_pack,
    entries_for_run,
    export_run,
    write_pack,
)
from nipo_local.reviewer import Reviewer, findings_submission
from nipo_local.store import (
    LocalArtifactStore,
    ReviewRecord,
    ReviewState,
)
from nipo_local.workbench import (
    WorkbenchRun,
    approve_analysis,
    assemble_artifact_runtime,
    environment_facts,
    run_analysis,
    signing_key_path,
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

CALIBRATED_AT: Final = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)
EXPORTED_AT: Final = datetime(2026, 7, 25, 12, tzinfo=UTC)
REVIEWED_AT: Final = datetime(2026, 7, 25, 11, tzinfo=UTC)
LINEAGE: Final = (UUID("018f47a0-7b9c-7aaa-8def-0123456789ab"),)

PACK_ID: Final = UUID("019f0000-0000-7000-8000-0000000000e1")
REVIEW_ID: Final = UUID("019f0000-0000-7000-8000-0000000000d1")
FINDING_IDS: Final = (
    UUID("019f0000-0000-7000-8000-00000000f001"),
    UUID("019f0000-0000-7000-8000-00000000f002"),
    UUID("019f0000-0000-7000-8000-00000000f003"),
    UUID("019f0000-0000-7000-8000-00000000f004"),
    UUID("019f0000-0000-7000-8000-00000000f005"),
)
EXTRA_ARTIFACT_ID: Final = UUID("019f0000-0000-7000-8000-0000000000a1")
EXTRA_VERSION_ID: Final = UUID("019f0000-0000-7000-8000-0000000000b1")
SUCCESSOR_VERSION_ID: Final = UUID("019f0000-0000-7000-8000-0000000000b2")
ABSENT_VERSION_ID: Final = UUID("019f0000-0000-7000-8000-0000000000cc")

SHA_PLACEHOLDER: Final = "a" * 64

JsonObject = dict[str, object]

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

# Distinctive enough that finding it anywhere in a pack is proof of a leak and
# never a coincidence. Deliberately not a real key shape.
SEALED_CANARY: Final = "CANARY-sealed-provider-blob-7Qv2Zx9LmR4tKp0BwEhNcJdSaFgYuIoP"
ENV_CANARY: Final = "CANARY-environment-provider-key-3XbNmQwErTyUiOpAsDfGh"

# Pairs whose two members are distinct byte sequences but which a
# case-insensitive or Unicode-normalizing filesystem cannot keep apart.
CASE_PAIR: Final = ("artifacts/Report.md", "artifacts/report.md")
NFC_NFD_PAIR: Final = (
    "artifacts/" + unicodedata.normalize("NFC", "café.csv"),
    "artifacts/" + unicodedata.normalize("NFD", "café.csv"),
)
LIGATURE_PAIR: Final = ("artifacts/ﬁle.csv", "artifacts/file.csv")
# The ambiguity these two flag is the hazard under test, not a typo.
FULLWIDTH_PAIR: Final = ("artifacts/ａ.csv", "artifacts/a.csv")  # noqa: RUF001
ROMAN_PAIR: Final = ("artifacts/Ⅻ.csv", "artifacts/xii.csv")


@pytest.fixture(name="paths")
def paths_fixture(tmp_path: Path) -> LocalPaths:
    return resolve_paths(tmp_path / "data-root")


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
) -> tuple[ArtifactScope, WorkbenchRun]:
    runtime = assemble_artifact_runtime(store, paths)
    run = run_analysis(runtime, INTENT, _probe(), approve_analysis(runtime, INTENT))
    return runtime.scope, run


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


def _request(
    entries: Sequence[ExportEntry],
    run_id: UUID,
    attested: AttestedInputs | None = None,
    selection: tuple[UUID, ...] | None = None,
) -> ExportRequest:
    return ExportRequest(
        pack_id=PACK_ID,
        run_id=run_id,
        selection=_selection(entries) if selection is None else selection,
        entries=tuple(entries),
        created_at=EXPORTED_AT,
        attested=AttestedInputs() if attested is None else attested,
    )


def _full_attestation() -> AttestedInputs:
    return AttestedInputs(
        research_intent_json=INTENT.canonical_bytes,
        scientific_input_json=_probe().model_dump_json().encode(),
        environment_facts=environment_facts(),
    )


def _exported(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
    attested: AttestedInputs | None = None,
    name: str = "pack.zip",
) -> tuple[Path, ExportPack, WorkbenchRun, ArtifactScope]:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    destination = tmp_path / name
    pack = export_run(
        store,
        scope,
        paths,
        _request(entries, run.run_id, attested),
        destination,
    )
    return destination, pack, run, scope


def _canonical(value: object) -> bytes:
    """Re-implement the manifest's stated canonical rule, without importing it."""
    return json.dumps(
        value,
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")


def _extract(archive_path: Path, into: Path) -> None:
    """Extract with a stdlib reader, refusing anything a stranger would refuse."""
    into.mkdir(parents=True, exist_ok=True)
    resolved_root = into.resolve()
    with zipfile.ZipFile(archive_path) as archive:
        for info in archive.infolist():
            mode = info.external_attr >> 16
            assert stat.S_ISREG(mode), info.filename
            assert not stat.S_ISLNK(mode), info.filename
            assert not info.is_dir(), info.filename
            assert not info.filename.startswith("/"), info.filename
            assert ".." not in info.filename.split("/"), info.filename
            target = into / info.filename
            assert target.resolve().is_relative_to(resolved_root), info.filename
            target.parent.mkdir(parents=True, exist_ok=True)
            _ = target.write_bytes(archive.read(info.filename))


def _verify_independently(extracted: Path) -> dict[str, object]:
    """Recompute every digest from the extracted bytes, as a third party would.

    Nothing here reads a value the exporter produced in memory. Every digest is
    taken over bytes read back off the filesystem, and the manifest and the
    checksum file are required to agree with each other and with the bytes.
    """
    lines = (extracted / "checksums.sha256").read_bytes().decode("utf-8").splitlines()
    recorded: dict[str, str] = {}
    for line in lines:
        digest, separator, name = line.partition("  ")
        assert separator == "  "
        assert len(digest) == 64
        assert digest == digest.lower()
        assert name not in recorded
        recorded[name] = digest
    on_disk = {
        str(item.relative_to(extracted))
        for item in extracted.rglob("*")
        if item.is_file()
    }
    assert on_disk == set(recorded) | {"checksums.sha256"}
    for name, digest in recorded.items():
        assert hashlib.sha256((extracted / name).read_bytes()).hexdigest() == digest

    manifest_bytes = (extracted / "manifest.json").read_bytes()
    manifest = _object(manifest_bytes)
    assert _canonical(manifest) == manifest_bytes

    entries = _entries(manifest)
    for entry in entries:
        path = str(entry["path"])
        payload = (extracted / path).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == entry["sha256"]
        assert len(payload) == entry["size_bytes"]
        assert recorded[path] == entry["sha256"]

    selection = _selection_ids(manifest)
    assert selection == sorted(selection)
    assert len(set(selection)) == len(selection)
    pinned = sorted(
        str(entry["artifact_version_id"])
        for entry in entries
        if entry["kind"] == "artifact_version"
    )
    assert pinned == selection

    for name, document in (
        ("action-plan.json", "action_plan"),
        ("provenance.json", "provenance"),
        ("review.json", "review"),
    ):
        assert (extracted / name).read_bytes() == _canonical(manifest[document])
    return manifest


def _object(payload: bytes) -> JsonObject:
    """Decode one JSON object with a declared shape rather than `Any`."""
    value = cast("object", json.loads(payload))
    assert isinstance(value, dict)
    return cast("JsonObject", value)


def _mapping(value: object) -> JsonObject:
    assert isinstance(value, dict)
    return cast("JsonObject", value)


def _objects(value: object) -> list[JsonObject]:
    assert isinstance(value, list)
    return [_mapping(item) for item in cast("list[object]", value)]


def _strings(value: object) -> list[str]:
    assert isinstance(value, list)
    return [str(item) for item in cast("list[object]", value)]


def _entries(manifest: JsonObject) -> list[JsonObject]:
    return _objects(manifest["entries"])


def _selection_ids(manifest: JsonObject) -> list[str]:
    return _strings(_mapping(manifest["selection"])["artifact_version_ids"])


def _section(manifest: JsonObject, key: str) -> JsonObject:
    return _mapping(manifest[key])


def _entry_for(manifest: JsonObject, path: str) -> JsonObject:
    return next(entry for entry in _entries(manifest) if entry["path"] == path)


def _artifact(scope: ArtifactScope, artifact_id: UUID, name: str) -> ArtifactRecord:
    return ArtifactRecord(
        id=artifact_id,
        org_id=scope.org_id,
        project_id=scope.project_id,
        name=name,
        created_at=EXPORTED_AT,
    )


@dataclass(frozen=True, slots=True)
class _CommitSpec:
    """One directly committed Version, for evidence a normal run never makes.

    `execution_id` is not decoration. `commit_version` refuses a Version whose
    producing execution and that execution's Run do not resolve in this exact
    Project, so every spec names the execution of the Run `_published` really
    started. An invented identifier would make these commits fail on
    provenance rather than exercise the behaviour each test is written for.
    """

    scope: ArtifactScope
    artifact_id: UUID
    version_id: UUID
    payload: bytes
    execution_id: UUID
    version_no: int = 1


def _commit(store: LocalArtifactStore, spec: _CommitSpec) -> ArtifactVersion:
    """Commit one Version directly against its exact base version number."""
    digest = hashlib.sha256(spec.payload).hexdigest()
    version = ArtifactVersion(
        id=spec.version_id,
        org_id=spec.scope.org_id,
        project_id=spec.scope.project_id,
        artifact_id=spec.artifact_id,
        version_no=spec.version_no,
        object_key=LocalArtifactStore.object_key(spec.scope, digest),
        content_sha256=digest,
        size_bytes=len(spec.payload),
        media_type="application/octet-stream",
        producing_execution_id=spec.execution_id,
        environment_sha256=SHA_PLACEHOLDER,
        code_sha256=SHA_PLACEHOLDER,
        runtime_adapter_id="local_deterministic",
        runtime_connection_id=LOCAL_RUNTIME_CONNECTION_ID,
        skill_content_hashes=(),
        source_hashes=(),
        input_version_ids=(),
        created_at=EXPORTED_AT,
    )
    assert (
        store.commit_version(spec.scope, spec.version_no - 1, version, spec.payload)
        is StoreOutcome.CREATED
    )
    return version


def _leaking_entry(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    payload: bytes,
    execution_id: UUID,
) -> ExportEntry:
    """Publish a Version whose bytes carry credential material and select it.

    The leaking Version is produced by the same real execution the published
    Run claimed, so the pack is refused for carrying credential material and
    never for an unresolvable producer.
    """
    assert (
        store.create_artifact(scope, _artifact(scope, EXTRA_ARTIFACT_ID, "leak.bin"))
        is StoreOutcome.CREATED
    )
    _ = _commit(
        store,
        _CommitSpec(scope, EXTRA_ARTIFACT_ID, EXTRA_VERSION_ID, payload, execution_id),
    )
    return ExportEntry(
        artifact_id=EXTRA_ARTIFACT_ID,
        artifact_version_id=EXTRA_VERSION_ID,
        path="artifacts/leak.bin",
    )


def _submit_review(
    store: LocalArtifactStore,
    scope: ArtifactScope,
    run_id: UUID,
) -> ReviewRecord:
    evidence = store.pinned_run_evidence(scope, run_id)
    assert evidence is not None
    versions = tuple(sorted(evidence.artifact_version_ids, key=str))
    executions = tuple(sorted(evidence.execution_ids, key=str))
    review = ReviewRecord(
        id=REVIEW_ID,
        org_id=scope.org_id,
        project_id=scope.project_id,
        source_run_id=run_id,
        state=ReviewState.QUEUED,
        pinned_input_sha256=LocalArtifactStore.pinned_input_digest(
            scope,
            run_id,
            versions,
            executions,
        ),
        pinned_artifact_version_ids=versions,
        pinned_execution_ids=executions,
        created_at=REVIEWED_AT,
        updated_at=REVIEWED_AT,
    )
    assert store.open_review(scope, review) is StoreOutcome.CREATED
    assert store.start_review(scope, review.id, REVIEWED_AT) is StoreOutcome.CREATED
    outcome = Reviewer(evidence).review()
    submission = findings_submission(review, outcome, FINDING_IDS, REVIEWED_AT)
    assert store.submit_review_findings(scope, submission) is StoreOutcome.CREATED
    return review


def _reason(error: pytest.ExceptionInfo[ExportError]) -> str:
    return error.value.reason.value


# --------------------------------------------------------------------------
# Round trip against the real filesystem
# --------------------------------------------------------------------------


def test_a_written_pack_verifies_from_its_extracted_bytes_alone(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    destination, _, run, _ = _exported(store, paths, tmp_path, _full_attestation())
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)

    assert manifest["schema"] == "nipo.local.export-pack.v1"
    assert sorted(str(entry["path"]) for entry in _entries(manifest)) == [
        "action-plan.json",
        "artifacts/analysis-report.md",
        "artifacts/evidence-ledger.json",
        "artifacts/hypothesis-table.csv",
        "artifacts/spectrum-plot.png",
        "environment.json",
        "provenance.json",
        "research-intent.json",
        "review.json",
        "run-record.json",
        "scientific-input.json",
    ]
    # The bytes on disk are the science package's own output, obtained without
    # asking the exporter what it thinks it wrote.
    assert (extracted / "artifacts/hypothesis-table.csv").read_bytes() == (
        run.analysis.hypothesis_table_csv
    )


def test_the_pack_verifies_under_an_external_checksum_tool(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    """A stranger with coreutils and nothing else must be able to check it."""
    destination, _, _, _ = _exported(store, paths, tmp_path)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    completed = subprocess.run(
        ["/usr/bin/shasum", "-a", "256", "-c", "checksums.sha256"],
        cwd=extracted,
        capture_output=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr
    assert b"FAILED" not in completed.stdout


def test_checksums_cover_every_member_except_the_checksum_file(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    destination, _, _, _ = _exported(store, paths, tmp_path)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    names = {
        line.split("  ", 1)[1]
        for line in (extracted / "checksums.sha256").read_text("utf-8").splitlines()
    }
    assert "checksums.sha256" not in names
    assert "manifest.json" in names
    assert names == {
        str(item.relative_to(extracted))
        for item in extracted.rglob("*")
        if item.is_file()
    } - {"checksums.sha256"}


def test_the_manifest_records_no_digest_of_itself(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    destination, _, _, _ = _exported(store, paths, tmp_path)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    payload = (extracted / "manifest.json").read_bytes()
    digest = hashlib.sha256(payload).hexdigest()
    assert digest.encode("ascii") not in payload
    manifest = _object(payload)
    assert "manifest.json" not in {str(entry["path"]) for entry in _entries(manifest)}
    # An exact key set, so no field claiming to be the manifest's own digest
    # can be added without this failing.
    assert sorted(manifest) == [
        "action_plan",
        "created_at",
        "disclosures",
        "entries",
        "org_id",
        "pack_id",
        "project_id",
        "provenance",
        "research_intent_sha256",
        "review",
        "schema",
        "selection",
        "verification",
    ]
    assert "sha256" not in manifest
    assert str(_section(manifest, "verification")["manifest_self_digest"]).startswith(
        "absent by construction"
    )


def test_manifest_bytes_are_ascii_even_when_an_entry_path_is_not(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    """`ensure_ascii=true` is the pack rule; the archive name stays UTF-8."""
    scope, run = _published(store, paths)
    entries = list(entries_for_run(store, scope, run.run_id))
    entries[0] = ExportEntry(
        artifact_id=entries[0].artifact_id,
        artifact_version_id=entries[0].artifact_version_id,
        path="artifacts/résumé-täble.csv",
    )
    destination = tmp_path / "unicode.zip"
    _ = export_run(store, scope, paths, _request(entries, run.run_id), destination)
    with zipfile.ZipFile(destination) as archive:
        manifest = archive.read("manifest.json")
        assert "artifacts/résumé-täble.csv" in archive.namelist()
    assert manifest.decode("ascii")
    assert b"r\\u00e9sum\\u00e9-t\\u00e4ble.csv" in manifest


def test_two_exports_of_the_same_evidence_are_byte_identical(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    request = _request(entries, run.run_id, _full_attestation())
    first = tmp_path / "first.zip"
    second = tmp_path / "second.zip"
    _ = export_run(store, scope, paths, request, first)
    _ = export_run(store, scope, paths, request, second)
    assert first.read_bytes() == second.read_bytes()


# --------------------------------------------------------------------------
# Explicit Version pinning, never latest
# --------------------------------------------------------------------------


def test_export_packs_the_pinned_version_not_the_newer_one(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    """The race the requirement exists to prevent, played out for real."""
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    pinned = entries[0]
    assert pinned.artifact_version_id is not None
    original = store.read_content(scope, pinned.artifact_version_id)
    assert original is not None
    successor = b"claim,value\nsuperseded,1\n"
    assert successor != original
    _ = _commit(
        store,
        _CommitSpec(
            scope,
            pinned.artifact_id,
            SUCCESSOR_VERSION_ID,
            successor,
            run.provenance.execution_id,
            version_no=2,
        ),
    )

    destination = tmp_path / "pinned.zip"
    _ = export_run(store, scope, paths, _request(entries, run.run_id), destination)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)

    packed = (extracted / pinned.path).read_bytes()
    assert packed == original
    assert packed != successor
    entry = _entry_for(manifest, pinned.path)
    assert entry["version_no"] == 1
    assert entry["artifact_version_id"] == str(pinned.artifact_version_id)
    assert str(SUCCESSOR_VERSION_ID) not in _selection_ids(manifest)


def test_an_entry_without_a_pinned_version_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    """An artifact named without a Version is refused, never resolved to head."""
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    unpinned = ExportEntry(
        artifact_id=entries[1].artifact_id,
        artifact_version_id=None,
        path="artifacts/unpinned.png",
    )
    request = _request(
        (entries[0], unpinned),
        run.run_id,
        selection=_selection(entries[:1]),
    )
    with pytest.raises(ExportError) as error:
        _ = export_run(store, scope, paths, request, tmp_path / "refused.zip")
    assert _reason(error) == "version_not_pinned"
    assert not list(tmp_path.glob("*.zip"))


def test_a_version_that_does_not_exist_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    absent = ExportEntry(
        artifact_id=entries[0].artifact_id,
        artifact_version_id=ABSENT_VERSION_ID,
        path="artifacts/absent.csv",
    )
    with pytest.raises(ExportError) as error:
        _ = build_pack(store, scope, paths, _request((absent,), run.run_id))
    assert _reason(error) == "version_not_found"


def test_an_entry_naming_the_wrong_artifact_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    crossed = ExportEntry(
        artifact_id=entries[1].artifact_id,
        artifact_version_id=entries[0].artifact_version_id,
        path="artifacts/crossed.csv",
    )
    with pytest.raises(ExportError) as error:
        _ = build_pack(store, scope, paths, _request((crossed,), run.run_id))
    assert _reason(error) == "entry_artifact_mismatch"


# --------------------------------------------------------------------------
# Selection rules
# --------------------------------------------------------------------------


def test_an_unsorted_selection_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    reversed_selection = tuple(reversed(_selection(entries)))
    request = _request(entries, run.run_id, selection=reversed_selection)
    with pytest.raises(ExportError) as error:
        _ = build_pack(store, scope, paths, request)
    assert _reason(error) == "selection_unsorted"


def test_a_repeated_selection_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    selection = _selection(entries)
    request = _request(
        entries,
        run.run_id,
        selection=(selection[0], *selection),
    )
    with pytest.raises(ExportError) as error:
        _ = build_pack(store, scope, paths, request)
    assert _reason(error) == "selection_duplicate"


def test_an_empty_selection_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run = _published(store, paths)
    with pytest.raises(ExportError) as error:
        _ = build_pack(store, scope, paths, _request((), run.run_id, selection=()))
    assert _reason(error) == "selection_empty"


def test_a_selection_that_is_not_what_the_entries_export_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    request = _request(entries[:3], run.run_id, selection=_selection(entries))
    with pytest.raises(ExportError) as error:
        _ = build_pack(store, scope, paths, request)
    assert _reason(error) == "selection_mismatch"


# --------------------------------------------------------------------------
# Hostile paths
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("path", "expected"),
    [
        ("/etc/passwd", "path_absolute"),
        ("/artifacts/table.csv", "path_absolute"),
        ("C:/Windows/system32/table.csv", "path_drive_qualified"),
        ("c:table.csv", "path_drive_qualified"),
        ("artifacts\\table.csv", "path_backslash"),
        ("..", "path_dot_segment"),
        ("../../etc/passwd", "path_dot_segment"),
        ("artifacts/../../escape.csv", "path_dot_segment"),
        ("./table.csv", "path_dot_segment"),
        ("artifacts/./table.csv", "path_dot_segment"),
        ("artifacts//table.csv", "path_empty_segment"),
        ("artifacts/table.csv/", "path_empty_segment"),
        ("artifacts/table.", "path_segment_trailing_dot"),
        ("artifacts./table.csv", "path_segment_trailing_dot"),
        ("artifacts/table.csv ", "path_segment_trailing_space"),
        ("artifacts/tab\nle.csv", "path_control_character"),
        ("artifacts/tab\x00le.csv", "path_control_character"),
        ("artifacts/AUX.csv", "path_reserved_device"),
        ("artifacts/con", "path_reserved_device"),
        ("nul.txt", "path_reserved_device"),
        ("artifacts/COM1.csv", "path_reserved_device"),
        ("artifacts/lpt9.dat", "path_reserved_device"),
        ("", "path_empty"),
        ("manifest.json", "path_reserved_root"),
        ("checksums.sha256", "path_reserved_root"),
        ("provenance.json", "path_reserved_root"),
        ("action-plan.json", "path_reserved_root"),
        ("review.json", "path_reserved_root"),
        ("run-record.json", "path_reserved_root"),
        ("research-intent.json", "path_reserved_root"),
        ("manifest.json/child.csv", "path_reserved_root"),
        ("MANIFEST.JSON", "path_collision"),
        ("Checksums.SHA256", "path_collision"),
        ("a" * 300, "path_too_long"),
        ("artifacts/" + "b" * 1100, "path_too_long"),
    ],
)
def test_a_hostile_entry_path_refuses_the_whole_pack(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
    path: str,
    expected: str,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    hostile = (
        ExportEntry(
            artifact_id=entries[0].artifact_id,
            artifact_version_id=entries[0].artifact_version_id,
            path=path,
        ),
    )
    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(hostile, run.run_id),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == expected
    assert not (tmp_path / "refused.zip").exists()


@pytest.mark.parametrize(
    "pair",
    [CASE_PAIR, NFC_NFD_PAIR, LIGATURE_PAIR, FULLWIDTH_PAIR, ROMAN_PAIR],
)
def test_two_paths_that_normalize_together_refuse_the_whole_pack(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
    pair: tuple[str, str],
) -> None:
    assert pair[0] != pair[1]
    assert pair[0].encode("utf-8") != pair[1].encode("utf-8")
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    colliding = tuple(
        ExportEntry(
            artifact_id=entry.artifact_id,
            artifact_version_id=entry.artifact_version_id,
            path=path,
        )
        for entry, path in zip(entries[:2], pair, strict=True)
    )
    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(colliding, run.run_id),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == "path_collision"
    assert not (tmp_path / "refused.zip").exists()


@pytest.mark.skipif(
    sys.platform != "darwin",
    reason="APFS folds case and normalization; Linux filesystems do not",
)
@pytest.mark.parametrize("pair", [CASE_PAIR, NFC_NFD_PAIR, LIGATURE_PAIR])
def test_the_refused_pairs_really_do_collapse_on_this_filesystem(
    tmp_path: Path,
    pair: tuple[str, str],
) -> None:
    """The rejection is not theoretical on the platform this product supports.

    macOS is both case-insensitive and normalization-insensitive by default,
    so these three pairs written side by side leave one file, not two. The
    exporter is additionally stricter than this filesystem for pairs that only
    NFKC folds; those are covered by the rejection test, not by this one.
    """
    directory = tmp_path / "collapse"
    directory.mkdir()
    for index, name in enumerate(pair):
        _ = (directory / Path(name).name).write_bytes(f"{index}".encode())
    assert len(list(directory.iterdir())) == 1


def test_an_entry_that_is_a_directory_prefix_of_another_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    nested = tuple(
        ExportEntry(
            artifact_id=entry.artifact_id,
            artifact_version_id=entry.artifact_version_id,
            path=path,
        )
        for entry, path in zip(entries[:2], ("data", "data/table.csv"), strict=True)
    )
    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(nested, run.run_id),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == "path_directory_prefix"
    assert not (tmp_path / "refused.zip").exists()


# --------------------------------------------------------------------------
# Links, real ones
# --------------------------------------------------------------------------


def test_a_symbolic_link_where_the_run_record_belongs_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    """The one member read from an arbitrary path is the one a link can swap."""
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    mirror = tmp_path / "data-root" / "runs" / f"{run.provenance.execution_id}.json"
    assert mirror.is_file()
    mirror.unlink()
    mirror.symlink_to(signing_key_path(paths))
    assert mirror.is_symlink()

    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(entries, run.run_id),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == "link_entry"
    assert not (tmp_path / "refused.zip").exists()


def test_a_hard_link_where_the_run_record_belongs_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    mirror = tmp_path / "data-root" / "runs" / f"{run.provenance.execution_id}.json"
    other = tmp_path / "second-name.json"
    os.link(mirror, other)
    assert mirror.stat().st_nlink == 2

    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(entries, run.run_id),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == "link_entry"
    assert not (tmp_path / "refused.zip").exists()


def test_writing_through_a_symbolic_link_destination_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    pack = build_pack(store, scope, paths, _request(entries, run.run_id))
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    destination = tmp_path / "pack.zip"
    destination.symlink_to(elsewhere / "escaped.zip")

    with pytest.raises(ExportError) as error:
        write_pack(pack, destination)
    assert _reason(error) == "link_entry"
    assert not (elsewhere / "escaped.zip").exists()


def test_writing_into_a_symbolic_link_directory_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    pack = build_pack(store, scope, paths, _request(entries, run.run_id))
    real = tmp_path / "real"
    real.mkdir()
    link = tmp_path / "link"
    link.symlink_to(real, target_is_directory=True)

    with pytest.raises(ExportError) as error:
        write_pack(pack, link / "pack.zip")
    assert _reason(error) == "link_entry"
    assert not list(real.iterdir())


def test_an_existing_destination_is_never_overwritten(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    pack = build_pack(store, scope, paths, _request(entries, run.run_id))
    destination = tmp_path / "pack.zip"
    _ = destination.write_bytes(b"an earlier pack")

    with pytest.raises(ExportError) as error:
        write_pack(pack, destination)
    assert _reason(error) == "destination_exists"
    assert destination.read_bytes() == b"an earlier pack"


def test_every_written_member_is_a_regular_owner_only_file(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    destination, _, _, _ = _exported(store, paths, tmp_path)
    assert stat.S_IMODE(destination.stat().st_mode) == 0o600
    with zipfile.ZipFile(destination) as archive:
        modes = {info.filename: info.external_attr >> 16 for info in archive.infolist()}
    assert modes
    for name, mode in modes.items():
        assert stat.S_ISREG(mode), name
        assert not stat.S_ISLNK(mode), name
        assert stat.S_IMODE(mode) == 0o600, name


# --------------------------------------------------------------------------
# Credential canaries
# --------------------------------------------------------------------------


def _seed_credentials(paths: LocalPaths) -> None:
    paths.ensure()
    _ = paths.credentials.write_text(
        json.dumps({"version": 1, "entries": {"acme": SEALED_CANARY}}),
        encoding="utf-8",
    )


def test_no_credential_material_reaches_a_pack(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Absence proven with a canary, over the pack's own bytes and members."""
    _seed_credentials(paths)
    monkeypatch.setenv("NIPO_ACME_API_KEY", ENV_CANARY)
    destination, _, _, _ = _exported(store, paths, tmp_path, _full_attestation())
    signing_key = signing_key_path(paths).read_bytes()
    assert len(signing_key) == 32

    forbidden = [
        SEALED_CANARY.encode("utf-8"),
        ENV_CANARY.encode("utf-8"),
        signing_key,
        signing_key.hex().encode("ascii"),
        signing_key.hex().upper().encode("ascii"),
        b"download-signing.key",
    ]
    raw = destination.read_bytes()
    for needle in forbidden:
        assert needle not in raw

    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    _ = _verify_independently(extracted)
    for item in extracted.rglob("*"):
        if not item.is_file():
            continue
        payload = item.read_bytes()
        for needle in forbidden:
            assert needle not in payload, str(item.relative_to(extracted))
        for needle in forbidden:
            assert needle not in str(item.relative_to(extracted)).encode("utf-8")


def test_an_artifact_carrying_a_sealed_credential_refuses_the_pack(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    _seed_credentials(paths)
    scope, run = _published(store, paths)
    entries = (
        *entries_for_run(store, scope, run.run_id),
        _leaking_entry(
            store,
            scope,
            f"leaked provider blob: {SEALED_CANARY}\n".encode(),
            run.provenance.execution_id,
        ),
    )
    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(entries, run.run_id),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == "credential_material"
    assert not (tmp_path / "refused.zip").exists()


def test_an_artifact_carrying_the_download_signing_key_refuses_the_pack(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    signing_key = signing_key_path(paths).read_bytes()
    entries = (
        *entries_for_run(store, scope, run.run_id),
        _leaking_entry(store, scope, signing_key, run.provenance.execution_id),
    )
    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(entries, run.run_id),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == "credential_material"
    assert not (tmp_path / "refused.zip").exists()


def test_an_artifact_carrying_an_environment_provider_key_refuses_the_pack(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("NIPO_ACME_API_KEY", ENV_CANARY)
    scope, run = _published(store, paths)
    entries = (
        *entries_for_run(store, scope, run.run_id),
        _leaking_entry(
            store,
            scope,
            ENV_CANARY.encode("utf-8"),
            run.provenance.execution_id,
        ),
    )
    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(entries, run.run_id),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == "credential_material"


# --------------------------------------------------------------------------
# Provenance and honest disclosure
# --------------------------------------------------------------------------


def test_every_exported_version_carries_its_full_pinned_provenance(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    destination, _, run, _ = _exported(store, paths, tmp_path, _full_attestation())
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)
    provenance = _section(manifest, "provenance")
    execution = _mapping(provenance["execution"])
    assert execution["execution_isolation"] == "in_process"
    assert execution["execution_isolation_is_a_sandbox"] is False
    assert execution["id"] == str(run.provenance.execution_id)

    versions = _objects(provenance["versions"])
    assert len(versions) == 4
    required = {
        "artifact_id",
        "artifact_version_id",
        "code_sha256",
        "content_sha256",
        "created_at",
        "environment_sha256",
        "input_version_ids",
        "media_type",
        "object_key",
        "output_name",
        "output_sequence",
        "path",
        "producing_execution_id",
        "role",
        "runtime_adapter_id",
        "runtime_connection_id",
        "size_bytes",
        "skill_content_hashes",
        "source_hashes",
        "version_no",
    }
    for record in versions:
        assert required <= set(record)
        assert record["producing_execution_id"] == str(run.provenance.execution_id)
        recomputed = hashlib.sha256(
            (extracted / str(record["path"])).read_bytes()
        ).hexdigest()
        assert record["content_sha256"] == recomputed
    assert {str(record["role"]) for record in versions} == {
        "csv",
        "png",
        "markdown",
        "ledger",
    }


def test_the_pack_discloses_what_it_cannot_prove(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    destination, _, _, _ = _exported(store, paths, tmp_path)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)
    disclosures = _section(manifest, "disclosures")
    assert disclosures["execution_isolation"] == "in_process"
    assert disclosures["execution_isolation_is_a_sandbox"] is False
    assert "sandbox" not in str(disclosures["execution_isolation_note"]).lower() or (
        "asserts no" in str(disclosures["execution_isolation_note"])
    )
    for key in (
        "environment_digest_coverage",
        "export_selections_not_persisted",
        "keychain_master_key",
        "skill_content_hashes",
        "code_digest",
    ):
        assert str(disclosures[key])

    verification = _section(manifest, "verification")
    assert sorted(_mapping(verification["not_recomputable_from_pack"])) == [
        "code_sha256",
        "environment_sha256",
        "input_sha256",
        "research_intent_sha256",
    ]


def test_the_manifest_states_how_to_verify_without_this_codebase(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    destination, _, _, _ = _exported(store, paths, tmp_path)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)
    verification = _section(manifest, "verification")
    assert verification["digest_algorithm"] == "sha256"
    assert verification["checksums_file"] == "checksums.sha256"
    assert verification["checksums_line_format"] == (
        "<64 lowercase hex digits><two spaces><pack-relative path>"
    )
    assert verification["canonical_json"] == (
        "json.dumps(value, sort_keys=True, separators=(',', ':'), "
        "ensure_ascii=True).encode('utf-8')"
    )
    assert len(_strings(verification["steps"])) >= 8


# --------------------------------------------------------------------------
# Review status travels with the evidence
# --------------------------------------------------------------------------


def test_a_submitted_review_and_its_findings_travel_with_the_pack(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    review = _submit_review(store, scope, run.run_id)
    entries = entries_for_run(store, scope, run.run_id)
    destination = tmp_path / "reviewed.zip"
    _ = export_run(store, scope, paths, _request(entries, run.run_id), destination)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)

    section = _section(manifest, "review")
    assert section["present"] is True
    assert section["state"] == "completed"
    assert section["id"] == str(review.id)
    assert section["pinned_input_sha256"] == review.pinned_input_sha256
    findings = _objects(section["findings"])
    assert [str(item["rule_id"]) for item in findings] == [
        "RV01",
        "RV02",
        "RV03",
        "RV04",
        "RV05",
    ]
    for item in findings:
        assert item["verdict"] in {"pass", "warn", "fail", "inconclusive"}
        assert item["status"] == "open"


def test_an_unreviewed_run_records_the_absence_rather_than_claiming_review(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    destination, _, _, _ = _exported(store, paths, tmp_path)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)
    section = _section(manifest, "review")
    assert section["present"] is False
    assert section["findings"] == []
    assert len(str(section["pinned_input_sha256"])) == 64


def test_the_caller_cannot_choose_which_review_the_pack_reports(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    """The Review is looked up from the Run's own pins, never named by a caller."""
    scope, run = _published(store, paths)
    _ = _submit_review(store, scope, run.run_id)
    entries = entries_for_run(store, scope, run.run_id)
    # Export only two of the four outputs: the Review still travels whole.
    subset = entries[:2]
    destination = tmp_path / "subset.zip"
    _ = export_run(store, scope, paths, _request(subset, run.run_id), destination)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)
    section = _section(manifest, "review")
    assert section["present"] is True
    assert len(_strings(section["pinned_artifact_version_ids"])) == 4


# --------------------------------------------------------------------------
# Attested bytes behind digests the store does not persist
# --------------------------------------------------------------------------


def test_attested_intent_bytes_make_the_intent_digest_recomputable(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    destination, _, _, _ = _exported(store, paths, tmp_path, _full_attestation())
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)

    intent_bytes = (extracted / "research-intent.json").read_bytes()
    provenance = _section(manifest, "provenance")
    execution = _mapping(provenance["execution"])
    pinned_intent = str(execution["research_intent_sha256"])
    assert hashlib.sha256(intent_bytes).hexdigest() == pinned_intent
    assert manifest["research_intent_sha256"] == pinned_intent

    input_bytes = (extracted / "scientific-input.json").read_bytes()
    assert hashlib.sha256(input_bytes).hexdigest() == execution["input_sha256"]

    environment_bytes = (extracted / "environment.json").read_bytes()
    assert (
        hashlib.sha256(environment_bytes).hexdigest()
        == (execution["environment_sha256"])
    )

    verification = _section(manifest, "verification")
    assert sorted(_mapping(verification["recomputable_from_pack"])) == [
        "entry_sha256",
        "environment_sha256",
        "input_sha256",
        "manifest_sha256",
        "research_intent_sha256",
    ]
    assert sorted(_mapping(verification["not_recomputable_from_pack"])) == [
        "code_sha256"
    ]


@pytest.mark.parametrize(
    ("attested", "expected"),
    [
        (
            AttestedInputs(research_intent_json=b'{"question":"a different one"}'),
            "intent_digest_mismatch",
        ),
        (
            AttestedInputs(scientific_input_json=b'{"spectrum":null}'),
            "input_digest_mismatch",
        ),
        (
            AttestedInputs(environment_facts={"python": "0.0.0"}),
            "environment_digest_mismatch",
        ),
    ],
)
def test_attested_bytes_that_disagree_with_the_pinned_digest_are_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
    attested: AttestedInputs,
    expected: str,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(entries, run.run_id, attested),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == expected
    assert not (tmp_path / "refused.zip").exists()


# --------------------------------------------------------------------------
# Content integrity and missing evidence
# --------------------------------------------------------------------------


def test_a_tampered_blob_fails_loudly_instead_of_being_packed(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    digest = run.csv.version.content_sha256
    blob = paths.blobs / digest[:2] / digest[2:4] / digest
    original = blob.read_bytes()
    _ = blob.write_bytes(original[:-1] + (b"." if original.endswith(b"\n") else b"\n"))

    with pytest.raises(BlobIntegrityError):
        _ = export_run(
            store,
            scope,
            paths,
            _request(entries, run.run_id),
            tmp_path / "refused.zip",
        )
    assert not (tmp_path / "refused.zip").exists()


def test_the_exporter_re_verifies_bytes_the_store_hands_it(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A pack rests on recomputation, not on what the producing side says.

    The store verifies its own blobs, so a store that lies is the only way to
    show the exporter is not leaning on that verification.
    """
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    target = entries[0].artifact_version_id
    honest = store.redeem_content

    def lying(
        redeem_scope: ArtifactScope,
        version_id: UUID,
    ) -> tuple[StoreOutcome, ArtifactVersion | None, bytes | None]:
        outcome, version, payload = honest(redeem_scope, version_id)
        if version is not None and version.id == target:
            return outcome, version, b"substituted bytes that never hashed to that"
        return outcome, version, payload

    monkeypatch.setattr(store, "redeem_content", lying)
    with pytest.raises(ExportError) as error:
        _ = export_run(
            store,
            scope,
            paths,
            _request(entries, run.run_id),
            tmp_path / "refused.zip",
        )
    assert _reason(error) == "content_digest_mismatch"
    assert not (tmp_path / "refused.zip").exists()


def test_an_unknown_run_is_refused(
    store: LocalArtifactStore,
    paths: LocalPaths,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    with pytest.raises(ExportError) as error:
        _ = build_pack(store, scope, paths, _request(entries, ABSENT_VERSION_ID))
    assert _reason(error) == "run_not_found"


def test_a_missing_run_record_mirror_is_recorded_rather_than_invented(
    store: LocalArtifactStore,
    paths: LocalPaths,
    tmp_path: Path,
) -> None:
    scope, run = _published(store, paths)
    entries = entries_for_run(store, scope, run.run_id)
    (tmp_path / "data-root" / "runs" / f"{run.provenance.execution_id}.json").unlink()
    destination = tmp_path / "mirrorless.zip"
    _ = export_run(store, scope, paths, _request(entries, run.run_id), destination)
    extracted = tmp_path / "fresh"
    _extract(destination, extracted)
    manifest = _verify_independently(extracted)
    assert "run-record.json" not in {str(entry["path"]) for entry in _entries(manifest)}
    assert not (extracted / "run-record.json").exists()
