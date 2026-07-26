"""Real-socket tests for the Export Pack lifecycle: list, remove, and cost.

Export used to be a one-way door. A pack was written under the data root and
nothing listed it, nothing removed it, and no surface showed what it cost.
These tests cover the other half of that door, and they are written against the
two things that can actually be wrong about it:

* **The listing must describe the filesystem.** A size taken from a manifest is
  a description of what is *inside* a pack, not of what the pack costs, and the
  two really are different numbers -- which is asserted, so a total computed
  from the wrong one fails here rather than merely being wrong.
* **Deletion must be confined, and confinement is not a string comparison.** A
  sibling surface was defeated by a check that resolved one path segment too
  many: swap `exports/<project>/` for a link and the comparison agrees with
  wherever the link points. Every hostile shape that has actually worked
  somewhere -- a substituted directory link, a pack that is itself a link to a
  file outside the root, a traversal-shaped identifier, another Project's
  identifier -- is exercised here against a real listener with real links on a
  real filesystem, and the bytes that must survive are checked afterwards.

Assertions use literal status codes, literal JSON field names, and literal
field values rather than constants imported from the modules under test, so a
renamed or retuned constant fails here instead of silently agreeing. Nothing is
asserted by searching for a substring of a filesystem path: `tmp_path` embeds
the test's own function name, which has already produced false-passing
assertions in this repository. Where a path must not appear in a response, the
assertion is that the response carries no path separator at all and that its
object has exactly the closed set of fields it is allowed to have.
"""

import hashlib
import http.client
import io
import json
import os
import zipfile
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from types import MappingProxyType
from typing import cast, final
from uuid import UUID, uuid4

import pytest
from services.api.artifacts.runtime import SystemClock, Uuid7Factory

from nipo_local.api import (
    LocalApiDeps,
    LocalGuard,
    RunningLocalApi,
    create_app,
    new_local_token,
    start_local_api,
)
from nipo_local.apiquery import LocalReadModel
from nipo_local.config import DEFAULT_PROJECT_ID, resolve_paths
from nipo_local.providers import InMemoryCredentialBackend, ProviderRegistry
from nipo_local.runsurface import StoreRunSurface
from nipo_local.store import LocalArtifactStore, ProjectRecord
from nipo_local.webui import StaticSurface
from nipo_local.workbench import (
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

TOKEN_HEADER_NAME = "X-Nipo-Token"  # noqa: S105 - a header name, not a secret
API = "/api/v1"
PROJECTS = f"{API}/projects"
EXPORTS_DIRECTORY_NAME = "exports"
NO_EXTRA: Mapping[str, str] = MappingProxyType({})

#: Every field one listed pack row is allowed to carry, and nothing else. A
#: path field cannot be added without failing this literal.
PACK_ROW_FIELDS = frozenset(
    {
        "pack_id",
        "size_bytes",
        "modified_at",
        "manifest_readable",
        "run_id",
        "created_at",
        "selection",
        "entry_count",
    }
)

LISTING_FIELDS = frozenset(
    {
        "project_id",
        "packs",
        "pack_count",
        "total_size_bytes",
        "budget_bytes",
        "over_budget",
        "undescribed_count",
    }
)

RECEIPT_FIELDS = frozenset(
    {
        "pack_id",
        "project_id",
        "freed_bytes",
        "pack_count",
        "total_size_bytes",
        "over_budget",
    }
)

CHAIN_INTENT = ResearchIntent(
    question="Does the calibrated 430 nm band persist across replicate runs?",
    rationale="A stable corrected maximum would justify a targeted follow-up.",
    intended_benefit="Avoid bench time spent on non-reproducible bands.",
    success_criteria=("A corrected local maximum is reported near 430 nm.",),
    constraints=("Observed calibrated spectra only.",),
    stop_conditions=("Stop when calibration metadata is absent.",),
    research_mode=ResearchMode.AI_FOR_SCIENCE,
    data_origin=DataOrigin.OBSERVED,
)


def _chain_probe() -> ProbeInput:
    """Build the calibrated spectrum the seeded chain really analyses."""
    return ProbeInput(
        spectrum=SpectrumInput(
            wavelengths=(400.0, 410.0, 420.0, 430.0, 440.0, 450.0, 460.0),
            intensities=(0.10, 0.35, 0.20, 0.55, 0.25, 0.30, 0.15),
            metadata=InputMetadata(
                units=(
                    MeasurementUnit(quantity="wavelength", ucum_code="nm"),
                    MeasurementUnit(quantity="intensity", ucum_code="1"),
                ),
                calibration=CalibrationMetadata(
                    method="two-point-standard",
                    reference="NIST-SRM-2242",
                    calibrated_at=datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC),
                    calibration_sha256="c" * 64,
                ),
                lineage_version_ids=(UUID("018f47a0-7b9c-7aaa-8def-0123456789ab"),),
                research_only=True,
                non_clinical=True,
            ),
        )
    )


def as_dict(value: object) -> dict[str, object]:
    """Narrow one decoded JSON value to an object."""
    assert isinstance(value, dict)
    return cast("dict[str, object]", value)


def as_list(value: object) -> list[object]:
    """Narrow one decoded JSON value to an array."""
    assert isinstance(value, list)
    return cast("list[object]", value)


@final
@dataclass(frozen=True, slots=True)
class Call:
    """One HTTP request expressed as data so no helper needs many parameters."""

    method: str = "GET"
    path: str = f"{API}/health"
    body: object | None = None
    omit_token: bool = False
    origin: str | None = None
    site: str | None = None
    host: str | None = None
    extra: Mapping[str, str] = NO_EXTRA


@final
@dataclass(frozen=True, slots=True)
class Reply:
    """One HTTP response captured off the wire."""

    status: int
    headers: Mapping[str, str]
    body: bytes

    def payload(self) -> dict[str, object]:
        """Parse the JSON body."""
        return as_dict(cast("object", json.loads(self.body)))

    def error(self) -> str:
        """Return the stable error code the body carries."""
        return str(self.payload()["error"])

    def rows(self, key: str) -> list[dict[str, object]]:
        """Return one array-of-objects field of the body."""
        return [as_dict(item) for item in as_list(self.payload()[key])]


@final
class Harness:
    """A started local API over a data root the test can inspect directly."""

    def __init__(
        self,
        api: RunningLocalApi,
        store: LocalArtifactStore,
        read_model: LocalReadModel,
        root: Path,
    ) -> None:
        """Retain the running API and the local core behind it."""
        self.api = api
        self.store = store
        self.read_model = read_model
        self.root = root

    def close(self) -> None:
        """Release everything this harness opened."""
        self.api.close()
        self.store.close()
        self.read_model.close()

    @property
    def port(self) -> int:
        """Return the bound loopback port."""
        return self.api.port

    @property
    def token(self) -> str:
        """Return the per-run credential value."""
        return self.api.token.value

    def send(self, call: Call) -> Reply:
        """Issue one real HTTP request and capture the response."""
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            payload = None if call.body is None else json.dumps(call.body).encode()
            connection.putrequest(
                call.method,
                call.path,
                skip_host=True,
                skip_accept_encoding=True,
            )
            connection.putheader("Host", call.host or f"127.0.0.1:{self.port}")
            if not call.omit_token:
                connection.putheader(TOKEN_HEADER_NAME, self.token)
            if call.origin is not None:
                connection.putheader("Origin", call.origin)
            if call.site is not None:
                connection.putheader("Sec-Fetch-Site", call.site)
            for name, value in call.extra.items():
                connection.putheader(name, value)
            if payload is not None:
                connection.putheader("Content-Type", "application/json")
                connection.putheader("Content-Length", str(len(payload)))
            connection.endheaders(payload)
            response = connection.getresponse()
            headers = {name.lower(): value for name, value in response.getheaders()}
            return Reply(response.status, headers, response.read())
        finally:
            connection.close()

    def same_origin(self, method: str, path: str, body: object | None = None) -> Reply:
        """Issue a request that looks exactly like the local front end's."""
        return self.send(
            Call(
                method=method,
                path=path,
                body=body,
                origin=f"http://127.0.0.1:{self.port}",
                site="same-origin",
            )
        )

    def exports_directory(self, project_id: str) -> Path:
        """Return where this Project's packs are written, spelled out literally."""
        return self.root / EXPORTS_DIRECTORY_NAME / project_id

    def pack_path(self, project_id: str, pack_id: str) -> Path:
        """Return one pack's file, built from literals rather than from the code."""
        return self.exports_directory(project_id) / f"{pack_id}.zip"


def _chain_harness(root: Path) -> tuple[Harness, str, str]:
    """Start an API whose store already holds one really published chain."""
    paths = resolve_paths(root)
    paths.ensure()
    store = LocalArtifactStore(paths)
    scope = local_scope(DEFAULT_PROJECT_ID)
    _ = store.create_project(
        scope,
        ProjectRecord(
            id=DEFAULT_PROJECT_ID,
            org_id=scope.org_id,
            name="chain",
            created_at=datetime.now(UTC),
        ),
    )
    runtime = assemble_artifact_runtime(store, paths, project_id=DEFAULT_PROJECT_ID)
    run = run_analysis(
        runtime,
        CHAIN_INTENT,
        _chain_probe(),
        approve_analysis(runtime, CHAIN_INTENT),
    )
    registry = ProviderRegistry(paths, InMemoryCredentialBackend(), {})
    read_model = LocalReadModel(paths)
    api = start_local_api(
        paths,
        LocalApiDeps(
            store=store,
            registry=registry,
            read_model=read_model,
            paths=paths,
            clock=SystemClock(),
            ids=Uuid7Factory(),
            runs=StoreRunSurface(store),
        ),
    )
    harness = Harness(api, store, read_model, root)
    return harness, str(DEFAULT_PROJECT_ID), str(run.run_id)


@pytest.fixture
def chain(tmp_path: Path) -> Iterator[tuple[Harness, str, str]]:
    """Provide a started API over one published chain, ready to export."""
    harness, project_id, run_id = _chain_harness(tmp_path / "root")
    try:
        yield harness, project_id, run_id
    finally:
        harness.close()


def _pinned(harness: Harness, project_id: str, run_id: str) -> list[str]:
    """Return the Version identifiers this Run published, in plan order."""
    reply = harness.send(Call(path=f"{PROJECTS}/{project_id}/runs/{run_id}/export"))
    assert reply.status == 200
    return [str(item["artifact_version_id"]) for item in reply.rows("candidates")]


def _produce(harness: Harness, project_id: str, run_id: str) -> str:
    """Produce one pack over every published Version and return its identifier."""
    reply = harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/runs/{run_id}/export",
        {"artifact_version_ids": _pinned(harness, project_id, run_id)},
    )
    assert reply.status == 201
    return str(reply.payload()["pack_id"])


def _listing(harness: Harness, project_id: str) -> Reply:
    """Read the stored-pack listing for one Project."""
    return harness.send(Call(path=f"{PROJECTS}/{project_id}/exports"))


def _remove(harness: Harness, project_id: str, pack_id: str) -> Reply:
    """Ask for one pack to be removed, exactly as the front end does."""
    return harness.same_origin(
        "DELETE",
        f"{PROJECTS}/{project_id}/exports/{pack_id}",
    )


def _sizes_on_disk(directory: Path) -> dict[str, int]:
    """Read every pack file's real size straight off the filesystem."""
    return {
        item.name: item.stat().st_size
        for item in sorted(directory.iterdir())
        if item.is_file() and item.name.endswith(".zip")
    }


def _manifest_member_total(archive: Path) -> int:
    """Sum what a pack's manifest says its members are.

    Deliberately a different number from the file's size: a manifest describes
    members, and a member total is neither the ZIP's framing nor the two
    documents no entry names.
    """
    with zipfile.ZipFile(io.BytesIO(archive.read_bytes())) as opened:
        manifest = as_dict(cast("object", json.loads(opened.read("manifest.json"))))
    entries = [as_dict(item) for item in as_list(manifest["entries"])]
    return sum(int(cast("int", entry["size_bytes"])) for entry in entries)


def _digest(path: Path) -> str:
    """Return the digest of one file exactly as it is on disk now."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


# --------------------------------------------------------------------------
# Listing: what is on disk, described by disk and by the pack
# --------------------------------------------------------------------------


def test_a_project_that_never_exported_lists_nothing_rather_than_failing(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, _ = chain

    reply = _listing(harness, project_id)

    assert reply.status == 200
    assert set(reply.payload()) == LISTING_FIELDS
    assert reply.payload()["packs"] == []
    assert reply.payload()["pack_count"] == 0
    assert reply.payload()["total_size_bytes"] == 0
    assert reply.payload()["undescribed_count"] == 0
    assert reply.payload()["over_budget"] is False
    # The reported threshold is a literal here, so retuning it is a visible
    # decision rather than a silently agreeing test.
    assert reply.payload()["budget_bytes"] == 2_147_483_648
    assert not harness.exports_directory(project_id).exists()


def test_the_listing_describes_every_pack_that_is_really_on_disk(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    first = _produce(harness, project_id, run_id)
    second = _produce(harness, project_id, run_id)

    reply = _listing(harness, project_id)
    rows = reply.rows("packs")

    assert reply.status == 200
    assert reply.payload()["pack_count"] == 2
    assert {str(row["pack_id"]) for row in rows} == {first, second}
    for row in rows:
        assert set(row) == PACK_ROW_FIELDS
        assert row["manifest_readable"] is True
        # From the pack's own manifest.
        assert row["run_id"] == run_id
        assert len(as_list(row["selection"])) == 4
        assert int(cast("int", row["entry_count"])) >= 4
        # From the filesystem, checked against the file the test opens itself.
        located = harness.pack_path(project_id, str(row["pack_id"]))
        assert row["size_bytes"] == located.stat().st_size


def test_the_reported_total_is_the_size_of_the_files_not_what_a_manifest_claims(
    chain: tuple[Harness, str, str],
) -> None:
    # The mutation this kills: computing the total from `manifest.entries`
    # instead of from `stat`. Both numbers exist and both are plausible, so the
    # test asserts the right one *and* that the wrong one is a different value.
    harness, project_id, run_id = chain
    _ = _produce(harness, project_id, run_id)
    _ = _produce(harness, project_id, run_id)

    on_disk = _sizes_on_disk(harness.exports_directory(project_id))
    reply = _listing(harness, project_id)
    from_manifests = sum(
        _manifest_member_total(harness.pack_path(project_id, str(row["pack_id"])))
        for row in reply.rows("packs")
    )

    assert reply.payload()["total_size_bytes"] == sum(on_disk.values())
    assert from_manifests != sum(on_disk.values())
    assert reply.payload()["total_size_bytes"] != from_manifests


def test_a_pack_whose_manifest_cannot_be_read_is_still_listed_at_its_real_size(
    chain: tuple[Harness, str, str],
) -> None:
    # A corrupt pack is the case where hiding the row would be worst: the file
    # still costs its bytes, and a listing that omitted it would under-report
    # the total and leave nothing to press to reclaim the space.
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    located = harness.pack_path(project_id, pack_id)
    os.truncate(located, 700)

    reply = _listing(harness, project_id)
    row = reply.rows("packs")[0]

    assert reply.status == 200
    assert row["pack_id"] == pack_id
    assert row["manifest_readable"] is False
    assert row["run_id"] is None
    assert row["created_at"] is None
    assert row["selection"] == []
    assert row["entry_count"] == 0
    assert row["size_bytes"] == 700
    assert reply.payload()["total_size_bytes"] == 700
    assert reply.payload()["undescribed_count"] == 1


def test_the_listing_names_no_path_and_carries_no_credential(
    chain: tuple[Harness, str, str],
) -> None:
    # The mutation this kills: a listing that leaks a filesystem path. A path
    # cannot be expressed without a separator, and this body legitimately
    # contains none -- identifiers, digits, and ISO instants have no `/`.
    harness, project_id, run_id = chain
    _ = _produce(harness, project_id, run_id)

    reply = _listing(harness, project_id)
    text = reply.body.decode("utf-8")

    assert reply.status == 200
    assert "/" not in text
    assert "\\" not in text
    assert harness.token not in text
    assert set(reply.payload()) == LISTING_FIELDS
    for row in reply.rows("packs"):
        assert set(row) == PACK_ROW_FIELDS


def test_a_file_that_does_not_name_a_pack_is_not_listed_or_counted(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    directory = harness.exports_directory(project_id)
    _ = (directory / "notes.txt").write_bytes(b"x" * 5000)
    _ = (directory / "not-a-uuid.zip").write_bytes(b"y" * 5000)
    (directory / "nested").mkdir()

    reply = _listing(harness, project_id)

    assert reply.status == 200
    assert [str(row["pack_id"]) for row in reply.rows("packs")] == [pack_id]
    assert reply.payload()["total_size_bytes"] == (
        harness.pack_path(project_id, pack_id).stat().st_size
    )
    assert reply.payload()["undescribed_count"] == 0


def test_a_link_wearing_a_pack_name_is_neither_listed_nor_deletable(
    chain: tuple[Harness, str, str],
) -> None:
    # The mutation this kills: deletion that escapes the exports root by
    # following a link. The link's target is a file the surface has no business
    # touching, and it must still be there afterwards, byte for byte.
    harness, project_id, run_id = chain
    _ = _produce(harness, project_id, run_id)
    outside = harness.root / "not-an-export.bin"
    _ = outside.write_bytes(b"evidence that must survive")
    before = _digest(outside)
    impostor = str(uuid4())
    (harness.exports_directory(project_id) / f"{impostor}.zip").symlink_to(outside)

    listed = _listing(harness, project_id)
    removal = _remove(harness, project_id, impostor)

    assert [str(row["pack_id"]) for row in listed.rows("packs")] != [impostor]
    assert impostor not in {str(row["pack_id"]) for row in listed.rows("packs")}
    assert listed.payload()["undescribed_count"] == 1
    assert removal.status == 404
    assert removal.payload() == {"error": "export_pack_not_found"}
    assert outside.exists()
    assert _digest(outside) == before
    # The link itself is not what this route removes either.
    link = harness.exports_directory(project_id) / f"{impostor}.zip"
    assert os.path.lexists(link)


def test_a_substituted_export_directory_is_refused_rather_than_listed(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    _ = _produce(harness, project_id, run_id)
    owned = harness.exports_directory(project_id)
    elsewhere = harness.root / "somewhere-else"
    _ = owned.rename(elsewhere)
    owned.symlink_to(elsewhere, target_is_directory=True)

    reply = _listing(harness, project_id)

    assert reply.status == 503
    assert reply.payload() == {
        "error": "local_state_unreadable",
        "reason": "exports_unreadable",
    }
    assert len(list(elsewhere.iterdir())) == 1


# --------------------------------------------------------------------------
# Deletion: one named pack, confined to one directory
# --------------------------------------------------------------------------


def test_deleting_a_pack_removes_its_bytes_from_the_filesystem(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    located = harness.pack_path(project_id, pack_id)
    size = located.stat().st_size

    reply = _remove(harness, project_id, pack_id)

    assert reply.status == 200
    assert set(reply.payload()) == RECEIPT_FIELDS
    assert reply.payload()["pack_id"] == pack_id
    assert reply.payload()["project_id"] == project_id
    assert reply.payload()["freed_bytes"] == size
    assert reply.payload()["pack_count"] == 0
    assert reply.payload()["total_size_bytes"] == 0
    assert reply.payload()["over_budget"] is False
    # Gone from the filesystem, not merely gone from a listing.
    assert not located.exists()
    assert not os.path.lexists(located)
    assert _sizes_on_disk(harness.exports_directory(project_id)) == {}
    assert _listing(harness, project_id).payload()["pack_count"] == 0


def test_deleting_one_pack_leaves_every_other_pack_byte_identical(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    kept = [_produce(harness, project_id, run_id) for _ in range(2)]
    doomed = _produce(harness, project_id, run_id)
    before = {item: _digest(harness.pack_path(project_id, item)) for item in kept}

    reply = _remove(harness, project_id, doomed)

    assert reply.status == 200
    assert reply.payload()["pack_count"] == 2
    for item in kept:
        assert _digest(harness.pack_path(project_id, item)) == before[item]
    assert not harness.pack_path(project_id, doomed).exists()


def test_deleting_the_same_pack_twice_is_refused_the_second_time(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)

    first = _remove(harness, project_id, pack_id)
    second = _remove(harness, project_id, pack_id)

    assert first.status == 200
    assert second.status == 404
    assert second.payload() == {"error": "export_pack_not_found"}


def test_deletion_is_refused_through_a_substituted_directory_link(
    chain: tuple[Harness, str, str],
) -> None:
    # The exact shape a sibling agent found: every path component still looks
    # ordinary, and only a check that refuses to resolve the Project segment --
    # or, here, one that opens each segment with O_NOFOLLOW -- notices.
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    owned = harness.exports_directory(project_id)
    elsewhere = harness.root / "somewhere-else"
    _ = owned.rename(elsewhere)
    owned.symlink_to(elsewhere, target_is_directory=True)
    before = _digest(elsewhere / f"{pack_id}.zip")

    reply = _remove(harness, project_id, pack_id)

    assert reply.status == 404
    assert reply.payload() == {"error": "export_pack_not_found"}
    assert (elsewhere / f"{pack_id}.zip").exists()
    assert _digest(elsewhere / f"{pack_id}.zip") == before


def test_a_directory_wearing_a_pack_name_is_refused_rather_than_removed(
    chain: tuple[Harness, str, str],
) -> None:
    # Not a link and not outside the root, so a path-shaped confinement check
    # has nothing to object to: only asking the filesystem what the entry *is*
    # refuses this. It must be a typed refusal, never an unlink that raises and
    # surfaces as an internal error.
    harness, project_id, run_id = chain
    _ = _produce(harness, project_id, run_id)
    impostor = str(uuid4())
    masquerading = harness.exports_directory(project_id) / f"{impostor}.zip"
    masquerading.mkdir()
    _ = (masquerading / "inside.txt").write_bytes(b"still here")

    listed = _listing(harness, project_id)
    removal = _remove(harness, project_id, impostor)

    assert removal.status == 404
    assert removal.payload() == {"error": "export_pack_not_found"}
    assert masquerading.is_dir()
    assert (masquerading / "inside.txt").read_bytes() == b"still here"
    assert impostor not in {str(row["pack_id"]) for row in listed.rows("packs")}
    assert listed.payload()["undescribed_count"] == 1


def test_a_substituted_exports_root_reaches_nothing_at_all(
    chain: tuple[Harness, str, str],
) -> None:
    # The harder half of the substituted-directory family. Swapping the
    # Project's own directory is caught by comparing resolved parents; swapping
    # the `exports` directory above it is not, because both sides of that
    # comparison travel through the same link and agree with wherever it
    # points. Every one of the three routes has to refuse here.
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    minted = harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/exports/{pack_id}/download",
    )
    assert minted.status == 201
    url = str(minted.payload()["url"])
    root = harness.root / EXPORTS_DIRECTORY_NAME
    elsewhere = harness.root / "stolen-exports"
    _ = root.rename(elsewhere)
    root.symlink_to(elsewhere, target_is_directory=True)
    stolen = elsewhere / project_id / f"{pack_id}.zip"
    before = _digest(stolen)

    listed = _listing(harness, project_id)
    removed = _remove(harness, project_id, pack_id)
    downloaded = harness.send(Call(path=url, omit_token=True, site="same-origin"))

    assert listed.status == 503
    assert listed.payload() == {
        "error": "local_state_unreadable",
        "reason": "exports_unreadable",
    }
    assert removed.status == 404
    assert removed.payload() == {"error": "export_pack_not_found"}
    assert downloaded.status == 404
    assert downloaded.payload() == {"error": "export_pack_not_found"}
    assert stolen.exists()
    assert _digest(stolen) == before


def test_a_traversal_shaped_identifier_reaches_no_file(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    _ = _produce(harness, project_id, run_id)
    target = harness.root / "nipo.sqlite3"
    before = _digest(target)

    escapes = [
        f"{PROJECTS}/{project_id}/exports/..%2f..%2fnipo.sqlite3",
        f"{PROJECTS}/{project_id}/exports/%2e%2e%2fnipo.sqlite3",
        f"{PROJECTS}/{project_id}/exports/nipo.sqlite3",
        f"{PROJECTS}/{project_id}/exports/..",
    ]
    replies = [harness.same_origin("DELETE", path) for path in escapes]

    for reply in replies:
        assert reply.status in {400, 404, 405}
        assert reply.error() in {"invalid_request", "not_found", "method_not_allowed"}
    assert target.exists()
    assert _digest(target) == before


def test_another_projects_pack_is_not_reachable_by_identifier(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    created = harness.same_origin("POST", PROJECTS, {"name": "그 옆 프로젝트"})
    assert created.status == 201
    other = str(created.payload()["id"])
    before = _digest(harness.pack_path(project_id, pack_id))

    reply = _remove(harness, other, pack_id)

    assert reply.status == 404
    assert reply.payload() == {"error": "export_pack_not_found"}
    assert harness.pack_path(project_id, pack_id).exists()
    assert _digest(harness.pack_path(project_id, pack_id)) == before


def test_an_unknown_project_neither_lists_nor_deletes(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    absent = "01900000-0000-7000-8000-0000000000ff"

    listed = harness.send(Call(path=f"{PROJECTS}/{absent}/exports"))
    removed = harness.same_origin("DELETE", f"{PROJECTS}/{absent}/exports/{pack_id}")

    assert listed.status == 404
    assert listed.payload() == {"error": "not_found"}
    assert removed.status == 404
    assert removed.payload() == {"error": "not_found"}
    assert harness.pack_path(project_id, pack_id).exists()


def test_an_archived_project_can_still_account_for_and_reclaim_its_packs(
    chain: tuple[Harness, str, str],
) -> None:
    # Archiving blocks writes to evidence. A pack is a derived file, and its
    # bytes do not stop costing anything, so refusing here would be the one
    # branch in which disk use becomes unrecoverable.
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    archived = harness.same_origin("POST", f"{PROJECTS}/{project_id}/archive")
    assert archived.status == 204

    listed = _listing(harness, project_id)
    removed = _remove(harness, project_id, pack_id)

    assert listed.status == 200
    assert [str(row["pack_id"]) for row in listed.rows("packs")] == [pack_id]
    assert removed.status == 200
    assert not harness.pack_path(project_id, pack_id).exists()


# --------------------------------------------------------------------------
# The guard applies here exactly as it does everywhere else
# --------------------------------------------------------------------------


def test_deleting_without_the_session_credential_is_refused(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    before = _digest(harness.pack_path(project_id, pack_id))

    missing = harness.send(
        Call(
            method="DELETE",
            path=f"{PROJECTS}/{project_id}/exports/{pack_id}",
            omit_token=True,
            site="same-origin",
        )
    )
    listed = harness.send(
        Call(path=f"{PROJECTS}/{project_id}/exports", omit_token=True)
    )

    assert missing.status == 401
    assert missing.payload() == {"error": "local_token_required"}
    assert listed.status == 401
    assert listed.payload() == {"error": "local_token_required"}
    assert _digest(harness.pack_path(project_id, pack_id)) == before


def test_a_cross_site_deletion_is_refused_before_the_credential_is_read(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    before = _digest(harness.pack_path(project_id, pack_id))

    reply = harness.send(
        Call(
            method="DELETE",
            path=f"{PROJECTS}/{project_id}/exports/{pack_id}",
            site="cross-site",
        )
    )

    assert reply.status == 403
    assert reply.payload() == {"error": "cross_origin_denied"}
    assert _digest(harness.pack_path(project_id, pack_id)) == before


def test_a_rebound_authority_cannot_delete_a_pack(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)

    reply = harness.send(
        Call(
            method="DELETE",
            path=f"{PROJECTS}/{project_id}/exports/{pack_id}",
            host="workbench.example",
            site="same-origin",
        )
    )

    assert reply.status == 403
    assert reply.payload() == {"error": "host_not_allowed"}
    assert harness.pack_path(project_id, pack_id).exists()


def test_a_download_capability_is_not_permission_to_delete(
    chain: tuple[Harness, str, str],
) -> None:
    # The capability is a second credential, never an exemption. It opens one
    # pack for reading and answers nothing else -- and holding one does not make
    # the credential-guarded delete route reachable without the credential.
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    minted = harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/exports/{pack_id}/download",
    )
    assert minted.status == 201
    url = str(minted.payload()["url"])
    before = _digest(harness.pack_path(project_id, pack_id))

    through_capability = harness.send(
        Call(method="DELETE", path=url, omit_token=True, site="same-origin")
    )
    without_credential = harness.send(
        Call(
            method="DELETE",
            path=f"{PROJECTS}/{project_id}/exports/{pack_id}",
            omit_token=True,
            site="same-origin",
        )
    )

    assert through_capability.status == 405
    assert through_capability.payload() == {"error": "method_not_allowed"}
    assert without_credential.status == 401
    assert without_credential.payload() == {"error": "local_token_required"}
    assert _digest(harness.pack_path(project_id, pack_id)) == before


def test_the_credential_exempt_path_set_did_not_widen(tmp_path: Path) -> None:
    # The lifecycle added two routes. Neither may become credential-free, so the
    # exempt set is asserted against literal paths rather than against whatever
    # the static surface happens to enumerate today.
    paths = resolve_paths(tmp_path / "root")
    paths.ensure()
    store = LocalArtifactStore(paths)
    read_model = LocalReadModel(paths)
    try:
        guard = create_app(
            LocalApiDeps(
                store=store,
                registry=ProviderRegistry(paths, InMemoryCredentialBackend(), {}),
                read_model=read_model,
                paths=paths,
                clock=SystemClock(),
                ids=Uuid7Factory(),
            ),
            new_local_token(),
            origins=frozenset({"http://127.0.0.1:1"}),
            authorities=frozenset({"127.0.0.1:1"}),
            web=StaticSurface(),
        )
        documents = cast("LocalGuard", guard).documents
    finally:
        store.close()
        read_model.close()

    assert documents == frozenset(
        {"/", "/index.html", "/app.js", "/favicon.svg", "/styles.css"}
    )


# --------------------------------------------------------------------------
# Bounded growth: the cost is reported, and nothing is ever removed for you
# --------------------------------------------------------------------------


def test_no_route_selects_packs_for_removal(
    chain: tuple[Harness, str, str],
) -> None:
    # The mutation this kills: a sweep endpoint that picks its own victims. If
    # one existed, one of these would stop being a refusal.
    harness, project_id, run_id = chain
    kept = [_produce(harness, project_id, run_id) for _ in range(3)]

    collection = f"{PROJECTS}/{project_id}/exports"
    collection_delete = harness.same_origin("DELETE", collection)
    collection_post = harness.same_origin("POST", collection)
    named_sweep = harness.same_origin("POST", f"{collection}/sweep")
    sweep_as_pack = harness.same_origin("DELETE", f"{collection}/sweep")

    assert collection_delete.status == 405
    assert collection_delete.payload() == {"error": "method_not_allowed"}
    assert collection_post.status == 405
    assert named_sweep.status in {404, 405}
    assert sweep_as_pack.status == 400
    assert sweep_as_pack.payload() == {"error": "invalid_request"}
    for pack_id in kept:
        assert harness.pack_path(project_id, pack_id).exists()


def test_producing_more_packs_never_evicts_an_older_one(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain

    produced = [_produce(harness, project_id, run_id) for _ in range(5)]

    reply = _listing(harness, project_id)
    assert reply.payload()["pack_count"] == 5
    assert {str(row["pack_id"]) for row in reply.rows("packs")} == set(produced)
    for pack_id in produced:
        assert harness.pack_path(project_id, pack_id).exists()


def test_crossing_the_budget_warns_and_still_removes_nothing(
    chain: tuple[Harness, str, str],
) -> None:
    # The file is grown sparsely: `st_size` is what the listing reports, and no
    # blocks are allocated for the zeros. Growing it past the end of the ZIP's
    # central directory also makes the manifest unreadable, which is why the row
    # is asserted on its filesystem fields only.
    harness, project_id, run_id = chain
    small = _produce(harness, project_id, run_id)
    swollen = _produce(harness, project_id, run_id)
    grown = harness.pack_path(project_id, swollen)
    os.truncate(grown, 2_147_483_649)
    assert grown.stat().st_size == 2_147_483_649

    reply = _listing(harness, project_id)
    rows = {str(row["pack_id"]): row for row in reply.rows("packs")}

    assert reply.status == 200
    assert reply.payload()["over_budget"] is True
    assert reply.payload()["budget_bytes"] == 2_147_483_648
    assert rows[swollen]["size_bytes"] == 2_147_483_649
    # Over budget removes nothing: both packs are still listed and still there.
    assert reply.payload()["pack_count"] == 2
    assert harness.pack_path(project_id, small).exists()
    assert grown.exists()


def test_the_receipt_reports_what_the_directory_holds_afterwards(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    first = _produce(harness, project_id, run_id)
    second = _produce(harness, project_id, run_id)
    remaining_size = harness.pack_path(project_id, second).stat().st_size
    freed_size = harness.pack_path(project_id, first).stat().st_size

    reply = _remove(harness, project_id, first)

    assert reply.status == 200
    assert reply.payload()["freed_bytes"] == freed_size
    assert reply.payload()["pack_count"] == 1
    assert reply.payload()["total_size_bytes"] == remaining_size
    assert _sizes_on_disk(harness.exports_directory(project_id)) == {
        f"{second}.zip": remaining_size
    }


def test_a_removed_pack_can_no_longer_be_downloaded(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)
    minted = harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/exports/{pack_id}/download",
    )
    assert minted.status == 201
    url = str(minted.payload()["url"])

    removed = _remove(harness, project_id, pack_id)
    spent = harness.send(Call(path=url, omit_token=True, site="same-origin"))
    reminted = harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/exports/{pack_id}/download",
    )

    assert removed.status == 200
    # A capability minted before the removal opens nothing afterwards: the file
    # it named is gone, and the route reads the disk rather than a cache.
    assert spent.status == 404
    assert spent.payload() == {"error": "export_pack_not_found"}
    assert reminted.status == 404
    assert reminted.payload() == {"error": "export_pack_not_found"}


def test_listing_and_deletion_carry_the_same_security_headers_as_every_response(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    pack_id = _produce(harness, project_id, run_id)

    listed = _listing(harness, project_id)
    removed = _remove(harness, project_id, pack_id)

    for reply in (listed, removed):
        assert reply.headers["referrer-policy"] == "no-referrer"
        assert reply.headers["x-content-type-options"] == "nosniff"
        assert reply.headers["cache-control"] == "no-store"
        assert reply.headers["content-security-policy"] == (
            "default-src 'none'; frame-ancestors 'none'"
        )
        assert "access-control-allow-origin" not in reply.headers


def _ordered_identifiers(rows: Sequence[Mapping[str, object]]) -> list[str]:
    """Return the pack identifiers of a listing in the order it returned them."""
    return [str(row["pack_id"]) for row in rows]


def test_the_listing_is_ordered_newest_written_first(
    chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = chain
    produced = [_produce(harness, project_id, run_id) for _ in range(3)]
    directory = harness.exports_directory(project_id)
    # Written times are set explicitly so the order asserted is the one the
    # filesystem reports, not one that happened to fall out of production speed.
    for offset, pack_id in enumerate(produced):
        moment = 1_800_000_000 + offset * 3600
        os.utime(directory / f"{pack_id}.zip", (moment, moment))

    reply = _listing(harness, project_id)

    assert _ordered_identifiers(reply.rows("packs")) == list(reversed(produced))
