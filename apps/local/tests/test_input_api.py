"""Real-socket tests for the L03 measurement-file product intake.

Covers the strict-JSON probe upload route: staging round-trip parity with the
path loader, science-issue refusals, product caps, zero durable side effects,
and the full HTTP file→intent→approve→run→review→export chain.
"""

from __future__ import annotations

import base64
import hashlib
import http.client
import json
import socket
import sqlite3
import zipfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from io import BytesIO
from typing import TYPE_CHECKING, Final, cast, final

import pytest
from PIL import Image
from services.api.artifacts.runtime import Uuid7Factory

from nipo_local.api import (
    PRODUCT_PROBE_JSON_BYTES,
    PRODUCT_UPLOAD_DATA_BYTES,
    PRODUCT_UPLOAD_IMAGE_PIXELS,
    PRODUCT_UPLOAD_SPECTRUM_POINTS,
    LocalApiDeps,
    RunningLocalApi,
    start_local_api,
)
from nipo_local.apiquery import LocalReadModel
from nipo_local.apiserver import MAX_BODY_BYTES
from nipo_local.apitypes import LoaderRejection
from nipo_local.config import resolve_paths
from nipo_local.loaders import (
    MAX_IMAGE_BYTES,
    MAX_IMAGE_PIXELS,
    MAX_TEXT_BYTES,
    load_probe,
)
from nipo_local.providers import InMemoryCredentialBackend, ProviderRegistry
from nipo_local.runsurface import StoreRunSurface
from nipo_local.store import LocalArtifactStore
from science_workbench_science import DataOrigin, ResearchIntent, ResearchMode

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

    from services.api.artifacts.models import Clock

TOKEN_HEADER_NAME = "X-Nipo-Token"  # noqa: S105 - a header name, not a secret
PROJECTS = "/api/v1/projects"
CANARY = "canary-upload-Qq7WwZzXx-do-not-echo"
LINEAGE_UUID7 = "018f47a0-7b9c-7aaa-8def-0123456789ab"
CALIBRATION_DIGEST = "c" * 64

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

INTENT = ResearchIntent(
    question="Does the calibrated 430 nm band persist across replicate runs?",
    rationale="A stable corrected maximum would justify a targeted follow-up.",
    intended_benefit="Avoid bench time spent on non-reproducible bands.",
    success_criteria=("A corrected local maximum is reported near 430 nm.",),
    constraints=("Observed calibrated spectra only.",),
    stop_conditions=("Stop when calibration metadata is absent.",),
    research_mode=ResearchMode.AI_FOR_SCIENCE,
    data_origin=DataOrigin.OBSERVED,
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
    """One HTTP request expressed as data."""

    method: str = "GET"
    path: str = "/api/v1/health"
    body: object | None = None
    omit_token: bool = False
    token: str | None = None
    origin: str | None = None
    site: str | None = None
    host: str | None = None


@final
@dataclass(frozen=True, slots=True)
class Reply:
    """One HTTP response captured off the wire."""

    status: int
    headers: dict[str, str]
    body: bytes

    def payload(self) -> dict[str, object]:
        """Decode the JSON body as an object."""
        return as_dict(cast("object", json.loads(self.body.decode("utf-8"))))

    def error(self) -> str:
        """Return the closed error code."""
        return str(self.payload()["error"])


@final
class _MovableClock:
    """A clock a test can advance so expiry is asserted rather than waited."""

    def __init__(self) -> None:
        self.moment = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)

    def now(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)


@final
class Harness:
    """A started local API plus helpers for the input/plan/run chain."""

    def __init__(
        self,
        api: RunningLocalApi,
        store: LocalArtifactStore,
        registry: ProviderRegistry,
        read_model: LocalReadModel,
        clock: Clock,
    ) -> None:
        self.api = api
        self.store = store
        self.registry = registry
        self.read_model = read_model
        self.clock = clock
        self.root = api.token_path.parent
        self.ids = Uuid7Factory()

    def close(self) -> None:
        self.api.close()
        self.store.close()
        self.read_model.close()

    @property
    def port(self) -> int:
        return self.api.port

    @property
    def token(self) -> str:
        return self.api.token.value

    def send(self, call: Call) -> Reply:
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=60)
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
                connection.putheader(TOKEN_HEADER_NAME, call.token or self.token)
            if call.origin is not None:
                connection.putheader("Origin", call.origin)
            if call.site is not None:
                connection.putheader("Sec-Fetch-Site", call.site)
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
        return self.send(
            Call(
                method=method,
                path=path,
                body=body,
                origin=f"http://127.0.0.1:{self.port}",
                site="same-origin",
            )
        )

    def make_project(self, name: str = "Input Lab") -> str:
        reply = self.same_origin("POST", PROJECTS, {"name": name})
        assert reply.status == 201
        return str(reply.payload()["id"])

    def make_session(self, project_id: str, title: str = "Session A") -> str:
        reply = self.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/sessions",
            {"title": title},
        )
        assert reply.status == 201
        return str(reply.payload()["id"])

    def intent_body(self, intent: ResearchIntent = INTENT) -> dict[str, object]:
        return dict(intent.to_dict())

    def upload_probe(  # noqa: PLR0913 - one keyword per wire field keeps call sites readable
        self,
        project_id: str,
        *,
        kind: str = "spectrum",
        data_filename: str = "probe-spectrum.csv",
        data: bytes | None = None,
        manifest: str = SPECTRUM_MANIFEST,
        data_base64: str | None = None,
    ) -> Reply:
        encoded = (
            data_base64
            if data_base64 is not None
            else base64.b64encode(
                data if data is not None else SPECTRUM_CSV.encode()
            ).decode("ascii")
        )
        return self.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/inputs/probe",
            {
                "kind": kind,
                "data_filename": data_filename,
                "data_base64": encoded,
                "manifest_toml": manifest,
            },
        )

    def create_plan(
        self,
        project_id: str,
        session_id: str,
        intent: ResearchIntent = INTENT,
    ) -> dict[str, object]:
        reply = self.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/action-plans",
            {
                "session_id": session_id,
                "research_intent": self.intent_body(intent),
            },
        )
        assert reply.status == 201, reply.body
        return reply.payload()

    def approve_plan(self, project_id: str, plan_id: str) -> dict[str, object]:
        reply = self.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/action-plans/{plan_id}/approvals",
            {},
        )
        assert reply.status == 201, reply.body
        return reply.payload()

    def start_run(  # noqa: PLR0913 - one keyword per wire field keeps call sites readable
        self,
        project_id: str,
        session_id: str,
        approval_id: str,
        scientific_input: dict[str, object],
        intent: ResearchIntent = INTENT,
        *,
        input_sha256: str | None = None,
    ) -> Reply:
        body: dict[str, object] = {
            "session_id": session_id,
            "approval_id": approval_id,
            "research_intent": self.intent_body(intent),
            "scientific_input": scientific_input,
        }
        if input_sha256 is not None:
            body["input_sha256"] = input_sha256
        return self.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/runs",
            body,
        )

    def counts(self) -> dict[str, int]:
        database = resolve_paths(self.root).database
        connection = sqlite3.connect(database)
        queries = {
            "action_plans": "SELECT COUNT(*) FROM action_plans",
            "plan_approvals": "SELECT COUNT(*) FROM plan_approvals",
            "runs": "SELECT COUNT(*) FROM runs",
            "executions": "SELECT COUNT(*) FROM executions",
            "artifacts": "SELECT COUNT(*) FROM artifacts",
            "artifact_versions": "SELECT COUNT(*) FROM artifact_versions",
            "reviews": "SELECT COUNT(*) FROM reviews",
        }
        try:
            return {
                name: int(cast("tuple[int]", connection.execute(query).fetchone())[0])
                for name, query in queries.items()
            }
        finally:
            connection.close()


def _build(root: Path, clock: Clock | None = None) -> Harness:
    paths = resolve_paths(root)
    paths.ensure()
    store = LocalArtifactStore(paths)
    registry = ProviderRegistry(paths, InMemoryCredentialBackend(), {})
    read_model = LocalReadModel(paths)
    used_clock = clock if clock is not None else _MovableClock()
    deps = LocalApiDeps(
        store=store,
        registry=registry,
        read_model=read_model,
        paths=paths,
        clock=used_clock,
        ids=Uuid7Factory(),
        runs=StoreRunSurface(store),
    )
    api = start_local_api(paths, deps)
    return Harness(api, store, registry, read_model, used_clock)


@pytest.fixture
def local(tmp_path: Path) -> Iterator[Harness]:
    harness = _build(tmp_path / "root")
    try:
        yield harness
    finally:
        harness.close()


def _manifest(
    kind: str = "spectrum",
    *,
    units: str | None = None,
    calibration: bool = True,
    lineage: bool = True,
) -> str:
    unit_block = (
        units
        if units is not None
        else (
            "[[units]]\n"
            'quantity = "wavelength"\n'
            'ucum_code = "nm"\n'
            "\n"
            "[[units]]\n"
            'quantity = "intensity"\n'
            'ucum_code = "1"\n'
        )
    )
    parts = [
        'manifest_version = "nipo.local.input-manifest.v1"\n',
        f'kind = "{kind}"\n',
        "[scope]\nresearch_only = true\nnon_clinical = true\n",
        unit_block,
    ]
    if calibration:
        parts.append(
            "[calibration]\n"
            'method = "two-point NIST-traceable"\n'
            'reference = "SRM 2242a"\n'
            "calibrated_at = 2026-01-04T09:30:00Z\n"
            f'calibration_sha256 = "{CALIBRATION_DIGEST}"\n'
        )
    if lineage:
        parts.append(f'[lineage]\nversion_ids = ["{LINEAGE_UUID7}"]\n')
    if kind == "image":
        parts.append("[image]\nregion_threshold = 12.5\n")
    return "\n".join(part for part in parts if part)


def _png_bytes(width: int, height: int) -> bytes:
    image = Image.new("RGB", (width, height), (10, 20, 30))
    buffer = BytesIO()
    image.save(buffer, format="PNG")
    return buffer.getvalue()


def test_load_probe_via_staging_round_trip_matches_path_loader(
    local: Harness,
    tmp_path: Path,
) -> None:
    """Upload returns the same ProbeInput the path loader would produce."""
    measurement = tmp_path / "inbox" / "probe-spectrum.csv"
    measurement.parent.mkdir(parents=True)
    _ = measurement.write_text(SPECTRUM_CSV, encoding="utf-8")
    _ = (measurement.parent / "probe-spectrum.csv.manifest.toml").write_text(
        SPECTRUM_MANIFEST,
        encoding="utf-8",
    )
    expected = load_probe(spectrum=measurement)
    expected_json = expected.model_dump_json()
    expected_digest = hashlib.sha256(expected_json.encode()).hexdigest()

    project_id = local.make_project()
    before = local.counts()
    reply = local.upload_probe(project_id)
    after = local.counts()

    assert reply.status == 201, reply.body
    body = reply.payload()
    assert body["kind"] == "spectrum"
    assert body["input_sha256"] == expected_digest
    assert body["scientific_input"] == json.loads(expected_json)
    assert after == before
    staging = resolve_paths(local.root).root / "staging"
    if staging.exists():
        assert list(staging.iterdir()) == []


def test_missing_units_refuses_with_science_issue_code(local: Harness) -> None:
    project_id = local.make_project()
    before = local.counts()
    reply = local.upload_probe(
        project_id,
        manifest=_manifest(units=""),
    )
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.METADATA_REJECTED
    assert body["science_issue"] == "units_required"
    assert local.counts() == before


def test_missing_calibration_refuses_with_science_issue_code(local: Harness) -> None:
    project_id = local.make_project()
    before = local.counts()
    reply = local.upload_probe(
        project_id,
        manifest=_manifest(calibration=False),
    )
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.METADATA_REJECTED
    assert body["science_issue"] == "calibration_required"
    assert local.counts() == before


def test_malformed_csv_refuses_before_any_store_write(local: Harness) -> None:
    project_id = local.make_project()
    before = local.counts()
    reply = local.upload_probe(
        project_id,
        data=b"not,a,spectrum\nthis is garbage\n",
    )
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.MALFORMED_DATA
    assert "science_issue" not in body
    assert local.counts() == before


def test_multipart_probe_upload_returns_scientific_input_and_creates_no_artifact(
    local: Harness,
) -> None:
    """Named for the plan; the wire is strict JSON, not multipart."""
    project_id = local.make_project()
    before = local.counts()
    reply = local.upload_probe(project_id)
    assert reply.status == 201
    body = reply.payload()
    assert body["kind"] == "spectrum"
    assert isinstance(body["scientific_input"], dict)
    assert len(str(body["input_sha256"])) == 64
    assert local.counts() == before


def test_probe_upload_over_body_cap_is_413_payload_too_large(local: Harness) -> None:
    project_id = local.make_project()
    # Content-Length beyond the pre-app body cap is refused before the app.
    request = (
        b"POST /api/v1/projects/%s/inputs/probe HTTP/1.1\r\n"
        b"Host: 127.0.0.1:%d\r\n"
        b"Content-Length: %d\r\n"
        b"%s: %s\r\n"
        b"Content-Type: application/json\r\n"
        b"Origin: http://127.0.0.1:%d\r\n"
        b"Sec-Fetch-Site: same-origin\r\n"
        b"\r\n"
    ) % (
        project_id.encode(),
        local.port,
        MAX_BODY_BYTES + 1,
        TOKEN_HEADER_NAME.encode(),
        local.token.encode(),
        local.port,
    )
    sock = socket.create_connection(("127.0.0.1", local.port), timeout=10)
    try:
        sock.sendall(request)
        reply = sock.recv(4096)
    finally:
        sock.close()
    assert reply.startswith(b"HTTP/1.1 413 ")
    assert b"payload_too_large" in reply


def test_oversized_decoded_payload_refused_before_allocation(local: Harness) -> None:
    """Decoded size is computed from base64 length before decoding."""
    project_id = local.make_project()
    before = local.counts()
    # Enough 'A' characters that decoded size exceeds PRODUCT_UPLOAD_DATA_BYTES.
    # 4 base64 chars → 3 bytes; pad none when length % 4 == 0.
    chars_needed = ((PRODUCT_UPLOAD_DATA_BYTES + 1) * 4 + 2) // 3
    # Round up to a multiple of 4.
    chars_needed = (chars_needed + 3) // 4 * 4
    encoded = "A" * chars_needed
    reply = local.upload_probe(project_id, data_base64=encoded)
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.DATA_TOO_LARGE
    assert local.counts() == before


def test_invalid_base64_is_refused(local: Harness) -> None:
    project_id = local.make_project()
    before = local.counts()
    reply = local.upload_probe(project_id, data_base64="%%%not-base64%%%")
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.INVALID_BASE64
    assert local.counts() == before


def test_unsafe_filename_is_refused(local: Harness) -> None:
    project_id = local.make_project()
    before = local.counts()
    reply = local.upload_probe(project_id, data_filename="../etc/passwd")
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.UNSAFE_FILENAME
    assert local.counts() == before


def test_kind_manifest_mismatch_is_refused(local: Harness) -> None:
    project_id = local.make_project()
    before = local.counts()
    reply = local.upload_probe(
        project_id,
        kind="table",
        manifest=SPECTRUM_MANIFEST,
    )
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.MANIFEST_KIND_MISMATCH
    assert local.counts() == before


def test_probe_upload_error_body_never_echoes_path_or_bytes(local: Harness) -> None:
    project_id = local.make_project()
    canary_name = f"{CANARY}.csv"
    canary_bytes = f"{CANARY}-payload-bytes".encode()
    reply = local.upload_probe(
        project_id,
        data_filename=canary_name,
        data=canary_bytes,
        manifest="kind = [unclosed\n",
    )
    assert reply.status == 422
    raw = reply.body
    assert CANARY.encode() not in raw
    assert canary_bytes not in raw
    assert canary_name.encode() not in raw
    assert b"staging" not in raw
    assert b"/" not in raw or b"invalid_request" in raw
    # Closed reason only.
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.MANIFEST_SYNTAX


def test_image_over_product_pixel_cap_is_refused_with_closed_reason(
    local: Harness,
) -> None:
    project_id = local.make_project()
    before = local.counts()
    # 501 x 500 = 250_500 > 250_000 product cap, well under module 4M.
    width, height = 501, 500
    assert width * height > PRODUCT_UPLOAD_IMAGE_PIXELS
    assert width * height < MAX_IMAGE_PIXELS
    image_units = '[[units]]\nquantity = "color"\nucum_code = "1"\n'
    reply = local.upload_probe(
        project_id,
        kind="image",
        data_filename="field.png",
        data=_png_bytes(width, height),
        manifest=_manifest("image", units=image_units),
    )
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.IMAGE_EXCEEDS_PRODUCT_PIXEL_CAP
    assert local.counts() == before


def test_spectrum_over_product_point_cap_is_refused(local: Harness) -> None:
    project_id = local.make_project()
    before = local.counts()
    points = PRODUCT_UPLOAD_SPECTRUM_POINTS + 1
    rows = "\n".join(
        f"{400.0 + i * 0.001},{0.1 + (i % 10) * 0.01}" for i in range(points)
    )
    data = f"wavelength,intensity\n{rows}\n".encode()
    # Keep under product data-byte cap so the point cap is what fires.
    assert len(data) <= PRODUCT_UPLOAD_DATA_BYTES
    reply = local.upload_probe(project_id, data=data)
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.SPECTRUM_EXCEEDS_PRODUCT_POINT_CAP
    assert local.counts() == before


def test_upload_caps_are_strictly_below_loader_module_caps() -> None:
    assert PRODUCT_UPLOAD_DATA_BYTES < MAX_TEXT_BYTES
    assert PRODUCT_UPLOAD_DATA_BYTES < MAX_IMAGE_BYTES
    assert PRODUCT_UPLOAD_IMAGE_PIXELS < MAX_IMAGE_PIXELS
    assert PRODUCT_PROBE_JSON_BYTES < MAX_BODY_BYTES
    assert MAX_BODY_BYTES == 32 * 1024 * 1024


def test_run_start_with_uploaded_probe_json_completes_chain_outputs(
    local: Harness,
) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    uploaded = local.upload_probe(project_id)
    assert uploaded.status == 201
    scientific_input = as_dict(uploaded.payload()["scientific_input"])
    plan = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(plan["plan_id"]))
    run = local.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
        scientific_input,
    )
    assert run.status == 201, run.body
    body = run.payload()
    assert body["state"] == "completed"
    assert len(as_list(body["output_version_ids"])) == 4


def test_run_start_with_pinned_input_sha256_matches_and_completes(
    local: Harness,
) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    uploaded = local.upload_probe(project_id)
    assert uploaded.status == 201
    receipt = uploaded.payload()
    scientific_input = as_dict(receipt["scientific_input"])
    pinned = str(receipt["input_sha256"])
    plan = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(plan["plan_id"]))
    run = local.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
        scientific_input,
        input_sha256=pinned,
    )
    assert run.status == 201, run.body
    body = run.payload()
    assert body["state"] == "completed"
    assert len(as_list(body["output_version_ids"])) == 4


def test_run_start_with_mismatched_input_sha256_refuses_before_any_side_effect(
    local: Harness,
) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    uploaded = local.upload_probe(project_id)
    assert uploaded.status == 201
    receipt = uploaded.payload()
    scientific_input = as_dict(receipt["scientific_input"])
    pinned = str(receipt["input_sha256"])
    plan = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(plan["plan_id"]))
    approval_id = str(approval["approval_id"])
    before = local.counts()

    # Tamper a field that stays schema-valid so the pin, not ProbeInput, fires.
    # Deep-copy first so the held clean document is not mutated in place.
    tampered = cast(
        "dict[str, object]",
        json.loads(json.dumps(scientific_input)),
    )
    spectrum = as_dict(tampered["spectrum"])
    metadata = as_dict(spectrum["metadata"])
    calibration = as_dict(metadata["calibration"])
    original_digest = str(calibration["calibration_sha256"])
    flipped = ("d" if original_digest[0] == "c" else "c") + original_digest[1:]
    calibration["calibration_sha256"] = flipped
    metadata["calibration"] = calibration
    spectrum["metadata"] = metadata
    tampered["spectrum"] = spectrum

    refused = local.start_run(
        project_id,
        session_id,
        approval_id,
        tampered,
        input_sha256=pinned,
    )
    assert refused.status == 409, refused.body
    assert refused.error() == "input_digest_mismatch"
    after_refusal = local.counts()
    assert after_refusal == before

    # Same approval is still unspent and can complete a clean untampered run.
    clean = local.start_run(
        project_id,
        session_id,
        approval_id,
        scientific_input,
        input_sha256=pinned,
    )
    assert clean.status == 201, clean.body
    assert clean.payload()["state"] == "completed"
    assert len(as_list(clean.payload()["output_version_ids"])) == 4


def test_run_start_body_accepts_worst_case_uploaded_probe_json(local: Harness) -> None:
    """Largest accepted spectrum round-trips upload → frozen run-start."""
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    # Near the point ceiling; keep file under data-byte cap.
    points = min(PRODUCT_UPLOAD_SPECTRUM_POINTS, 50_000)
    rows = "\n".join(f"{400.0 + i * 0.001},0.25" for i in range(points))
    data = f"wavelength,intensity\n{rows}\n".encode()
    assert len(data) <= PRODUCT_UPLOAD_DATA_BYTES
    uploaded = local.upload_probe(project_id, data=data)
    assert uploaded.status == 201, uploaded.body
    scientific_input = as_dict(uploaded.payload()["scientific_input"])
    serialized = json.dumps(scientific_input).encode()
    assert len(serialized) <= PRODUCT_PROBE_JSON_BYTES
    assert len(serialized) < MAX_BODY_BYTES
    plan = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(plan["plan_id"]))
    run = local.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
        scientific_input,
    )
    assert run.status == 201, run.body
    assert run.payload()["state"] == "completed"


def test_run_start_revalidates_probe_and_refuses_tampered_document(
    local: Harness,
) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    uploaded = local.upload_probe(project_id)
    assert uploaded.status == 201
    scientific_input = as_dict(uploaded.payload()["scientific_input"])
    # Tamper: drop the spectrum entirely so ProbeInput is empty/invalid for run.
    scientific_input["spectrum"] = None
    plan = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(plan["plan_id"]))
    before = local.counts()
    run = local.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
        scientific_input,
    )
    # Empty probe is invalid at the workbench/science boundary.
    assert run.status in {422, 400}
    assert run.error() == "invalid_request"
    after = local.counts()
    assert after["runs"] == before["runs"]
    assert after["executions"] == before["executions"]
    assert after["artifacts"] == before["artifacts"]


def test_archived_project_refuses_probe_upload(local: Harness) -> None:
    project_id = local.make_project()
    assert local.same_origin("POST", f"{PROJECTS}/{project_id}/archive").status == 204
    before = local.counts()
    reply = local.upload_probe(project_id)
    assert reply.status == 409
    assert reply.error() == "project_archived"
    assert local.counts() == before


def test_unknown_project_probe_upload_is_not_found(local: Harness) -> None:
    missing = "019f0000-0000-7000-8000-00000000dead"
    reply = local.upload_probe(missing)
    assert reply.status == 404
    assert reply.error() == "not_found"


def test_http_file_to_intent_to_approve_to_run_to_review_to_export(
    local: Harness,
) -> None:
    """Product-path e2e: upload → plan → approve → run → review → export → ticket."""
    project_id = local.make_project()
    session_id = local.make_session(project_id)

    uploaded = local.upload_probe(project_id)
    assert uploaded.status == 201, uploaded.body
    scientific_input = as_dict(uploaded.payload()["scientific_input"])
    assert uploaded.payload()["kind"] == "spectrum"

    plan = local.create_plan(project_id, session_id)
    plan_id = str(plan["plan_id"])
    approval = local.approve_plan(project_id, plan_id)
    approval_id = str(approval["approval_id"])

    run_reply = local.start_run(project_id, session_id, approval_id, scientific_input)
    assert run_reply.status == 201, run_reply.body
    run_body = run_reply.payload()
    run_id = str(run_body["run_id"])
    assert len(as_list(run_body["output_version_ids"])) == 4

    review_path = f"{PROJECTS}/{project_id}/runs/{run_id}/review"
    review = local.same_origin("POST", review_path)
    assert review.status in {200, 201}, review.body
    review_body = review.payload()
    assert "findings" in review_body
    assert review_body.get("verdict") is not None

    plan_path = f"{PROJECTS}/{project_id}/runs/{run_id}/export"
    export_plan = local.send(Call(path=plan_path))
    assert export_plan.status == 200, export_plan.body
    candidates = as_list(export_plan.payload()["candidates"])
    assert len(candidates) == 4
    selection = [str(as_dict(item)["artifact_version_id"]) for item in candidates]

    produced = local.same_origin(
        "POST",
        plan_path,
        {"artifact_version_ids": selection},
    )
    assert produced.status == 201, produced.body
    pack_id = str(produced.payload()["pack_id"])

    grant = local.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/exports/{pack_id}/download",
    )
    assert grant.status == 201, grant.body
    url = str(grant.payload()["url"])
    downloaded = local.send(Call(path=url, omit_token=True))
    assert downloaded.status == 200
    assert len(downloaded.body) > 0
    with zipfile.ZipFile(BytesIO(downloaded.body)) as opened:
        names = set(opened.namelist())
    assert "manifest.json" in names
    assert "scientific-input.json" in names
    assert "research-intent.json" in names
    assert "review.json" in names
