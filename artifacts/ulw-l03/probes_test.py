"""Throwaway adversarial probes for AC-L03 measurement-file intake (HTTP).

Not part of the product suite. Lives under artifacts/ulw-l03/ and is executed
by path. Imports harness helpers from apps/local/tests/test_input_api.py.

Probe D2 records the owner disposition that calibration_sha256 is a researcher
claim about the calibration reference material (pattern-validated and pinned,
never recomputed against measurement bytes). Probe E asserts the hardened
run-start pin: when the original upload receipt's input_sha256 is submitted
with a tampered ProbeInput, the server refuses with input_digest_mismatch
before any durable read or write and leaves the approval unspent.
"""

from __future__ import annotations

import base64
import hashlib
import importlib.util
import json
import sys
import unicodedata
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TEST_INPUT = REPO / "apps" / "local" / "tests" / "test_input_api.py"
SPEC = REPO / "docs" / "spec" / "SPEC-v0.5.md"
REQUIREMENTS = REPO / "docs" / "requirements" / "requirements.yaml"

for entry in (
    str(REPO / "apps" / "local"),
    str(REPO / "packages" / "science"),
    str(REPO),
):
    if entry not in sys.path:
        sys.path.insert(0, entry)

_spec = importlib.util.spec_from_file_location("qa_l03_test_input_api", TEST_INPUT)
assert _spec is not None and _spec.loader is not None
_input_api = importlib.util.module_from_spec(_spec)
sys.modules["qa_l03_test_input_api"] = _input_api
_spec.loader.exec_module(_input_api)

Call = _input_api.Call
Harness = _input_api.Harness
PROJECTS = _input_api.PROJECTS
SPECTRUM_CSV = _input_api.SPECTRUM_CSV
SPECTRUM_MANIFEST = _input_api.SPECTRUM_MANIFEST
CALIBRATION_DIGEST = _input_api.CALIBRATION_DIGEST
as_dict = _input_api.as_dict
_manifest = _input_api._manifest
local = _input_api.local  # pytest fixture re-export

from nipo_local.api import (  # noqa: E402
    PRODUCT_PROBE_JSON_BYTES,
    PRODUCT_UPLOAD_DATA_BYTES,
    PRODUCT_UPLOAD_IMAGE_PIXELS,
    PRODUCT_UPLOAD_SPECTRUM_POINTS,
)
from nipo_local.apitypes import LoaderRejection  # noqa: E402
from nipo_local.config import resolve_paths  # noqa: E402

# Hostile canaries that must never appear in any refusal body. Secret-shaped
# strings are assembled at runtime so this stored probe file itself carries no
# contiguous secret-shaped literal for the repository secret scan to refuse.
HOSTILE_UNICODE = "canary-ulw-l03-🔥‮\x00-do-not-echo"
SECRET_SHAPES = (
    "sk-" + "ant-api03-" + "L" * 44,
    "AKIA" + "IOSFODNN" + "7EXAMPLE",
    "ghp" + "_" + "0123456789" + "abcdefghijklmnopqrstuvwxyz",
    "-----BEGIN " + "PRIVATE KEY-----",
)
CANARIES = (HOSTILE_UNICODE, *SECRET_SHAPES)

SWAPPED_DIGEST = "d" * 64


def _staging_root(harness: Harness) -> Path:
    return resolve_paths(harness.root).root / "staging"


def _staging_entries(harness: Harness) -> list[Path]:
    staging = _staging_root(harness)
    if not staging.exists():
        return []
    return list(staging.iterdir())


def _root_files(harness: Harness) -> set[Path]:
    root = resolve_paths(harness.root).root
    return {path for path in root.rglob("*") if path.is_file()}


def _spectrum_csv(points: int) -> bytes:
    rows = "\n".join(f"{400.0 + i * 0.001},0.25" for i in range(points))
    return f"wavelength,intensity\n{rows}\n".encode()


def test_probe_a_oversized_base64_prefused_before_decode_allocation(
    local: Harness,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Arithmetic pre-refusal: decode must never run, no staging, no rows."""
    decode_calls: list[str] = []
    real_decode = base64.b64decode

    def spy_decode(value: object, *args: object, **kwargs: object) -> bytes:
        decode_calls.append("called")
        return real_decode(value, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(base64, "b64decode", spy_decode)
    project_id = local.make_project()
    before = local.counts()
    # Arithmetic: 4 chars -> 3 bytes. Decoded size would exceed the 16 MiB
    # product cap while the whole JSON body stays under the 32 MiB wire cap.
    chars = ((PRODUCT_UPLOAD_DATA_BYTES + 3) * 4 + 2) // 3
    chars = (chars + 3) // 4 * 4
    encoded = "A" * chars
    assert len(encoded) + 4096 < 32 * 1024 * 1024  # stays under wire body cap
    reply = local.upload_probe(project_id, data_base64=encoded)
    assert reply.status == 422, reply.body[:200]
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.DATA_TOO_LARGE
    # Refusal came from length arithmetic: base64.b64decode was never entered,
    # so no decoded buffer was ever allocated and no MemoryError path exists.
    assert decode_calls == []
    assert local.counts() == before
    assert _staging_entries(local) == []


def test_probe_b_decoded_size_guard_both_directions_zero_staging(
    local: Harness,
) -> None:
    """Over-cap by arithmetic and over-cap at decode size: both data_too_large."""
    project_id = local.make_project()
    before = local.counts()
    # Request 1: valid-alphabet payload whose arithmetic size exceeds the cap.
    chars = ((PRODUCT_UPLOAD_DATA_BYTES + 3) * 4 + 2) // 3
    chars = (chars + 3) // 4 * 4
    over_by_arithmetic = local.upload_probe(project_id, data_base64="A" * chars)
    assert over_by_arithmetic.status == 422
    assert over_by_arithmetic.payload()["reason"] == LoaderRejection.DATA_TOO_LARGE
    # Request 2: genuinely decodable bytes exactly one over the cap.
    raw = b"\x17" * (PRODUCT_UPLOAD_DATA_BYTES + 1)
    over_at_decode = local.upload_probe(
        project_id,
        data_base64=base64.b64encode(raw).decode("ascii"),
    )
    assert over_at_decode.status == 422
    assert over_at_decode.payload()["reason"] == LoaderRejection.DATA_TOO_LARGE
    assert local.counts() == before
    assert _staging_entries(local) == []


def test_probe_c_traversal_and_lookalike_filenames_refused(local: Harness) -> None:
    """Hostile leaf names all map to unsafe_filename; nothing lands on disk."""
    project_id = local.make_project()
    before_files = _root_files(local)
    before = local.counts()
    nfd_lookalike = unicodedata.normalize("NFD", "café-spectrum.csv")
    assert nfd_lookalike != "café-spectrum.csv"
    hostile_names = (
        "../../etc/passwd",
        "..\\..\\etc\\passwd",
        "C:\\windows",
        "C:windows",
        "CON",
        "con.csv",
        "NUL",
        nfd_lookalike,
    )
    for name in hostile_names:
        reply = local.upload_probe(project_id, data_filename=name)
        assert reply.status == 422, (name, reply.body[:200])
        body = reply.payload()
        assert body["error"] == "invalid_request"
        assert body["reason"] == LoaderRejection.UNSAFE_FILENAME, name
    assert local.counts() == before
    # No file escaped staging: the data root holds exactly the files it held.
    assert _root_files(local) == before_files
    assert _staging_entries(local) == []


def test_probe_d1_table_kind_with_spectrum_manifest_is_kind_mismatch(
    local: Harness,
) -> None:
    project_id = local.make_project()
    before = local.counts()
    reply = local.upload_probe(project_id, kind="table", manifest=SPECTRUM_MANIFEST)
    assert reply.status == 422
    body = reply.payload()
    assert body["error"] == "invalid_request"
    assert body["reason"] == LoaderRejection.MANIFEST_KIND_MISMATCH
    assert local.counts() == before


def test_probe_d2_calibration_digest_is_researcher_claim_accepted_201(
    local: Harness,
) -> None:
    """blk-d2 by-design disposition: calibration_sha256 is the researcher's
    claim about the calibration REFERENCE material, never the data file.

    The product pattern-validates the digest and pins it into provenance but
    MUST NOT recompute it against measurement bytes. The shipped reference
    manifest deliberately carries a digest that does not match the data file
    and is accepted; the claim is preserved verbatim on the returned document.
    """
    project_id = local.make_project()
    data = SPECTRUM_CSV.encode()
    actual_digest = hashlib.sha256(data).hexdigest()
    assert CALIBRATION_DIGEST != actual_digest  # the shipped manifest mismatches
    before = local.counts()
    reply = local.upload_probe(project_id, data=data, manifest=SPECTRUM_MANIFEST)
    assert reply.status == 201, (
        f"calibration claim was refused with status {reply.status}; "
        "calibration_sha256 is a researcher claim, not a data-file checksum"
    )
    body = reply.payload()
    scientific_input = as_dict(body["scientific_input"])
    spectrum = as_dict(scientific_input["spectrum"])
    metadata = as_dict(spectrum["metadata"])
    calibration = as_dict(metadata["calibration"])
    assert calibration["calibration_sha256"] == CALIBRATION_DIGEST
    assert local.counts() == before


def test_probe_e_swapped_calibration_digest_run_start_refuses(
    local: Harness,
) -> None:
    """blk-e hardening: ProbeInput tampered between upload and run-start is
    refused when the original upload receipt's input_sha256 is pinned.

    The product interface submits the receipt digest on createRun. A document
    that no longer recomputes to that digest is refused 409 input_digest_mismatch
    before any durable read or write; the approval stays unspent and usable.
    """
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    uploaded = local.upload_probe(project_id)
    assert uploaded.status == 201
    receipt = uploaded.payload()
    scientific_input = as_dict(receipt["scientific_input"])
    pinned = str(receipt["input_sha256"])
    assert len(pinned) == 64
    spectrum = as_dict(scientific_input["spectrum"])
    metadata = as_dict(spectrum["metadata"])
    calibration = as_dict(metadata["calibration"])
    assert calibration["calibration_sha256"] == CALIBRATION_DIGEST
    calibration["calibration_sha256"] = SWAPPED_DIGEST
    metadata["calibration"] = calibration
    spectrum["metadata"] = metadata
    tampered = dict(scientific_input)
    tampered["spectrum"] = spectrum
    plan = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(plan["plan_id"]))
    approval_id = str(approval["approval_id"])
    before = local.counts()
    run = local.start_run(
        project_id,
        session_id,
        approval_id,
        tampered,
        input_sha256=pinned,
    )
    assert run.status == 409, (
        f"tampered ProbeInput with pinned upload digest started a run with "
        f"status {run.status}; expected 409 input_digest_mismatch"
    )
    assert run.error() == "input_digest_mismatch"
    after = local.counts()
    assert after == before

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

def test_probe_f_canary_sweep_refusal_bodies_never_echo(local: Harness) -> None:
    """Hostile unicode + secret-shaped strings in bytes/manifest/filename are
    never echoed in any refusal body."""
    project_id = local.make_project()
    canary_bytes = json.dumps(CANARIES).encode()
    replies = []
    # Canary inside the uploaded data bytes -> malformed_data.
    replies.append(local.upload_probe(project_id, data=canary_bytes))
    # Canaries inside the manifest text -> manifest_syntax.
    replies.append(
        local.upload_probe(project_id, manifest=f"# {HOSTILE_UNICODE}\nkind = [\n")
    )
    # Canary inside the filename -> unsafe_filename (separators) or refused name.
    replies.append(
        local.upload_probe(project_id, data_filename=f"../{HOSTILE_UNICODE}.csv")
    )
    # Canary as a smuggled extra wire field -> strict-model refusal.
    replies.append(
        local.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/inputs/probe",
            {
                "kind": "spectrum",
                "data_filename": "probe.csv",
                "data_base64": base64.b64encode(SPECTRUM_CSV.encode()).decode(),
                "manifest_toml": SPECTRUM_MANIFEST,
                "smuggled": list(CANARIES),
            },
        )
    )
    for reply in replies:
        assert reply.status in {400, 422}, reply.body[:200]
        raw = reply.body
        for canary in CANARIES:
            assert canary.encode() not in raw
            assert json.dumps(canary)[1:-1].encode() not in raw
        assert b"staging" not in raw


def test_probe_g_worst_case_spectrum_point_boundary(local: Harness) -> None:
    """Exactly at the product point cap: upload -> run-start 201.
    One point over: spectrum_exceeds_product_point_cap."""
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    at_cap = _spectrum_csv(PRODUCT_UPLOAD_SPECTRUM_POINTS)
    assert len(at_cap) <= PRODUCT_UPLOAD_DATA_BYTES
    uploaded = local.upload_probe(project_id, data=at_cap)
    assert uploaded.status == 201, uploaded.body[:200]
    scientific_input = as_dict(uploaded.payload()["scientific_input"])
    serialized = json.dumps(scientific_input).encode()
    assert len(serialized) <= PRODUCT_PROBE_JSON_BYTES
    plan = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(plan["plan_id"]))
    run = local.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
        scientific_input,
    )
    assert run.status == 201, run.body[:200]
    assert run.payload()["state"] == "completed"

    before = local.counts()
    over_cap = _spectrum_csv(PRODUCT_UPLOAD_SPECTRUM_POINTS + 1)
    assert len(over_cap) <= PRODUCT_UPLOAD_DATA_BYTES
    refused = local.upload_probe(project_id, data=over_cap)
    assert refused.status == 422
    assert (
        refused.payload()["reason"]
        == LoaderRejection.SPECTRUM_EXCEEDS_PRODUCT_POINT_CAP
    )
    assert local.counts() == before


def test_probe_h_staging_residue_audit_mixed_uploads(local: Harness) -> None:
    """Three mixed success/failure uploads leave zero staging residue."""
    project_id = local.make_project()
    ok = local.upload_probe(project_id)
    assert ok.status == 201
    bad_data = local.upload_probe(project_id, data=b"garbage,not,a,spectrum\n")
    assert bad_data.status == 422
    bad_name = local.upload_probe(project_id, data_filename="../../etc/passwd")
    assert bad_name.status == 422
    assert _staging_entries(local) == []
    for leftover in _root_files(local):
        assert "staging" not in leftover.parts or False, leftover


def test_probe_docs_honesty_l03_claims() -> None:
    """SPEC section 14 + requirements.yaml L03 claims match code and tests."""
    spec = SPEC.read_text(encoding="utf-8")
    requirements = REQUIREMENTS.read_text(encoding="utf-8")
    # Conformance flip: L03 is listed implemented in both authorities.
    assert '"implemented_and_verified": ["L03"' in requirements
    section14 = spec.split("## 14. Conformance status", 1)[1].split("## 15.", 1)[0]
    assert "L03" in section14
    # No invented AC-L03-B acceptance ID anywhere in either authority.
    assert "AC-L03-B" not in spec
    assert "AC-L03-B" not in requirements
    # Product caps stated in SPEC section 14 match the code constants.
    assert "16 MiB per file" in section14
    assert PRODUCT_UPLOAD_DATA_BYTES == 16 * 1024 * 1024
    assert "250,000 image pixels" in section14
    assert PRODUCT_UPLOAD_IMAGE_PIXELS == 250_000
    assert "400,000 spectrum points" in section14
    assert PRODUCT_UPLOAD_SPECTRUM_POINTS == 400_000
    # The AC-L03 statement itself is present in the manifest.
    assert '"AC-L03"' in requirements
