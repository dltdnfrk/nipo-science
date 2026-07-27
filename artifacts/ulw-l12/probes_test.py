"""Throwaway adversarial probes for AC-L12 / AC-L12-B (HTTP export surface).

Not part of the product suite. Lives under artifacts/ulw-l12/ and is executed
by path. Imports the exportable harness from apps/local/tests/test_api.py.
"""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
TEST_API = REPO / "apps" / "local" / "tests" / "test_api.py"

for entry in (
    str(REPO / "apps" / "local"),
    str(REPO / "packages" / "science"),
    str(REPO),
):
    if entry not in sys.path:
        sys.path.insert(0, entry)

_spec = importlib.util.spec_from_file_location("qa_l12_test_api", TEST_API)
assert _spec is not None and _spec.loader is not None
_api = importlib.util.module_from_spec(_spec)
sys.modules["qa_l12_test_api"] = _api
_spec.loader.exec_module(_api)

Call = _api.Call
PROJECTS = _api.PROJECTS
_plan = _api._plan
_pinned_ids = _api._pinned_ids
_produce = _api._produce
_mint = _api._mint
_pack_path = _api._pack_path
_verify_archive = _api._verify_archive
exportable = _api.exportable  # pytest fixture re-export

# Provider-key-shaped tokens that must never appear in pack bytes.
PROVIDER_KEY_SHAPES = (
    re.compile(rb"sk-[A-Za-z0-9_\-]{8,}"),
    re.compile(rb"sk-ant-[A-Za-z0-9_\-]{8,}"),
    re.compile(rb"sk-proj-[A-Za-z0-9_\-]{8,}"),
    re.compile(rb"xai-[A-Za-z0-9_\-]{8,}"),
    re.compile(rb"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(rb"ghp_[A-Za-z0-9]{20,}"),
)


def test_probe_a_smuggled_non_selected_version_id_is_refused(
    exportable: tuple[object, str, str],
) -> None:
    """(a) POST export body with pinned ids plus a foreign non-selected id."""
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    # Drop one legitimate pin so the foreign id is not merely "extra of set"
    # but smuggled alongside a partial legitimate selection.
    partial = pinned[:-1]
    assert partial
    _, foreign = harness.seed_artifact(project_id, "smuggle-outsider", [b"smuggled"])
    smuggled = [*partial, foreign[0]]

    reply = _produce(harness, project_id, run_id, smuggled)

    assert reply.status == 400
    assert reply.payload() == {
        "error": "export_selection_rejected",
        "reason": "selection_not_pinned_to_run",
    }
    assert not (harness.root / _api.EXPORTS_DIRECTORY_NAME).exists()


def test_probe_b_double_produce_then_download_with_other_pack_ticket_is_invalid(
    exportable: tuple[object, str, str],
) -> None:
    """(b) Produce twice; present pack A's ticket against pack B's content URL."""
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_a = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])
    pack_b = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])
    assert pack_a != pack_b

    ticket_a = str(_mint(harness, project_id, pack_a)["url"])
    # Route the A ticket to B's content path (same ticket secret, wrong pack).
    misdirected = ticket_a.replace(f"/exports/{pack_a}/", f"/exports/{pack_b}/")
    assert pack_b in misdirected and pack_a not in misdirected

    elsewhere = harness.send(Call(path=misdirected, omit_token=True))
    # Original ticket must remain unspent.
    still_a = harness.send(Call(path=ticket_a, omit_token=True))

    assert elsewhere.status == 401
    assert elsewhere.payload() == {"error": "download_ticket_invalid"}
    assert still_a.status == 200
    assert still_a.body == _pack_path(harness, project_id, pack_a).read_bytes()
    # B's bytes must not leak via the misdirected ticket.
    assert still_a.body != _pack_path(harness, project_id, pack_b).read_bytes()


def test_probe_c_selection_with_duplicate_of_a_pinned_id_is_refused(
    exportable: tuple[object, str, str],
) -> None:
    """(c) Selection is the full pinned set plus a duplicate of one pin."""
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    assert len(pinned) >= 2
    # Full set with a duplicate — not the single-id [p,p] happy case already covered.
    duplicated = [*pinned, pinned[0]]

    reply = _produce(harness, project_id, run_id, duplicated)

    assert reply.status == 400
    assert reply.payload() == {
        "error": "export_selection_rejected",
        "reason": "selection_duplicate",
    }


def test_probe_d_downloaded_pack_bytes_carry_neither_session_token_nor_provider_key(
    exportable: tuple[object, str, str],
) -> None:
    """(d) Downloaded pack must not contain session token or provider-key shapes."""
    harness, project_id, run_id = exportable
    # Plant a real provider key in the registry so a leak would have a canary.
    store_reply = harness.same_origin(
        "PUT",
        "/api/v1/providers/anthropic/key",
        {"key": _api.CANARY_KEY},
    )
    assert store_reply.status == 204, store_reply.body

    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack = _produce(harness, project_id, run_id, pinned).payload()
    pack_id = str(pack["pack_id"])
    url = str(_mint(harness, project_id, pack_id)["url"])
    downloaded = harness.send(Call(path=url, omit_token=True))

    assert downloaded.status == 200
    body = downloaded.body
    _ = _verify_archive(body)

    token = harness.token.encode("utf-8")
    assert token not in body
    assert _api.CANARY_KEY.encode("utf-8") not in body
    for pattern in PROVIDER_KEY_SHAPES:
        match = pattern.search(body)
        assert match is None, f"provider-key-shaped bytes matched: {match.group()!r}"
