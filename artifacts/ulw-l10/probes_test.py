"""Ultragoal part-2 G002 / L10 red-team probes (lane 38-QaL10).

Adversarial probes against the L10 run-bound turn surface, reusing the
test_turn_api harness conventions and the test_modelcall WireServer. Each
probe drives the real HTTP API against a real store with fake providers on
real loopback sockets. No secret-shaped literal is stored verbatim: the
probe canary is assembled from fragments exactly like ENV_CANARY in
test_turn_api.

Run:
    PYTHONPATH=apps/local:apps/local/tests:packages/science:. \
        .venv/bin/pytest artifacts/ulw-l10/probes_test.py -v
"""

from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Final, cast

from test_modelcall import OPENAI_PATH, Route, sse
from test_turn_api import (
    DEFAULT_ROUTES,
    OPENAI_MODEL,
    Rig,
    _build,
    make_run,
    run_projection,
    turn,
    turn_rows,
)

from nipo_local.apitypes import TurnFailedBody
from nipo_local.modelcall import ModelCallFailure

# Provider-key-shaped canary assembled from fragments so this artifact never
# stores a secret-shaped literal contiguously. The hostile provider double
# echoes it; the durable side must never carry it.
PROBE_CANARY: Final = "sk-" + "probe" + "-" + "Q7x" * 14 + "-Z"

EXPECTED_REASON_TOKENS: Final = {
    "authentication",
    "rate_limit",
    "quota",
    "model_unavailable",
    "provider_unavailable",
    "invalid_request",
    "timeout",
    "transport",
    "malformed_response",
    "response_too_large",
    "unclassified",
}

CONCURRENT_PAIRS: Final = 12


def _chunked_text_routes(pieces: int, piece: int, delay: float) -> dict[str, Route]:
    """One OpenAI route that slowly streams a large assistant answer."""
    frames = [json.dumps({"choices": [{"delta": {"role": "assistant"}}]})]
    frames.extend(
        json.dumps({"choices": [{"delta": {"content": "x" * piece}}]})
        for _ in range(pieces)
    )
    frames.append(
        json.dumps(
            {
                "choices": [{"delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 11, "completion_tokens": pieces},
            }
        )
    )
    frames.append("[DONE]")
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = Route(chunks=sse(frames), chunk_delay=delay)
    return routes


def _fire_turn(rig: Rig, project_id: str, run_id: str, out: list[object]) -> None:
    out.append(turn(rig, project_id, run_id))


def _make_run(rig: Rig, name: str) -> tuple[str, str]:
    """make_run with a unique project name so one rig can host many runs."""
    harness = rig.harness
    project_id = harness.make_project(name=name)
    session_id = harness.make_session(project_id)
    uploaded = harness.upload_probe(project_id)
    assert uploaded.status == 201, uploaded.body
    scientific_input = uploaded.payload()["scientific_input"]
    plan = harness.create_plan(project_id, session_id)
    approval = harness.approve_plan(project_id, str(plan["plan_id"]))
    run = harness.start_run(
        project_id, session_id, str(approval["approval_id"]), scientific_input
    )
    assert run.status == 201, run.body
    return project_id, str(run.payload()["run_id"])

def test_probe_a_concurrent_double_turn_one_run(tmp_path: Path) -> None:
    """Two threads, one run, same model: exactly seq 1..2, no dup, pin kept."""
    routes = _chunked_text_routes(pieces=120, piece=2000, delay=0.004)
    rig = _build(tmp_path / "root", routes)
    anomalies: list[str] = []
    try:
        for attempt in range(CONCURRENT_PAIRS):
            project_id, run_id = _make_run(rig, f"probe-a-{attempt}")
            wire_before = len(rig.wire_log)
            replies: list[object] = []
            first = threading.Thread(
                target=_fire_turn, args=(rig, project_id, run_id, replies)
            )
            second = threading.Thread(
                target=_fire_turn, args=(rig, project_id, run_id, replies)
            )
            first.start()
            second.start()
            first.join(timeout=120)
            second.join(timeout=120)
            statuses = sorted(
                cast("int", getattr(reply, "status")) for reply in replies
            )
            rows = [
                row for row in turn_rows(rig) if row["run_id"] == run_id
            ]
            seqs = sorted(cast("int", row["seq"]) for row in rows)
            hits = len(rig.wire_log) - wire_before
            projection = run_projection(rig, project_id, run_id)
            if statuses != [201, 201]:
                anomalies.append(
                    f"attempt {attempt}: statuses {statuses} "
                    f"(bodies: {[getattr(r, 'body') for r in replies]!r})"
                )
            if seqs != [1, 2]:
                anomalies.append(f"attempt {attempt}: rows seqs {seqs}")
            if hits != 2:
                anomalies.append(f"attempt {attempt}: provider hits {hits}")
            if projection["pinned_model_id"] != OPENAI_MODEL:
                anomalies.append(
                    f"attempt {attempt}: pin {projection['pinned_model_id']!r}"
                )
    finally:
        rig.close()
    assert anomalies == [], "\n".join(anomalies)


def test_probe_b_hostile_prompt_canary_never_persisted(tmp_path: Path) -> None:
    """Canary in the prompt may echo in the 201 text; row/projection stay clean."""
    import hashlib

    canary_digest = hashlib.sha256(PROBE_CANARY.encode()).hexdigest()
    frames = [
        json.dumps({"choices": [{"delta": {"role": "assistant"}}]}),
        json.dumps({"choices": [{"delta": {"content": PROBE_CANARY}}]}),
        json.dumps(
            {
                "choices": [{"delta": {}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 9, "completion_tokens": 3},
            }
        ),
        "[DONE]",
    ]
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = Route(chunks=sse(frames))
    rig = _build(tmp_path / "root", routes)
    try:
        project_id, run_id = make_run(rig)
        reply = rig.harness.same_origin(
            "POST",
            f"/api/v1/projects/{project_id}/runs/{run_id}/turns",
            {
                "model_id": OPENAI_MODEL,
                "messages": [
                    {
                        "role": "user",
                        "content": f"Repeat this token back: {PROBE_CANARY}",
                    }
                ],
                "max_output_tokens": 256,
            },
        )
        projection = run_projection(rig, project_id, run_id)
        rows = turn_rows(rig)
    finally:
        rig.close()
    assert canary_digest  # digest computed so the report can cite it, not the canary
    assert reply.status == 201, reply.body
    # The provider double echoed the canary; the 201 text may carry it.
    assert PROBE_CANARY.encode() in reply.body
    # The durable side must never carry it: no row value, no projection field.
    assert len(rows) == 1
    assert all(
        PROBE_CANARY not in str(value) for row in rows for value in row.values()
    )
    assert PROBE_CANARY not in json.dumps(projection)
    # The row keeps digests, not prose: no column even named like text.
    assert not any("text" == str(name) for row in rows for name in row)


def test_probe_c_slow_stream_cut_mid_frame_leaves_nothing(tmp_path: Path) -> None:
    """Slow stream severed mid-frame: closed failure, no row, no pin, no AV change."""
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = Route(
        chunks=_chunked_text_routes(6, 400, 0.0)[OPENAI_PATH].chunks,
        chunk_delay=0.25,
        cut_after=2,
    )
    rig = _build(tmp_path / "root", routes)
    try:
        project_id, run_id = make_run(rig)
        before = rig.harness.counts()
        reply = turn(rig, project_id, run_id)
        after = rig.harness.counts()
        rows = turn_rows(rig)
        projection = run_projection(rig, project_id, run_id)
    finally:
        rig.close()
    assert reply.status == 502, reply.body
    assert reply.payload() == {"error": "turn_failed", "reason": "transport"}
    assert rows == []
    assert projection["pinned_provider_id"] is None
    assert projection["pinned_model_id"] is None
    assert projection["turns"] == []
    assert after == before


def test_probe_d_pin_allows_new_token_cap_refuses_case_space_variants(
    tmp_path: Path,
) -> None:
    """Pinned run: new max_output_tokens allowed; case/space variants refused pre-egress."""
    rig = _build(tmp_path / "root", DEFAULT_ROUTES)
    try:
        project_id, run_id = make_run(rig)
        first = turn(rig, project_id, run_id)
        assert first.status == 201, first.body

        allowed = rig.harness.same_origin(
            "POST",
            f"/api/v1/projects/{project_id}/runs/{run_id}/turns",
            {
                "model_id": OPENAI_MODEL,
                "messages": [{"role": "user", "content": "Again."}],
                "max_output_tokens": 512,
            },
        )
        assert allowed.status == 201, allowed.body
        assert allowed.payload()["seq"] == 2

        hits_after_two = len(rig.wire_log)
        refused: list[tuple[str, int, str]] = []
        for variant in (
            "OpenAI:gpt-test",
            "OPENAI:gpt-test",
            "openai:gpt-test ",
            " openai:gpt-test",
            "openai: gpt-test",
        ):
            reply = turn(rig, project_id, run_id, variant)
            refused.append((variant, reply.status, reply.body.decode("utf-8", "replace")))
    finally:
        rig.close()
    # Every variant was refused with a closed pre-egress code, and not one of
    # them reached a provider: the wire log still shows exactly the two turns.
    for variant, status, body in refused:
        assert status in {404, 409, 422}, (variant, status, body)
        parsed = json.loads(body)
        assert parsed["error"] in {
            "unknown_provider",
            "model_not_enabled",
            "model_id_malformed",
            "model_selection_locked",
        }, (variant, status, body)
    assert len(rig.wire_log) == hits_after_two == 2
    rows = turn_rows(rig)
    assert [row["seq"] for row in rows] == [1, 2]
    assert all(row["model_id"] == OPENAI_MODEL for row in rows)


def test_probe_e_archived_409_and_traversal_provider_closed_refusal(
    tmp_path: Path,
) -> None:
    """Archived project: 409 with zero provider contact; traversal-shaped
    provider id: closed refusal with no path-like echo in the body."""
    rig = _build(tmp_path / "root", DEFAULT_ROUTES)
    try:
        project_id, run_id = make_run(rig)
        traversal = turn(rig, project_id, run_id, "../..:../../etc/passwd")
        hits_before_archive = len(rig.wire_log)
        assert (
            rig.harness.same_origin(
                "POST", f"/api/v1/projects/{project_id}/archive"
            ).status
            == 204
        )
        archived = turn(rig, project_id, run_id)
    finally:
        rig.close()
    assert traversal.status == 404, traversal.body
    assert json.loads(traversal.body)["error"] == "unknown_provider"
    assert b".." not in traversal.body
    assert b"etc" not in traversal.body
    assert b"passwd" not in traversal.body
    assert hits_before_archive == 0
    assert archived.status == 409, archived.body
    assert json.loads(archived.body)["error"] == "project_archived"
    assert len(rig.wire_log) == 0
    assert turn_rows(rig) == []


def test_probe_f_turn_failed_reason_tokens_match_modelcall_exactly() -> None:
    """The wire reason set equals exactly ModelCallFailure's values — no drift."""
    wire_values = {failure.value for failure in ModelCallFailure}
    assert wire_values == EXPECTED_REASON_TOKENS
    assert len(ModelCallFailure) == 11
    # The failure body declares the enum itself as the reason type, so no
    # out-of-enum token can be emitted by construction.
    assert TurnFailedBody.model_fields["reason"].annotation is ModelCallFailure
    # Every token has a named wire test: the ten parametrized cases plus the
    # response_too_large case in test_turn_api.
    from test_turn_api import FAILURE_CASES

    covered = {failure.value for failure, _, _ in FAILURE_CASES}
    covered.add("response_too_large")
    assert covered == EXPECTED_REASON_TOKENS
