"""Real-socket tests for the L10 run-bound model turn product surface.

Covers the synchronous turn route: exact-selection turns, selection pinned on
the Run projection, the closed pre-egress refusal matrix, provider-neutral
failure mapping for every ModelCallFailure token, zero durable side effects
on every failure path, and the no-fallback rule made observable by exactly
one provider request.
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, Final, cast, final

import pytest
from services.api.artifacts.runtime import Uuid7Factory
from test_input_api import PROJECTS, Call, Harness, Reply, as_dict, as_list
from test_modelcall import (
    ANTHROPIC_PATH,
    CANARY_KEY,
    GOOGLE_PATH,
    OLLAMA_CHUNKS,
    OLLAMA_PATH,
    OPENAI_CHUNKS,
    OPENAI_PATH,
    SECOND_KEY,
    RecordedRequest,
    Route,
    WireServer,
    endpoints_for,
    error_body,
    json_body,
    sse,
)

from nipo_local.api import LocalApiDeps, start_local_api
from nipo_local.apiquery import LocalReadModel
from nipo_local.config import resolve_paths
from nipo_local.modelcall import CallLimits, ModelCallClient, ModelCallFailure
from nipo_local.providers import InMemoryCredentialBackend, ProviderRegistry
from nipo_local.runsurface import StoreRunSurface
from nipo_local.store import LocalArtifactStore

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from pathlib import Path

    from services.api.artifacts.models import Clock

OPENAI_MODEL: Final = "openai:gpt-test"
ANTHROPIC_MODEL: Final = "anthropic:claude-test"
GOOGLE_MODEL: Final = "google:gemini-test"
OLLAMA_MODEL: Final = "ollama:llama-test"
ENABLED_MODELS: Final = (OPENAI_MODEL, ANTHROPIC_MODEL, GOOGLE_MODEL, OLLAMA_MODEL)
DEFAULT_KEYS: Final = {
    "openai": CANARY_KEY,
    "anthropic": SECOND_KEY,
    "google": SECOND_KEY,
}
DEFAULT_ROUTES: Final = {
    OPENAI_PATH: Route(chunks=OPENAI_CHUNKS),
    ANTHROPIC_PATH: Route(
        chunks=sse(
            [
                json.dumps({"choices": [{"delta": {"content": "fallback"}}]}),
                "[DONE]",
            ]
        )
    ),
    GOOGLE_PATH: Route(chunks=()),
    OLLAMA_PATH: Route(chunks=OLLAMA_CHUNKS),
}
ENV_KEY_SLOT: Final = "NIPO_OPENAI_API_KEY"
ENV_CANARY: Final = "sk-env-canaryslot-" + "Qy4wE" * 20 + "-TAIL"


@final
class MovableClock:
    """A clock a test can advance so timestamps are asserted, not waited."""

    def __init__(self) -> None:
        self.moment = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)

    def now(self) -> datetime:
        return self.moment

    def advance(self, seconds: float) -> None:
        self.moment += timedelta(seconds=seconds)


@final
@dataclass(slots=True)
class Rig:
    """One started API harness plus its fake-provider wire server."""

    harness: Harness
    server: WireServer

    def close(self) -> None:
        self.harness.close()
        self.server.close()

    @property
    def wire_log(self) -> tuple[RecordedRequest, ...]:
        """Return every request the fake providers received."""
        return self.server.requests


def make_run(rig: Rig) -> tuple[str, str]:
    """Drive project → session → upload → plan → approve → run."""
    harness = rig.harness
    project_id = harness.make_project()
    session_id = harness.make_session(project_id)
    uploaded = harness.upload_probe(project_id)
    assert uploaded.status == 201, uploaded.body
    scientific_input = as_dict(uploaded.payload()["scientific_input"])
    plan = harness.create_plan(project_id, session_id)
    approval = harness.approve_plan(project_id, str(plan["plan_id"]))
    run = harness.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
        scientific_input,
    )
    assert run.status == 201, run.body
    return project_id, str(run.payload()["run_id"])


def turn(
    rig: Rig,
    project_id: str,
    run_id: str,
    model_id: str = OPENAI_MODEL,
) -> Reply:
    """POST one turn request on the exact wire."""
    return rig.harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/runs/{run_id}/turns",
        {
            "model_id": model_id,
            "messages": [{"role": "user", "content": "Summarise the spectrum."}],
            "max_output_tokens": 256,
        },
    )


def run_projection(rig: Rig, project_id: str, run_id: str) -> dict[str, object]:
    """Read one Run's projection through the bound run surface."""
    reply = rig.harness.send(Call(path=f"{PROJECTS}/{project_id}/runs/{run_id}"))
    assert reply.status == 200, reply.body
    return reply.payload()


def turn_rows(rig: Rig) -> list[dict[str, object]]:
    """Dump every run_turns row for direct no-secret assertions."""
    database = resolve_paths(rig.harness.root).database
    connection = sqlite3.connect(database)
    try:
        cursor = connection.execute("SELECT * FROM run_turns")
        names = [str(column[0]) for column in cursor.description]
        rows = cast("list[tuple[object, ...]]", cursor.fetchall())
        return [dict(zip(names, row, strict=True)) for row in rows]
    finally:
        connection.close()


def _build(
    root: Path,
    routes: Mapping[str, Route],
    *,
    keys: Mapping[str, str] | None = None,
    env: Mapping[str, str] | None = None,
    limits: CallLimits | None = None,
) -> Rig:
    """Start the API wired to one fake-provider server and a real store."""
    server = WireServer(routes)
    try:
        paths = resolve_paths(root)
        paths.ensure()
        store = LocalArtifactStore(paths)
        registry = ProviderRegistry(
            paths,
            InMemoryCredentialBackend(),
            dict(env or {}),
        )
        for provider_id, key in (keys if keys is not None else DEFAULT_KEYS).items():
            registry.set_key(provider_id, key)
        _ = registry.set_enabled_models(ENABLED_MODELS)
        read_model = LocalReadModel(paths)
        clock: Clock = MovableClock()
        client = ModelCallClient(
            registry,
            endpoints_for(server.origin),
            limits or CallLimits(),
        )
        deps = LocalApiDeps(
            store=store,
            registry=registry,
            read_model=read_model,
            paths=paths,
            clock=clock,
            ids=Uuid7Factory(),
            runs=StoreRunSurface(store),
            turn_client=client,
        )
        api = start_local_api(paths, deps)
    except BaseException:
        server.close()
        raise
    return Rig(Harness(api, store, registry, read_model, clock), server)


@pytest.fixture
def local(tmp_path: Path) -> Iterator[Rig]:
    rig = _build(tmp_path / "root", DEFAULT_ROUTES)
    try:
        yield rig
    finally:
        rig.close()


def test_turn_uses_exactly_the_selected_model_id(local: Rig) -> None:
    project_id, run_id = make_run(local)
    before = local.harness.counts()

    reply = turn(local, project_id, run_id)

    assert reply.status == 201, reply.body
    body = reply.payload()
    assert body["text"] == "Hello"
    assert body["provider_id"] == "openai"
    assert body["model_id"] == OPENAI_MODEL
    assert body["model_name"] == "gpt-test"
    assert body["adapter"] == "openai_compatible"
    assert body["seq"] == 1
    assert body["request_count"] == 1
    assert body["stop_reason"] == "stop"
    assert body["input_tokens"] == 11
    assert body["output_tokens"] == 2
    assert body["response_sha256"] == hashlib.sha256(b"Hello").hexdigest()
    assert len(str(body["prompt_sha256"])) == 64
    log = local.wire_log
    assert len(log) == 1
    assert log[0].path == OPENAI_PATH
    assert log[0].headers["authorization"] == f"Bearer {CANARY_KEY}"
    # A turn persists only its own row; nothing else in the store moved.
    assert local.harness.counts() == before
    assert len(turn_rows(local)) == 1


def test_turn_persists_selection_on_the_run_projection(local: Rig) -> None:
    project_id, run_id = make_run(local)

    projection = run_projection(local, project_id, run_id)
    assert projection["pinned_provider_id"] is None
    assert projection["pinned_model_id"] is None
    assert projection["turns"] == []

    first = turn(local, project_id, run_id)
    assert first.status == 201, first.body
    projection = run_projection(local, project_id, run_id)
    assert projection["pinned_provider_id"] == "openai"
    assert projection["pinned_model_id"] == OPENAI_MODEL
    turns = [as_dict(item) for item in as_list(projection["turns"])]
    assert len(turns) == 1
    assert turns[0]["seq"] == 1
    assert turns[0]["provider_id"] == "openai"
    assert turns[0]["model_id"] == OPENAI_MODEL
    assert turns[0]["request_count"] == 1
    assert turns[0]["stop_reason"] == "stop"
    assert "text" not in turns[0]

    second = turn(local, project_id, run_id)
    assert second.status == 201, second.body
    assert second.payload()["seq"] == 2
    projection = run_projection(local, project_id, run_id)
    assert projection["pinned_provider_id"] == "openai"
    assert projection["pinned_model_id"] == OPENAI_MODEL
    turns = [as_dict(item) for item in as_list(projection["turns"])]
    assert [item["seq"] for item in turns] == [1, 2]
    # Two completed turns still produced exactly one request each, and no
    # Artifact Version was created or touched by either.
    assert len(local.wire_log) == 2
    assert local.harness.counts()["artifact_versions"] == 4


def test_quota_failure_is_provider_neutral_and_contacts_no_fallback(
    tmp_path: Path,
) -> None:
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = Route(
        status=402,
        body=json_body({}),
        content_type="application/json",
    )
    rig = _build(tmp_path / "root", routes)
    try:
        project_id, run_id = make_run(rig)
        reply = turn(rig, project_id, run_id)
        log = rig.wire_log
    finally:
        rig.close()
    assert reply.status == 502
    assert reply.payload() == {"error": "turn_failed", "reason": "quota"}
    # Anthropic, Google, and Ollama were all reachable and would have
    # succeeded; exactly one request went out, to the selected provider only.
    assert len(log) == 1
    assert log[0].path == OPENAI_PATH


def test_authentication_failure_does_not_try_another_provider_or_env_key_slot(
    tmp_path: Path,
) -> None:
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = Route(
        status=401,
        body=error_body(type="authentication_error"),
        content_type="application/json",
    )
    rig = _build(
        tmp_path / "root",
        routes,
        env={ENV_KEY_SLOT: ENV_CANARY},
    )
    try:
        project_id, run_id = make_run(rig)
        reply = turn(rig, project_id, run_id)
        log = rig.wire_log
    finally:
        rig.close()
    assert reply.status == 502
    assert reply.payload() == {"error": "turn_failed", "reason": "authentication"}
    # One request, carrying the stored credential; the env-slot key for the
    # same provider was never substituted, and no other provider was tried.
    assert len(log) == 1
    assert log[0].headers["authorization"] == f"Bearer {CANARY_KEY}"
    assert all(ENV_CANARY not in value for value in log[0].headers.values())


def test_terminal_turn_failure_leaves_artifact_versions_unchanged(
    tmp_path: Path,
) -> None:
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = Route(
        status=500,
        body=json_body({}),
        content_type="application/json",
    )
    rig = _build(tmp_path / "root", routes)
    try:
        project_id, run_id = make_run(rig)
        before = rig.harness.counts()
        reply = turn(rig, project_id, run_id)
        after = rig.harness.counts()
        rows = turn_rows(rig)
    finally:
        rig.close()
    assert reply.status == 502
    assert reply.payload() == {"error": "turn_failed", "reason": "provider_unavailable"}
    assert after == before
    assert rows == []


def test_turn_error_bodies_and_run_turns_rows_carry_no_canary_key(
    tmp_path: Path,
) -> None:
    # The hostile endpoint echoes the credential back in its own error body.
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = Route(
        status=401,
        body=error_body(
            type=CANARY_KEY,
            code=CANARY_KEY,
            message=f"bad key {CANARY_KEY}",
        ),
        content_type="application/json",
    )
    failing = _build(tmp_path / "failing", routes)
    try:
        project_id, run_id = make_run(failing)
        reply = turn(failing, project_id, run_id)
    finally:
        failing.close()
    assert reply.status == 502
    assert CANARY_KEY.encode() not in reply.body

    succeeding = _build(tmp_path / "succeeding", DEFAULT_ROUTES)
    try:
        project_id, run_id = make_run(succeeding)
        reply = turn(succeeding, project_id, run_id)
        projection = run_projection(succeeding, project_id, run_id)
        rows = turn_rows(succeeding)
    finally:
        succeeding.close()
    assert reply.status == 201, reply.body
    assert CANARY_KEY.encode() not in reply.body
    assert len(rows) == 1
    assert all(CANARY_KEY not in str(value) for row in rows for value in row.values())
    assert CANARY_KEY not in json.dumps(projection)


FAILURE_CASES: Final[list[tuple[ModelCallFailure, Route, int]]] = [
    (
        ModelCallFailure.AUTHENTICATION,
        Route(
            status=401,
            body=error_body(type="authentication_error"),
            content_type="application/json",
        ),
        502,
    ),
    (
        ModelCallFailure.RATE_LIMIT,
        Route(status=429, body=json_body({}), content_type="application/json"),
        502,
    ),
    (
        ModelCallFailure.QUOTA,
        Route(status=402, body=json_body({}), content_type="application/json"),
        502,
    ),
    (
        ModelCallFailure.MODEL_UNAVAILABLE,
        Route(status=404, body=json_body({}), content_type="application/json"),
        502,
    ),
    (
        ModelCallFailure.PROVIDER_UNAVAILABLE,
        Route(status=500, body=json_body({}), content_type="application/json"),
        502,
    ),
    (
        ModelCallFailure.INVALID_REQUEST,
        Route(status=400, body=json_body({}), content_type="application/json"),
        502,
    ),
    (
        ModelCallFailure.TIMEOUT,
        Route(status=504, body=json_body({}), content_type="application/json"),
        504,
    ),
    (
        ModelCallFailure.TRANSPORT,
        Route(chunks=OPENAI_CHUNKS, cut_after=1),
        502,
    ),
    (
        ModelCallFailure.MALFORMED_RESPONSE,
        Route(chunks=sse(["not json at all"])),
        502,
    ),
    (
        ModelCallFailure.UNCLASSIFIED,
        Route(status=418, body=json_body({}), content_type="application/json"),
        502,
    ),
]
"""Ten of the eleven tokens; response_too_large needs tight call limits."""


@pytest.mark.parametrize(("failure", "route", "status"), FAILURE_CASES)
def test_every_model_call_failure_token_maps_to_turn_failed_wire(
    tmp_path: Path,
    failure: ModelCallFailure,
    route: Route,
    status: int,
) -> None:
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = route
    rig = _build(tmp_path / "root", routes)
    try:
        project_id, run_id = make_run(rig)
        reply = turn(rig, project_id, run_id)
        log = rig.wire_log
        rows = turn_rows(rig)
    finally:
        rig.close()
    assert reply.status == status
    assert reply.payload() == {"error": "turn_failed", "reason": failure.value}
    assert len(log) == 1
    assert rows == []


def test_response_too_large_token_maps_to_turn_failed_wire(tmp_path: Path) -> None:
    filler = json.dumps({"choices": [{"delta": {"content": "x" * 900}}]})
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = Route(chunks=sse([filler] * 64))
    rig = _build(
        tmp_path / "root",
        routes,
        limits=CallLimits(max_response_bytes=2048),
    )
    try:
        project_id, run_id = make_run(rig)
        reply = turn(rig, project_id, run_id)
        rows = turn_rows(rig)
    finally:
        rig.close()
    assert reply.status == 502
    assert reply.payload() == {"error": "turn_failed", "reason": "response_too_large"}
    assert rows == []


def test_failed_turn_persists_no_row_and_no_pin(tmp_path: Path) -> None:
    routes = dict(DEFAULT_ROUTES)
    routes[OPENAI_PATH] = Route(
        status=500,
        body=json_body({}),
        content_type="application/json",
    )
    rig = _build(tmp_path / "root", routes)
    try:
        project_id, run_id = make_run(rig)
        reply = turn(rig, project_id, run_id)
        projection = run_projection(rig, project_id, run_id)
        rows = turn_rows(rig)
    finally:
        rig.close()
    assert reply.status == 502
    assert rows == []
    assert projection["pinned_provider_id"] is None
    assert projection["pinned_model_id"] is None
    assert projection["turns"] == []


def test_second_turn_with_different_model_is_refused_pre_egress(
    local: Rig,
) -> None:
    project_id, run_id = make_run(local)
    first = turn(local, project_id, run_id)
    assert first.status == 201, first.body

    refused = turn(local, project_id, run_id, ANTHROPIC_MODEL)

    assert refused.status == 409
    assert refused.error() == "model_selection_locked"
    # Pre-egress: the second provider was never contacted, and the pin and
    # the single row are exactly what the first turn left.
    assert len(local.wire_log) == 1
    assert local.wire_log[0].path == OPENAI_PATH
    rows = turn_rows(local)
    assert len(rows) == 1
    assert rows[0]["model_id"] == OPENAI_MODEL
    assert run_projection(local, project_id, run_id)["pinned_model_id"] == OPENAI_MODEL


def test_concurrent_turns_both_record_and_lose_no_completed_turn(local: Rig) -> None:
    """Two turns completing at once serialize into positions 1 and 2.

    Regression for the seq-outside-lock race: the store assigns the position
    inside the claiming transaction, so a concurrent loser is no longer
    billed by its provider and then dropped with a mislabeled 503.
    """
    project_id, run_id = make_run(local)
    barrier = threading.Barrier(2)
    replies: list[Reply] = []
    lock = threading.Lock()

    def worker() -> None:
        _ = barrier.wait(timeout=10)
        reply = turn(local, project_id, run_id)
        with lock:
            replies.append(reply)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert {reply.status for reply in replies} == {201}
    rows = turn_rows(local)
    assert [int(str(row["seq"])) for row in rows] == [1, 2]
    assert len({str(row["turn_id"]) for row in rows}) == 2
    projection = run_projection(local, project_id, run_id)
    assert projection["pinned_model_id"] == OPENAI_MODEL
    turns = projection["turns"]
    assert isinstance(turns, list)
    assert len(cast("list[object]", turns)) == 2


def test_pinned_run_locks_before_availability_of_the_other_model(local: Rig) -> None:
    """The pin answers model_selection_locked even for a disabled other model.

    Discriminates the deliberate ordering: the lock check runs before the
    availability checks, so a pinned run naming any different model — enabled
    or not — gets the lock's closed code, never model_not_enabled.
    """
    project_id, run_id = make_run(local)
    first = turn(local, project_id, run_id)
    assert first.status == 201, first.body

    locked = turn(local, project_id, run_id, "anthropic:claude-not-enabled")

    assert locked.status == 409
    assert locked.error() == "model_selection_locked"
    assert len(local.wire_log) == 1
    rows = turn_rows(local)
    assert len(rows) == 1
    assert rows[0]["model_id"] == OPENAI_MODEL


def test_turn_refused_when_provider_key_is_not_configured(tmp_path: Path) -> None:
    rig = _build(
        tmp_path / "root",
        DEFAULT_ROUTES,
        keys={"anthropic": SECOND_KEY, "google": SECOND_KEY},
    )
    try:
        project_id, run_id = make_run(rig)
        reply = turn(rig, project_id, run_id)
        log = rig.wire_log
    finally:
        rig.close()
    assert reply.status == 409
    assert reply.error() == "provider_not_configured"
    assert log == ()


def test_malformed_model_id_is_refused_422(local: Rig) -> None:
    project_id, run_id = make_run(local)
    for model_id in ("not-a-model-id", "openai:"):
        reply = turn(local, project_id, run_id, model_id)
        assert reply.status == 422, reply.body
        assert reply.error() == "model_id_malformed"
    assert local.wire_log == ()


def test_unknown_provider_is_refused_404(local: Rig) -> None:
    project_id, run_id = make_run(local)
    reply = turn(local, project_id, run_id, "nosuch:model")
    assert reply.status == 404
    assert reply.error() == "unknown_provider"
    assert local.wire_log == ()


def test_model_not_enabled_is_refused_409(local: Rig) -> None:
    project_id, run_id = make_run(local)
    reply = turn(local, project_id, run_id, "openai:gpt-not-enabled")
    assert reply.status == 409
    assert reply.error() == "model_not_enabled"
    assert local.wire_log == ()


def test_unknown_run_is_404(local: Rig) -> None:
    project_id, _ = make_run(local)
    missing = "019f0000-0000-7000-8000-00000000dead"
    reply = turn(local, project_id, missing)
    assert reply.status == 404
    assert reply.error() == "not_found"
    assert local.wire_log == ()


def test_unknown_project_is_404(local: Rig) -> None:
    missing = "019f0000-0000-7000-8000-00000000dead"
    reply = turn(local, missing, "019f0000-0000-7000-8000-00000000beef")
    assert reply.status == 404
    assert reply.error() == "not_found"
    assert local.wire_log == ()


def test_archived_project_refuses_turn_409(local: Rig) -> None:
    project_id, run_id = make_run(local)
    assert (
        local.harness.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/archive",
        ).status
        == 204
    )
    reply = turn(local, project_id, run_id)
    assert reply.status == 409
    assert reply.error() == "project_archived"
    assert local.wire_log == ()
    assert turn_rows(local) == []
