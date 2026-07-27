"""Real-socket tests for the ActionPlan, approval, and run-start surface.

Assertions use literal status codes and closed error codes rather than
constants imported from the modules under test, so a renamed constant is a
failing test. Side-effect claims inspect the durable store after each
refusal so a refused request cannot hide a queued Run or spent approval.
"""

from __future__ import annotations

import http.client
import json
import sqlite3
import threading
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING, cast, final
from uuid import UUID

import pytest
from services.api.artifacts.runtime import Uuid7Factory

if TYPE_CHECKING:
    from collections.abc import Iterator, Mapping
    from pathlib import Path

    from services.api.artifacts.models import Clock

from nipo_local.api import LocalApiDeps, RunningLocalApi, start_local_api
from nipo_local.apiquery import LocalReadModel
from nipo_local.config import resolve_paths
from nipo_local.providers import InMemoryCredentialBackend, ProviderRegistry
from nipo_local.store import LocalArtifactStore
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
PROJECTS = "/api/v1/projects"
CANARY = "canary-intent-Qq7WwZzXx-do-not-echo"

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

EDITED_INTENT = ResearchIntent(
    question="Does the calibrated 430 nm band persist across replicate runs?",
    rationale="A stable corrected maximum would justify a targeted follow-up.",
    intended_benefit="Avoid bench time spent on non-reproducible bands.",
    success_criteria=("A corrected local maximum is reported near 430 nm.",),
    constraints=("Observed calibrated spectra only.",),
    stop_conditions=("Stop when calibration metadata is missing.",),
    research_mode=ResearchMode.AI_FOR_SCIENCE,
    data_origin=DataOrigin.OBSERVED,
)


def _probe() -> ProbeInput:
    """Build the calibrated spectrum the deterministic analysis accepts."""
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
    """One HTTP request expressed as data."""

    method: str = "GET"
    path: str = "/api/v1/health"
    body: object | None = None
    token: str | None = None
    omit_token: bool = False
    origin: str | None = None
    site: str | None = None
    host: str | None = None


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


@final
class _MovableClock:
    """A clock a test can advance so expiry is asserted rather than waited."""

    def __init__(self) -> None:
        """Start at one fixed aware UTC instant."""
        self.moment = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)

    def now(self) -> datetime:
        """Return the current instant of this clock."""
        return self.moment

    def advance(self, seconds: int) -> None:
        """Move this clock forward by whole seconds."""
        self.moment += timedelta(seconds=seconds)


@final
class Harness:
    """A started local API plus the pieces a plan/run test needs."""

    def __init__(
        self,
        api: RunningLocalApi,
        store: LocalArtifactStore,
        registry: ProviderRegistry,
        read_model: LocalReadModel,
        clock: Clock,
    ) -> None:
        """Retain the running API and the local core behind it."""
        self.api = api
        self.store = store
        self.registry = registry
        self.read_model = read_model
        self.clock = clock
        self.root = api.token_path.parent
        self.ids = Uuid7Factory()

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
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=30)
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

    def make_project(self, name: str = "Plan Lab") -> str:
        """Create one Project through the API and return its identifier."""
        reply = self.same_origin("POST", PROJECTS, {"name": name})
        assert reply.status == 201
        return str(reply.payload()["id"])

    def make_session(self, project_id: str, title: str = "Session A") -> str:
        """Create one Session under a Project and return its identifier."""
        reply = self.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/sessions",
            {"title": title},
        )
        assert reply.status == 201
        return str(reply.payload()["id"])

    def intent_body(self, intent: ResearchIntent = INTENT) -> dict[str, object]:
        """Return the wire shape of one ResearchIntent."""
        return dict(intent.to_dict())

    def probe_body(self) -> dict[str, object]:
        """Return the wire shape of the calibrated ProbeInput."""
        return cast("dict[str, object]", json.loads(_probe().model_dump_json()))

    def create_plan(
        self,
        project_id: str,
        session_id: str,
        intent: ResearchIntent = INTENT,
    ) -> dict[str, object]:
        """POST one ActionPlan and return its 201 body."""
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
        """POST the one approval a plan may carry and return its 201 body."""
        reply = self.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/action-plans/{plan_id}/approvals",
            {},
        )
        assert reply.status == 201, reply.body
        return reply.payload()

    def start_run(
        self,
        project_id: str,
        session_id: str,
        approval_id: str,
        intent: ResearchIntent = INTENT,
    ) -> Reply:
        """POST one run-start request and return the raw reply."""
        return self.same_origin(
            "POST",
            f"{PROJECTS}/{project_id}/runs",
            {
                "session_id": session_id,
                "approval_id": approval_id,
                "research_intent": self.intent_body(intent),
                "scientific_input": self.probe_body(),
            },
        )

    def counts(self) -> dict[str, int]:
        """Count the durable plan/approval/run/execution rows on disk."""
        database = resolve_paths(self.root).database
        connection = sqlite3.connect(database)
        queries = {
            "action_plans": "SELECT COUNT(*) FROM action_plans",
            "plan_approvals": "SELECT COUNT(*) FROM plan_approvals",
            "runs": "SELECT COUNT(*) FROM runs",
            "executions": "SELECT COUNT(*) FROM executions",
            "artifacts": "SELECT COUNT(*) FROM artifacts",
            "artifact_versions": "SELECT COUNT(*) FROM artifact_versions",
        }
        try:
            return {
                name: int(cast("tuple[int]", connection.execute(query).fetchone())[0])
                for name, query in queries.items()
            }
        finally:
            connection.close()

    def approval_row(self, approval_id: str) -> dict[str, object] | None:
        """Read one approval row's consumption state from the durable store."""
        database = resolve_paths(self.root).database
        connection = sqlite3.connect(database)
        try:
            row = cast(
                "tuple[object, object] | None",
                connection.execute(
                    "SELECT consumed_at, consumed_by_run_id FROM plan_approvals "
                    "WHERE id = ?",
                    (approval_id,),
                ).fetchone(),
            )
        finally:
            connection.close()
        if row is None:
            return None
        return {"consumed_at": row[0], "consumed_by_run_id": row[1]}


def _build(root: Path, clock: Clock | None = None) -> Harness:
    """Start a local API over a throwaway data root."""
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
    )
    api = start_local_api(paths, deps)
    return Harness(api, store, registry, read_model, used_clock)


@pytest.fixture
def local(tmp_path: Path) -> Iterator[Harness]:
    """Provide a started local API bound to an ephemeral loopback port."""
    harness = _build(tmp_path / "root")
    try:
        yield harness
    finally:
        harness.close()


@pytest.fixture
def local_at(tmp_path: Path) -> Iterator[tuple[Harness, _MovableClock]]:
    """Provide the same, with a clock the test controls."""
    clock = _MovableClock()
    harness = _build(tmp_path / "root", clock)
    try:
        yield harness, clock
    finally:
        harness.close()


def test_incomplete_research_intent_is_rejected_at_plan_route(local: Harness) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    before = local.counts()

    incomplete = local.intent_body()
    del incomplete["stop_conditions"]
    reply = local.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/action-plans",
        {"session_id": session_id, "research_intent": incomplete},
    )

    assert reply.status == 422
    assert reply.error() == "invalid_request"
    assert local.counts() == before


def test_create_plan_binds_server_derived_plan_digest_to_intent_digest(
    local: Harness,
) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)

    created = local.create_plan(project_id, session_id)

    assert created["session_id"] == session_id
    assert created["research_intent_sha256"] == INTENT.sha256
    assert created["plan_sha256"] != created["research_intent_sha256"]
    assert len(str(created["plan_sha256"])) == 64
    assert created["plan_id"]
    assert created["created_at"]

    got = local.send(
        Call(path=f"{PROJECTS}/{project_id}/action-plans/{created['plan_id']}")
    )
    assert got.status == 200
    assert got.payload()["plan_id"] == created["plan_id"]
    assert got.payload()["plan_sha256"] == created["plan_sha256"]
    assert got.payload()["research_intent_sha256"] == INTENT.sha256


def test_plan_and_approval_get_round_trips(local: Harness) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    created = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(created["plan_id"]))

    plan = local.send(
        Call(path=f"{PROJECTS}/{project_id}/action-plans/{created['plan_id']}")
    )
    assert plan.status == 200
    assert plan.payload() == {
        "plan_id": created["plan_id"],
        "plan_sha256": created["plan_sha256"],
        "research_intent_sha256": created["research_intent_sha256"],
        "created_at": created["created_at"],
    }

    granted = local.send(
        Call(path=f"{PROJECTS}/{project_id}/approvals/{approval['approval_id']}")
    )
    assert granted.status == 200
    body = granted.payload()
    assert body["approval_id"] == approval["approval_id"]
    assert body["plan_id"] == created["plan_id"]
    assert body["plan_sha256"] == created["plan_sha256"]
    assert body["research_intent_sha256"] == INTENT.sha256
    assert body["consumed_at"] is None
    assert body["consumed_by_run_id"] is None
    assert body["granted_at"]
    assert body["expires_at"]


def test_successful_plan_approve_run_chain(local: Harness) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    created = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(created["plan_id"]))

    reply = local.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
    )

    assert reply.status == 201, reply.body
    body = reply.payload()
    assert body["state"] == "completed"
    assert body["execution_isolation"] == "in_process"
    assert len(as_list(body["output_version_ids"])) == 4
    assert body["run_id"]
    assert body["execution_id"]
    counts = local.counts()
    assert counts["runs"] == 1
    assert counts["executions"] == 1
    assert counts["artifacts"] == 4
    assert counts["artifact_versions"] == 4
    spent = local.send(
        Call(path=f"{PROJECTS}/{project_id}/approvals/{approval['approval_id']}")
    )
    assert spent.status == 200
    consumed = spent.payload()
    assert consumed["consumed_at"] is not None
    assert consumed["consumed_by_run_id"] == body["run_id"]


def test_incomplete_research_intent_is_rejected_at_run_start(local: Harness) -> None:
    """AC-L04: the incomplete-intent refusal holds at the run boundary too."""
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    created = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(created["plan_id"]))
    before = local.counts()

    incomplete = local.intent_body()
    incomplete["success_criteria"] = []
    reply = local.send(
        Call(
            method="POST",
            path=f"{PROJECTS}/{project_id}/runs",
            body={
                "session_id": session_id,
                "approval_id": str(approval["approval_id"]),
                "research_intent": incomplete,
                "scientific_input": local.probe_body(),
            },
        )
    )

    assert reply.status == 422
    assert reply.payload() == {"error": "invalid_request"}
    assert local.counts() == before
    row = local.approval_row(str(approval["approval_id"]))
    assert row is not None
    assert row["consumed_at"] is None


def test_approval_is_one_use_and_second_run_start_is_rejected(local: Harness) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    created = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(created["plan_id"]))

    first = local.start_run(project_id, session_id, str(approval["approval_id"]))
    assert first.status == 201
    after_first = local.counts()

    second = local.start_run(project_id, session_id, str(approval["approval_id"]))
    assert second.status == 409
    assert second.error() == "approval_consumed"
    assert local.counts() == after_first


def test_mutated_intent_fields_invalidate_approval_with_zero_side_effects(
    local: Harness,
) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    created = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(created["plan_id"]))
    before = local.counts()
    assert EDITED_INTENT.sha256 != INTENT.sha256

    reply = local.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
        intent=EDITED_INTENT,
    )

    assert reply.status == 409
    assert reply.error() == "approval_digest_mismatch"
    assert local.counts() == before
    row = local.approval_row(str(approval["approval_id"]))
    assert row is not None
    assert row["consumed_at"] is None
    assert row["consumed_by_run_id"] is None


def test_expired_approval_is_rejected_with_zero_side_effects(
    local_at: tuple[Harness, _MovableClock],
) -> None:
    harness, clock = local_at
    project_id = harness.make_project()
    session_id = harness.make_session(project_id)
    created = harness.create_plan(project_id, session_id)
    approval = harness.approve_plan(project_id, str(created["plan_id"]))
    before = harness.counts()

    clock.advance(3601)
    reply = harness.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
    )

    assert reply.status == 409
    assert reply.error() == "approval_expired"
    assert harness.counts() == before
    row = harness.approval_row(str(approval["approval_id"]))
    assert row is not None
    assert row["consumed_at"] is None


def test_replayed_approval_id_does_not_create_execution(local: Harness) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    created = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(created["plan_id"]))
    first = local.start_run(project_id, session_id, str(approval["approval_id"]))
    assert first.status == 201
    before = local.counts()

    replay = local.start_run(project_id, session_id, str(approval["approval_id"]))

    assert replay.status == 409
    assert replay.error() == "approval_consumed"
    assert local.counts()["executions"] == before["executions"]
    assert local.counts()["runs"] == before["runs"]


def test_run_start_without_approval_is_rejected(local: Harness) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    before = local.counts()
    missing = str(local.ids.new_uuid7())

    reply = local.start_run(project_id, session_id, missing)

    assert reply.status == 404
    assert reply.error() == "approval_not_found"
    assert local.counts() == before


def test_approval_consumption_and_execution_appear_in_same_store_state(
    local: Harness,
) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    created = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(created["plan_id"]))

    reply = local.start_run(project_id, session_id, str(approval["approval_id"]))
    assert reply.status == 201
    body = reply.payload()

    row = local.approval_row(str(approval["approval_id"]))
    assert row is not None
    assert row["consumed_at"] is not None
    assert row["consumed_by_run_id"] == body["run_id"]
    counts = local.counts()
    assert counts["executions"] == 1
    assert counts["runs"] == 1

    granted = local.send(
        Call(path=f"{PROJECTS}/{project_id}/approvals/{approval['approval_id']}")
    )
    assert granted.status == 200
    assert granted.payload()["consumed_at"] is not None


def test_concurrent_run_starts_consume_one_approval_exactly_once(
    local: Harness,
) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    created = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(created["plan_id"]))
    barrier = threading.Barrier(2)
    results: list[Reply] = []
    lock = threading.Lock()

    def worker() -> None:
        _ = barrier.wait(timeout=10)
        reply = local.start_run(
            project_id,
            session_id,
            str(approval["approval_id"]),
        )
        with lock:
            results.append(reply)

    threads = [threading.Thread(target=worker) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=60)

    assert len(results) == 2
    statuses = sorted(reply.status for reply in results)
    assert statuses == [201, 409]
    codes = {reply.error() for reply in results if reply.status != 201}
    assert codes == {"approval_consumed"}
    counts = local.counts()
    # The loser still queues a Run that is abandoned as failed before any
    # execution is claimed; the approval fence guarantees exactly one execution.
    assert counts["executions"] == 1
    assert counts["artifacts"] == 4
    assert counts["runs"] >= 1
    assert sum(1 for reply in results if reply.status == 201) == 1
    row = local.approval_row(str(approval["approval_id"]))
    assert row is not None
    assert row["consumed_at"] is not None


def test_error_bodies_use_closed_codes_and_never_echo_intent_text(
    local: Harness,
) -> None:
    project_id = local.make_project()
    session_id = local.make_session(project_id)
    canary_intent = {
        "question": CANARY,
        "rationale": CANARY,
        "intended_benefit": CANARY,
        "success_criteria": [CANARY],
        "constraints": [CANARY],
        "stop_conditions": [],
        "research_mode": "ai_for_science",
        "data_origin": "observed",
    }
    incomplete = local.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/action-plans",
        {"session_id": session_id, "research_intent": canary_intent},
    )
    assert incomplete.status == 422
    assert incomplete.error() == "invalid_request"
    assert CANARY.encode() not in incomplete.body
    assert b"canary" not in incomplete.body.lower()

    created = local.create_plan(project_id, session_id)
    approval = local.approve_plan(project_id, str(created["plan_id"]))
    mutated = local.start_run(
        project_id,
        session_id,
        str(approval["approval_id"]),
        intent=EDITED_INTENT,
    )
    assert mutated.status == 409
    assert mutated.error() == "approval_digest_mismatch"
    assert b"missing" not in mutated.body
    assert CANARY.encode() not in mutated.body

    missing = local.start_run(project_id, session_id, str(local.ids.new_uuid7()))
    assert missing.status == 404
    assert missing.error() == "approval_not_found"
    assert CANARY.encode() not in missing.body

    # First success, then replay — the refusal must stay closed.
    ok = local.start_run(project_id, session_id, str(approval["approval_id"]))
    assert ok.status == 201
    replay = local.start_run(project_id, session_id, str(approval["approval_id"]))
    assert replay.status == 409
    assert replay.error() == "approval_consumed"
    assert CANARY.encode() not in replay.body
    assert b"do-not-echo" not in replay.body
