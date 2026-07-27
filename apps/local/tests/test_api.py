"""Real-socket tests for the local loopback HTTP surface.

Every security claim this module makes is tested against a listening socket
and real HTTP bytes, not against an in-process test client. A test client
shares the application object and therefore cannot observe the bind address,
the wire framing, or a `Host` header a browser would send -- which is exactly
where the interesting failures live.

Assertions use literal status codes and literal JSON field values rather than
constants imported from the modules under test, so a renamed constant is a
failing test rather than a silently agreeing one. Nothing is asserted by
searching for a substring of a file system path: `tmp_path` embeds the test's
own function name, which has already produced false-passing assertions
elsewhere in this repository.
"""

import asyncio
import hashlib
import http.client
import io
import ipaddress
import json
import socket
import sqlite3
import stat
import tracemalloc
import zipfile
from collections.abc import Iterator, Mapping, MutableMapping, Sequence
from contextlib import suppress
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import MappingProxyType
from typing import cast, final
from uuid import UUID

import pytest
from services.api.artifacts.models import (
    ArtifactRecord,
    ArtifactScope,
    ArtifactVersion,
    Clock,
)
from services.api.artifacts.runtime import SystemClock, Uuid7Factory
from starlette.types import Receive, Scope, Send

from nipo_local.api import (
    LocalApiDeps,
    LocalGuard,
    LocalToken,
    RunningLocalApi,
    RunSurface,
    create_app,
    default_deps,
    start_local_api,
)
from nipo_local.apiquery import LocalReadModel
from nipo_local.apiserver import (
    LoopbackServer,
    NonLoopbackBindError,
    bind_loopback,
    loopback_authorities,
    loopback_origins,
    require_loopback,
)
from nipo_local.config import DEFAULT_PROJECT_ID, resolve_paths
from nipo_local.providers import InMemoryCredentialBackend, ProviderRegistry
from nipo_local.runsurface import StoreRunSurface
from nipo_local.store import (
    ActionPlanRecord,
    ExecutionRecord,
    LocalArtifactStore,
    PlanApprovalRecord,
    ProjectRecord,
    RunClaim,
    RunRecord,
    RunState,
)
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
HEALTH = "/api/v1/health"
PROJECTS = "/api/v1/projects"
ZERO_DIGEST = "0" * 64
ONE_DIGEST = "1" * 64
CANARY_KEY = "sk-" + "canary-Qq7WwZzXx-do-not-echo"
NO_EXTRA: Mapping[str, str] = MappingProxyType({})

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
    path: str = HEALTH
    body: object | None = None
    token: str | None = None
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

    def values(self, key: str) -> list[object]:
        """Return one array field of the body."""
        return as_list(self.payload()[key])

    def rows(self, key: str) -> list[dict[str, object]]:
        """Return one array-of-objects field of the body."""
        return [as_dict(item) for item in self.values(key)]


@final
class Harness:
    """A started local API plus the pieces a test needs to poke at it."""

    def __init__(
        self,
        api: RunningLocalApi,
        store: LocalArtifactStore,
        registry: ProviderRegistry,
        read_model: LocalReadModel,
    ) -> None:
        """Retain the running API and the local core behind it."""
        self.api = api
        self.store = store
        self.registry = registry
        self.read_model = read_model
        self.root = api.token_path.parent
        self.ids = Uuid7Factory()
        self.executions: dict[str, UUID] = {}

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
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
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

    def make_project(self, name: str) -> str:
        """Create one Project through the API and return its identifier."""
        reply = self.same_origin("POST", PROJECTS, {"name": name})
        assert reply.status == 201
        return str(reply.payload()["id"])

    def project_count(self) -> int:
        """Count the Projects the API currently lists."""
        reply = self.send(Call(path=PROJECTS))
        assert reply.status == 200
        return len(reply.values("projects"))

    def scope(self, project_id: str) -> ArtifactScope:
        """Build the fixed local scope for one Project."""
        return ArtifactScope(
            org_id=UUID("01900000-0000-7000-8000-000000000001"),
            project_id=UUID(project_id),
            requester_id=UUID("01900000-0000-7000-8000-000000000002"),
        )

    def seed_execution(self, project_id: str) -> UUID:
        """Start one real Run in this Project and return its execution id.

        `commit_version` refuses a Version whose producing execution and that
        execution's Run do not resolve in this exact Project, so a Version
        committed straight through the store needs a real plan, approval, Run,
        and claimed execution behind it. The chain is created once per Project
        and reused: one Run publishing several Artifacts is exactly what the
        workbench itself does, so reuse is not a shortcut around the check.
        """
        cached = self.executions.get(project_id)
        if cached is not None:
            return cached
        scope = self.scope(project_id)
        moment = datetime.now(UTC)
        intent = hashlib.sha256(f"seeded-intent:{project_id}".encode()).hexdigest()
        plan_id = self.ids.new_uuid7()
        plan = ActionPlanRecord(
            id=plan_id,
            org_id=scope.org_id,
            project_id=scope.project_id,
            requester_id=scope.requester_id,
            research_intent_sha256=intent,
            plan_sha256=LocalArtifactStore.plan_digest(scope, plan_id, intent),
            created_at=moment,
        )
        assert str(self.store.create_action_plan(scope, plan)) == "created"
        approval = PlanApprovalRecord(
            id=self.ids.new_uuid7(),
            org_id=scope.org_id,
            project_id=scope.project_id,
            plan_id=plan_id,
            approver_id=scope.requester_id,
            research_intent_sha256=intent,
            plan_sha256=plan.plan_sha256,
            granted_at=moment,
            expires_at=moment + timedelta(hours=1),
        )
        assert str(self.store.grant_approval(scope, approval)) == "created"
        run = RunRecord(
            id=self.ids.new_uuid7(),
            org_id=scope.org_id,
            project_id=scope.project_id,
            plan_id=plan_id,
            approval_id=approval.id,
            requester_id=scope.requester_id,
            state=RunState.QUEUED,
            research_intent_sha256=intent,
            created_at=moment,
            updated_at=moment,
        )
        assert str(self.store.create_run(scope, run)) == "created"
        execution_id = self.ids.new_uuid7()
        claim = RunClaim(
            run_id=run.id,
            approval_id=approval.id,
            research_intent_sha256=intent,
            execution=ExecutionRecord(
                id=execution_id,
                org_id=scope.org_id,
                project_id=scope.project_id,
                run_id=run.id,
                execution_isolation="in_process",
                input_sha256=ZERO_DIGEST,
                research_intent_sha256=intent,
                code_sha256=ONE_DIGEST,
                environment_sha256=ZERO_DIGEST,
                created_at=moment,
            ),
            started_at=moment,
        )
        assert str(self.store.start_run(scope, claim)) == "consumed"
        self.executions[project_id] = execution_id
        return execution_id

    def seed_artifact(
        self,
        project_id: str,
        name: str,
        payloads: Sequence[bytes],
    ) -> tuple[str, list[str]]:
        """Commit one Artifact and its Versions straight through the store."""
        scope = self.scope(project_id)
        producing_execution_id = self.seed_execution(project_id)
        artifact_id = self.ids.new_uuid7()
        moment = datetime.now(UTC)
        _ = self.store.create_artifact(
            scope,
            ArtifactRecord(
                id=artifact_id,
                org_id=scope.org_id,
                project_id=scope.project_id,
                name=name,
                created_at=moment,
            ),
        )
        version_ids: list[str] = []
        for index, payload in enumerate(payloads, start=1):
            digest = hashlib.sha256(payload).hexdigest()
            version = ArtifactVersion(
                id=self.ids.new_uuid7(),
                org_id=scope.org_id,
                project_id=scope.project_id,
                artifact_id=artifact_id,
                version_no=index,
                object_key=LocalArtifactStore.object_key(scope, digest),
                content_sha256=digest,
                size_bytes=len(payload),
                media_type="text/csv",
                producing_execution_id=producing_execution_id,
                environment_sha256=ZERO_DIGEST,
                code_sha256=ONE_DIGEST,
                runtime_adapter_id="local_deterministic",
                runtime_connection_id=UUID("01900000-0000-7000-8000-000000000004"),
                skill_content_hashes=(),
                source_hashes=(),
                input_version_ids=(),
                created_at=moment,
            )
            outcome = self.store.commit_version(scope, index - 1, version, payload)
            assert str(outcome) == "created"
            version_ids.append(str(version.id))
        return str(artifact_id), version_ids


@final
class StubRuns:
    """A Run surface double, so the declared seam is exercised end to end."""

    def __init__(self, isolation: str | None = "in_process") -> None:
        """Record the isolation level this double will disclose."""
        self.isolation = isolation

    def list_runs(self, scope: ArtifactScope) -> Sequence[Mapping[str, object]]:
        """Return one opaque projection owned by the implementation."""
        return ({"id": str(scope.project_id), "state": "queued"},)

    def read_run(
        self,
        scope: ArtifactScope,
        run_id: UUID,
    ) -> Mapping[str, object] | None:
        """Return one opaque projection, or nothing for the nil identifier."""
        if run_id.int == 0:
            return None
        return {"id": str(run_id), "project_id": str(scope.project_id)}

    def execution_isolation(
        self,
        scope: ArtifactScope,
        execution_id: UUID,
    ) -> str | None:
        """Disclose the isolation level of one produced execution."""
        assert scope.project_id is not None
        assert execution_id is not None
        return self.isolation


def _build(root: Path, runs: RunSurface | None = None) -> Harness:
    """Start a local API over a throwaway data root."""
    paths = resolve_paths(root)
    paths.ensure()
    store = LocalArtifactStore(paths)
    registry = ProviderRegistry(paths, InMemoryCredentialBackend(), {})
    read_model = LocalReadModel(paths)
    api = start_local_api(
        paths,
        default_deps(store, registry, read_model, paths, runs),
    )
    return Harness(api, store, registry, read_model)


@pytest.fixture
def local(tmp_path: Path) -> Iterator[Harness]:
    """Provide a started local API bound to an ephemeral loopback port."""
    harness = _build(tmp_path / "root")
    try:
        yield harness
    finally:
        harness.close()


@pytest.fixture
def local_with_runs(tmp_path: Path) -> Iterator[Harness]:
    """Provide a started local API with the Run seam bound to a double."""
    harness = _build(tmp_path / "root", StubRuns())
    try:
        yield harness
    finally:
        harness.close()


def _non_loopback_ipv4s() -> tuple[str, ...]:
    """Return every non-loopback IPv4 address this machine answers on."""
    found: set[str] = set()
    probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        # Connecting a UDP socket only selects a route; no packet is sent.
        probe.connect(("192.0.2.1", 9))
        found.add(str(_bound_name(probe)[0]))
    except OSError:
        pass
    finally:
        probe.close()
    with suppress(OSError):
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            found.add(str(info[4][0]))
    return tuple(
        address
        for address in sorted(found)
        if not ipaddress.ip_address(address).is_loopback
    )


# --------------------------------------------------------------------------
# LS01: loopback-only binding, proven against real sockets
# --------------------------------------------------------------------------


def _connect(address: str, port: int) -> None:
    """Open and immediately close one TCP connection."""
    socket.create_connection((address, port), timeout=2).close()


def _bound_name(listener: socket.socket) -> tuple[object, ...]:
    """Return one socket's bound address as an opaque tuple."""
    return cast("tuple[object, ...]", listener.getsockname())


def test_listening_socket_is_bound_to_the_loopback_address(local: Harness) -> None:
    bound = _bound_name(local.api.server.socket)
    assert bound[0] == "127.0.0.1"
    assert bound[1] == local.port


def test_no_non_loopback_address_of_this_machine_accepts_a_connection(
    local: Harness,
) -> None:
    for address in _non_loopback_ipv4s():
        with pytest.raises(OSError, match=r".*"):
            _connect(address, local.port)


def test_a_wildcard_bound_socket_is_refused_by_the_server(local: Harness) -> None:
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("0.0.0.0", 0))  # noqa: S104 - the very address under test
    listener.listen(1)
    assert _bound_name(listener)[0] == "0.0.0.0"  # noqa: S104
    read_model = LocalReadModel(resolve_paths(local.root))
    try:
        app = create_app(
            LocalApiDeps(
                store=local.store,
                registry=local.registry,
                read_model=read_model,
                paths=resolve_paths(local.root),
                clock=_FixedClock(),
                ids=Uuid7Factory(),
            ),
            LocalToken("unused"),
            origins=frozenset(),
            authorities=frozenset(),
        )
        with pytest.raises(NonLoopbackBindError):
            _ = LoopbackServer(app, listener)
        # The refused socket is closed, so no listener is left behind.
        with pytest.raises(OSError, match=r".*"):
            _ = _bound_name(listener)
    finally:
        read_model.close()


@pytest.mark.parametrize(
    "host",
    [
        "0.0.0.0",  # noqa: S104 - the wildcard is exactly what must be refused
        "::",
        "0",
        "192.0.2.1",
        "10.0.0.1",
        "example.com",
        "",
        " 127.0.0.1",
        "127.0.0.1 ",
        "localhost.evil.test",
    ],
)
def test_binding_refuses_every_non_loopback_host(host: str) -> None:
    with pytest.raises(NonLoopbackBindError):
        _ = require_loopback(host)
    with pytest.raises(NonLoopbackBindError):
        _ = bind_loopback(host, 0)


@pytest.mark.parametrize("host", ["127.0.0.1", "localhost", "::1", "127.0.0.53"])
def test_require_loopback_accepts_loopback_literals(host: str) -> None:
    assert require_loopback(host).is_loopback


def test_bound_loopback_socket_reports_a_loopback_name() -> None:
    listener = bind_loopback("localhost", 0)
    try:
        assert _bound_name(listener)[0] == "127.0.0.1"
    finally:
        listener.close()


# --------------------------------------------------------------------------
# The local session credential
# --------------------------------------------------------------------------


def test_request_without_the_token_is_rejected(local: Harness) -> None:
    reply = local.send(Call(omit_token=True))
    assert reply.status == 401
    assert reply.error() == "local_token_required"


def test_request_with_a_wrong_token_is_rejected(local: Harness) -> None:
    reply = local.send(Call(token="not-the-token"))  # noqa: S106 - a wrong credential
    assert reply.status == 401
    assert reply.error() == "local_token_invalid"


def test_request_with_a_truncated_token_is_rejected(local: Harness) -> None:
    reply = local.send(Call(token=local.token[:-1]))
    assert reply.status == 401
    assert reply.error() == "local_token_invalid"


def test_a_non_ascii_token_is_refused_rather_than_erroring(local: Harness) -> None:
    reply = local.send(Call(token="tökén-not-the-token"))  # noqa: S106 - malformed
    assert reply.status == 401
    assert reply.error() == "local_token_invalid"


def test_an_empty_token_header_is_refused(local: Harness) -> None:
    reply = local.send(Call(omit_token=True, extra={TOKEN_HEADER_NAME: ""}))
    assert reply.status == 401
    assert reply.error() == "local_token_invalid"


def test_request_with_the_token_succeeds(local: Harness) -> None:
    reply = local.send(Call())
    assert reply.status == 200
    assert reply.payload()["status"] == "ok"


def test_token_in_a_query_parameter_is_not_accepted(local: Harness) -> None:
    reply = local.send(Call(path=f"{HEALTH}?token={local.token}", omit_token=True))
    assert reply.status == 401
    assert reply.error() == "local_token_required"


def test_every_state_changing_route_requires_the_token(local: Harness) -> None:
    project = local.make_project("Alpha")
    unauthenticated = [
        Call(method="POST", path=PROJECTS, body={"name": "Beta"}, omit_token=True),
        Call(
            method="POST",
            path=f"{PROJECTS}/{project}/sessions",
            body={"title": "Run"},
            omit_token=True,
        ),
        Call(
            method="PUT",
            path="/api/v1/providers/openai/key",
            body={"key": CANARY_KEY},
            omit_token=True,
        ),
        Call(method="DELETE", path="/api/v1/providers/openai/key", omit_token=True),
        Call(method="POST", path=f"{PROJECTS}/{project}/archive", omit_token=True),
    ]
    for call in unauthenticated:
        assert local.send(call).status == 401
    assert local.project_count() == 1
    assert local.send(Call(path="/api/v1/providers/openai")).payload()["status"] == (
        "not_set_up"
    )


def test_token_file_is_owner_only_and_carries_what_the_front_end_needs(
    local: Harness,
) -> None:
    mode = stat.S_IMODE(local.api.token_path.stat().st_mode)
    assert mode == 0o600
    document = as_dict(
        cast("object", json.loads(local.api.token_path.read_text(encoding="utf-8")))
    )
    assert document["token"] == local.token
    assert document["header"] == "x-nipo-token"
    assert document["base_url"] == f"http://127.0.0.1:{local.port}"


def test_closing_the_api_removes_the_credential_file(tmp_path: Path) -> None:
    harness = _build(tmp_path / "root")
    path = harness.api.token_path
    assert path.exists()
    harness.close()
    assert not path.exists()


def test_the_token_never_appears_in_any_response(local: Harness) -> None:
    project = local.make_project("Alpha")
    probes = [
        Call(),
        Call(omit_token=True),
        Call(token="wrong"),  # noqa: S106 - a wrong credential, on purpose
        Call(path=PROJECTS),
        Call(path=f"{PROJECTS}/{project}"),
        Call(path="/api/v1/providers"),
        Call(path="/api/v1/composer"),
        Call(path="/api/v1/nope"),
        Call(
            method="POST", path=PROJECTS, body={"name": "x"}, origin="https://evil.test"
        ),
    ]
    secret = local.token.encode()
    for call in probes:
        reply = local.send(call)
        assert secret not in reply.body
        assert all(secret not in value.encode() for value in reply.headers.values())


def test_the_token_is_redacted_in_its_own_repr() -> None:
    token = LocalToken("super-secret-value")
    assert "super-secret-value" not in repr(token)
    assert "super-secret-value" not in str(token)
    assert "redacted" in repr(token)


# --------------------------------------------------------------------------
# Same-origin discipline and the rebinding authority pin
# --------------------------------------------------------------------------


def test_cross_origin_state_change_is_refused_and_changes_nothing(
    local: Harness,
) -> None:
    before = local.project_count()
    reply = local.send(
        Call(
            method="POST",
            path=PROJECTS,
            body={"name": "Injected"},
            origin="https://evil.example",
        )
    )
    assert reply.status == 403
    assert reply.error() == "cross_origin_denied"
    assert local.project_count() == before


def test_cross_site_fetch_metadata_state_change_is_refused_and_changes_nothing(
    local: Harness,
) -> None:
    before = local.project_count()
    reply = local.send(
        Call(method="POST", path=PROJECTS, body={"name": "Injected"}, site="cross-site")
    )
    assert reply.status == 403
    assert reply.error() == "cross_origin_denied"
    assert local.project_count() == before


def test_same_site_but_not_same_origin_state_change_is_refused(local: Harness) -> None:
    reply = local.send(
        Call(method="POST", path=PROJECTS, body={"name": "Injected"}, site="same-site")
    )
    assert reply.status == 403
    assert reply.error() == "cross_origin_denied"


def test_cross_origin_read_is_refused(local: Harness) -> None:
    reply = local.send(Call(path=PROJECTS, origin="https://evil.example"))
    assert reply.status == 403
    assert reply.error() == "cross_origin_denied"


def test_same_origin_state_change_is_accepted(local: Harness) -> None:
    reply = local.same_origin("POST", PROJECTS, {"name": "Spectra"})
    assert reply.status == 201
    assert reply.payload()["name"] == "Spectra"


def test_localhost_origin_and_authority_are_accepted(local: Harness) -> None:
    reply = local.send(
        Call(
            method="POST",
            path=PROJECTS,
            body={"name": "Spectra"},
            origin=f"http://localhost:{local.port}",
            site="same-origin",
            host=f"localhost:{local.port}",
        )
    )
    assert reply.status == 201


def test_a_rebound_host_authority_is_refused_and_changes_nothing(
    local: Harness,
) -> None:
    before = local.project_count()
    reply = local.send(
        Call(
            method="POST",
            path=PROJECTS,
            body={"name": "Injected"},
            origin="http://research.evil.example",
            site="same-origin",
            host="research.evil.example",
        )
    )
    assert reply.status == 403
    assert reply.error() == "host_not_allowed"
    assert local.project_count() == before


def test_a_rebound_host_authority_is_refused_on_reads_too(local: Harness) -> None:
    reply = local.send(Call(path=PROJECTS, host="research.evil.example"))
    assert reply.status == 403
    assert reply.error() == "host_not_allowed"


def test_a_loopback_authority_on_the_wrong_port_is_refused(local: Harness) -> None:
    reply = local.send(Call(path=PROJECTS, host=f"127.0.0.1:{local.port + 1}"))
    assert reply.status == 403
    assert reply.error() == "host_not_allowed"


def test_preflight_is_refused_and_no_response_ever_grants_cors(
    local: Harness,
) -> None:
    preflight = local.send(
        Call(
            method="OPTIONS",
            path=PROJECTS,
            origin=f"http://127.0.0.1:{local.port}",
            extra={"Access-Control-Request-Method": "POST"},
        )
    )
    assert preflight.status == 403
    assert preflight.error() == "preflight_denied"
    project = local.make_project("Alpha")
    for call in (Call(), Call(path=PROJECTS), Call(path=f"{PROJECTS}/{project}")):
        reply = local.send(call)
        assert "access-control-allow-origin" not in reply.headers
        assert "access-control-allow-credentials" not in reply.headers


def test_responses_carry_the_hardened_browser_headers(local: Harness) -> None:
    reply = local.send(Call())
    assert reply.headers["x-content-type-options"] == "nosniff"
    assert reply.headers["referrer-policy"] == "no-referrer"
    assert reply.headers["cache-control"] == "no-store"
    assert reply.headers["x-frame-options"] == "DENY"
    assert "default-src 'none'" in reply.headers["content-security-policy"]


def test_refusals_carry_the_hardened_browser_headers(local: Harness) -> None:
    reply = local.send(Call(omit_token=True))
    assert reply.status == 401
    assert reply.headers["x-content-type-options"] == "nosniff"


def test_a_websocket_connection_never_reaches_the_application() -> None:
    seen: list[dict[str, object]] = []

    async def application(
        _scope: MutableMapping[str, object],
        _receive: object,
        _send: object,
    ) -> None:  # pragma: no cover - reaching this is the failure
        raise AssertionError

    async def send(message: MutableMapping[str, object]) -> None:
        seen.append(dict(message))

    async def receive() -> MutableMapping[str, object]:
        return {"type": "websocket.connect"}

    guard = LocalGuard(
        application,
        token=LocalToken("t"),
        origins=frozenset(),
        authorities=frozenset(),
    )
    asyncio.run(guard({"type": "websocket"}, receive, send))
    assert seen == [{"type": "websocket.close", "code": 1008}]


def test_origin_and_authority_sets_are_exactly_the_local_ones() -> None:
    assert loopback_origins(4321) == frozenset(
        {"http://127.0.0.1:4321", "http://localhost:4321", "http://[::1]:4321"}
    )
    assert loopback_authorities(4321) == frozenset(
        {"127.0.0.1:4321", "localhost:4321", "[::1]:4321"}
    )


# --------------------------------------------------------------------------
# Providers: presence, never value
# --------------------------------------------------------------------------


def test_provider_list_reports_status_and_no_key_field(local: Harness) -> None:
    reply = local.send(Call(path="/api/v1/providers"))
    assert reply.status == 200
    providers = reply.rows("providers")
    assert len(providers) == 13
    assert set(providers[0]) == {
        "provider_id",
        "display_name",
        "status",
        "requires_key",
        "env_var",
        "is_ready",
    }
    statuses = {str(item["provider_id"]): str(item["status"]) for item in providers}
    assert statuses["ollama"] == "no_key_needed"
    assert statuses["anthropic"] == "not_set_up"


def test_setting_and_clearing_a_key_only_moves_the_status(local: Harness) -> None:
    stored = local.same_origin(
        "PUT",
        "/api/v1/providers/anthropic/key",
        {"key": CANARY_KEY},
    )
    assert stored.status == 204
    assert stored.body == b""

    card = local.send(Call(path="/api/v1/providers/anthropic"))
    assert card.payload()["status"] == "configured"
    assert CANARY_KEY.encode() not in card.body

    listing = local.send(Call(path="/api/v1/providers"))
    assert CANARY_KEY.encode() not in listing.body

    cleared = local.same_origin("DELETE", "/api/v1/providers/anthropic/key")
    assert cleared.status == 204
    after = local.send(Call(path="/api/v1/providers/anthropic"))
    assert after.payload()["status"] == "not_set_up"


def test_the_stored_key_is_still_exactly_what_was_submitted(local: Harness) -> None:
    assert (
        local.same_origin(
            "PUT",
            "/api/v1/providers/anthropic/key",
            {"key": CANARY_KEY},
        ).status
        == 204
    )
    assert local.registry.resolve_key("anthropic") == CANARY_KEY


def test_a_key_for_a_keyless_provider_is_refused(local: Harness) -> None:
    reply = local.same_origin("PUT", "/api/v1/providers/ollama/key", {"key": "x"})
    assert reply.status == 409
    assert reply.error() == "key_not_required"


@pytest.mark.parametrize(
    "provider_id",
    ["nope", "..", "../../etc/passwd", "%2e%2e%2fopenai", "OPENAI"],
)
def test_an_unknown_provider_identifier_is_refused(
    local: Harness,
    provider_id: str,
) -> None:
    reply = local.send(Call(path=f"/api/v1/providers/{provider_id}"))
    assert reply.status in {404, 400}
    assert reply.error() in {"unknown_provider", "not_found", "invalid_request"}


@pytest.mark.parametrize(
    ("key", "reason"),
    [
        (" " + CANARY_KEY, "surrounding_whitespace"),
        (CANARY_KEY + "\t", "surrounding_whitespace"),
        (CANARY_KEY[:4] + "\u200b" + CANARY_KEY[4:], "invisible_character"),
        ("   ", "empty"),
    ],
)
def test_a_rejected_key_reports_a_reason_and_never_echoes_the_key(
    local: Harness,
    key: str,
    reason: str,
) -> None:
    reply = local.same_origin("PUT", "/api/v1/providers/anthropic/key", {"key": key})
    assert reply.status == 400
    assert reply.error() == "key_rejected"
    assert reply.payload()["reason"] == reason
    assert b"canary" not in reply.body.lower()
    assert local.send(Call(path="/api/v1/providers/anthropic")).payload()["status"] == (
        "not_set_up"
    )


def test_a_malformed_key_request_body_never_echoes_the_submitted_value(
    local: Harness,
) -> None:
    reply = local.same_origin(
        "PUT",
        "/api/v1/providers/anthropic/key",
        {"api_key": CANARY_KEY},
    )
    assert reply.status == 400
    assert reply.error() == "invalid_request"
    assert CANARY_KEY.encode() not in reply.body
    assert b"canary" not in reply.body.lower()
    assert reply.payload() == {"error": "invalid_request"}


def test_an_extra_field_alongside_the_key_never_echoes_it(local: Harness) -> None:
    reply = local.same_origin(
        "PUT",
        "/api/v1/providers/anthropic/key",
        {"key": "abc", "smuggled": CANARY_KEY},
    )
    assert reply.status == 400
    assert CANARY_KEY.encode() not in reply.body


def test_composer_round_trips_and_refuses_a_default_outside_the_set(
    local: Harness,
) -> None:
    written = local.same_origin(
        "PUT",
        "/api/v1/composer",
        {
            "enabled_models": ["anthropic:claude", "openai:gpt"],
            "default_model": "openai:gpt",
        },
    )
    assert written.status == 200
    assert written.payload()["default_model"] == "openai:gpt"

    read = local.send(Call(path="/api/v1/composer"))
    assert read.payload()["enabled_models"] == ["anthropic:claude", "openai:gpt"]
    assert [item["is_default"] for item in read.rows("models")] == [False, True]

    refused = local.same_origin(
        "PUT",
        "/api/v1/composer",
        {"enabled_models": ["anthropic:claude"], "default_model": "openai:gpt"},
    )
    assert refused.status == 409
    assert refused.error() == "model_not_enabled"

    malformed = local.same_origin(
        "PUT",
        "/api/v1/composer",
        {"enabled_models": ["not-a-model-id"]},
    )
    assert malformed.status == 400
    assert malformed.error() == "model_id_malformed"


# --------------------------------------------------------------------------
# Projects and Sessions
# --------------------------------------------------------------------------


def test_project_lifecycle(local: Harness) -> None:
    project = local.make_project("Spectra")
    read = local.send(Call(path=f"{PROJECTS}/{project}"))
    assert read.status == 200
    assert read.payload()["archived"] is False

    archived = local.same_origin("POST", f"{PROJECTS}/{project}/archive")
    assert archived.status == 204
    assert local.send(Call(path=f"{PROJECTS}/{project}")).payload()["archived"] is True

    refused = local.same_origin(
        "POST",
        f"{PROJECTS}/{project}/sessions",
        {"title": "After"},
    )
    assert refused.status == 409
    assert refused.error() == "project_archived"


def test_an_unregistered_project_is_not_found(local: Harness) -> None:
    reply = local.send(Call(path=f"{PROJECTS}/01900000-0000-7000-8000-0000000000ff"))
    assert reply.status == 404
    assert reply.error() == "not_found"


def test_a_non_uuid7_project_identifier_is_not_found(local: Harness) -> None:
    reply = local.send(Call(path=f"{PROJECTS}/00000000-0000-4000-8000-000000000000"))
    assert reply.status == 404


@pytest.mark.parametrize(
    ("name", "reason"),
    [
        ("../etc/passwd", "path_separator"),
        ("..\\windows", "path_separator"),
        ("nested/name", "path_separator"),
        ("..", "relative_segment"),
        (".", "relative_segment"),
        ("trailing.", "trailing_dot"),
        ("~/secrets", "path_separator"),
        ("~secrets", "absolute_path"),
        ("C:evil", "drive_qualified"),
        ("CON", "reserved_device_name"),
        ("nul.txt", "reserved_device_name"),
        ("lpt9", "reserved_device_name"),
        ("bad\x00name", "invisible_character"),
        ("zero\u200bwidth", "invisible_character"),
        ("café", "not_nfc"),
        (" padded", "boundary_whitespace"),
        ("padded ", "boundary_whitespace"),
        ("x" * 256, "too_long"),
    ],
)
def test_a_path_shaped_project_name_is_refused_with_a_typed_reason(
    local: Harness,
    name: str,
    reason: str,
) -> None:
    before = local.project_count()
    reply = local.same_origin("POST", PROJECTS, {"name": name})
    assert reply.status == 400
    assert reply.error() == "invalid_name"
    assert reply.payload()["reason"] == reason
    assert local.project_count() == before


@pytest.mark.parametrize(("first", "second"), [("Alpha", "alpha"), ("file", "ﬁle")])
def test_a_normalized_name_collision_is_refused(
    local: Harness,
    first: str,
    second: str,
) -> None:
    assert local.same_origin("POST", PROJECTS, {"name": first}).status == 201
    reply = local.same_origin("POST", PROJECTS, {"name": second})
    assert reply.status == 409
    assert reply.error() == "name_in_use"
    assert local.project_count() == 1


def test_session_lifecycle_and_ordering(local: Harness) -> None:
    project = local.make_project("Spectra")
    base = f"{PROJECTS}/{project}/sessions"
    first = local.same_origin("POST", base, {"title": "Baseline"})
    second = local.same_origin("POST", base, {"title": "Replicate"})
    assert first.status == 201
    assert second.status == 201

    listed = local.send(Call(path=base)).rows("sessions")
    assert [item["title"] for item in listed] == ["Replicate", "Baseline"]

    first_id = str(first.payload()["id"])
    resumed = local.same_origin("POST", f"{base}/{first_id}/resume")
    assert resumed.status == 200
    reordered = local.send(Call(path=base)).rows("sessions")
    assert [item["title"] for item in reordered] == ["Baseline", "Replicate"]

    archived = local.same_origin("POST", f"{base}/{first_id}/archive")
    assert archived.status == 204
    again = local.same_origin("POST", f"{base}/{first_id}/archive")
    assert again.status == 409
    assert again.error() == "session_archived"
    resume_dead = local.same_origin("POST", f"{base}/{first_id}/resume")
    assert resume_dead.status == 409
    assert resume_dead.error() == "session_archived"


def test_a_colliding_session_title_is_refused(local: Harness) -> None:
    project = local.make_project("Spectra")
    base = f"{PROJECTS}/{project}/sessions"
    assert local.same_origin("POST", base, {"title": "Baseline"}).status == 201
    reply = local.same_origin("POST", base, {"title": "baseline"})
    assert reply.status == 409
    assert reply.error() == "name_in_use"


def test_a_path_shaped_session_title_is_refused(local: Harness) -> None:
    project = local.make_project("Spectra")
    reply = local.same_origin(
        "POST",
        f"{PROJECTS}/{project}/sessions",
        {"title": "../escape"},
    )
    assert reply.status == 400
    assert reply.payload()["reason"] == "path_separator"


def test_an_unknown_session_is_not_found(local: Harness) -> None:
    project = local.make_project("Spectra")
    path = f"{PROJECTS}/{project}/sessions/01900000-0000-7000-8000-0000000000ee"
    assert local.send(Call(path=path)).status == 404


# --------------------------------------------------------------------------
# Artifacts, Versions, content, provenance
# --------------------------------------------------------------------------


def test_artifacts_list_detail_history_and_content(local: Harness) -> None:
    project = local.make_project("Spectra")
    payloads = [b"a,b\n1,2\n", b"a,b\n3,4\n"]
    artifact, versions = local.seed_artifact(project, "hypothesis-table.csv", payloads)
    base = f"{PROJECTS}/{project}/artifacts"

    listed = local.send(Call(path=base))
    assert listed.status == 200
    entries = listed.rows("artifacts")
    assert len(entries) == 1
    assert entries[0]["version_count"] == 2
    assert entries[0]["head_version_no"] == 2

    detail = local.send(Call(path=f"{base}/{artifact}"))
    assert detail.status == 200
    detail_versions = detail.rows("versions")
    assert [item["version_no"] for item in detail_versions] == [1, 2]
    assert all("object_key" not in item for item in detail_versions)

    history = local.send(Call(path=f"{base}/{artifact}/versions"))
    assert [item["id"] for item in history.rows("versions")] == versions

    for identifier, payload in zip(versions, payloads, strict=True):
        content = local.send(
            Call(path=f"{base}/{artifact}/versions/{identifier}/content")
        )
        assert content.status == 200
        assert content.body == payload
        assert (
            content.headers["x-content-sha256"] == hashlib.sha256(payload).hexdigest()
        )
        assert content.headers["content-type"] == "text/csv"
        assert content.headers["x-content-type-options"] == "nosniff"
        assert content.headers["content-disposition"] == (
            'attachment; filename="hypothesis-table.csv"'
        )


def test_provenance_pins_every_digest_and_withholds_the_object_key(
    local: Harness,
) -> None:
    project = local.make_project("Spectra")
    payload = b"a,b\n1,2\n"
    artifact, versions = local.seed_artifact(project, "table.csv", [payload])
    path = (
        f"{PROJECTS}/{project}/artifacts/{artifact}/versions/{versions[0]}/provenance"
    )
    reply = local.send(Call(path=path))
    assert reply.status == 200
    body = reply.payload()
    assert "object_key" not in body
    assert body["content_sha256"] == hashlib.sha256(payload).hexdigest()
    assert body["environment_sha256"] == ZERO_DIGEST
    assert body["code_sha256"] == ONE_DIGEST
    assert body["skill_content_hashes"] == []
    assert body["input_version_ids"] == []
    assert body["execution_isolation"] is None


def test_a_downloadable_name_can_never_carry_a_separator(local: Harness) -> None:
    project = local.make_project("Spectra")
    artifact, versions = local.seed_artifact(project, "../../etc/passwd", [b"x"])
    path = f"{PROJECTS}/{project}/artifacts/{artifact}/versions/{versions[0]}/content"
    reply = local.send(Call(path=path))
    assert reply.status == 200
    disposition = reply.headers["content-disposition"]
    assert "/" not in disposition.split("filename=")[1]
    assert ".." not in disposition
    assert "\r" not in disposition
    assert "\n" not in disposition


def test_an_unknown_artifact_or_foreign_version_is_not_found(local: Harness) -> None:
    project = local.make_project("Spectra")
    first, first_versions = local.seed_artifact(project, "one.csv", [b"1"])
    _second, second_versions = local.seed_artifact(project, "two.csv", [b"2"])
    base = f"{PROJECTS}/{project}/artifacts"
    assert (
        local.send(Call(path=f"{base}/01900000-0000-7000-8000-0000000000dd")).status
        == 404
    )
    foreign = local.send(Call(path=f"{base}/{first}/versions/{second_versions[0]}"))
    assert foreign.status == 404
    assert foreign.error() == "not_found"
    assert (
        local.send(Call(path=f"{base}/{first}/versions/{first_versions[0]}")).status
        == 200
    )


def test_an_archived_project_hides_its_artifacts(local: Harness) -> None:
    project = local.make_project("Spectra")
    artifact, versions = local.seed_artifact(project, "one.csv", [b"1"])
    assert local.same_origin("POST", f"{PROJECTS}/{project}/archive").status == 204
    base = f"{PROJECTS}/{project}/artifacts"
    assert local.send(Call(path=base)).status == 409
    assert local.send(Call(path=f"{base}/{artifact}")).status == 409
    content = local.send(Call(path=f"{base}/{artifact}/versions/{versions[0]}/content"))
    assert content.status == 409
    assert content.error() == "project_archived"


# --------------------------------------------------------------------------
# The Run seam
# --------------------------------------------------------------------------


def test_run_routes_declare_the_seam_when_nothing_is_bound(local: Harness) -> None:
    project = local.make_project("Spectra")
    listed = local.send(Call(path=f"{PROJECTS}/{project}/runs"))
    assert listed.status == 501
    assert listed.error() == "run_surface_unavailable"
    single = local.send(
        Call(path=f"{PROJECTS}/{project}/runs/01900000-0000-7000-8000-0000000000aa")
    )
    assert single.status == 501
    assert single.error() == "run_surface_unavailable"
    assert local.send(Call()).payload()["run_surface"] is False


def test_a_bound_run_surface_is_served_verbatim(local_with_runs: Harness) -> None:
    project = local_with_runs.make_project("Spectra")
    listed = local_with_runs.send(Call(path=f"{PROJECTS}/{project}/runs"))
    assert listed.status == 200
    runs = listed.payload()["runs"]
    assert runs == [{"id": project, "state": "queued"}]
    single = local_with_runs.send(
        Call(path=f"{PROJECTS}/{project}/runs/01900000-0000-7000-8000-0000000000aa")
    )
    assert single.status == 200
    assert single.payload()["project_id"] == project
    missing = local_with_runs.send(
        Call(path=f"{PROJECTS}/{project}/runs/00000000-0000-0000-0000-000000000000")
    )
    assert missing.status in {404, 400}
    assert local_with_runs.send(Call()).payload()["run_surface"] is True


def test_isolation_disclosure_comes_only_from_the_bound_run_surface(
    local_with_runs: Harness,
) -> None:
    project = local_with_runs.make_project("Spectra")
    artifact, versions = local_with_runs.seed_artifact(project, "one.csv", [b"1"])
    path = (
        f"{PROJECTS}/{project}/artifacts/{artifact}/versions/{versions[0]}/provenance"
    )
    reply = local_with_runs.send(Call(path=path))
    assert reply.status == 200
    assert reply.payload()["execution_isolation"] == "in_process"


# --------------------------------------------------------------------------
# Transport discipline
# --------------------------------------------------------------------------


def _raw(port: int, payload: bytes) -> bytes:
    """Send raw bytes to the listener and read whatever comes back."""
    connection = socket.create_connection(("127.0.0.1", port), timeout=5)
    try:
        connection.sendall(payload)
        chunks: list[bytes] = []
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            chunks.append(chunk)
        return b"".join(chunks)
    finally:
        connection.close()


def test_a_malformed_request_line_is_refused(local: Harness) -> None:
    reply = _raw(local.port, b"GARBAGE\r\n\r\n")
    assert reply.startswith(b"HTTP/1.1 400 ")
    assert b'"error":"invalid_request"' in reply


def test_a_chunked_body_is_refused_rather_than_guessed(local: Harness) -> None:
    request = (
        b"POST /api/v1/projects HTTP/1.1\r\n"
        b"Host: 127.0.0.1:%d\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    ) % local.port
    reply = _raw(local.port, request)
    assert reply.startswith(b"HTTP/1.1 413 ")


def test_a_duplicated_content_length_is_refused(local: Harness) -> None:
    request = (
        b"POST /api/v1/projects HTTP/1.1\r\n"
        b"Host: 127.0.0.1:%d\r\n"
        b"Content-Length: 2\r\n"
        b"Content-Length: 3\r\n\r\n"
    ) % local.port
    reply = _raw(local.port, request)
    assert reply.startswith(b"HTTP/1.1 413 ")


def test_an_oversized_body_is_refused_before_the_application_runs(
    local: Harness,
) -> None:
    request = (
        b"POST /api/v1/projects HTTP/1.1\r\n"
        b"Host: 127.0.0.1:%d\r\n"
        b"Content-Length: 9999999999\r\n\r\n"
    ) % local.port
    reply = _raw(local.port, request)
    assert reply.startswith(b"HTTP/1.1 413 ")
    assert local.project_count() == 0


def test_every_response_closes_its_connection_and_declares_its_length(
    local: Harness,
) -> None:
    reply = local.send(Call())
    assert reply.headers["connection"] == "close"
    assert reply.headers["content-length"] == str(len(reply.body))


def test_an_unknown_route_is_a_typed_not_found(local: Harness) -> None:
    reply = local.send(Call(path="/api/v1/../../etc/passwd"))
    assert reply.status == 404
    assert reply.error() == "not_found"


def test_a_wrong_method_is_a_typed_refusal(local: Harness) -> None:
    reply = local.same_origin("DELETE", PROJECTS)
    assert reply.status == 405
    assert reply.error() == "method_not_allowed"


def test_the_framework_documentation_endpoints_are_absent(local: Harness) -> None:
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert local.send(Call(path=path)).status == 404


# --------------------------------------------------------------------------
# The wire is incremental
#
# The listener used to fold every `http.response.body` event into one
# `bytearray` and write the socket once, so an Export Pack the non-functional
# budget sizes at up to 500 MiB was held whole in this process however
# carefully it had been read off disk. A test that only checks the bytes are
# correct cannot tell the two implementations apart -- both deliver the same
# bytes -- so these measure instead. `tracemalloc` traces every thread of this
# process, which is what makes the measurement meaningful: the listener runs on
# its own thread, and a buffer it kept would be counted here.
#
# The producer below builds each chunk as it sends it and keeps none, and the
# reader below digests each block and keeps none, so the only thing left that
# could account for a peak near the body size is the layer under test.
# --------------------------------------------------------------------------

WIRE_CHUNK_BYTES = 1 << 20
WIRE_CHUNK_COUNT = 64


def _wire_chunk(index: int) -> bytes:
    """Build one chunk of the measured body, distinguishable from its neighbours."""
    return bytes((index % 256,)) * WIRE_CHUNK_BYTES


def _wire_digest() -> str:
    """Digest the whole measured body without ever holding it whole."""
    digest = hashlib.sha256()
    for index in range(WIRE_CHUNK_COUNT):
        digest.update(_wire_chunk(index))
    return digest.hexdigest()


@final
class _Torrent:
    """An ASGI application that sends a large body one bounded chunk at a time."""

    def __init__(self, *, declare_length: bool) -> None:
        """Record whether this application states its own content length."""
        self._declare_length = declare_length

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Answer any request with the measured body."""
        del receive
        assert scope["type"] == "http"
        headers = [(b"content-type", b"application/octet-stream")]
        if self._declare_length:
            declared = str(WIRE_CHUNK_BYTES * WIRE_CHUNK_COUNT).encode("ascii")
            headers.append((b"content-length", declared))
        await send({"type": "http.response.start", "status": 200, "headers": headers})
        for index in range(WIRE_CHUNK_COUNT):
            await send(
                {
                    "type": "http.response.body",
                    # Built here and dropped once `send` returns: the producer
                    # is not what holds the body in either implementation.
                    "body": _wire_chunk(index),
                    "more_body": index + 1 < WIRE_CHUNK_COUNT,
                }
            )


@final
@dataclass(frozen=True, slots=True)
class _Transfer:
    """What one measured transfer put on the wire, minus the body itself."""

    status: int
    headers: Mapping[str, str]
    length: int
    digest: str
    peak_bytes: int


def _measure(*, declare_length: bool, method: str = "GET") -> _Transfer:
    """Serve one request from a large-body application and measure the process.

    The body is never assembled on either side: the reader digests each block
    and drops it, so a peak near the body size can only be the listener's.
    """
    server = LoopbackServer(_Torrent(declare_length=declare_length), bind_loopback())
    server.start()
    tracemalloc.start()
    try:
        tracemalloc.reset_peak()
        connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=30)
        try:
            connection.request(method, "/")
            response = connection.getresponse()
            digest = hashlib.sha256()
            length = 0
            while True:
                block = response.read(1 << 16)
                if not block:
                    break
                length += len(block)
                digest.update(block)
            status = response.status
            headers = {name.lower(): value for name, value in response.getheaders()}
        finally:
            connection.close()
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
        server.stop()
    return _Transfer(status, headers, length, digest.hexdigest(), peak)


def test_a_declared_length_reaches_the_socket_without_the_body_being_held() -> None:
    # 67108864 is 64 MiB, spelled out so a retuned chunk constant cannot make
    # this test agree with a smaller body than the one it means to measure.
    measured = _measure(declare_length=True)

    assert measured.status == 200
    assert measured.length == 67108864
    assert measured.digest == _wire_digest()
    # The application's own length is the framing, so a browser gets a real
    # progress bar and a transfer that dies half way through is a truncation
    # the client detects rather than a short file that looks complete.
    assert measured.headers["content-length"] == "67108864"
    assert "transfer-encoding" not in measured.headers
    assert measured.headers["connection"] == "close"
    # The measurement, and the whole point of the test: 8 MiB is an eighth of
    # the body. A listener that collects a body before writing it peaks above
    # the body size, not below a fraction of it.
    assert measured.peak_bytes < 8388608


def test_a_body_of_unknown_length_is_chunked_rather_than_collected() -> None:
    # No `content-length` from the application, so the listener has to frame
    # the response itself. Chunked rather than connection-close framing: both
    # are legal, but only chunked is self-delimiting, and a truncated pack that
    # looks complete is the worst outcome available here.
    measured = _measure(declare_length=False)

    assert measured.status == 200
    assert measured.length == 67108864
    assert measured.digest == _wire_digest()
    assert measured.headers["transfer-encoding"] == "chunked"
    assert "content-length" not in measured.headers
    assert measured.peak_bytes < 8388608


def test_a_no_content_response_declares_no_length_at_all(local: Harness) -> None:
    # RFC 9112 section 6.2 forbids a `content-length` on a 204 outright, and a
    # transfer coding on a response that cannot carry content is worse still:
    # a client that honoured it would sit waiting for a terminating chunk.
    project = local.make_project("Spectra")

    reply = local.same_origin("POST", f"{PROJECTS}/{project}/archive")

    assert reply.status == 204
    assert reply.body == b""
    assert "content-length" not in reply.headers
    assert "transfer-encoding" not in reply.headers
    assert reply.headers["connection"] == "close"


def test_a_head_request_reports_the_length_and_sends_no_body() -> None:
    measured = _measure(declare_length=True, method="HEAD")

    assert measured.status == 200
    # The length the same GET would have sent, which is what the method is for.
    assert measured.headers["content-length"] == "67108864"
    assert "transfer-encoding" not in measured.headers
    assert measured.length == 0
    assert measured.digest == hashlib.sha256(b"").hexdigest()


def _open_descriptors() -> int | None:
    """Count this process's open descriptors, or None where that is unreadable."""
    for directory in ("/proc/self/fd", "/dev/fd"):
        with suppress(OSError):
            return sum(1 for _ in Path(directory).iterdir())
    return None


def _abandon_mid_body(port: int) -> bytes:
    """Start a large download, read the first bytes off it, and vanish."""
    connection = socket.create_connection(("127.0.0.1", port), timeout=10)
    try:
        connection.sendall(b"GET / HTTP/1.1\r\nHost: 127.0.0.1:%d\r\n\r\n" % port)
        return connection.recv(4096)
    finally:
        connection.close()


def test_a_client_that_disappears_mid_body_leaves_the_listener_answering() -> None:
    server = LoopbackServer(_Torrent(declare_length=True), bind_loopback())
    server.start()
    try:
        # Warm the listener first, so the descriptors a first connection sets
        # up are not counted as growth caused by the abandoned ones.
        _ = _abandon_mid_body(server.port)
        before = _open_descriptors()

        started = [_abandon_mid_body(server.port) for _ in range(5)]

        after = _open_descriptors()
        connection = http.client.HTTPConnection("127.0.0.1", server.port, timeout=30)
        try:
            connection.request("HEAD", "/")
            response = connection.getresponse()
            still_serving = response.status
            declared = response.getheader("content-length")
            _ = response.read()
        finally:
            connection.close()
    finally:
        server.stop()

    for opening in started:
        # Bytes really arrived before the client vanished, so this is a
        # disconnect during a body rather than before one.
        assert opening.startswith(b"HTTP/1.1 200 ")
    # The listener is not wedged: it answers the next request on a new socket.
    assert still_serving == 200
    assert declared == "67108864"
    if before is not None and after is not None:
        # Five abandoned transfers left no sockets behind. Two descriptors of
        # slack, because reading the count opens one itself.
        assert after <= before + 2


@final
class _FixedClock:
    """A clock double for the wildcard-socket construction test."""

    def now(self) -> datetime:
        """Return one fixed aware UTC instant."""
        return datetime(2026, 1, 1, tzinfo=UTC)


# ------------------------------------------------------- the served front end
#
# `create_app` used to mount only `/api/v1`, so `GET /` was a 404 and the UI
# could not be served from the one origin a browser can present the custom
# credential header from. These assertions are literal: an assertion written
# against `webui.DOCUMENT_CSP` would agree with any policy that module held,
# including one that had grown `'unsafe-inline'`.


DOCUMENT_POLICY = (
    "default-src 'none'; script-src 'self'; style-src 'self'; "
    "connect-src 'self'; img-src 'self'; base-uri 'none'; "
    "form-action 'none'; frame-ancestors 'none'"
)
API_POLICY = "default-src 'none'; frame-ancestors 'none'"


@pytest.mark.parametrize("path", ["/", "/index.html"])
def test_the_document_is_served_under_a_policy_that_permits_only_self(
    local: Harness,
    path: str,
) -> None:
    reply = local.send(Call(path=path, omit_token=True))

    assert reply.status == 200
    assert reply.headers["content-type"] == "text/html; charset=utf-8"
    assert reply.headers["content-security-policy"] == DOCUMENT_POLICY
    assert "unsafe-inline" not in reply.headers["content-security-policy"]
    assert "unsafe-eval" not in reply.headers["content-security-policy"]
    assert "http" not in reply.headers["content-security-policy"]
    assert reply.headers["x-content-type-options"] == "nosniff"
    assert reply.headers["referrer-policy"] == "no-referrer"
    assert reply.headers["x-frame-options"] == "DENY"
    assert "access-control-allow-origin" not in reply.headers


def test_the_document_carries_this_run_s_credential_in_its_meta_anchor(
    local: Harness,
) -> None:
    reply = local.send(Call(path="/", omit_token=True))

    anchor = f'<meta name="nipo-local-token" content="{local.token}">'
    assert anchor.encode() in reply.body
    # And nothing else this listener serves carries it.
    for path in ("/app.js", "/styles.css", "/favicon.svg", HEALTH):
        other = local.send(Call(path=path))
        assert local.token.encode() not in other.body


def test_only_the_document_relaxes_the_policy(local: Harness) -> None:
    for path in ("/app.js", "/styles.css", "/favicon.svg", HEALTH):
        reply = local.send(Call(path=path))
        assert reply.status == 200, path
        assert reply.headers["content-security-policy"] == API_POLICY, path


def test_the_page_assets_are_served_with_their_own_media_types(
    local: Harness,
) -> None:
    expected = {
        "/app.js": "text/javascript; charset=utf-8",
        "/styles.css": "text/css; charset=utf-8",
        "/favicon.svg": "image/svg+xml",
    }
    for path, media_type in expected.items():
        reply = local.send(Call(path=path, omit_token=True))
        assert reply.status == 200, path
        assert reply.headers["content-type"] == media_type, path


@pytest.mark.parametrize(
    "path",
    [
        "/../etc/passwd",
        "/%2e%2e/etc/passwd",
        "/%2e%2e%2fetc%2fpasswd",
        "/..%2f..%2fetc%2fpasswd",
        "/./app.js/../../../etc/passwd",
        "/nipo.sqlite3",
        "/api-token.json",
        "/credentials.json",
        "/settings.json",
        "/download-signing.key",
        "/index.html/",
        "/INDEX.HTML",
    ],
)
def test_no_request_reaches_a_file_outside_the_served_set(
    local: Harness,
    path: str,
) -> None:
    # There is no path parameter on the static surface, so there is nothing
    # for any of these to traverse. The 404 is the absence of a route, not a
    # filter that could be bypassed.
    reply = local.send(Call(path=path))

    assert reply.status == 404
    assert reply.error() == "not_found"


def test_the_document_refuses_a_cross_site_load(local: Harness) -> None:
    # The document cannot carry a custom header, so the guard applies
    # Sec-Fetch-Site to every method here rather than only state-changing ones.
    for site in ("cross-site", "same-site"):
        reply = local.send(Call(path="/", omit_token=True, site=site))
        assert reply.status == 403, site
        assert reply.error() == "cross_origin_denied", site


def test_the_document_allows_a_user_navigation_and_a_same_origin_subresource(
    local: Harness,
) -> None:
    for site in ("none", "same-origin"):
        reply = local.send(Call(path="/", omit_token=True, site=site))
        assert reply.status == 200, site


def test_the_document_still_pins_the_host_authority(local: Harness) -> None:
    reply = local.send(
        Call(path="/", omit_token=True, host="workbench.attacker.example")
    )

    assert reply.status == 403
    assert reply.error() == "host_not_allowed"


def test_the_document_still_refuses_a_foreign_origin(local: Harness) -> None:
    reply = local.send(
        Call(path="/", omit_token=True, origin="https://attacker.example")
    )

    assert reply.status == 403
    assert reply.error() == "cross_origin_denied"


def test_the_document_still_refuses_a_preflight(local: Harness) -> None:
    reply = local.send(Call(method="OPTIONS", path="/", omit_token=True))

    assert reply.status == 403
    assert reply.error() == "preflight_denied"


def test_the_credential_exemption_does_not_reach_the_api(local: Harness) -> None:
    # The exempt set is a closed set of literal paths, not a hole in the guard.
    for path in (HEALTH, PROJECTS, "/api/v1/providers", "/api/v1/composer"):
        reply = local.send(Call(path=path, omit_token=True))
        assert reply.status == 401, path
        assert reply.error() == "local_token_required", path


def test_a_listener_without_a_front_end_serves_no_page(tmp_path: Path) -> None:
    # `create_app(web=None)` is the API-only arrangement, and in it every
    # single path requires the credential again.
    paths = resolve_paths(tmp_path / "root")
    paths.ensure()
    store = LocalArtifactStore(paths)
    registry = ProviderRegistry(paths, InMemoryCredentialBackend(), {})
    read_model = LocalReadModel(paths)
    listener = bind_loopback("127.0.0.1", 0)
    port = cast("int", cast("tuple[object, ...]", listener.getsockname())[1])
    token = LocalToken("only-for-this-listener")
    app = create_app(
        default_deps(store, registry, read_model, paths, None),
        token,
        origins=loopback_origins(port),
        authorities=loopback_authorities(port),
        web=None,
    )
    server = LoopbackServer(app, listener)
    server.start()
    try:
        connection = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        try:
            connection.request("GET", "/", headers={TOKEN_HEADER_NAME: token.value})
            response = connection.getresponse()
            body = response.read()
            assert response.status == 404
            assert b"not_found" in body
        finally:
            connection.close()
    finally:
        server.stop()
        store.close()
        read_model.close()


def test_a_trailing_slash_is_a_not_found_rather_than_a_redirect(
    local: Harness,
) -> None:
    for path in ("/index.html/", "/app.js/", f"{PROJECTS}/"):
        reply = local.send(Call(path=path))
        assert reply.status == 404, path
        assert reply.error() == "not_found", path
        assert "location" not in reply.headers, path


# ------------------------------------------------------------------- reviews
#
# `reviewer.py` was complete, `store.py` could persist a Review, and no route
# joined them. These exercise the route over a real published chain.


@pytest.fixture
def local_with_chain(tmp_path: Path) -> Iterator[tuple[Harness, str, str]]:
    """Provide a started API whose store already holds one published chain."""
    root = tmp_path / "root"
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
        default_deps(store, registry, read_model, paths, StoreRunSurface(store)),
    )
    harness = Harness(api, store, registry, read_model)
    try:
        yield harness, str(DEFAULT_PROJECT_ID), str(run.run_id)
    finally:
        harness.close()


def test_a_run_has_no_review_until_one_is_opened(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = local_with_chain
    path = f"/api/v1/projects/{project_id}/runs/{run_id}/review"

    reply = harness.send(Call(path=path))

    # Not an empty findings list: that would read as "reviewed and clean".
    assert reply.status == 404
    assert reply.error() == "review_not_found"


def test_opening_a_review_records_one_finding_per_rule(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = local_with_chain
    path = f"/api/v1/projects/{project_id}/runs/{run_id}/review"

    reply = harness.same_origin("POST", path)

    assert reply.status == 201
    body = reply.payload()
    assert body["state"] == "completed"
    assert body["source_run_id"] == run_id
    findings = [as_dict(item) for item in as_list(body["findings"])]
    assert [item["rule_id"] for item in findings] == [
        "RV01",
        "RV02",
        "RV03",
        "RV04",
        "RV05",
    ]
    assert [item["sequence"] for item in findings] == [1, 2, 3, 4, 5]
    assert {str(item["status"]) for item in findings} == {"open"}
    assert {str(item["verdict"]) for item in findings} <= {
        "pass",
        "warn",
        "fail",
        "inconclusive",
    }


def test_a_review_ships_the_limits_of_every_rule_beside_its_verdict(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = local_with_chain
    path = f"/api/v1/projects/{project_id}/runs/{run_id}/review"

    body = harness.same_origin("POST", path).payload()

    coverage = [as_dict(item) for item in as_list(body["coverage"])]
    assert [item["rule_id"] for item in coverage] == [
        "RV01",
        "RV02",
        "RV03",
        "RV04",
        "RV05",
    ]
    for item in coverage:
        # A rule with no published limits would let a surface present a narrow
        # check as a broad one without any code changing.
        assert len(as_list(item["limits"])) >= 1, item["rule_id"]
        assert len(as_list(item["checks"])) >= 1, item["rule_id"]
        assert str(item["statement"]).strip() != ""


def test_a_review_summarizes_without_ever_reporting_pass_over_inconclusive(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = local_with_chain
    path = f"/api/v1/projects/{project_id}/runs/{run_id}/review"

    body = harness.same_origin("POST", path).payload()

    findings = [as_dict(item) for item in as_list(body["findings"])]
    verdicts = {str(item["verdict"]) for item in findings}
    if "inconclusive" in verdicts:
        assert body["verdict"] != "pass"
    assert str(body["verdict"]) in {"pass", "warn", "fail", "inconclusive"}


def test_reviewing_twice_returns_one_review(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = local_with_chain
    path = f"/api/v1/projects/{project_id}/runs/{run_id}/review"

    first = harness.same_origin("POST", path).payload()
    second = harness.same_origin("POST", path).payload()

    assert second["id"] == first["id"]
    assert second["pinned_input_sha256"] == first["pinned_input_sha256"]
    assert second["verdict"] == first["verdict"]


def test_a_review_reads_back_identically(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = local_with_chain
    path = f"/api/v1/projects/{project_id}/runs/{run_id}/review"
    opened = harness.same_origin("POST", path).payload()

    first = harness.send(Call(path=path))
    second = harness.send(Call(path=path))

    assert first.status == 200
    assert first.payload() == second.payload() == opened


def test_a_review_of_an_unknown_run_is_a_typed_not_found(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, _ = local_with_chain
    absent = "018f47a0-7b9c-7fff-8def-0123456789ab"

    reply = harness.same_origin(
        "POST",
        f"/api/v1/projects/{project_id}/runs/{absent}/review",
    )

    assert reply.status == 404
    assert reply.error() == "not_found"


def test_a_review_needs_the_credential_and_a_same_origin_caller(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = local_with_chain
    path = f"/api/v1/projects/{project_id}/runs/{run_id}/review"

    unauthenticated = harness.send(Call(method="POST", path=path, omit_token=True))
    cross_site = harness.send(Call(method="POST", path=path, site="cross-site"))

    assert unauthenticated.status == 401
    assert unauthenticated.error() == "local_token_required"
    assert cross_site.status == 403
    assert cross_site.error() == "cross_origin_denied"


def test_a_review_writes_no_version(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = local_with_chain
    before = harness.send(Call(path=f"/api/v1/projects/{project_id}/artifacts"))

    _ = harness.same_origin(
        "POST",
        f"/api/v1/projects/{project_id}/runs/{run_id}/review",
    )
    after = harness.send(Call(path=f"/api/v1/projects/{project_id}/artifacts"))

    assert after.payload() == before.payload()
    assert len(after.rows("artifacts")) == 4
    assert {
        int(cast("int", item["head_version_no"])) for item in after.rows("artifacts")
    } == {1}


# --------------------------------------------------- the bound Run surface --


def test_a_bound_run_surface_discloses_the_recorded_isolation(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    # `execution_isolation` read `null` on every Version because the run
    # surface was never bound. Bound, it reports what the execution recorded.
    harness, project_id, run_id = local_with_chain
    run = harness.send(Call(path=f"/api/v1/projects/{project_id}/runs/{run_id}"))
    assert run.status == 200
    outputs = [as_dict(item) for item in as_list(run.payload()["committed_outputs"])]
    assert [item["role"] for item in outputs] == ["csv", "png", "markdown", "ledger"]

    first = outputs[0]
    provenance = harness.send(
        Call(
            path=(
                f"/api/v1/projects/{project_id}/artifacts/{first['artifact_id']}"
                f"/versions/{first['version_id']}/provenance"
            )
        )
    )

    assert provenance.status == 200
    assert provenance.payload()["execution_isolation"] == "in_process"
    assert run.payload()["execution_isolation"] == "in_process"
    assert run.payload()["state"] == "completed"


def _forget_execution(harness: Harness, execution_id: UUID) -> None:
    """Remove one execution row the way a lossy restore would.

    Nothing in this build can publish a Version without its execution, so a
    Version whose producer answers nothing has to be manufactured here.
    """
    connection = sqlite3.connect(resolve_paths(harness.root).database)
    try:
        deleted = connection.execute(
            "DELETE FROM executions WHERE id = ?",
            (str(execution_id),),
        )
        assert deleted.rowcount == 1
        connection.commit()
    finally:
        connection.close()


def test_an_unanswerable_execution_still_reports_null_isolation(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    # A null must stay reachable with the surface bound, because the front end
    # renders its "assume nothing" disclosure for exactly that value. Here the
    # Version's producing execution has no `executions` row.
    #
    # `commit_version` now refuses such a Version outright, so the only way one
    # exists is the way this test builds it: a Version published by a real
    # execution whose row later went missing -- a data root written by an older
    # build, or one restored from a backup that lost the row. The disclosure
    # must still be the absent one rather than an invented isolation level.
    harness, project_id, _ = local_with_chain
    artifact_id, version_ids = harness.seed_artifact(project_id, "orphan", (b"a,b\n",))
    _forget_execution(harness, harness.seed_execution(project_id))

    reply = harness.send(
        Call(
            path=(
                f"/api/v1/projects/{project_id}/artifacts/{artifact_id}"
                f"/versions/{version_ids[0]}/provenance"
            )
        )
    )

    assert reply.status == 200
    assert reply.payload()["execution_isolation"] is None


def test_the_run_list_is_served_from_the_durable_rows(
    local_with_chain: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = local_with_chain

    reply = harness.send(Call(path=f"/api/v1/projects/{project_id}/runs"))

    assert reply.status == 200
    runs = [as_dict(item) for item in as_list(reply.payload()["runs"])]
    assert [item["run_id"] for item in runs] == [run_id]
    assert runs[0]["state"] == "completed"
    assert runs[0]["execution_isolation"] == "in_process"
    assert len(as_list(runs[0]["committed_outputs"])) == 4


@final
class _AnswerAnything:
    """A minimal ASGI app that answers 200 on every path.

    The real application 404s outside its own routes, which would hide a
    widened credential exemption behind a not-found. This one answers, so the
    guard's decision is the only thing the assertion can be measuring.
    """

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        """Answer one request with an empty 200."""
        del receive
        assert scope["type"] == "http"
        await send(
            {
                "type": "http.response.start",
                "status": 200,
                "headers": [(b"content-type", b"text/plain")],
            }
        )
        await send({"type": "http.response.body", "body": b"ok", "more_body": False})


def _guarded_reply(
    guard: LocalGuard,
    path: str,
    headers: Sequence[tuple[bytes, bytes]],
) -> tuple[int, bytes]:
    """Drive one guarded request through the ASGI interface and capture it."""
    captured: dict[str, object] = {"status": 0, "body": b""}

    async def receive() -> MutableMapping[str, object]:
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message: MutableMapping[str, object]) -> None:
        if message["type"] == "http.response.start":
            captured["status"] = message["status"]
        elif message["type"] == "http.response.body":
            captured["body"] = cast("bytes", captured["body"]) + cast(
                "bytes", message.get("body", b"")
            )

    scope: MutableMapping[str, object] = {
        "type": "http",
        "method": "GET",
        "path": path,
        "headers": list(headers),
    }
    asyncio.run(guard(cast("Scope", scope), receive, send))
    return cast("int", captured["status"]), cast("bytes", captured["body"])


def test_the_credential_exemption_is_a_closed_set_not_a_prefix() -> None:
    # The exempt paths are the static surface's own enumeration. A path that
    # merely sits outside `/api/v1` is *not* exempt, so a future route added
    # anywhere cannot become credential-free by virtue of where it lives.
    token = LocalToken("the-only-accepted-credential")
    guard = LocalGuard(
        _AnswerAnything(),
        token=token,
        origins=frozenset({"http://127.0.0.1:9"}),
        authorities=frozenset({"127.0.0.1:9"}),
        documents=frozenset({"/", "/index.html"}),
    )
    host = (b"host", b"127.0.0.1:9")

    exempt_status, exempt_body = _guarded_reply(guard, "/", [host])
    outside_status, outside_body = _guarded_reply(guard, "/anything-else", [host])
    api_status, _ = _guarded_reply(guard, "/api/v1/health", [host])
    with_token_status, _ = _guarded_reply(
        guard,
        "/anything-else",
        [host, (b"x-nipo-token", token.value.encode())],
    )

    assert (exempt_status, exempt_body) == (200, b"ok")
    assert outside_status == 401
    assert b"local_token_required" in outside_body
    assert api_status == 401
    assert with_token_status == 200


def test_create_app_exempts_exactly_the_paths_it_serves(tmp_path: Path) -> None:
    # One statement, not two: the routes registered and the paths exempted
    # come from the same enumeration, so they cannot drift apart.
    paths = resolve_paths(tmp_path / "root")
    paths.ensure()
    store = LocalArtifactStore(paths)
    read_model = LocalReadModel(paths)
    registry = ProviderRegistry(paths, InMemoryCredentialBackend(), {})
    surface = StaticSurface()
    try:
        app = create_app(
            default_deps(store, registry, read_model, paths, None),
            LocalToken("value"),
            origins=frozenset(),
            authorities=frozenset(),
            web=surface,
        )
        assert isinstance(app, LocalGuard)
        assert app.documents == surface.paths
        assert app.documents == frozenset(
            {"/", "/index.html", "/app.js", "/styles.css", "/favicon.svg"}
        )
        assert not any(item.startswith("/api") for item in app.documents)
    finally:
        store.close()
        read_model.close()


# -------------------------------------------------------------------- exports
#
# `exportpack.py` was complete and fully tested, `store.py` held the pinned
# evidence, and nothing joined them: Export was the one stage of the ordered
# chain with no route. These exercise the route over a real published chain,
# against a real socket, and read the produced pack back off the disk.
#
# The download is checked twice over. Once for the bytes -- a response that is
# 200 with an empty body is the exact failure a "did it download?" assertion
# misses -- and once for the capability, which must be spendable once, only for
# its own pack, only before it expires, and never as a substitute for the
# session credential.

EXPORTS_DIRECTORY_NAME = "exports"
PACK_SCHEMA_NAME = "nipo.local.export-pack.v1"


@final
class _MovableClock:
    """A clock a test can advance, so an expiry is asserted rather than waited."""

    def __init__(self) -> None:
        """Start at one fixed aware UTC instant."""
        self.moment = datetime(2026, 3, 4, 5, 6, 7, tzinfo=UTC)

    def now(self) -> datetime:
        """Return the current instant of this clock."""
        return self.moment

    def advance(self, seconds: int) -> None:
        """Move this clock forward."""
        self.moment += timedelta(seconds=seconds)


def _chain_harness(root: Path, clock: Clock | None = None) -> tuple[Harness, str, str]:
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
    deps = LocalApiDeps(
        store=store,
        registry=registry,
        read_model=read_model,
        paths=paths,
        clock=SystemClock() if clock is None else clock,
        ids=Uuid7Factory(),
        runs=StoreRunSurface(store),
    )
    api = start_local_api(paths, deps)
    return (
        Harness(api, store, registry, read_model),
        str(DEFAULT_PROJECT_ID),
        str(run.run_id),
    )


@pytest.fixture
def exportable(tmp_path: Path) -> Iterator[tuple[Harness, str, str]]:
    """Provide a started API over one published chain, ready to export."""
    harness, project_id, run_id = _chain_harness(tmp_path / "root")
    try:
        yield harness, project_id, run_id
    finally:
        harness.close()


@pytest.fixture
def exportable_at(tmp_path: Path) -> Iterator[tuple[Harness, str, str, _MovableClock]]:
    """Provide the same, with a clock the test controls."""
    clock = _MovableClock()
    harness, project_id, run_id = _chain_harness(tmp_path / "root", clock)
    try:
        yield harness, project_id, run_id, clock
    finally:
        harness.close()


def _plan(harness: Harness, project_id: str, run_id: str) -> dict[str, object]:
    """Read the export plan for one Run."""
    reply = harness.send(Call(path=f"{PROJECTS}/{project_id}/runs/{run_id}/export"))
    assert reply.status == 200
    return reply.payload()


def _pinned_ids(plan: Mapping[str, object]) -> list[str]:
    """Return the Version identifiers one plan offers, in publication order."""
    return [
        str(as_dict(item)["artifact_version_id"])
        for item in as_list(plan["candidates"])
    ]


def _produce(
    harness: Harness,
    project_id: str,
    run_id: str,
    selection: Sequence[str],
) -> Reply:
    """Ask for one pack over an explicit selection."""
    return harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/runs/{run_id}/export",
        {"artifact_version_ids": list(selection)},
    )


def _pack_path(harness: Harness, project_id: str, pack_id: str) -> Path:
    """Return where one produced pack is written under the data root."""
    return harness.root / EXPORTS_DIRECTORY_NAME / project_id / f"{pack_id}.zip"


def _mint(harness: Harness, project_id: str, pack_id: str) -> dict[str, object]:
    """Mint one download capability for one produced pack."""
    reply = harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/exports/{pack_id}/download",
    )
    assert reply.status == 201
    return reply.payload()


def _verify_archive(archive: bytes) -> dict[str, object]:
    """Recompute every digest from the archive alone and return its manifest.

    This is the check a colleague performs. It reads nothing from the producing
    modules: the digests come from `hashlib` over the bytes in the ZIP, and the
    expected values come from the two independent statements the pack itself
    carries.
    """
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        names = opened.namelist()
        assert "manifest.json" in names
        assert "checksums.sha256" in names
        recomputed = {
            name: hashlib.sha256(opened.read(name)).hexdigest() for name in names
        }
        declared: dict[str, str] = {}
        for line in opened.read("checksums.sha256").decode("utf-8").splitlines():
            assert line[64:66] == "  "
            declared[line[66:]] = line[:64]
        assert set(declared) == set(names) - {"checksums.sha256"}
        assert declared == {
            name: digest for name, digest in recomputed.items() if name in declared
        }
        manifest = as_dict(cast("object", json.loads(opened.read("manifest.json"))))
    for entry in [as_dict(item) for item in as_list(manifest["entries"])]:
        assert recomputed[str(entry["path"])] == entry["sha256"]
    assert manifest["schema"] == PACK_SCHEMA_NAME
    return manifest


def test_the_export_plan_offers_only_the_versions_the_run_published(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable

    plan = _plan(harness, project_id, run_id)

    candidates = [as_dict(item) for item in as_list(plan["candidates"])]
    assert [str(item["role"]) for item in candidates] == [
        "csv",
        "png",
        "markdown",
        "ledger",
    ]
    assert [int(str(item["sequence"])) for item in candidates] == [1, 2, 3, 4]
    assert {str(item["version_no"]) for item in candidates} == {"1"}
    assert [str(item["pack_path"]) for item in candidates] == [
        "artifacts/hypothesis-table.csv",
        "artifacts/spectrum-plot.png",
        "artifacts/analysis-report.md",
        "artifacts/evidence-ledger.json",
    ]
    # The declared resolution is a literal, not a value copied from the module
    # under test, so renaming the constant there fails this test.
    assert plan["selection_resolution"] == "explicit_version_ids_never_latest"
    assert plan["execution_isolation"] == "in_process"
    assert plan["always_included_documents"] == [
        "manifest.json",
        "checksums.sha256",
        "provenance.json",
        "action-plan.json",
        "review.json",
    ]
    assert plan["conditional_documents"] == [
        "run-record.json",
        "research-intent.json",
        "scientific-input.json",
        "environment.json",
    ]


@pytest.mark.parametrize(
    ("recorded", "expected"),
    [("container_rootless", "container_rootless"), (None, None)],
)
def test_the_plan_reports_the_recorded_isolation_and_never_a_default(
    exportable: tuple[Harness, str, str],
    recorded: str | None,
    expected: str | None,
) -> None:
    # SPEC-v0.5 section 5 forbids presenting an isolation level that was not
    # recorded. The seeded chain records `in_process`, which is also the value
    # a defaulting implementation would invent, so the recorded value is moved
    # out from under the route: to a level this product never writes, and then
    # away entirely. Both answers have to follow the column.
    harness, project_id, run_id = exportable
    assert _plan(harness, project_id, run_id)["execution_isolation"] == "in_process"
    database = resolve_paths(harness.root).database
    connection = sqlite3.connect(database)
    try:
        if recorded is None:
            _ = connection.execute("DELETE FROM executions WHERE run_id = ?", (run_id,))
        else:
            _ = connection.execute(
                "UPDATE executions SET execution_isolation = ? WHERE run_id = ?",
                (recorded, run_id),
            )
        connection.commit()
    finally:
        connection.close()

    plan = _plan(harness, project_id, run_id)

    assert plan["execution_isolation"] == expected
    # The candidates are unaffected: isolation is a disclosure about the
    # execution, not a condition on what may be exported.
    assert len(as_list(plan["candidates"])) == 4


def test_a_newer_version_never_appears_in_the_plan_or_replaces_the_pinned_one(
    exportable: tuple[Harness, str, str],
) -> None:
    # This is the race SPEC-v0.5 section 9 exists to prevent, reproduced: a new
    # Version of an already-exported Artifact is committed between publication
    # and export. The plan must keep offering the Version the Run recorded, and
    # a pack built from it must carry that Version's bytes.
    harness, project_id, run_id = exportable
    plan = _plan(harness, project_id, run_id)
    csv = as_dict(as_list(plan["candidates"])[0])
    pinned = str(csv["artifact_version_id"])
    pinned_digest = str(csv["content_sha256"])

    scope = harness.scope(project_id)
    superseding = b"wavelength_nm,intensity\n999.0,9.99\n"
    newer_digest = hashlib.sha256(superseding).hexdigest()
    newer = ArtifactVersion(
        id=harness.ids.new_uuid7(),
        org_id=scope.org_id,
        project_id=scope.project_id,
        artifact_id=UUID(str(csv["artifact_id"])),
        version_no=2,
        object_key=LocalArtifactStore.object_key(scope, newer_digest),
        content_sha256=newer_digest,
        size_bytes=len(superseding),
        media_type="text/csv",
        # A second real Run supersedes the Artifact, which is exactly the race
        # this test reproduces. An invented execution would be refused at
        # commit and the race would never be set up at all.
        producing_execution_id=harness.seed_execution(project_id),
        environment_sha256=ZERO_DIGEST,
        code_sha256=ONE_DIGEST,
        runtime_adapter_id="local_deterministic",
        runtime_connection_id=UUID("01900000-0000-7000-8000-000000000004"),
        skill_content_hashes=(),
        source_hashes=(),
        input_version_ids=(),
        created_at=datetime.now(UTC),
    )
    assert str(harness.store.commit_version(scope, 1, newer, superseding)) == "created"

    after = _plan(harness, project_id, run_id)
    offered = _pinned_ids(after)
    assert pinned in offered
    assert str(newer.id) not in offered

    reply = _produce(harness, project_id, run_id, [pinned])
    assert reply.status == 201
    pack = reply.payload()
    assert pack["selection"] == [pinned]

    archive = _pack_path(harness, project_id, str(pack["pack_id"])).read_bytes()
    manifest = _verify_archive(archive)
    with zipfile.ZipFile(io.BytesIO(archive)) as opened:
        exported = opened.read("artifacts/hypothesis-table.csv")
    assert hashlib.sha256(exported).hexdigest() == pinned_digest
    assert hashlib.sha256(exported).hexdigest() != newer_digest
    assert exported != superseding
    assert as_dict(manifest["selection"])["artifact_version_ids"] == [pinned]


def test_a_pack_is_not_read_through_a_substituted_directory(
    exportable: tuple[Harness, str, str],
    tmp_path: Path,
) -> None:
    # The pack file itself is already refused when it is a link. This is the
    # other half: the directory it sits in is swapped for a link to somewhere
    # else, so every path component still looks ordinary and only a comparison
    # that stops resolving at the exports root notices.
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])
    grant = _mint(harness, project_id, pack_id)

    owned = tmp_path / "root" / EXPORTS_DIRECTORY_NAME / project_id
    elsewhere = tmp_path / "root" / "somewhere-else"
    _ = owned.rename(elsewhere)
    owned.symlink_to(elsewhere, target_is_directory=True)

    download = harness.send(Call(path=str(grant["url"]), omit_token=True))
    minting = harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/exports/{pack_id}/download",
    )

    assert download.status == 404
    assert download.payload() == {"error": "export_pack_not_found"}
    assert minting.status == 404
    assert minting.payload() == {"error": "export_pack_not_found"}


def test_the_export_directory_and_its_packs_are_owner_only(
    exportable: tuple[Harness, str, str],
) -> None:
    # The data root holds research inputs and sealed credentials, and a pack is
    # a bundle of pinned evidence. Neither the directory nor the file may be
    # readable by another account on this machine.
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])

    directory = harness.root / EXPORTS_DIRECTORY_NAME / project_id

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert (
        stat.S_IMODE(_pack_path(harness, project_id, pack_id).stat().st_mode) == 0o600
    )


def test_every_capability_is_fresh_and_carries_real_entropy(
    exportable: tuple[Harness, str, str],
) -> None:
    # A capability travels in a URL, so guessing one is the attack. 43 URL-safe
    # characters is 256 bits; the assertion is on the length rather than on the
    # constant that produced it, so shortening the secret fails here.
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])

    secrets_seen = [
        str(_mint(harness, project_id, pack_id)["url"]).rsplit("/", maxsplit=1)[-1]
        for _ in range(8)
    ]

    assert len(set(secrets_seen)) == 8
    for value in secrets_seen:
        assert len(value) >= 43, value
        assert set(value) <= set(
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        )
        assert harness.token not in value


def test_an_artifact_identifier_is_refused_rather_than_resolved_to_a_version(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable
    plan = _plan(harness, project_id, run_id)
    artifact_id = str(as_dict(as_list(plan["candidates"])[0])["artifact_id"])

    reply = _produce(harness, project_id, run_id, [artifact_id])

    assert reply.status == 400
    assert reply.payload() == {
        "error": "export_selection_rejected",
        "reason": "selection_not_pinned_to_run",
    }
    assert not (harness.root / EXPORTS_DIRECTORY_NAME).exists()


@pytest.mark.parametrize(
    ("body", "expected"),
    [
        ({}, {"error": "invalid_request"}),
        ({"artifact_version_ids": "all"}, {"error": "invalid_request"}),
        ({"all": True}, {"error": "invalid_request"}),
        (
            {"artifact_version_ids": []},
            {"error": "export_selection_rejected", "reason": "selection_empty"},
        ),
    ],
)
def test_an_export_that_does_not_pin_versions_is_refused(
    exportable: tuple[Harness, str, str],
    body: dict[str, object],
    expected: dict[str, str],
) -> None:
    # None of these widens to "every output" or to "the latest". A request that
    # does not say which Versions travel does not produce a pack at all.
    harness, project_id, run_id = exportable

    reply = harness.same_origin(
        "POST",
        f"{PROJECTS}/{project_id}/runs/{run_id}/export",
        body,
    )

    assert reply.status == 400
    assert reply.payload() == expected
    assert not (harness.root / EXPORTS_DIRECTORY_NAME).exists()


def test_a_repeated_version_is_refused_rather_than_collapsed(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))[0]

    reply = _produce(harness, project_id, run_id, [pinned, pinned])

    assert reply.status == 400
    assert reply.payload() == {
        "error": "export_selection_rejected",
        "reason": "selection_duplicate",
    }


def test_a_version_this_run_did_not_publish_is_refused(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable
    _, foreign = harness.seed_artifact(project_id, "outsider", [b"not from this run"])

    reply = _produce(harness, project_id, run_id, foreign)

    assert reply.status == 400
    assert reply.payload() == {
        "error": "export_selection_rejected",
        "reason": "selection_not_pinned_to_run",
    }


def test_product_export_pack_contains_required_members_via_http(
    exportable: tuple[Harness, str, str],
) -> None:
    """AC-L12 over the product path: produce, download, and check every member.

    The pack must carry the selected CSV, PNG, Markdown, and ledger plus the
    manifest, checksums, provenance, ActionPlan, pinned ResearchIntent, and
    Review status — observed through HTTP produce and a ticket download, not
    through the exporting modules.
    """
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack = _produce(harness, project_id, run_id, pinned).payload()
    pack_id = str(pack["pack_id"])
    url = str(_mint(harness, project_id, pack_id)["url"])

    downloaded = harness.send(Call(path=url, omit_token=True))

    assert downloaded.status == 200
    manifest = _verify_archive(downloaded.body)
    with zipfile.ZipFile(io.BytesIO(downloaded.body)) as opened:
        names = sorted(opened.namelist())
    assert names == [
        "action-plan.json",
        "artifacts/analysis-report.md",
        "artifacts/evidence-ledger.json",
        "artifacts/hypothesis-table.csv",
        "artifacts/spectrum-plot.png",
        "checksums.sha256",
        "environment.json",
        "manifest.json",
        "provenance.json",
        "research-intent.json",
        "review.json",
        "run-record.json",
        "scientific-input.json",
    ]
    assert "research_intent_sha256" in manifest
    assert as_dict(manifest["disclosures"])["execution_isolation"] == "in_process"


def test_a_pack_verifies_from_its_own_bytes_and_carries_no_credential(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))

    reply = _produce(harness, project_id, run_id, pinned)

    assert reply.status == 201
    pack = reply.payload()
    path = _pack_path(harness, project_id, str(pack["pack_id"]))
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    archive = path.read_bytes()
    manifest = _verify_archive(archive)
    assert as_dict(manifest["selection"])["artifact_version_ids"] == sorted(pinned)
    assert as_dict(manifest["disclosures"])["execution_isolation"] == "in_process"
    assert as_dict(manifest["disclosures"])["execution_isolation_is_a_sandbox"] is False
    # No credential of any kind reaches a pack. The session token is the one
    # secret this listener holds in memory, so it is the sharpest probe.
    assert harness.token.encode("utf-8") not in archive


def test_an_unsorted_selection_produces_the_canonical_sorted_manifest(
    exportable: tuple[Harness, str, str],
) -> None:
    # Ordering a set of checkboxes is a rendering decision, so the route sorts.
    # Membership is not normalized, and the pack records the canonical order it
    # documents, so a verifier's step 5 still passes.
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))

    reply = _produce(harness, project_id, run_id, list(reversed(pinned)))

    assert reply.status == 201
    pack = reply.payload()
    assert pack["selection"] == sorted(pinned)
    manifest = _verify_archive(
        _pack_path(harness, project_id, str(pack["pack_id"])).read_bytes()
    )
    assert as_dict(manifest["selection"])["artifact_version_ids"] == sorted(pinned)
    assert as_dict(manifest["selection"])["resolution"] == (
        "explicit_version_ids_never_latest"
    )


def test_the_response_quotes_the_packs_own_manifest_rather_than_rebuilding_it(
    exportable: tuple[Harness, str, str],
) -> None:
    # A screen renders the disclosures this response carries, so they have to
    # be the pack's own words. Byte equality with the manifest is the only
    # assertion that proves the API did not compose its own summary.
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))

    pack = _produce(harness, project_id, run_id, pinned).payload()

    manifest = _verify_archive(
        _pack_path(harness, project_id, str(pack["pack_id"])).read_bytes()
    )
    assert pack["disclosures"] == manifest["disclosures"]
    assert pack["verification"] == manifest["verification"]
    # The entry list is a projection of the manifest's, not a rebuild of it:
    # every field this surface reports has to be the manifest's own value.
    assert [
        {
            "kind": item["kind"],
            "path": item["path"],
            "sha256": item["sha256"],
            "size_bytes": item["size_bytes"],
        }
        for item in [as_dict(row) for row in as_list(manifest["entries"])]
    ] == [as_dict(row) for row in as_list(pack["entries"])]
    # The store now records the canonical `ResearchIntent` and scientific-input
    # bytes against the producing execution and re-verifies them against the
    # pinned digest on the way out, so both digests are recomputable from the
    # pack and both documents travel. `code_sha256` stays self-reported: it is
    # taken over source files, which are not artifacts and are never exported.
    absent = as_dict(as_dict(manifest["verification"])["not_recomputable_from_pack"])
    assert "code_sha256" in absent
    assert "research_intent_sha256" not in absent
    assert "input_sha256" not in absent
    present = as_dict(as_dict(manifest["verification"])["recomputable_from_pack"])
    assert "code_sha256" not in present
    assert "research_intent_sha256" in present
    assert "input_sha256" in present
    documents = {
        str(item["path"]): item["included"]
        for item in [as_dict(row) for row in as_list(pack["pack_documents"])]
    }
    assert documents["manifest.json"] is True
    assert documents["checksums.sha256"] is True
    assert documents["research-intent.json"] is True
    assert documents["scientific-input.json"] is True


def test_an_export_of_a_run_that_does_not_exist_is_not_found(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, _ = exportable
    missing = "019f0000-0000-7000-8000-00000000dead"

    plan = harness.send(Call(path=f"{PROJECTS}/{project_id}/runs/{missing}/export"))
    produced = _produce(harness, project_id, missing, [missing])

    assert plan.status == 404
    assert plan.error() == "not_found"
    assert produced.status == 404
    assert produced.error() == "not_found"


def test_the_export_routes_require_the_session_credential(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])

    refusals = [
        Call(path=f"{PROJECTS}/{project_id}/runs/{run_id}/export", omit_token=True),
        Call(
            method="POST",
            path=f"{PROJECTS}/{project_id}/runs/{run_id}/export",
            body={"artifact_version_ids": pinned},
            omit_token=True,
        ),
        Call(
            method="POST",
            path=f"{PROJECTS}/{project_id}/exports/{pack_id}/download",
            omit_token=True,
        ),
    ]

    for call in refusals:
        reply = harness.send(call)
        assert reply.status == 401, call.path
        assert reply.error() == "local_token_required", call.path


def test_a_capability_downloads_the_pack_bytes_exactly_once(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack = _produce(harness, project_id, run_id, pinned).payload()
    pack_id = str(pack["pack_id"])
    grant = _mint(harness, project_id, pack_id)
    assert grant["single_use"] is True
    assert grant["expires_in_seconds"] == 60
    url = str(grant["url"])
    assert f"/exports/{pack_id}/content/" in url
    # The capability is not the session credential and shares nothing with it.
    assert harness.token not in url

    # No token header: a browser cannot attach one to a download navigation,
    # which is the entire reason this capability exists.
    first = harness.send(Call(path=url, omit_token=True))
    second = harness.send(Call(path=url, omit_token=True))

    assert first.status == 200
    assert first.headers["content-type"] == "application/zip"
    assert first.headers["content-disposition"] == (
        f'attachment; filename="nipo-export-{pack_id}.zip"'
    )
    assert first.headers["referrer-policy"] == "no-referrer"
    assert "accept-ranges" not in first.headers
    # The body is the pack, not an empty 200. A streaming response whose body
    # is cancelled produces exactly that, and it is the defect this asserts
    # against rather than assumes away.
    on_disk = _pack_path(harness, project_id, pack_id).read_bytes()
    assert first.body == on_disk
    assert first.headers["content-length"] == str(len(on_disk))
    assert len(first.body) == int(str(pack["size_bytes"]))
    _ = _verify_archive(first.body)

    assert second.status == 401
    assert second.payload() == {"error": "download_ticket_spent"}


def test_a_capability_expires_and_stops_working(
    exportable_at: tuple[Harness, str, str, _MovableClock],
) -> None:
    harness, project_id, run_id, clock = exportable_at
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])
    url = str(_mint(harness, project_id, pack_id)["url"])

    clock.advance(59)
    inside = harness.send(
        Call(path=str(_mint(harness, project_id, pack_id)["url"]), omit_token=True)
    )
    clock.advance(1)
    outside = harness.send(Call(path=url, omit_token=True))

    assert inside.status == 200
    assert outside.status == 401
    assert outside.payload() == {"error": "download_ticket_expired"}


def test_a_capability_opens_only_the_pack_it_was_minted_for(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    first = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])
    second = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])
    url = str(_mint(harness, project_id, first)["url"])

    at_the_other_pack = url.replace(f"/exports/{first}/", f"/exports/{second}/")
    elsewhere = harness.send(Call(path=at_the_other_pack, omit_token=True))
    still_good = harness.send(Call(path=url, omit_token=True))

    assert elsewhere.status == 401
    assert elsewhere.payload() == {"error": "download_ticket_invalid"}
    # Presenting it at the wrong pack must not spend it either.
    assert still_good.status == 200
    assert still_good.body == _pack_path(harness, project_id, first).read_bytes()


def test_the_session_credential_does_not_substitute_for_a_capability(
    exportable: tuple[Harness, str, str],
) -> None:
    # The guard is the only authority on who may read a pack. A request that
    # carries a perfectly good session credential but no accepted capability
    # reaches the route with nothing, and the route serves nothing.
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])

    reply = harness.same_origin(
        "GET",
        f"{PROJECTS}/{project_id}/exports/{pack_id}/content/not-a-real-capability",
    )

    assert reply.status == 401
    assert reply.payload() == {"error": "download_ticket_invalid"}


def test_a_capability_is_screened_more_strictly_than_the_credential_path(
    exportable: tuple[Harness, str, str],
) -> None:
    # A `GET` is not state-changing, so the ordinary credential path lets a
    # cross-site fetch metadata value through and refuses on the credential. A
    # capability travels in a URL a page on another site could navigate this
    # browser to, so it gets the document surface's stricter rule instead:
    # `Sec-Fetch-Site` is enforced for every method.
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])
    url = str(_mint(harness, project_id, pack_id)["url"])

    cross_site = harness.send(Call(path=url, omit_token=True, site="cross-site"))
    rebound = harness.send(Call(path=url, omit_token=True, host="attacker.example"))
    foreign_origin = harness.send(
        Call(path=url, omit_token=True, origin="https://evil.example")
    )
    ordinary = harness.send(Call(path=HEALTH, site="cross-site"))

    assert cross_site.status == 403
    assert cross_site.payload() == {"error": "cross_origin_denied"}
    assert rebound.status == 403
    assert rebound.payload() == {"error": "host_not_allowed"}
    assert foreign_origin.status == 403
    assert foreign_origin.payload() == {"error": "cross_origin_denied"}
    # The looser rule still applies everywhere else, unchanged.
    assert ordinary.status == 200
    # A refused capability is not spent by the refusal.
    assert harness.send(Call(path=url, omit_token=True)).status == 200


def test_a_refused_capability_never_reaches_the_pack_file(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])

    traversal = harness.send(
        Call(
            path=f"{PROJECTS}/{project_id}/exports/{pack_id}/content/..%2f..%2fapi-token.json",
            omit_token=True,
        )
    )
    missing_pack = harness.send(
        Call(
            method="POST",
            path=f"{PROJECTS}/{project_id}/exports/019f0000-0000-7000-8000-00000000feed/download",
            body=None,
            origin=f"http://127.0.0.1:{harness.port}",
            site="same-origin",
        )
    )

    assert traversal.status == 401
    assert traversal.payload() == {"error": "local_token_required"}
    assert missing_pack.status == 404
    assert missing_pack.payload() == {"error": "export_pack_not_found"}


def test_the_capability_table_stays_bounded(
    exportable: tuple[Harness, str, str],
) -> None:
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])

    minted = [str(_mint(harness, project_id, pack_id)["url"]) for _ in range(70)]

    # The bound is 64. Minting past it drops the oldest capability, which costs
    # the caller its own stale URL and nothing else: the newest still works.
    assert harness.send(Call(path=minted[0], omit_token=True)).status == 401
    assert harness.send(Call(path=minted[-1], omit_token=True)).status == 200


def test_binding_capabilities_does_not_widen_the_credential_exemption(
    exportable: tuple[Harness, str, str],
    tmp_path: Path,
) -> None:
    # The exempt set is the static surface's own enumeration and nothing else.
    # A download path is not exempt from the credential check: it presents a
    # credential of its own. Both halves are asserted -- the set an application
    # built with capabilities bound actually exempts, and the behaviour of a
    # path that sits right next to a capability URL.
    harness, project_id, run_id = exportable
    pinned = _pinned_ids(_plan(harness, project_id, run_id))
    pack_id = str(_produce(harness, project_id, run_id, pinned).payload()["pack_id"])
    url = str(_mint(harness, project_id, pack_id)["url"])

    paths = resolve_paths(tmp_path / "other")
    paths.ensure()
    store = LocalArtifactStore(paths)
    read_model = LocalReadModel(paths)
    registry = ProviderRegistry(paths, InMemoryCredentialBackend(), {})
    surface = StaticSurface()
    try:
        app = create_app(
            default_deps(store, registry, read_model, paths, None),
            LocalToken("value"),
            origins=frozenset(),
            authorities=frozenset(),
            web=surface,
        )
        assert isinstance(app, LocalGuard)
        assert app.documents == surface.paths
        assert app.documents == frozenset(
            {"/", "/index.html", "/app.js", "/styles.css", "/favicon.svg"}
        )
        assert not any(item.startswith("/api") for item in app.documents)
        assert url not in app.documents
    finally:
        store.close()
        read_model.close()

    # The path a capability URL is one segment away from carries no capability,
    # so nothing became credential-free by proximity.
    neighbour = url.rsplit("/", maxsplit=1)[0]
    assert harness.send(Call(path=neighbour, omit_token=True)).status == 401
    # With the credential it is simply a path this listener does not serve.
    # There is no route without a capability segment, so there is nothing a
    # caller could reach by dropping one.
    with_credential = harness.send(Call(path=neighbour))
    assert with_credential.status == 404
    assert with_credential.payload() == {"error": "not_found"}
