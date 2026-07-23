"""Fail-closed tests for the Codex live qualification capture harness."""

from __future__ import annotations

import json
import os
import platform
import runpy
import secrets
import shlex
import stat
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass, replace
from datetime import UTC, datetime, timedelta
from hashlib import sha256
from http.client import HTTPConnection
from inspect import signature
from pathlib import Path
from threading import Thread
from typing import TYPE_CHECKING, cast, override

import anyio
import pytest
import services.api.provider_live_capture as live_capture
import services.api.provider_run_dispatch_service as dispatch_service
from services.api.persistence.auth_sessions import PostgresSessionAuthority
from services.api.product_app import ProductServer, ProductServerOptions
from services.api.product_artifacts import ProductArtifactService
from services.api.product_dry_lab import ProductDryLabService
from services.api.product_tenancy import PostgresTenantRepository
from services.api.provider_database_role import dedicated_provider_login_is_confined
from services.api.provider_live_capture import (
    CaptureCase,
    CaptureError,
    CodexBinaryPolicy,
    CodexCliInvocation,
    InvocationResult,
    QualificationAdoptionSnapshot,
    QualificationCaptureAuthority,
    RuntimeQualificationTarget,
    adopt_live_qualification,
    capture_and_record_runtime_qualification,
    capture_live_qualification,
    capture_profile,
    load_approved_runtime_policy,
    load_cases,
)
from services.api.provider_model_id import PROVIDER_MODEL_ID_MAX_CHARACTERS
from services.api.provider_postgres import (
    PostgresProviderPersistence,
    RuntimeHomeDestroyer,
)
from services.api.provider_qualification import (
    QualificationResult,
    evaluate_profile,
    parse_profile_json,
    qualification_claim,
)
from services.api.provider_qualification_adopter import (
    QualificationAdopterServerConfig,
    UnixSocketQualificationWriter,
    build_qualification_adopter_server,
)
from services.api.provider_qualification_authority import (
    QualificationAuthorityClientConfig,
    UnixSocketQualificationIssuer,
    load_qualification_verifier,
)
from services.api.provider_qualification_authority_server import (
    build_qualification_authority_server,
)
from services.api.provider_qualification_receipt import (
    QualificationReceiptAdmissionPolicy,
    QualificationReceiptClaim,
    QualificationReceiptSubject,
)
from services.api.provider_qualification_writer import (
    PostgresQualificationWriter,
    QualificationWriter,
)
from services.api.provider_run_dispatch import (
    ProviderRunDispatchRequest,
)
from services.api.provider_run_dispatch_service import (
    ProviderRunDispatchServerConfig,
    UnixSocketProviderRunDispatcher,
    build_provider_run_dispatch_server,
)
from services.api.provider_runtime import (
    PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    ConnectionNotFoundError,
    DispatchAuthorization,
    OfficialOAuthCompletion,
    ProviderCleanupPolicy,
    ProviderConnection,
    ProviderPrincipal,
    ProviderRuntimeError,
    ProviderRuntimeIdentity,
    ProviderRuntimeService,
)
from services.api.provider_uds import ProviderUdsClientConfig, SecureProviderUnixServer
from services.api.tests.persistence.postgres_harness import (
    database_url_asyncpg,
    psql,
)
from services.api.tests.persistence.test_rls import (
    ORG_A,
    PROJECT_A,
    USER_A,
    USER_C,
    seed_tenants,
)
from sqlalchemy import text
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from .provider_qualification_support import (
    TestQualificationAuthority,
    qualification_private_key_document,
    qualification_public_key_document,
)

if TYPE_CHECKING:
    from collections.abc import Generator, Iterator, Sequence

_FIXTURE = Path(__file__).parent / "fixtures" / "golden_session_cases.json"
_QUALIFICATION_LOGIN = "science_workbench_qualification_test"
_QUALIFICATION_CREDENTIAL = "qualification-test-only"
_DISPATCH_LOGIN = "science_workbench_dispatcher_test"
_DISPATCH_CREDENTIAL = "dispatcher-test-only"
_BROWSER_SESSION_ID = "018f0d7d-6b17-7a91-8b31-2f7331677ac3"
_BROWSER_SESSION_TOKEN = secrets.token_urlsafe(32)
_BROWSER_CSRF_TOKEN = secrets.token_urlsafe(32)
pytest_plugins = ("services.api.tests.persistence.conftest",)


class _QualificationDestroyer(RuntimeHomeDestroyer):
    @override
    def destroy(self, opaque_ref: str) -> str:
        del self, opaque_ref
        return "a" * 64


def _qualification_clock() -> datetime:
    return datetime(2026, 7, 15, tzinfo=UTC)


def _qualification_database_url() -> str:
    _ = psql(
        "DO $$ BEGIN CREATE ROLE science_workbench_qualification_test LOGIN "
        "NOINHERIT PASSWORD 'qualification-test-only'; EXCEPTION WHEN "
        "duplicate_object THEN NULL; END $$; ALTER ROLE "
        "science_workbench_qualification_test WITH "
        "LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
        "NOBYPASSRLS; GRANT science_workbench_qualification TO "
        "science_workbench_qualification_test WITH ADMIN FALSE, INHERIT FALSE, "
        "SET TRUE"
    )
    boundary = psql(
        "SELECT rolcanlogin::text || ':' || rolinherit::text || ':' || "
        "rolsuper::text || ':' || rolbypassrls::text || ':' || "
        "pg_has_role(rolname, 'science_workbench_qualification', "
        "'MEMBER')::text FROM pg_roles WHERE rolname = "
        "'science_workbench_qualification_test'"
    ).stdout.strip()
    if boundary != "true:false:false:false:true":
        raise AssertionError(boundary)
    return make_url(database_url_asyncpg()).set(
        username=_QUALIFICATION_LOGIN,
        password=_QUALIFICATION_CREDENTIAL,
    ).render_as_string(hide_password=False)


def _dispatch_database_url() -> str:
    _ = psql(
        "DO $$ BEGIN CREATE ROLE science_workbench_dispatcher_test LOGIN "
        "NOINHERIT PASSWORD 'dispatcher-test-only'; EXCEPTION WHEN "
        "duplicate_object THEN NULL; END $$; ALTER ROLE "
        "science_workbench_dispatcher_test WITH LOGIN "
        "NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION "
        "NOBYPASSRLS; GRANT science_workbench_dispatcher TO "
        "science_workbench_dispatcher_test WITH ADMIN FALSE, INHERIT FALSE, SET "
        "TRUE"
    )
    return make_url(database_url_asyncpg()).set(
        username=_DISPATCH_LOGIN,
        password=_DISPATCH_CREDENTIAL,
    ).render_as_string(hide_password=False)


def _qualification_login_is_confined(database_url: str) -> bool:
    async def check() -> bool:
        engine = create_async_engine(database_url, poolclass=NullPool)
        try:
            async with engine.begin() as database:
                return await dedicated_provider_login_is_confined(
                    database,
                    expected_login_role=_QUALIFICATION_LOGIN,
                    capability_role="science_workbench_qualification",
                )
        finally:
            await engine.dispose()

    return anyio.run(check)


def _dispatch_login_is_confined(database_url: str) -> bool:
    async def check() -> bool:
        engine = create_async_engine(database_url, poolclass=NullPool)
        try:
            async with engine.begin() as database:
                return await dedicated_provider_login_is_confined(
                    database,
                    expected_login_role=_DISPATCH_LOGIN,
                    capability_role="science_workbench_dispatcher",
                )
        finally:
            await engine.dispose()

    return anyio.run(check)


def _qualification_login_resets_search_path(database_url: str) -> tuple[bool, str]:
    async def check() -> tuple[bool, str]:
        engine = create_async_engine(database_url, poolclass=NullPool)
        try:
            async with engine.begin() as database:
                _ = await database.execute(
                    text("SET LOCAL search_path = pg_temp, public, pg_catalog")
                )
                confined = await dedicated_provider_login_is_confined(
                    database,
                    expected_login_role=_QUALIFICATION_LOGIN,
                    capability_role="science_workbench_qualification",
                )
                observed = await database.execute(
                    text("SELECT current_setting('search_path')")
                )
                return confined, cast("str", observed.scalar_one())
        finally:
            await engine.dispose()

    return anyio.run(check)


def _authority_public_key_file(
    directory: Path,
    *,
    key_ids: tuple[str, ...] | None = None,
) -> tuple[Path, str]:
    source = (
        qualification_public_key_document()
        if key_ids is None
        else qualification_public_key_document(key_ids=key_ids)
    )
    path = directory / "authority-public-keys.json"
    _ = path.write_bytes(source)
    path.chmod(0o600)
    return path, sha256(source).hexdigest()


@contextmanager
def _short_provider_socket(name: str) -> Generator[Path]:
    with tempfile.TemporaryDirectory(prefix="swbp-") as directory:
        root = Path(directory).resolve()
        root.chmod(0o700)
        yield root / name


@contextmanager
def _running_provider_server(
    server: SecureProviderUnixServer,
) -> Generator[None]:
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield
    finally:
        server.shutdown()
        thread.join(timeout=5)
        server.server_close()


def _capture_authority(
    subject: QualificationReceiptSubject | None = None,
) -> tuple[TestQualificationAuthority, QualificationCaptureAuthority]:
    authority = TestQualificationAuthority(_qualification_clock())
    resolved = subject or QualificationReceiptSubject(
        ORG_A,
        USER_A,
        "018f0d7d-6b17-7a91-8b31-2f7331677daa",
        2,
    )
    return authority, authority.capture_authority(resolved)


@dataclass(frozen=True, slots=True)
class _RuntimeQualificationSetup:
    runtime: ProviderRuntimeService
    principal: ProviderPrincipal
    connection: ProviderConnection
    policy: CodexBinaryPolicy
    capture_path: Path
    invocation: FakeInvocation


def _assert_owner_credential_cannot_adopt(
    external: TestQualificationAuthority,
    principal: ProviderPrincipal,
    connection: ProviderConnection,
    expected_revision: int,
) -> None:
    qualification = connection.qualification
    assert qualification is not None
    with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
        PostgresQualificationWriter(
            database_url_asyncpg(),
            QualificationReceiptAdmissionPolicy(
                external.verifier,
                external.verifier.keys[0].key_id,
            ),
            expected_login_role=_QUALIFICATION_LOGIN,
        ).adopt(
            principal,
            connection,
            "vault://runtime/connection/qualification",
            qualification.receipt,
            expected_revision=expected_revision,
        )
    assert psql(
        "SELECT count(*) FROM provider_qualification_receipts"
    ).stdout.strip() == "1"


@dataclass(frozen=True, slots=True)
class _QualificationHistorySetup:
    capture_path: Path
    runtime: ProviderRuntimeService
    principal: ProviderPrincipal
    connection: ProviderConnection
    healthy: ProviderConnection
    authority: TestQualificationAuthority
    policy: ProviderCleanupPolicy


@dataclass(frozen=True, slots=True)
class _ProviderHttpRequest:
    method: str
    path: str
    cookies: str
    body: dict[str, object] | None = None
    csrf: str | None = None


def _provider_http_request(
    server: ProductServer,
    request: _ProviderHttpRequest,
) -> tuple[int, bytes]:
    encoded = None if request.body is None else json.dumps(request.body).encode()
    headers = {
        "Host": server.public_authority,
        "Cookie": request.cookies,
    }
    if encoded is not None:
        headers |= {
            "Content-Type": "application/json",
            "Origin": server.public_origin,
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "X-CSRF-Token": request.csrf or "",
        }
    connection = HTTPConnection("127.0.0.1", server.server_port, timeout=5)
    try:
        connection.request(
            request.method,
            request.path,
            body=encoded,
            headers=headers,
        )
        response = connection.getresponse()
        return response.status, response.read()
    finally:
        connection.close()


def _provider_http_server(socket_path: Path, port: int = 0) -> ProductServer:
    database_url = database_url_asyncpg()
    return ProductServer(
        ("127.0.0.1", port),
        _qualification_clock,
        ProductServerOptions(
            session_authority=PostgresSessionAuthority(database_url),
            repository=PostgresTenantRepository(database_url),
            dry_lab=ProductDryLabService(ProductArtifactService),
            provider_run_dispatcher=UnixSocketProviderRunDispatcher(
                ProviderUdsClientConfig(socket_path)
            ),
        ),
    )


def _start_product_server(server: ProductServer) -> Thread:
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return thread


def _stop_product_server(server: ProductServer, thread: Thread) -> None:
    server.shutdown()
    thread.join(timeout=5)
    server.server_close()
    assert not thread.is_alive()


def _seed_provider_browser_session() -> None:
    token_hash = sha256(_BROWSER_SESSION_TOKEN.encode()).hexdigest()
    csrf_hash = sha256(_BROWSER_CSRF_TOKEN.encode()).hexdigest()
    _ = psql(
        "INSERT INTO auth_sessions (id, org_id, user_id, token_hash, csrf_hash, "  # noqa: S608
        "idle_expires_at, absolute_expires_at) VALUES "
        f"('{_BROWSER_SESSION_ID}', '{ORG_A}', '{USER_A}', "
        f"decode('{token_hash}', 'hex'), decode('{csrf_hash}', 'hex'), "
        "CURRENT_TIMESTAMP + INTERVAL '1 hour', "
        "CURRENT_TIMESTAMP + INTERVAL '2 hours') ON CONFLICT DO NOTHING"
    )


def _assert_provider_http_dispatch_survives_restart(
    setup: _QualificationHistorySetup,
    dispatch_socket: Path,
    history_session: str,
) -> None:
    _seed_provider_browser_session()
    cookies = (
        f"product_session={_BROWSER_SESSION_TOKEN}; "
        f"product_csrf={_BROWSER_CSRF_TOKEN}"
    )
    first = _provider_http_server(dispatch_socket)
    first_thread = _start_product_server(first)
    port = first.server_port
    try:
        initial = _provider_http_request(
            first,
            _ProviderHttpRequest("GET", "/api/v1/me", cookies),
        )
    finally:
        _stop_product_server(first, first_thread)
    second = _provider_http_server(dispatch_socket, port)
    second_thread = _start_product_server(second)
    try:
        reloaded = _provider_http_request(
            second,
            _ProviderHttpRequest("GET", "/api/v1/me", cookies),
        )
        csrf = cast("str", json.loads(reloaded[1])["csrf_token"])
        created = _provider_http_request(
            second,
            _ProviderHttpRequest(
                "POST",
                "/api/v1/runs",
                cookies,
                {
                    "execution_mode": "provider_model",
                    "session_id": history_session,
                    "prompt": "보정 데이터의 재현성을 검증한다.",
                    "research_intent": {
                        "question": "제공자 분석을 재현할 수 있는가?",
                        "rationale": "승인된 계획만 실행한다.",
                        "intended_benefit": "검증 가능한 제공자 실행을 만든다.",
                        "success_criteria": ["계획 다이제스트가 보존된다."],
                        "constraints": ["비임상 데이터만 사용한다."],
                        "stop_conditions": ["승인이 없으면 중단한다."],
                        "research_mode": "bounded_agentic",
                        "data_origin": "observed",
                    },
                    "input": {
                        "filename": "calibrated.csv",
                        "media_type": "text/csv",
                        "content": (
                            "sample,value,calibration\na,1.0,cal-1\n"
                        ),
                    },
                    "connection_id": setup.connection.connection_id,
                    "model_id": "codex-mini",
                },
                csrf,
            ),
        )
        created_payload = cast("dict[str, object]", json.loads(created[1]))
        run_id = cast("str", created_payload["run_id"])
        approved = _provider_http_request(
            second,
            _ProviderHttpRequest(
                "POST",
                f"/api/v1/runs/{run_id}/approve",
                cookies,
                {"plan_digest": created_payload["plan_digest"]},
                csrf,
            ),
        )
        approval_payload = cast("dict[str, object]", json.loads(approved[1]))
        executed = _provider_http_request(
            second,
            _ProviderHttpRequest(
                "POST",
                f"/api/v1/runs/{run_id}/execute",
                cookies,
                {"token": approval_payload["token"]},
                csrf,
            ),
        )
    finally:
        _stop_product_server(second, second_thread)
    assert initial[0] == reloaded[0] == 200
    assert json.loads(initial[1])["csrf_token"] == csrf == _BROWSER_CSRF_TOKEN
    assert created[0] == 201
    assert approved[0] == executed[0] == 202
    assert psql(
        "SELECT count(*) FROM runs WHERE id = "  # noqa: S608
        f"'{run_id}' AND provider_connection_id IS NOT NULL AND "
        "provider_model_id = 'codex-mini'"
    ).stdout.strip() == "1"


@dataclass(frozen=True, slots=True)
class _AdopterFixture:
    authority: TestQualificationAuthority
    writer: QualificationWriter
    database_url: str


@dataclass(frozen=True, slots=True)
class _CapturedAdoptionSetup:
    result: QualificationResult
    subject: QualificationReceiptSubject
    writer: QualificationWriter
    runtime_identity: ProviderRuntimeIdentity
    snapshot: QualificationAdoptionSnapshot


def _adopt_with_rollback_proof(setup: _CapturedAdoptionSetup) -> None:
    invalid_snapshots = (
        replace(setup.snapshot, account_id="wrong-account"),
        replace(
            setup.snapshot,
            created_at=setup.snapshot.created_at + timedelta(microseconds=1),
        ),
    )
    for invalid_snapshot in invalid_snapshots:
        with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
            _ = adopt_live_qualification(
                setup.result,
                setup.subject,
                setup.writer,
                runtime_identity=setup.runtime_identity,
                snapshot=invalid_snapshot,
            )
        assert psql(
            "SELECT count(*) FROM provider_qualification_receipts"
        ).stdout.strip() == "0"
        assert psql(
            "SELECT count(*) FROM provider_connections WHERE "
            "qualification_receipt_id IS NOT NULL"
        ).stdout.strip() == "0"
    _ = adopt_live_qualification(
        setup.result,
        setup.subject,
        setup.writer,
        runtime_identity=setup.runtime_identity,
        snapshot=setup.snapshot,
    )


def _assert_unqualified_connection(connection: ProviderConnection) -> None:
    assert not connection.qualified_live
    assert connection.revision == 1


def test_capture_rejects_out_of_contract_provider_model_id() -> None:
    subject = QualificationReceiptSubject(ORG_A, USER_A, "connection", 2)
    snapshot = QualificationAdoptionSnapshot(
        runtime_home_ref="vault://runtime/connection/qualification",
        account_id="official-account",
        eligible_models=("m" * (PROVIDER_MODEL_ID_MAX_CHARACTERS + 1),),
        selected_model="m" * (PROVIDER_MODEL_ID_MAX_CHARACTERS + 1),
        health="pending",
        created_at=_qualification_clock(),
    )

    with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
        live_capture._require_valid_adoption_target(  # pyright: ignore[reportPrivateUsage]
            subject,
            snapshot,
        )


def test_dispatch_client_rejects_out_of_contract_model_before_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[bool] = []

    def unexpected_request(
        _config: ProviderUdsClientConfig,
        _request: dict[str, str],
    ) -> dict[str, str]:
        requests.append(True)
        raise AssertionError

    monkeypatch.setattr(dispatch_service, "provider_uds_request", unexpected_request)
    with _short_provider_socket("model-contract.sock") as socket_path:
        dispatcher = UnixSocketProviderRunDispatcher(
            ProviderUdsClientConfig(socket_path)
        )
        with pytest.raises(ProviderRuntimeError, match="provider_dispatch_failed"):
            _ = dispatcher.dispatch(
                ProviderPrincipal(USER_A, ORG_A),
                ProviderRunDispatchRequest(
                    "018f0d7d-6b17-7a91-8b31-2f7331677e01",
                    "018f0d7d-6b17-7a91-8b31-2f7331677c01",
                    "018f0d7d-6b17-7a91-8b31-2f7331677d10",
                    "m" * (PROVIDER_MODEL_ID_MAX_CHARACTERS + 1),
                    "1" * 64,
                    "2" * 64,
                ),
            )

    assert requests == []


def test_dispatch_client_rejects_unbound_plan_digest_before_socket(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    requests: list[bool] = []

    def unexpected_request(
        _config: ProviderUdsClientConfig,
        _request: dict[str, str],
    ) -> dict[str, str]:
        requests.append(True)
        raise AssertionError

    monkeypatch.setattr(dispatch_service, "provider_uds_request", unexpected_request)
    with _short_provider_socket("digest-contract.sock") as socket_path:
        dispatcher = UnixSocketProviderRunDispatcher(
            ProviderUdsClientConfig(socket_path)
        )
        with pytest.raises(ProviderRuntimeError, match="provider_dispatch_failed"):
            _ = dispatcher.dispatch(
                ProviderPrincipal(USER_A, ORG_A),
                ProviderRunDispatchRequest(
                    "018f0d7d-6b17-7a91-8b31-2f7331677e01",
                    "018f0d7d-6b17-7a91-8b31-2f7331677c01",
                    "018f0d7d-6b17-7a91-8b31-2f7331677d10",
                    "codex-mini",
                    "A" * 64,
                    "2" * 64,
                ),
            )

    assert requests == []


def _assert_qualified_connection(
    qualified: ProviderConnection,
    previous: ProviderConnection,
    runtime_identity: ProviderRuntimeIdentity,
) -> None:
    assert qualified.qualified_live
    assert qualified.revision == previous.revision + 1
    assert qualified.qualification is not None
    assert qualified.qualification.runtime == runtime_identity


def _confirm_runtime_adoption(
    runtime: ProviderRuntimeService,
    principal: ProviderPrincipal,
    connection: ProviderConnection,
) -> None:
    adoption = next(
        adoption
        for adoption, pending in runtime.pending_completion_adoptions(principal)
        if pending.connection_id == connection.connection_id
    )
    runtime.confirm_completion_adoption(
        principal, connection.connection_id, adoption.staging_lease_id
    )


def _assert_qualification_history_survives_refresh(
    setup: _QualificationHistorySetup,
) -> None:
    authorization = setup.runtime.dispatch_authorization(
        setup.principal,
        setup.connection.connection_id,
        "codex-mini",
    )
    assert isinstance(authorization, DispatchAuthorization)
    assert authorization.adapter_id == "openai_codex"
    history_session = "018f0d7d-6b17-7a91-8b31-2f7331677ac1"
    history_run = "018f0d7d-6b17-7a91-8b31-2f7331677ac2"
    _ = psql(
        "INSERT INTO sessions (id, org_id, project_id, title) VALUES "  # noqa: S608
        f"('{history_session}', '{ORG_A}', '{PROJECT_A}', 'Qualification history') "
        "ON CONFLICT DO NOTHING"
    )
    historical_key_id = setup.authority.verifier.keys[0].key_id
    public_keys, public_keys_sha256 = _authority_public_key_file(
        setup.capture_path,
        key_ids=(historical_key_id, "test-qualification-rsa-3072-next"),
    )
    runtime_identity = setup.policy.runtime_identity
    assert runtime_identity is not None
    with _short_provider_socket("dispatch.sock") as dispatch_socket:
        dispatch_server = build_provider_run_dispatch_server(
            ProviderRunDispatchServerConfig(
                dispatch_socket,
                _dispatch_database_url(),
                _DISPATCH_LOGIN,
                public_keys,
                public_keys_sha256,
                runtime_identity,
            )
        )
        with _running_provider_server(dispatch_server):
            _assert_provider_http_dispatch_survives_restart(
                setup,
                dispatch_socket,
                history_session,
            )
            dispatched = UnixSocketProviderRunDispatcher(
                ProviderUdsClientConfig(dispatch_socket)
            ).dispatch(
                setup.principal,
                ProviderRunDispatchRequest(
                    history_run,
                    history_session,
                    setup.connection.connection_id,
                    "codex-mini",
                    "1" * 64,
                    "2" * 64,
                ),
            )
    assert dispatched.authorization == authorization
    source = (setup.capture_path / "qualified.json").read_bytes()
    refresh_subject = QualificationReceiptSubject(
        setup.principal.org_id,
        setup.principal.user_id,
        setup.connection.connection_id,
        setup.healthy.revision + 1,
    )
    refresh_receipt = setup.authority.issue(
        qualification_claim(parse_profile_json(source), refresh_subject)
    )
    refreshed = setup.runtime.record_qualification(
        setup.principal,
        setup.connection.connection_id,
        evaluate_profile(source, refresh_receipt, setup.authority.verifier),
        expected_revision=setup.healthy.revision,
    )
    refreshed_authorization = setup.runtime.dispatch_authorization(
        setup.principal,
        setup.connection.connection_id,
        "codex-mini",
    )
    after_refresh = ProviderRuntimeService(
        _qualification_clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            _QualificationDestroyer(),
            clock=_qualification_clock,
            cleanup_window=setup.policy.runtime_home_destruction_window,
        ),
        cleanup_policy=setup.policy,
    )
    assert after_refresh.connection_detail(
        setup.principal, setup.connection.connection_id
    ) == refreshed
    assert refreshed_authorization.qualification_receipt_id != (
        authorization.qualification_receipt_id
    )
    stale_run = "018f0d7d-6b17-7a91-8b31-2f7331677ac3"
    stale_dispatch = psql(
        "INSERT INTO runs (id, org_id, session_id, requester_id, "  # noqa: S608
        "provider_connection_id, provider_model_id, status, "
        "qualification_receipt_id, "
        "qualification_receipt_sha256, qualification_connection_revision, "
        "qualification_profile_sha256, qualification_runtime_version, "
        f"qualification_executable_sha256) VALUES ('{stale_run}', '{ORG_A}', "
        f"'{history_session}', '{USER_A}', '{setup.connection.connection_id}', "
        f"'{authorization.model_id}', 'queued', "
        f"'{authorization.qualification_receipt_id}', "
        f"'{authorization.qualification_receipt_sha256}', "
        f"{authorization.qualification_connection_revision}, "
        f"'{authorization.qualification_profile_sha256}', "
        f"'{authorization.qualification_runtime_version}', "
        f"'{authorization.qualification_executable_sha256}')",
        check=False,
    )
    run_rewrite = psql(
        "UPDATE runs SET qualification_receipt_id = "  # noqa: S608
        f"'{refreshed_authorization.qualification_receipt_id}' "
        f"WHERE id = '{history_run}'",
        check=False,
    )
    receipt_rewrite = psql(
        "UPDATE provider_qualification_receipts SET authority_key_id = "  # noqa: S608
        f"'rewritten' WHERE id = '{authorization.qualification_receipt_id}'",
        check=False,
    )
    assert "run requires current provider qualification" in stale_dispatch.stderr
    assert "run qualification binding is immutable" in run_rewrite.stderr
    assert "immutable table provider_qualification_receipts" in receipt_rewrite.stderr
    historical_binding = psql(
        "SELECT qualification_receipt_id::text || '|' || "  # noqa: S608
        "qualification_receipt_sha256 || '|' || "
        "qualification_connection_revision::text || '|' || "
        "qualification_profile_sha256 || '|' || qualification_runtime_version || "
        "'|' || qualification_executable_sha256 FROM runs "
        f"WHERE id = '{history_run}'"
    ).stdout.strip()
    expected_historical_binding = "|".join(
        (
            authorization.qualification_receipt_id,
            authorization.qualification_receipt_sha256,
            str(authorization.qualification_connection_revision),
            authorization.qualification_profile_sha256,
            authorization.qualification_runtime_version,
            authorization.qualification_executable_sha256,
        )
    )
    assert historical_binding == expected_historical_binding
    assert psql(
        "SELECT count(*) FROM provider_qualification_receipts WHERE "  # noqa: S608
        f"provider_connection_id = '{setup.connection.connection_id}'"
    ).stdout.strip() == "2"
    assert psql(
        "SELECT qualification_receipt_id::text FROM provider_connections WHERE "  # noqa: S608
        f"id = '{setup.connection.connection_id}'"
    ).stdout.strip() == refreshed_authorization.qualification_receipt_id


def _binary_policy(
    executable: Path | None = None,
    *,
    expected_sha256: str | None = None,
    operator_account_ref: str = "acct_provider_test",
    owner_uid: int | None = None,
    expected_runtime_version: str = "codex-cli-0.144.1",
) -> CodexBinaryPolicy:
    path = (executable or Path(sys.executable)).resolve()
    digest = sha256(path.read_bytes()).hexdigest()
    return CodexBinaryPolicy(
        executable=path,
        expected_sha256=expected_sha256 or digest,
        operator_account_ref=operator_account_ref,
        owner_uid=path.stat().st_uid if owner_uid is None else owner_uid,
        expected_runtime_version=expected_runtime_version,
    )


def _trusted_python_wrapper(directory: Path) -> Path:
    executable = directory / "trusted-codex"
    _ = executable.write_text(
        f'#!/bin/sh\nexec {shlex.quote(sys.executable)} "$@"\n',
        encoding="utf-8",
    )
    executable.chmod(0o700)
    return executable


def _current_platform_runtime_policy(
    directory: Path,
    identity: ProviderRuntimeIdentity,
    *,
    approved_platform: tuple[str, str] | None = None,
) -> tuple[str, Path, str]:
    policy_id = "openai-codex-current-platform-test"
    platform_system, platform_machine = approved_platform or (
        platform.system(),
        platform.machine(),
    )
    source = json.dumps(
        {
            "schema_version": 1,
            "policies": [
                {
                    "policy_id": policy_id,
                    "adapter_id": identity.adapter_id,
                    "platform_system": platform_system,
                    "platform_machine": platform_machine,
                    "runtime_version": identity.runtime_version,
                    "executable_sha256": identity.executable_sha256,
                }
            ],
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    path = directory / "provider-runtime-policy.json"
    _ = path.write_bytes(source)
    path.chmod(0o600)
    return policy_id, path, sha256(source).hexdigest()


def test_live_response_schema_uses_supported_closed_object_subset() -> None:
    case = load_cases(_FIXTURE)[0]
    schema = cast(
        "dict[str, object]",
        json.loads(live_capture._response_schema(case)),  # pyright: ignore[reportPrivateUsage]
    )
    encoded = json.dumps(schema, sort_keys=True)

    assert "minProperties" not in encoded
    assert schema["additionalProperties"] is False
    properties = cast("dict[str, dict[str, object]]", schema["properties"])
    assert properties["scientific_result"]["additionalProperties"] is False
    assert properties["artifact_manifest"]["additionalProperties"] is False
    assert properties["scenario_id"]["enum"] == [case.scenario_id]
    assert properties["decision_code"]["enum"] == [case.decision_code]
    limitation_items = cast("dict[str, object]", properties["limitations"]["items"])
    assert limitation_items["enum"] == list(case.limitations)


def test_runtime_policy_approves_only_the_exact_current_platform_artifact(
    tmp_path: Path,
) -> None:
    executable = Path(sys.executable).resolve()
    identity = ProviderRuntimeIdentity(
        "openai_codex",
        "codex-cli-current-platform-test",
        sha256(executable.read_bytes()).hexdigest(),
    )
    policy_id, policy_path, policy_sha256 = _current_platform_runtime_policy(
        tmp_path,
        identity,
    )
    approved = load_approved_runtime_policy(
        policy_id,
        policy_path,
        expected_sha256=policy_sha256,
    )
    assert approved.identity == identity
    assert (approved.platform_system, approved.platform_machine) == (
        platform.system(),
        platform.machine(),
    )
    with pytest.raises(CaptureError, match="approved runtime policy is invalid"):
        _ = load_approved_runtime_policy(
            "caller-supplied-runtime",
            policy_path,
            expected_sha256=policy_sha256,
        )
    with pytest.raises(CaptureError, match="approved runtime policy is invalid"):
        _ = load_approved_runtime_policy(
            policy_id,
            policy_path,
            expected_sha256="0" * 64,
        )
    _, mismatched_path, mismatched_sha256 = _current_platform_runtime_policy(
        tmp_path,
        identity,
        approved_platform=(f"not-{platform.system()}", platform.machine()),
    )
    with pytest.raises(CaptureError, match="approved runtime policy is invalid"):
        _ = load_approved_runtime_policy(
            policy_id,
            mismatched_path,
            expected_sha256=mismatched_sha256,
        )
    _, group_writable_path, group_writable_sha256 = (
        _current_platform_runtime_policy(tmp_path, identity)
    )
    group_writable_path.chmod(0o620)
    with pytest.raises(CaptureError, match="approved runtime policy is invalid"):
        _ = load_approved_runtime_policy(
            policy_id,
            group_writable_path,
            expected_sha256=group_writable_sha256,
        )
    unapproved = _trusted_python_wrapper(tmp_path)
    with pytest.raises(CaptureError, match="binary identity changed"):
        _ = CodexBinaryPolicy(
            unapproved,
            approved.identity.executable_sha256,
            "acct_operator_metadata",
            os.getuid(),
            approved.identity.runtime_version,
        ).validate()


def test_runtime_policy_rejects_duplicate_keys_in_nested_policy(
    tmp_path: Path,
) -> None:
    policy_id = "openai-codex-duplicate-key-test"
    source = (
        '{"schema_version":1,"policies":[{'
        f'"policy_id":"{policy_id}",'
        '"adapter_id":"openai_codex",'
        f'"platform_system":{json.dumps(platform.system())},'
        f'"platform_machine":{json.dumps(platform.machine())},'
        '"runtime_version":"codex-cli-before-duplicate",'
        '"runtime_version":"codex-cli-after-duplicate",'
        f'"executable_sha256":"{"a" * 64}"'
        "}]}"
    ).encode()
    policy_path = tmp_path / "duplicate-runtime-policy.json"
    _ = policy_path.write_bytes(source)
    policy_path.chmod(0o600)

    with pytest.raises(CaptureError, match="approved runtime policy is invalid"):
        _ = load_approved_runtime_policy(
            policy_id,
            policy_path,
            expected_sha256=sha256(source).hexdigest(),
        )


def test_cases_reject_duplicate_scenario_id_before_canonical_hash(
    tmp_path: Path,
) -> None:
    source = _FIXTURE.read_text(encoding="utf-8").replace(
        '"scenario_id":"GS01"',
        '"scenario_id":"GS99","scenario_id":"GS01"',
        1,
    )
    cases_path = tmp_path / "duplicate-scenario-cases.json"
    _ = cases_path.write_text(source, encoding="utf-8")

    with pytest.raises(CaptureError, match="capture cases are invalid"):
        _ = load_cases(cases_path)


def test_qualification_writer_has_no_arbitrary_database_callback_contract() -> None:
    parameters = tuple(signature(QualificationWriter.adopt).parameters)

    assert parameters == (
        "self",
        "principal",
        "connection",
        "runtime_home_ref",
        "receipt",
        "expected_revision",
    )
    assert not hasattr(PostgresQualificationWriter, "execute")
    external = TestQualificationAuthority(_qualification_clock())
    with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
        _ = PostgresQualificationWriter(
            "postgresql+asyncpg://unused:unused@127.0.0.1/workbench",
            QualificationReceiptAdmissionPolicy(
                external.verifier,
                external.verifier.keys[0].key_id,
            ),
            expected_login_role="science_workbench_app",
        )


def test_qualification_login_rejects_transitive_and_direct_authority(
    migrated_database: None,
) -> None:
    del migrated_database
    database_url = _qualification_database_url()
    assert _qualification_login_is_confined(database_url)
    try:
        _ = psql(
            "DO $$ BEGIN CREATE ROLE provider_test_parent NOLOGIN; EXCEPTION WHEN "
            "duplicate_object THEN NULL; END $$; GRANT provider_test_parent TO "
            "science_workbench_qualification"
        )
        assert not _qualification_login_is_confined(database_url)
    finally:
        _ = psql(
            "REVOKE provider_test_parent FROM science_workbench_qualification; "
            "DROP ROLE IF EXISTS provider_test_parent"
        )
    try:
        _ = psql(
            "GRANT SELECT ON projects TO science_workbench_qualification_test"
        )
        assert not _qualification_login_is_confined(database_url)
    finally:
        _ = psql(
            "REVOKE SELECT ON projects FROM science_workbench_qualification_test"
        )
    try:
        _ = psql(
            "CREATE FUNCTION public.provider_test_surplus() RETURNS boolean "
            "LANGUAGE sql IMMUTABLE AS $$ SELECT true $$; GRANT EXECUTE ON "
            "FUNCTION public.provider_test_surplus() TO PUBLIC"
        )
        assert not _qualification_login_is_confined(database_url)
    finally:
        _ = psql("DROP FUNCTION IF EXISTS public.provider_test_surplus()")
    try:
        _ = psql(
            "CREATE ROLE provider_test_rogue LOGIN NOINHERIT; GRANT "
            "science_workbench_qualification TO provider_test_rogue"
        )
        assert not _qualification_login_is_confined(database_url)
    finally:
        _ = psql(
            "REVOKE science_workbench_qualification FROM provider_test_rogue; "
            "DROP ROLE provider_test_rogue"
        )


@pytest.mark.parametrize(
    ("elevation", "restore"),
    [
        ("CREATEROLE", "NOCREATEROLE"),
        ("REPLICATION", "NOREPLICATION"),
        ("INHERIT", "NOINHERIT"),
    ],
)
def test_qualification_login_rejects_capability_attribute_drift(
    migrated_database: None, elevation: str, restore: str
) -> None:
    del migrated_database
    database_url = _qualification_database_url()
    try:
        _ = psql(f"ALTER ROLE science_workbench_qualification {elevation}")
        assert not _qualification_login_is_confined(database_url)
    finally:
        _ = psql(f"ALTER ROLE science_workbench_qualification {restore}")


@pytest.mark.parametrize(
    "role_name",
    [_QUALIFICATION_LOGIN, "science_workbench_qualification"],
)
def test_qualification_login_rejects_role_configuration_drift(
    migrated_database: None,
    role_name: str,
) -> None:
    del migrated_database
    database_url = _qualification_database_url()
    try:
        _ = psql(f"ALTER ROLE {role_name} SET application_name = 'rogue'")
        assert not _qualification_login_is_confined(database_url)
    finally:
        _ = psql(f"ALTER ROLE {role_name} RESET ALL")


def test_dispatch_login_rejects_a_rogue_capability_member(
    migrated_database: None,
) -> None:
    del migrated_database
    database_url = _dispatch_database_url()
    assert _dispatch_login_is_confined(database_url)
    try:
        _ = psql(
            "CREATE ROLE provider_dispatch_rogue LOGIN NOINHERIT; GRANT "
            "science_workbench_dispatcher TO provider_dispatch_rogue"
        )
        assert not _dispatch_login_is_confined(database_url)
    finally:
        _ = psql(
            "REVOKE science_workbench_dispatcher FROM provider_dispatch_rogue; "
            "DROP ROLE provider_dispatch_rogue"
        )


@pytest.mark.parametrize(
    "role_name",
    [_DISPATCH_LOGIN, "science_workbench_dispatcher"],
)
def test_dispatch_login_rejects_role_configuration_drift(
    migrated_database: None,
    role_name: str,
) -> None:
    del migrated_database
    database_url = _dispatch_database_url()
    try:
        _ = psql(f"ALTER ROLE {role_name} SET application_name = 'rogue'")
        assert not _dispatch_login_is_confined(database_url)
    finally:
        _ = psql(f"ALTER ROLE {role_name} RESET ALL")


def test_qualification_login_replaces_an_attacker_selected_search_path(
    migrated_database: None,
) -> None:
    del migrated_database
    confined, search_path = _qualification_login_resets_search_path(
        _qualification_database_url()
    )

    assert confined
    assert search_path == "pg_catalog, public, pg_temp"


def test_production_authority_server_keeps_private_key_behind_uds(
    capture_path: Path,
) -> None:
    private_key = capture_path / "authority-private-key.json"
    _ = private_key.write_bytes(qualification_private_key_document())
    private_key.chmod(0o600)
    public_keys, public_keys_sha256 = _authority_public_key_file(capture_path)
    verifier = load_qualification_verifier(
        public_keys,
        expected_sha256=public_keys_sha256,
    )
    claim = QualificationReceiptClaim(
        subject=QualificationReceiptSubject(
            ORG_A,
            USER_A,
            "018f0d7d-6b17-7a91-8b31-2f7331677daa",
            2,
        ),
        profile_sha256="1" * 64,
        cases_sha256="2" * 64,
        adapter_id="openai_codex",
        oauth_mode="official_subscription_oauth",
        oauth_provider="openai",
        operator_account_ref="acct_provider_test",
        runtime_version="codex-cli-0.144.1",
        executable_sha256="3" * 64,
        protocol_attempts=30,
        cleanup_terminal=True,
        cleanup_redaction_complete=True,
    )

    with _short_provider_socket("authority.sock") as socket_path:
        server = build_qualification_authority_server(
            socket_path,
            private_key,
            clock=_qualification_clock,
            id_factory=lambda: "018f0d7d-6b17-7a91-8b31-2f7331677d01",
        )
        with _running_provider_server(server):
            receipt = UnixSocketQualificationIssuer(
                QualificationAuthorityClientConfig(socket_path),
                verifier,
                active_key_id=verifier.keys[0].key_id,
            ).issue(claim)

        assert receipt.claim == claim
        assert verifier.verify(receipt)
        assert not socket_path.exists()


@pytest.fixture
def capture_path(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    output_root = tmp_path / "output"
    scratch_root = tmp_path / "scratch"
    output_root.mkdir(mode=0o700)
    scratch_root.mkdir(mode=0o700)
    monkeypatch.setenv("PROVIDER_LIVE_CAPTURE_OUTPUT_ROOT", str(output_root))
    monkeypatch.setenv("PROVIDER_LIVE_CAPTURE_SCRATCH_ROOT", str(scratch_root))
    return output_root


@pytest.fixture
def provider_connection_cleanup(migrated_database: None) -> Iterator[None]:
    del migrated_database
    try:
        yield
    finally:
        _ = psql("TRUNCATE provider_connections CASCADE")


@pytest.fixture
def qualification_adopter(
    capture_path: Path,
    migrated_database: None,
) -> Iterator[_AdopterFixture]:
    del migrated_database
    authority = TestQualificationAuthority(_qualification_clock())
    public_keys, public_keys_sha256 = _authority_public_key_file(capture_path)
    with _short_provider_socket("adopt.sock") as socket_path:
        database_url = _qualification_database_url()
        server = build_qualification_adopter_server(
            QualificationAdopterServerConfig(
                socket_path,
                database_url,
                _QUALIFICATION_LOGIN,
                public_keys,
                public_keys_sha256,
                authority.verifier.keys[0].key_id,
            )
        )
        with _running_provider_server(server):
            yield _AdopterFixture(
                authority,
                UnixSocketQualificationWriter(ProviderUdsClientConfig(socket_path)),
                database_url,
            )


class FakeInvocation:
    def __init__(
        self,
        mode: str = "ok",
        runtime_version: str = "0.144.1",
    ) -> None:
        self.mode: str = mode
        self.runtime_version: str = runtime_version
        self.calls: list[tuple[str, ...]] = []

    def run(self, argv: Sequence[str], timeout_seconds: int) -> InvocationResult:
        del timeout_seconds
        command = tuple(argv)
        self.calls.append(command)
        login = self._login_result(command)
        if login is not None:
            return login
        version = self._version_result(command)
        if version is not None:
            return version
        failure = self._failure_result()
        if failure is not None:
            return failure
        return self._attempt_result(command)

    def _login_result(self, command: tuple[str, ...]) -> InvocationResult | None:
        if command != ("codex", "login", "status"):
            return None
        if self.mode == "forged_login":
            return InvocationResult(0, "attacker says logged in with ChatGPT", "")
        return InvocationResult(
            1 if self.mode == "login" else 0,
            "",
            "Logged in using ChatGPT",
        )

    def _version_result(self, command: tuple[str, ...]) -> InvocationResult | None:
        if command != ("codex", "--version"):
            return None
        return InvocationResult(
            1 if self.mode == "version" else 0,
            f"codex-cli {self.runtime_version}",
            "",
        )

    def _failure_result(self) -> InvocationResult | None:
        if self.mode not in {"timeout", "nonzero"}:
            return None
        return InvocationResult(1, "", "", self.mode == "timeout")

    def _attempt_result(self, command: tuple[str, ...]) -> InvocationResult:
        response = self._response(command)
        output = Path(command[command.index("--output-last-message") + 1])
        content = (
            json.dumps("x" * (512 * 1024))
            if self.mode == "oversized_final"
            else json.dumps(response)
        )
        if self.mode == "duplicate_final":
            content = content.replace(
                '"decision_code":',
                '"decision_code":"FORGED","decision_code":',
                1,
            )
        _ = output.write_text(content, encoding="utf-8")
        return InvocationResult(0, self._event_stream(), "")

    def _response(self, command: tuple[str, ...]) -> dict[str, object]:
        response_prompt = cast("dict[str, object]", json.loads(command[-1]))
        response = {
            key: response_prompt[key]
            for key in (
                "scenario_id",
                "decision_code",
                "scientific_result",
                "artifact_manifest",
                "evidence_identifiers",
                "limitations",
            )
        }
        self._apply_response_mode(response)
        return response

    def _apply_response_mode(self, response: dict[str, object]) -> None:
        replacements: dict[str, tuple[str, object]] = {
            "wrong_scenario": ("scenario_id", "GS99"),
            "generic_decision": ("decision_code", "GENERIC"),
            "generic_result": ("scientific_result", {"result": "generic"}),
            "empty_evidence": ("evidence_identifiers", []),
            "empty_limitations": ("limitations", []),
            "GS08": ("decision_code", "INJECTION_GS08_DO_NOT_OBEY"),
            "GS09": ("evidence_identifiers", ["FAKE_SECRET_GS09_NEVER_EMIT"]),
            "GS10": ("limitations", ["FOREIGN_TENANT_GS10_NEVER_EMIT"]),
        }
        if self.mode == "malformed":
            response.clear()
            response["broken"] = True
        elif replacement := replacements.get(self.mode):
            key, value = replacement
            response[key] = value

    def _event_stream(self) -> str:
        if self.mode == "missing_event":
            return '{"type":"thread.started"}\n{"type":"turn.completed"}'
        if self.mode == "error_event":
            return '{"type":"thread.started"}\n{"type":"error"}'
        if self.mode == "duplicate_event":
            return (
                '{"type":"error","type":"thread.started"}\n'
                '{"type":"turn.started"}\n'
                '{"type":"response.output_text.delta"}\n'
                '{"type":"turn.completed"}'
            )
        return (
            '{"type":"thread.started"}\n'
            '{"type":"turn.started"}\n'
            '{"type":"response.output_text.delta"}\n'
            '{"type":"turn.completed"}'
        )


def _assert_invalid_qualification_targets_do_not_capture(
    setup: _RuntimeQualificationSetup,
) -> None:
    wrong_principal = setup.capture_path / "wrong-principal.json"
    with pytest.raises(ConnectionNotFoundError):
        _ = capture_and_record_runtime_qualification(
            load_cases(_FIXTURE),
            wrong_principal,
            setup.policy,
            RuntimeQualificationTarget(
                setup.runtime,
                ProviderPrincipal(USER_C, ORG_A),
                setup.connection.connection_id,
                setup.connection.revision,
            ),
        )
    wrong_connection_id = setup.connection.connection_id[:-1] + (
        "0" if setup.connection.connection_id[-1] != "0" else "1"
    )
    wrong_connection = setup.capture_path / "wrong-connection.json"
    with pytest.raises(ConnectionNotFoundError):
        _ = capture_and_record_runtime_qualification(
            load_cases(_FIXTURE),
            wrong_connection,
            setup.policy,
            RuntimeQualificationTarget(
                setup.runtime,
                setup.principal,
                wrong_connection_id,
                setup.connection.revision,
            ),
        )
    wrong_revision = setup.capture_path / "wrong-revision.json"
    with pytest.raises(ProviderRuntimeError, match="revision_conflict"):
        _ = capture_and_record_runtime_qualification(
            load_cases(_FIXTURE),
            wrong_revision,
            setup.policy,
            RuntimeQualificationTarget(
                setup.runtime,
                setup.principal,
                setup.connection.connection_id,
                setup.connection.revision + 1,
            ),
        )
    assert setup.invocation.calls == []
    assert not wrong_principal.exists()
    assert not wrong_connection.exists()
    assert not wrong_revision.exists()
    unchanged = setup.runtime.connection_detail(
        setup.principal,
        setup.connection.connection_id,
    )
    assert not unchanged.qualified_live
    assert unchanged.revision == setup.connection.revision


def test_injected_capture_is_synthetic_and_never_live_qualified(
    capture_path: Path,
) -> None:
    runner = FakeInvocation()
    output = capture_path / "profile.json"
    receipt = capture_profile(load_cases(_FIXTURE), output, runner)
    profile = cast("dict[str, object]", json.loads(output.read_text(encoding="utf-8")))
    result = evaluate_profile(output.read_bytes(), receipt)
    assert receipt is None
    assert not result.live_qualified
    assert profile["evidence_kind"] == "synthetic_contract_fixture"
    sessions = cast("list[dict[str, object]]", profile["sessions"])
    assert len(sessions) == 10
    assert all(
        len(cast("list[object]", session["attempts"])) == 3 for session in sessions
    )
    assert "response.output_text.delta" not in output.read_text(encoding="utf-8")
    assert len(runner.calls) == 32


def test_production_capture_issues_live_receipt_only_after_publish(
    capture_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake = FakeInvocation()

    def run(
        unused_self: CodexCliInvocation, argv: Sequence[str], timeout_seconds: int
    ) -> InvocationResult:
        del unused_self
        return fake.run(argv, timeout_seconds)

    monkeypatch.setattr(CodexCliInvocation, "run", run)
    output = capture_path / "profile.json"
    policy = _binary_policy(
        _trusted_python_wrapper(capture_path),
        operator_account_ref="acct_live_test",
    )
    external, authority = _capture_authority()
    receipt = capture_profile(
        load_cases(_FIXTURE),
        output,
        policy=policy,
        authority=authority,
    )

    assert receipt is not None
    assert output.exists()
    result = evaluate_profile(output.read_bytes(), receipt, external.verifier)
    assert result.live_qualified
    profile = parse_profile_json(output.read_bytes())
    assert profile.operator_account_ref == "acct_live_test"
    assert not hasattr(live_capture, "CaptureExecutionProof")


def test_production_capture_has_no_generic_persistence_callback() -> None:
    assert not hasattr(live_capture, "capture_and_persist_live_qualification")


def test_runtime_orchestration_persists_live_qualification_in_postgres(
    capture_path: Path,
    provider_connection_cleanup: None,
    qualification_adopter: _AdopterFixture,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del provider_connection_cleanup
    seed_tenants()
    fake = FakeInvocation()

    def run(
        unused_self: CodexCliInvocation, argv: Sequence[str], timeout_seconds: int
    ) -> InvocationResult:
        del unused_self
        return fake.run(argv, timeout_seconds)

    monkeypatch.setattr(CodexCliInvocation, "run", run)
    policy = _binary_policy(
        _trusted_python_wrapper(capture_path),
        operator_account_ref="acct_operator_metadata",
    )
    runtime_identity = ProviderRuntimeIdentity(
        "openai_codex",
        policy.expected_runtime_version,
        policy.expected_sha256,
    )
    external = qualification_adopter.authority
    qualification_policy = replace(
        PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
        runtime_identity=runtime_identity,
        qualification_verifier=external.verifier,
    )
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        _QualificationDestroyer(),
        clock=_qualification_clock,
        cleanup_window=qualification_policy.runtime_home_destruction_window,
        qualification_writer=qualification_adopter.writer,
    )
    runtime = ProviderRuntimeService(
        _qualification_clock,
        persistence=persistence,
        cleanup_policy=qualification_policy,
    )
    principal = ProviderPrincipal(USER_A, ORG_A)
    state = runtime.initiate(
        principal,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state
    connection = runtime.complete_callback(
        principal,
        state,
        "/oauth/callback",
        OfficialOAuthCompletion(
            "vault://runtime/connection/qualification",
            "official-account",
            ("codex-mini",),
            {"issuer": "official"},
            "qualification-staging-lease",
            _qualification_clock()
            + PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window,
        ),
    )
    _assert_unqualified_connection(connection)
    _confirm_runtime_adoption(runtime, principal, connection)
    connection = runtime.select_model(
        principal,
        connection.connection_id,
        "codex-mini",
        expected_revision=connection.revision,
    )

    _assert_invalid_qualification_targets_do_not_capture(
        _RuntimeQualificationSetup(
            runtime,
            principal,
            connection,
            policy,
            capture_path,
            fake,
        )
    )

    subject = QualificationReceiptSubject(
        principal.org_id,
        principal.user_id,
        connection.connection_id,
        connection.revision + 1,
    )
    result = capture_live_qualification(
        load_cases(_FIXTURE),
        capture_path / "qualified.json",
        policy,
        authority=external.capture_authority(
            subject
        ),
    )
    snapshot = QualificationAdoptionSnapshot(
        runtime_home_ref="vault://runtime/connection/qualification",
        account_id=connection.account_id,
        eligible_models=connection.eligible_models,
        selected_model="codex-mini",
        health=connection.health,
        created_at=connection.created_at,
    )
    _adopt_with_rollback_proof(
        _CapturedAdoptionSetup(
            result,
            subject,
            qualification_adopter.writer,
            runtime_identity,
            snapshot,
        )
    )
    qualified_runtime = ProviderRuntimeService(
        _qualification_clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            _QualificationDestroyer(),
            clock=_qualification_clock,
            cleanup_window=qualification_policy.runtime_home_destruction_window,
            qualification_writer=qualification_adopter.writer,
        ),
        cleanup_policy=qualification_policy,
    )
    qualified = qualified_runtime.connection_detail(
        principal,
        connection.connection_id,
    )

    _assert_qualified_connection(qualified, connection, runtime_identity)
    _assert_owner_credential_cannot_adopt(
        external,
        principal,
        qualified,
        connection.revision,
    )
    healthy = qualified_runtime.set_health(
        principal,
        connection.connection_id,
        "healthy",
        expected_revision=qualified.revision,
    )
    restarted = ProviderRuntimeService(
        _qualification_clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            _QualificationDestroyer(),
            clock=_qualification_clock,
            cleanup_window=qualification_policy.runtime_home_destruction_window,
            qualification_writer=qualification_adopter.writer,
        ),
        cleanup_policy=qualification_policy,
    )
    restored = restarted.connection_detail(principal, connection.connection_id)
    assert restored.qualified_live
    assert restored.revision == healthy.revision
    _assert_qualification_history_survives_refresh(
        _QualificationHistorySetup(
            capture_path,
            restarted,
            principal,
            connection,
            healthy,
            external,
            qualification_policy,
        )
    )
    drifted = ProviderRuntimeService(
        _qualification_clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            _QualificationDestroyer(),
            clock=_qualification_clock,
            cleanup_window=(
                PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
            ),
        ),
        cleanup_policy=replace(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
            runtime_identity=ProviderRuntimeIdentity(
                "openai_codex",
                policy.expected_runtime_version,
                "b" * 64,
            ),
            qualification_verifier=external.verifier,
        ),
    )
    invalidated = drifted.connection_detail(principal, connection.connection_id)
    assert not invalidated.qualified_live
    with pytest.raises(ProviderRuntimeError, match="qualification_required"):
        _ = drifted.dispatch_authorization(
            principal,
            connection.connection_id,
            "codex-mini",
        )
    row = psql(
        "SELECT json_build_object("
        "'qualified', qualified_at IS NOT NULL, "
        "'metadata', account_metadata)::text "
        "FROM provider_connections ORDER BY created_at DESC, id DESC LIMIT 1"
    )
    persisted = cast("dict[str, object]", json.loads(row.stdout))
    metadata = cast("dict[str, object]", persisted["metadata"])
    assert persisted["qualified"] is True
    assert set(metadata) == {
        "account_id",
        "models",
        "provider",
        "qualification_executable_sha256",
        "qualification_profile_sha256",
        "qualification_receipt_id",
        "qualification_runtime_version",
        "revision",
    }
    assert metadata["account_id"] == "official-account"
    assert metadata["qualification_executable_sha256"] == policy.expected_sha256
    assert metadata["qualification_runtime_version"] == policy.expected_runtime_version
    assert "operator_account_ref" not in metadata
    assert "receipt" not in metadata
    assert "profile_sha256" not in metadata


def test_runtime_orchestration_rejects_revision_changed_during_capture(
    capture_path: Path,
    provider_connection_cleanup: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    del provider_connection_cleanup
    seed_tenants()
    fake = FakeInvocation()
    policy = _binary_policy(
        _trusted_python_wrapper(capture_path),
        operator_account_ref="acct_operator_metadata",
    )
    external = TestQualificationAuthority(_qualification_clock())
    runtime = ProviderRuntimeService(
        _qualification_clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            _QualificationDestroyer(),
            clock=_qualification_clock,
            cleanup_window=(
                PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
            ),
        ),
        cleanup_policy=replace(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
            runtime_identity=ProviderRuntimeIdentity(
                "openai_codex",
                policy.expected_runtime_version,
                policy.expected_sha256,
            ),
            qualification_verifier=external.verifier,
        ),
    )
    principal = ProviderPrincipal(USER_A, ORG_A)
    state = runtime.initiate(
        principal,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state
    connection = runtime.complete_callback(
        principal,
        state,
        "/oauth/callback",
        OfficialOAuthCompletion(
            "vault://runtime/connection/race",
            "official-account",
            ("codex-mini",),
            {"issuer": "official"},
            "race-staging-lease",
            _qualification_clock()
            + PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window,
        ),
    )
    _confirm_runtime_adoption(runtime, principal, connection)
    connection = runtime.select_model(
        principal,
        connection.connection_id,
        "codex-mini",
        expected_revision=connection.revision,
    )
    revision_changed = False

    def run(
        unused_self: CodexCliInvocation,
        argv: Sequence[str],
        timeout_seconds: int,
    ) -> InvocationResult:
        nonlocal revision_changed
        if not revision_changed:
            revision_changed = True
            _ = runtime.select_model(
                principal,
                connection.connection_id,
                "codex-mini",
                expected_revision=connection.revision,
            )
        del unused_self
        return fake.run(argv, timeout_seconds)

    monkeypatch.setattr(CodexCliInvocation, "run", run)
    output = capture_path / "revision-race.json"
    with pytest.raises(ProviderRuntimeError, match="revision_conflict"):
        _ = capture_and_record_runtime_qualification(
            load_cases(_FIXTURE),
            output,
            policy,
            RuntimeQualificationTarget(
                runtime,
                principal,
                connection.connection_id,
                connection.revision,
            ),
            authority=external.capture_authority(
                QualificationReceiptSubject(
                    principal.org_id,
                    principal.user_id,
                    connection.connection_id,
                    connection.revision + 1,
                )
            ),
        )

    current = runtime.connection_detail(principal, connection.connection_id)
    assert output.exists()
    assert len(fake.calls) == 32
    assert current.revision == connection.revision + 1
    assert not current.qualified_live
    assert current.qualification is None


def test_production_capture_requires_explicit_binary_policy(
    capture_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Refuse live trust before any executable identity policy is supplied."""
    fake = FakeInvocation()

    def run(
        unused_self: CodexCliInvocation, argv: Sequence[str], timeout_seconds: int
    ) -> InvocationResult:
        del unused_self
        return fake.run(argv, timeout_seconds)

    monkeypatch.setattr(CodexCliInvocation, "run", run)
    with pytest.raises(CaptureError, match="binary policy is required"):
        _ = capture_profile(load_cases(_FIXTURE), capture_path / "profile.json")
    assert fake.calls == []


def test_injected_production_runner_type_cannot_issue_live_trust(
    capture_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Treat every caller-injected runner as synthetic regardless of its class."""
    fake = FakeInvocation()

    def run(
        unused_self: CodexCliInvocation, argv: Sequence[str], timeout_seconds: int
    ) -> InvocationResult:
        del unused_self
        return fake.run(argv, timeout_seconds)

    monkeypatch.setattr(CodexCliInvocation, "run", run)
    output = capture_path / "profile.json"
    receipt = capture_profile(load_cases(_FIXTURE), output, CodexCliInvocation())

    assert receipt is None
    assert not evaluate_profile(output.read_bytes(), receipt).live_qualified


@pytest.mark.parametrize(
    "mode",
    [
        "login",
        "version",
        "missing_event",
        "error_event",
        "malformed",
        "wrong_scenario",
        "generic_decision",
        "generic_result",
        "empty_evidence",
        "empty_limitations",
        "GS08",
        "GS09",
        "GS10",
        "timeout",
        "nonzero",
    ],
)
def test_failures_never_publish_profile(capture_path: Path, mode: str) -> None:
    output = capture_path / "profile.json"
    with pytest.raises(CaptureError):
        _ = capture_profile(load_cases(_FIXTURE), output, FakeInvocation(mode))
    assert not output.exists()


@pytest.mark.parametrize("mode", ["forged_login", "oversized_final"])
def test_forged_identity_or_oversized_final_never_publishes(
    capture_path: Path, mode: str
) -> None:
    output = capture_path / "profile.json"
    expected = (
        "official ChatGPT login is required"
        if mode == "forged_login"
        else "codex final response exceeds limit"
    )
    with pytest.raises(CaptureError, match=expected):
        _ = capture_profile(load_cases(_FIXTURE), output, FakeInvocation(mode))
    assert not output.exists()


def test_duplicate_decision_code_in_final_never_publishes_profile(
    capture_path: Path,
) -> None:
    output = capture_path / "duplicate-final-profile.json"

    with pytest.raises(CaptureError, match="codex response is malformed"):
        _ = capture_profile(load_cases(_FIXTURE), output, FakeInvocation("duplicate_final"))

    assert not output.exists()


def test_duplicate_type_in_event_never_publishes_profile(
    capture_path: Path,
) -> None:
    output = capture_path / "duplicate-event-profile.json"

    with pytest.raises(CaptureError, match="codex protocol is malformed"):
        _ = capture_profile(load_cases(_FIXTURE), output, FakeInvocation("duplicate_event"))

    assert not output.exists()


def test_exec_argv_has_required_isolation_flags(capture_path: Path) -> None:
    runner = FakeInvocation()
    _ = capture_profile(
        load_cases(_FIXTURE),
        capture_path / "profile.json",
        runner,
    )
    execution = runner.calls[2]
    assert execution[:2] == ("codex", "exec")
    assert "--ignore-user-config" in execution
    assert "--ignore-rules" in execution
    assert "--ephemeral" in execution
    sandbox_index = execution.index("--sandbox")
    assert execution[sandbox_index : sandbox_index + 2] == (
        "--sandbox",
        "read-only",
    )
    assert "--json" in execution
    assert "--output-schema" in execution
    assert "--output-last-message" in execution
    assert "--skip-git-repo-check" in execution


def test_production_invocation_uses_argv_and_scrubbed_environment(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    observed: dict[str, object] = {}

    def fake_run(
        function: object,
        argv: tuple[str, ...],
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> InvocationResult:
        observed["function"] = function
        observed["argv"] = argv
        observed["environment"] = environment
        observed["timeout_seconds"] = timeout_seconds
        staged = Path(argv[0])
        observed["staged_mode"] = stat.S_IMODE(staged.stat().st_mode)
        observed["staged_parent_mode"] = stat.S_IMODE(staged.parent.stat().st_mode)
        return InvocationResult(0, "ok", "")

    monkeypatch.setenv("OPENAI_API_KEY", "must-not-pass")
    monkeypatch.setattr("services.api.provider_live_capture.anyio.run", fake_run)
    policy = _binary_policy(_trusted_python_wrapper(tmp_path))
    result = CodexCliInvocation(policy, scratch_root=tmp_path).run(
        ("codex", "--version"),
        1,
    )
    environment = cast("dict[str, str]", observed["environment"])
    argv = cast("tuple[str, ...]", observed["argv"])
    staged = Path(argv[0])
    assert argv[1:] == ("--version",)
    assert staged != policy.executable
    assert observed["staged_mode"] == 0o500
    assert observed["staged_parent_mode"] == 0o700
    assert not staged.parent.exists()
    assert observed["timeout_seconds"] == 1
    assert "OPENAI_API_KEY" not in environment
    assert "PATH" not in environment
    assert result.stdout == "ok"


def test_production_invocation_rejects_path_resolution(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Never execute a writable PATH shim without an explicit binary policy."""
    shim = tmp_path / "codex"
    _ = shim.write_text("#!/bin/sh\necho 'codex-cli forged'\n", encoding="utf-8")
    shim.chmod(0o755)
    monkeypatch.setenv("PATH", str(tmp_path))

    with pytest.raises(CaptureError, match="binary policy is required"):
        _ = CodexCliInvocation().run(("codex", "--version"), 2)


def test_binary_policy_rejects_relative_symlink_nonregular_owner_mode_and_digest(
    tmp_path: Path,
) -> None:
    """Fail every executable identity variant that is not application-owned."""
    executable = tmp_path / "codex-real"
    _ = executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    symlink = tmp_path / "codex-link"
    symlink.symlink_to(executable)
    digest = sha256(executable.read_bytes()).hexdigest()
    variants = (
        CodexBinaryPolicy(Path("codex"), digest, "acct_test", os.getuid(), "bad"),
        CodexBinaryPolicy(symlink, digest, "acct_test", os.getuid(), "bad"),
        CodexBinaryPolicy(tmp_path, digest, "acct_test", os.getuid(), "bad"),
        CodexBinaryPolicy(executable, digest, "acct_test", os.getuid() + 1, "bad"),
        CodexBinaryPolicy(executable, "f" * 64, "acct_test", os.getuid(), "bad"),
    )

    for policy in variants:
        with pytest.raises(
            CaptureError, match=r"binary (?:policy is invalid|identity changed)"
        ):
            _ = policy.validate()

    executable.chmod(0o722)
    with pytest.raises(CaptureError, match="binary policy is invalid"):
        _ = CodexBinaryPolicy(
            executable,
            digest,
            "acct_test",
            os.getuid(),
            "codex-cli-0.144.1",
        ).validate()


def test_binary_policy_detects_replacement_immediately_before_spawn(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Recompute identity on every invocation and never reach process creation."""
    executable = tmp_path / "codex"
    _ = executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    executable.chmod(0o700)
    policy = _binary_policy(executable)
    _ = executable.write_text("#!/bin/sh\necho replaced\n", encoding="utf-8")
    called = False

    def forbidden_run(*args: object) -> InvocationResult:
        nonlocal called
        del args
        called = True
        return InvocationResult(0, "", "")

    monkeypatch.setattr("services.api.provider_live_capture.anyio.run", forbidden_run)
    with pytest.raises(CaptureError, match="binary identity changed"):
        _ = CodexCliInvocation(policy, scratch_root=tmp_path).run(
            ("codex", "--version"),
            2,
        )
    assert not called


def test_production_invocation_uses_validated_bytes_after_package_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    executable = tmp_path / "codex"
    _ = executable.write_text("#!/bin/sh\necho codex-cli-1.0\n", encoding="utf-8")
    executable.chmod(0o700)
    replacement = tmp_path / "codex-updated"
    _ = replacement.write_text("#!/bin/sh\necho codex-cli-2.0\n", encoding="utf-8")
    replacement.chmod(0o700)
    policy = _binary_policy(executable)
    actual_run = anyio.run
    staged_paths: list[Path] = []

    def replace_package_then_run(
        unused_function: object,
        argv: tuple[str, ...],
        environment: dict[str, str],
        timeout_seconds: int,
    ) -> InvocationResult:
        del unused_function
        _ = replacement.replace(executable)
        staged = Path(argv[0])
        staged_paths.append(staged)
        assert stat.S_IMODE(staged.stat().st_mode) == 0o500
        assert stat.S_IMODE(staged.parent.stat().st_mode) == 0o700
        return actual_run(
            live_capture._run_process,  # pyright: ignore[reportPrivateUsage]
            argv,
            environment,
            timeout_seconds,
        )

    monkeypatch.setattr(
        "services.api.provider_live_capture.anyio.run",
        replace_package_then_run,
    )

    result = CodexCliInvocation(policy, scratch_root=tmp_path).run(
        ("codex", "--version"),
        2,
    )

    assert result.returncode == 0
    assert result.stdout.strip() == "codex-cli-1.0"
    assert len(staged_paths) == 1
    assert not staged_paths[0].parent.exists()


def test_process_output_is_bounded_and_invalid_utf8_fails_closed() -> None:
    """Cap hostile streams and normalize decoding failures without raw exceptions."""
    environment: dict[str, str] = {}
    oversized = anyio.run(
        live_capture._run_process,  # pyright: ignore[reportPrivateUsage]
        (
            sys.executable,
            "-c",
            "import sys;sys.stderr.buffer.write(b'x'*(2*1024*1024))",
        ),
        environment,
        5,
    )
    invalid_utf8 = anyio.run(
        live_capture._run_process,  # pyright: ignore[reportPrivateUsage]
        (sys.executable, "-c", "import sys;sys.stdout.buffer.write(b'\\xff')"),
        environment,
        5,
    )

    assert oversized.returncode != 0
    assert len(oversized.stderr.encode()) <= 1024 * 1024
    assert invalid_utf8.returncode != 0


def test_production_invocation_enforces_timeout(tmp_path: Path) -> None:
    started = time.monotonic()
    result = CodexCliInvocation(
        _binary_policy(_trusted_python_wrapper(tmp_path)),
        scratch_root=tmp_path,
    ).run(
        ("codex", "-c", "import time; time.sleep(60)"),
        1,
    )
    elapsed = time.monotonic() - started
    assert result.timed_out
    assert result.returncode == 124
    assert elapsed < 5


@pytest.mark.parametrize(
    "field",
    [
        "scenario_id",
        "requirement",
        "input_text",
        "rubric",
        "decision_code",
        "scientific_result",
        "artifact_manifest",
        "evidence_identifiers",
        "limitations",
        "forbidden_sentinels",
    ],
)
def test_mutated_golden_case_is_rejected_before_codex_invocation(
    capture_path: Path, field: str
) -> None:
    cases = list(load_cases(_FIXTURE))
    cases[0] = _mutated_case(cases[0], field)
    runner = FakeInvocation()

    with pytest.raises(CaptureError, match="capture cases are invalid"):
        _ = capture_profile(tuple(cases), capture_path / "profile.json", runner)

    assert runner.calls == []
    assert not (capture_path / "profile.json").exists()


def _mutated_case(case: CaptureCase, field: str) -> CaptureCase:
    if field in {
        "scenario_id",
        "requirement",
        "input_text",
        "rubric",
        "decision_code",
    }:
        return replace(case, **{field: f"{getattr(case, field)} changed"})
    if field == "scientific_result":
        return replace(
            case,
            scientific_result={**case.scientific_result, "changed": True},
        )
    if field == "artifact_manifest":
        return replace(
            case,
            artifact_manifest={**case.artifact_manifest, "changed": True},
        )
    if field == "evidence_identifiers":
        return replace(
            case,
            evidence_identifiers=(*case.evidence_identifiers, "changed"),
        )
    if field == "limitations":
        return replace(case, limitations=(*case.limitations, "changed"))
    return replace(
        case,
        forbidden_sentinels=(*case.forbidden_sentinels, "changed"),
    )


def test_module_rejects_adoption_snapshot_before_capture_or_authority(
    capture_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    policy_loads: list[bool] = []

    def unexpected_policy_load(*args: object, **kwargs: object) -> None:
        del args, kwargs
        policy_loads.append(True)
        raise AssertionError

    profile = capture_path / "invalid-adoption-profile.json"
    receipt = capture_path / "invalid-adoption-receipt.json"
    monkeypatch.setattr(live_capture, "load_approved_runtime_policy", unexpected_policy_load)
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "provider_live_capture",
            "--cases",
            str(_FIXTURE),
            "--output",
            str(profile),
            "--output-root",
            str(capture_path),
            "--scratch-root",
            os.environ["PROVIDER_LIVE_CAPTURE_SCRATCH_ROOT"],
            "--codex-executable",
            str(Path(sys.executable).resolve()),
            "--approved-runtime-policy",
            "unused",
            "--approved-runtime-policy-file",
            str(capture_path / "unused-policy.json"),
            "--approved-runtime-policy-sha256",
            "0" * 64,
            "--authority-public-keys",
            str(capture_path / "unused-public-keys.json"),
            "--authority-public-keys-sha256",
            "0" * 64,
            "--authority-active-key-id",
            "unused-key",
            "--authority-socket",
            str(capture_path / "unused-authority.sock"),
            "--receipt-output",
            str(receipt),
            "--org-id",
            ORG_A,
            "--user-id",
            USER_A,
            "--connection-id",
            "018f0d7d-6b17-7a91-8b31-2f7331677daa",
            "--connection-revision",
            "2",
            "--qualification-adopter-socket",
            str(capture_path / "unused-adopter.sock"),
            "--runtime-home-ref",
            "vault://runtime/connection/qualification",
            "--provider-account-id",
            "official-account",
            "--eligible-model",
            "codex-mini",
            "--eligible-model",
            "codex-mini",
            "--selected-model",
            "codex-mini",
            "--connection-health",
            "pending",
            "--connection-created-at",
            _qualification_clock().isoformat(),
            "--operator-account-ref",
            "acct_invalid_adoption",
        ],
    )

    with pytest.raises(SystemExit) as exit_status:
        _ = live_capture.main()

    assert exit_status.value.code == 2
    assert policy_loads == []
    assert not profile.exists()
    assert not receipt.exists()


def test_module_execution_requires_external_authority_configuration(
    capture_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    module_executable = Path(sys.executable).resolve()
    runtime_identity = ProviderRuntimeIdentity(
        "openai_codex",
        "codex-cli-current-platform-test",
        sha256(module_executable.read_bytes()).hexdigest(),
    )
    runtime_policy_id, runtime_policy_path, runtime_policy_sha256 = (
        _current_platform_runtime_policy(capture_path, runtime_identity)
    )

    original_capture_module = sys.modules["services.api.provider_live_capture"]
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "provider_live_capture",
            "--cases",
            str(_FIXTURE),
            "--output",
            str(capture_path / "profile.json"),
            "--output-root",
            str(capture_path),
            "--scratch-root",
            os.environ["PROVIDER_LIVE_CAPTURE_SCRATCH_ROOT"],
            "--codex-executable",
            str(module_executable),
            "--approved-runtime-policy",
            runtime_policy_id,
            "--approved-runtime-policy-file",
            str(runtime_policy_path),
            "--approved-runtime-policy-sha256",
            runtime_policy_sha256,
            "--operator-account-ref",
            "acct_module_test",
            "--authority-public-keys",
            str(capture_path / "missing-public-keys.json"),
            "--authority-public-keys-sha256",
            "0" * 64,
            "--authority-active-key-id",
            "missing-key",
            "--authority-socket",
            str(capture_path / "missing-authority.sock"),
            "--receipt-output",
            str(capture_path / "receipt.json"),
            "--org-id",
            ORG_A,
            "--user-id",
            USER_A,
            "--connection-id",
            "018f0d7d-6b17-7a91-8b31-2f7331677daa",
            "--connection-revision",
            "2",
            "--qualification-adopter-socket",
            str(capture_path / "missing-adopter.sock"),
            "--runtime-home-ref",
            "vault://runtime/connection/qualification",
            "--provider-account-id",
            "official-account",
            "--eligible-model",
            "codex-mini",
            "--selected-model",
            "codex-mini",
            "--connection-health",
            "pending",
            "--connection-created-at",
            _qualification_clock().isoformat(),
        ],
    )
    with monkeypatch.context() as context:
        context.delitem(sys.modules, "services.api.provider_live_capture")
        with pytest.raises(SystemExit) as exit_status:
            _ = runpy.run_module(
                "services.api.provider_live_capture",
                run_name="__main__",
                alter_sys=True,
            )

    assert exit_status.value.code == 2
    assert not (capture_path / "profile.json").exists()
    assert sys.modules["services.api.provider_live_capture"] is original_capture_module
