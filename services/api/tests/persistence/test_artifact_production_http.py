from __future__ import annotations

import base64
import hashlib
import http.client
import json
import secrets
import socket
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from threading import Thread
from typing import TYPE_CHECKING, Final, cast, final
from uuid import UUID

import pytest

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

    from services.api.artifacts.models import ArtifactScope

from services.api.artifact_production_app import (
    ArtifactProductionAppConfigError,
    ArtifactProductionApplication,
    build_artifact_production_application,
)
from services.api.artifacts.http import ArtifactHttpService
from services.api.artifacts.scope_resolver import PostgresArtifactScopeResolver
from services.api.provider_run_dispatch_service import UnixSocketProviderRunDispatcher
from services.api.tests.persistence.postgres_harness import (
    database_url_asyncpg,
    psql,
)
from services.api.tests.persistence.test_artifact_composition_postgres import (
    DOWNLOAD_KEY,
    RECOVERY_KEY,
    SequenceUuid7Factory,
    uuid7_values,
)
from services.api.tests.persistence.test_rls import (
    ORG_A,
    ORG_B,
    PROJECT_A,
    USER_A,
    USER_B,
)
from services.api.tests.persistence.test_rls_contracts import (
    EXECUTION,
    PROVIDER,
    SHA,
    seed_artifact_version,
)

pytestmark = pytest.mark.usefixtures("migrated_database")
SESSION_A: Final = "018f47a0-7b9c-7d01-8def-0123456789ab"
SESSION_B: Final = "018f47a0-7b9c-7d02-8def-0123456789ab"
COOKIE_A: Final = secrets.token_urlsafe(32)
COOKIE_B: Final = secrets.token_urlsafe(32)
CSRF_A: Final = secrets.token_urlsafe(32)
CSRF_B: Final = secrets.token_urlsafe(32)
PAYLOAD: Final = b"durable HTTP production bytes"
FIXED_NOW: Final = datetime(2026, 7, 15, 9, 0, tzinfo=UTC)


@final
class FixedClock:
    def now(self) -> datetime:
        return FIXED_NOW


@dataclass(frozen=True, slots=True)
class HttpResult:
    status: int
    body: bytes
    content_type: str | None
    content_disposition: str | None
    content_security_policy: str | None


@dataclass(frozen=True, slots=True)
class HttpRequest:
    method: str
    path: str
    cookie: str
    csrf: str | None = None
    csrf_cookie: str | None = None
    body: Mapping[str, object] | None = None
    host: str | None = None
    origin: str | None = None


@dataclass(frozen=True, slots=True)
class CommittedArtifact:
    application: ArtifactProductionApplication
    recovery_root: Path
    port: int
    scope: ArtifactScope
    artifact_id: str
    version_id: str


@final
class ArchiveAfterScopeResolution:
    def __init__(self, database_url: str) -> None:
        self._base = PostgresArtifactScopeResolver(database_url)

    def artifact_scope(
        self,
        org_id: UUID,
        requester_id: UUID,
        artifact_id: UUID,
    ) -> ArtifactScope | None:
        scope = self._base.artifact_scope(org_id, requester_id, artifact_id)
        if scope is not None:
            _archive_project()
        return scope

    def version_scope(
        self,
        org_id: UUID,
        requester_id: UUID,
        artifact_id: UUID,
        version_id: UUID,
    ) -> ArtifactScope | None:
        scope = self._base.version_scope(
            org_id,
            requester_id,
            artifact_id,
            version_id,
        )
        if scope is not None:
            _archive_project()
        return scope


def _free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return cast("int", listener.getsockname()[1])


def _archive_project() -> None:
    _ = psql(
        f"UPDATE projects SET archived_at = CURRENT_TIMESTAMP WHERE id = '{PROJECT_A}'"
    )


def _restore_project() -> None:
    _ = psql(f"UPDATE projects SET archived_at = NULL WHERE id = '{PROJECT_A}'")


def _wait_for_active_requests(
    application: ArtifactProductionApplication,
    expected: int,
) -> None:
    deadline = time.monotonic() + 5
    while application.server.active_request_count() != expected:
        if time.monotonic() >= deadline:
            pytest.fail(
                f"expected {expected} active requests, observed "
                f"{application.server.active_request_count()}"
            )
        time.sleep(0.01)


def _environment(root: Path, port: int) -> dict[str, str]:
    trusted = [
        {
            "org_id": ORG_A,
            "project_id": PROJECT_A,
            "requester_id": USER_A,
            "execution_id": EXECUTION,
            "runtime_adapter_id": "openai_codex",
            "runtime_connection_id": PROVIDER,
        }
    ]
    return {
        "ARTIFACT_DATABASE_URL": database_url_asyncpg(),
        "ARTIFACT_PRIVATE_BLOB_ROOT": str(root / "private-blobs"),
        "ARTIFACT_RECOVERY_ROOT": str(root / "recovery"),
        "ARTIFACT_RECOVERY_INTEGRITY_KEY_B64": base64.b64encode(RECOVERY_KEY).decode(
            "ascii"
        ),
        "ARTIFACT_DOWNLOAD_SIGNING_KEY_B64": base64.b64encode(DOWNLOAD_KEY).decode(
            "ascii"
        ),
        "ARTIFACT_TRUSTED_EXECUTIONS_JSON": json.dumps(trusted),
        "ARTIFACT_BIND_HOST": "127.0.0.1",
        "ARTIFACT_BIND_PORT": str(port),
        "ARTIFACT_PUBLIC_ORIGIN": f"http://127.0.0.1:{port}",
        "PROVIDER_RUN_DISPATCH_SOCKET": (
            "/run/science-workbench/provider-dispatch.sock"
        ),
    }


def _seed_session(
    session_id: str,
    org_id: str,
    user_id: str,
    token: str,
    csrf: str,
) -> None:
    token_hash = hashlib.sha256(token.encode()).hexdigest()
    csrf_hash = hashlib.sha256(csrf.encode()).hexdigest()
    _ = psql(
        "INSERT INTO auth_sessions "
        "(id, org_id, user_id, token_hash, csrf_hash, idle_expires_at, "
        "absolute_expires_at) VALUES "
        f"('{session_id}', '{org_id}', '{user_id}', "
        f"decode('{token_hash}', 'hex'), decode('{csrf_hash}', 'hex'), "
        "CURRENT_TIMESTAMP + INTERVAL '1 hour', "
        "CURRENT_TIMESTAMP + INTERVAL '2 hours') ON CONFLICT DO NOTHING"
    )


def _seed_http_principals() -> None:
    seed_artifact_version()
    _seed_session(SESSION_A, ORG_A, USER_A, COOKIE_A, CSRF_A)
    _seed_session(SESSION_B, ORG_B, USER_B, COOKIE_B, CSRF_B)


def _start(application: ArtifactProductionApplication) -> Thread:
    thread = Thread(target=application.server.serve_forever, daemon=True)
    thread.start()
    return thread


def _stop(application: ArtifactProductionApplication, thread: Thread) -> None:
    application.server.shutdown()
    thread.join(timeout=5)
    application.server.server_close()
    assert not thread.is_alive()


def _request(
    port: int,
    request: HttpRequest,
) -> HttpResult:
    encoded = None if request.body is None else json.dumps(request.body).encode()
    authority = request.host or f"127.0.0.1:{port}"
    cookie = f"product_session={request.cookie}"
    if request.csrf_cookie is not None:
        cookie = f"{cookie}; product_csrf={request.csrf_cookie}"
    headers = {
        "Host": authority,
        "Cookie": cookie,
    }
    if request.body is not None:
        headers |= {
            "Content-Type": "application/json",
            "Origin": request.origin or f"http://127.0.0.1:{port}",
            "Sec-Fetch-Site": "same-origin",
            "Sec-Fetch-Mode": "cors",
            "X-CSRF-Token": request.csrf or "",
        }
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(request.method, request.path, body=encoded, headers=headers)
        response = connection.getresponse()
        return HttpResult(
            response.status,
            response.read(),
            response.getheader("Content-Type"),
            response.getheader("Content-Disposition"),
            response.getheader("Content-Security-Policy"),
        )
    finally:
        connection.close()


def _duplicate_host_request(port: int, path: str, cookie: str) -> HttpResult:
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.putrequest("GET", path, skip_host=True)
        connection.putheader("Host", f"127.0.0.1:{port}")
        connection.putheader("Host", "attacker.invalid")
        connection.putheader("Cookie", f"product_session={cookie}")
        connection.endheaders()
        response = connection.getresponse()
        return HttpResult(
            response.status,
            response.read(),
            response.getheader("Content-Type"),
            response.getheader("Content-Disposition"),
            response.getheader("Content-Security-Policy"),
        )
    finally:
        connection.close()


def _json(result: HttpResult) -> dict[str, object]:
    return cast("dict[str, object]", json.loads(result.body))


def _version_body(reference: str, *, base_version_no: int) -> dict[str, object]:
    return {
        "base_version_no": base_version_no,
        "watcher_reference": reference,
        "producing_execution_id": EXECUTION,
        "environment_sha256": SHA,
        "code_sha256": "b" * 64,
        "runtime_adapter_id": "openai_codex",
        "runtime_connection_id": PROVIDER,
        "skill_content_hashes": [SHA],
        "source_hashes": ["b" * 64],
        "input_version_ids": [],
    }


def _assert_recovery_failure_is_sanitized(
    proof: CommittedArtifact,
    tmp_path: Path,
) -> None:
    reference = proof.application.stack.watcher.register(
        proof.scope,
        UUID(EXECUTION),
        b"corrupt recovery",
        "text/plain",
    )
    record_name = f"{hashlib.sha256(reference.encode()).hexdigest()}.json"
    recovery_root = tmp_path / "recovery"
    assert recovery_root == proof.recovery_root
    _ = (recovery_root / "records" / record_name).write_bytes(b"corrupt")
    failed = _request(
        proof.port,
        HttpRequest(
            "POST",
            f"/api/v1/artifacts/{proof.artifact_id}/versions",
            COOKIE_A,
            csrf=CSRF_A,
            body=_version_body(reference, base_version_no=1),
        ),
    )
    healthy = _request(
        proof.port,
        HttpRequest(
            "GET",
            f"/api/v1/artifacts/{proof.artifact_id}/versions/{proof.version_id}",
            COOKIE_A,
        ),
    )
    assert (failed.status, failed.body, healthy.status) == (
        503,
        b'{"error":"service_unavailable"}',
        200,
    )
    assert str(proof.recovery_root).encode() not in failed.body


def _archive_race_statuses(
    application: ArtifactProductionApplication,
    artifact_id: str,
    version_id: str,
) -> tuple[int, int, int]:
    racing = ArtifactHttpService(
        application.stack.service,
        ArchiveAfterScopeResolution(database_url_asyncpg()),
    )
    try:
        artifact = racing.read_artifact(ORG_A, USER_A, artifact_id)
        _restore_project()
        version = racing.read_version(ORG_A, USER_A, artifact_id, version_id)
        _restore_project()
        download = racing.download_version(ORG_A, USER_A, artifact_id, version_id)
        return artifact.status, version.status, download.status
    finally:
        _restore_project()


def test_production_config_rejects_secret_bearing_or_incomplete_environment(
    tmp_path: Path,
) -> None:
    values = _environment(tmp_path, _free_port())
    marker = "secret-marker-that-must-not-leak"
    values["ARTIFACT_RECOVERY_INTEGRITY_KEY_B64"] = marker

    with pytest.raises(ArtifactProductionAppConfigError) as rejected:
        _ = build_artifact_production_application(values)

    assert marker not in str(rejected.value)
    assert rejected.value.__context__ is None
    assert not (tmp_path / "private-blobs").exists()
    assert not (tmp_path / "recovery").exists()


def test_production_config_requires_provider_dispatch_before_serving(
    tmp_path: Path,
) -> None:
    values = _environment(tmp_path, _free_port())
    del values["PROVIDER_RUN_DISPATCH_SOCKET"]

    with pytest.raises(ArtifactProductionAppConfigError):
        _ = build_artifact_production_application(values)

    assert not (tmp_path / "private-blobs").exists()
    assert not (tmp_path / "recovery").exists()


def test_production_composition_injects_only_dispatch_socket_client(
    tmp_path: Path,
) -> None:
    values = _environment(tmp_path, _free_port())
    identifiers = SequenceUuid7Factory(uuid7_values(200, 24))
    values["PROVIDER_RUN_DISPATCH_SOCKET"] = (
        "/run/science-workbench/provider-dispatch.sock"
    )
    application = build_artifact_production_application(
        values,
        uuid7_factory=identifiers,
    )
    try:
        assert isinstance(
            application.server.provider_run_dispatcher,
            UnixSocketProviderRunDispatcher,
        )
        assert application.server.uuid7_factory is identifiers
        assert "PROVIDER_RUN_DISPATCH_DATABASE_URL" not in values
    finally:
        application.server.server_close()


def test_session_authentication_function_has_one_non_login_bypass_owner() -> None:
    role = psql(
        "SELECT rolcanlogin::text || ':' || rolbypassrls::text FROM pg_roles "
        "WHERE rolname = 'science_workbench_session_authenticator'"
    ).stdout.strip()
    function = psql(
        "SELECT procedure.prosecdef::text || ':' || owner.rolname || ':' || "
        "has_function_privilege('science_workbench_app', procedure.oid, "
        "'EXECUTE')::text || ':' || has_function_privilege("
        "'science_workbench_compliance', procedure.oid, 'EXECUTE')::text "
        "FROM pg_proc procedure JOIN pg_roles owner ON owner.oid = "
        "procedure.proowner WHERE procedure.proname = 'resolve_auth_session'"
    ).stdout.strip()
    absent = psql(
        "SET ROLE science_workbench_app; SELECT count(*) FROM "
        "resolve_auth_session(sha256('absent'::bytea))"
    ).stdout.strip()
    direct_table_access = psql(
        "SELECT has_table_privilege('science_workbench_app', 'auth_sessions', "
        "'SELECT')::text"
    ).stdout.strip()

    assert role == "false:true"
    assert function == ("true:science_workbench_session_authenticator:true:false")
    assert absent == "0"
    assert direct_table_access == "false"


def test_production_server_bounds_slow_clients_and_handler_concurrency(
    tmp_path: Path,
) -> None:
    port = _free_port()
    application = build_artifact_production_application(
        _environment(tmp_path, port),
        clock=FixedClock(),
        uuid7_factory=SequenceUuid7Factory(uuid7_values(128, 24)),
    )
    thread = _start(application)
    slow_clients: list[socket.socket] = []
    try:
        for _ in range(application.server.request_queue_size):
            client = socket.create_connection(("127.0.0.1", port), timeout=2)
            client.sendall(
                f"GET /api/v1/artifacts HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n".encode()
            )
            slow_clients.append(client)
        _wait_for_active_requests(application, application.server.request_queue_size)

        overflow = socket.create_connection(("127.0.0.1", port), timeout=2)
        try:
            overflow.sendall(b"GET / HTTP/1.1\r\n")
            try:
                overflow_result = overflow.recv(1)
            except ConnectionResetError:
                overflow_result = b""
            assert overflow_result == b""
        finally:
            overflow.close()

        slow_clients[0].settimeout(application.server.request_timeout_seconds + 1)
        assert slow_clients[0].recv(1) == b""
        _wait_for_active_requests(application, 0)
    finally:
        for client in slow_clients:
            client.close()
        _stop(application, thread)


def test_authenticated_artifact_http_survives_full_production_reconstruction(
    tmp_path: Path,
) -> None:
    _seed_http_principals()
    port = _free_port()
    environment = _environment(tmp_path, port)
    first = build_artifact_production_application(
        environment,
        clock=FixedClock(),
        uuid7_factory=SequenceUuid7Factory(uuid7_values(160, 24)),
    )
    first_thread = _start(first)

    rejected_body = {"project_id": PROJECT_A, "name": "Rejected"}
    fixture_auth = _request(
        port,
        HttpRequest(
            "POST",
            "/api/v1/auth/magic-link",
            "no-fixture-session",
            csrf=CSRF_A,
            body={"email": "fixture@example.invalid"},
        ),
    )
    wrong_csrf = _request(
        port,
        HttpRequest(
            "POST",
            "/api/v1/artifacts",
            COOKIE_A,
            csrf="wrong-csrf",
            body=rejected_body,
        ),
    )
    cross_origin = _request(
        port,
        HttpRequest(
            "POST",
            "/api/v1/artifacts",
            COOKIE_A,
            csrf=CSRF_A,
            body=rejected_body,
            origin="https://attacker.invalid",
        ),
    )
    forged = _request(
        port,
        HttpRequest("GET", "/api/v1/artifacts/absent", "forged-cookie"),
    )
    assert (
        fixture_auth.status,
        fixture_auth.body,
        wrong_csrf.status,
        cross_origin.status,
        forged.status,
    ) == (404, b'{"error":"not_found"}', 403, 403, 401)

    created = _request(
        port,
        HttpRequest(
            "POST",
            "/api/v1/artifacts",
            COOKIE_A,
            csrf=CSRF_A,
            body={"project_id": PROJECT_A, "name": "HTTP restart proof"},
        ),
    )
    assert created.status == 201
    artifact_id = cast("str", _json(created)["id"])
    scope = first.artifact_http.resolve_artifact_scope(
        UUID(ORG_A), UUID(USER_A), UUID(artifact_id)
    )
    assert scope is not None
    watcher_reference = first.stack.watcher.register(
        scope,
        UUID(EXECUTION),
        PAYLOAD,
        "text/plain",
    )
    version = _request(
        port,
        HttpRequest(
            "POST",
            f"/api/v1/artifacts/{artifact_id}/versions",
            COOKIE_A,
            csrf=CSRF_A,
            body=_version_body(watcher_reference, base_version_no=0),
        ),
    )
    assert version.status == 201
    version_id = cast("str", _json(version)["id"])
    before = _request(
        port,
        HttpRequest(
            "GET",
            f"/api/v1/artifacts/{artifact_id}/versions/{version_id}/download",
            COOKIE_A,
        ),
    )
    assert (
        before.status,
        before.body,
        before.content_type,
        before.content_disposition,
        before.content_security_policy,
    ) == (
        200,
        PAYLOAD,
        "application/octet-stream",
        'attachment; filename="artifact-version"',
        "default-src 'none'; sandbox",
    )

    _assert_recovery_failure_is_sanitized(
        CommittedArtifact(
            first,
            tmp_path / "recovery",
            port,
            scope,
            artifact_id,
            version_id,
        ),
        tmp_path,
    )
    _stop(first, first_thread)

    second = build_artifact_production_application(
        environment,
        clock=FixedClock(),
        uuid7_factory=SequenceUuid7Factory(uuid7_values(192, 24)),
    )
    second_thread = _start(second)
    try:
        persisted = _request(
            port,
            HttpRequest(
                "GET",
                f"/api/v1/artifacts/{artifact_id}/versions/{version_id}",
                COOKIE_A,
            ),
        )
        downloaded = _request(
            port,
            HttpRequest(
                "GET",
                f"/api/v1/artifacts/{artifact_id}/versions/{version_id}/download",
                COOKIE_A,
            ),
        )
        foreign = _request(
            port,
            HttpRequest(
                "GET",
                f"/api/v1/artifacts/{artifact_id}/versions/{version_id}",
                COOKIE_B,
            ),
        )
        absent = _request(
            port,
            HttpRequest(
                "GET",
                f"/api/v1/artifacts/{artifact_id}/versions/"
                "018f47a0-7b9c-7dff-8def-0123456789ab",
                COOKIE_B,
            ),
        )
        wrong_host = _request(
            port,
            HttpRequest(
                "GET",
                f"/api/v1/artifacts/{artifact_id}/versions/{version_id}",
                COOKIE_A,
                host="attacker.invalid",
            ),
        )
        duplicate_host = _duplicate_host_request(
            port,
            f"/api/v1/artifacts/{artifact_id}/versions/{version_id}",
            COOKIE_A,
        )
        second.server.session_authority.revoke(COOKIE_B)
        revoked = _request(
            port,
            HttpRequest(
                "GET",
                f"/api/v1/artifacts/{artifact_id}/versions/{version_id}",
                COOKIE_B,
            ),
        )
        raced_statuses = _archive_race_statuses(second, artifact_id, version_id)
    finally:
        _restore_project()
        _stop(second, second_thread)

    assert persisted.status == 200
    assert _json(persisted)["id"] == version_id
    assert (downloaded.status, downloaded.body) == (200, PAYLOAD)
    assert (foreign.status, foreign.body, foreign.content_type) == (
        absent.status,
        absent.body,
        absent.content_type,
    )
    assert wrong_host.status == 403
    assert duplicate_host.status == 403
    assert revoked.status == 401
    assert raced_statuses == (404, 404, 404)
    count = psql(
        f"SELECT count(*) FROM artifact_versions WHERE artifact_id = '{artifact_id}'"
    ).stdout.strip()
    assert count == "1"


def test_persisted_browser_bootstraps_csrf_after_production_restart(
    tmp_path: Path,
) -> None:
    _seed_http_principals()
    port = _free_port()
    environment = _environment(tmp_path, port)
    first = build_artifact_production_application(environment, clock=FixedClock())
    first_thread = _start(first)
    try:
        initial = _request(
            port,
            HttpRequest(
                "GET",
                "/api/v1/me",
                COOKIE_A,
                csrf_cookie=CSRF_A,
            ),
        )
    finally:
        _stop(first, first_thread)

    second = build_artifact_production_application(environment, clock=FixedClock())
    second_thread = _start(second)
    try:
        reloaded = _request(
            port,
            HttpRequest(
                "GET",
                "/api/v1/me",
                COOKIE_A,
                csrf_cookie=CSRF_A,
            ),
        )
        duplicate = _request(
            port,
            HttpRequest(
                "GET",
                "/api/v1/me",
                COOKIE_A,
                csrf_cookie=f"{CSRF_A}; product_csrf={CSRF_A}",
            ),
        )
        reloaded_csrf = cast("str", _json(reloaded)["csrf_token"])
        mutated = _request(
            port,
            HttpRequest(
                "POST",
                "/api/v1/artifacts",
                COOKIE_A,
                csrf=reloaded_csrf,
                csrf_cookie=CSRF_A,
                body={"project_id": PROJECT_A, "name": "Reloaded browser proof"},
            ),
        )
    finally:
        _stop(second, second_thread)

    assert (initial.status, reloaded.status, duplicate.status, mutated.status) == (
        200,
        200,
        401,
        201,
    )
    assert _json(initial)["csrf_token"] == reloaded_csrf == CSRF_A
    assert hashlib.sha256(CSRF_A.encode()).hexdigest().encode() not in reloaded.body
