"""HTTP-to-Postgres persistence coverage for provider connections."""

from __future__ import annotations

import json
import tempfile
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from http.client import HTTPConnection
from pathlib import Path
from secrets import token_urlsafe
from threading import Lock, Thread
from typing import TYPE_CHECKING, Final, cast, override
from uuid import UUID, uuid4

import pytest
from pydantic import TypeAdapter
from services.api.product_app import (
    Principal,
    ProductServer,
    ProductServerOptions,
    ProviderAuthorization,
    ProviderDiagnosticRecord,
    ProviderDiagnosticSink,
    ProviderOAuthBroker,
    run_product_server,
)
from services.api.provider_cleanup_cli import main as cleanup_main
from services.api.provider_cleanup_postgres import (
    PostgresProviderCleanupSweeper,
    ProviderCleanupSweepResult,
)
from services.api.provider_model_id import PROVIDER_MODEL_ID_MAX_CHARACTERS
from services.api.provider_postgres import (
    PostgresProviderPersistence,
    RuntimeHomeDestroyer,
)
from services.api.provider_runtime import (
    PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    Health,
    OAuthClaim,
    OfficialOAuthCompletion,
    ProviderCompletionAdoption,
    ProviderConnection,
    ProviderPrincipal,
    ProviderRuntimeError,
    ProviderRuntimeService,
    ProviderUpsertControl,
)
from services.api.provider_uds import (
    SecureProviderUnixServer,
    canonical_provider_json,
    strict_provider_json,
)
from services.api.tests.persistence.postgres_harness import (
    database_url_asyncpg,
    psql,
)
from services.api.tests.persistence.test_rls import (
    ORG_A,
    ORG_B,
    USER_A,
    USER_B,
    seed_tenants,
)
from sqlalchemy.engine import make_url

if TYPE_CHECKING:
    from collections.abc import Callable, Iterator


def _socket_temp_base() -> str:
    """Short, real (non-symlink) temp root: /private/tmp on macOS, /tmp elsewhere."""
    return "/private/tmp" if Path("/private/tmp").is_dir() else "/tmp"  # noqa: S108


pytest_plugins = ("services.api.tests.persistence.conftest",)
pytestmark = pytest.mark.usefixtures("migrated_database")

_LOOPBACK: Final = "127.0.0.1"
_SHA256_EVIDENCE: Final = "a" * 64
_DESTROY_FAILURE: Final = "destroy failed"
_CLEANUP_LOGIN: Final = "science_workbench_cleanup_test"
_CLEANUP_PASSWORD: Final = token_urlsafe(24)
_RESPONSE = TypeAdapter(dict[str, object])


@pytest.fixture(autouse=True)
def isolate_provider_database_state() -> Iterator[None]:
    reset = (
        "TRUNCATE TABLE provider_runtime_home_cleanups, "
        "provider_qualification_legacy_evidence, runs, "
        "provider_qualification_receipts, provider_connections CASCADE"
    )
    _ = psql(reset)
    try:
        yield
    finally:
        _ = psql(reset)


def _clock() -> datetime:
    return datetime(2026, 7, 13, tzinfo=UTC)


def _completion(runtime_home_ref: str, account_id: str) -> OfficialOAuthCompletion:
    return OfficialOAuthCompletion(
        runtime_home_ref,
        account_id,
        ("codex-mini", "codex-max"),
        {"issuer": "official"},
        "fixture-staging-lease",
        _clock() + PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window,
    )


def _confirm_adoption(
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


class _DiagnosticSink(ProviderDiagnosticSink):
    """Thread-safe durable diagnostic fixture."""

    def __init__(self) -> None:
        self.records: list[ProviderDiagnosticRecord] = []
        self._lock: Lock = Lock()

    @override
    def append(self, record: ProviderDiagnosticRecord) -> None:
        with self._lock:
            self.records.append(record)


@dataclass(frozen=True, slots=True)
class _Response:
    status: int
    body: dict[str, object]


@dataclass(frozen=True, slots=True)
class _RequestSpec:
    method: str
    path: str
    payload: dict[str, object] | None = None
    headers: dict[str, str] | None = None


class _Destroyer(RuntimeHomeDestroyer):
    def __init__(self) -> None:
        self.refs: list[str] = []
        self.fail: bool = False

    @override
    def destroy(self, opaque_ref: str) -> str:
        self.refs.append(opaque_ref)
        if self.fail:
            raise RuntimeError(_DESTROY_FAILURE)
        return _SHA256_EVIDENCE


def test_persistence_rejects_out_of_contract_provider_model_before_database() -> None:
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        _Destroyer(),
        clock=_clock,
        cleanup_window=(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    )
    connection = ProviderConnection(
        connection_id="018f0d7d-6b17-7a91-8b31-2f7331677d10",
        adapter_id="openai_codex",
        account_id="account-redacted",
        eligible_models=("m" * (PROVIDER_MODEL_ID_MAX_CHARACTERS + 1),),
        selected_model=None,
        health="pending",
        cleanup_verified=False,
        qualified_live=False,
        created_at=_clock(),
        revision=1,
        qualification=None,
    )

    with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
        persistence.upsert(
            ProviderPrincipal(USER_A, ORG_A),
            connection,
            "vault://runtime/connection/model-contract",
            ProviderUpsertControl(expected_revision=None),
        )


def _cleanup_service_database_url() -> str:
    _ = psql(
        "DO $$ BEGIN CREATE ROLE science_workbench_provider_cleanup NOLOGIN; "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$; "
        "ALTER ROLE science_workbench_provider_cleanup WITH NOLOGIN NOSUPERUSER "
        "NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; "
        "DO $$ BEGIN CREATE ROLE science_workbench_cleanup_test LOGIN; "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$; "
        f"ALTER ROLE science_workbench_cleanup_test WITH LOGIN PASSWORD "
        f"'{_CLEANUP_PASSWORD}' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT "
        "NOREPLICATION NOBYPASSRLS; "
        "DO $$ BEGIN CREATE ROLE science_workbench_cleanup_extra NOLOGIN; "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$; "
        "ALTER ROLE science_workbench_cleanup_extra WITH NOLOGIN NOSUPERUSER "
        "NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS; "
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "
        "science_workbench_cleanup_test; "
        "REVOKE science_workbench_app FROM science_workbench_cleanup_test; "
        "REVOKE ADMIN OPTION FOR science_workbench_provider_cleanup FROM "
        "science_workbench_cleanup_test; "
        "REVOKE science_workbench_cleanup_extra FROM "
        "science_workbench_provider_cleanup; "
        "GRANT science_workbench_provider_cleanup TO "
        "science_workbench_cleanup_test WITH ADMIN FALSE, INHERIT FALSE, SET TRUE; "
        "GRANT USAGE ON SCHEMA public TO science_workbench_provider_cleanup; "
        "REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM "
        "science_workbench_provider_cleanup"
    )
    return (
        make_url(database_url_asyncpg())
        .set(
            username=_CLEANUP_LOGIN,
            password=_CLEANUP_PASSWORD,
        )
        .render_as_string(hide_password=False)
    )


def _cleanup_sweeper(
    destroyer: RuntimeHomeDestroyer,
    *,
    clock: Callable[[], datetime],
) -> PostgresProviderCleanupSweeper:
    return PostgresProviderCleanupSweeper(
        _cleanup_service_database_url(),
        destroyer,
        clock=clock,
        expected_login_role=_CLEANUP_LOGIN,
    )


class _Broker(ProviderOAuthBroker):
    def __init__(
        self, runtime_home_ref: str = "vault://runtime/connection/postgres"
    ) -> None:
        self.adopted: list[str] = []
        self.discarded: list[str] = []
        self.runtime_home_ref: str = runtime_home_ref

    @override
    def authorize(
        self, adapter_id: str, state: str, flow: str, redirect_uri: str
    ) -> ProviderAuthorization:
        assert adapter_id == "openai_codex"
        assert state
        assert flow == "callback"
        assert redirect_uri == "/settings/providers"
        return ProviderAuthorization(
            authorization_url=f"https://provider.example.test/authorize?state={state}"
        )

    @override
    def exchange(self, claim: OAuthClaim) -> OfficialOAuthCompletion:
        assert claim.adapter_id == "openai_codex"
        assert claim.state
        assert claim.flow == "callback"
        assert claim.redirect_uri == "/settings/providers"
        return OfficialOAuthCompletion(
            self.runtime_home_ref,
            "account-redacted",
            ("codex-mini", "codex-max"),
            {"issuer": "official"},
            claim.claim_id,
            claim.expires_at,
        )

    @override
    def adopt_completion(
        self, adoption: ProviderCompletionAdoption, connection: ProviderConnection
    ) -> None:
        assert connection.connection_id == adoption.connection_id
        self.adopted.append(adoption.staging_lease_id)

    @override
    def abandon_completion(self, completion: OfficialOAuthCompletion) -> None:
        assert completion.vault_home_ref.startswith("vault://runtime/connection/")
        self.discarded.append(completion.staging_lease_id)

    @override
    def health(self, connection: ProviderConnection) -> Health:
        assert connection.connection_id
        return "healthy"


class _FailingAdoptionBroker(_Broker):
    def __init__(self) -> None:
        super().__init__()
        self.fail_adoption: bool = True

    @override
    def adopt_completion(
        self, adoption: ProviderCompletionAdoption, connection: ProviderConnection
    ) -> None:
        if self.fail_adoption:
            raise RuntimeError(_DESTROY_FAILURE)
        super().adopt_completion(adoption, connection)


def _request(server: ProductServer, cookie: str, spec: _RequestSpec) -> _Response:
    request_headers = {"Cookie": cookie} | (spec.headers or {})
    if spec.payload is not None:
        request_headers["Content-Type"] = "application/json"
    connection = HTTPConnection(_LOOPBACK, server.server_port)
    try:
        connection.request(
            spec.method,
            spec.path,
            json.dumps(spec.payload).encode() if spec.payload is not None else None,
            request_headers,
        )
        response = connection.getresponse()
        return _Response(response.status, _RESPONSE.validate_json(response.read()))
    finally:
        connection.close()


def _same_origin(server: ProductServer, **extra: str) -> dict[str, str]:
    return {
        "Origin": f"http://{_LOOPBACK}:{server.server_port}",
        "Sec-Fetch-Site": "same-origin",
        "Sec-Fetch-Mode": "cors",
        "X-CSRF-Token": server.fixture_csrf_token(),
        **extra,
    }


def _connection_row(connection_id: str | None = None) -> dict[str, object]:
    result = psql(
        "SELECT json_build_object("
        "'id', id, 'org_id', org_id, 'requester_user_id', requester_user_id, "
        "'adapter_id', adapter_id, 'account_metadata', account_metadata, "
        "'selected_model', selected_model, 'status', status, "
        "'qualified_at', qualified_at IS NOT NULL, "
        "'runtime_ref', encrypted_runtime_home_ref, "
        "'superseded_runtime_ref', superseded_runtime_home_ref, "
        "'health_checked_at', health_checked_at IS NOT NULL, "
        "'revoked_at', revoked_at IS NOT NULL)::text "
        "FROM provider_connections ORDER BY created_at DESC, id DESC"
    )
    rows = tuple(
        _RESPONSE.validate_json(line) for line in result.stdout.splitlines() if line
    )
    if connection_id is None:
        return rows[0]
    normalized_id = str(UUID(connection_id))
    return next(row for row in rows if row["id"] == normalized_id)


def _cleanup_row(runtime_home_ref: str) -> dict[str, object]:
    result = psql(
        "SELECT json_build_object('runtime_ref', encrypted_runtime_home_ref, "
        "'connection_id', connection_id, 'reason', reason, 'status', status, "
        "'requested_at', requested_at, 'destroy_by', destroy_by, "
        "'destroyed_at', destroyed_at, 'evidence_sha256', evidence_sha256)::text "
        "FROM provider_runtime_home_cleanups ORDER BY created_at"
    )
    rows = tuple(
        _RESPONSE.validate_json(line) for line in result.stdout.splitlines() if line
    )
    return next(row for row in rows if row["runtime_ref"] == runtime_home_ref)


def _assert_revoke_cleanup_reservations(
    connection_id: str, source_ref: str, status: str
) -> None:
    for runtime_ref in (
        source_ref,
        f"vault://runtime/destroyed/{connection_id}",
    ):
        reservation = _cleanup_row(runtime_ref)
        assert reservation["connection_id"] == connection_id
        assert reservation["reason"] == "revoke"
        assert reservation["status"] == status


def _other_requester_connection_count_query() -> str:
    return (
        "SET ROLE science_workbench_app; "
        "SELECT set_config('app.org_id', "
        "'018f0d7d-6b17-7a91-8b31-2f7331677a01', false); "
        "SELECT set_config('app.user_id', "
        "'018f0d7d-6b17-7a91-8b31-2f7331677a03', false); "
        "SELECT count(*) FROM provider_connections"
    )


def _assert_created_connection(connection_id: str) -> None:
    created = _connection_row()
    assert created["id"] == connection_id
    metadata = created["account_metadata"]
    assert isinstance(metadata, dict)
    assert created["org_id"] == ORG_A
    assert created["requester_user_id"] == USER_A
    assert created["adapter_id"] == "openai_codex"
    assert connection_id[14] == "7"
    assert created["selected_model"] is None
    assert created["status"] == "pending"
    assert created["runtime_ref"] == "vault://runtime/connection/postgres"
    assert metadata == {
        "account_id": "account-redacted",
        "models": ["codex-mini", "codex-max"],
        "provider": "openai_codex",
        "revision": "1",
    }
    assert "vault" not in json.dumps(metadata)
    assert "token" not in json.dumps(metadata)

    hidden = psql(_other_requester_connection_count_query())
    assert hidden.stdout.splitlines()[-1] == "0"


def _complete_connection(
    server: ProductServer, cookie: str, state: object
) -> _Response:
    return _request(
        server,
        cookie,
        _RequestSpec(
            "POST",
            "/api/v1/provider-connections/oauth/complete",
            {
                "state": state,
                "flow": "callback",
                "redirect_uri": "/settings/providers",
            },
            _same_origin(server, **{"Idempotency-Key": "postgres-complete"}),
        ),
    )


def _assert_completed_connection(response: _Response) -> str:
    assert response.status == 200
    response_text = json.dumps(response.body)
    assert "vault" not in response_text
    assert "token" not in response_text
    assert "authorization_response" not in response_text
    return str(response.body["id"])


def _assert_completed_sweep(result: ProviderCleanupSweepResult) -> None:
    assert result.scanned == 1
    assert result.completed == 1
    assert result.failed == 0


def test_requester_persistence_has_no_cross_tenant_sweep_surface() -> None:
    assert not hasattr(PostgresProviderPersistence, "sweep_due_cleanups")


def test_cleanup_sweeper_rejects_the_database_owner_login() -> None:
    seed_tenants()
    destroyer = _Destroyer()
    sweeper = PostgresProviderCleanupSweeper(
        database_url_asyncpg(),
        destroyer,
        clock=_clock,
        expected_login_role=_CLEANUP_LOGIN,
    )

    with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
        _ = sweeper.sweep_due_cleanups()

    assert destroyer.refs == []


def test_cleanup_service_login_accepts_exact_baseline() -> None:
    seed_tenants()
    result = _cleanup_sweeper(_Destroyer(), clock=_clock).sweep_due_cleanups()

    assert result.scanned == 0
    assert result.completed == 0
    assert result.failed == 0


@pytest.mark.parametrize(
    ("mutation", "rollback"),
    [
        (
            "GRANT science_workbench_app TO science_workbench_cleanup_test",
            "REVOKE science_workbench_app FROM science_workbench_cleanup_test",
        ),
        (
            "GRANT SELECT ON organizations TO science_workbench_cleanup_test",
            "REVOKE ALL PRIVILEGES ON organizations FROM "
            "science_workbench_cleanup_test",
        ),
        (
            "GRANT science_workbench_provider_cleanup TO "
            "science_workbench_cleanup_test WITH ADMIN OPTION",
            "REVOKE ADMIN OPTION FOR science_workbench_provider_cleanup FROM "
            "science_workbench_cleanup_test",
        ),
        (
            "GRANT science_workbench_provider_cleanup TO "
            "science_workbench_cleanup_test WITH INHERIT TRUE",
            "GRANT science_workbench_provider_cleanup TO "
            "science_workbench_cleanup_test WITH INHERIT FALSE",
        ),
        (
            "GRANT science_workbench_provider_cleanup TO "
            "science_workbench_cleanup_test WITH SET FALSE",
            "GRANT science_workbench_provider_cleanup TO "
            "science_workbench_cleanup_test WITH SET TRUE",
        ),
        (
            "CREATE ROLE provider_cleanup_login_child LOGIN NOINHERIT; GRANT "
            "science_workbench_cleanup_test TO provider_cleanup_login_child",
            "REVOKE science_workbench_cleanup_test FROM "
            "provider_cleanup_login_child; DROP ROLE provider_cleanup_login_child",
        ),
        (
            "GRANT science_workbench_cleanup_extra TO "
            "science_workbench_provider_cleanup",
            "REVOKE science_workbench_cleanup_extra FROM "
            "science_workbench_provider_cleanup",
        ),
        (
            "CREATE FUNCTION public.provider_test_surplus() RETURNS boolean "
            "LANGUAGE sql IMMUTABLE AS $$ SELECT true $$; GRANT EXECUTE ON "
            "FUNCTION public.provider_test_surplus() TO PUBLIC",
            "DROP FUNCTION IF EXISTS public.provider_test_surplus()",
        ),
        (
            "GRANT SELECT (name) ON organizations TO science_workbench_cleanup_test",
            "REVOKE SELECT (name) ON organizations FROM science_workbench_cleanup_test",
        ),
        (
            "CREATE FOREIGN DATA WRAPPER provider_test_fdw NO HANDLER NO VALIDATOR; "
            "GRANT USAGE ON FOREIGN DATA WRAPPER provider_test_fdw TO "
            "science_workbench_cleanup_test",
            "REVOKE USAGE ON FOREIGN DATA WRAPPER provider_test_fdw FROM "
            "science_workbench_cleanup_test; DROP FOREIGN DATA WRAPPER "
            "provider_test_fdw",
        ),
        (
            "CREATE FOREIGN DATA WRAPPER provider_test_fdw NO HANDLER NO VALIDATOR; "
            "CREATE SERVER provider_test_server FOREIGN DATA WRAPPER "
            "provider_test_fdw; GRANT USAGE ON FOREIGN SERVER provider_test_server "
            "TO science_workbench_provider_cleanup",
            "REVOKE USAGE ON FOREIGN SERVER provider_test_server FROM "
            "science_workbench_provider_cleanup; DROP SERVER provider_test_server; "
            "DROP FOREIGN DATA WRAPPER provider_test_fdw",
        ),
        (
            "GRANT USAGE ON LANGUAGE plpgsql TO science_workbench_cleanup_test",
            "REVOKE USAGE ON LANGUAGE plpgsql FROM science_workbench_cleanup_test",
        ),
        (
            "GRANT CREATE ON TABLESPACE pg_default TO "
            "science_workbench_provider_cleanup",
            "REVOKE CREATE ON TABLESPACE pg_default FROM "
            "science_workbench_provider_cleanup",
        ),
        (
            "SELECT lo_create(987654321); GRANT SELECT ON LARGE OBJECT 987654321 TO "
            "science_workbench_provider_cleanup",
            "REVOKE SELECT ON LARGE OBJECT 987654321 FROM "
            "science_workbench_provider_cleanup; SELECT lo_unlink(987654321)",
        ),
        (
            "GRANT SET ON PARAMETER work_mem TO science_workbench_provider_cleanup",
            "REVOKE SET ON PARAMETER work_mem FROM science_workbench_provider_cleanup",
        ),
        (
            "CREATE FOREIGN DATA WRAPPER provider_test_owned_fdw NO HANDLER NO "
            "VALIDATOR; GRANT USAGE ON FOREIGN DATA WRAPPER provider_test_owned_fdw "
            "TO science_workbench_provider_cleanup; CREATE SERVER "
            "provider_test_owned_server FOREIGN DATA WRAPPER "
            "provider_test_owned_fdw; ALTER SERVER provider_test_owned_server OWNER "
            "TO science_workbench_provider_cleanup; REVOKE USAGE ON FOREIGN DATA "
            "WRAPPER provider_test_owned_fdw FROM "
            "science_workbench_provider_cleanup",
            "ALTER SERVER provider_test_owned_server OWNER TO science_workbench; "
            "DROP SERVER provider_test_owned_server; DROP FOREIGN DATA WRAPPER "
            "provider_test_owned_fdw",
        ),
        (
            "SELECT lo_create(987654322); ALTER LARGE OBJECT 987654322 OWNER TO "
            "science_workbench_provider_cleanup",
            "ALTER LARGE OBJECT 987654322 OWNER TO science_workbench; SELECT "
            "lo_unlink(987654322)",
        ),
        (
            "GRANT EXECUTE ON FUNCTION public.provider_due_cleanup_candidates("
            "timestamptz) TO science_workbench_provider_cleanup WITH GRANT OPTION",
            "REVOKE GRANT OPTION FOR EXECUTE ON FUNCTION "
            "public.provider_due_cleanup_candidates(timestamptz) FROM "
            "science_workbench_provider_cleanup",
        ),
        (
            "GRANT SELECT ON public.organizations TO PUBLIC",
            "REVOKE SELECT ON public.organizations FROM PUBLIC",
        ),
        (
            "CREATE SEQUENCE public.provider_test_public_sequence; GRANT USAGE ON "
            "SEQUENCE public.provider_test_public_sequence TO PUBLIC",
            "DROP SEQUENCE public.provider_test_public_sequence",
        ),
        (
            "CREATE FOREIGN DATA WRAPPER provider_test_public_fdw NO HANDLER NO "
            "VALIDATOR; GRANT USAGE ON FOREIGN DATA WRAPPER "
            "provider_test_public_fdw TO PUBLIC",
            "DROP FOREIGN DATA WRAPPER provider_test_public_fdw",
        ),
        (
            "CREATE FOREIGN DATA WRAPPER provider_test_public_server_fdw NO HANDLER "
            "NO VALIDATOR; CREATE SERVER provider_test_public_server FOREIGN DATA "
            "WRAPPER provider_test_public_server_fdw; GRANT USAGE ON FOREIGN SERVER "
            "provider_test_public_server TO PUBLIC",
            "DROP SERVER provider_test_public_server; DROP FOREIGN DATA WRAPPER "
            "provider_test_public_server_fdw",
        ),
        (
            "SELECT lo_create(987654323); GRANT SELECT ON LARGE OBJECT 987654323 TO "
            "PUBLIC",
            "REVOKE SELECT ON LARGE OBJECT 987654323 FROM PUBLIC; SELECT "
            "lo_unlink(987654323)",
        ),
        (
            "ALTER DEFAULT PRIVILEGES FOR ROLE science_workbench IN SCHEMA public "
            "GRANT SELECT ON TABLES TO science_workbench_provider_cleanup",
            "ALTER DEFAULT PRIVILEGES FOR ROLE science_workbench IN SCHEMA public "
            "REVOKE SELECT ON TABLES FROM science_workbench_provider_cleanup",
        ),
        (
            "GRANT CREATE ON DATABASE science_workbench TO PUBLIC",
            "REVOKE CREATE ON DATABASE science_workbench FROM PUBLIC",
        ),
        (
            "CREATE PUBLICATION provider_test_owned_publication; ALTER PUBLICATION "
            "provider_test_owned_publication OWNER TO "
            "science_workbench_provider_cleanup",
            "ALTER PUBLICATION provider_test_owned_publication OWNER TO "
            "science_workbench; DROP PUBLICATION provider_test_owned_publication",
        ),
        (
            "CREATE SCHEMA provider_test_evil; GRANT USAGE ON SCHEMA "
            "provider_test_evil TO PUBLIC; CREATE FUNCTION "
            "provider_test_evil.read_secret() RETURNS text LANGUAGE sql SECURITY "
            "DEFINER AS $$ SELECT 'secret'::text $$; GRANT EXECUTE ON FUNCTION "
            "provider_test_evil.read_secret() TO PUBLIC",
            "DROP SCHEMA provider_test_evil CASCADE",
        ),
        (
            "CREATE ROLE provider_cleanup_rogue LOGIN NOINHERIT; GRANT "
            "science_workbench_provider_cleanup TO provider_cleanup_rogue",
            "REVOKE science_workbench_provider_cleanup FROM provider_cleanup_rogue; "
            "DROP ROLE provider_cleanup_rogue",
        ),
        (
            "ALTER ROLE science_workbench_provider_cleanup_definer LOGIN",
            "ALTER ROLE science_workbench_provider_cleanup_definer NOLOGIN",
        ),
        (
            "GRANT SELECT ON organizations TO "
            "science_workbench_provider_cleanup_definer",
            "REVOKE SELECT ON organizations FROM "
            "science_workbench_provider_cleanup_definer",
        ),
        (
            "GRANT science_workbench_cleanup_extra TO "
            "science_workbench_provider_cleanup_definer",
            "REVOKE science_workbench_cleanup_extra FROM "
            "science_workbench_provider_cleanup_definer",
        ),
        (
            "ALTER FUNCTION public.validate_due_provider_cleanup(uuid,uuid,uuid,"
            "text,text,timestamptz) RESET ALL",
            "ALTER FUNCTION public.validate_due_provider_cleanup(uuid,uuid,uuid,"
            "text,text,timestamptz) SET search_path TO pg_catalog, pg_temp",
        ),
        (
            "ALTER FUNCTION public.validate_due_provider_cleanup(uuid,uuid,uuid,"
            "text,text,timestamptz) SECURITY INVOKER",
            "ALTER FUNCTION public.validate_due_provider_cleanup(uuid,uuid,uuid,"
            "text,text,timestamptz) SECURITY DEFINER",
        ),
        (
            "CREATE FUNCTION public.cleanup_definer_surplus() RETURNS boolean "
            "LANGUAGE sql SECURITY DEFINER SET search_path = pg_catalog, pg_temp "
            "AS $$ SELECT true $$; ALTER FUNCTION "
            "public.cleanup_definer_surplus() OWNER TO "
            "science_workbench_provider_cleanup_definer",
            "ALTER FUNCTION public.cleanup_definer_surplus() OWNER TO "
            "science_workbench; DROP FUNCTION public.cleanup_definer_surplus()",
        ),
        (
            "GRANT EXECUTE ON FUNCTION public.provider_due_cleanup_candidates("
            "timestamptz) TO science_workbench_cleanup_extra",
            "REVOKE EXECUTE ON FUNCTION public.provider_due_cleanup_candidates("
            "timestamptz) FROM science_workbench_cleanup_extra",
        ),
    ],
    ids=(
        "extra-membership",
        "direct-grant",
        "admin-option",
        "membership-inherit-option",
        "membership-set-option",
        "login-rogue-member",
        "capability-parent",
        "public-function",
        "login-column",
        "login-foreign-data-wrapper",
        "capability-foreign-server",
        "login-language",
        "capability-tablespace",
        "capability-large-object",
        "capability-parameter",
        "capability-owned-foreign-server",
        "capability-owned-large-object",
        "capability-grant-option",
        "public-table",
        "public-sequence",
        "public-foreign-data-wrapper",
        "public-foreign-server",
        "public-large-object",
        "capability-default-acl",
        "public-database-create",
        "capability-owned-publication",
        "non-public-schema-function",
        "capability-rogue-member",
        "definer-login",
        "definer-direct-grant",
        "definer-membership",
        "definer-search-path",
        "definer-security-invoker",
        "definer-surplus-function",
        "definer-function-rogue-execute",
    ),
)
def test_cleanup_sweeper_rejects_expanded_login_authority(
    mutation: str, rollback: str
) -> None:
    seed_tenants()
    service_database_url = _cleanup_service_database_url()
    _ = psql(mutation)
    destroyer = _Destroyer()
    try:
        with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
            _ = PostgresProviderCleanupSweeper(
                service_database_url,
                destroyer,
                clock=_clock,
                expected_login_role=_CLEANUP_LOGIN,
            ).sweep_due_cleanups()
    finally:
        _ = psql(rollback)
    assert destroyer.refs == []


def test_cleanup_cli_fails_closed_without_service_authorities(
    capsys: pytest.CaptureFixture[str],
) -> None:
    assert cleanup_main((), {}) == 2
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == "provider_cleanup_failed\n"


def test_cleanup_cli_runs_fixed_sweep_through_protected_vault_socket(
    capsys: pytest.CaptureFixture[str],
) -> None:
    seed_tenants()
    runtime_home_ref = "vault://runtime/connection/cli-sweep"
    failing_destroyer = _Destroyer()
    failing_destroyer.fail = True
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        failing_destroyer,
        clock=_clock,
        cleanup_window=(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    )
    with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
        persistence.discard_runtime_home(
            ProviderPrincipal(USER_A, ORG_A), runtime_home_ref
        )
    requests: list[dict[str, object]] = []

    def destroy(source: bytes) -> bytes:
        requests.append(dict(strict_provider_json(source)))
        return canonical_provider_json(
            {"schema_version": 1, "evidence_sha256": _SHA256_EVIDENCE}
        )

    with tempfile.TemporaryDirectory(
        prefix="nq-sock-", dir=_socket_temp_base()
    ) as socket_dir:
        socket_root = Path(socket_dir)
        socket_path = socket_root / f"pc-{uuid4().hex[:8]}.sock"
        server = SecureProviderUnixServer(socket_path, destroy)
        server_thread = Thread(target=server.serve_forever)
        server_thread.start()
        try:
            exit_code = cleanup_main(
                (),
                {
                    "PROVIDER_CLEANUP_DATABASE_URL": _cleanup_service_database_url(),
                    "PROVIDER_CLEANUP_EXPECTED_LOGIN_ROLE": _CLEANUP_LOGIN,
                    "PROVIDER_CLEANUP_VAULT_SOCKET": str(socket_path),
                },
            )
        finally:
            server.shutdown()
            server_thread.join()
            server.server_close()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert captured.out == '{"completed":1,"failed":0,"scanned":1}\n'
    assert captured.err == ""
    assert requests == [
        {
            "schema_version": 1,
            "operation": "destroy_provider_runtime_home",
            "runtime_home_ref": runtime_home_ref,
        }
    ]
    assert _cleanup_row(runtime_home_ref)["status"] == "completed"


def _listed_connection(response: _Response, connection_id: str) -> dict[str, object]:
    connections = response.body["connections"]
    assert isinstance(connections, list)
    validated = (
        _RESPONSE.validate_python(item) for item in cast("list[object]", connections)
    )
    return next(item for item in validated if item.get("id") == connection_id)


def _restart_with_persistence(
    destroyer: _Destroyer,
) -> tuple[ProductServer, ProviderRuntimeService, str]:
    runtime = ProviderRuntimeService(
        _clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            destroyer,
            clock=_clock,
            cleanup_window=(
                PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
            ),
        ),
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    server = run_product_server(
        authenticated_fixture=True,
        options=ProductServerOptions(
            principal=Principal(USER_A, ORG_A, "a@example.test", "A"),
            provider_runtime=runtime,
            provider_oauth_broker=_Broker(),
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    return server, runtime, server.fixture_session_cookie()


def _restart_and_assert_restored(
    server: ProductServer,
    destroyer: _Destroyer,
    selected: _Response,
) -> tuple[ProductServer, ProviderRuntimeService, str]:
    server.shutdown()
    server.server_close()
    restarted, runtime, cookie = _restart_with_persistence(destroyer)
    restored = _request(
        restarted,
        cookie,
        _RequestSpec("GET", "/api/v1/provider-connections"),
    )
    assert restored.status == 200
    assert restored.body["connections"] == [selected.body]
    return restarted, runtime, cookie


def test_http_provider_lifecycle_persists_only_safe_requester_owned_data() -> None:
    seed_tenants()
    destroyer = _Destroyer()
    runtime = ProviderRuntimeService(
        _clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            destroyer,
            clock=_clock,
            cleanup_window=(
                PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
            ),
        ),
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    server = run_product_server(
        authenticated_fixture=True,
        options=ProductServerOptions(
            principal=Principal(USER_A, ORG_A, "a@example.test", "A"),
            provider_runtime=runtime,
            provider_oauth_broker=_Broker(),
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        initiated = _request(
            server,
            cookie,
            _RequestSpec(
                "POST",
                "/api/v1/provider-connections",
                {
                    "adapter_id": "openai_codex",
                    "flow": "callback",
                    "redirect_uri": "/settings/providers",
                },
                _same_origin(server, **{"Idempotency-Key": "postgres-init"}),
            ),
        )
        assert initiated.status == 202
        completed = _complete_connection(server, cookie, initiated.body["state"])
        connection_id = _assert_completed_connection(completed)
        _assert_created_connection(connection_id)

        selected = _request(
            server,
            cookie,
            _RequestSpec(
                "POST",
                f"/api/v1/provider-connections/{connection_id}/model",
                {"model_id": "codex-mini"},
                _same_origin(
                    server,
                    **{
                        "Idempotency-Key": "postgres-select",
                        "If-Match": str(completed.body["revision"]),
                    },
                ),
            ),
        )
        assert selected.status == 200

        server, runtime, cookie = _restart_and_assert_restored(
            server, destroyer, selected
        )

        stale = _request(
            server,
            cookie,
            _RequestSpec(
                "POST",
                f"/api/v1/provider-connections/{connection_id}/model",
                {"model_id": "codex-max"},
                _same_origin(
                    server,
                    **{
                        "Idempotency-Key": "postgres-stale",
                        "If-Match": str(completed.body["revision"]),
                    },
                ),
            ),
        )
        assert stale.status == 412
        unqualified_health = _request(
            server,
            cookie,
            _RequestSpec(
                "POST",
                f"/api/v1/provider-connections/{connection_id}/health",
                {},
                _same_origin(
                    server,
                    **{
                        "Idempotency-Key": "postgres-health",
                        "If-Match": str(selected.body["revision"]),
                    },
                ),
            ),
        )
        assert unqualified_health.status == 409
        unqualified = _connection_row()
        assert unqualified["selected_model"] == "codex-mini"
        assert unqualified["status"] == "pending"
        assert unqualified["qualified_at"] is False
        assert unqualified["health_checked_at"] is False

        revoked = _request(
            server,
            cookie,
            _RequestSpec(
                "DELETE",
                f"/api/v1/provider-connections/{connection_id}",
                headers=_same_origin(
                    server, **{"If-Match": str(selected.body["revision"])}
                ),
            ),
        )
        assert revoked.status == 200
        receipt = runtime.cleanup_receipt(
            ProviderPrincipal(USER_A, ORG_A), connection_id
        )
        assert receipt.evidence_sha256 == _SHA256_EVIDENCE
        assert receipt.destroyed_at >= receipt.requested_at
        cleanup = revoked.body["cleanup_receipt"]
        assert isinstance(cleanup, dict)
        assert cleanup["redacted"] is True
        assert "vault" not in json.dumps(cleanup)
        assert "token" not in json.dumps(cleanup)
        assert destroyer.refs == ["vault://runtime/connection/postgres"]

        deleted = _connection_row()
        metadata = deleted["account_metadata"]
        assert isinstance(metadata, dict)
        assert deleted["selected_model"] is None
        assert deleted["status"] == "revoked"
        assert deleted["revoked_at"] is True
        assert deleted["runtime_ref"] == f"vault://runtime/destroyed/{connection_id}"
        assert metadata["cleanup_status"] == "completed"
        assert metadata["evidence_sha256"] == _SHA256_EVIDENCE
        revision = selected.body["revision"]
        assert isinstance(revision, str)
        assert metadata["revision"] == str(int(revision) + 1)
    finally:
        server.shutdown()
        server.server_close()


def test_reauthentication_destroys_the_distinct_superseded_home() -> None:
    seed_tenants()
    destroyer = _Destroyer()
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        destroyer,
        clock=_clock,
        cleanup_window=(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    )
    runtime = ProviderRuntimeService(
        _clock,
        persistence=persistence,
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    principal = ProviderPrincipal(USER_A, ORG_A)
    initial = runtime.initiate(
        principal, "openai_codex", "callback", "/settings/providers"
    )
    connection = runtime.complete_callback(
        principal,
        initial.state,
        "/settings/providers",
        _completion("vault://runtime/connection/old-distinct", "account-old"),
    )
    _confirm_adoption(runtime, principal, connection)
    reauth = runtime.initiate_reauth(
        principal, connection.connection_id, "callback", "/settings/providers"
    )

    rotated = runtime.complete_callback(
        principal,
        reauth.state,
        "/settings/providers",
        _completion("vault://runtime/connection/new-distinct", "account-new"),
    )
    _confirm_adoption(runtime, principal, rotated)

    row = _connection_row(connection.connection_id)
    cleanup = _cleanup_row("vault://runtime/connection/old-distinct")
    assert rotated.account_id == "account-new"
    assert row["runtime_ref"] == "vault://runtime/connection/new-distinct"
    assert row["superseded_runtime_ref"] is None
    assert cleanup["reason"] == "superseded"
    assert cleanup["status"] == "completed"
    assert cleanup["evidence_sha256"] == _SHA256_EVIDENCE
    assert destroyer.refs == ["vault://runtime/connection/old-distinct"]


def test_restart_reconciles_a_committed_broker_adoption_outbox() -> None:
    seed_tenants()
    broker = _FailingAdoptionBroker()
    destroyer = _Destroyer()
    runtime = ProviderRuntimeService(
        _clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            destroyer,
            clock=_clock,
            cleanup_window=(
                PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
            ),
        ),
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    server = run_product_server(
        authenticated_fixture=True,
        options=ProductServerOptions(
            principal=Principal(USER_A, ORG_A, "a@example.test", "A"),
            provider_runtime=runtime,
            provider_oauth_broker=broker,
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    cookie = server.fixture_session_cookie()
    initiated = _request(
        server,
        cookie,
        _RequestSpec(
            "POST",
            "/api/v1/provider-connections",
            {
                "adapter_id": "openai_codex",
                "flow": "callback",
                "redirect_uri": "/settings/providers",
            },
            _same_origin(server, **{"Idempotency-Key": "outbox-init"}),
        ),
    )
    failed = _complete_connection(server, cookie, initiated.body["state"])
    pending = _connection_row()
    metadata = pending["account_metadata"]
    assert failed.status == 503
    assert isinstance(metadata, dict)
    assert metadata["adoption_status"] == "pending"
    assert broker.discarded == []
    server.shutdown()
    server.server_close()

    broker.fail_adoption = False
    restarted_runtime = ProviderRuntimeService(
        _clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            destroyer,
            clock=_clock,
            cleanup_window=(
                PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
            ),
        ),
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    restarted = run_product_server(
        authenticated_fixture=True,
        options=ProductServerOptions(
            principal=Principal(USER_A, ORG_A, "a@example.test", "A"),
            provider_runtime=restarted_runtime,
            provider_oauth_broker=broker,
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        recovered = _request(
            restarted,
            restarted.fixture_session_cookie(),
            _RequestSpec("GET", "/api/v1/provider-connections"),
        )
        completed_metadata = _connection_row()["account_metadata"]
        assert recovered.status == 200
        assert len(broker.adopted) == 1
        assert isinstance(completed_metadata, dict)
        assert "adoption_status" not in completed_metadata
        assert "staging_lease_id" not in completed_metadata
    finally:
        restarted.shutdown()
        restarted.server_close()


def test_reauthentication_cleanup_resumes_after_postcommit_destroy_failure() -> None:
    seed_tenants()
    failing_destroyer = _Destroyer()
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        failing_destroyer,
        clock=_clock,
        cleanup_window=(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    )
    runtime = ProviderRuntimeService(
        _clock,
        persistence=persistence,
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    principal = ProviderPrincipal(USER_A, ORG_A)
    initial = runtime.initiate(
        principal, "openai_codex", "callback", "/settings/providers"
    )
    connection = runtime.complete_callback(
        principal,
        initial.state,
        "/settings/providers",
        _completion("vault://runtime/connection/old-crash", "account-old"),
    )
    _confirm_adoption(runtime, principal, connection)
    reauth = runtime.initiate_reauth(
        principal, connection.connection_id, "callback", "/settings/providers"
    )
    failing_destroyer.fail = True

    rotated = runtime.complete_callback(
        principal,
        reauth.state,
        "/settings/providers",
        _completion("vault://runtime/connection/new-crash", "account-new"),
    )
    _confirm_adoption(runtime, principal, rotated)

    pending_row = _connection_row(connection.connection_id)
    pending_cleanup = _cleanup_row("vault://runtime/connection/old-crash")
    assert pending_row["runtime_ref"] == "vault://runtime/connection/new-crash"
    assert pending_row["superseded_runtime_ref"] == (
        "vault://runtime/connection/old-crash"
    )
    assert pending_cleanup["status"] == "scheduled"
    assert rotated.account_id == "account-new"

    recovery_destroyer = _Destroyer()
    recovery_persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        recovery_destroyer,
        clock=lambda: (
            _clock()
            + PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
        cleanup_window=(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    )
    sweep = _cleanup_sweeper(
        recovery_destroyer,
        clock=lambda: (
            _clock()
            + PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    ).sweep_due_cleanups()
    restarted = ProviderRuntimeService(
        _clock,
        persistence=recovery_persistence,
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    restored = restarted.connection_detail(principal, connection.connection_id)
    completed_row = _connection_row(connection.connection_id)
    completed_cleanup = _cleanup_row("vault://runtime/connection/old-crash")
    assert restored.account_id == "account-new"
    assert completed_row["superseded_runtime_ref"] is None
    assert completed_cleanup["status"] == "completed"
    assert recovery_destroyer.refs == ["vault://runtime/connection/old-crash"]
    _assert_completed_sweep(sweep)


def test_same_ref_reauthentication_never_destroys_the_active_postgres_home() -> None:
    seed_tenants()
    destroyer = _Destroyer()
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        destroyer,
        clock=_clock,
        cleanup_window=(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    )
    runtime = ProviderRuntimeService(
        _clock,
        persistence=persistence,
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    principal = ProviderPrincipal(USER_A, ORG_A)
    initial = runtime.initiate(
        principal, "openai_codex", "callback", "/settings/providers"
    )
    connection = runtime.complete_callback(
        principal,
        initial.state,
        "/settings/providers",
        _completion("vault://runtime/connection/shared", "account-old"),
    )
    _confirm_adoption(runtime, principal, connection)
    reauth = runtime.initiate_reauth(
        principal, connection.connection_id, "callback", "/settings/providers"
    )

    rotated = runtime.complete_callback(
        principal,
        reauth.state,
        "/settings/providers",
        _completion("vault://runtime/connection/shared", "account-new"),
    )
    _confirm_adoption(runtime, principal, rotated)

    assert rotated.account_id == "account-new"
    assert destroyer.refs == []
    _ = runtime.revoke(principal, connection.connection_id, rotated.revision)
    assert destroyer.refs == ["vault://runtime/connection/shared"]


def test_unbound_completion_cleanup_is_durable_and_restart_retryable() -> None:
    seed_tenants()
    principal = ProviderPrincipal(USER_A, ORG_A)
    failing_destroyer = _Destroyer()
    failing_destroyer.fail = True
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        failing_destroyer,
        clock=_clock,
        cleanup_window=(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    )

    with pytest.raises(Exception, match="provider_persistence_failed"):
        persistence.discard_runtime_home(
            principal, "vault://runtime/connection/unbound"
        )

    assert _cleanup_row("vault://runtime/connection/unbound")["status"] == ("scheduled")
    recovery_destroyer = _Destroyer()
    result = _cleanup_sweeper(
        recovery_destroyer,
        clock=lambda: (
            _clock()
            + PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    ).sweep_due_cleanups()
    assert _cleanup_row("vault://runtime/connection/unbound")["status"] == ("completed")
    assert recovery_destroyer.refs == ["vault://runtime/connection/unbound"]
    _assert_completed_sweep(result)


def test_unbound_completion_at_deadline_is_destroyed_before_overdue_is_reported() -> (
    None
):
    seed_tenants()
    cleanup_window = timedelta(hours=1)
    now = [_clock()]

    class _DeadlineDestroyer:
        def __init__(self) -> None:
            self.refs: list[str] = []

        def destroy(self, opaque_ref: str) -> str:
            self.refs.append(opaque_ref)
            now[0] += cleanup_window
            return _SHA256_EVIDENCE

    destroyer = _DeadlineDestroyer()
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        destroyer,
        clock=lambda: now[0],
        cleanup_window=cleanup_window,
    )
    runtime_home_ref = "vault://runtime/connection/exact-deadline"

    principal = ProviderPrincipal(USER_A, ORG_A)
    persistence.discard_runtime_home(principal, runtime_home_ref)

    assert destroyer.refs == [runtime_home_ref]
    assert _cleanup_row(runtime_home_ref)["status"] == "completed"
    restart_destroyer = _Destroyer()
    restarted = PostgresProviderPersistence(
        database_url_asyncpg(),
        restart_destroyer,
        clock=lambda: now[0],
        cleanup_window=cleanup_window,
    )
    assert restarted.load(principal) == ()
    assert restart_destroyer.refs == []


def test_service_sweep_refuses_cross_requester_duplicate_runtime_home() -> None:
    seed_tenants()
    runtime_home_ref = "vault://runtime/connection/cross-requester-duplicate"
    failing_destroyer = _Destroyer()
    failing_destroyer.fail = True
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        failing_destroyer,
        clock=_clock,
        cleanup_window=(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    )
    for principal in (
        ProviderPrincipal(USER_A, ORG_A),
        ProviderPrincipal(USER_B, ORG_B),
    ):
        with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
            persistence.discard_runtime_home(principal, runtime_home_ref)
    recovery_destroyer = _Destroyer()

    try:
        result = _cleanup_sweeper(
            recovery_destroyer,
            clock=lambda: (
                _clock()
                + PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
            ),
        ).sweep_due_cleanups()

        scheduled = psql(
            "SELECT count(*) FROM provider_runtime_home_cleanups WHERE "
            "encrypted_runtime_home_ref = "
            "'vault://runtime/connection/cross-requester-duplicate' AND "
            "status = 'scheduled'"
        )
        assert result.scanned == 2
        assert result.completed == 0
        assert result.failed == 2
        assert recovery_destroyer.refs == []
        assert scheduled.stdout == "2\n"
    finally:
        _ = psql(
            "DELETE FROM provider_runtime_home_cleanups WHERE "
            "encrypted_runtime_home_ref = "
            "'vault://runtime/connection/cross-requester-duplicate'"
        )


def test_scheduled_revocation_resumes_fail_closed_after_restart() -> None:
    seed_tenants()
    runtime_home_ref = "vault://runtime/connection/restart-revoke"
    failing_destroyer = _Destroyer()
    runtime = ProviderRuntimeService(
        _clock,
        persistence=PostgresProviderPersistence(
            database_url_asyncpg(),
            failing_destroyer,
            clock=_clock,
            cleanup_window=(
                PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
            ),
        ),
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    server = run_product_server(
        authenticated_fixture=True,
        options=ProductServerOptions(
            principal=Principal(USER_A, ORG_A, "a@example.test", "A"),
            provider_runtime=runtime,
            provider_oauth_broker=_Broker(runtime_home_ref),
            provider_diagnostic_sink=_DiagnosticSink(),
        ),
    )
    try:
        cookie = server.fixture_session_cookie()
        initiated = _request(
            server,
            cookie,
            _RequestSpec(
                "POST",
                "/api/v1/provider-connections",
                {
                    "adapter_id": "openai_codex",
                    "flow": "callback",
                    "redirect_uri": "/settings/providers",
                },
                _same_origin(server, **{"Idempotency-Key": "restart-init"}),
            ),
        )
        completed = _complete_connection(server, cookie, initiated.body["state"])
        connection_id = _assert_completed_connection(completed)
        failing_destroyer.fail = True

        failed = _request(
            server,
            cookie,
            _RequestSpec(
                "DELETE",
                f"/api/v1/provider-connections/{connection_id}",
                headers=_same_origin(
                    server, **{"If-Match": str(completed.body["revision"])}
                ),
            ),
        )
        assert failed.status == 503
        scheduled = _connection_row(connection_id)
        assert scheduled["status"] == "revoked"
        assert scheduled["selected_model"] is None
        metadata = scheduled["account_metadata"]
        assert isinstance(metadata, dict)
        assert metadata["cleanup_status"] == "scheduled"
        _assert_revoke_cleanup_reservations(
            connection_id, runtime_home_ref, "scheduled"
        )
    finally:
        server.shutdown()
        server.server_close()

    recovery_destroyer = _Destroyer()
    sweep = _cleanup_sweeper(
        recovery_destroyer,
        clock=lambda: (
            _clock()
            + PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window
        ),
    ).sweep_due_cleanups()
    swept_metadata = _connection_row(connection_id)["account_metadata"]
    assert recovery_destroyer.refs == [runtime_home_ref]
    _assert_completed_sweep(sweep)
    assert isinstance(swept_metadata, dict)
    assert swept_metadata["cleanup_status"] == "completed"
    _assert_revoke_cleanup_reservations(connection_id, runtime_home_ref, "completed")
    restarted, restarted_runtime, cookie = _restart_with_persistence(recovery_destroyer)
    try:
        listed = _request(
            restarted,
            cookie,
            _RequestSpec("GET", "/api/v1/provider-connections"),
        )
        assert listed.status == 200
        connection = _listed_connection(listed, connection_id)
        assert connection["status"] == "revoked"
        receipt = restarted_runtime.cleanup_receipt(
            ProviderPrincipal(USER_A, ORG_A), connection_id
        )
        assert receipt.evidence_sha256 == _SHA256_EVIDENCE
        assert recovery_destroyer.refs == [runtime_home_ref]
        completed_row = _connection_row(connection_id)
        completed_metadata = completed_row["account_metadata"]
        assert isinstance(completed_metadata, dict)
        assert completed_metadata["cleanup_status"] == "completed"
        assert completed_row["runtime_ref"] == (
            f"vault://runtime/destroyed/{connection_id}"
        )
    finally:
        restarted.shutdown()
        restarted.server_close()
