from __future__ import annotations

from typing import TYPE_CHECKING, Final

import pytest

from services.api.tests.persistence.postgres_harness import psql
from services.api.tests.persistence.test_rls import ORG_A, USER_A, seed_tenants

if TYPE_CHECKING:
    import subprocess

REVOKED_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e39"
SOURCE_REUSE_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e3a"
TOMBSTONE_REUSE_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e3b"
SOURCE_REF: Final = "vault://runtime/cleanup-retirement-source"
TOMBSTONE_REF: Final = f"vault://runtime/destroyed/{REVOKED_PROVIDER}"
EVIDENCE_SHA256: Final = "a" * 64
pytestmark = pytest.mark.usefixtures("migrated_database")


def test_global_cleanup_functions_have_a_confined_rls_bypass_owner() -> None:
    # Given the global functions query FORCE-RLS provider tables across tenants.
    boundary = psql(
        "WITH owned AS (SELECT DISTINCT owner.rolname FROM pg_proc procedure "
        "JOIN pg_roles owner ON owner.oid = procedure.proowner WHERE procedure.oid "
        "IN ('public.provider_due_cleanup_candidates(timestamptz)'::regprocedure, "
        "'public.validate_due_provider_cleanup(uuid,uuid,uuid,text,text,"
        "timestamptz)'::regprocedure, 'public.complete_provider_cleanup_outbox("
        "uuid,uuid,uuid,text,text,timestamptz,text)'::regprocedure, "
        "'public.complete_provider_revoked_cleanup(uuid,uuid,uuid,text,"
        "timestamptz,text)'::regprocedure, "
        "'public.lock_provider_connection_runtime_refs()'::regprocedure)) "
        "SELECT role.rolname || ':' || role.rolcanlogin::text || ':' || "
        "role.rolinherit::text || ':' || role.rolsuper::text || ':' || "
        "role.rolbypassrls::text || ':' || (SELECT count(*) FROM pg_auth_members "
        "WHERE roleid = role.oid OR member = role.oid)::text || ':' || "
        "has_table_privilege(role.rolname, 'provider_connections', 'SELECT')::text "
        "|| ':' || has_column_privilege(role.rolname, 'provider_connections', "
        "'encrypted_runtime_home_ref', 'UPDATE')::text || ':' || "
        "has_table_privilege(role.rolname, 'provider_runtime_home_cleanups', "
        "'SELECT')::text || ':' || has_table_privilege(role.rolname, "
        "'provider_runtime_home_cleanups', 'INSERT')::text || ':' || "
        "has_column_privilege(role.rolname, 'provider_runtime_home_cleanups', "
        "'status', 'UPDATE')::text || ':' || has_table_privilege(role.rolname, "
        "'provider_runtime_home_cleanups', 'DELETE')::text || ':' || "
        "(SELECT count(*) FROM owned)::text FROM owned JOIN pg_roles role ON "
        "role.rolname = owned.rolname"
    ).stdout.strip()

    # Then one membership-free NOLOGIN owner has only the required global authority.
    assert boundary == (
        "science_workbench_provider_cleanup_definer:false:false:false:true:0:"
        "true:true:true:true:true:false:1"
    )


def test_revoke_reservations_are_durable_immutable_and_nonrebindable() -> None:
    # Given a due revoke with no pre-existing source or tombstone reservation.
    seed_tenants()
    _ = psql(
        f"DELETE FROM provider_runtime_home_cleanups WHERE "
        f"encrypted_runtime_home_ref IN ('{SOURCE_REF}', '{TOMBSTONE_REF}'); "
        "DELETE FROM provider_connections WHERE id IN "
        f"('{REVOKED_PROVIDER}', '{SOURCE_REUSE_PROVIDER}', "
        f"'{TOMBSTONE_REUSE_PROVIDER}'); "
        "INSERT INTO provider_connections (id, org_id, requester_user_id, "
        "adapter_id, encrypted_runtime_home_ref, account_metadata, status) VALUES "
        f"('{REVOKED_PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{SOURCE_REF}', jsonb_build_object('cleanup_status', 'scheduled', "
        "'cleanup_requested_at', transaction_timestamp() - interval '2 hours', "
        "'destroy_by', transaction_timestamp() - interval '1 hour'), 'revoked')"
    )
    try:
        # When validation reserves both refs and completion records destruction.
        completed = psql(
            "BEGIN; SET ROLE science_workbench_provider_cleanup; "
            "SELECT (public.validate_due_provider_cleanup("
            f"'{ORG_A}', '{USER_A}', '{REVOKED_PROVIDER}', '{SOURCE_REF}', "
            "'revoke', transaction_timestamp()) IS NOT NULL)::text; "
            "RESET ROLE; "
            "SELECT count(*)::text FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref IN ('{SOURCE_REF}', '{TOMBSTONE_REF}') "
            "AND reason = 'revoke' AND status = 'scheduled'; "
            "SET ROLE science_workbench_provider_cleanup; "
            "SELECT public.complete_provider_revoked_cleanup("
            f"'{ORG_A}', '{USER_A}', '{REVOKED_PROVIDER}', '{SOURCE_REF}', "
            f"transaction_timestamp(), '{EVIDENCE_SHA256}')::text; "
            "RESET ROLE; "
            "SELECT count(*)::text FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref IN ('{SOURCE_REF}', '{TOMBSTONE_REF}') "
            "AND reason = 'revoke' AND status = 'completed'; COMMIT"
        ).stdout.splitlines()
        principal = (
            "BEGIN; SET ROLE science_workbench_app; "
            f"SELECT set_config('app.org_id', '{ORG_A}', true); "
            f"SELECT set_config('app.user_id', '{USER_A}', true); "
        )
        retarget = psql(
            principal
            + "UPDATE provider_runtime_home_cleanups SET "
            "encrypted_runtime_home_ref = encrypted_runtime_home_ref || '-moved' "
            f"WHERE encrypted_runtime_home_ref = '{SOURCE_REF}'; ROLLBACK",
            check=False,
        )
        rewrite = psql(
            principal
            + "UPDATE provider_runtime_home_cleanups SET status = 'scheduled', "
            "destroyed_at = NULL, evidence_sha256 = NULL WHERE "
            f"encrypted_runtime_home_ref = '{SOURCE_REF}'; ROLLBACK",
            check=False,
        )
        delete = psql(
            principal
            + "DELETE FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref = '{SOURCE_REF}'; ROLLBACK",
            check=False,
        )

        def direct_rebind(
            provider_id: str, runtime_ref: str
        ) -> subprocess.CompletedProcess[str]:
            return psql(
                principal
                + "INSERT INTO provider_connections (id, org_id, "
                "requester_user_id, adapter_id, encrypted_runtime_home_ref, "
                "account_metadata, status) VALUES "
                f"('{provider_id}', '{ORG_A}', '{USER_A}', 'openai_codex', "
                f"'{runtime_ref}', '{{}}', 'pending'); ROLLBACK",
                check=False,
            )

        source_rebind = direct_rebind(SOURCE_REUSE_PROVIDER, SOURCE_REF)
        tombstone_rebind = direct_rebind(TOMBSTONE_REUSE_PROVIDER, TOMBSTONE_REF)
    finally:
        _ = psql(
            f"DELETE FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref IN ('{SOURCE_REF}', '{TOMBSTONE_REF}'); "
            "DELETE FROM provider_connections WHERE id IN "
            f"('{REVOKED_PROVIDER}', '{SOURCE_REUSE_PROVIDER}', "
            f"'{TOMBSTONE_REUSE_PROVIDER}')"
        )

    # Then retirement cannot be erased, rewritten, or rebound by the app role.
    assert completed == ["true", "2", "true", "2"]
    assert all(result.returncode != 0 for result in (retarget, rewrite, delete))
    assert source_rebind.returncode != 0
    assert "provider runtime home ref has cleanup history" in source_rebind.stderr
    assert tombstone_rebind.returncode != 0
    assert "provider runtime tombstone transition is invalid" in tombstone_rebind.stderr
