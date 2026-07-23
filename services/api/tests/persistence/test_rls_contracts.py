from __future__ import annotations

from typing import Final

import anyio
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from services.api.tests.persistence.postgres_harness import (
    database_url_asyncpg,
    psql,
)
from services.api.tests.persistence.test_rls import (
    ORG_A,
    PROJECT_A,
    USER_A,
    app_principal_sql,
    seed_tenants,
)

SESSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e01"
PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e02"
RUN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e03"
RECEIPT: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e20"
NEXT_RECEIPT: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e23"
SKIP_RECEIPT: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e24"
SHADOW_RECEIPT: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e27"
DISPATCHED_RUN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e25"
RACING_RUN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e26"
CLEANUP_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e28"
CLEANUP_REVOKED_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e29"
CLEANUP_FUTURE_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e30"
PLAN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e04"
APPROVAL: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e05"
EXECUTION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e06"
BAD_EXECUTION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e07"
ARTIFACT: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e08"
VERSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e09"
REVIEW: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e10"
SUBMISSION: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e11"
FINDING: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e12"
BAD_FINDING: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e13"
BAD_PLAN: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e14"
SHA: Final = "a" * 64
RECEIPT_SHA: Final = "b" * 64
RESEARCH_INTENT_SHA: Final = (
    "60d80404ffbcbf2a738a9e2874376e5b951fc9c506ccfe4329ade98190580fb7"
)
RESEARCH_INTENT_SQL: Final = (
    '{"question":"보정된 관측값을 재현 가능하게 정규화할 수 있는가?",'
    '"rationale":"반복 분석에서 입력 순서가 결과를 바꾸지 않도록 확인한다.",'
    '"intended_benefit":"검증 가능한 정규화 기준선을 만든다.",'
    '"success_criteria":["동일 입력은 동일 체크섬을 만든다."],'
    '"constraints":["비임상 연구 데이터만 사용한다."],'
    '"stop_conditions":["보정 메타데이터가 없으면 중단한다."],'
    '"research_mode":"bounded_agentic","data_origin":"observed",'
    '"synthetic_generator_ref":null,"synthetic_validator_ref":null}'
)
pytestmark = pytest.mark.usefixtures("migrated_database")


def test_provider_roles_have_exact_effective_function_privileges() -> None:
    # Given a database freshly migrated through provider security revision 0004.
    effective = psql(
        "WITH roles(role_name) AS (VALUES ('science_workbench_app'), "
        "('science_workbench_compliance'), "
        "('science_workbench_dispatcher'), "
        "('science_workbench_provider_cleanup'), "
        "('science_workbench_qualification')) SELECT role_name || '=' || "
        "COALESCE(string_agg(function_name, '|' ORDER BY function_name), '') FROM "
        "roles LEFT JOIN LATERAL (SELECT p.oid::regprocedure::text AS "
        "function_name FROM pg_proc p JOIN pg_namespace n ON n.oid = "
        "p.pronamespace WHERE n.nspname = 'public' AND has_function_privilege("
        "role_name, p.oid, 'EXECUTE')) functions ON true GROUP BY role_name ORDER "
        "BY role_name"
    ).stdout.strip()

    # When the effective privileges include direct grants, role inheritance, and PUBLIC.
    public_execute = psql(
        "SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid = "
        "p.pronamespace WHERE n.nspname = 'public' AND EXISTS (SELECT 1 FROM "
        "aclexplode(COALESCE(p.proacl, acldefault('f', p.proowner))) entry WHERE "
        "entry.grantee = 0 AND entry.privilege_type = 'EXECUTE')"
    ).stdout.strip()
    public_default_execute = psql(
        "WITH owner AS (SELECT oid FROM pg_roles WHERE rolname = current_user), "
        "configured AS (SELECT defaults.defaclacl FROM pg_default_acl defaults, "
        "owner WHERE defaults.defaclrole = owner.oid AND "
        "defaults.defaclnamespace = 0 AND defaults.defaclobjtype = 'f') SELECT "
        "count(*) FROM owner, LATERAL aclexplode(COALESCE((SELECT defaclacl FROM "
        "configured), acldefault('f', owner.oid))) entry WHERE entry.grantee = 0 "
        "AND entry.privilege_type = 'EXECUTE'"
    ).stdout.strip()
    snapshot_boundary = psql(
        "SELECT rolcanlogin::text || ':' || rolinherit::text || ':' || "
        "rolsuper::text || ':' || rolbypassrls::text || ':' || (SELECT count(*) "
        "FROM pg_auth_members membership WHERE membership.roleid = role.oid OR "
        "membership.member = role.oid)::text || ':' || "
        "(shobj_description(role.oid, 'pg_authid') LIKE "
        "'science-workbench-0004-public-function-default|%')::text FROM pg_roles "
        "role WHERE role.rolname = "
        "'science_workbench_0004_public_execute_snapshot'"
    ).stdout.strip()

    # Then every runtime role has only its required callable surface.
    assert public_execute == "0"
    assert public_default_execute == "0"
    assert snapshot_boundary == "false:false:false:false:0:true"
    assert effective == (
        "science_workbench_app=complete_provider_cleanup_outbox(uuid,uuid,uuid,"
        "text,text,timestamp with time zone,text)|current_principal_org()|"
        "resolve_auth_session(bytea)|revoke_auth_session(bytea)|"
        "validate_due_provider_cleanup(uuid,uuid,uuid,text,text,timestamp with "
        "time zone)\n"
        "science_workbench_compliance=current_principal_org()\n"
        "science_workbench_dispatcher=current_principal_org()\n"
        "science_workbench_provider_cleanup="
        "complete_provider_cleanup_outbox(uuid,uuid,uuid,text,text,timestamp with "
        "time zone,text)|complete_provider_revoked_cleanup(uuid,uuid,uuid,text,"
        "timestamp with time zone,text)|provider_due_cleanup_candidates(timestamp "
        "with time zone)|validate_due_provider_cleanup(uuid,uuid,uuid,text,text,"
        "timestamp with time zone)\n"
        "science_workbench_qualification=current_principal_org()"
    )


def test_qualification_role_is_nologin_and_column_limited() -> None:
    role = psql(
        "SELECT rolcanlogin::text || ':' || rolinherit::text || ':' || "
        "rolsuper::text || ':' || rolbypassrls::text FROM pg_roles WHERE "
        "rolname = 'science_workbench_qualification'"
    ).stdout.strip()
    privileges = psql(
        "SELECT has_table_privilege('science_workbench_qualification', "
        "'provider_qualification_receipts', 'INSERT')::text || ':' || "
        "has_column_privilege('science_workbench_qualification', "
        "'provider_connections', 'qualification_receipt_id', 'UPDATE')::text || "
        "':' || has_column_privilege('science_workbench_qualification', "
        "'provider_connections', 'status', 'UPDATE')::text || ':' || "
        "has_column_privilege('science_workbench_qualification', "
        "'provider_connections', 'encrypted_runtime_home_ref', 'UPDATE')::text || "
        "':' || has_table_privilege('science_workbench_app', 'runs', "
        "'INSERT')::text || ':' || has_table_privilege("
        "'science_workbench_dispatcher', 'runs', 'INSERT')::text || ':' || "
        "has_table_privilege('science_workbench_dispatcher', 'runs', "
        "'UPDATE')::text || ':' || has_table_privilege("
        "'science_workbench_dispatcher', 'provider_connections', "
        "'SELECT')::text || ':' || has_table_privilege("
        "'science_workbench_dispatcher', 'provider_qualification_receipts', "
        "'SELECT')::text || ':' || has_function_privilege("
        "'science_workbench_dispatcher', "
        "'validate_run_qualification_binding()', 'EXECUTE')::text"
    ).stdout.strip()
    dispatcher = psql(
        "SELECT rolcanlogin::text || ':' || rolinherit::text || ':' || "
        "rolsuper::text || ':' || rolbypassrls::text FROM pg_roles WHERE "
        "rolname = 'science_workbench_dispatcher'"
    ).stdout.strip()
    cleanup = psql(
        "SELECT rolcanlogin::text || ':' || rolinherit::text || ':' || "
        "rolsuper::text || ':' || rolbypassrls::text || ':' || "
        "has_table_privilege('science_workbench_provider_cleanup', "
        "'provider_connections', 'SELECT')::text || ':' || "
        "has_table_privilege('science_workbench_provider_cleanup', "
        "'provider_connections', 'UPDATE')::text || ':' || "
        "has_table_privilege('science_workbench_provider_cleanup', "
        "'provider_connections', 'INSERT')::text || ':' || "
        "has_table_privilege('science_workbench_provider_cleanup', "
        "'provider_runtime_home_cleanups', 'SELECT')::text || ':' || "
        "has_table_privilege('science_workbench_provider_cleanup', "
        "'provider_runtime_home_cleanups', 'UPDATE')::text || ':' || "
        "has_table_privilege('science_workbench_provider_cleanup', "
        "'provider_runtime_home_cleanups', 'DELETE')::text || ':' || "
        "has_column_privilege('science_workbench_provider_cleanup', "
        "'provider_connections', 'account_metadata', 'UPDATE')::text || ':' || "
        "has_column_privilege('science_workbench_provider_cleanup', "
        "'provider_runtime_home_cleanups', 'status', 'UPDATE')::text || ':' || "
        "has_function_privilege('science_workbench_provider_cleanup', "
        "'provider_due_cleanup_candidates(timestamptz)', 'EXECUTE')::text || "
        "':' || has_function_privilege('science_workbench_provider_cleanup', "
        "'validate_due_provider_cleanup(uuid,uuid,uuid,text,text,timestamptz)', "
        "'EXECUTE')::text || ':' || "
        "has_function_privilege('science_workbench_provider_cleanup', "
        "'complete_provider_cleanup_outbox(uuid,uuid,uuid,text,text,"
        "timestamptz,text)', "
        "'EXECUTE')::text || ':' || has_function_privilege("
        "'science_workbench_provider_cleanup', "
        "'complete_provider_revoked_cleanup(uuid,uuid,uuid,text,timestamptz,text)', "
        "'EXECUTE')::text || ':' || has_function_privilege("
        "'science_workbench_app', "
        "'complete_provider_revoked_cleanup(uuid,uuid,uuid,text,timestamptz,text)', "
        "'EXECUTE')::text FROM pg_roles WHERE "
        "rolname = 'science_workbench_provider_cleanup'"
    ).stdout.strip()
    cleanup_direct_update = psql(
        "SET ROLE science_workbench_provider_cleanup; UPDATE "
        "provider_connections SET account_metadata = '{}'::jsonb",
        check=False,
    )
    cleanup_direct_select = psql(
        "SET ROLE science_workbench_provider_cleanup; SELECT count(*) FROM "
        "provider_connections",
        check=False,
    )

    assert role == "false:false:false:false"
    assert dispatcher == "false:false:false:false"
    assert cleanup == (
        "false:false:false:false:false:false:false:false:false:false:false:false:"
        "true:true:true:true:false"
    )
    assert cleanup_direct_update.returncode != 0
    assert cleanup_direct_select.returncode != 0
    assert privileges == "true:true:false:false:false:true:false:true:true:false"


def test_app_role_cannot_forge_qualification_or_unbound_run() -> None:
    seed_execution_graph()
    forged_receipt = "018f0d7d-6b17-7a91-8b31-2f7331677e21"
    forged_run = "018f0d7d-6b17-7a91-8b31-2f7331677e22"
    principal = "SET ROLE science_workbench_app; " + app_principal_sql(
        ORG_A, USER_A
    )
    receipt = psql(
        principal
        + "INSERT INTO provider_qualification_receipts (id, org_id, "
        "requester_user_id, provider_connection_id, connection_revision, "
        "adapter_id, profile_sha256, cases_sha256, operator_account_ref, "
        "oauth_mode, oauth_provider, runtime_version, executable_sha256, "
        "protocol_attempts, cleanup_terminal, cleanup_redaction_complete, "
        "authority_key_id, authority_issued_at, authority_algorithm, "
        f"authority_signature, receipt_sha256) VALUES ('{forged_receipt}', "
        f"'{ORG_A}', '{USER_A}', '{PROVIDER}', 3, 'openai_codex', '{SHA}', "
        f"'{SHA}', 'Bearer forged-secret', 'official_subscription_oauth', "
        f"'openai', 'codex-cli-forged', '{SHA}', 30, true, true, 'forged', "
        "CURRENT_TIMESTAMP, 'RSASSA-PKCS1-v1_5/SHA-256', "
        f"'{'c' * 768}', '{SHA}')",
        check=False,
    )
    pointer = psql(
        principal
        + "UPDATE provider_connections SET qualification_receipt_id = "
        f"'{forged_receipt}', qualified_at = CURRENT_TIMESTAMP WHERE id = "
        f"'{PROVIDER}'",
        check=False,
    )
    run = psql(
        principal
        + "INSERT INTO runs (id, org_id, session_id, requester_id, "
        "provider_connection_id, status, qualification_receipt_id, "
        "qualification_receipt_sha256, qualification_connection_revision, "
        "qualification_profile_sha256, qualification_runtime_version, "
        "qualification_executable_sha256, provider_model_id) VALUES "
        f"('{forged_run}', '{ORG_A}', '{SESSION}', '{USER_A}', '{PROVIDER}', "
        f"'queued', '{RECEIPT}', '{RECEIPT_SHA}', 2, '{SHA}', "
        f"'codex-cli-fixture', '{SHA}', 'codex-mini')",
        check=False,
    )
    assert "permission denied" in receipt.stderr
    assert "provider qualification requires adopter authority" in pointer.stderr
    assert "permission denied for table runs" in run.stderr


def test_app_role_cannot_forge_cleanup_completion_columns() -> None:
    seed_tenants()
    runtime_home_ref = "vault://runtime/cleanup-app-forgery"
    _ = psql(
        "INSERT INTO provider_runtime_home_cleanups (org_id, requester_user_id, "
        "encrypted_runtime_home_ref, connection_id, reason, status, requested_at, "
        "destroy_by) VALUES ("
        f"'{ORG_A}', '{USER_A}', '{runtime_home_ref}', NULL, 'unbound', "
        "'scheduled', transaction_timestamp(), transaction_timestamp() + "
        "interval '1 hour')"
    )
    principal = "SET ROLE science_workbench_app; " + app_principal_sql(
        ORG_A, USER_A
    )
    try:
        forged = psql(
            principal
            + "UPDATE provider_runtime_home_cleanups SET status = 'completed', "
            "destroyed_at = transaction_timestamp(), evidence_sha256 = "
            f"'{SHA}' WHERE encrypted_runtime_home_ref = '{runtime_home_ref}'",
            check=False,
        )
        status = psql(
            "SELECT status FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref = '{runtime_home_ref}'"
        ).stdout.strip()
    finally:
        _ = psql(
            "DELETE FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref = '{runtime_home_ref}'"
        )

    assert forged.returncode != 0
    assert "permission denied" in forged.stderr
    assert status == "scheduled"


def test_cleanup_functions_enforce_deadlines_and_exact_runtime_binding() -> None:
    seed_tenants()
    future_outbox_ref = "vault://runtime/cleanup-future-outbox"
    referenced_outbox_ref = "vault://runtime/cleanup-still-referenced"
    due_revoked_ref = "vault://runtime/cleanup-due-revoked"
    future_revoked_ref = "vault://runtime/cleanup-future-revoked"
    _ = psql(
        "INSERT INTO provider_connections (id, org_id, requester_user_id, "
        "adapter_id, encrypted_runtime_home_ref, account_metadata, status) VALUES "
        f"('{CLEANUP_PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{referenced_outbox_ref}', '{{}}', 'pending'), "
        f"('{CLEANUP_REVOKED_PROVIDER}', '{ORG_A}', '{USER_A}', "
        f"'openai_codex', '{due_revoked_ref}', jsonb_build_object("
        "'cleanup_status', 'scheduled', 'cleanup_requested_at', "
        "transaction_timestamp() - interval '2 hours', 'destroy_by', "
        "transaction_timestamp() - interval '1 hour'), 'revoked'), "
        f"('{CLEANUP_FUTURE_PROVIDER}', '{ORG_A}', '{USER_A}', "
        f"'openai_codex', '{future_revoked_ref}', jsonb_build_object("
        "'cleanup_status', 'scheduled', 'cleanup_requested_at', "
        "transaction_timestamp(), 'destroy_by', transaction_timestamp() + "
        "interval '1 day'), 'revoked'); "
        "INSERT INTO provider_runtime_home_cleanups (org_id, requester_user_id, "
        "encrypted_runtime_home_ref, connection_id, reason, status, requested_at, "
        "destroy_by) VALUES "
        f"('{ORG_A}', '{USER_A}', '{future_outbox_ref}', NULL, 'unbound', "
        "'scheduled', transaction_timestamp(), transaction_timestamp() + "
        "interval '1 day')"
    )
    # Seed an impossible legacy-corrupt row to exercise the function's own guard.
    _ = psql(
        "BEGIN; ALTER TABLE provider_runtime_home_cleanups DISABLE TRIGGER "
        "provider_cleanup_runtime_ref_lock; INSERT INTO "
        "provider_runtime_home_cleanups (org_id, requester_user_id, "
        "encrypted_runtime_home_ref, connection_id, reason, status, "
        "requested_at, destroy_by) VALUES "
        f"('{ORG_A}', '{USER_A}', '{referenced_outbox_ref}', NULL, 'unbound', "
        "'scheduled', transaction_timestamp() - interval '2 hours', "
        "transaction_timestamp() - interval '1 hour'); ALTER TABLE "
        "provider_runtime_home_cleanups ENABLE TRIGGER "
        "provider_cleanup_runtime_ref_lock; COMMIT"
    )
    principal = "SET ROLE science_workbench_provider_cleanup; "
    due_only = psql(
        principal
        + "SELECT count(*)::text || ':' || bool_and(destroy_by <= "
        "transaction_timestamp())::text FROM "
        "public.provider_due_cleanup_candidates(transaction_timestamp())"
    ).stdout.strip()
    validation = psql(
        principal
        + "SELECT (public.validate_due_provider_cleanup("
        f"'{ORG_A}', '{USER_A}', NULL::uuid, '{future_outbox_ref}', "
        "'unbound', transaction_timestamp()) IS NULL)::text || ':' || "
        "(public.validate_due_provider_cleanup("
        f"'{ORG_A}', '{USER_A}', NULL::uuid, '{referenced_outbox_ref}', "
        "'unbound', transaction_timestamp()) IS NULL)::text || ':' || "
        "(public.validate_due_provider_cleanup("
        f"'{ORG_A}', '{USER_A}', '{CLEANUP_FUTURE_PROVIDER}', "
        f"'{future_revoked_ref}', 'revoke', transaction_timestamp()) IS NULL)::text "
        "|| ':' || (public.validate_due_provider_cleanup("
        f"'{ORG_A}', '{USER_A}', '{CLEANUP_FUTURE_PROVIDER}', "
        f"'{due_revoked_ref}', 'revoke', transaction_timestamp()) IS NULL)::text"
    ).stdout.strip()
    rejected = psql(
        principal
        + "SELECT public.complete_provider_cleanup_outbox("
        f"'{ORG_A}', '{USER_A}', NULL::uuid, '{future_outbox_ref}', "
        f"'unbound', transaction_timestamp(), '{SHA}')::text || ':' || "
        "public.complete_provider_cleanup_outbox("
        f"'{ORG_A}', '{USER_A}', NULL::uuid, '{referenced_outbox_ref}', "
        f"'unbound', transaction_timestamp(), '{SHA}')::text || ':' || "
        "public.complete_provider_revoked_cleanup("
        f"'{ORG_A}', '{USER_A}', '{CLEANUP_FUTURE_PROVIDER}', "
        f"'{future_revoked_ref}', transaction_timestamp(), '{SHA}')::text || ':' || "
        "public.complete_provider_revoked_cleanup("
        f"'{ORG_A}', '{USER_A}', '{CLEANUP_FUTURE_PROVIDER}', "
        f"'{due_revoked_ref}', transaction_timestamp(), '{SHA}')::text"
    ).stdout.strip()
    unchanged = psql(
        "SELECT (SELECT count(*) FROM provider_runtime_home_cleanups WHERE status "
        "= 'scheduled' AND encrypted_runtime_home_ref IN "
        f"('{future_outbox_ref}', '{referenced_outbox_ref}'))::text || ':' || "
        "(SELECT count(*) FROM provider_connections WHERE status = 'revoked' AND "
        "encrypted_runtime_home_ref IN "
        f"('{due_revoked_ref}', '{future_revoked_ref}'))::text"
    ).stdout.strip()
    exact_revoke_result = psql(
        "BEGIN; "
        + principal
        + "SELECT (public.validate_due_provider_cleanup("
        f"'{ORG_A}', '{USER_A}', '{CLEANUP_REVOKED_PROVIDER}', "
        f"'{due_revoked_ref}', 'revoke', transaction_timestamp()) IS NOT NULL)"
        "::text; SELECT public.complete_provider_revoked_cleanup("
        f"'{ORG_A}', '{USER_A}', '{CLEANUP_REVOKED_PROVIDER}', "
        f"'{due_revoked_ref}', transaction_timestamp(), '{SHA}')::text; COMMIT",
        check=False,
    )
    exact_revoke = exact_revoke_result.stdout.splitlines()

    assert due_only == "2:true"
    assert validation == "true:true:true:true"
    assert rejected == "false:false:false:false"
    assert unchanged == "2:2"
    assert exact_revoke_result.returncode == 0, exact_revoke_result.stderr
    assert exact_revoke == ["true", "true"]


def test_qualification_adopter_is_exact_next_revision_and_projection_only() -> None:
    seed_qualified_provider()
    _ = psql(
        "INSERT INTO provider_qualification_receipts (id, org_id, "
        "requester_user_id, provider_connection_id, connection_revision, "
        "adapter_id, profile_sha256, cases_sha256, operator_account_ref, "
        "oauth_mode, oauth_provider, runtime_version, executable_sha256, "
        "protocol_attempts, cleanup_terminal, cleanup_redaction_complete, "
        "authority_key_id, authority_issued_at, authority_algorithm, "
        "authority_signature, receipt_sha256) VALUES "
        f"('{NEXT_RECEIPT}', '{ORG_A}', '{USER_A}', '{PROVIDER}', 3, "
        f"'openai_codex', '{SHA}', '{SHA}', 'acct-next', "
        "'official_subscription_oauth', 'openai', 'codex-cli-next', "
        f"'{SHA}', 30, true, true, 'fixture-key', CURRENT_TIMESTAMP, "
        "'RSASSA-PKCS1-v1_5/SHA-256', repeat('b', 768), repeat('c', 64)), "
        f"('{SKIP_RECEIPT}', '{ORG_A}', '{USER_A}', '{PROVIDER}', 4, "
        f"'openai_codex', '{SHA}', '{SHA}', 'acct-skip', "
        "'official_subscription_oauth', 'openai', 'codex-cli-skip', "
        f"'{SHA}', 30, true, true, 'fixture-key', CURRENT_TIMESTAMP, "
        "'RSASSA-PKCS1-v1_5/SHA-256', repeat('d', 768), repeat('e', 64)) "
        "ON CONFLICT DO NOTHING"
    )
    principal = "SET ROLE science_workbench_qualification; " + app_principal_sql(
        ORG_A, USER_A
    )
    exact = psql(
        "BEGIN; "
        + principal
        + "UPDATE provider_connections SET account_metadata = account_metadata || "
        f"'{{\"revision\":\"3\",\"qualification_receipt_id\":\"{NEXT_RECEIPT}\","
        f'"qualification_runtime_version":"codex-cli-next",'
        f'"qualification_executable_sha256":"{SHA}",'
        f"\"qualification_profile_sha256\":\"{SHA}\"}}'::jsonb, "
        f"qualification_receipt_id = '{NEXT_RECEIPT}' WHERE id = '{PROVIDER}'; "
        "ROLLBACK",
        check=False,
    )
    rollback = psql(
        "BEGIN; "
        + principal
        + "UPDATE provider_connections SET account_metadata = account_metadata || "
        f"'{{\"revision\":\"3\",\"qualification_receipt_id\":\"{NEXT_RECEIPT}\","
        f'"qualification_runtime_version":"codex-cli-next",'
        f'"qualification_executable_sha256":"{SHA}",'
        f"\"qualification_profile_sha256\":\"{SHA}\"}}'::jsonb, "
        f"qualification_receipt_id = '{NEXT_RECEIPT}' WHERE id = '{PROVIDER}'; "
        "UPDATE provider_connections SET account_metadata = account_metadata || "
        f"'{{\"revision\":\"2\",\"qualification_receipt_id\":\"{RECEIPT}\","
        f'"qualification_runtime_version":"codex-cli-fixture",'
        f'"qualification_executable_sha256":"{SHA}",'
        f"\"qualification_profile_sha256\":\"{SHA}\"}}'::jsonb, "
        f"qualification_receipt_id = '{RECEIPT}' WHERE id = '{PROVIDER}'; "
        "ROLLBACK",
        check=False,
    )
    projection_escape = psql(
        "BEGIN; "
        + principal
        + "UPDATE provider_connections SET account_metadata = account_metadata || "
        f"'{{\"revision\":\"3\",\"account_id\":\"forged\","
        f'"qualification_receipt_id":"{NEXT_RECEIPT}",'
        f'"qualification_runtime_version":"codex-cli-next",'
        f'"qualification_executable_sha256":"{SHA}",'
        f"\"qualification_profile_sha256\":\"{SHA}\"}}'::jsonb, "
        f"qualification_receipt_id = '{NEXT_RECEIPT}' WHERE id = '{PROVIDER}'; "
        "ROLLBACK",
        check=False,
    )
    skipped_receipt = psql(
        "BEGIN; "
        + principal
        + "INSERT INTO provider_qualification_receipts SELECT * FROM "
        f"provider_qualification_receipts WHERE id = '{SKIP_RECEIPT}'; ROLLBACK",
        check=False,
    )
    shadowed_revision = psql(
        "BEGIN; "
        + principal
        + "CREATE TEMP TABLE provider_connections (org_id uuid, "
        "requester_user_id uuid, id uuid, account_metadata jsonb, "
        "adapter_id text) ON COMMIT DROP; INSERT INTO provider_connections "
        f"VALUES ('{ORG_A}', '{USER_A}', '{PROVIDER}', "
        "'{\"revision\":\"98\"}'::jsonb, 'openai_codex'); INSERT INTO "
        "public.provider_qualification_receipts (id, org_id, requester_user_id, "
        "provider_connection_id, connection_revision, adapter_id, "
        "profile_sha256, cases_sha256, operator_account_ref, oauth_mode, "
        "oauth_provider, runtime_version, executable_sha256, protocol_attempts, "
        "cleanup_terminal, cleanup_redaction_complete, authority_key_id, "
        "authority_issued_at, authority_algorithm, authority_signature, "
        f"receipt_sha256) VALUES ('{SHADOW_RECEIPT}', '{ORG_A}', '{USER_A}', "
        f"'{PROVIDER}', 99, 'openai_codex', '{SHA}', '{SHA}', 'acct-shadow', "
        "'official_subscription_oauth', 'openai', 'codex-cli-shadow', "
        f"'{SHA}', 30, true, true, 'fixture-key', CURRENT_TIMESTAMP, "
        "'RSASSA-PKCS1-v1_5/SHA-256', repeat('f', 768), repeat('a', 64)); "
        "ROLLBACK",
        check=False,
    )
    shadowed_pointer = psql(
        "BEGIN; "
        + principal
        + "CREATE TEMP TABLE provider_qualification_receipts "
        "(connection_revision bigint, adapter_id text, profile_sha256 text, "
        "runtime_version text, executable_sha256 text, "
        "authority_issued_at timestamptz, org_id uuid, requester_user_id uuid, "
        "provider_connection_id uuid, id uuid) ON COMMIT DROP; INSERT INTO "
        "provider_qualification_receipts VALUES "
        f"(3, 'openai_codex', '{SHA}', 'codex-cli-skip', '{SHA}', "
        f"CURRENT_TIMESTAMP, '{ORG_A}', '{USER_A}', '{PROVIDER}', "
        f"'{SKIP_RECEIPT}'); UPDATE public.provider_connections SET "
        "account_metadata = account_metadata || "
        f"'{{\"revision\":\"3\",\"qualification_receipt_id\":\"{SKIP_RECEIPT}\","
        f'"qualification_runtime_version":"codex-cli-skip",'
        f'"qualification_executable_sha256":"{SHA}",'
        f"\"qualification_profile_sha256\":\"{SHA}\"}}'::jsonb, "
        f"qualification_receipt_id = '{SKIP_RECEIPT}' WHERE id = '{PROVIDER}'; "
        "ROLLBACK",
        check=False,
    )

    assert exact.returncode == 0
    assert "advance exactly one revision" in rollback.stderr
    assert "exact qualification projection" in projection_escape.stderr
    assert "advance exactly one revision" in skipped_receipt.stderr
    assert "advance exactly one revision" in shadowed_revision.stderr
    assert "provider qualification pointer is stale" in shadowed_pointer.stderr


def test_dispatcher_role_creates_only_an_exact_current_model_run() -> None:
    seed_execution_graph()
    principal = "SET ROLE science_workbench_dispatcher; " + app_principal_sql(
        ORG_A, USER_A
    )
    accepted = psql(
        principal
        + "INSERT INTO runs (id, org_id, session_id, requester_id, "
        "provider_connection_id, status, qualification_receipt_id, "
        "qualification_receipt_sha256, qualification_connection_revision, "
        "qualification_profile_sha256, qualification_runtime_version, "
        "qualification_executable_sha256, provider_model_id) VALUES "
        f"('{DISPATCHED_RUN}', '{ORG_A}', '{SESSION}', '{USER_A}', '{PROVIDER}', "
        f"'queued', '{RECEIPT}', '{RECEIPT_SHA}', 2, '{SHA}', "
        f"'codex-cli-fixture', '{SHA}', 'codex-mini')"
    )
    wrong_model = psql(
        principal
        + "INSERT INTO runs (id, org_id, session_id, requester_id, "
        "provider_connection_id, status, qualification_receipt_id, "
        "qualification_receipt_sha256, qualification_connection_revision, "
        "qualification_profile_sha256, qualification_runtime_version, "
        "qualification_executable_sha256, provider_model_id) VALUES "
        f"('{RACING_RUN}', '{ORG_A}', '{SESSION}', '{USER_A}', '{PROVIDER}', "
        f"'queued', '{RECEIPT}', '{RECEIPT_SHA}', 2, '{SHA}', "
        f"'codex-cli-fixture', '{SHA}', 'wrong-model')",
        check=False,
    )

    assert accepted.returncode == 0
    assert "run requires current provider model" in wrong_model.stderr


def test_dispatch_waits_for_concurrent_revocation_and_fails_closed() -> None:
    seed_execution_graph()

    async def run_race() -> tuple[str, ...]:
        engine = create_async_engine(database_url_asyncpg(), poolclass=NullPool)
        revoked = anyio.Event()
        dispatch_started = anyio.Event()
        errors: list[str] = []

        async def revoke() -> None:
            async with engine.begin() as database:
                _ = await database.execute(
                    text(
                        "UPDATE provider_connections SET status = "
                        "'reauth_required' WHERE id = :provider"
                    ),
                    {"provider": PROVIDER},
                )
                revoked.set()
                await dispatch_started.wait()

        async def dispatch() -> None:
            await revoked.wait()
            try:
                async with engine.begin() as database:
                    _ = await database.execute(
                        text("SET LOCAL ROLE science_workbench_dispatcher")
                    )
                    _ = await database.execute(
                        text(
                            "SELECT set_config('app.org_id', :org, true), "
                            "set_config('app.user_id', :user, true)"
                        ),
                        {"org": ORG_A, "user": USER_A},
                    )
                    dispatch_started.set()
                    _ = await database.execute(
                        text(
                            "INSERT INTO runs (id, org_id, session_id, "
                            "requester_id, provider_connection_id, status, "
                            "qualification_receipt_id, "
                            "qualification_receipt_sha256, "
                            "qualification_connection_revision, "
                            "qualification_profile_sha256, "
                            "qualification_runtime_version, "
                            "qualification_executable_sha256, provider_model_id) "
                            "VALUES (:run, :org, :session, :user, :provider, "
                            "'queued', :receipt, :receipt_sha, 2, :sha, "
                            "'codex-cli-fixture', :sha, 'codex-mini')"
                        ),
                        {
                            "run": RACING_RUN,
                            "org": ORG_A,
                            "session": SESSION,
                            "user": USER_A,
                            "provider": PROVIDER,
                            "receipt": RECEIPT,
                            "receipt_sha": RECEIPT_SHA,
                            "sha": SHA,
                        },
                    )
            except DBAPIError as error:
                errors.append(str(error.orig))

        try:
            async with anyio.create_task_group() as tasks:
                _ = tasks.start_soon(revoke)
                _ = tasks.start_soon(dispatch)
        finally:
            await engine.dispose()
        return tuple(errors)

    errors = anyio.run(run_race)
    _ = psql(
        f"UPDATE provider_connections SET status = 'healthy' WHERE id = '{PROVIDER}'"
    )

    assert len(errors) == 1
    assert "run requires a healthy provider" in errors[0]


def test_action_plan_schema_requires_a_canonical_research_intent_pin() -> None:
    # Given/When: the migrated PostgreSQL catalog is queried directly.
    column = psql(
        "SELECT data_type || ':' || is_nullable FROM information_schema.columns "
        "WHERE table_schema = 'public' AND table_name = 'action_plans' "
        "AND column_name = 'research_intent_sha256'"
    ).stdout.strip()

    # Then: every persisted ActionPlan has a required fixed-width intent digest.
    assert column == "character varying:NO"


def test_action_plan_persistence_rejects_missing_or_invalid_research_intent() -> None:
    seed_execution_graph()
    missing = psql(
        "INSERT INTO action_plans (id, org_id, run_id, requester_id, version, "
        "tool, arguments, arguments_hash, network_scope, secret_scope, reason, "
        f"plan_digest) VALUES ('{BAD_PLAN}', '{ORG_A}', '{RUN}', '{USER_A}', "
        f"2, 'python', '{{}}', '{SHA}', '{{}}', '{{}}', 'bad', '{SHA}')",
        check=False,
    )
    invalid_digest = psql(
        "INSERT INTO action_plans (id, org_id, run_id, requester_id, "
        "research_intent, research_intent_sha256, version, tool, arguments, "
        "arguments_hash, network_scope, secret_scope, reason, plan_digest) "
        f"VALUES ('{BAD_PLAN}', '{ORG_A}', '{RUN}', '{USER_A}', "
        f"'{RESEARCH_INTENT_SQL}', '{'x' * 64}', 2, 'python', '{{}}', "
        f"'{SHA}', '{{}}', '{{}}', 'bad', '{SHA}')",
        check=False,
    )
    incomplete = psql(
        "INSERT INTO action_plans (id, org_id, run_id, requester_id, "
        "research_intent, research_intent_sha256, version, tool, arguments, "
        "arguments_hash, network_scope, secret_scope, reason, plan_digest) "
        f"VALUES ('{BAD_PLAN}', '{ORG_A}', '{RUN}', '{USER_A}', '{{}}', "
        "encode(sha256(convert_to(science_workbench_canonical_jsonb('{}'::jsonb), "
        f"'UTF8')), 'hex'), 2, 'python', '{{}}', '{SHA}', '{{}}', '{{}}', 'bad', "
        f"'{SHA}')",
        check=False,
    )
    wrong_binding = psql(
        "INSERT INTO action_plans (id, org_id, run_id, requester_id, "
        "research_intent, research_intent_sha256, version, tool, arguments, "
        "arguments_hash, network_scope, secret_scope, reason, plan_digest) "
        f"VALUES ('{BAD_PLAN}', '{ORG_A}', '{RUN}', '{USER_A}', "
        f"'{RESEARCH_INTENT_SQL}', '{SHA}', 2, 'python', '{{}}', "
        f"'{SHA}', '{{}}', '{{}}', 'bad', '{SHA}')",
        check=False,
    )
    extra_key_intent = RESEARCH_INTENT_SQL[:-1] + ',"server_default":"forbidden"}'
    extra_key = psql(
        "INSERT INTO action_plans (id, org_id, run_id, requester_id, "
        "research_intent, research_intent_sha256, version, tool, arguments, "
        "arguments_hash, network_scope, secret_scope, reason, plan_digest) "
        f"VALUES ('{BAD_PLAN}', '{ORG_A}', '{RUN}', '{USER_A}', "
        f"'{extra_key_intent}', encode(sha256(convert_to("
        f"science_workbench_canonical_jsonb('{extra_key_intent}'::jsonb), "
        f"'UTF8')), 'hex'), 2, 'python', '{{}}', '{SHA}', '{{}}', '{{}}', "
        f"'bad', '{SHA}')",
        check=False,
    )
    collision_intent = RESEARCH_INTENT_SQL.replace(
        '"동일 입력은 동일 체크섬을 만든다."', '"é","e\\u0301"'
    )
    collision = psql(
        "INSERT INTO action_plans (id, org_id, run_id, requester_id, "
        "research_intent, research_intent_sha256, version, tool, arguments, "
        "arguments_hash, network_scope, secret_scope, reason, plan_digest) "
        f"VALUES ('{BAD_PLAN}', '{ORG_A}', '{RUN}', '{USER_A}', "
        f"'{collision_intent}', encode(sha256(convert_to("
        f"science_workbench_canonical_jsonb('{collision_intent}'::jsonb), "
        f"'UTF8')), 'hex'), 2, 'python', '{{}}', '{SHA}', '{{}}', '{{}}', "
        f"'bad', '{SHA}')",
        check=False,
    )
    assert "research_intent" in missing.stderr
    assert "action_plan_research_intent_digest_binding" in invalid_digest.stderr
    assert "action_plan_research_intent_complete" in incomplete.stderr
    assert "action_plan_research_intent_digest_binding" in wrong_binding.stderr
    assert "action_plan_research_intent_complete" in extra_key.stderr
    assert "action_plan_research_intent_complete" in collision.stderr


def test_database_canonical_digest_matches_all_language_boundaries() -> None:
    assert psql(
        "SELECT encode(sha256(convert_to(science_workbench_canonical_jsonb("
        f"'{RESEARCH_INTENT_SQL}'::jsonb), 'UTF8')), 'hex')"
    ).stdout.strip() == RESEARCH_INTENT_SHA


def seed_execution_graph() -> None:
    seed_qualified_provider()
    _ = psql(
        "INSERT INTO runs (id, org_id, session_id, requester_id, "
        "provider_connection_id, status, qualification_receipt_id, "
        "qualification_receipt_sha256, qualification_connection_revision, "
        "qualification_profile_sha256, qualification_runtime_version, "
        "qualification_executable_sha256, provider_model_id) VALUES "
        f"('{RUN}', '{ORG_A}', '{SESSION}', '{USER_A}', '{PROVIDER}', 'running', "
        f"'{RECEIPT}', '{RECEIPT_SHA}', 2, '{SHA}', 'codex-cli-fixture', '{SHA}', "
        "'codex-mini') "
        "ON CONFLICT DO NOTHING; "
        "INSERT INTO action_plans (id, org_id, run_id, requester_id, "
        "research_intent, research_intent_sha256, version, tool, arguments, "
        "arguments_hash, network_scope, secret_scope, reason, plan_digest) "
        f"VALUES ('{PLAN}', '{ORG_A}', '{RUN}', '{USER_A}', "
        f"'{RESEARCH_INTENT_SQL}', '{RESEARCH_INTENT_SHA}', 1, 'python', "
        f"'{{}}', '{SHA}', "
        f"'{{}}', '{{}}', 'contract', '{SHA}') ON CONFLICT DO NOTHING"
    )


def seed_qualified_provider() -> None:
    seed_tenants()
    _ = psql(
        "INSERT INTO sessions (id, org_id, project_id, title) VALUES "
        f"('{SESSION}', '{ORG_A}', '{PROJECT_A}', 'Contract') ON CONFLICT DO NOTHING; "
        "INSERT INTO provider_connections (id, org_id, requester_user_id, adapter_id, "
        "encrypted_runtime_home_ref, account_metadata, selected_model, status) "
        "VALUES "
        f"('{PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        "'vault://runtime/contract', "
        f"'{{\"revision\":\"2\",\"qualification_receipt_id\":\"{RECEIPT}\","
        f'"qualification_runtime_version":"codex-cli-fixture",'
        f'"qualification_executable_sha256":"{SHA}",'
        f"\"qualification_profile_sha256\":\"{SHA}\"}}', "
        "'codex-mini', 'pending') "
        "ON CONFLICT DO NOTHING; INSERT INTO provider_qualification_receipts "
        "(id, org_id, requester_user_id, provider_connection_id, "
        "connection_revision, adapter_id, profile_sha256, cases_sha256, "
        "operator_account_ref, oauth_mode, oauth_provider, runtime_version, "
        "executable_sha256, protocol_attempts, cleanup_terminal, "
        "cleanup_redaction_complete, authority_key_id, authority_issued_at, "
        "authority_algorithm, authority_signature, receipt_sha256) VALUES "
        f"('{RECEIPT}', '{ORG_A}', '{USER_A}', '{PROVIDER}', 2, 'openai_codex', "
        f"'{SHA}', '{SHA}', 'acct_persistence_fixture', "
        "'official_subscription_oauth', 'openai', 'codex-cli-fixture', "
        f"'{SHA}', 30, true, true, 'fixture-key', CURRENT_TIMESTAMP, "
        "'RSASSA-PKCS1-v1_5/SHA-256', "
        f"'{'a' * 768}', '{RECEIPT_SHA}') ON CONFLICT DO NOTHING; UPDATE "
        "provider_connections SET status = 'healthy', qualified_at = "
        f"CURRENT_TIMESTAMP, qualification_receipt_id = '{RECEIPT}' WHERE id = "
        f"'{PROVIDER}'"
    )


def seed_artifact_version() -> None:
    seed_execution_graph()
    _ = psql(
        "INSERT INTO executions (id, org_id, run_id, action_plan_id, status, "
        f"attempt_token, result_ref) VALUES ('{EXECUTION}', '{ORG_A}', '{RUN}', "
        f"'{PLAN}', 'completed', 1, 'artifact://result') ON CONFLICT DO NOTHING; "
        "INSERT INTO artifacts (id, org_id, project_id, name) VALUES "
        f"('{ARTIFACT}', '{ORG_A}', '{PROJECT_A}', 'Result') ON CONFLICT DO NOTHING; "
        "INSERT INTO artifact_versions (id, org_id, project_id, artifact_id, "
        "producing_execution_id, runtime_connection_id, version, object_key, "
        "content_sha256, size_bytes, media_type, environment_sha256, code_sha256, "
        "runtime_adapter_id, skill_content_hashes, source_hashes) VALUES "
        f"('{VERSION}', '{ORG_A}', '{PROJECT_A}', '{ARTIFACT}', '{EXECUTION}', "
        f"'{PROVIDER}', 1, 'org/{ORG_A}/project/{PROJECT_A}/sha256/{SHA}', "
        f"'{SHA}', 1, 'text/csv', '{SHA}', '{SHA}', "
        "'openai_codex', '{}', '{}') ON CONFLICT DO NOTHING"
    )


def seed_completed_review() -> None:
    seed_artifact_version()
    _ = psql(
        "BEGIN; INSERT INTO reviews (id, org_id, source_run_id, run_id, "
        f"pinned_input_sha256, status) VALUES ('{REVIEW}', '{ORG_A}', '{RUN}', "
        f"'{RUN}', '{SHA}', 'running') ON CONFLICT DO NOTHING; "
        "INSERT INTO review_artifact_versions (org_id, review_id, artifact_version_id) "
        f"SELECT '{ORG_A}', '{REVIEW}', '{VERSION}' WHERE EXISTS (SELECT 1 FROM "
        f"reviews WHERE id = '{REVIEW}' AND status = 'running') AND NOT EXISTS "
        "(SELECT 1 FROM review_artifact_versions WHERE "
        f"review_id = '{REVIEW}' AND artifact_version_id = '{VERSION}'); "
        "INSERT INTO review_execution_refs (org_id, review_id, execution_id) "
        f"SELECT '{ORG_A}', '{REVIEW}', '{EXECUTION}' WHERE EXISTS (SELECT 1 FROM "
        f"reviews WHERE id = '{REVIEW}' AND status = 'running') AND NOT EXISTS "
        f"(SELECT 1 FROM review_execution_refs WHERE review_id = '{REVIEW}' "
        f"AND execution_id = '{EXECUTION}'); "
        f"UPDATE reviews SET revision = revision + 1, "
        f"submission_id = '{SUBMISSION}', submitted_at = CURRENT_TIMESTAMP "
        f"WHERE id = '{REVIEW}' AND status = 'running'; "
        "INSERT INTO review_findings (id, org_id, review_id, submission_id, rule_id, "
        f"verdict, status, message) SELECT '{FINDING}', '{ORG_A}', '{REVIEW}', "
        f"'{SUBMISSION}', 'RV01', 'pass', 'open', 'verified' WHERE EXISTS "
        f"(SELECT 1 FROM reviews WHERE id = '{REVIEW}' AND status = 'running') "
        f"AND NOT EXISTS (SELECT 1 FROM review_findings WHERE id = '{FINDING}'); "
        "INSERT INTO review_finding_artifact_versions "
        f"(org_id, finding_id, artifact_version_id) SELECT '{ORG_A}', '{FINDING}', "
        f"'{VERSION}' WHERE EXISTS (SELECT 1 FROM reviews WHERE id = '{REVIEW}' "
        f"AND status = 'running') AND NOT EXISTS (SELECT 1 FROM "
        f"review_finding_artifact_versions WHERE finding_id = '{FINDING}' AND "
        f"artifact_version_id = '{VERSION}'); UPDATE reviews SET "
        f"status = 'completed', revision = revision + 1 WHERE id = '{REVIEW}' "
        "AND status = 'running'; COMMIT"
    )


def test_approval_revision_and_completed_execution_result_are_enforced() -> None:
    seed_execution_graph()
    revision = psql(
        "INSERT INTO approval_requests (id, org_id, run_id, action_plan_id, "
        "requester_id, digest, status, expires_at) VALUES "
        f"('{APPROVAL}', '{ORG_A}', '{RUN}', '{PLAN}', '{USER_A}', '{SHA}', "
        "'pending', CURRENT_TIMESTAMP + interval '5 minutes') RETURNING revision"
    ).stdout.strip()
    rejected = psql(
        "INSERT INTO executions (id, org_id, run_id, action_plan_id, status, "
        f"attempt_token) VALUES ('{BAD_EXECUTION}', '{ORG_A}', '{RUN}', "
        f"'{PLAN}', 'completed', 1)",
        check=False,
    )
    accepted = psql(
        "INSERT INTO executions (id, org_id, run_id, action_plan_id, status, "
        f"attempt_token, result_ref) VALUES ('{EXECUTION}', '{ORG_A}', '{RUN}', "
        f"'{PLAN}', 'completed', 1, 'artifact://result')"
    )
    assert revision == "1"
    assert "completed_execution_result" in rejected.stderr
    assert accepted.returncode == 0


def test_review_cas_submission_and_finding_evidence_are_representable() -> None:
    seed_artifact_version()
    initial = psql(
        "BEGIN; INSERT INTO reviews (id, org_id, source_run_id, run_id, "
        f"pinned_input_sha256, status) VALUES ('{REVIEW}', '{ORG_A}', '{RUN}', "
        f"'{RUN}', '{SHA}', 'running'); INSERT INTO review_execution_refs "
        f"(org_id, review_id, execution_id) VALUES ('{ORG_A}', '{REVIEW}', "
        f"'{EXECUTION}'); INSERT INTO review_artifact_versions "
        f"(org_id, review_id, artifact_version_id) VALUES ('{ORG_A}', '{REVIEW}', "
        f"'{VERSION}'); COMMIT; SELECT revision || ':' || "
        f"(reviewer_capabilities->>'reexecution') FROM reviews WHERE id = '{REVIEW}'"
    ).stdout.strip()
    missing_submission = psql(
        f"UPDATE reviews SET status = 'completed', revision = 2 WHERE id = '{REVIEW}'",
        check=False,
    )
    missing_disposition = psql(
        f"BEGIN; UPDATE reviews SET revision = 2, submission_id = '{SUBMISSION}', "
        f"submitted_at = CURRENT_TIMESTAMP WHERE id = '{REVIEW}'; "
        "INSERT INTO review_findings (id, org_id, review_id, submission_id, rule_id, "
        f"verdict, status, message) VALUES ('{BAD_FINDING}', '{ORG_A}', '{REVIEW}', "
        f"'{SUBMISSION}', 'RV02', 'warn', 'accepted_risk', 'missing audit'); COMMIT",
        check=False,
    )
    submitted = psql(
        f"BEGIN; UPDATE reviews SET revision = 2, "
        f"submission_id = '{SUBMISSION}', submitted_at = CURRENT_TIMESTAMP "
        f"WHERE id = '{REVIEW}'; INSERT INTO review_findings (id, org_id, review_id, "
        "submission_id, rule_id, verdict, status, message) VALUES "
        f"('{FINDING}', '{ORG_A}', '{REVIEW}', '{SUBMISSION}', 'RV01', 'pass', "
        f"'open', 'verified'); INSERT INTO review_finding_artifact_versions "
        f"(org_id, finding_id, artifact_version_id) VALUES ('{ORG_A}', '{FINDING}', "
        f"'{VERSION}'); UPDATE reviews SET status = 'completed', revision = 3 "
        f"WHERE id = '{REVIEW}'; COMMIT",
        check=False,
    )
    assert initial == "1:false"
    assert "review submission lifecycle" in missing_submission.stderr
    assert submitted.returncode == 0, submitted.stderr
    assert "finding_disposition_audit" in missing_disposition.stderr
