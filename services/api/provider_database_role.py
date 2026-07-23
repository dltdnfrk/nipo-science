"""Database checks for single-purpose provider service login roles."""

from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

from sqlalchemy import text

from services.api.provider_database_authority import (
    database_has_public_sensitive_authority,
    database_role_direct_acls,
    database_role_owns_objects,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection

SAFE_PROVIDER_SEARCH_PATH_SQL: Final = (
    "SET LOCAL search_path = pg_catalog, public, pg_temp"
)

_CAPABILITY_ACLS = {
    "science_workbench_qualification": frozenset(
        {
            "schema:public:USAGE",
            "table:public.provider_connections:SELECT",
            "table:public.provider_qualification_receipts:INSERT",
            "table:public.provider_qualification_receipts:SELECT",
            "column:public.provider_connections.account_metadata:UPDATE",
            "column:public.provider_connections.qualification_receipt_id:UPDATE",
            "column:public.provider_connections.qualified_at:UPDATE",
            "function:public.current_principal_org():EXECUTE",
        }
    ),
    "science_workbench_dispatcher": frozenset(
        {
            "schema:public:USAGE",
            "table:public.provider_connections:SELECT",
            "table:public.provider_qualification_receipts:SELECT",
            "table:public.runs:INSERT",
            "function:public.current_principal_org():EXECUTE",
        }
    ),
    "science_workbench_provider_cleanup": frozenset(
        {
            "schema:public:USAGE",
            (
                "function:public.provider_due_cleanup_candidates(timestamp with time "
                "zone):EXECUTE"
            ),
            (
                "function:public.validate_due_provider_cleanup(uuid,uuid,uuid,text,text,"
                "timestamp with time zone):EXECUTE"
            ),
            (
                "function:public.complete_provider_cleanup_outbox(uuid,uuid,uuid,text,text,"
                "timestamp with time zone,text):EXECUTE"
            ),
            (
                "function:public.complete_provider_revoked_cleanup(uuid,uuid,uuid,text,"
                "timestamp with time zone,text):EXECUTE"
            ),
        }
    ),
}


async def dedicated_provider_login_is_confined(
    database: AsyncConnection,
    *,
    expected_login_role: str,
    capability_role: str,
) -> bool:
    """Accept only a direct, unprivileged member of one NOLOGIN capability role."""
    _ = await database.execute(text(SAFE_PROVIDER_SEARCH_PATH_SQL))
    expected_acls = _CAPABILITY_ACLS.get(capability_role)
    if expected_acls is None:
        return False
    identity = (
        await database.execute(
            text(
                "SELECT session_user, login.rolcanlogin AND NOT login.rolsuper AND "
                "NOT login.rolbypassrls AND NOT login.rolcreatedb AND NOT "
                "login.rolcreaterole AND NOT login.rolreplication AND NOT "
                "login.rolinherit AND login.rolconfig IS NULL AND NOT EXISTS "
                "(SELECT 1 FROM pg_auth_members "
                "WHERE roleid = login.oid), NOT capability.rolcanlogin AND NOT "
                "capability.rolsuper AND NOT capability.rolbypassrls AND NOT "
                "capability.rolcreatedb AND NOT capability.rolcreaterole AND NOT "
                "capability.rolreplication AND NOT capability.rolinherit AND "
                "capability.rolconfig IS NULL, "
                "COALESCE((SELECT array_agg(parent.rolname ORDER BY parent.rolname) "
                "FROM pg_auth_members memberships JOIN pg_roles parent ON "
                "parent.oid = memberships.roleid WHERE memberships.member = "
                "login.oid), ARRAY[]::name[]), COALESCE((SELECT bool_or("
                "memberships.admin_option) FROM pg_auth_members memberships WHERE "
                "memberships.member = login.oid), false), NOT EXISTS (SELECT 1 "
                "FROM pg_auth_members WHERE member = capability.oid), NOT EXISTS "
                "(SELECT 1 FROM pg_auth_members WHERE member = capability.oid AND "
                "admin_option), COALESCE((SELECT array_agg(member.rolname ORDER BY "
                "member.rolname) FROM pg_auth_members memberships JOIN pg_roles "
                "member ON member.oid = memberships.member WHERE memberships."
                "roleid = capability.oid), ARRAY[]::name[]), COALESCE((SELECT "
                "bool_or(memberships.admin_option) FROM pg_auth_members "
                "memberships WHERE memberships.roleid = capability.oid), false), "
                "COALESCE((SELECT bool_or(memberships.inherit_option) FROM "
                "pg_auth_members memberships WHERE memberships.roleid = "
                "capability.oid), false), COALESCE((SELECT bool_and(memberships."
                "set_option) FROM pg_auth_members memberships WHERE memberships."
                "roleid = capability.oid), false) FROM pg_roles login JOIN "
                "pg_roles capability ON capability.rolname = :capability WHERE "
                "login.rolname = session_user"
            ),
            {"capability": capability_role},
        )
    ).one_or_none()
    if identity is None:
        return False
    memberships = tuple(cast("list[str]", identity[3]))
    capability_members = tuple(cast("list[str]", identity[7]))
    if (
        identity[0] != expected_login_role
        or identity[1] is not True
        or identity[2] is not True
        or memberships != (capability_role,)
        or identity[4] is not False
        or identity[5] is not True
        or identity[6] is not True
        or capability_members != (expected_login_role,)
        or identity[8] is not False
        or identity[9] is not False
        or identity[10] is not True
    ):
        return False
    if await database_role_owns_objects(
        database, role_name=expected_login_role
    ) or await database_role_direct_acls(database, role_name=expected_login_role):
        return False
    return await provider_capability_acl_is_exact(
        database,
        capability_role=capability_role,
    )


async def provider_capability_acl_is_exact(
    database: AsyncConnection,
    *,
    capability_role: str,
) -> bool:
    """Require exact direct ACLs and effective callable functions for a capability."""
    expected_acls = _CAPABILITY_ACLS.get(capability_role)
    if expected_acls is None:
        return False
    if await database_has_public_sensitive_authority(database):
        return False
    direct_acls = await database_role_direct_acls(
        database, role_name=capability_role
    )
    if await database_role_owns_objects(database, role_name=capability_role):
        return False
    effective_function_rows = await database.execute(
        text(
            "SELECT n.nspname || '.' || p.oid::regprocedure::text FROM pg_proc p "
            "JOIN pg_namespace n ON n.oid = p.pronamespace WHERE n.nspname <> "
            "'information_schema' AND n.nspname NOT LIKE 'pg\\_%' ESCAPE '\\' AND "
            "has_function_privilege(CAST(:capability AS name), p.oid, 'EXECUTE') "
            "ORDER BY 1"
        ),
        {"capability": capability_role},
    )
    effective_function_acls = frozenset(
        f"function:{cast('str', row[0])}:EXECUTE" for row in effective_function_rows
    )
    expected_function_acls = frozenset(
        acl for acl in expected_acls if acl.startswith("function:")
    )
    return (
        direct_acls == expected_acls
        and effective_function_acls == expected_function_acls
    )
