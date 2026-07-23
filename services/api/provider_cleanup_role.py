"""Database identity checks for the provider cleanup service login."""

from __future__ import annotations

from typing import TYPE_CHECKING, cast

from sqlalchemy import text

from services.api.migrations.versioned_0004_role_names import (
    APP_ROLE,
    CLEANUP_CAPABILITY_ROLE,
    CLEANUP_DEFINER_ROLE,
)
from services.api.provider_database_authority import (
    database_role_direct_acls,
    database_role_owned_object_inventory,
    database_role_owns_objects,
)
from services.api.provider_database_role import (
    SAFE_PROVIDER_SEARCH_PATH_SQL,
    provider_capability_acl_is_exact,
)

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection

PROVIDER_CLEANUP_CAPABILITY_ROLE = CLEANUP_CAPABILITY_ROLE

_DEFINER_BASE_ACLS = frozenset(
    {
        "schema:public:USAGE",
        "table:public.provider_connections:SELECT",
        "table:public.provider_runtime_home_cleanups:INSERT",
        "table:public.provider_runtime_home_cleanups:SELECT",
        "column:public.provider_connections.account_metadata:UPDATE",
        "column:public.provider_connections.encrypted_runtime_home_ref:UPDATE",
        "column:public.provider_connections.superseded_runtime_home_ref:UPDATE",
        "column:public.provider_runtime_home_cleanups.destroyed_at:UPDATE",
        "column:public.provider_runtime_home_cleanups.evidence_sha256:UPDATE",
        "column:public.provider_runtime_home_cleanups.status:UPDATE",
    }
)
_DEFINER_FUNCTIONS = frozenset(
    {
        "function:public.provider_due_cleanup_candidates(timestamp with time zone)",
        (
            "function:public.validate_due_provider_cleanup(uuid,uuid,uuid,text,text,"
            "timestamp with time zone)"
        ),
        (
            "function:public.complete_provider_cleanup_outbox(uuid,uuid,uuid,text,"
            "text,timestamp with time zone,text)"
        ),
        (
            "function:public.complete_provider_revoked_cleanup(uuid,uuid,uuid,text,"
            "timestamp with time zone,text)"
        ),
        "function:public.lock_provider_connection_runtime_refs()",
        "function:public.reserve_provider_revoke_cleanup_refs()",
        "function:public.lock_provider_cleanup_runtime_ref()",
    }
)
_DEFINER_ACLS = _DEFINER_BASE_ACLS | frozenset(
    f"{owned_function}:EXECUTE" for owned_function in _DEFINER_FUNCTIONS
)
_SERVICE_FUNCTIONS = frozenset(
    function
    for function in _DEFINER_FUNCTIONS
    if not function.startswith("function:public.lock_provider_")
    and not function.startswith("function:public.reserve_provider_")
)
_VALIDATION_FUNCTION = (
    "function:public.validate_due_provider_cleanup(uuid,uuid,uuid,text,text,"
    "timestamp with time zone)"
)
_OUTBOX_COMPLETION_FUNCTION = (
    "function:public.complete_provider_cleanup_outbox(uuid,uuid,uuid,text,text,"
    "timestamp with time zone,text)"
)
_DEFINER_FUNCTION_ACLS = (
    frozenset(
        f"{function}|{CLEANUP_DEFINER_ROLE}|EXECUTE|false"
        for function in _DEFINER_FUNCTIONS
    )
    | frozenset(
        f"{function}|{CLEANUP_CAPABILITY_ROLE}|EXECUTE|false"
        for function in _SERVICE_FUNCTIONS
    )
    | frozenset(
        {
            f"{_VALIDATION_FUNCTION}|{APP_ROLE}|EXECUTE|false",
            f"{_OUTBOX_COMPLETION_FUNCTION}|{APP_ROLE}|EXECUTE|false",
        }
    )
)


async def cleanup_service_login_is_confined(
    database: AsyncConnection, expected_login_role: str
) -> bool:
    """Accept only a direct, unprivileged member of the cleanup capability."""
    _ = await database.execute(text(SAFE_PROVIDER_SEARCH_PATH_SQL))
    identity = (
        await database.execute(
            text(
                "SELECT session_user, login.rolcanlogin AND NOT login.rolsuper "
                "AND NOT login.rolbypassrls AND NOT login.rolcreatedb AND NOT "
                "login.rolcreaterole AND NOT login.rolreplication AND NOT "
                "login.rolinherit AND login.rolconfig IS NULL AND NOT EXISTS "
                "(SELECT 1 FROM pg_auth_members "
                "WHERE roleid = login.oid), NOT capability.rolcanlogin AND NOT "
                "capability.rolsuper AND NOT capability.rolbypassrls AND NOT "
                "capability.rolcreatedb AND NOT capability.rolcreaterole AND NOT "
                "capability.rolreplication AND NOT capability.rolinherit AND "
                "capability.rolconfig IS NULL, "
                "COALESCE((SELECT array_agg(parent.rolname ORDER BY "
                "parent.rolname) FROM pg_auth_members memberships JOIN pg_roles "
                "parent ON parent.oid = memberships.roleid WHERE "
                "memberships.member = login.oid), ARRAY[]::name[]), "
                "COALESCE((SELECT bool_or(memberships.admin_option) FROM "
                "pg_auth_members memberships WHERE memberships.member = "
                "login.oid), false), COALESCE((SELECT array_agg(parent.rolname "
                "ORDER BY parent.rolname) FROM pg_auth_members memberships JOIN "
                "pg_roles parent ON parent.oid = memberships.roleid WHERE "
                "memberships.member = capability.oid), ARRAY[]::name[]), "
                "COALESCE((SELECT bool_or(memberships.admin_option) FROM "
                "pg_auth_members memberships WHERE memberships.member = "
                "capability.oid), false), COALESCE((SELECT array_agg(member."
                "rolname ORDER BY member.rolname) FROM pg_auth_members "
                "memberships JOIN pg_roles member ON member.oid = memberships."
                "member WHERE memberships.roleid = capability.oid), ARRAY[]::"
                "name[]), COALESCE((SELECT bool_or(memberships.admin_option) "
                "FROM pg_auth_members memberships WHERE memberships.roleid = "
                "capability.oid), false), COALESCE((SELECT bool_or(memberships."
                "inherit_option) FROM pg_auth_members memberships WHERE "
                "memberships.roleid = capability.oid), false), COALESCE((SELECT "
                "bool_and(memberships.set_option) FROM pg_auth_members memberships "
                "WHERE memberships.roleid = capability.oid), false) FROM pg_roles "
                "login JOIN pg_roles "
                "capability ON capability.rolname = :capability WHERE "
                "login.rolname = session_user"
            ),
            {"capability": PROVIDER_CLEANUP_CAPABILITY_ROLE},
        )
    ).one_or_none()
    if identity is None:
        return False
    login_memberships = tuple(cast("list[str]", identity[3]))
    capability_memberships = tuple(cast("list[str]", identity[5]))
    capability_members = tuple(cast("list[str]", identity[7]))
    if (
        identity[0] != expected_login_role
        or identity[1] is not True
        or identity[2] is not True
        or login_memberships != (PROVIDER_CLEANUP_CAPABILITY_ROLE,)
        or identity[4] is not False
        or capability_memberships
        or identity[6] is not False
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
    if not await cleanup_definer_authority_is_exact(database):
        return False
    return await provider_capability_acl_is_exact(
        database,
        capability_role=PROVIDER_CLEANUP_CAPABILITY_ROLE,
    )


async def cleanup_definer_authority_is_exact(database: AsyncConnection) -> bool:
    """Require one immutable BYPASSRLS owner with only cleanup authority."""
    identity = (
        await database.execute(
            text(
                "SELECT NOT role.rolcanlogin AND NOT role.rolsuper AND "
                "role.rolbypassrls AND NOT role.rolcreatedb AND NOT "
                "role.rolcreaterole AND NOT role.rolreplication AND NOT "
                "role.rolinherit AND role.rolconfig IS NULL AND NOT EXISTS "
                "(SELECT 1 FROM pg_auth_members WHERE roleid = role.oid OR "
                "member = role.oid) FROM pg_roles role WHERE role.rolname = :role"
            ),
            {"role": CLEANUP_DEFINER_ROLE},
        )
    ).scalar_one_or_none()
    if identity is not True:
        return False
    direct_acls = await database_role_direct_acls(
        database,
        role_name=CLEANUP_DEFINER_ROLE,
    )
    if direct_acls != _DEFINER_ACLS:
        return False
    owned = await database_role_owned_object_inventory(
        database,
        role_name=CLEANUP_DEFINER_ROLE,
    )
    if owned != _DEFINER_FUNCTIONS:
        return False
    properties = await database.execute(
        text(
            "SELECT count(*) = :expected_count AND bool_and(function.prosecdef) "
            "AND bool_and(function.proconfig IS NOT DISTINCT FROM ARRAY["
            "'search_path=pg_catalog, pg_temp']::text[]) AND bool_and(NOT "
            "has_function_privilege("
            "'public', function.oid, 'EXECUTE')) FROM pg_proc function WHERE "
            "function.proowner = (SELECT oid FROM pg_roles WHERE rolname = :role)"
        ),
        {"expected_count": len(_DEFINER_FUNCTIONS), "role": CLEANUP_DEFINER_ROLE},
    )
    if properties.scalar_one() is not True:
        return False
    acl_rows = await database.execute(
        text(
            "SELECT 'function:' || namespace.nspname || '.' || function.oid::"
            "regprocedure::text || '|' || CASE WHEN acl.grantee = 0 THEN 'PUBLIC' "
            "ELSE grantee.rolname END || '|' || acl.privilege_type || '|' || "
            "acl.is_grantable::text FROM pg_proc function JOIN pg_namespace "
            "namespace ON namespace.oid = function.pronamespace JOIN pg_roles "
            "owner ON owner.oid = function.proowner CROSS JOIN LATERAL aclexplode("
            "function.proacl) acl LEFT JOIN pg_roles grantee ON grantee.oid = "
            "acl.grantee WHERE owner.rolname = :role ORDER BY 1"
        ),
        {"role": CLEANUP_DEFINER_ROLE},
    )
    function_acls = frozenset(cast("str", row[0]) for row in acl_rows)
    return function_acls == _DEFINER_FUNCTION_ACLS
