"""Version-pinned capability-role ACLs introduced by migration 0004."""

from alembic import op

from services.api.migrations.versioned_0004_cleanup_functions import (
    create_cleanup_functions,
    drop_cleanup_functions,
)
from services.api.migrations.versioned_0004_function_privileges import (
    harden_public_function_execute,
    restore_public_function_execute,
)
from services.api.migrations.versioned_0004_role_names import (
    APP_ROLE,
    CLEANUP_CAPABILITY_ROLE,
    CLEANUP_DEFINER_ROLE,
    DISPATCHER_ROLE,
    QUALIFICATION_ROLE,
)

_DISPATCHER = DISPATCHER_ROLE
_QUALIFICATION = QUALIFICATION_ROLE
_CLEANUP = CLEANUP_CAPABILITY_ROLE
_CLEANUP_DEFINER = CLEANUP_DEFINER_ROLE
_APP = APP_ROLE
_COMPLIANCE = "science_workbench_compliance"


def converge_provider_capability_roles() -> None:
    """Create hardened NOLOGIN roles and replace every direct object ACL."""
    harden_public_function_execute()
    _create_cleanup_definer_role()
    _replace_qualification_role()
    _create_role(_DISPATCHER, bypass_rls=False)
    _create_role(_CLEANUP, bypass_rls=False)
    for role in (_DISPATCHER, _QUALIFICATION, _CLEANUP):
        _revoke_direct_acl(role)
        op.execute(f"GRANT USAGE ON SCHEMA public TO {role}")
    op.execute(
        f"GRANT SELECT ON provider_connections, "
        f"provider_qualification_receipts TO {_DISPATCHER}"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.current_principal_org() TO "
        f"{_APP}, {_COMPLIANCE}, {_DISPATCHER}, {_QUALIFICATION}"
    )
    op.execute(f"GRANT INSERT ON runs TO {_DISPATCHER}")
    op.execute(
        f"GRANT SELECT, INSERT ON provider_qualification_receipts TO {_QUALIFICATION}"
    )
    op.execute(f"GRANT SELECT ON provider_connections TO {_QUALIFICATION}")
    op.execute(
        "GRANT UPDATE (account_metadata, qualified_at, "
        f"qualification_receipt_id) ON provider_connections TO {_QUALIFICATION}"
    )
    op.execute(
        "REVOKE UPDATE, DELETE ON provider_runtime_home_cleanups FROM "
        f"{_APP}"
    )
    create_cleanup_functions()
    _converge_cleanup_definer_acl()
    for signature in (
        "provider_due_cleanup_candidates(timestamptz)",
        "validate_due_provider_cleanup(uuid, uuid, uuid, text, text, timestamptz)",
        "complete_provider_cleanup_outbox(uuid, uuid, uuid, text, text, "
        "timestamptz, text)",
        "complete_provider_revoked_cleanup(uuid, uuid, uuid, text, timestamptz, text)",
    ):
        op.execute(
            f"ALTER FUNCTION public.{signature} OWNER TO {_CLEANUP_DEFINER}"
        )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.provider_due_cleanup_candidates("
        f"timestamptz) TO {_CLEANUP}"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.validate_due_provider_cleanup("
        f"uuid, uuid, uuid, text, text, timestamptz) TO {_CLEANUP}"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.validate_due_provider_cleanup("
        f"uuid, uuid, uuid, text, text, timestamptz) TO {_APP}"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.complete_provider_cleanup_outbox("
        f"uuid, uuid, uuid, text, text, timestamptz, text) TO {_CLEANUP}"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.complete_provider_cleanup_outbox("
        f"uuid, uuid, uuid, text, text, timestamptz, text) TO {_APP}"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.complete_provider_revoked_cleanup("
        f"uuid, uuid, uuid, text, timestamptz, text) TO {_CLEANUP}"
    )
    op.execute(f"REVOKE INSERT ON runs FROM {_APP}")


def drop_provider_capability_roles() -> None:
    """Remove 0004 roles only after deployment memberships are deprovisioned."""
    _require_deprovisioned_capability_memberships()
    op.execute(f"GRANT INSERT ON runs TO {_APP}")
    op.execute(
        "REVOKE UPDATE (status, destroyed_at, evidence_sha256) ON "
        f"provider_runtime_home_cleanups FROM {_APP}"
    )
    op.execute(
        "GRANT UPDATE, DELETE ON provider_runtime_home_cleanups TO "
        f"{_APP}"
    )
    op.execute(
        "REVOKE EXECUTE ON FUNCTION public.current_principal_org() FROM "
        f"{_APP}, {_COMPLIANCE}, {_QUALIFICATION}"
    )
    for role in (_DISPATCHER, _CLEANUP):
        _revoke_direct_acl(role)
        op.execute(f"DROP ROLE IF EXISTS {role}")
    drop_cleanup_functions()
    _drop_cleanup_definer_role()
    restore_public_function_execute()


def _create_cleanup_definer_role() -> None:
    op.execute(
        "DO $$ BEGIN IF to_regrole('"
        f"{_CLEANUP_DEFINER}') IS NOT NULL THEN RAISE EXCEPTION 'reserved provider "
        "cleanup definer role already exists' USING ERRCODE = '42710'; END IF; "
        f"CREATE ROLE {_CLEANUP_DEFINER} WITH NOLOGIN NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS; END $$"
    )


def _require_deprovisioned_capability_memberships() -> None:
    for role in (_DISPATCHER, _QUALIFICATION, _CLEANUP):
        op.execute(
            "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid = "
            f"'{role}'::regrole) THEN RAISE EXCEPTION "
            f"'deprovision members of {role} before downgrade' "
            "USING ERRCODE = '55000'; END IF; END $$"
        )


def _converge_cleanup_definer_acl() -> None:
    _revoke_direct_acl(_CLEANUP_DEFINER)
    op.execute(f"GRANT USAGE ON SCHEMA public TO {_CLEANUP_DEFINER}")
    op.execute(
        "GRANT SELECT ON provider_connections, provider_runtime_home_cleanups TO "
        f"{_CLEANUP_DEFINER}"
    )
    op.execute(
        "GRANT INSERT ON provider_runtime_home_cleanups TO "
        f"{_CLEANUP_DEFINER}"
    )
    op.execute(
        "GRANT UPDATE (encrypted_runtime_home_ref, "
        "superseded_runtime_home_ref, account_metadata) ON provider_connections TO "
        f"{_CLEANUP_DEFINER}"
    )
    op.execute(
        "GRANT UPDATE (status, destroyed_at, evidence_sha256) ON "
        f"provider_runtime_home_cleanups TO {_CLEANUP_DEFINER}"
    )


def _drop_cleanup_definer_role() -> None:
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM pg_auth_members WHERE roleid = "
        f"'{_CLEANUP_DEFINER}'::regrole OR member = '{_CLEANUP_DEFINER}'::regrole) "
        "THEN RAISE EXCEPTION 'provider cleanup definer role has unexpected "
        "memberships' USING ERRCODE = '55000'; END IF; END $$"
    )
    _revoke_direct_acl(_CLEANUP_DEFINER)
    op.execute(f"DROP ROLE {_CLEANUP_DEFINER}")


def _create_role(role: str, *, bypass_rls: bool) -> None:
    op.execute(f"CREATE ROLE {role} NOLOGIN")
    rls = "BYPASSRLS" if bypass_rls else "NOBYPASSRLS"
    op.execute(
        f"ALTER ROLE {role} WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
        f"NOINHERIT NOREPLICATION {rls}"
    )
    _revoke_role_memberships(role)


def _replace_qualification_role() -> None:
    _revoke_role_memberships(_QUALIFICATION)
    _revoke_direct_acl(_QUALIFICATION)
    op.execute(
        "DO $$ DECLARE granted_column record; BEGIN FOR granted_column IN SELECT "
        "namespace.nspname AS schema_name, relation.relname AS relation_name, "
        "attribute.attname AS column_name FROM pg_attribute attribute JOIN "
        "pg_class relation ON relation.oid = attribute.attrelid JOIN pg_namespace "
        "namespace ON namespace.oid = relation.relnamespace, LATERAL aclexplode("
        "attribute.attacl) entry WHERE NOT attribute.attisdropped AND entry.grantee "
        f"= '{_QUALIFICATION}'::regrole LOOP EXECUTE format('REVOKE ALL PRIVILEGES "
        f"(%I) ON TABLE %I.%I FROM {_QUALIFICATION}', granted_column.column_name, "
        "granted_column.schema_name, granted_column.relation_name); END LOOP; END $$"
    )
    op.execute(f"DROP ROLE {_QUALIFICATION}")
    _create_role(_QUALIFICATION, bypass_rls=False)


def _revoke_role_memberships(role: str) -> None:
    op.execute(
        "DO $$ DECLARE parent_role record; BEGIN FOR parent_role IN SELECT "
        "granted.rolname FROM pg_auth_members membership JOIN pg_roles granted "
        "ON granted.oid = membership.roleid WHERE membership.member = "
        f"'{role}'::regrole LOOP EXECUTE format('REVOKE %I FROM {role}', "
        "parent_role.rolname); END LOOP; END $$"
    )
    op.execute(
        "DO $$ DECLARE member_role record; BEGIN FOR member_role IN SELECT "
        "member.rolname FROM pg_auth_members membership JOIN pg_roles member ON "
        "member.oid = membership.member WHERE membership.roleid = "
        f"'{role}'::regrole LOOP EXECUTE format('REVOKE {role} FROM %I', "
        "member_role.rolname); END LOOP; END $$"
    )


def _revoke_direct_acl(role: str) -> None:
    op.execute(f"REVOKE ALL PRIVILEGES ON SCHEMA public FROM {role}")
    op.execute(f"REVOKE ALL PRIVILEGES ON ALL TABLES IN SCHEMA public FROM {role}")
    op.execute(f"REVOKE ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public FROM {role}")
    op.execute(f"REVOKE ALL PRIVILEGES ON ALL ROUTINES IN SCHEMA public FROM {role}")
