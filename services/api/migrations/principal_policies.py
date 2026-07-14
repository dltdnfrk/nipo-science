from __future__ import annotations

from alembic import op


def create_principal_guard() -> None:
    """Bind tenant RLS to an active user and organization membership."""
    op.execute(
        "CREATE FUNCTION current_principal_org() RETURNS uuid LANGUAGE sql STABLE "
        "SECURITY DEFINER SET search_path = public, pg_temp AS $$ "
        "SELECT requested.org_id "
        "FROM (SELECT NULLIF(current_setting('app.org_id', true), '')::uuid AS org_id, "
        "NULLIF(current_setting('app.user_id', true), '')::uuid AS user_id) requested "
        "WHERE requested.org_id IS NOT NULL AND requested.user_id IS NOT NULL "
        "AND EXISTS "
        "(SELECT 1 FROM memberships m WHERE m.org_id = requested.org_id "
        "AND m.user_id = requested.user_id AND m.revoked_at IS NULL) $$"
    )


def create_compliance_policy() -> None:
    """Permit only explicitly scoped compliance access to legal holds."""
    principal = "org_id = NULLIF(current_setting('app.org_id', true), '')::uuid"
    op.execute(
        "CREATE POLICY compliance_tenant ON legal_holds TO "
        f"science_workbench_compliance USING ({principal}) WITH CHECK ({principal})"
    )


def drop_principal_guard() -> None:
    """Remove principal-specific policies and helper functions."""
    op.execute("DROP POLICY compliance_tenant ON legal_holds")
    op.execute("DROP FUNCTION current_principal_org() CASCADE")
