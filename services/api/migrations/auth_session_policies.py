from __future__ import annotations

from alembic import op

AUTHENTICATOR_ROLE = "science_workbench_session_authenticator"


def create_session_authentication_boundary() -> None:
    op.execute(
        f"DO $$ BEGIN CREATE ROLE {AUTHENTICATOR_ROLE} NOLOGIN BYPASSRLS; "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    op.execute(
        f"ALTER ROLE {AUTHENTICATOR_ROLE} WITH NOLOGIN NOSUPERUSER NOCREATEDB "
        "NOCREATEROLE NOINHERIT NOREPLICATION BYPASSRLS"
    )
    op.execute(f"GRANT USAGE ON SCHEMA public TO {AUTHENTICATOR_ROLE}")
    op.execute(
        "GRANT SELECT ON auth_sessions, memberships, users, organizations TO "
        f"{AUTHENTICATOR_ROLE}"
    )
    op.execute(f"GRANT UPDATE (revoked_at) ON auth_sessions TO {AUTHENTICATOR_ROLE}")
    op.execute(
        "CREATE OR REPLACE FUNCTION resolve_auth_session(candidate_hash bytea) "
        "RETURNS TABLE (session_id uuid, organization_id uuid, user_id uuid, "
        "email text, organization_name text, csrf_hash bytea) LANGUAGE sql "
        "STABLE SECURITY DEFINER SET search_path = public, pg_temp AS $$ "
        "SELECT session.id, session.org_id, session.user_id, identity.email, "
        "organization.name, session.csrf_hash FROM auth_sessions session "
        "JOIN memberships membership ON membership.org_id = session.org_id "
        "AND membership.user_id = session.user_id "
        "JOIN users identity ON identity.id = session.user_id "
        "JOIN organizations organization ON organization.id = session.org_id "
        "WHERE octet_length(candidate_hash) = 32 "
        "AND session.token_hash = candidate_hash "
        "AND session.revoked_at IS NULL AND membership.revoked_at IS NULL "
        "AND session.idle_expires_at > CURRENT_TIMESTAMP "
        "AND session.absolute_expires_at > CURRENT_TIMESTAMP $$"
    )
    op.execute(
        "CREATE OR REPLACE FUNCTION revoke_auth_session(candidate_hash bytea) "
        "RETURNS boolean LANGUAGE sql VOLATILE SECURITY DEFINER "
        "SET search_path = public, pg_temp AS $$ WITH revoked AS ("
        "UPDATE auth_sessions SET revoked_at = CURRENT_TIMESTAMP "
        "WHERE octet_length(candidate_hash) = 32 "
        "AND token_hash = candidate_hash AND revoked_at IS NULL RETURNING 1) "
        "SELECT EXISTS (SELECT 1 FROM revoked) $$"
    )
    for function in (
        "resolve_auth_session(bytea)",
        "revoke_auth_session(bytea)",
    ):
        op.execute(f"ALTER FUNCTION {function} OWNER TO {AUTHENTICATOR_ROLE}")
        op.execute(f"REVOKE ALL ON FUNCTION {function} FROM PUBLIC")
        op.execute(f"GRANT EXECUTE ON FUNCTION {function} TO science_workbench_app")
    op.execute("REVOKE ALL ON auth_sessions FROM science_workbench_app")


def drop_session_authentication_boundary() -> None:
    for function in (
        "revoke_auth_session(bytea)",
        "resolve_auth_session(bytea)",
    ):
        op.execute(f"REVOKE EXECUTE ON FUNCTION {function} FROM science_workbench_app")
        op.execute(f"DROP FUNCTION {function}")
    op.execute(
        f"REVOKE ALL ON auth_sessions, memberships, users, organizations "
        f"FROM {AUTHENTICATOR_ROLE}"
    )
    op.execute(f"REVOKE USAGE ON SCHEMA public FROM {AUTHENTICATOR_ROLE}")
    op.execute(f"DROP ROLE IF EXISTS {AUTHENTICATOR_ROLE}")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON auth_sessions "
        "TO science_workbench_app"
    )
