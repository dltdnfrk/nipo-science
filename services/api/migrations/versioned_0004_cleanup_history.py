"""Version-pinned cleanup-history constraint lifecycle for provider revocation."""

from alembic import op


def enable_revoke_cleanup_history() -> None:
    """Allow completed and scheduled revoke reservations with a connection."""
    op.execute(
        "ALTER TABLE public.provider_runtime_home_cleanups DROP CONSTRAINT "
        "provider_cleanup_reason_scope, ADD CONSTRAINT "
        "provider_cleanup_reason_scope CHECK ((reason = 'unbound' AND "
        "connection_id IS NULL) OR (reason IN ('superseded', 'revoke') AND "
        "connection_id IS NOT NULL))"
    )


def restore_pre_0004_cleanup_history() -> None:
    """Refuse destructive downgrade when durable revoke reservations exist."""
    op.execute(
        "DO $$ BEGIN IF EXISTS (SELECT 1 FROM "
        "public.provider_runtime_home_cleanups WHERE reason = 'revoke') THEN "
        "RAISE EXCEPTION 'cannot downgrade provider revoke cleanup history' "
        "USING ERRCODE = '55000'; END IF; END $$"
    )
    op.execute(
        "ALTER TABLE public.provider_runtime_home_cleanups DROP CONSTRAINT "
        "provider_cleanup_reason_scope, ADD CONSTRAINT "
        "provider_cleanup_reason_scope CHECK ((reason = 'unbound' AND "
        "connection_id IS NULL) OR (reason = 'superseded' AND connection_id IS "
        "NOT NULL))"
    )
