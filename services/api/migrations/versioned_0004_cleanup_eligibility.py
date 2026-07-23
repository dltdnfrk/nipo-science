"""Version-pinned provider cleanup candidate and eligibility functions."""

from alembic import op


def create_cleanup_eligibility_functions() -> None:
    """Create the bounded cleanup candidate query."""
    op.execute(
        """
        CREATE FUNCTION public.provider_due_cleanup_candidates(timestamptz)
        RETURNS TABLE (
            org_id uuid,
            requester_user_id uuid,
            runtime_home_ref text,
            connection_id uuid,
            reason text,
            destroy_by timestamptz,
            created_at timestamptz
        )
        LANGUAGE sql STABLE SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        WITH horizon AS (
            SELECT CASE
                WHEN $1 IS NULL THEN '-infinity'::timestamptz
                ELSE LEAST($1, transaction_timestamp())
            END AS cutoff
        ), revoked AS (
            SELECT
                connection.org_id,
                connection.requester_user_id,
                connection.encrypted_runtime_home_ref AS runtime_home_ref,
                connection.id AS connection_id,
                'revoke'::text AS reason,
                CASE WHEN pg_input_is_valid(
                    connection.account_metadata ->> 'destroy_by',
                    'timestamp with time zone'
                ) THEN (
                    connection.account_metadata ->> 'destroy_by'
                )::timestamptz END AS destroy_by,
                connection.created_at
            FROM public.provider_connections AS connection
            WHERE connection.status = 'revoked'
              AND connection.selected_model IS NULL
              AND connection.account_metadata ->> 'cleanup_status' = 'scheduled'
        )
        SELECT candidate.*
        FROM (
            SELECT
                cleanup.org_id,
                cleanup.requester_user_id,
                cleanup.encrypted_runtime_home_ref AS runtime_home_ref,
                cleanup.connection_id,
                cleanup.reason,
                cleanup.destroy_by,
                cleanup.created_at
            FROM public.provider_runtime_home_cleanups AS cleanup, horizon
            WHERE cleanup.status = 'scheduled'
              AND cleanup.reason IN ('unbound', 'superseded')
              AND cleanup.destroy_by <= horizon.cutoff
            UNION ALL
            SELECT revoked.*
            FROM revoked, horizon
            WHERE revoked.destroy_by IS NOT NULL
              AND revoked.destroy_by <= horizon.cutoff
        ) AS candidate
        ORDER BY candidate.destroy_by, candidate.created_at,
                 candidate.runtime_home_ref
        LIMIT 100
        $$
        """
    )


def revoke_public_cleanup_eligibility_functions() -> None:
    """Keep eligibility functions callable only by the cleanup capability."""
    op.execute(
        "REVOKE ALL ON FUNCTION public.provider_due_cleanup_candidates("
        "timestamptz) FROM PUBLIC"
    )


def drop_cleanup_eligibility_functions() -> None:
    """Drop eligibility functions in their original migration order."""
    op.execute(
        "DROP FUNCTION IF EXISTS public.provider_due_cleanup_candidates(timestamptz)"
    )
