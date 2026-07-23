"""Version-pinned provider cleanup completion functions."""

from alembic import op

from services.api.migrations.versioned_0004_role_names import (
    APP_ROLE,
    CLEANUP_CAPABILITY_ROLE,
)


def create_cleanup_completion_functions() -> None:
    """Create exact outbox and revoked-provider cleanup completion functions."""
    op.execute(
        f"""
        CREATE FUNCTION public.complete_provider_cleanup_outbox(
            uuid, uuid, uuid, text, text, timestamptz, text
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            affected integer;
            stored_connection uuid;
            requested timestamptz;
            deadline timestamptz;
            completion_time timestamptz;
            reference_count bigint;
            cleanup_count bigint;
            exact_connection_count bigint;
            invoker_role text;
        BEGIN
            invoker_role := current_setting('role', true);
            IF invoker_role NOT IN ('{APP_ROLE}', '{CLEANUP_CAPABILITY_ROLE}')
               OR $5 NOT IN ('unbound', 'superseded')
               OR $6 IS NULL
               OR $7 !~ '^[0-9a-f]{{64}}$' THEN
                RETURN false;
            END IF;
            IF invoker_role = '{APP_ROLE}' AND (
                current_setting('app.org_id', true) IS DISTINCT FROM $1::text
                OR current_setting('app.user_id', true) IS DISTINCT FROM $2::text
            ) THEN
                RETURN false;
            END IF;
            SELECT connection_id, requested_at, destroy_by
            INTO stored_connection, requested, deadline
            FROM public.provider_runtime_home_cleanups
            WHERE org_id = $1
              AND requester_user_id = $2
              AND encrypted_runtime_home_ref = $4
              AND reason = $5
              AND status = 'scheduled'
            FOR UPDATE;
            IF NOT FOUND
               OR stored_connection IS DISTINCT FROM $3
               OR (
                   invoker_role = '{CLEANUP_CAPABILITY_ROLE}'
                   AND deadline > transaction_timestamp()
               )
               OR deadline <= requested
               OR $6 < requested THEN
                RETURN false;
            END IF;
            IF $5 = 'superseded' THEN
                SELECT count(*) INTO exact_connection_count
                FROM (
                    SELECT 1
                    FROM public.provider_connections
                    WHERE org_id = $1
                      AND requester_user_id = $2
                      AND id = stored_connection
                      AND encrypted_runtime_home_ref <> $4
                      AND superseded_runtime_home_ref = $4
                    FOR UPDATE
                ) AS exact_connection;
                IF stored_connection IS NULL OR exact_connection_count <> 1 THEN
                    RETURN false;
                END IF;
            END IF;
            PERFORM pg_advisory_xact_lock(hashtextextended($4, 0));
            SELECT count(*) INTO cleanup_count
            FROM public.provider_runtime_home_cleanups
            WHERE encrypted_runtime_home_ref = $4;
            SELECT count(*) INTO reference_count
            FROM public.provider_connections
            WHERE encrypted_runtime_home_ref = $4
               OR superseded_runtime_home_ref = $4;
            IF cleanup_count <> 1
               OR ($5 = 'unbound' AND (
                   stored_connection IS NOT NULL OR reference_count <> 0
               ))
               OR ($5 = 'superseded' AND reference_count <> 1) THEN
                RETURN false;
            END IF;
            IF $5 = 'superseded' THEN
                UPDATE public.provider_connections
                SET superseded_runtime_home_ref = NULL
                WHERE org_id = $1
                  AND requester_user_id = $2
                  AND id = stored_connection
                  AND superseded_runtime_home_ref = $4;
                GET DIAGNOSTICS affected = ROW_COUNT;
                IF affected <> 1 THEN
                    RETURN false;
                END IF;
            END IF;
            completion_time := GREATEST(clock_timestamp(), requested);
            UPDATE public.provider_runtime_home_cleanups
            SET status = 'completed',
                destroyed_at = completion_time,
                evidence_sha256 = $7
            WHERE org_id = $1
              AND requester_user_id = $2
              AND encrypted_runtime_home_ref = $4
              AND reason = $5
              AND status = 'scheduled';
            GET DIAGNOSTICS affected = ROW_COUNT;
            RETURN affected = 1;
        END
        $$
        """
    )
    op.execute(
        """
        CREATE FUNCTION public.complete_provider_revoked_cleanup(
            uuid, uuid, uuid, text, timestamptz, text
        ) RETURNS boolean
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            affected integer;
            requested timestamptz;
            deadline timestamptz;
            completion_time timestamptz;
            reference_count bigint;
            cleanup_count bigint;
            exact_cleanup_count bigint;
            runtime_ref text;
            tombstone_ref text;
        BEGIN
            IF $5 IS NULL OR $6 !~ '^[0-9a-f]{64}$' THEN
                RETURN false;
            END IF;
            SELECT
                CASE WHEN pg_input_is_valid(
                    account_metadata ->> 'cleanup_requested_at',
                    'timestamp with time zone'
                ) THEN (
                    account_metadata ->> 'cleanup_requested_at'
                )::timestamptz END,
                CASE WHEN pg_input_is_valid(
                    account_metadata ->> 'destroy_by',
                    'timestamp with time zone'
                ) THEN (account_metadata ->> 'destroy_by')::timestamptz END
            INTO requested, deadline
            FROM public.provider_connections
            WHERE org_id = $1
              AND requester_user_id = $2
              AND id = $3
              AND encrypted_runtime_home_ref = $4
              AND superseded_runtime_home_ref IS NULL
              AND status = 'revoked'
              AND selected_model IS NULL
              AND account_metadata ->> 'cleanup_status' = 'scheduled'
            FOR UPDATE;
            IF NOT FOUND
               OR requested IS NULL
               OR deadline IS NULL
               OR deadline > transaction_timestamp()
               OR deadline <= requested
               OR $5 < requested THEN
                RETURN false;
            END IF;
            tombstone_ref := 'vault://runtime/destroyed/' || $3::text;
            FOR runtime_ref IN
                SELECT DISTINCT candidate.runtime_ref COLLATE "C"
                FROM (VALUES ($4), (tombstone_ref)) AS candidate(runtime_ref)
                WHERE candidate.runtime_ref IS NOT NULL
                ORDER BY 1
            LOOP
                PERFORM pg_advisory_xact_lock(hashtextextended(runtime_ref, 0));
            END LOOP;
            SELECT count(*) INTO reference_count
            FROM public.provider_connections
            WHERE encrypted_runtime_home_ref IN ($4, tombstone_ref)
               OR superseded_runtime_home_ref IN ($4, tombstone_ref);
            SELECT count(*) INTO cleanup_count
            FROM public.provider_runtime_home_cleanups
            WHERE encrypted_runtime_home_ref IN ($4, tombstone_ref);
            SELECT count(*) INTO exact_cleanup_count
            FROM public.provider_runtime_home_cleanups
            WHERE org_id = $1
              AND requester_user_id = $2
              AND connection_id = $3
              AND encrypted_runtime_home_ref IN ($4, tombstone_ref)
              AND reason = 'revoke'
              AND status = 'scheduled'
              AND requested_at = requested
              AND destroy_by = deadline;
            IF reference_count <> 1
               OR cleanup_count <> 2
               OR exact_cleanup_count <> 2 THEN
                RETURN false;
            END IF;
            completion_time := GREATEST(clock_timestamp(), requested);
            UPDATE public.provider_connections
            SET encrypted_runtime_home_ref = tombstone_ref,
                account_metadata = account_metadata || jsonb_build_object(
                    'cleanup_status', 'completed',
                    'destroyed_at', completion_time::text,
                    'evidence_sha256', $6
                )
            WHERE org_id = $1
              AND requester_user_id = $2
              AND id = $3
              AND encrypted_runtime_home_ref = $4
              AND superseded_runtime_home_ref IS NULL
              AND status = 'revoked'
              AND selected_model IS NULL
              AND account_metadata ->> 'cleanup_status' = 'scheduled';
            GET DIAGNOSTICS affected = ROW_COUNT;
            RETURN affected = 1;
        END
        $$
        """
    )


def revoke_public_cleanup_completion_functions() -> None:
    """Keep completion functions callable only by the cleanup capability."""
    op.execute(
        "REVOKE ALL ON FUNCTION public.complete_provider_cleanup_outbox("
        "uuid, uuid, uuid, text, text, timestamptz, text) FROM PUBLIC"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.complete_provider_revoked_cleanup("
        "uuid, uuid, uuid, text, timestamptz, text) FROM PUBLIC"
    )


def drop_cleanup_completion_functions() -> None:
    """Drop completion functions in their original migration order."""
    op.execute(
        "DROP FUNCTION IF EXISTS public.complete_provider_cleanup_outbox("
        "uuid, uuid, uuid, text, text, timestamptz, text)"
    )
    op.execute(
        "DROP FUNCTION IF EXISTS public.complete_provider_revoked_cleanup("
        "uuid, uuid, uuid, text, timestamptz, text)"
    )
