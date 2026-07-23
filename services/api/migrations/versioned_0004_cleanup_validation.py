"""Version-pinned provider cleanup validation and destruction reservations."""

from alembic import op

from services.api.migrations.versioned_0004_role_names import (
    APP_ROLE,
    CLEANUP_CAPABILITY_ROLE,
)


def create_cleanup_validation_function() -> None:
    """Lock exact rows before refs and reserve both refs for revoked cleanup."""
    op.execute(
        f"""
        CREATE FUNCTION public.validate_due_provider_cleanup(
            uuid, uuid, uuid, text, text, timestamptz
        ) RETURNS timestamptz
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            stored_connection uuid;
            requested timestamptz;
            deadline timestamptz;
            cutoff timestamptz;
            reference_count bigint;
            cleanup_count bigint;
            exact_cleanup_count bigint;
            exact_connection_count bigint;
            invoker_role text;
            runtime_ref text;
            tombstone_ref text;
        BEGIN
            invoker_role := current_setting('role', true);
            IF invoker_role NOT IN ('{APP_ROLE}', '{CLEANUP_CAPABILITY_ROLE}')
               OR $5 NOT IN ('unbound', 'superseded', 'revoke') THEN
                RETURN NULL;
            END IF;
            IF invoker_role = '{APP_ROLE}' AND (
                current_setting('app.org_id', true) IS DISTINCT FROM $1::text
                OR current_setting('app.user_id', true) IS DISTINCT FROM $2::text
            ) THEN
                RETURN NULL;
            END IF;
            cutoff := CASE WHEN $6 IS NULL THEN NULL
                ELSE LEAST($6, transaction_timestamp()) END;
            IF $5 IN ('unbound', 'superseded') THEN
                SELECT
                    cleanup.connection_id,
                    cleanup.requested_at,
                    cleanup.destroy_by
                INTO stored_connection, requested, deadline
                FROM public.provider_runtime_home_cleanups AS cleanup
                WHERE cleanup.org_id = $1
                  AND cleanup.requester_user_id = $2
                  AND cleanup.encrypted_runtime_home_ref = $4
                  AND cleanup.reason = $5
                  AND cleanup.status = 'scheduled'
                FOR UPDATE;
                IF NOT FOUND
                   OR stored_connection IS DISTINCT FROM $3
                   OR requested IS NULL
                   OR deadline IS NULL
                   OR ($6 IS NOT NULL AND deadline > cutoff)
                   OR deadline <= requested THEN
                    RETURN NULL;
                END IF;
                IF $5 = 'superseded' THEN
                    SELECT count(*) INTO exact_connection_count
                    FROM (
                        SELECT 1
                        FROM public.provider_connections AS connection
                        WHERE connection.org_id = $1
                          AND connection.requester_user_id = $2
                          AND connection.id = stored_connection
                          AND connection.encrypted_runtime_home_ref <> $4
                          AND connection.superseded_runtime_home_ref = $4
                        FOR UPDATE
                    ) AS exact_connection;
                    IF stored_connection IS NULL
                       OR exact_connection_count <> 1 THEN
                        RETURN NULL;
                    END IF;
                END IF;
                PERFORM pg_advisory_xact_lock(hashtextextended($4, 0));
                SELECT count(*) INTO cleanup_count
                FROM public.provider_runtime_home_cleanups AS cleanup
                WHERE cleanup.encrypted_runtime_home_ref = $4;
                SELECT count(*) INTO reference_count
                FROM public.provider_connections AS connection
                WHERE connection.encrypted_runtime_home_ref = $4
                   OR connection.superseded_runtime_home_ref = $4;
                IF cleanup_count <> 1
                   OR ($5 = 'unbound' AND (
                       stored_connection IS NOT NULL OR reference_count <> 0
                   ))
                   OR ($5 = 'superseded' AND reference_count <> 1) THEN
                    RETURN NULL;
                END IF;
                RETURN requested;
            END IF;
            IF $3 IS NULL THEN
                RETURN NULL;
            END IF;
            SELECT
                CASE WHEN pg_input_is_valid(
                    connection.account_metadata ->> 'cleanup_requested_at',
                    'timestamp with time zone'
                ) THEN (
                    connection.account_metadata ->> 'cleanup_requested_at'
                )::timestamptz END,
                CASE WHEN pg_input_is_valid(
                    connection.account_metadata ->> 'destroy_by',
                    'timestamp with time zone'
                ) THEN (
                    connection.account_metadata ->> 'destroy_by'
                )::timestamptz END
            INTO requested, deadline
            FROM public.provider_connections AS connection
            WHERE connection.org_id = $1
              AND connection.requester_user_id = $2
              AND connection.id = $3
              AND connection.encrypted_runtime_home_ref = $4
              AND connection.superseded_runtime_home_ref IS NULL
              AND connection.status = 'revoked'
              AND connection.selected_model IS NULL
              AND connection.account_metadata ->> 'cleanup_status' = 'scheduled'
            FOR UPDATE;
            IF NOT FOUND
               OR requested IS NULL
               OR deadline IS NULL
               OR ($6 IS NOT NULL AND deadline > cutoff)
               OR deadline <= requested THEN
                RETURN NULL;
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
            FROM public.provider_connections AS connection
            WHERE connection.encrypted_runtime_home_ref IN ($4, tombstone_ref)
               OR connection.superseded_runtime_home_ref IN ($4, tombstone_ref);
            SELECT count(*) INTO cleanup_count
            FROM public.provider_runtime_home_cleanups AS cleanup
            WHERE cleanup.encrypted_runtime_home_ref IN ($4, tombstone_ref);
            SELECT count(*) INTO exact_cleanup_count
            FROM public.provider_runtime_home_cleanups AS cleanup
            WHERE cleanup.org_id = $1
              AND cleanup.requester_user_id = $2
              AND cleanup.connection_id = $3
              AND cleanup.encrypted_runtime_home_ref IN ($4, tombstone_ref)
              AND cleanup.reason = 'revoke'
              AND cleanup.status = 'scheduled'
              AND cleanup.requested_at = requested
              AND cleanup.destroy_by = deadline;
            IF reference_count <> 1
               OR cleanup_count NOT IN (0, 2)
               OR (cleanup_count = 2 AND exact_cleanup_count <> 2) THEN
                RETURN NULL;
            END IF;
            IF cleanup_count = 0 THEN
                INSERT INTO public.provider_runtime_home_cleanups (
                    org_id,
                    requester_user_id,
                    encrypted_runtime_home_ref,
                    connection_id,
                    reason,
                    status,
                    requested_at,
                    destroy_by
                )
                SELECT $1, $2, candidate.runtime_ref, $3, 'revoke',
                       'scheduled', requested, deadline
                FROM (VALUES ($4), (tombstone_ref)) AS candidate(runtime_ref)
                ORDER BY candidate.runtime_ref COLLATE "C";
            END IF;
            RETURN requested;
        END
        $$
        """
    )


def revoke_public_cleanup_validation_function() -> None:
    """Keep cleanup validation callable only by the cleanup capability."""
    op.execute(
        "REVOKE ALL ON FUNCTION public.validate_due_provider_cleanup("
        "uuid, uuid, uuid, text, text, timestamptz) FROM PUBLIC"
    )


def drop_cleanup_validation_function() -> None:
    """Drop the cleanup validation function."""
    op.execute(
        "DROP FUNCTION IF EXISTS public.validate_due_provider_cleanup("
        "uuid, uuid, uuid, text, text, timestamptz)"
    )
