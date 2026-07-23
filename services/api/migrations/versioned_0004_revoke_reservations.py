"""Pre-destruction source and tombstone reservations for provider revocation."""

from alembic import op

from services.api.migrations.versioned_0004_role_names import CLEANUP_DEFINER_ROLE


def create_revoke_reservation_guard() -> None:
    """Reserve both revoke refs while the exact provider row is locked."""
    drop_revoke_reservation_guard()
    op.execute(
        """
        CREATE FUNCTION public.reserve_provider_revoke_cleanup_refs()
        RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            cleanup_count bigint;
            reference_count bigint;
            requested timestamptz;
            deadline timestamptz;
            runtime_ref text;
            tombstone_ref text;
        BEGIN
            IF NEW.org_id IS DISTINCT FROM OLD.org_id
               OR NEW.requester_user_id IS DISTINCT FROM OLD.requester_user_id
               OR NEW.id IS DISTINCT FROM OLD.id
               OR NEW.encrypted_runtime_home_ref IS DISTINCT FROM
                   OLD.encrypted_runtime_home_ref
               OR NEW.superseded_runtime_home_ref IS NOT NULL
               OR NEW.status <> 'revoked'
               OR NEW.selected_model IS NOT NULL
               OR OLD.account_metadata ->> 'cleanup_status' IS NOT DISTINCT FROM
                   'scheduled'
               OR NEW.account_metadata ->> 'cleanup_status' <> 'scheduled' THEN
                RETURN NEW;
            END IF;
            IF NOT pg_input_is_valid(
                NEW.account_metadata ->> 'cleanup_requested_at',
                'timestamp with time zone'
            ) OR NOT pg_input_is_valid(
                NEW.account_metadata ->> 'destroy_by',
                'timestamp with time zone'
            ) THEN
                RAISE EXCEPTION 'provider revoke cleanup schedule is invalid'
                    USING ERRCODE = '55000';
            END IF;
            requested := (
                NEW.account_metadata ->> 'cleanup_requested_at'
            )::timestamptz;
            deadline := (NEW.account_metadata ->> 'destroy_by')::timestamptz;
            IF deadline <= requested THEN
                RAISE EXCEPTION 'provider revoke cleanup schedule is invalid'
                    USING ERRCODE = '55000';
            END IF;
            tombstone_ref := 'vault://runtime/destroyed/' || NEW.id::text;
            FOR runtime_ref IN
                SELECT candidate.runtime_ref
                FROM (
                    VALUES (NEW.encrypted_runtime_home_ref), (tombstone_ref)
                ) AS candidate(runtime_ref)
                ORDER BY candidate.runtime_ref COLLATE "C"
            LOOP
                PERFORM pg_advisory_xact_lock(hashtextextended(runtime_ref, 0));
            END LOOP;
            SELECT count(*) INTO reference_count
            FROM public.provider_connections AS connection
            WHERE connection.encrypted_runtime_home_ref IN (
                NEW.encrypted_runtime_home_ref,
                tombstone_ref
            )
               OR connection.superseded_runtime_home_ref IN (
                   NEW.encrypted_runtime_home_ref,
                   tombstone_ref
               );
            SELECT count(*) INTO cleanup_count
            FROM public.provider_runtime_home_cleanups AS cleanup
            WHERE cleanup.encrypted_runtime_home_ref IN (
                NEW.encrypted_runtime_home_ref,
                tombstone_ref
            );
            IF reference_count <> 1 OR cleanup_count <> 0 THEN
                RAISE EXCEPTION 'provider revoke cleanup reservation is unsafe'
                    USING ERRCODE = '55000';
            END IF;
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
            SELECT NEW.org_id, NEW.requester_user_id, candidate.runtime_ref,
                   NEW.id, 'revoke', 'scheduled', requested, deadline
            FROM (
                VALUES (NEW.encrypted_runtime_home_ref), (tombstone_ref)
            ) AS candidate(runtime_ref)
            ORDER BY candidate.runtime_ref COLLATE "C";
            RETURN NEW;
        END
        $$
        """
    )
    op.execute(
        f"ALTER FUNCTION public.reserve_provider_revoke_cleanup_refs() OWNER TO "
        f"{CLEANUP_DEFINER_ROLE}"
    )
    op.execute(
        "CREATE TRIGGER provider_connections_revoke_cleanup_reservation AFTER "
        "UPDATE ON public.provider_connections FOR EACH ROW EXECUTE FUNCTION "
        "public.reserve_provider_revoke_cleanup_refs()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.reserve_provider_revoke_cleanup_refs() "
        "FROM PUBLIC"
    )


def drop_revoke_reservation_guard() -> None:
    """Drop the revoke-reservation trigger through its owning function."""
    op.execute(
        "DROP FUNCTION IF EXISTS public.reserve_provider_revoke_cleanup_refs() CASCADE"
    )
