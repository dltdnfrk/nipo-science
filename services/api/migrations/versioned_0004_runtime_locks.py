"""Version-pinned advisory-lock and history guards for provider runtime refs."""

from alembic import op

from services.api.migrations.versioned_0004_cleanup_history import (
    enable_revoke_cleanup_history,
    restore_pre_0004_cleanup_history,
)
from services.api.migrations.versioned_0004_cleanup_history_guards import (
    create_cleanup_history_guards,
    drop_cleanup_history_guards,
)
from services.api.migrations.versioned_0004_revoke_reservations import (
    create_revoke_reservation_guard,
    drop_revoke_reservation_guard,
)
from services.api.migrations.versioned_0004_role_names import CLEANUP_DEFINER_ROLE


def create_provider_runtime_lock_guards() -> None:
    """Serialize ref binding and make completed destruction history immutable."""
    drop_provider_runtime_lock_guards()
    enable_revoke_cleanup_history()
    create_revoke_reservation_guard()
    op.execute(
        """
        CREATE FUNCTION public.lock_provider_connection_runtime_refs()
        RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            affected integer;
            locked_refs text[];
            new_refs text[];
            runtime_ref text;
            requested timestamptz;
            deadline timestamptz;
            destroyed timestamptz;
            tombstone_ref text;
            terminal_transition boolean;
        BEGIN
            CASE TG_OP
                WHEN 'INSERT' THEN
                    locked_refs := ARRAY[
                        NEW.encrypted_runtime_home_ref,
                        NEW.superseded_runtime_home_ref
                    ];
                    new_refs := locked_refs;
                WHEN 'UPDATE' THEN
                    locked_refs := ARRAY[
                        CASE WHEN NEW.encrypted_runtime_home_ref IS DISTINCT FROM
                            OLD.encrypted_runtime_home_ref
                            THEN OLD.encrypted_runtime_home_ref END,
                        CASE WHEN NEW.encrypted_runtime_home_ref IS DISTINCT FROM
                            OLD.encrypted_runtime_home_ref
                            THEN NEW.encrypted_runtime_home_ref END,
                        CASE WHEN NEW.superseded_runtime_home_ref IS DISTINCT FROM
                            OLD.superseded_runtime_home_ref
                            THEN OLD.superseded_runtime_home_ref END,
                        CASE WHEN NEW.superseded_runtime_home_ref IS DISTINCT FROM
                            OLD.superseded_runtime_home_ref
                            THEN NEW.superseded_runtime_home_ref END
                    ];
                    new_refs := ARRAY[
                        CASE WHEN NEW.encrypted_runtime_home_ref IS DISTINCT FROM
                            OLD.encrypted_runtime_home_ref
                            THEN NEW.encrypted_runtime_home_ref END,
                        CASE WHEN NEW.superseded_runtime_home_ref IS DISTINCT FROM
                            OLD.superseded_runtime_home_ref
                            THEN NEW.superseded_runtime_home_ref END
                    ];
                WHEN 'DELETE' THEN
                    locked_refs := ARRAY[
                        OLD.encrypted_runtime_home_ref,
                        OLD.superseded_runtime_home_ref
                    ];
                    new_refs := ARRAY[]::text[];
                ELSE
                    RAISE EXCEPTION 'unsupported provider runtime ref operation'
                        USING ERRCODE = '55000';
            END CASE;
            tombstone_ref := CASE WHEN TG_OP <> 'DELETE' THEN
                'vault://runtime/destroyed/' || NEW.id::text END;
            terminal_transition := TG_OP = 'UPDATE'
                AND NEW.org_id IS NOT DISTINCT FROM OLD.org_id
                AND NEW.requester_user_id IS NOT DISTINCT FROM OLD.requester_user_id
                AND NEW.id IS NOT DISTINCT FROM OLD.id
                AND NEW.encrypted_runtime_home_ref = tombstone_ref
                AND NEW.encrypted_runtime_home_ref IS DISTINCT FROM
                    OLD.encrypted_runtime_home_ref
                AND NEW.superseded_runtime_home_ref IS NULL
                AND OLD.superseded_runtime_home_ref IS NULL
                AND NEW.status = 'revoked'
                AND OLD.status = 'revoked'
                AND NEW.selected_model IS NULL
                AND OLD.selected_model IS NULL
                AND OLD.account_metadata ->> 'cleanup_status' = 'scheduled'
                AND NEW.account_metadata ->> 'cleanup_status' = 'completed'
                AND NEW.account_metadata ->> 'cleanup_requested_at'
                    = OLD.account_metadata ->> 'cleanup_requested_at'
                AND NEW.account_metadata ->> 'destroy_by'
                    = OLD.account_metadata ->> 'destroy_by'
                AND pg_input_is_valid(
                    NEW.account_metadata ->> 'cleanup_requested_at',
                    'timestamp with time zone'
                )
                AND pg_input_is_valid(
                    NEW.account_metadata ->> 'destroy_by',
                    'timestamp with time zone'
                )
                AND pg_input_is_valid(
                    NEW.account_metadata ->> 'destroyed_at',
                    'timestamp with time zone'
                )
                AND NEW.account_metadata ->> 'evidence_sha256' ~ '^[0-9a-f]{64}$';
            IF terminal_transition THEN
                requested := (
                    NEW.account_metadata ->> 'cleanup_requested_at'
                )::timestamptz;
                deadline := (
                    NEW.account_metadata ->> 'destroy_by'
                )::timestamptz;
                destroyed := (
                    NEW.account_metadata ->> 'destroyed_at'
                )::timestamptz;
                terminal_transition := deadline > requested
                    AND destroyed >= requested;
            END IF;
            IF EXISTS (
                SELECT 1
                FROM unnest(new_refs) AS candidate(runtime_ref)
                WHERE candidate.runtime_ref LIKE 'vault://runtime/destroyed/%'
            ) AND NOT terminal_transition THEN
                RAISE EXCEPTION 'provider runtime tombstone transition is invalid'
                    USING ERRCODE = '55000';
            END IF;
            FOR runtime_ref IN
                SELECT DISTINCT candidate.runtime_ref COLLATE "C"
                FROM unnest(locked_refs) AS candidate(runtime_ref)
                WHERE candidate.runtime_ref IS NOT NULL
                ORDER BY 1
            LOOP
                PERFORM pg_advisory_xact_lock(hashtextextended(runtime_ref, 0));
            END LOOP;
            IF EXISTS (
                SELECT 1
                FROM unnest(new_refs) AS candidate(runtime_ref)
                JOIN public.provider_runtime_home_cleanups AS cleanup
                  ON cleanup.encrypted_runtime_home_ref = candidate.runtime_ref
                WHERE candidate.runtime_ref IS NOT NULL
                  AND NOT (
                      terminal_transition
                      AND cleanup.org_id = NEW.org_id
                      AND cleanup.requester_user_id = NEW.requester_user_id
                      AND cleanup.connection_id = NEW.id
                      AND cleanup.reason = 'revoke'
                      AND cleanup.status = 'scheduled'
                      AND cleanup.encrypted_runtime_home_ref IN (
                          OLD.encrypted_runtime_home_ref,
                          NEW.encrypted_runtime_home_ref
                      )
                  )
            ) THEN
                RAISE EXCEPTION 'provider runtime home ref has cleanup history'
                    USING ERRCODE = '55000';
            END IF;
            IF terminal_transition THEN
                UPDATE public.provider_runtime_home_cleanups
                SET status = 'completed',
                    destroyed_at = destroyed,
                    evidence_sha256 = NEW.account_metadata ->> 'evidence_sha256'
                WHERE org_id = NEW.org_id
                  AND requester_user_id = NEW.requester_user_id
                  AND connection_id = NEW.id
                  AND encrypted_runtime_home_ref IN (
                      OLD.encrypted_runtime_home_ref,
                      NEW.encrypted_runtime_home_ref
                  )
                  AND reason = 'revoke'
                  AND status = 'scheduled'
                  AND requested_at = requested
                  AND destroy_by = deadline;
                GET DIAGNOSTICS affected = ROW_COUNT;
                IF affected <> 2 THEN
                    RAISE EXCEPTION 'provider revoke cleanup reservations are invalid'
                        USING ERRCODE = '55000';
                END IF;
            END IF;
            CASE TG_OP
                WHEN 'DELETE' THEN RETURN OLD;
                WHEN 'INSERT', 'UPDATE' THEN RETURN NEW;
                ELSE
                    RAISE EXCEPTION 'unsupported provider runtime ref operation'
                        USING ERRCODE = '55000';
            END CASE;
        END
        $$
        """
    )
    op.execute(
        f"ALTER FUNCTION public.lock_provider_connection_runtime_refs() OWNER TO "
        f"{CLEANUP_DEFINER_ROLE}"
    )
    op.execute(
        "CREATE TRIGGER provider_connections_runtime_ref_lock BEFORE INSERT OR "
        "UPDATE OF encrypted_runtime_home_ref, superseded_runtime_home_ref OR "
        "DELETE ON public.provider_connections FOR EACH ROW EXECUTE FUNCTION "
        "public.lock_provider_connection_runtime_refs()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.lock_provider_connection_runtime_refs() "
        "FROM PUBLIC"
    )
    create_cleanup_history_guards()


def drop_provider_runtime_lock_guards() -> None:
    """Restore the old reason constraint and remove runtime-ref guards."""
    restore_pre_0004_cleanup_history()
    op.execute(
        "DROP FUNCTION IF EXISTS public.lock_provider_connection_runtime_refs() CASCADE"
    )
    drop_revoke_reservation_guard()
    drop_cleanup_history_guards()
