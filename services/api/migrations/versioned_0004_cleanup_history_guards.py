"""Mutation guards for immutable provider cleanup history."""

from alembic import op

from services.api.migrations.versioned_0004_role_names import CLEANUP_DEFINER_ROLE


def create_cleanup_history_guards() -> None:
    """Validate global reservations and freeze completed cleanup history."""
    drop_cleanup_history_guards()
    op.execute(
        """
        CREATE FUNCTION public.lock_provider_cleanup_runtime_ref()
        RETURNS trigger
        LANGUAGE plpgsql SECURITY DEFINER
        SET search_path = pg_catalog, pg_temp
        AS $$
        DECLARE
            cleanup_count bigint;
            conflicting_cleanup_count bigint;
            exact_cleanup_count bigint;
            reference_count bigint;
            locked_refs text[];
            runtime_ref text;
            source_ref text;
            tombstone_ref text;
            table_owner name;
        BEGIN
            CASE TG_OP
                WHEN 'INSERT' THEN
                    locked_refs := ARRAY[NEW.encrypted_runtime_home_ref];
                    IF NEW.status <> 'scheduled'
                        OR NEW.destroyed_at IS NOT NULL
                        OR NEW.evidence_sha256 IS NOT NULL
                        OR NEW.requested_at IS NULL
                        OR NEW.destroy_by IS NULL
                        OR NEW.destroy_by <= NEW.requested_at THEN
                        RAISE EXCEPTION 'provider cleanup insertion is invalid'
                            USING ERRCODE = '55000';
                    END IF;
                    CASE NEW.reason
                        WHEN 'unbound' THEN
                            IF NEW.connection_id IS NOT NULL THEN
                                RAISE EXCEPTION 'provider cleanup reservation is unsafe'
                                    USING ERRCODE = '55000';
                            END IF;
                        WHEN 'superseded' THEN
                            IF NEW.connection_id IS NULL THEN
                                RAISE EXCEPTION 'provider cleanup reservation is unsafe'
                                    USING ERRCODE = '55000';
                            END IF;
                            PERFORM 1
                            FROM public.provider_connections AS connection
                            WHERE connection.org_id = NEW.org_id
                              AND connection.requester_user_id =
                                  NEW.requester_user_id
                              AND connection.id = NEW.connection_id
                              AND connection.encrypted_runtime_home_ref <>
                                  NEW.encrypted_runtime_home_ref
                              AND connection.superseded_runtime_home_ref =
                                  NEW.encrypted_runtime_home_ref
                            FOR UPDATE;
                            IF NOT FOUND THEN
                                RAISE EXCEPTION 'provider cleanup reservation is unsafe'
                                    USING ERRCODE = '55000';
                            END IF;
                        WHEN 'revoke' THEN
                            IF NEW.connection_id IS NULL THEN
                                RAISE EXCEPTION 'provider cleanup reservation is unsafe'
                                    USING ERRCODE = '55000';
                            END IF;
                            SELECT connection.encrypted_runtime_home_ref
                            INTO source_ref
                            FROM public.provider_connections AS connection
                            WHERE connection.org_id = NEW.org_id
                              AND connection.requester_user_id =
                                  NEW.requester_user_id
                              AND connection.id = NEW.connection_id
                              AND connection.superseded_runtime_home_ref IS NULL
                              AND connection.status = 'revoked'
                              AND connection.selected_model IS NULL
                              AND connection.account_metadata ->>
                                  'cleanup_status' = 'scheduled'
                              AND pg_input_is_valid(
                                  connection.account_metadata ->>
                                      'cleanup_requested_at',
                                  'timestamp with time zone'
                              )
                              AND pg_input_is_valid(
                                  connection.account_metadata ->> 'destroy_by',
                                  'timestamp with time zone'
                              )
                              AND (
                                  connection.account_metadata ->>
                                      'cleanup_requested_at'
                              )::timestamptz = NEW.requested_at
                              AND (
                                  connection.account_metadata ->> 'destroy_by'
                              )::timestamptz = NEW.destroy_by
                            FOR UPDATE;
                            tombstone_ref := 'vault://runtime/destroyed/' ||
                                NEW.connection_id::text;
                            IF NOT FOUND
                               OR NEW.encrypted_runtime_home_ref NOT IN (
                                   source_ref,
                                   tombstone_ref
                               ) THEN
                                RAISE EXCEPTION 'provider cleanup reservation is unsafe'
                                    USING ERRCODE = '55000';
                            END IF;
                            locked_refs := ARRAY[source_ref, tombstone_ref];
                        ELSE
                            RAISE EXCEPTION 'provider cleanup insertion is invalid'
                                USING ERRCODE = '55000';
                    END CASE;
                WHEN 'UPDATE' THEN
                    locked_refs := ARRAY[
                        CASE WHEN NEW.encrypted_runtime_home_ref IS DISTINCT FROM
                            OLD.encrypted_runtime_home_ref
                            THEN OLD.encrypted_runtime_home_ref END,
                        CASE WHEN NEW.encrypted_runtime_home_ref IS DISTINCT FROM
                            OLD.encrypted_runtime_home_ref
                            THEN NEW.encrypted_runtime_home_ref END
                    ];
                    IF ROW(
                        NEW.org_id,
                        NEW.requester_user_id,
                        NEW.encrypted_runtime_home_ref,
                        NEW.connection_id,
                        NEW.reason,
                        NEW.requested_at,
                        NEW.destroy_by,
                        NEW.created_at
                    ) IS DISTINCT FROM ROW(
                        OLD.org_id,
                        OLD.requester_user_id,
                        OLD.encrypted_runtime_home_ref,
                        OLD.connection_id,
                        OLD.reason,
                        OLD.requested_at,
                        OLD.destroy_by,
                        OLD.created_at
                    )
                    OR OLD.status <> 'scheduled'
                    OR OLD.destroyed_at IS NOT NULL
                    OR OLD.evidence_sha256 IS NOT NULL
                    OR NEW.status <> 'completed'
                    OR NEW.destroyed_at IS NULL
                    OR NEW.destroyed_at < OLD.requested_at
                    OR NEW.evidence_sha256 !~ '^[0-9a-f]{64}$' THEN
                        RAISE EXCEPTION 'provider cleanup history is immutable'
                            USING ERRCODE = '55000';
                    END IF;
                WHEN 'DELETE' THEN
                    locked_refs := ARRAY[OLD.encrypted_runtime_home_ref];
                    SELECT pg_get_userbyid(relation.relowner) INTO table_owner
                    FROM pg_class AS relation
                    WHERE relation.oid = TG_RELID;
                    IF current_setting('role', true) <> 'none'
                       OR session_user <> table_owner THEN
                        RAISE EXCEPTION 'provider cleanup history is immutable'
                            USING ERRCODE = '55000';
                    END IF;
                ELSE
                    RAISE EXCEPTION 'unsupported provider cleanup ref operation'
                        USING ERRCODE = '55000';
            END CASE;
            FOR runtime_ref IN
                SELECT DISTINCT candidate.runtime_ref COLLATE "C"
                FROM unnest(locked_refs) AS candidate(runtime_ref)
                WHERE candidate.runtime_ref IS NOT NULL
                ORDER BY 1
            LOOP
                PERFORM pg_advisory_xact_lock(hashtextextended(runtime_ref, 0));
            END LOOP;
            IF TG_OP = 'INSERT' THEN
                SELECT count(*) INTO reference_count
                FROM public.provider_connections AS connection
                WHERE connection.encrypted_runtime_home_ref = ANY(locked_refs)
                   OR connection.superseded_runtime_home_ref = ANY(locked_refs);
                SELECT count(*) INTO cleanup_count
                FROM public.provider_runtime_home_cleanups AS cleanup
                WHERE cleanup.encrypted_runtime_home_ref = ANY(locked_refs);
                SELECT count(*) INTO conflicting_cleanup_count
                FROM public.provider_runtime_home_cleanups AS cleanup
                WHERE cleanup.encrypted_runtime_home_ref = ANY(locked_refs)
                  AND (cleanup.reason <> 'unbound'
                       OR cleanup.status <> 'scheduled');
                IF NEW.reason = 'revoke' THEN
                    SELECT count(*) INTO exact_cleanup_count
                    FROM public.provider_runtime_home_cleanups AS cleanup
                    WHERE cleanup.org_id = NEW.org_id
                      AND cleanup.requester_user_id = NEW.requester_user_id
                      AND cleanup.connection_id = NEW.connection_id
                      AND cleanup.encrypted_runtime_home_ref = ANY(locked_refs)
                      AND cleanup.reason = 'revoke'
                      AND cleanup.status = 'scheduled'
                      AND cleanup.requested_at = NEW.requested_at
                      AND cleanup.destroy_by = NEW.destroy_by;
                ELSE
                    exact_cleanup_count := 0;
                END IF;
                IF (NEW.reason = 'unbound' AND (
                        reference_count <> 0 OR conflicting_cleanup_count <> 0
                    ))
                   OR (NEW.reason = 'superseded' AND (
                       reference_count <> 1 OR cleanup_count <> 0
                   ))
                   OR (NEW.reason = 'revoke' AND (
                       reference_count <> 1
                       OR cleanup_count NOT IN (0, 1)
                       OR exact_cleanup_count <> cleanup_count
                   )) THEN
                    RAISE EXCEPTION 'provider cleanup reservation is unsafe'
                        USING ERRCODE = '55000';
                END IF;
            END IF;
            CASE TG_OP
                WHEN 'DELETE' THEN RETURN OLD;
                WHEN 'INSERT', 'UPDATE' THEN RETURN NEW;
                ELSE
                    RAISE EXCEPTION 'unsupported provider cleanup ref operation'
                        USING ERRCODE = '55000';
            END CASE;
        END
        $$
        """
    )
    op.execute(
        f"ALTER FUNCTION public.lock_provider_cleanup_runtime_ref() OWNER TO "
        f"{CLEANUP_DEFINER_ROLE}"
    )
    op.execute(
        "CREATE TRIGGER provider_cleanup_runtime_ref_lock BEFORE INSERT OR UPDATE "
        "OR DELETE ON public.provider_runtime_home_cleanups FOR EACH ROW EXECUTE "
        "FUNCTION public.lock_provider_cleanup_runtime_ref()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.lock_provider_cleanup_runtime_ref() FROM PUBLIC"
    )


def drop_cleanup_history_guards() -> None:
    """Drop the cleanup-history trigger through its owning function."""
    op.execute(
        "DROP FUNCTION IF EXISTS public.lock_provider_cleanup_runtime_ref() CASCADE"
    )
