"""Version-pinned database guards for provider authority migration 0004."""

from alembic import op

from services.api.migrations.versioned_0004_runtime_locks import (
    create_provider_runtime_lock_guards,
    drop_provider_runtime_lock_guards,
)


def create_hardened_provider_guards() -> None:
    """Bind receipt adoption and Run insertion to locked current state."""
    drop_provider_guards()
    create_provider_runtime_lock_guards()
    op.execute(
        "CREATE OR REPLACE FUNCTION public.reject_provider_metadata_secret() "
        "RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path = "
        "pg_catalog, pg_temp AS $$ BEGIN IF "
        "public.jsonb_contains_secret(NEW.account_metadata) THEN "
        "RAISE EXCEPTION 'provider account metadata contains secret' USING "
        "ERRCODE = '23514'; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION public.reject_provider_metadata_secret() FROM PUBLIC"
    )
    op.execute(
        "CREATE FUNCTION validate_qualification_receipt_revision() RETURNS "
        "trigger LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ "
        "DECLARE current_revision text; "
        "current_adapter text; BEGIN IF current_user = "
        "'science_workbench_qualification' THEN SELECT "
        "account_metadata ->> 'revision', adapter_id INTO current_revision, "
        "current_adapter FROM public.provider_connections WHERE org_id = "
        "NEW.org_id AND "
        "requester_user_id = NEW.requester_user_id AND id = "
        "NEW.provider_connection_id FOR UPDATE; IF NOT FOUND OR current_revision "
        "!~ '^[0-9]+$' OR NEW.connection_revision <> "
        "current_revision::bigint + 1 OR NEW.adapter_id <> current_adapter THEN "
        "RAISE EXCEPTION 'provider qualification must advance exactly one "
        "revision' USING ERRCODE = '23514'; END IF; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER provider_qualification_receipt_revision BEFORE INSERT ON "
        "provider_qualification_receipts FOR EACH ROW EXECUTE FUNCTION "
        "validate_qualification_receipt_revision()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION validate_qualification_receipt_revision() FROM PUBLIC"
    )
    op.execute(
        "CREATE FUNCTION validate_provider_qualification_pointer() RETURNS trigger "
        "LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ DECLARE "
        "qualification record; expected_metadata jsonb; old_revision text; "
        "BEGIN IF current_user = "
        "'science_workbench_app' AND NEW.qualification_receipt_id IS NOT NULL AND "
        "NEW.qualification_receipt_id IS DISTINCT FROM "
        "OLD.qualification_receipt_id THEN RAISE EXCEPTION 'provider "
        "qualification requires adopter authority' USING ERRCODE = '42501'; END "
        "IF; IF (NEW.qualified_at IS NULL) <> (NEW.qualification_receipt_id IS "
        "NULL) THEN RAISE EXCEPTION 'provider qualification pointer mismatch' "
        "USING ERRCODE = '23514'; END IF; IF NEW.qualification_receipt_id IS NOT "
        "NULL AND NEW.qualification_receipt_id IS DISTINCT FROM "
        "OLD.qualification_receipt_id THEN SELECT q.connection_revision, "
        "q.adapter_id, q.profile_sha256, q.runtime_version, q.executable_sha256, "
        "q.authority_issued_at INTO qualification FROM "
        "public.provider_qualification_receipts q WHERE q.org_id = NEW.org_id AND "
        "q.requester_user_id = NEW.requester_user_id AND "
        "q.provider_connection_id = NEW.id AND q.id = "
        "NEW.qualification_receipt_id; IF NOT FOUND OR qualification.adapter_id <> "
        "NEW.adapter_id OR NEW.account_metadata ->> 'revision' !~ '^[0-9]+$' OR "
        "qualification.connection_revision <> (NEW.account_metadata ->> "
        "'revision')::bigint THEN RAISE EXCEPTION 'provider qualification pointer "
        "is stale' USING ERRCODE = '23514'; END IF; END IF; IF current_user = "
        "'science_workbench_qualification' THEN IF "
        "NEW.qualification_receipt_id IS NULL OR "
        "NEW.qualification_receipt_id IS NOT DISTINCT FROM "
        "OLD.qualification_receipt_id THEN RAISE EXCEPTION 'qualification adopter "
        "requires an exact qualification projection' USING ERRCODE = '23514'; END "
        "IF; old_revision := OLD.account_metadata ->> 'revision'; IF old_revision "
        "!~ '^[0-9]+$' OR qualification.connection_revision <> "
        "old_revision::bigint + 1 THEN RAISE EXCEPTION 'provider qualification "
        "must advance exactly one revision' USING ERRCODE = '23514'; END IF; "
        "expected_metadata := (OLD.account_metadata - ARRAY['revision', "
        "'qualification_receipt_id', 'qualification_runtime_version', "
        "'qualification_executable_sha256', 'qualification_profile_sha256']::text[]) "
        "|| jsonb_build_object('revision', "
        "qualification.connection_revision::text, 'qualification_receipt_id', "
        "NEW.qualification_receipt_id::text, 'qualification_runtime_version', "
        "qualification.runtime_version, 'qualification_executable_sha256', "
        "qualification.executable_sha256, 'qualification_profile_sha256', "
        "qualification.profile_sha256); IF NEW.account_metadata IS DISTINCT FROM "
        "expected_metadata OR (OLD.qualified_at IS NULL AND (NEW.qualified_at IS "
        "NULL OR NEW.qualified_at < qualification.authority_issued_at OR "
        "NEW.qualified_at > transaction_timestamp())) OR (OLD.qualified_at IS NOT "
        "NULL AND NEW.qualified_at IS DISTINCT FROM OLD.qualified_at) THEN RAISE "
        "EXCEPTION 'qualification adopter requires an exact qualification "
        "projection' USING ERRCODE = '23514'; END IF; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER provider_connections_qualification_pointer BEFORE UPDATE "
        "OF account_metadata, qualified_at, qualification_receipt_id ON "
        "provider_connections FOR EACH ROW EXECUTE FUNCTION "
        "validate_provider_qualification_pointer()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION validate_provider_qualification_pointer() FROM PUBLIC"
    )
    op.execute(
        "CREATE FUNCTION validate_run_qualification_binding() RETURNS trigger "
        "LANGUAGE plpgsql SECURITY DEFINER SET search_path = pg_catalog, pg_temp "
        "AS $$ DECLARE current_receipt uuid; current_model text; current_status "
        "text; BEGIN IF TG_OP = 'UPDATE' THEN IF ROW("
        "NEW.requester_id, NEW.provider_connection_id, "
        "NEW.qualification_receipt_id, NEW.qualification_receipt_sha256, "
        "NEW.qualification_connection_revision, NEW.qualification_profile_sha256, "
        "NEW.qualification_runtime_version, NEW.qualification_executable_sha256, "
        "NEW.provider_model_id) IS DISTINCT FROM ROW(OLD.requester_id, "
        "OLD.provider_connection_id, OLD.qualification_receipt_id, "
        "OLD.qualification_receipt_sha256, OLD.qualification_connection_revision, "
        "OLD.qualification_profile_sha256, OLD.qualification_runtime_version, "
        "OLD.qualification_executable_sha256, OLD.provider_model_id) THEN RAISE "
        "EXCEPTION 'run qualification binding is immutable' USING ERRCODE = "
        "'55000'; END IF; RETURN NEW; END IF; SELECT "
        "p.qualification_receipt_id, p.selected_model, p.status INTO "
        "current_receipt, current_model, current_status FROM "
        "public.provider_connections p WHERE p.org_id = NEW.org_id AND "
        "p.requester_user_id = "
        "NEW.requester_id AND p.id = NEW.provider_connection_id FOR UPDATE; IF "
        "NOT FOUND OR current_status <> 'healthy' THEN RAISE EXCEPTION 'run "
        "requires a healthy provider' USING ERRCODE = '23514'; END IF; IF "
        "current_receipt IS NULL OR NEW.qualification_receipt_id IS NULL OR "
        "NEW.qualification_receipt_id IS DISTINCT FROM current_receipt THEN RAISE "
        "EXCEPTION 'run requires current provider qualification' USING ERRCODE = "
        "'23514'; END IF; IF current_model IS NULL OR NEW.provider_model_id IS "
        "NULL OR NEW.provider_model_id IS DISTINCT FROM current_model THEN RAISE "
        "EXCEPTION 'run requires current provider model' USING ERRCODE = '23514'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER runs_qualification_binding BEFORE INSERT OR UPDATE ON runs "
        "FOR EACH ROW EXECUTE FUNCTION validate_run_qualification_binding()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION validate_run_qualification_binding() FROM PUBLIC"
    )


def drop_provider_guards() -> None:
    """Drop every 0003/0004 provider trigger through its owning function."""
    op.execute(
        "DROP FUNCTION IF EXISTS validate_qualification_receipt_revision() CASCADE"
    )
    op.execute("DROP FUNCTION IF EXISTS validate_run_qualification_binding() CASCADE")
    op.execute(
        "DROP FUNCTION IF EXISTS validate_provider_qualification_pointer() CASCADE"
    )
    drop_provider_runtime_lock_guards()


def restore_0003_provider_guards() -> None:
    """Restore the exact pre-0004 pointer and Run checks on downgrade."""
    op.execute(
        "CREATE OR REPLACE FUNCTION public.reject_provider_metadata_secret() "
        "RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF "
        "jsonb_contains_secret(NEW.account_metadata) THEN RAISE EXCEPTION "
        "'provider account metadata contains secret' USING ERRCODE = '23514'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "GRANT EXECUTE ON FUNCTION public.reject_provider_metadata_secret() TO PUBLIC"
    )
    op.execute(
        "CREATE FUNCTION validate_provider_qualification_pointer() RETURNS trigger "
        "LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ BEGIN IF "
        "current_user = "
        "'science_workbench_app' AND NEW.qualification_receipt_id IS NOT NULL AND "
        "NEW.qualification_receipt_id IS DISTINCT FROM "
        "OLD.qualification_receipt_id THEN RAISE EXCEPTION 'provider "
        "qualification requires adopter authority' USING ERRCODE = '42501'; END "
        "IF; IF (NEW.qualified_at IS NULL) <> (NEW.qualification_receipt_id IS "
        "NULL) THEN RAISE EXCEPTION 'provider qualification pointer mismatch' "
        "USING ERRCODE = '23514'; END IF; IF NEW.qualification_receipt_id IS NOT "
        "NULL AND NEW.qualification_receipt_id IS DISTINCT FROM "
        "OLD.qualification_receipt_id AND NOT EXISTS (SELECT 1 FROM "
        "public.provider_qualification_receipts q WHERE q.org_id = NEW.org_id AND "
        "q.requester_user_id = NEW.requester_user_id AND "
        "q.provider_connection_id = NEW.id AND q.id = "
        "NEW.qualification_receipt_id AND q.connection_revision = "
        "(NEW.account_metadata ->> 'revision')::bigint AND q.adapter_id = "
        "NEW.adapter_id) THEN RAISE EXCEPTION 'provider qualification pointer is "
        "stale' USING ERRCODE = '23514'; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER provider_connections_qualification_pointer BEFORE UPDATE "
        "OF qualified_at, qualification_receipt_id ON provider_connections FOR "
        "EACH ROW EXECUTE FUNCTION validate_provider_qualification_pointer()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION validate_provider_qualification_pointer() FROM PUBLIC"
    )
    op.execute(
        "CREATE FUNCTION validate_run_qualification_binding() RETURNS trigger "
        "LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ DECLARE "
        "current_receipt uuid; BEGIN IF TG_OP = "
        "'UPDATE' THEN IF ROW(NEW.requester_id, NEW.provider_connection_id, "
        "NEW.qualification_receipt_id, NEW.qualification_receipt_sha256, "
        "NEW.qualification_connection_revision, NEW.qualification_profile_sha256, "
        "NEW.qualification_runtime_version, NEW.qualification_executable_sha256) "
        "IS DISTINCT FROM ROW(OLD.requester_id, OLD.provider_connection_id, "
        "OLD.qualification_receipt_id, OLD.qualification_receipt_sha256, "
        "OLD.qualification_connection_revision, OLD.qualification_profile_sha256, "
        "OLD.qualification_runtime_version, OLD.qualification_executable_sha256) "
        "THEN RAISE EXCEPTION 'run qualification binding is immutable' USING "
        "ERRCODE = '55000'; END IF; RETURN NEW; END IF; SELECT "
        "p.qualification_receipt_id INTO current_receipt FROM "
        "public.provider_connections p WHERE p.org_id = NEW.org_id AND "
        "p.requester_user_id = NEW.requester_id AND p.id = "
        "NEW.provider_connection_id FOR UPDATE; IF NOT FOUND OR current_receipt IS "
        "NULL OR NEW.qualification_receipt_id IS NULL OR "
        "NEW.qualification_receipt_id IS DISTINCT FROM current_receipt THEN RAISE "
        "EXCEPTION 'run requires current provider qualification' USING ERRCODE = "
        "'23514'; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER runs_qualification_binding BEFORE INSERT OR UPDATE ON runs "
        "FOR EACH ROW EXECUTE FUNCTION validate_run_qualification_binding()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION validate_run_qualification_binding() FROM PUBLIC"
    )
