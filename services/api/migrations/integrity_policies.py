from __future__ import annotations

from alembic import op


def create_last_owner_guard() -> None:
    op.execute(
        "CREATE FUNCTION protect_last_owner() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF OLD.role = 'owner' AND OLD.revoked_at IS NULL AND "
        "(TG_OP = 'DELETE' OR NEW.role <> 'owner' OR NEW.revoked_at IS NOT NULL) "
        "THEN IF NOT pg_try_advisory_xact_lock(hashtextextended(OLD.org_id::text, 0)) "
        "THEN RAISE EXCEPTION 'concurrent owner membership change' "
        "USING ERRCODE = '40001'; END IF; IF NOT EXISTS "
        "(SELECT 1 FROM memberships m WHERE m.org_id = OLD.org_id "
        "AND m.user_id <> OLD.user_id AND m.role = 'owner' "
        "AND m.revoked_at IS NULL) THEN RAISE EXCEPTION "
        "'organization requires an owner' USING ERRCODE = '23514'; END IF; END IF; "
        "IF TG_OP = 'DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER memberships_last_owner BEFORE UPDATE OR DELETE ON memberships "
        "FOR EACH ROW EXECUTE FUNCTION protect_last_owner()"
    )


def create_membership_admin_guard() -> None:
    op.execute(
        "CREATE FUNCTION require_owner_membership_mutation() RETURNS trigger "
        "LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$ "
        "DECLARE target_org uuid; BEGIN target_org := CASE WHEN TG_OP = 'INSERT' "
        "THEN NEW.org_id ELSE OLD.org_id END; IF current_setting('role', true) = "
        "'science_workbench_app' AND TG_OP = 'DELETE' THEN RAISE EXCEPTION "
        "'memberships require soft revocation' USING ERRCODE = '55000'; END IF; "
        "IF current_setting('role', true) = 'science_workbench_app' AND NOT EXISTS "
        "(SELECT 1 FROM memberships m WHERE "
        "m.org_id = target_org AND m.user_id = NULLIF(current_setting('app.user_id', "
        "true), '')::uuid AND m.role = 'owner' AND m.revoked_at IS NULL) "
        "THEN RAISE EXCEPTION "
        "'membership mutation requires owner' USING ERRCODE = '42501'; END IF; "
        "IF TG_OP = 'DELETE' THEN RETURN OLD; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER memberships_owner_admin BEFORE INSERT OR UPDATE OR DELETE "
        "ON memberships FOR EACH ROW EXECUTE FUNCTION "
        "require_owner_membership_mutation()"
    )


def create_provider_metadata_guard() -> None:
    op.execute(
        "CREATE FUNCTION jsonb_contains_secret(payload jsonb) RETURNS boolean "
        "LANGUAGE plpgsql IMMUTABLE SET search_path = pg_catalog AS $$ DECLARE "
        "entry record; normalized_key text; scalar text; BEGIN CASE "
        "jsonb_typeof(payload) WHEN 'object' THEN FOR entry IN SELECT key, value "
        "FROM jsonb_each(payload) LOOP "
        "normalized_key := regexp_replace(lower(normalize(entry.key, NFKC)), "
        "'[^a-z0-9]', '', 'g'); "
        "IF normalized_key <> ALL (ARRAY['accountid','accountname','adoptionstatus',"
        "'cleanuprequestedat','cleanupstatus','destroyby','destroyedat',"
        "'displayname','email',"
        "'evidencesha256','lastverifiedat','model','models','provider','revision',"
        "'qualificationexecutablesha256','qualificationprofilesha256',"
        "'qualificationreceiptid','qualificationruntimeversion','stagingleaseid',"
        "'stagingleasedestroyby',"
        "'subscriptiontier','username',"
        "'workspaceid']::text[]) OR "
        "public.jsonb_contains_secret(entry.value) "
        "THEN RETURN true; "
        "END IF; END LOOP; WHEN 'array' THEN FOR entry IN SELECT value FROM "
        "jsonb_array_elements(payload) LOOP IF "
        "public.jsonb_contains_secret(entry.value) "
        "THEN RETURN true; END IF; END LOOP; WHEN 'string' THEN scalar := "
        "normalize(payload #>> '{}', NFKC); "
        "IF scalar ~* '^[[:space:]]*(bearer|basic)[[:space:]]+"
        "[A-Za-z0-9._~+/=-]{8,}[[:space:]]*$' OR scalar ~* "
        "'^[[:space:]]*(sk-|xox[baprs]-|gh[pousr]_)[A-Za-z0-9._=-]{12,}"
        "[[:space:]]*$' OR scalar ~* 'ya29[.][A-Za-z0-9._=-]{8,}' OR scalar ~ "
        "'AKIA[A-Z0-9]{16}' OR scalar ~* '(client[_ -]?secret|access[_ -]?token|"
        "refresh[_ -]?token|api[_ -]?key|password|authorization)[[:space:]]*[:=]' "
        "OR scalar ~* '-----BEGIN[[:space:]]+[A-Z0-9 ]*PRIVATE KEY-----' "
        "THEN RETURN true; END IF; ELSE NULL; END CASE; "
        "RETURN false; END $$"
    )
    op.execute(
        "CREATE FUNCTION reject_provider_metadata_secret() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN IF jsonb_contains_secret(NEW.account_metadata) "
        "THEN RAISE EXCEPTION 'provider account metadata contains secret' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER provider_connections_metadata_secret BEFORE INSERT OR UPDATE "
        "OF account_metadata ON provider_connections FOR EACH ROW "
        "EXECUTE FUNCTION reject_provider_metadata_secret()"
    )


def create_provider_qualification_guards() -> None:
    op.execute(
        "CREATE FUNCTION validate_provider_qualification_pointer() RETURNS trigger "
        "LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ BEGIN IF "
        "current_user = "
        "'science_workbench_app' AND NEW.qualification_receipt_id IS NOT NULL "
        "AND NEW.qualification_receipt_id IS DISTINCT FROM "
        "OLD.qualification_receipt_id THEN RAISE EXCEPTION "
        "'provider qualification requires adopter authority' USING ERRCODE = "
        "'42501'; END IF; IF (NEW.qualified_at IS NULL) <> "
        "(NEW.qualification_receipt_id IS NULL) THEN RAISE EXCEPTION "
        "'provider qualification pointer mismatch' USING ERRCODE = '23514'; "
        "END IF; IF NEW.qualification_receipt_id IS NOT NULL AND "
        "NEW.qualification_receipt_id IS DISTINCT FROM OLD.qualification_receipt_id "
        "AND NOT EXISTS (SELECT 1 FROM public.provider_qualification_receipts q "
        "WHERE "
        "q.org_id = NEW.org_id AND q.requester_user_id = NEW.requester_user_id "
        "AND q.provider_connection_id = NEW.id AND "
        "q.id = NEW.qualification_receipt_id AND q.connection_revision = "
        "(NEW.account_metadata ->> 'revision')::bigint AND "
        "q.adapter_id = NEW.adapter_id) THEN RAISE EXCEPTION "
        "'provider qualification pointer is stale' USING ERRCODE = '23514'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER provider_connections_qualification_pointer BEFORE UPDATE OF "
        "qualified_at, qualification_receipt_id ON provider_connections FOR EACH "
        "ROW EXECUTE FUNCTION validate_provider_qualification_pointer()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION validate_provider_qualification_pointer() FROM PUBLIC"
    )
    op.execute(
        "CREATE FUNCTION validate_run_qualification_binding() RETURNS trigger "
        "LANGUAGE plpgsql SET search_path = pg_catalog, pg_temp AS $$ DECLARE "
        "current_receipt uuid; BEGIN IF "
        "TG_OP = 'UPDATE' THEN IF "
        "ROW(NEW.requester_id, NEW.provider_connection_id, "
        "NEW.qualification_receipt_id, NEW.qualification_receipt_sha256, "
        "NEW.qualification_connection_revision, NEW.qualification_profile_sha256, "
        "NEW.qualification_runtime_version, NEW.qualification_executable_sha256) "
        "IS DISTINCT FROM ROW(OLD.requester_id, OLD.provider_connection_id, "
        "OLD.qualification_receipt_id, OLD.qualification_receipt_sha256, "
        "OLD.qualification_connection_revision, OLD.qualification_profile_sha256, "
        "OLD.qualification_runtime_version, OLD.qualification_executable_sha256) "
        "THEN RAISE EXCEPTION 'run qualification binding is immutable' "
        "USING ERRCODE = '55000'; END IF; RETURN NEW; END IF; SELECT "
        "p.qualification_receipt_id INTO current_receipt FROM "
        "public.provider_connections p WHERE p.org_id = NEW.org_id AND "
        "p.requester_user_id = NEW.requester_id AND "
        "p.id = NEW.provider_connection_id FOR UPDATE; IF NOT FOUND OR "
        "current_receipt IS NULL OR NEW.qualification_receipt_id IS NULL OR "
        "NEW.qualification_receipt_id IS DISTINCT FROM current_receipt THEN "
        "RAISE EXCEPTION "
        "'run requires current provider qualification' USING ERRCODE = '23514'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER runs_qualification_binding BEFORE INSERT OR UPDATE ON runs "
        "FOR EACH ROW EXECUTE FUNCTION validate_run_qualification_binding()"
    )
    op.execute(
        "REVOKE ALL ON FUNCTION validate_run_qualification_binding() FROM PUBLIC"
    )


def drop_integrity_guards() -> None:
    op.execute("DROP FUNCTION IF EXISTS validate_run_qualification_binding() CASCADE")
    op.execute(
        "DROP FUNCTION IF EXISTS validate_provider_qualification_pointer() CASCADE"
    )
    op.execute("DROP FUNCTION IF EXISTS reject_provider_metadata_secret() CASCADE")
    op.execute("DROP FUNCTION IF EXISTS jsonb_contains_secret(jsonb) CASCADE")
    op.execute("DROP FUNCTION IF EXISTS require_owner_membership_mutation() CASCADE")
    op.execute("DROP FUNCTION IF EXISTS protect_last_owner() CASCADE")
