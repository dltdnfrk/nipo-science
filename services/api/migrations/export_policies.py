from __future__ import annotations

from alembic import op


def create_export_guards() -> None:
    """Freeze export selections at creation and prevent terminal rewinds."""
    op.execute(
        "CREATE FUNCTION validate_export_pin_insert() RETURNS trigger LANGUAGE plpgsql "
        "AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM export_jobs e WHERE "
        "e.org_id = NEW.org_id AND e.id = NEW.export_id AND "
        "e.created_at = CURRENT_TIMESTAMP) THEN RAISE EXCEPTION "
        "'export selection is immutable' USING ERRCODE = '55000'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER export_artifact_versions_insert BEFORE INSERT ON "
        "export_artifact_versions FOR EACH ROW EXECUTE FUNCTION "
        "validate_export_pin_insert()"
    )
    op.execute(
        "CREATE FUNCTION protect_export_job() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF TG_OP = 'UPDATE' AND (NEW.id <> OLD.id OR NEW.org_id <> OLD.org_id "
        "OR NEW.created_at <> OLD.created_at) THEN RAISE EXCEPTION "
        "'export identity is immutable' USING ERRCODE = '55000'; END IF; "
        "IF OLD.status IN ('completed', 'failed') THEN RAISE EXCEPTION "
        "'terminal export is immutable' USING ERRCODE = '55000'; END IF; "
        "RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER export_jobs_terminal BEFORE UPDATE OR DELETE ON export_jobs "
        "FOR EACH ROW EXECUTE FUNCTION protect_export_job()"
    )
    op.execute(
        "CREATE FUNCTION validate_export_selection() RETURNS trigger LANGUAGE plpgsql "
        "AS $$ BEGIN IF EXISTS (SELECT 1 FROM export_jobs e "
        "WHERE e.org_id = NEW.org_id "
        "AND e.id = NEW.id) AND NOT EXISTS (SELECT 1 FROM export_artifact_versions s "
        "WHERE s.org_id = NEW.org_id AND s.export_id = NEW.id) THEN RAISE EXCEPTION "
        "'export requires an artifact version selection' USING ERRCODE = '23514'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE CONSTRAINT TRIGGER export_jobs_selection AFTER INSERT OR UPDATE "
        "ON export_jobs DEFERRABLE INITIALLY DEFERRED FOR EACH ROW "
        "EXECUTE FUNCTION validate_export_selection()"
    )


def drop_export_guards() -> None:
    """Drop export integrity functions with their triggers."""
    op.execute("DROP FUNCTION validate_export_selection() CASCADE")
    op.execute("DROP FUNCTION protect_export_job() CASCADE")
    op.execute("DROP FUNCTION validate_export_pin_insert() CASCADE")
