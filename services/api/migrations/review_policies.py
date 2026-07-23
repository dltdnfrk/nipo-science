from __future__ import annotations

from alembic import op


def create_review_evidence_guards() -> None:
    """Freeze Review inputs and bind Finding evidence to those inputs."""
    op.execute(
        "CREATE FUNCTION validate_review_evidence() RETURNS trigger LANGUAGE plpgsql "
        "AS $$ BEGIN IF NOT EXISTS "
        "(SELECT 1 FROM review_artifact_versions a WHERE a.org_id = NEW.org_id "
        "AND a.review_id = NEW.id UNION ALL SELECT 1 FROM review_execution_refs e "
        "WHERE e.org_id = NEW.org_id AND e.review_id = NEW.id) THEN RAISE EXCEPTION "
        "'completed review requires evidence pins' USING ERRCODE = '23514'; END IF; "
        "IF EXISTS (SELECT 1 FROM reviews r WHERE r.org_id = NEW.org_id AND "
        "r.id = NEW.id AND ((r.status = 'completed') <> "
        "(r.submission_id IS NOT NULL AND r.submitted_at IS NOT NULL))) THEN "
        "RAISE EXCEPTION 'review submission lifecycle' USING ERRCODE = '23514'; "
        "END IF; IF EXISTS (SELECT 1 FROM reviews r WHERE r.org_id = NEW.org_id "
        "AND r.id = NEW.id AND r.status = 'completed') AND NOT EXISTS "
        "(SELECT 1 FROM review_findings f JOIN reviews r ON r.org_id = f.org_id "
        "AND r.id = f.review_id WHERE f.org_id = NEW.org_id AND f.review_id = NEW.id "
        "AND f.submission_id = r.submission_id) THEN RAISE EXCEPTION "
        "'completed review requires findings' USING ERRCODE = '23514'; END IF; "
        "IF TG_OP = 'UPDATE' AND (OLD.status IN ('completed', 'failed') OR "
        "NEW.org_id <> OLD.org_id OR NEW.source_run_id <> OLD.source_run_id OR "
        "NEW.run_id <> OLD.run_id OR "
        "NEW.pinned_input_sha256 <> OLD.pinned_input_sha256 "
        "OR NEW.reviewer_capabilities <> OLD.reviewer_capabilities OR "
        "NEW.created_at <> OLD.created_at OR NEW.revision <> OLD.revision + 1) "
        "THEN RAISE EXCEPTION 'review inputs are immutable' USING ERRCODE = '55000'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE CONSTRAINT TRIGGER reviews_evidence AFTER INSERT OR UPDATE ON reviews "
        "DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION "
        "validate_review_evidence()"
    )
    op.execute(
        "CREATE FUNCTION protect_review_delete() RETURNS trigger LANGUAGE plpgsql "
        "AS $$ "
        "BEGIN RAISE EXCEPTION 'review evidence is immutable' USING ERRCODE = '55000'; "
        "END $$"
    )
    op.execute(
        "CREATE TRIGGER reviews_no_delete BEFORE DELETE ON reviews FOR EACH ROW "
        "EXECUTE FUNCTION protect_review_delete()"
    )
    op.execute(
        "CREATE FUNCTION validate_review_pin_insert() RETURNS trigger LANGUAGE plpgsql "
        "AS $$ BEGIN IF EXISTS (SELECT 1 FROM reviews r WHERE r.org_id = NEW.org_id "
        "AND r.id = NEW.review_id AND r.created_at <> CURRENT_TIMESTAMP) THEN "
        "RAISE EXCEPTION 'review inputs are immutable' "
        "USING ERRCODE = '55000'; "
        "END IF; RETURN NEW; END $$"
    )
    for table in ("review_artifact_versions", "review_execution_refs"):
        op.execute(
            f"CREATE TRIGGER {table}_insert BEFORE INSERT ON {table} FOR EACH ROW "
            "EXECUTE FUNCTION validate_review_pin_insert()"
        )
    op.execute(
        "CREATE FUNCTION validate_finding_insert() RETURNS trigger LANGUAGE plpgsql "
        "AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM reviews r "
        "WHERE r.org_id = NEW.org_id "
        "AND r.id = NEW.review_id AND r.status = 'running' AND "
        "r.submission_id = NEW.submission_id AND r.submitted_at = CURRENT_TIMESTAMP) "
        "THEN RAISE EXCEPTION 'review findings are immutable' USING ERRCODE = '55000'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER review_findings_insert BEFORE INSERT ON review_findings "
        "FOR EACH ROW EXECUTE FUNCTION validate_finding_insert()"
    )
    op.execute(
        "CREATE FUNCTION validate_finding_evidence() RETURNS trigger LANGUAGE plpgsql "
        "AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM review_finding_artifact_versions a "
        "WHERE a.org_id = NEW.org_id AND a.finding_id = NEW.id) THEN RAISE EXCEPTION "
        "'review finding requires artifact evidence' USING ERRCODE = '23514'; END IF; "
        "IF TG_OP = 'UPDATE' AND (NEW.org_id <> OLD.org_id OR "
        "NEW.review_id <> OLD.review_id OR NEW.submission_id <> OLD.submission_id OR "
        "NEW.rule_id <> OLD.rule_id OR NEW.verdict <> OLD.verdict OR "
        "NEW.message <> OLD.message OR NEW.created_at <> OLD.created_at) THEN "
        "RAISE EXCEPTION 'review finding evidence is immutable' "
        "USING ERRCODE = '55000'; "
        "END IF; IF TG_OP = 'UPDATE' AND OLD.status IN "
        "('rebutted', 'accepted_risk') AND (NEW.status <> OLD.status OR "
        "NEW.disposition_actor_id IS DISTINCT FROM OLD.disposition_actor_id OR "
        "NEW.disposition_reason IS DISTINCT FROM OLD.disposition_reason) THEN "
        "RAISE EXCEPTION 'finding disposition audit is immutable' "
        "USING ERRCODE = '55000'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE CONSTRAINT TRIGGER review_findings_evidence AFTER INSERT OR UPDATE "
        "ON review_findings DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE "
        "FUNCTION validate_finding_evidence()"
    )
    op.execute(
        "CREATE TRIGGER review_findings_no_delete BEFORE DELETE ON review_findings "
        "FOR EACH ROW EXECUTE FUNCTION protect_review_delete()"
    )
    op.execute(
        "CREATE FUNCTION validate_finding_artifact_pin() RETURNS trigger LANGUAGE "
        "plpgsql AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM review_findings f JOIN "
        "review_artifact_versions p ON p.org_id = f.org_id AND p.review_id = "
        "f.review_id JOIN reviews r ON r.org_id = f.org_id AND r.id = f.review_id "
        "WHERE f.org_id = NEW.org_id AND f.id = NEW.finding_id AND "
        "p.artifact_version_id = NEW.artifact_version_id AND r.status = 'running' "
        "AND r.submitted_at = CURRENT_TIMESTAMP) THEN RAISE EXCEPTION "
        "'finding artifact must be pinned by review' USING ERRCODE = '23514'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER review_finding_artifact_pin BEFORE INSERT ON "
        "review_finding_artifact_versions FOR EACH ROW EXECUTE FUNCTION "
        "validate_finding_artifact_pin()"
    )
    op.execute(
        "CREATE FUNCTION validate_finding_execution_pin() RETURNS trigger LANGUAGE "
        "plpgsql AS $$ BEGIN IF NOT EXISTS (SELECT 1 FROM review_findings f JOIN "
        "review_execution_refs p ON p.org_id = f.org_id AND p.review_id = f.review_id "
        "JOIN reviews r ON r.org_id = f.org_id AND r.id = f.review_id WHERE "
        "f.org_id = NEW.org_id AND f.id = NEW.finding_id AND "
        "p.execution_id = NEW.execution_id AND r.status = 'running' "
        "AND r.submitted_at = CURRENT_TIMESTAMP) THEN RAISE EXCEPTION "
        "'finding execution must be pinned by review' USING ERRCODE = '23514'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER review_finding_execution_pin BEFORE INSERT ON "
        "review_finding_execution_refs FOR EACH ROW EXECUTE FUNCTION "
        "validate_finding_execution_pin()"
    )


def drop_review_evidence_guards() -> None:
    """Drop Review and Finding integrity functions with their triggers."""
    op.execute("DROP FUNCTION validate_finding_execution_pin() CASCADE")
    op.execute("DROP FUNCTION validate_finding_artifact_pin() CASCADE")
    op.execute("DROP FUNCTION validate_finding_evidence() CASCADE")
    op.execute("DROP FUNCTION validate_finding_insert() CASCADE")
    op.execute("DROP FUNCTION validate_review_pin_insert() CASCADE")
    op.execute("DROP FUNCTION protect_review_delete() CASCADE")
    op.execute("DROP FUNCTION validate_review_evidence() CASCADE")
