from __future__ import annotations

from alembic import op

from services.api.migrations.export_policies import (
    create_export_guards,
    drop_export_guards,
)
from services.api.migrations.integrity_policies import (
    create_last_owner_guard,
    create_membership_admin_guard,
    create_provider_metadata_guard,
    create_provider_qualification_guards,
    drop_integrity_guards,
)
from services.api.migrations.principal_policies import (
    create_compliance_policy,
    create_principal_guard,
    drop_principal_guard,
)
from services.api.migrations.review_policies import (
    create_review_evidence_guards,
    drop_review_evidence_guards,
)
from services.api.migrations.role_policies import create_roles
from services.api.persistence.schema_inventory import (
    APPEND_ONLY_TABLES,
    TENANT_TABLE_POLICIES,
    UUID7_ID_TABLES,
)

_PROVIDER_QUALIFICATION_TABLES = frozenset(
    {
        "provider_qualification_receipts",
        "provider_qualification_legacy_evidence",
    }
)


def create_immutable_trigger(*, include_provider_qualification: bool = True) -> None:
    op.execute(
        "CREATE FUNCTION reject_immutable_mutation() RETURNS trigger "
        "LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION "
        "'immutable table % rejects %', TG_TABLE_NAME, TG_OP "
        "USING ERRCODE = '55000'; END $$"
    )
    for table in APPEND_ONLY_TABLES:
        if (
            not include_provider_qualification
            and table in _PROVIDER_QUALIFICATION_TABLES
        ):
            continue
        op.execute(
            f"CREATE TRIGGER {table}_immutable BEFORE UPDATE OR DELETE ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION reject_immutable_mutation()"
        )


def create_uuid7_trigger(*, include_provider_qualification: bool = True) -> None:
    op.execute(
        "CREATE FUNCTION enforce_uuid7_id() RETURNS trigger LANGUAGE plpgsql AS $$ "
        "BEGIN IF uuid_extract_version(NEW.id) <> 7 THEN RAISE EXCEPTION "
        "'primary id must be UUIDv7' USING ERRCODE = '23514'; END IF; "
        "RETURN NEW; END $$"
    )
    for table in UUID7_ID_TABLES:
        if (
            not include_provider_qualification
            and table in _PROVIDER_QUALIFICATION_TABLES
        ):
            continue
        op.execute(
            f"CREATE TRIGGER {table}_uuid7 BEFORE INSERT OR UPDATE OF id ON {table} "
            "FOR EACH ROW EXECUTE FUNCTION enforce_uuid7_id()"
        )


def create_outbox_trigger() -> None:
    op.execute(
        "CREATE FUNCTION enqueue_audit_outbox() RETURNS trigger LANGUAGE plpgsql "
        "SECURITY DEFINER SET search_path = public, pg_temp AS $$ BEGIN "
        "INSERT INTO audit_outbox (org_id, audit_log_id, payload) VALUES "
        "(NEW.org_id, NEW.id, jsonb_build_object('audit_log_id', NEW.id, "
        "'org_id', NEW.org_id, 'event_type', NEW.event_type, 'resource_type', "
        "NEW.resource_type, 'resource_id', NEW.resource_id, "
        "'metadata', NEW.metadata, "
        "'created_at', NEW.created_at)); RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER audit_logs_enqueue AFTER INSERT ON audit_logs "
        "FOR EACH ROW EXECUTE FUNCTION enqueue_audit_outbox()"
    )


def create_artifact_version_scope_guard() -> None:
    op.execute(
        "CREATE FUNCTION validate_artifact_version_scope() RETURNS trigger "
        "LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$ "
        "BEGIN IF NOT EXISTS (SELECT 1 FROM executions e JOIN runs r "
        "ON r.org_id = e.org_id AND r.id = e.run_id JOIN sessions s "
        "ON s.org_id = r.org_id AND s.id = r.session_id JOIN projects project "
        "ON project.org_id = s.org_id AND project.id = s.project_id "
        "JOIN provider_connections p ON p.org_id = r.org_id "
        "AND p.id = r.provider_connection_id AND p.requester_user_id = r.requester_id "
        "WHERE e.org_id = NEW.org_id AND e.id = NEW.producing_execution_id "
        "AND s.project_id = NEW.project_id AND project.archived_at IS NULL "
        "AND s.archived_at IS NULL AND (NULLIF(current_setting("
        "'app.user_id', true), '') IS NULL OR r.requester_id = NULLIF("
        "current_setting('app.user_id', true), '')::uuid) "
        "AND NEW.runtime_connection_id = r.provider_connection_id "
        "AND NEW.runtime_adapter_id = p.adapter_id FOR UPDATE OF project, s) "
        "THEN RAISE EXCEPTION 'artifact version scope mismatch' "
        "USING ERRCODE = '23514'; END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER artifact_versions_scope BEFORE INSERT ON artifact_versions "
        "FOR EACH ROW EXECUTE FUNCTION validate_artifact_version_scope()"
    )
    op.execute(
        "CREATE FUNCTION validate_artifact_association_scope() RETURNS trigger "
        "LANGUAGE plpgsql SECURITY DEFINER SET search_path = public, pg_temp AS $$ "
        "BEGIN IF NOT EXISTS (SELECT 1 FROM projects p JOIN sessions s "
        "ON s.org_id = p.org_id AND s.project_id = p.id "
        "WHERE p.org_id = NEW.org_id AND p.id = NEW.project_id "
        "AND p.archived_at IS NULL AND s.id = NEW.session_id "
        "AND s.archived_at IS NULL FOR UPDATE OF p, s) THEN RAISE EXCEPTION "
        "'artifact association scope is inactive' USING ERRCODE = '23514'; "
        "END IF; RETURN NEW; END $$"
    )
    op.execute(
        "CREATE TRIGGER session_artifact_versions_scope BEFORE INSERT ON "
        "session_artifact_versions FOR EACH ROW EXECUTE FUNCTION "
        "validate_artifact_association_scope()"
    )


def apply_rls(*, include_provider_qualification: bool = False) -> None:
    create_roles()
    create_principal_guard()
    principal = "org_id = current_principal_org()"
    for table_policy in TENANT_TABLE_POLICIES:
        table = table_policy.name
        if (
            not include_provider_qualification
            and table in _PROVIDER_QUALIFICATION_TABLES
        ):
            continue
        table_principal = principal
        if table_policy.requester_column is not None:
            table_principal = (
                f"({principal}) AND {table_policy.requester_column} = "
                "NULLIF(current_setting('app.user_id', true), '')::uuid"
            )
        op.execute(f"ALTER TABLE {table} ENABLE ROW LEVEL SECURITY")
        op.execute(f"ALTER TABLE {table} FORCE ROW LEVEL SECURITY")
        op.execute(
            f"CREATE POLICY tenant_isolation ON {table} USING ({table_principal}) "
            f"WITH CHECK ({table_principal})"
        )
    op.execute("GRANT USAGE ON SCHEMA public TO science_workbench_app")
    op.execute(
        "GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public "
        "TO science_workbench_app"
    )
    op.execute(
        "REVOKE INSERT, UPDATE, DELETE ON audit_outbox, legal_holds "
        "FROM science_workbench_app"
    )
    immutable_revoke = (
        "action_plans, artifact_dependencies, artifact_versions, audit_logs, "
        "run_events"
    )
    if include_provider_qualification:
        immutable_revoke += (
            ", provider_qualification_receipts, "
            "provider_qualification_legacy_evidence"
        )
    op.execute(
        f"REVOKE UPDATE, DELETE ON {immutable_revoke} FROM science_workbench_app"
    )
    op.execute("REVOKE ALL ON organizations, users FROM science_workbench_app")
    op.execute("GRANT USAGE ON SCHEMA public TO science_workbench_compliance")
    op.execute("GRANT SELECT, INSERT ON legal_holds TO science_workbench_compliance")
    create_compliance_policy()
    op.execute(
        "REVOKE ALL ON alembic_version FROM science_workbench_app, "
        "science_workbench_compliance"
    )
    create_uuid7_trigger(
        include_provider_qualification=include_provider_qualification
    )
    create_immutable_trigger(
        include_provider_qualification=include_provider_qualification
    )
    create_last_owner_guard()
    create_membership_admin_guard()
    create_provider_metadata_guard()
    if include_provider_qualification:
        create_provider_qualification_guards()
    create_artifact_version_scope_guard()
    create_review_evidence_guards()
    create_export_guards()
    create_outbox_trigger()


def drop_policies() -> None:
    op.execute("DROP FUNCTION enqueue_audit_outbox() CASCADE")
    drop_export_guards()
    drop_review_evidence_guards()
    drop_integrity_guards()
    drop_principal_guard()
    op.execute("DROP FUNCTION validate_artifact_association_scope() CASCADE")
    op.execute("DROP FUNCTION validate_artifact_version_scope() CASCADE")
    op.execute("DROP FUNCTION reject_immutable_mutation() CASCADE")
    op.execute("DROP FUNCTION enforce_uuid7_id() CASCADE")
