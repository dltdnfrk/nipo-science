from __future__ import annotations

from alembic import op


def create_roles() -> None:
    op.execute(
        "DO $$ BEGIN CREATE ROLE science_workbench_app NOLOGIN; "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    op.execute(
        "DO $$ BEGIN CREATE ROLE science_workbench_compliance NOLOGIN; "
        "EXCEPTION WHEN duplicate_object THEN NULL; END $$"
    )
    for role in ("science_workbench_app", "science_workbench_compliance"):
        op.execute(
            f"ALTER ROLE {role} WITH NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE "
            "NOINHERIT NOREPLICATION NOBYPASSRLS"
        )


def drop_roles() -> None:
    op.execute("REVOKE USAGE ON SCHEMA public FROM science_workbench_compliance")
    op.execute("REVOKE USAGE ON SCHEMA public FROM science_workbench_app")
