from __future__ import annotations

from typing import TYPE_CHECKING

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

if TYPE_CHECKING:
    from datetime import datetime
    from uuid import UUID


def uuid_pk() -> sa.Column[UUID]:
    return sa.Column(
        "id",
        postgresql.UUID(as_uuid=True),
        primary_key=True,
        server_default=sa.text("uuidv7()"),
    )


def org_id() -> sa.Column[UUID]:
    return sa.Column("org_id", postgresql.UUID(as_uuid=True), nullable=False)


def uuid_ref(name: str, *, nullable: bool = False) -> sa.Column[UUID]:
    return sa.Column(name, postgresql.UUID(as_uuid=True), nullable=nullable)


def created_at() -> sa.Column[datetime]:
    return sa.Column(
        "created_at",
        sa.DateTime(timezone=True),
        nullable=False,
        server_default=sa.text("CURRENT_TIMESTAMP"),
    )


def tenant_unique() -> sa.UniqueConstraint:
    return sa.UniqueConstraint("org_id", "id")


def tenant_fk(
    local_id: str,
    remote_table: str,
    constraint_name: str | None = None,
) -> sa.ForeignKeyConstraint:
    return sa.ForeignKeyConstraint(
        ["org_id", local_id],
        [f"{remote_table}.org_id", f"{remote_table}.id"],
        name=constraint_name,
    )
