from __future__ import annotations

from typing import TYPE_CHECKING

from services.api.migrations.policies import apply_rls, drop_policies
from services.api.migrations.role_policies import drop_roles
from services.api.migrations.schema import drop_schema, upgrade_schema
from services.api.migrations.versioned_0001 import normalize_0001_contract

if TYPE_CHECKING:
    from collections.abc import Sequence

revision: str = "0001_tenant_spine"
down_revision: str | None = None
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    upgrade_schema()
    apply_rls()
    normalize_0001_contract()


def downgrade() -> None:
    drop_policies()
    drop_schema()
    drop_roles()
