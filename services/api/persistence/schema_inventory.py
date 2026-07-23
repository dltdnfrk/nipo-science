"""Typed authority for database table scope and cross-cutting policies."""

from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final


class TableScope(StrEnum):
    """Whether a table is global or tenant-isolated."""

    GLOBAL = "global"
    TENANT = "tenant"


@dataclass(frozen=True, slots=True)
class TablePolicy:
    """Cross-cutting migration policy for one schema table."""

    name: str
    scope: TableScope
    uuid7_id: bool = False
    append_only: bool = False
    requester_column: str | None = None


TABLE_POLICIES: Final = (
    TablePolicy("organizations", TableScope.GLOBAL, uuid7_id=True),
    TablePolicy("users", TableScope.GLOBAL, uuid7_id=True),
    TablePolicy("memberships", TableScope.TENANT),
    TablePolicy("auth_sessions", TableScope.TENANT, uuid7_id=True),
    TablePolicy("consents", TableScope.TENANT, uuid7_id=True),
    TablePolicy("projects", TableScope.TENANT, uuid7_id=True),
    TablePolicy("sessions", TableScope.TENANT, uuid7_id=True),
    TablePolicy(
        "provider_connections",
        TableScope.TENANT,
        uuid7_id=True,
        requester_column="requester_user_id",
    ),
    TablePolicy(
        "provider_qualification_receipts",
        TableScope.TENANT,
        uuid7_id=True,
        append_only=True,
        requester_column="requester_user_id",
    ),
    TablePolicy(
        "provider_qualification_legacy_evidence",
        TableScope.TENANT,
        uuid7_id=True,
        append_only=True,
        requester_column="requester_user_id",
    ),
    TablePolicy(
        "provider_runtime_home_cleanups",
        TableScope.TENANT,
        requester_column="requester_user_id",
    ),
    TablePolicy("runs", TableScope.TENANT, uuid7_id=True),
    TablePolicy("messages", TableScope.TENANT, uuid7_id=True),
    TablePolicy(
        "run_events", TableScope.TENANT, uuid7_id=True, append_only=True
    ),
    TablePolicy(
        "action_plans", TableScope.TENANT, uuid7_id=True, append_only=True
    ),
    TablePolicy("approval_requests", TableScope.TENANT, uuid7_id=True),
    TablePolicy("executions", TableScope.TENANT, uuid7_id=True),
    TablePolicy("execution_leases", TableScope.TENANT),
    TablePolicy("uploaded_files", TableScope.TENANT, uuid7_id=True),
    TablePolicy("artifacts", TableScope.TENANT, uuid7_id=True),
    TablePolicy(
        "artifact_versions",
        TableScope.TENANT,
        uuid7_id=True,
        append_only=True,
    ),
    TablePolicy(
        "artifact_dependencies", TableScope.TENANT, append_only=True
    ),
    TablePolicy("session_artifact_versions", TableScope.TENANT),
    TablePolicy("skills", TableScope.TENANT, uuid7_id=True),
    TablePolicy("run_skill_snapshots", TableScope.TENANT, uuid7_id=True),
    TablePolicy("connectors", TableScope.TENANT, uuid7_id=True),
    TablePolicy("connector_calls", TableScope.TENANT, uuid7_id=True),
    TablePolicy("credentials", TableScope.TENANT, uuid7_id=True),
    TablePolicy("tool_grants", TableScope.TENANT, uuid7_id=True),
    TablePolicy("reviews", TableScope.TENANT, uuid7_id=True),
    TablePolicy(
        "review_artifact_versions", TableScope.TENANT, append_only=True
    ),
    TablePolicy("review_execution_refs", TableScope.TENANT, append_only=True),
    TablePolicy("review_findings", TableScope.TENANT, uuid7_id=True),
    TablePolicy(
        "review_finding_artifact_versions", TableScope.TENANT, append_only=True
    ),
    TablePolicy(
        "review_finding_execution_refs", TableScope.TENANT, append_only=True
    ),
    TablePolicy("export_jobs", TableScope.TENANT, uuid7_id=True),
    TablePolicy("export_artifact_versions", TableScope.TENANT, append_only=True),
    TablePolicy("idempotency_records", TableScope.TENANT, uuid7_id=True),
    TablePolicy(
        "audit_logs", TableScope.TENANT, uuid7_id=True, append_only=True
    ),
    TablePolicy(
        "audit_outbox", TableScope.TENANT, uuid7_id=True, append_only=True
    ),
    TablePolicy("deletion_requests", TableScope.TENANT, uuid7_id=True),
    TablePolicy("deletion_receipts", TableScope.TENANT, uuid7_id=True),
    TablePolicy("deletion_tombstones", TableScope.TENANT, uuid7_id=True),
    TablePolicy(
        "legal_holds", TableScope.TENANT, uuid7_id=True, append_only=True
    ),
)

TABLE_BY_NAME: Final = MappingProxyType(
    {policy.name: policy for policy in TABLE_POLICIES}
)
GLOBAL_TABLES: Final = tuple(
    policy.name for policy in TABLE_POLICIES if policy.scope is TableScope.GLOBAL
)
TENANT_TABLE_POLICIES: Final = tuple(
    policy for policy in TABLE_POLICIES if policy.scope is TableScope.TENANT
)
TENANT_TABLES: Final = tuple(policy.name for policy in TENANT_TABLE_POLICIES)
APPEND_ONLY_TABLES: Final = tuple(
    policy.name for policy in TABLE_POLICIES if policy.append_only
)
UUID7_ID_TABLES: Final = tuple(
    policy.name for policy in TABLE_POLICIES if policy.uuid7_id
)


def _validate_inventory() -> None:
    names = tuple(policy.name for policy in TABLE_POLICIES)
    if (
        len(names) != len(set(names))
        or len(TABLE_BY_NAME) != len(TABLE_POLICIES)
        or any(
            policy.requester_column is not None
            and policy.scope is not TableScope.TENANT
            for policy in TABLE_POLICIES
        )
    ):
        message = "schema inventory is internally inconsistent"
        raise RuntimeError(message)


_validate_inventory()
