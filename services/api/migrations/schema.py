from services.api.migrations.schema_artifacts import (
    drop_artifacts,
    upgrade_artifacts,
)
from services.api.migrations.schema_executions import (
    drop_executions,
    upgrade_executions,
)
from services.api.migrations.schema_governance import (
    drop_governance,
    upgrade_governance,
)
from services.api.migrations.schema_identity import drop_identity, upgrade_identity
from services.api.migrations.schema_reviews import drop_reviews, upgrade_reviews
from services.api.migrations.schema_runs import drop_runs, upgrade_runs
from services.api.migrations.schema_workspace import (
    drop_workspace,
    upgrade_workspace,
)


def upgrade_schema() -> None:
    upgrade_identity()
    upgrade_workspace()
    upgrade_runs()
    upgrade_executions()
    upgrade_artifacts()
    upgrade_reviews()
    upgrade_governance()


def drop_schema() -> None:
    drop_governance()
    drop_reviews()
    drop_artifacts()
    drop_executions()
    drop_runs()
    drop_workspace()
    drop_identity()
