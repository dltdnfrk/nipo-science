from datetime import UTC, datetime, timedelta
from pathlib import Path

from science_workbench_contracts.protocols.fixture import ProtocolFixture
from science_workbench_contracts.protocols.models import (
    ExecutionRecord,
    ExecutionStatus,
    RunAggregate,
    RunStatus,
)

FIXTURE_PATH = Path(__file__).parents[2] / "fixtures" / "run-runtime-protocol.json"
NOW = datetime(2026, 7, 13, 10, 0, 10, tzinfo=UTC)


def protocol_fixture() -> ProtocolFixture:
    return ProtocolFixture.model_validate_json(FIXTURE_PATH.read_text(encoding="utf-8"))


def run_aggregate(status: RunStatus) -> RunAggregate:
    fixture = protocol_fixture()
    run = fixture.run.model_copy(update={"status": status})
    return RunAggregate(run=run)


def execution(status: ExecutionStatus, attempt_token: int = 2) -> ExecutionRecord:
    fixture = protocol_fixture()
    return fixture.execution.model_copy(
        update={
            "status": status,
            "attempt_token": attempt_token,
            "result_ref": "artifact-version:1" if status == "completed" else None,
        }
    )


def later(seconds: int) -> datetime:
    return NOW + timedelta(seconds=seconds)
