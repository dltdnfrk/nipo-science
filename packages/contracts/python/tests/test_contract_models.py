from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError

from science_workbench_contracts import ContractRoundTrip
from science_workbench_contracts.auth import ProjectCreate
from science_workbench_contracts.runs import RunCreate

FIXTURE = Path(__file__).parents[2] / "fixtures" / "auth-run-artifact.json"


def test_round_trips_auth_run_artifact_fixture() -> None:
    # Given: representative JSON from authentication through a saved Artifact Version.
    raw = FIXTURE.read_text(encoding="utf-8")

    # When: Pydantic parses and serializes the shared boundary fixture.
    parsed = ContractRoundTrip.model_validate_json(raw)
    reparsed = ContractRoundTrip.model_validate_json(parsed.model_dump_json())

    # Then: semantic IDs and tenant scope survive the round trip.
    assert reparsed == parsed
    assert reparsed.run.org_id == reparsed.auth.org_id
    assert reparsed.artifact_version.producing_run_id == reparsed.run.id


@pytest.mark.parametrize("model", [ProjectCreate, RunCreate])
def test_rejects_client_supplied_org_id(
    model: type[ProjectCreate | RunCreate],
) -> None:
    # Given: a client request attempting to select its own tenant.
    fixture = (
        {"name": "forged", "org_id": "018f47a0-7b9c-7abd-8def-0123456789ab"}
        if model is ProjectCreate
        else {
            "session_id": "018f47a0-7b9c-7abf-8def-0123456789ab",
            "provider_connection_id": "018f47a0-7b9c-7ac0-8def-0123456789ab",
            "prompt": "forged",
            "org_id": "018f47a0-7b9c-7abd-8def-0123456789ab",
        }
    )

    # When/Then: strict request parsing rejects the extra authority field.
    with pytest.raises(ValidationError, match="org_id"):
        _ = model.model_validate(fixture)


def test_rejects_non_uuidv7_and_non_utc_fixture() -> None:
    # Given: a shared fixture with a UUIDv4 and offset timestamp.
    fixture = FIXTURE.read_text(encoding="utf-8").replace(
        '"018f47a0-7b9c-7abe-8def-0123456789ab"',
        '"550e8400-e29b-41d4-a716-446655440000"',
        1,
    )
    fixture = fixture.replace(
        '"2026-07-13T10:00:00Z"',
        '"2026-07-13T19:00:00+09:00"',
    )

    # When/Then: runtime parsing rejects both wire-contract violations.
    with pytest.raises(ValidationError) as captured:
        _ = ContractRoundTrip.model_validate_json(fixture)
    assert {item["type"] for item in captured.value.errors()} >= {
        "uuid7",
        "utc_timestamp",
    }
