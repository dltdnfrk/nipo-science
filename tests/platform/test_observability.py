from pathlib import Path
from typing import ClassVar

import pytest
from pydantic import BaseModel, ConfigDict, TypeAdapter
from tools.platform_policy.observability import (
    ObservabilityEvent,
    ObservabilityPolicy,
    PlaintextSecretError,
    UnknownMetadataError,
    validate_event,
)


class _ObservabilityDocument(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="allow", frozen=True)

    allowed_metadata: frozenset[str]


def test_security_allowlisted_metadata_is_accepted() -> None:
    # Given
    policy = ObservabilityPolicy.default()
    event = ObservabilityEvent(
        name="run.completed",
        metadata={
            "request_id": "req-1",
            "org_id": "org-1",
            "run_id": "run-1",
            "status": "completed",
            "latency_ms": 42,
        },
    )

    # When
    validated = validate_event(policy, event)

    # Then
    assert validated == event


def test_security_unknown_metadata_is_rejected() -> None:
    # Given
    event = ObservabilityEvent(
        name="run.completed",
        metadata={"request_id": "req-1", "prompt": "private research"},
    )

    # When / Then
    with pytest.raises(UnknownMetadataError, match="prompt"):
        _ = validate_event(ObservabilityPolicy.default(), event)


def test_security_plaintext_fixture_is_rejected() -> None:
    # Given
    root = Path(__file__).parent.parent
    event = TypeAdapter(ObservabilityEvent).validate_json(
        (root / "fixtures/ci/plaintext-observability.json").read_bytes()
    )

    # When / Then
    with pytest.raises(PlaintextSecretError):
        _ = validate_event(ObservabilityPolicy.default(), event)


def test_contract_documented_otel_allowlist_matches_runtime() -> None:
    # Given
    root = Path(__file__).parents[2]
    document = _ObservabilityDocument.model_validate_json(
        (root / "docs/architecture/observability.json").read_bytes()
    )

    # When
    documented = document.allowed_metadata

    # Then
    assert documented == ObservabilityPolicy.default().allowed_metadata
