"""Structured observability metadata allowlist and redaction gate."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import ClassVar, Final, override

from pydantic import BaseModel, ConfigDict, Field

type MetadataValue = str | int | float | bool

SECRET_PATTERN: Final = re.compile(
    r"(?i)(bearer\s+\S+|sk-[a-z0-9_-]{8,}|api[_-]?key|refresh[_-]?token|authorization)"
)


class ObservabilityEvent(BaseModel):
    """Parsed structured event at the observability boundary."""

    model_config: ClassVar[ConfigDict] = ConfigDict(frozen=True, extra="forbid")

    name: str = Field(min_length=1, max_length=128)
    metadata: dict[str, MetadataValue]


@dataclass(frozen=True, slots=True)
class ObservabilityPolicy:
    """Metadata keys permitted to leave the application."""

    allowed_metadata: frozenset[str]

    @classmethod
    def default(cls) -> ObservabilityPolicy:
        """Build the normative metadata allowlist."""
        return cls(
            frozenset(
                {
                    "artifact_id",
                    "connection_id",
                    "error_code",
                    "latency_ms",
                    "org_id",
                    "request_id",
                    "run_id",
                    "status",
                    "trace_id",
                }
            )
        )


@dataclass(frozen=True, slots=True)
class UnknownMetadataError(Exception):
    """Rejects fields outside the explicit allowlist."""

    keys: tuple[str, ...]

    @override
    def __str__(self) -> str:
        """List fields rejected by the allowlist."""
        return f"metadata keys are not allowlisted: {', '.join(self.keys)}"


@dataclass(frozen=True, slots=True)
class PlaintextSecretError(Exception):
    """Rejects secret-shaped values before export."""

    key: str

    @override
    def __str__(self) -> str:
        """Identify the field containing secret-shaped text."""
        return f"metadata field {self.key} contains secret-shaped plaintext"


def validate_event(
    policy: ObservabilityPolicy,
    event: ObservabilityEvent,
) -> ObservabilityEvent:
    """Enforce allowlisted keys and secret-free values."""
    unknown = tuple(sorted(set(event.metadata) - policy.allowed_metadata))
    if unknown:
        raise UnknownMetadataError(unknown)
    for key, value in event.metadata.items():
        if isinstance(value, str) and SECRET_PATTERN.search(value):
            raise PlaintextSecretError(key)
    return event
