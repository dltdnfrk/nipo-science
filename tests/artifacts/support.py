from datetime import UTC, datetime, timedelta
from typing import final
from uuid import UUID

from services.api.artifacts import (
    ArtifactScope,
    ArtifactService,
    InMemoryArtifactStore,
    OutputWatcher,
)

ORG_A = UUID("018f47a0-7b9c-7a01-8def-0123456789ab")
ORG_B = UUID("018f47a0-7b9c-7b01-8def-0123456789ab")
PROJECT_A = UUID("018f47a0-7b9c-7a03-8def-0123456789ab")
PROJECT_B = UUID("018f47a0-7b9c-7b03-8def-0123456789ab")
USER_A = UUID("018f47a0-7b9c-7a02-8def-0123456789ab")
USER_B = UUID("018f47a0-7b9c-7b02-8def-0123456789ab")
USER_C = UUID("018f47a0-7b9c-7a05-8def-0123456789ab")
SESSION_A = UUID("018f47a0-7b9c-7a30-8def-0123456789ab")
SESSION_B = UUID("018f47a0-7b9c-7b30-8def-0123456789ab")
EXECUTION_A = UUID("018f47a0-7b9c-7a40-8def-0123456789ab")
EXECUTION_B = UUID("018f47a0-7b9c-7b40-8def-0123456789ab")
RUNTIME_CONNECTION = UUID("018f47a0-7b9c-7a41-8def-0123456789ab")
SCOPE_A = ArtifactScope(org_id=ORG_A, project_id=PROJECT_A, requester_id=USER_A)
SCOPE_B = ArtifactScope(org_id=ORG_B, project_id=PROJECT_B, requester_id=USER_B)
SCOPE_C = ArtifactScope(org_id=ORG_A, project_id=PROJECT_A, requester_id=USER_C)
SHA_A = "a" * 64
SHA_B = "b" * 64


@final
class FixedClock:
    def __init__(self) -> None:
        self._current = datetime(2026, 7, 13, 6, tzinfo=UTC)

    def now(self) -> datetime:
        return self._current

    def advance(self, delta: timedelta) -> None:
        self._current += delta


@final
class SequenceIds:
    def __init__(self, values: tuple[UUID, ...]) -> None:
        self._values = iter(values)

    def new_uuid7(self) -> UUID:
        return next(self._values)


def artifact_ids(start: int, count: int) -> tuple[UUID, ...]:
    return tuple(
        UUID(f"018f47a0-7b9c-7c{start + offset:02x}-8def-0123456789ab")
        for offset in range(count)
    )


def build_service() -> tuple[
    ArtifactService,
    InMemoryArtifactStore,
    OutputWatcher,
    FixedClock,
]:
    clock = FixedClock()
    store = InMemoryArtifactStore(
        projects=frozenset({(ORG_A, PROJECT_A), (ORG_B, PROJECT_B)}),
        sessions=frozenset(
            {
                (ORG_A, PROJECT_A, SESSION_A),
                (ORG_B, PROJECT_B, SESSION_B),
            }
        ),
    )
    watcher = OutputWatcher(
        ids=SequenceIds(artifact_ids(80, 12)),
        executions=frozenset(
            {
                (
                    ORG_A,
                    PROJECT_A,
                    USER_A,
                    EXECUTION_A,
                    "openai_codex",
                    RUNTIME_CONNECTION,
                ),
                (
                    ORG_B,
                    PROJECT_B,
                    USER_B,
                    EXECUTION_B,
                    "openai_codex",
                    RUNTIME_CONNECTION,
                ),
            }
        ),
    )
    service = ArtifactService(
        store=store,
        watcher=watcher,
        ids=SequenceIds(artifact_ids(100, 24)),
        clock=clock,
        download_signing_key=bytes(range(32)),
    )
    return service, store, watcher, clock
