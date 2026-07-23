from datetime import UTC, datetime
from pathlib import Path
from stat import S_IMODE
from typing import Final, final
from uuid import UUID

import pytest

from services.api.artifacts.composition import (
    ArtifactProductionConfig,
    compose_artifact_production,
)
from services.api.artifacts.models import ArtifactScope, VersionDraft
from services.api.tests.persistence.postgres_harness import database_url_asyncpg, psql
from services.api.tests.persistence.test_rls import ORG_A, PROJECT_A, USER_A
from services.api.tests.persistence.test_rls_contracts import (
    EXECUTION,
    PROVIDER,
    SHA,
    seed_artifact_version,
)

pytestmark = pytest.mark.usefixtures("migrated_database")
RECOVERY_KEY: Final = b"recovery-integrity-domain-key!" + bytes((0, 1, 2))
DOWNLOAD_KEY: Final = b"download-signing-domain-key!!!!" + bytes((3, 4, 5))
FIXED_NOW: Final = datetime(2026, 7, 15, 3, 30, tzinfo=UTC)
SCOPE: Final = ArtifactScope(
    org_id=UUID(ORG_A),
    project_id=UUID(PROJECT_A),
    requester_id=UUID(USER_A),
)


@final
class FixedClock:
    def now(self) -> datetime:
        return FIXED_NOW


@final
class SequenceUuid7Factory:
    def __init__(self, values: tuple[UUID, ...]) -> None:
        self._values = iter(values)

    def new_uuid7(self) -> UUID:
        return next(self._values)


def uuid7_values(start: int, count: int) -> tuple[UUID, ...]:
    return tuple(
        UUID(f"018f47a0-7b9c-7c{start + offset:02x}-8def-0123456789ab")
        for offset in range(count)
    )


def production_config(root: Path) -> ArtifactProductionConfig:
    return ArtifactProductionConfig.model_validate(
        {
            "database_url": database_url_asyncpg(),
            "private_blob_root": root / "blobs",
            "recovery_root": root / "recovery",
            "recovery_integrity_key": RECOVERY_KEY,
            "download_signing_key": DOWNLOAD_KEY,
            "trusted_executions": frozenset(
                {
                    (
                        SCOPE.org_id,
                        SCOPE.project_id,
                        SCOPE.requester_id,
                        UUID(EXECUTION),
                        "openai_codex",
                        UUID(PROVIDER),
                    )
                }
            ),
        }
    )


def version_draft(artifact_id: UUID, reference: str) -> VersionDraft:
    return VersionDraft(
        artifact_id=artifact_id,
        base_version_no=0,
        watcher_reference=reference,
        producing_execution_id=UUID(EXECUTION),
        environment_sha256=SHA,
        code_sha256="b" * 64,
        runtime_adapter_id="openai_codex",
        runtime_connection_id=UUID(PROVIDER),
        skill_content_hashes=(SHA,),
        source_hashes=("b" * 64,),
        input_version_ids=(),
    )


def test_production_composition_injects_clock_uuid7_and_private_roots(
    tmp_path: Path,
) -> None:
    # Given: a migrated tenant graph and explicit deterministic dependencies.
    seed_artifact_version()
    identifiers = uuid7_values(32, 16)
    config = production_config(tmp_path)
    stack = compose_artifact_production(
        config,
        clock=FixedClock(),
        uuid7_factory=SequenceUuid7Factory(identifiers),
    )

    # When: the composed core creates one Artifact.
    artifact = stack.service.create_artifact(SCOPE, "Production composition")

    # Then: caller-owned time/identity and private durable roots are observable.
    assert artifact.id == identifiers[0]
    assert artifact.created_at == FIXED_NOW
    assert S_IMODE((tmp_path / "blobs").stat().st_mode) == 0o700
    assert S_IMODE((tmp_path / "recovery").stat().st_mode) == 0o700
    assert S_IMODE((tmp_path / "recovery" / "records").stat().st_mode) == 0o700


def test_production_composition_reuses_durable_authorities_across_recomposition(
    tmp_path: Path,
) -> None:
    # Given: one real PostgreSQL graph and stable blob/recovery/key authorities.
    seed_artifact_version()
    config = production_config(tmp_path)
    first = compose_artifact_production(
        config,
        clock=FixedClock(),
        uuid7_factory=SequenceUuid7Factory(uuid7_values(64, 24)),
    )
    artifact = first.service.create_artifact(SCOPE, "Recomposition proof")
    reference = first.watcher.register(
        SCOPE,
        UUID(EXECUTION),
        b"durable production bytes",
        "text/plain",
    )
    draft = version_draft(artifact.id, reference)
    committed = first.service.create_version(SCOPE, draft)

    # When: every adapter/service object is reconstructed over the same authorities.
    recomposed = compose_artifact_production(
        config,
        clock=FixedClock(),
        uuid7_factory=SequenceUuid7Factory(uuid7_values(96, 24)),
    )
    replayed = recomposed.service.create_version(SCOPE, draft)
    payload = recomposed.service.read_content(SCOPE, committed.id)
    persisted_count = psql(
        "SELECT count(*) FROM artifact_versions WHERE artifact_id = "
        f"'{artifact.id}'"
    ).stdout.strip()

    # Then: recovery is idempotent and PostgreSQL retains one exact Version.
    assert replayed == committed
    assert replayed.id == committed.id
    assert payload == b"durable production bytes"
    assert persisted_count == "1"
