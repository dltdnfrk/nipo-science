"""Production-only composition root for the durable Artifact core."""

import hmac
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Annotated, ClassVar, Final, Self
from uuid import UUID

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    SecretBytes,
    SecretStr,
    ValidationError,
    field_validator,
    model_validator,
)
from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from .blob_store import PrivateBlobStore
from .file_recovery import FileArtifactRecovery
from .models import Clock, IdFactory, Uuid7
from .postgres_store import PostgresArtifactStore
from .service import ArtifactService
from .watcher import OutputWatcher

TrustedRuntimeAdapterId = Annotated[str, Field(min_length=1, max_length=255)]
type TrustedExecution = tuple[
    Uuid7,
    Uuid7,
    Uuid7,
    Uuid7,
    TrustedRuntimeAdapterId,
    Uuid7,
]
type TrustedExecutionKey = tuple[UUID, UUID, UUID, UUID]
type ArtifactProductionConfigValue = str | Path | bytes | frozenset[TrustedExecution]
MAX_TCP_PORT: Final = 65535


class ArtifactProductionConfigError(ValueError):
    """Reject unsafe or ambiguous durable Artifact authority configuration."""


class _ArtifactProductionConfigValues(BaseModel):
    """Validate raw production configuration before public construction."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
        hide_input_in_errors=True,
    )

    database_url: SecretStr = Field(min_length=1)
    private_blob_root: Path
    recovery_root: Path
    recovery_integrity_key: SecretBytes = Field(min_length=32)
    download_signing_key: SecretBytes = Field(min_length=32)
    trusted_executions: frozenset[TrustedExecution] = Field(min_length=1)

    @field_validator("database_url")
    @classmethod
    def require_asyncpg_postgresql(cls, value: SecretStr) -> SecretStr:
        """Accept only an explicit SQLAlchemy asyncpg PostgreSQL URL."""
        try:
            parsed = make_url(value.get_secret_value())
            port = parsed.port
        except (ArgumentError, ValueError):
            raise ArtifactProductionConfigError from None
        if (
            parsed.drivername != "postgresql+asyncpg"
            or not parsed.database
            or (port is not None and not 1 <= port <= MAX_TCP_PORT)
        ):
            raise ArtifactProductionConfigError
        return value

    @field_validator("private_blob_root", "recovery_root")
    @classmethod
    def require_absolute_storage_root(cls, value: Path) -> Path:
        """Reject process-directory-dependent durable storage roots."""
        if not value.is_absolute():
            raise ArtifactProductionConfigError
        return value

    @model_validator(mode="after")
    def require_separate_unambiguous_authorities(self) -> Self:
        """Keep storage, secrets, and execution bindings in separate domains."""
        blob_root = self.private_blob_root.resolve()
        recovery_root = self.recovery_root.resolve()
        if (
            blob_root == recovery_root
            or blob_root in recovery_root.parents
            or recovery_root in blob_root.parents
        ):
            raise ArtifactProductionConfigError
        recovery_key = self.recovery_integrity_key.get_secret_value()
        download_key = self.download_signing_key.get_secret_value()
        if hmac.compare_digest(recovery_key, download_key):
            raise ArtifactProductionConfigError
        bindings: dict[TrustedExecutionKey, tuple[str, UUID]] = {}
        for (
            org_id,
            project_id,
            requester_id,
            execution_id,
            runtime_adapter_id,
            runtime_connection_id,
        ) in self.trusted_executions:
            if (
                not runtime_adapter_id
                or runtime_adapter_id != runtime_adapter_id.strip()
            ):
                raise ArtifactProductionConfigError
            key = (org_id, project_id, requester_id, execution_id)
            binding = (runtime_adapter_id, runtime_connection_id)
            previous = bindings.setdefault(key, binding)
            if previous != binding:
                raise ArtifactProductionConfigError
        return self


@dataclass(frozen=True, slots=True, init=False)
class ArtifactProductionConfig:
    """Expose only validated secrets and authorities with sanitized failures."""

    database_url: SecretStr
    private_blob_root: Path
    recovery_root: Path
    recovery_integrity_key: SecretBytes
    download_signing_key: SecretBytes
    trusted_executions: frozenset[TrustedExecution]

    def __init__(self) -> None:
        """Reject construction that bypasses the trusted parser."""
        raise ArtifactProductionConfigError

    @classmethod
    def model_validate(
        cls,
        values: Mapping[str, ArtifactProductionConfigValue],
    ) -> Self:
        """Parse raw values while exposing no rejected input in errors."""
        try:
            parsed = _ArtifactProductionConfigValues.model_validate(values)
        except ValidationError:
            parsed = None
        if parsed is None:
            raise ArtifactProductionConfigError
        instance = cls.__new__(cls)
        object.__setattr__(instance, "database_url", parsed.database_url)
        object.__setattr__(
            instance,
            "private_blob_root",
            parsed.private_blob_root,
        )
        object.__setattr__(instance, "recovery_root", parsed.recovery_root)
        object.__setattr__(
            instance,
            "recovery_integrity_key",
            parsed.recovery_integrity_key,
        )
        object.__setattr__(
            instance,
            "download_signing_key",
            parsed.download_signing_key,
        )
        object.__setattr__(
            instance,
            "trusted_executions",
            parsed.trusted_executions,
        )
        return instance


@dataclass(frozen=True, slots=True)
class ArtifactProductionStack:
    """Expose one service and its exact trusted output-registration boundary."""

    service: ArtifactService
    watcher: OutputWatcher


def compose_artifact_production(
    config: ArtifactProductionConfig,
    *,
    clock: Clock,
    uuid7_factory: IdFactory,
) -> ArtifactProductionStack:
    """Build the durable core from explicit production-owned dependencies."""
    blobs = PrivateBlobStore(config.private_blob_root)
    store = PostgresArtifactStore(config.database_url.get_secret_value(), blobs)
    recovery = FileArtifactRecovery(
        config.recovery_root,
        integrity_key=config.recovery_integrity_key.get_secret_value(),
    )
    watcher = OutputWatcher(
        ids=uuid7_factory,
        executions=config.trusted_executions,
        recovery=recovery,
    )
    service = ArtifactService(
        store=store,
        watcher=watcher,
        ids=uuid7_factory,
        clock=clock,
        download_signing_key=config.download_signing_key.get_secret_value(),
    )
    return ArtifactProductionStack(service=service, watcher=watcher)
