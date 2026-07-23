from importlib import import_module
from importlib.util import find_spec
from pathlib import Path
from typing import Final
from uuid import UUID

import pytest

from services.api.artifacts.composition import (
    ArtifactProductionConfig,
    ArtifactProductionConfigError,
    TrustedExecution,
)

ORG_ID: Final = UUID("018f47a0-7b9c-7a01-8def-0123456789ab")
PROJECT_ID: Final = UUID("018f47a0-7b9c-7a02-8def-0123456789ab")
REQUESTER_ID: Final = UUID("018f47a0-7b9c-7a03-8def-0123456789ab")
EXECUTION_ID: Final = UUID("018f47a0-7b9c-7a04-8def-0123456789ab")
CONNECTION_ID: Final = UUID("018f47a0-7b9c-7a05-8def-0123456789ab")
TRUSTED_EXECUTION: Final[TrustedExecution] = (
    ORG_ID,
    PROJECT_ID,
    REQUESTER_ID,
    EXECUTION_ID,
    "openai_codex",
    CONNECTION_ID,
)
type ConfigValue = str | Path | bytes | frozenset[TrustedExecution]


def production_config_values(tmp_path: Path) -> dict[str, ConfigValue]:
    return {
        "database_url": "postgresql+asyncpg://app:secret@127.0.0.1/workbench",
        "private_blob_root": tmp_path / "blobs",
        "recovery_root": tmp_path / "recovery",
        "recovery_integrity_key": b"r" * 32,
        "download_signing_key": b"d" * 32,
        "trusted_executions": frozenset({TRUSTED_EXECUTION}),
    }


def test_production_artifact_composition_seam_exists() -> None:
    # Given: the durable Artifact adapters are available independently.
    module_name = "services.api.artifacts.composition"

    # When: production code asks for their explicit composition boundary.
    specification = find_spec(module_name)

    # Then: one importable production seam owns that wiring.
    assert specification is not None


def test_production_composition_exposes_strict_config_boundary() -> None:
    # Given: the production composition module is importable.
    module = import_module("services.api.artifacts.composition")

    # When: its public configuration boundary is inspected.
    config_type = getattr(module, "ArtifactProductionConfig", None)

    # Then: callers cannot bypass a named typed configuration model.
    assert config_type is not None


def test_production_composition_exposes_service_and_watcher_stack() -> None:
    # Given: output registration and Artifact orchestration share one authority.
    module = import_module("services.api.artifacts.composition")

    # When: the production assembly surface is inspected.
    stack_type = getattr(module, "ArtifactProductionStack", None)
    factory = getattr(module, "compose_artifact_production", None)

    # Then: callers receive both boundaries from one explicit factory.
    assert stack_type is not None
    assert callable(factory)


@pytest.mark.parametrize(
    "missing_field",
    [
        "database_url",
        "private_blob_root",
        "recovery_root",
        "recovery_integrity_key",
        "download_signing_key",
        "trusted_executions",
    ],
)
def test_production_config_rejects_every_missing_authority_input(
    tmp_path: Path,
    missing_field: str,
) -> None:
    # Given: one required production authority input is absent.
    values = production_config_values(tmp_path)
    _ = values.pop(missing_field)

    # When: the composition configuration crosses its trust boundary.
    with pytest.raises(ArtifactProductionConfigError):
        _ = ArtifactProductionConfig.model_validate(values)

    # Then: rejection occurs before either durable root is created.
    assert not (tmp_path / "blobs").exists()
    assert not (tmp_path / "recovery").exists()


@pytest.mark.parametrize(
    ("field_name", "invalid_value"),
    [
        ("database_url", ""),
        ("database_url", "sqlite:///artifact.db"),
        ("recovery_integrity_key", b"r" * 31),
        ("download_signing_key", b"d" * 31),
        ("trusted_executions", frozenset[TrustedExecution]()),
    ],
)
def test_production_config_rejects_weak_or_unsupported_authority_values(
    tmp_path: Path,
    field_name: str,
    invalid_value: ConfigValue,
) -> None:
    # Given: a complete configuration contains one weak authority value.
    values = production_config_values(tmp_path)
    values[field_name] = invalid_value

    # When: the configuration is parsed.
    with pytest.raises(ArtifactProductionConfigError):
        _ = ArtifactProductionConfig.model_validate(values)

    # Then: no storage authority has been initialized.
    assert not (tmp_path / "blobs").exists()
    assert not (tmp_path / "recovery").exists()


def test_production_config_rejects_relative_or_overlapping_storage_roots(
    tmp_path: Path,
) -> None:
    # Given: storage roots are relative or share one authority directory.
    relative = production_config_values(tmp_path)
    relative["private_blob_root"] = Path("relative-blobs")
    overlapping = production_config_values(tmp_path)
    overlapping["recovery_root"] = tmp_path / "blobs" / "recovery"

    # When: either configuration is parsed.
    with pytest.raises(ArtifactProductionConfigError):
        _ = ArtifactProductionConfig.model_validate(relative)
    with pytest.raises(ArtifactProductionConfigError):
        _ = ArtifactProductionConfig.model_validate(overlapping)

    # Then: validation remains side-effect free.
    assert not (tmp_path / "blobs").exists()
    assert not (tmp_path / "recovery").exists()


def test_production_config_rejects_shared_secret_domains(tmp_path: Path) -> None:
    # Given: recovery integrity and download signing reuse one secret.
    values = production_config_values(tmp_path)
    values["download_signing_key"] = b"r" * 32

    # When: the configuration is parsed.
    with pytest.raises(ArtifactProductionConfigError):
        _ = ArtifactProductionConfig.model_validate(values)

    # Then: domain separation fails closed before storage mutation.
    assert not (tmp_path / "blobs").exists()
    assert not (tmp_path / "recovery").exists()


@pytest.mark.parametrize(
    ("field_name", "invalid_value", "secret_marker"),
    [
        (
            "database_url",
            "postgresql+asyncpg://app:TOP-SECRET@127.0.0.1",
            "TOP-SECRET",
        ),
        ("recovery_integrity_key", b"RECOVERY-SECRET", "RECOVERY-SECRET"),
    ],
)
def test_production_config_rejection_never_exposes_secret_input(
    tmp_path: Path,
    field_name: str,
    invalid_value: ConfigValue,
    secret_marker: str,
) -> None:
    # Given: one rejected production secret contains a recognizable marker.
    values = production_config_values(tmp_path)
    values[field_name] = invalid_value

    # When: the trusted parser rejects the value.
    with pytest.raises(ArtifactProductionConfigError) as rejected:
        _ = ArtifactProductionConfig.model_validate(values)

    # Then: every public error rendering omits the secret bytes and text.
    error = rejected.value
    rendered = f"{error!s}\n{error!r}"
    assert error.__context__ is None
    assert secret_marker not in rendered


def test_production_config_rejects_invalid_tcp_port_before_storage_mutation(
    tmp_path: Path,
) -> None:
    # Given: an asyncpg URL names a TCP port outside the valid range.
    values = production_config_values(tmp_path)
    values["database_url"] = (
        "postgresql+asyncpg://app:secret@127.0.0.1:70000/workbench"
    )

    # When: the configuration boundary parses the URL.
    with pytest.raises(ArtifactProductionConfigError):
        _ = ArtifactProductionConfig.model_validate(values)

    # Then: rejection happens before either durable authority is initialized.
    assert not (tmp_path / "blobs").exists()
    assert not (tmp_path / "recovery").exists()


@pytest.mark.parametrize(
    "invalid_execution",
    [
        (
            UUID("12345678-1234-4123-8123-123456789abc"),
            PROJECT_ID,
            REQUESTER_ID,
            EXECUTION_ID,
            "openai_codex",
            CONNECTION_ID,
        ),
        (
            ORG_ID,
            PROJECT_ID,
            REQUESTER_ID,
            EXECUTION_ID,
            "x" * 256,
            CONNECTION_ID,
        ),
    ],
)
def test_production_config_rejects_binding_values_invalid_for_watcher_output(
    tmp_path: Path,
    invalid_execution: TrustedExecution,
) -> None:
    # Given: a trusted binding cannot form a valid watcher output identity.
    values = production_config_values(tmp_path)
    values["trusted_executions"] = frozenset({invalid_execution})

    # When: the production configuration is parsed.
    with pytest.raises(ArtifactProductionConfigError):
        _ = ArtifactProductionConfig.model_validate(values)

    # Then: malformed authority is rejected without durable side effects.
    assert not (tmp_path / "blobs").exists()
    assert not (tmp_path / "recovery").exists()
