from __future__ import annotations

from typing import TYPE_CHECKING

import services.api.provider_qualification as qualification_facade
import services.api.provider_run_dispatch as dispatch_facade
from services.api.provider_qualification_adopter import (
    QualificationAdopterServerConfig,
)
from services.api.provider_qualification_json import (
    JsonObject,
    JsonValue,
    QualificationValidationError,
)
from services.api.provider_qualification_profile import (
    AttemptObservation,
    CleanupReceipt,
    OAuthAttestation,
    ProtocolEvent,
    QualificationProfile,
    SessionObservation,
    parse_profile_json,
)
from services.api.provider_run_dispatch_contracts import (
    DispatchedProviderRun,
    ProviderRunDispatcher,
    ProviderRunDispatchError,
    ProviderRunDispatchRequest,
)
from services.api.provider_run_dispatch_postgres import (
    PostgresProviderRunDispatcher,
)
from services.api.provider_run_dispatch_service import (
    ProviderRunDispatchServerConfig,
)
from services.api.provider_runtime_contracts import ProviderRuntimeIdentity

if TYPE_CHECKING:
    from pathlib import Path


def test_qualification_facade_reexports_exact_profile_objects() -> None:
    assert qualification_facade.JsonObject is JsonObject
    assert qualification_facade.JsonValue is JsonValue
    assert qualification_facade.QualificationValidationError is (
        QualificationValidationError
    )
    assert qualification_facade.OAuthAttestation is OAuthAttestation
    assert qualification_facade.ProtocolEvent is ProtocolEvent
    assert qualification_facade.AttemptObservation is AttemptObservation
    assert qualification_facade.SessionObservation is SessionObservation
    assert qualification_facade.CleanupReceipt is CleanupReceipt
    assert qualification_facade.QualificationProfile is QualificationProfile
    assert qualification_facade.parse_profile_json is parse_profile_json


def test_dispatch_facade_reexports_exact_contract_and_postgres_objects() -> None:
    assert dispatch_facade.ProviderRunDispatchError is ProviderRunDispatchError
    assert dispatch_facade.ProviderRunDispatchRequest is ProviderRunDispatchRequest
    assert dispatch_facade.DispatchedProviderRun is DispatchedProviderRun
    assert dispatch_facade.ProviderRunDispatcher is ProviderRunDispatcher
    assert dispatch_facade.PostgresProviderRunDispatcher is (
        PostgresProviderRunDispatcher
    )


def test_provider_service_config_reprs_omit_database_credentials(
    tmp_path: Path,
) -> None:
    dsn = "postgresql+asyncpg://provider:password-value@db.internal/workbench"
    adopter = QualificationAdopterServerConfig(
        tmp_path / "provider-adopter.sock",
        dsn,
        "provider_adopter_login",
        tmp_path / "provider-authority-keys.json",
        "a" * 64,
        "active-key",
    )
    dispatcher = ProviderRunDispatchServerConfig(
        tmp_path / "provider-dispatch.sock",
        dsn,
        "provider_dispatch_login",
        tmp_path / "provider-authority-keys.json",
        "a" * 64,
        ProviderRuntimeIdentity("openai_codex", "codex-cli-1", "b" * 64),
    )

    assert dsn not in repr(adopter)
    assert dsn not in repr(dispatcher)
    assert "password-value" not in repr(adopter)
    assert "password-value" not in repr(dispatcher)
