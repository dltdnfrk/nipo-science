"""Production process composition for durable authenticated Artifact HTTP routes."""

from __future__ import annotations

import base64
import binascii
import ipaddress
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, ClassVar, Final, Self
from urllib.parse import urlsplit

from pydantic import UUID7, BaseModel, ConfigDict, TypeAdapter, ValidationError

from services.api.artifacts.composition import (
    ArtifactProductionConfig,
    ArtifactProductionConfigError,
    ArtifactProductionStack,
    TrustedExecution,
    compose_artifact_production,
)
from services.api.artifacts.http import ArtifactHttpService
from services.api.artifacts.runtime import SystemClock, Uuid7Factory
from services.api.artifacts.scope_resolver import PostgresArtifactScopeResolver
from services.api.persistence.auth_sessions import PostgresSessionAuthority
from services.api.product_app import ProductServer, ProductServerOptions
from services.api.provider_run_dispatch_service import UnixSocketProviderRunDispatcher
from services.api.provider_uds import ProviderUdsClientConfig, ProviderUdsError

MAX_TCP_PORT: Final = 65535

if TYPE_CHECKING:
    from collections.abc import Mapping

    from services.api.artifacts.models import Clock, IdFactory


class ArtifactProductionAppConfigError(ValueError):
    """Reject incomplete or ambiguous deployment-owned HTTP configuration."""


class _TrustedExecutionInput(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(extra="forbid")

    org_id: UUID7
    project_id: UUID7
    requester_id: UUID7
    execution_id: UUID7
    runtime_adapter_id: str
    runtime_connection_id: UUID7

    def as_tuple(self) -> TrustedExecution:
        return (
            self.org_id,
            self.project_id,
            self.requester_id,
            self.execution_id,
            self.runtime_adapter_id,
            self.runtime_connection_id,
        )


_TRUSTED_EXECUTIONS = TypeAdapter(tuple[_TrustedExecutionInput, ...])


@dataclass(frozen=True, slots=True)
class ArtifactProductionAppConfig:
    """Validated durable core, listener, and public-origin authorities."""

    artifact: ArtifactProductionConfig
    bind_host: str
    bind_port: int
    public_origin: str
    provider_run_dispatch_socket: Path

    @classmethod
    def from_environment(cls, values: Mapping[str, str]) -> Self:
        """Parse the deployment allowlist while sanitizing every rejection."""
        try:
            database_url = _required(values, "ARTIFACT_DATABASE_URL")
            private_blob_root = Path(_required(values, "ARTIFACT_PRIVATE_BLOB_ROOT"))
            recovery_root = Path(_required(values, "ARTIFACT_RECOVERY_ROOT"))
            recovery_key = _decode_key(
                _required(values, "ARTIFACT_RECOVERY_INTEGRITY_KEY_B64")
            )
            download_key = _decode_key(
                _required(values, "ARTIFACT_DOWNLOAD_SIGNING_KEY_B64")
            )
            trusted_values = _TRUSTED_EXECUTIONS.validate_python(
                json.loads(_required(values, "ARTIFACT_TRUSTED_EXECUTIONS_JSON"))
            )
            bind_host = _bind_host(_required(values, "ARTIFACT_BIND_HOST"))
            bind_port = _bind_port(_required(values, "ARTIFACT_BIND_PORT"))
            public_origin = _public_origin(_required(values, "ARTIFACT_PUBLIC_ORIGIN"))
            provider_run_dispatch_socket = _absolute_socket_path(
                _required(values, "PROVIDER_RUN_DISPATCH_SOCKET")
            )
            _ = ProviderUdsClientConfig(provider_run_dispatch_socket)
            artifact = ArtifactProductionConfig.model_validate(
                {
                    "database_url": database_url,
                    "private_blob_root": private_blob_root,
                    "recovery_root": recovery_root,
                    "recovery_integrity_key": recovery_key,
                    "download_signing_key": download_key,
                    "trusted_executions": frozenset(
                        item.as_tuple() for item in trusted_values
                    ),
                }
            )
        except (
            ArtifactProductionConfigError,
            binascii.Error,
            json.JSONDecodeError,
            KeyError,
            UnicodeEncodeError,
            ValidationError,
            ValueError,
            ProviderUdsError,
        ):
            parsed = None
        else:
            parsed = cls(
                artifact,
                bind_host,
                bind_port,
                public_origin,
                provider_run_dispatch_socket,
            )
        if parsed is None:
            raise ArtifactProductionAppConfigError
        return parsed


@dataclass(frozen=True, slots=True)
class ArtifactProductionApplication:
    """Expose the composed server, domain stack, and output-registration scope."""

    server: ProductServer
    stack: ArtifactProductionStack
    artifact_http: ArtifactHttpService


def build_artifact_production_application(
    environment: Mapping[str, str],
    *,
    clock: Clock | None = None,
    uuid7_factory: IdFactory | None = None,
) -> ArtifactProductionApplication:
    """Build one authenticated production server from deployment authorities."""
    config = ArtifactProductionAppConfig.from_environment(environment)
    runtime_clock = clock or SystemClock()
    runtime_ids = uuid7_factory or Uuid7Factory()
    stack = compose_artifact_production(
        config.artifact,
        clock=runtime_clock,
        uuid7_factory=runtime_ids,
    )
    database_url = config.artifact.database_url.get_secret_value()
    artifact_http = ArtifactHttpService(
        stack.service,
        PostgresArtifactScopeResolver(database_url),
    )
    server = ProductServer(
        (config.bind_host, config.bind_port),
        runtime_clock.now,
        ProductServerOptions(
            public_origin=config.public_origin,
            session_authority=PostgresSessionAuthority(database_url),
            artifact_http=artifact_http,
            provider_run_dispatcher=UnixSocketProviderRunDispatcher(
                ProviderUdsClientConfig(config.provider_run_dispatch_socket)
            ),
            uuid7_factory=runtime_ids,
        ),
    )
    return ArtifactProductionApplication(server, stack, artifact_http)


def main() -> None:
    """Run the durable Artifact HTTP process until operator shutdown."""
    application = build_artifact_production_application(os.environ)
    with application.server:
        application.server.serve_forever()


def _required(values: Mapping[str, str], name: str) -> str:
    value = values[name]
    if not value or value != value.strip():
        raise ArtifactProductionAppConfigError
    return value


def _decode_key(value: str) -> bytes:
    return base64.b64decode(value.encode("ascii"), validate=True)


def _bind_host(value: str) -> str:
    address = ipaddress.ip_address(value)
    if str(address) != value:
        raise ArtifactProductionAppConfigError
    return value


def _bind_port(value: str) -> int:
    port = int(value)
    if not 1 <= port <= MAX_TCP_PORT or str(port) != value:
        raise ArtifactProductionAppConfigError
    return port


def _public_origin(value: str) -> str:
    parsed = urlsplit(value)
    port = parsed.port
    hostname = parsed.hostname
    if (
        parsed.scheme not in {"http", "https"}
        or hostname is None
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
    ):
        raise ArtifactProductionAppConfigError
    ascii_hostname = hostname.encode("idna").decode("ascii")
    host = f"[{ascii_hostname}]" if ":" in ascii_hostname else ascii_hostname
    default_port = 80 if parsed.scheme == "http" else 443
    authority = host if port in {None, default_port} else f"{host}:{port}"
    if value != f"{parsed.scheme}://{authority}":
        raise ArtifactProductionAppConfigError
    if parsed.scheme == "http" and not _loopback_hostname(hostname):
        raise ArtifactProductionAppConfigError
    return value


def _absolute_socket_path(value: str) -> Path:
    path = Path(value)
    if (
        not value
        or value != value.strip()
        or not path.is_absolute()
        or not path.name
        or any(component in {".", ".."} for component in path.parts[1:])
    ):
        raise ArtifactProductionAppConfigError
    return path


def _loopback_hostname(hostname: str) -> bool:
    if hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(hostname).is_loopback
    except ValueError:
        return False


if __name__ == "__main__":
    main()
