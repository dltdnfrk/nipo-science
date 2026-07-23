"""One-shot provider cleanup process with an external vault boundary."""

from __future__ import annotations

import argparse
import json
import os
import sys
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Final

from sqlalchemy.engine import make_url
from sqlalchemy.exc import ArgumentError

from services.api.provider_cleanup_postgres import PostgresProviderCleanupSweeper
from services.api.provider_runtime import ProviderRuntimeError
from services.api.provider_uds import (
    ProviderUdsClientConfig,
    ProviderUdsError,
    provider_uds_request,
)

if TYPE_CHECKING:
    from collections.abc import Mapping, Sequence

_ERROR_CLEANUP: Final = "provider_cleanup_failed"
_DATABASE_URL: Final = "PROVIDER_CLEANUP_DATABASE_URL"
_EXPECTED_LOGIN: Final = "PROVIDER_CLEANUP_EXPECTED_LOGIN_ROLE"
_VAULT_SOCKET: Final = "PROVIDER_CLEANUP_VAULT_SOCKET"
_PROTOCOL_VERSION: Final = 1
_DESTROY_OPERATION: Final = "destroy_provider_runtime_home"


class CleanupCliError(RuntimeError):
    """Stable non-disclosing process-boundary failure."""

    def __init__(self) -> None:
        """Avoid disclosing database or vault connection details."""
        super().__init__(_ERROR_CLEANUP)


@dataclass(frozen=True, slots=True)
class ProviderCleanupProcessConfig:
    """Validated deployment authorities for one cleanup process."""

    service_database_url: str = field(repr=False, compare=False)
    expected_login_role: str
    vault_socket: Path

    @classmethod
    def from_environment(
        cls, environment: Mapping[str, str]
    ) -> ProviderCleanupProcessConfig:
        """Parse the three mandatory deployment-owned authorities."""
        try:
            database_url = environment[_DATABASE_URL]
            expected_login = environment[_EXPECTED_LOGIN]
            vault_socket = Path(environment[_VAULT_SOCKET])
            parsed_url = make_url(database_url)
        except (ArgumentError, KeyError, ValueError) as error:
            raise CleanupCliError from error
        if (
            parsed_url.drivername != "postgresql+asyncpg"
            or parsed_url.username is None
            or parsed_url.password is None
            or not expected_login
            or expected_login != expected_login.strip()
            or not vault_socket.is_absolute()
        ):
            raise CleanupCliError
        return cls(database_url, expected_login, vault_socket)


@dataclass(frozen=True, slots=True)
class UnixSocketRuntimeHomeDestroyer:
    """Request idempotent destruction from the deployment vault service."""

    socket_path: Path

    def destroy(self, opaque_ref: str) -> str:
        """Exchange one strict request/response over a protected Unix socket."""
        try:
            response = provider_uds_request(
                ProviderUdsClientConfig(self.socket_path),
                {
                    "schema_version": _PROTOCOL_VERSION,
                    "operation": _DESTROY_OPERATION,
                    "runtime_home_ref": opaque_ref,
                },
            )
        except ProviderUdsError as error:
            raise CleanupCliError from error
        if (
            set(response) != {"schema_version", "evidence_sha256"}
            or response.get("schema_version") != _PROTOCOL_VERSION
        ):
            raise CleanupCliError
        evidence = response.get("evidence_sha256")
        if not isinstance(evidence, str):
            raise CleanupCliError
        return evidence


def main(
    arguments: Sequence[str] | None = None,
    environment: Mapping[str, str] | None = None,
) -> int:
    """Run one bounded sweep and emit only machine-readable counters."""
    parser = argparse.ArgumentParser()
    _ = parser.parse_args(arguments)
    try:
        config = ProviderCleanupProcessConfig.from_environment(
            os.environ if environment is None else environment
        )
        result = PostgresProviderCleanupSweeper(
            config.service_database_url,
            UnixSocketRuntimeHomeDestroyer(config.vault_socket),
            clock=_utc_now,
            expected_login_role=config.expected_login_role,
        ).sweep_due_cleanups()
    except (CleanupCliError, ProviderRuntimeError):
        _ = sys.stderr.write(f"{_ERROR_CLEANUP}\n")
        return 2
    _ = sys.stdout.write(
        json.dumps(
            {
                "scanned": result.scanned,
                "completed": result.completed,
                "failed": result.failed,
            },
            separators=(",", ":"),
            sort_keys=True,
        )
        + "\n"
    )
    return int(result.failed > 0)


def _utc_now() -> datetime:
    return datetime.now(tz=UTC)


if __name__ == "__main__":
    raise SystemExit(main())
