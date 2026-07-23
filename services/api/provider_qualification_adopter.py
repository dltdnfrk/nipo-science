"""UDS client and isolated PostgreSQL service for qualification adoption."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast, final, override

from services.api.provider_qualification_adoption_protocol import (
    QualificationAdoptionCommand,
    qualification_adoption_operation,
    qualification_adoption_request,
    qualification_adoption_succeeded,
)
from services.api.provider_qualification_authority import (
    load_qualification_admission_policy,
)
from services.api.provider_qualification_writer import (
    PostgresQualificationWriter,
    QualificationWriter,
    QualificationWriterError,
)
from services.api.provider_uds import (
    ProviderUdsClientConfig,
    ProviderUdsError,
    SecureProviderUnixServer,
    provider_uds_request,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from services.api.provider_qualification_json import JsonValue
    from services.api.provider_qualification_receipt import QualificationReceipt
    from services.api.provider_runtime_contracts import (
        ProviderConnection,
        ProviderPrincipal,
    )


@final
class UnixSocketQualificationWriter(QualificationWriter):
    """Send an exact adoption to a service that alone holds its database login."""

    def __init__(self, config: ProviderUdsClientConfig) -> None:
        """Bind only non-secret UDS settings in the live-capture process."""
        self._config = config

    @override
    def adopt(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        receipt: QualificationReceipt,
        *,
        expected_revision: int,
    ) -> None:
        """Request one fixed adoption operation without a generic SQL surface."""
        command = QualificationAdoptionCommand(
            principal,
            connection,
            runtime_home_ref,
            receipt,
            expected_revision,
        )
        try:
            response = provider_uds_request(
                self._config,
                qualification_adoption_request(command),
            )
        except ProviderUdsError as error:
            raise QualificationWriterError from error
        if not qualification_adoption_succeeded(
            cast("Mapping[str, JsonValue]", response)
        ):
            raise QualificationWriterError


@dataclass(frozen=True, slots=True)
class QualificationAdopterServerConfig:
    """Secret-bearing settings read only by the isolated adopter process."""

    socket_path: Path
    database_url: str = field(repr=False, compare=False)
    expected_login_role: str
    authority_public_keys: Path
    authority_public_keys_sha256: str
    active_key_id: str


def build_qualification_adopter_server(
    config: QualificationAdopterServerConfig,
) -> SecureProviderUnixServer:
    """Compose a fixed writer endpoint with its dedicated database credential."""
    writer = PostgresQualificationWriter(
        config.database_url,
        load_qualification_admission_policy(
            config.authority_public_keys,
            expected_sha256=config.authority_public_keys_sha256,
            active_key_id=config.active_key_id,
        ),
        expected_login_role=config.expected_login_role,
    )
    return SecureProviderUnixServer(
        config.socket_path,
        qualification_adoption_operation(writer),
    )


def main() -> None:
    """Serve qualification adoption with deployment-only database credentials."""
    try:
        config = QualificationAdopterServerConfig(
            socket_path=Path(os.environ["PROVIDER_QUALIFICATION_ADOPTER_SOCKET"]),
            database_url=os.environ["PROVIDER_QUALIFICATION_ADOPTER_DATABASE_URL"],
            expected_login_role=os.environ["PROVIDER_QUALIFICATION_ADOPTER_LOGIN_ROLE"],
            authority_public_keys=Path(
                os.environ["PROVIDER_QUALIFICATION_AUTHORITY_PUBLIC_KEYS_FILE"]
            ),
            authority_public_keys_sha256=os.environ[
                "PROVIDER_QUALIFICATION_AUTHORITY_PUBLIC_KEYS_SHA256"
            ],
            active_key_id=os.environ["PROVIDER_QUALIFICATION_ACTIVE_KEY_ID"],
        )
    except (KeyError, ValueError) as error:
        raise SystemExit(2) from error
    with build_qualification_adopter_server(config) as server:
        server.serve_forever()


if __name__ == "__main__":
    main()
