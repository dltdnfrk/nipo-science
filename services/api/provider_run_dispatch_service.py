"""UDS client and isolated PostgreSQL service for qualified Run dispatch."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, cast, final, override

from services.api.provider_qualification_authority import load_qualification_verifier
from services.api.provider_run_dispatch import (
    DispatchedProviderRun,
    PostgresProviderRunDispatcher,
    ProviderRunDispatcher,
    ProviderRunDispatchError,
    ProviderRunDispatchRequest,
)
from services.api.provider_run_dispatch_contracts import (
    provider_run_dispatch_request_object,
)
from services.api.provider_run_dispatch_policy import (
    provider_run_dispatch_request_is_valid,
)
from services.api.provider_runtime_contracts import (
    DispatchAuthorization,
    ProviderPrincipal,
    ProviderRuntimeIdentity,
)
from services.api.provider_uds import (
    ProviderUdsClientConfig,
    ProviderUdsError,
    SecureProviderUnixServer,
    canonical_provider_json,
    provider_uds_request,
    strict_provider_json,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from services.api.provider_run_dispatch_contracts import DispatchWireValue

_PROTOCOL_VERSION, _DISPATCH_OPERATION = 1, "dispatch_provider_run"


@final
class UnixSocketProviderRunDispatcher(ProviderRunDispatcher):
    """Dispatch through a process that alone owns its dedicated database login."""

    def __init__(self, config: ProviderUdsClientConfig) -> None:
        """Bind non-secret socket settings in the ordinary product process."""
        self._config = config

    @override
    def dispatch(
        self,
        principal: ProviderPrincipal,
        request: ProviderRunDispatchRequest,
    ) -> DispatchedProviderRun:
        """Request one fixed dispatch and validate the exact returned binding."""
        if not provider_run_dispatch_request_is_valid(request):
            raise ProviderRunDispatchError
        try:
            response = cast(
                "Mapping[str, DispatchWireValue]",
                provider_uds_request(
                    self._config,
                    {
                        "schema_version": _PROTOCOL_VERSION,
                        "operation": _DISPATCH_OPERATION,
                        "principal": {
                            "org_id": principal.org_id,
                            "user_id": principal.user_id,
                        },
                        "request": provider_run_dispatch_request_object(request),
                    },
                ),
            )
        except ProviderUdsError as error:
            raise ProviderRunDispatchError from error
        if (
            set(response) != {"schema_version", "run"}
            or response.get("schema_version") != _PROTOCOL_VERSION
        ):
            raise ProviderRunDispatchError
        run = _mapping(response.get("run"))
        if (
            set(run) != {"run_id", "authorization"}
            or run.get("run_id") != request.run_id
        ):
            raise ProviderRunDispatchError
        authorization = _authorization(_mapping(run.get("authorization")))
        if (
            authorization.connection_id != request.connection_id
            or authorization.model_id != request.model_id
        ):
            raise ProviderRunDispatchError
        return DispatchedProviderRun(request.run_id, authorization)


@dataclass(frozen=True, slots=True)
class ProviderRunDispatchServerConfig:
    """Secret-bearing configuration confined to the dispatch service process."""

    socket_path: Path
    database_url: str = field(repr=False, compare=False)
    expected_login_role: str
    authority_public_keys: Path
    authority_public_keys_sha256: str
    runtime_identity: ProviderRuntimeIdentity


def build_provider_run_dispatch_server(
    config: ProviderRunDispatchServerConfig,
) -> SecureProviderUnixServer:
    """Compose the only service permitted to use the dispatch database login."""
    dispatcher = PostgresProviderRunDispatcher(
        config.database_url,
        load_qualification_verifier(
            config.authority_public_keys,
            expected_sha256=config.authority_public_keys_sha256,
        ),
        config.runtime_identity,
        expected_login_role=config.expected_login_role,
    )

    def operation(source: bytes) -> bytes:
        root = cast("Mapping[str, DispatchWireValue]", strict_provider_json(source))
        if set(root) != {"schema_version", "operation", "principal", "request"} or (
            root.get("schema_version") != _PROTOCOL_VERSION
            or root.get("operation") != _DISPATCH_OPERATION
        ):
            raise ProviderRunDispatchError
        principal = _principal(_mapping(root.get("principal")))
        request = _request(_mapping(root.get("request")))
        dispatched = dispatcher.dispatch(principal, request)
        return canonical_provider_json(
            {
                "schema_version": _PROTOCOL_VERSION,
                "run": {
                    "run_id": dispatched.run_id,
                    "authorization": _authorization_object(dispatched.authorization),
                },
            }
        )

    return SecureProviderUnixServer(config.socket_path, operation)


def main() -> None:
    """Serve qualified Run persistence with a dedicated deployment login."""
    try:
        config = ProviderRunDispatchServerConfig(
            socket_path=Path(os.environ["PROVIDER_RUN_DISPATCH_SOCKET"]),
            database_url=os.environ["PROVIDER_RUN_DISPATCH_DATABASE_URL"],
            expected_login_role=os.environ["PROVIDER_RUN_DISPATCH_LOGIN_ROLE"],
            authority_public_keys=Path(
                os.environ["PROVIDER_QUALIFICATION_AUTHORITY_PUBLIC_KEYS_FILE"]
            ),
            authority_public_keys_sha256=os.environ[
                "PROVIDER_QUALIFICATION_AUTHORITY_PUBLIC_KEYS_SHA256"
            ],
            runtime_identity=ProviderRuntimeIdentity(
                os.environ["PROVIDER_RUNTIME_ADAPTER_ID"],
                os.environ["PROVIDER_RUNTIME_VERSION"],
                os.environ["PROVIDER_RUNTIME_EXECUTABLE_SHA256"],
            ),
        )
    except (KeyError, ValueError) as error:
        raise SystemExit(2) from error
    with build_provider_run_dispatch_server(config) as server:
        server.serve_forever()


def _request(root: Mapping[str, DispatchWireValue]) -> ProviderRunDispatchRequest:
    fields = (
        "run_id",
        "session_id",
        "connection_id",
        "model_id",
        "action_plan_digest",
        "research_intent_sha256",
    )
    if set(root) != set(fields):
        raise ProviderRunDispatchError
    values = tuple(root.get(name) for name in fields)
    model_id = root.get("model_id")
    if (
        not all(isinstance(value, str) for value in values)
        or not isinstance(model_id, str)
    ):
        raise ProviderRunDispatchError
    return ProviderRunDispatchRequest(
        *(cast("tuple[str, str, str, str, str, str]", values))
    )


def _principal(root: Mapping[str, DispatchWireValue]) -> ProviderPrincipal:
    if set(root) != {"org_id", "user_id"}:
        raise ProviderRunDispatchError
    org_id = root.get("org_id")
    user_id = root.get("user_id")
    if not isinstance(org_id, str) or not isinstance(user_id, str):
        raise ProviderRunDispatchError
    return ProviderPrincipal(user_id, org_id)


def _authorization_object(
    authorization: DispatchAuthorization,
) -> dict[str, DispatchWireValue]:
    return {
        "adapter_id": authorization.adapter_id,
        "connection_id": authorization.connection_id,
        "model_id": authorization.model_id,
        "qualification_receipt_id": authorization.qualification_receipt_id,
        "qualification_receipt_sha256": (authorization.qualification_receipt_sha256),
        "qualification_connection_revision": (
            authorization.qualification_connection_revision
        ),
        "qualification_profile_sha256": authorization.qualification_profile_sha256,
        "qualification_runtime_version": authorization.qualification_runtime_version,
        "qualification_executable_sha256": (
            authorization.qualification_executable_sha256
        ),
        "built_in_tools_enabled": authorization.built_in_tools_enabled,
    }


def _authorization(root: Mapping[str, DispatchWireValue]) -> DispatchAuthorization:
    expected = {
        "adapter_id",
        "connection_id",
        "model_id",
        "qualification_receipt_id",
        "qualification_receipt_sha256",
        "qualification_connection_revision",
        "qualification_profile_sha256",
        "qualification_runtime_version",
        "qualification_executable_sha256",
        "built_in_tools_enabled",
    }
    if set(root) != expected or root.get("built_in_tools_enabled") is not False:
        raise ProviderRunDispatchError
    revision = root.get("qualification_connection_revision")
    model_id = root.get("model_id")
    string_names = expected - {
        "qualification_connection_revision",
        "built_in_tools_enabled",
    }
    if (
        not isinstance(revision, int)
        or isinstance(revision, bool)
        or not all(isinstance(root.get(name), str) for name in string_names)
        or not isinstance(model_id, str)
    ):
        raise ProviderRunDispatchError
    return DispatchAuthorization(
        adapter_id=cast("str", root["adapter_id"]),
        connection_id=cast("str", root["connection_id"]),
        model_id=cast("str", root["model_id"]),
        qualification_receipt_id=cast("str", root["qualification_receipt_id"]),
        qualification_receipt_sha256=cast("str", root["qualification_receipt_sha256"]),
        qualification_connection_revision=revision,
        qualification_profile_sha256=cast("str", root["qualification_profile_sha256"]),
        qualification_runtime_version=cast(
            "str", root["qualification_runtime_version"]
        ),
        qualification_executable_sha256=cast(
            "str", root["qualification_executable_sha256"]
        ),
    )


def _mapping(value: DispatchWireValue) -> Mapping[str, DispatchWireValue]:
    if not isinstance(value, dict):
        raise ProviderRunDispatchError
    return value


if __name__ == "__main__":
    main()
