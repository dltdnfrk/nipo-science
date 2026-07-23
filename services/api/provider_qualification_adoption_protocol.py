"""Fixed UDS protocol for adopting one provider qualification."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import TYPE_CHECKING, cast

from services.api import provider_qualification_authority as qualification_authority
from services.api import provider_uds
from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_qualification_receipt import qualification_receipt_sha256
from services.api.provider_qualification_writer import (
    QualificationWriter,
    QualificationWriterError,
)
from services.api.provider_runtime_contracts import (
    ProviderConnection,
    ProviderPrincipal,
    ProviderQualificationIdentity,
    ProviderRuntimeIdentity,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from services.api.provider_qualification_json import JsonValue
    from services.api.provider_qualification_receipt import QualificationReceipt
    from services.api.provider_runtime_contracts import Health

_PROTOCOL_VERSION = 1
_ADOPT_OPERATION = "adopt_provider_qualification"


@dataclass(frozen=True, slots=True)
class QualificationAdoptionCommand:
    """The exact typed values carried by one qualification adoption request."""

    principal: ProviderPrincipal
    connection: ProviderConnection
    runtime_home_ref: str
    receipt: QualificationReceipt
    expected_revision: int


def qualification_adoption_request(
    command: QualificationAdoptionCommand,
) -> dict[str, JsonValue]:
    """Encode one closed adoption request for the local protocol."""
    receipt = qualification_authority.qualification_receipt_json(command.receipt)
    return {
        "schema_version": _PROTOCOL_VERSION,
        "operation": _ADOPT_OPERATION,
        "principal": _principal_object(command.principal),
        "connection": _connection_object(command.connection),
        "runtime_home_ref": command.runtime_home_ref,
        "receipt": cast("JsonValue", provider_uds.strict_provider_json(receipt)),
        "expected_revision": command.expected_revision,
    }


def qualification_adoption_succeeded(response: Mapping[str, JsonValue]) -> bool:
    """Return whether a response is exactly the fixed adoption acknowledgement."""
    return response == {"schema_version": _PROTOCOL_VERSION, "status": "adopted"}


def qualification_adoption_operation(
    writer: QualificationWriter,
) -> Callable[[bytes], bytes]:
    """Build the closed adoption handler around one active-key-aware writer."""

    def operation(source: bytes) -> bytes:
        root = cast(
            "Mapping[str, JsonValue]", provider_uds.strict_provider_json(source)
        )
        expected = {
            "schema_version",
            "operation",
            "principal",
            "connection",
            "runtime_home_ref",
            "receipt",
            "expected_revision",
        }
        if (
            set(root) != expected
            or root.get("schema_version") != _PROTOCOL_VERSION
            or root.get("operation") != _ADOPT_OPERATION
        ):
            raise QualificationWriterError
        principal = _principal(_mapping(root.get("principal")))
        receipt = qualification_authority.parse_qualification_receipt_json(
            provider_uds.canonical_provider_json(_mapping(root.get("receipt")))
        )
        connection = _connection(_mapping(root.get("connection")), receipt)
        runtime_home_ref = root.get("runtime_home_ref")
        expected_revision = root.get("expected_revision")
        if (
            not isinstance(runtime_home_ref, str)
            or not isinstance(expected_revision, int)
            or isinstance(expected_revision, bool)
        ):
            raise QualificationWriterError
        writer.adopt(
            principal,
            connection,
            runtime_home_ref,
            receipt,
            expected_revision=expected_revision,
        )
        return provider_uds.canonical_provider_json(
            {"schema_version": _PROTOCOL_VERSION, "status": "adopted"}
        )

    return operation


def _principal_object(principal: ProviderPrincipal) -> dict[str, JsonValue]:
    return {"org_id": principal.org_id, "user_id": principal.user_id}


def _principal(root: Mapping[str, JsonValue]) -> ProviderPrincipal:
    if set(root) != {"org_id", "user_id"}:
        raise QualificationWriterError
    org_id = root.get("org_id")
    user_id = root.get("user_id")
    if not isinstance(org_id, str) or not isinstance(user_id, str):
        raise QualificationWriterError
    return ProviderPrincipal(user_id, org_id)


def _connection_object(connection: ProviderConnection) -> dict[str, JsonValue]:
    qualification = connection.qualification
    if qualification is None:
        raise QualificationWriterError
    return {
        "connection_id": connection.connection_id,
        "adapter_id": connection.adapter_id,
        "account_id": connection.account_id,
        "eligible_models": list(connection.eligible_models),
        "selected_model": connection.selected_model,
        "health": connection.health,
        "cleanup_verified": connection.cleanup_verified,
        "qualified_live": connection.qualified_live,
        "created_at": connection.created_at.isoformat(timespec="microseconds"),
        "revision": connection.revision,
        "qualification": {
            "profile_sha256": qualification.profile_sha256,
            "receipt_sha256": qualification.receipt_sha256,
            "runtime": {
                "adapter_id": qualification.runtime.adapter_id,
                "runtime_version": qualification.runtime.runtime_version,
                "executable_sha256": qualification.runtime.executable_sha256,
            },
        },
    }


def _connection(
    root: Mapping[str, JsonValue],
    receipt: QualificationReceipt,
) -> ProviderConnection:
    expected = {
        "connection_id",
        "adapter_id",
        "account_id",
        "eligible_models",
        "selected_model",
        "health",
        "cleanup_verified",
        "qualified_live",
        "created_at",
        "revision",
        "qualification",
    }
    if set(root) != expected:
        raise QualificationWriterError
    connection_id = root.get("connection_id")
    adapter_id = root.get("adapter_id")
    account_id = root.get("account_id")
    models = root.get("eligible_models")
    selected_model = root.get("selected_model")
    health = root.get("health")
    cleanup_verified = root.get("cleanup_verified")
    qualified_live = root.get("qualified_live")
    created_at = root.get("created_at")
    revision = root.get("revision")
    qualification = _mapping(root.get("qualification"))
    if (
        not all(
            isinstance(value, str) for value in (connection_id, adapter_id, account_id)
        )
        or not isinstance(models, list)
        or not models
        or not all(
            isinstance(model, str) and provider_model_id_is_valid(model)
            for model in models
        )
        or (
            selected_model is not None
            and (
                not isinstance(selected_model, str)
                or not provider_model_id_is_valid(selected_model)
            )
        )
        or (isinstance(selected_model, str) and selected_model not in models)
        or health
        not in {
            "pending",
            "healthy",
            "reauth_required",
            "unavailable",
            "quota_exhausted",
            "revoked",
        }
        or not isinstance(cleanup_verified, bool)
        or not isinstance(qualified_live, bool)
        or not isinstance(created_at, str)
        or not isinstance(revision, int)
        or isinstance(revision, bool)
    ):
        raise QualificationWriterError
    runtime = _mapping(qualification.get("runtime"))
    if set(qualification) != {"profile_sha256", "receipt_sha256", "runtime"} or set(
        runtime
    ) != {"adapter_id", "runtime_version", "executable_sha256"}:
        raise QualificationWriterError
    profile = qualification.get("profile_sha256")
    digest = qualification.get("receipt_sha256")
    runtime_adapter = runtime.get("adapter_id")
    runtime_version = runtime.get("runtime_version")
    executable = runtime.get("executable_sha256")
    if not all(
        isinstance(value, str)
        for value in (profile, digest, runtime_adapter, runtime_version, executable)
    ):
        raise QualificationWriterError
    try:
        created = datetime.fromisoformat(created_at)
    except ValueError as error:
        raise QualificationWriterError from error
    if created.tzinfo is None or digest != qualification_receipt_sha256(receipt):
        raise QualificationWriterError
    identity = ProviderQualificationIdentity(
        ProviderRuntimeIdentity(
            cast("str", runtime_adapter),
            cast("str", runtime_version),
            cast("str", executable),
        ),
        cast("str", profile),
        receipt,
        cast("str", digest),
    )
    return ProviderConnection(
        cast("str", connection_id),
        cast("str", adapter_id),
        cast("str", account_id),
        tuple(cast("list[str]", models)),
        selected_model,
        cast("Health", health),
        cleanup_verified,
        qualified_live,
        created,
        revision,
        identity,
    )


def _mapping(value: JsonValue) -> Mapping[str, JsonValue]:
    if not isinstance(value, dict):
        raise QualificationWriterError
    return value
