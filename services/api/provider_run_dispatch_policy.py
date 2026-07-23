"""Pure authorization policy for qualified provider Run dispatch."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import RFC_4122, UUID

from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_qualification_postgres import qualification_from_row
from services.api.provider_run_dispatch_contracts import (
    ProviderRunDispatchError,
    ProviderRunDispatchRequest,
)
from services.api.provider_runtime_contracts import (
    DispatchAuthorization,
    ProviderPrincipal,
    ProviderRuntimeIdentity,
)

type ProviderRowValue = (
    None
    | bool
    | int
    | float
    | str
    | bytes
    | datetime
    | list[ProviderRowValue]
    | dict[str, ProviderRowValue]
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from services.api.provider_qualification_receipt import QualificationReceiptVerifier

_UUID7_VERSION = 7
_FORBIDDEN_LOGIN_ROLES = frozenset(
    {
        "science_workbench",
        "science_workbench_app",
        "science_workbench_dispatcher",
        "science_workbench_qualification",
    }
)


def provider_run_dispatch_login_is_valid(expected_login_role: str) -> bool:
    """Return whether a deployment login may assume only the dispatch capability."""
    return bool(
        expected_login_role
        and expected_login_role not in _FORBIDDEN_LOGIN_ROLES
        and expected_login_role.replace("_", "").isalnum()
    )


def provider_run_dispatch_request_is_valid(
    request: ProviderRunDispatchRequest,
) -> bool:
    """Return whether all identifiers satisfy the closed dispatch contract."""
    return (
        _uuid7(request.run_id)
        and _uuid7(request.session_id)
        and _uuid7(request.connection_id)
        and provider_model_id_is_valid(request.model_id)
        and _sha256(request.action_plan_digest)
        and _sha256(request.research_intent_sha256)
    )


@dataclass(frozen=True, slots=True)
class ProviderRunAuthorizationPolicy:
    """Verify one selected connection row against signed runtime authority."""

    verifier: QualificationReceiptVerifier
    runtime_identity: ProviderRuntimeIdentity
    clock: Callable[[], datetime]

    def authorize(
        self,
        principal: ProviderPrincipal,
        request: ProviderRunDispatchRequest,
        row: Mapping[str, ProviderRowValue],
    ) -> DispatchAuthorization:
        """Return the immutable Run binding or reject the entire dispatch."""
        metadata_value = row.get("account_metadata")
        if not isinstance(metadata_value, dict):
            raise ProviderRunDispatchError
        metadata = metadata_value
        adapter = row.get("adapter_id")
        models = metadata.get("models")
        revision = metadata.get("revision")
        receipt_id = metadata.get("qualification_receipt_id")
        runtime_version = metadata.get("qualification_runtime_version")
        executable_sha256 = metadata.get("qualification_executable_sha256")
        profile_sha256 = metadata.get("qualification_profile_sha256")
        if (
            row.get("id") != request.connection_id
            or not isinstance(adapter, str)
            or metadata.get("provider") != adapter
            or row.get("status") != "healthy"
            or row.get("selected_model") != request.model_id
            or not isinstance(models, list)
            or request.model_id not in models
            or not isinstance(revision, str)
            or not revision.isdecimal()
            or not all(
                isinstance(value, str)
                for value in (
                    receipt_id,
                    runtime_version,
                    executable_sha256,
                    profile_sha256,
                )
            )
            or not isinstance(row.get("qualified_at"), datetime)
            or metadata.get("adoption_status") is not None
        ):
            raise ProviderRunDispatchError
        qualification = qualification_from_row(
            row,
            adapter_id=adapter,
            metadata=(
                receipt_id,
                runtime_version,
                executable_sha256,
                profile_sha256,
            ),
        )
        if qualification is None:
            raise ProviderRunDispatchError
        receipt = qualification.receipt
        subject = receipt.claim.subject
        if (
            not self.verifier.verify(receipt)
            or receipt.issued_at > self.clock().astimezone(UTC)
            or qualification.runtime != self.runtime_identity
            or subject.org_id != principal.org_id
            or subject.user_id != principal.user_id
            or subject.connection_id != request.connection_id
            or subject.connection_revision > int(revision)
        ):
            raise ProviderRunDispatchError
        return DispatchAuthorization(
            adapter_id=adapter,
            connection_id=request.connection_id,
            model_id=request.model_id,
            qualification_receipt_id=receipt.receipt_id,
            qualification_receipt_sha256=qualification.receipt_sha256,
            qualification_connection_revision=subject.connection_revision,
            qualification_profile_sha256=qualification.profile_sha256,
            qualification_runtime_version=qualification.runtime.runtime_version,
            qualification_executable_sha256=(qualification.runtime.executable_sha256),
        )


def _uuid7(value: str) -> bool:
    try:
        parsed = UUID(value)
    except (AttributeError, ValueError):
        return False
    return (
        str(parsed) == value
        and parsed.version == _UUID7_VERSION
        and parsed.variant == RFC_4122
    )


_SHA256_HEX_LENGTH = 64


def _sha256(value: str) -> bool:
    hex_digits = "0123456789abcdef"
    return len(value) == _SHA256_HEX_LENGTH and all(
        character in hex_digits for character in value
    )
