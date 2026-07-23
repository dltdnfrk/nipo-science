"""Compatibility facade for provider runtime contracts and service composition."""

from __future__ import annotations

from secrets import token_bytes
from typing import TYPE_CHECKING, final

from services.api.artifacts.runtime import Uuid7Factory
from services.api.provider_connection_aggregate import ProviderConnectionAggregate
from services.api.provider_oauth_state import ProviderOAuthState
from services.api.provider_qualification import (
    QualificationResult,
    qualification_result_is_verified,
)
from services.api.provider_qualification_receipt import (
    QualificationReceipt,
    QualificationReceiptSubject,
    QualificationReceiptVerifier,
    qualification_receipt_sha256,
)
from services.api.provider_runtime_configuration import (
    ADAPTERS,
    NONCE_BYTES,
    OAUTH_EXPIRATION,
    PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    SHA256_HEX_LENGTH,
    ProviderAdapter,
    ProviderCleanupPolicy,
    is_safe_runtime_home_ref,
)
from services.api.provider_runtime_contracts import (
    ERROR_ACCOUNT_UNAVAILABLE,
    ERROR_ADAPTER_DISABLED,
    ERROR_INVALID_CLEANUP_POLICY,
    ERROR_INVALID_COMPLETION,
    ERROR_INVALID_CONNECTION_ID,
    ERROR_INVALID_HEALTH,
    ERROR_INVALID_NONCE,
    ERROR_INVALID_OAUTH_REQUEST,
    ERROR_MODEL_UNAVAILABLE,
    ERROR_NOT_FOUND,
    ERROR_OAUTH_BINDING_MISMATCH,
    ERROR_OAUTH_EXPIRED,
    ERROR_PROVIDER_CLEANUP_OVERDUE,
    ERROR_PROVIDER_UNAVAILABLE,
    ERROR_QUALIFICATION_REQUIRED,
    ERROR_QUOTA_EXHAUSTED,
    ERROR_REAUTH_REQUIRED,
    ERROR_REVISION_CONFLICT,
    ERROR_UNSAFE_COMPLETION,
    AuditReceipt,
    ConnectionNotFoundError,
    DispatchAuthorization,
    Flow,
    Health,
    OAuthClaim,
    OAuthInitiation,
    OfficialOAuthCompletion,
    ProviderCleanupReceipt,
    ProviderCompletionAdoption,
    ProviderConnection,
    ProviderConnectionSnapshot,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderQualificationIdentity,
    ProviderRevokeMutation,
    ProviderRuntimeError,
    ProviderRuntimeIdentity,
    ProviderUpsertControl,
)
from services.api.provider_runtime_qualification_service import (
    ProviderRuntimeQualificationServiceMixin,
)

__all__ = (
    "ADAPTERS",
    "ERROR_ACCOUNT_UNAVAILABLE",
    "ERROR_ADAPTER_DISABLED",
    "ERROR_INVALID_CLEANUP_POLICY",
    "ERROR_INVALID_COMPLETION",
    "ERROR_INVALID_CONNECTION_ID",
    "ERROR_INVALID_HEALTH",
    "ERROR_INVALID_NONCE",
    "ERROR_INVALID_OAUTH_REQUEST",
    "ERROR_MODEL_UNAVAILABLE",
    "ERROR_NOT_FOUND",
    "ERROR_OAUTH_BINDING_MISMATCH",
    "ERROR_OAUTH_EXPIRED",
    "ERROR_PROVIDER_CLEANUP_OVERDUE",
    "ERROR_PROVIDER_UNAVAILABLE",
    "ERROR_QUALIFICATION_REQUIRED",
    "ERROR_QUOTA_EXHAUSTED",
    "ERROR_REAUTH_REQUIRED",
    "ERROR_REVISION_CONFLICT",
    "ERROR_UNSAFE_COMPLETION",
    "NONCE_BYTES",
    "OAUTH_EXPIRATION",
    "PROVIDER_RUNTIME_HOME_CLEANUP_POLICY",
    "SHA256_HEX_LENGTH",
    "AuditReceipt",
    "ConnectionNotFoundError",
    "DispatchAuthorization",
    "Flow",
    "Health",
    "OAuthClaim",
    "OAuthInitiation",
    "OfficialOAuthCompletion",
    "ProviderAdapter",
    "ProviderCleanupPolicy",
    "ProviderCleanupReceipt",
    "ProviderCompletionAdoption",
    "ProviderConnection",
    "ProviderConnectionSnapshot",
    "ProviderPersistence",
    "ProviderPrincipal",
    "ProviderQualificationIdentity",
    "ProviderRevokeMutation",
    "ProviderRuntimeError",
    "ProviderRuntimeIdentity",
    "ProviderRuntimeService",
    "ProviderUpsertControl",
    "QualificationReceipt",
    "QualificationReceiptSubject",
    "QualificationReceiptVerifier",
    "QualificationResult",
    "is_safe_runtime_home_ref",
    "qualification_receipt_sha256",
    "qualification_result_is_verified",
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime


@final
class ProviderRuntimeService(ProviderRuntimeQualificationServiceMixin):
    """Compose OAuth state and the single provider connection aggregate."""

    def __init__(
        self,
        clock: Callable[[], datetime],
        nonce_factory: Callable[[], bytes] | None = None,
        id_factory: Callable[[], str] | None = None,
        *,
        persistence: ProviderPersistence,
        cleanup_policy: ProviderCleanupPolicy,
    ) -> None:
        """Initialize the service with injectable clock and identifier sources."""
        nonce_source = nonce_factory or _default_nonce
        id_source = id_factory or _default_id
        super().__init__(
            ProviderOAuthState(clock, nonce_source, id_source),
            ProviderConnectionAggregate(
                clock,
                id_source,
                persistence,
                cleanup_policy,
            ),
            persistence,
        )


def _default_nonce() -> bytes:
    return token_bytes(NONCE_BYTES)


def _default_id() -> str:
    return str(Uuid7Factory().new_uuid7())
