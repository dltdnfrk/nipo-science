"""Connection operations for the composed provider runtime service."""

from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_oauth_state import OAuthRequest
from services.api.provider_runtime_configuration import ADAPTERS, ProviderAdapter
from services.api.provider_runtime_contracts import (
    ERROR_ACCOUNT_UNAVAILABLE,
    ERROR_INVALID_HEALTH,
    ERROR_MODEL_UNAVAILABLE,
    ERROR_QUALIFICATION_REQUIRED,
    ERROR_REVISION_CONFLICT,
    Flow,
    Health,
    OAuthInitiation,
    ProviderCleanupReceipt,
    ProviderConnection,
    ProviderPrincipal,
    runtime_error,
)
from services.api.provider_runtime_oauth_service import ProviderRuntimeOAuthServiceMixin
from services.api.provider_runtime_rules import (
    connection_is_qualified,
    connection_view,
    require_mutable,
)

if TYPE_CHECKING:
    from services.api.provider_connection_record import ConnectionRecord


class _ProviderRuntimeConnectionService(ProviderRuntimeOAuthServiceMixin):
    """Expose durable connection actions over the exclusive aggregate."""

    def adapters(self) -> tuple[ProviderAdapter, ...]:
        """Return the fixed provider registry."""
        return ADAPTERS

    def list_connections(
        self,
        principal: ProviderPrincipal,
    ) -> tuple[ProviderConnection, ...]:
        """List connections owned by the principal."""
        return self._connections.list_connections(principal)

    def connection_detail(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
    ) -> ProviderConnection:
        """Return one connection owned by the principal."""
        return self._connections.connection_detail(principal, connection_id)

    def select_account(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        account_id: str,
    ) -> ProviderConnection:
        """Confirm the account selected by the official OAuth completion."""

        def select(record: ConnectionRecord) -> ProviderConnection:
            require_mutable(record)
            if record.account_id != account_id:
                raise runtime_error(ERROR_ACCOUNT_UNAVAILABLE)
            return connection_view(record)

        return self._connections.inspect(principal, connection_id, select)

    def select_model(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        model_id: str,
        expected_revision: int | None = None,
    ) -> ProviderConnection:
        """Select an eligible model for a connection."""

        def update(record: ConnectionRecord) -> ConnectionRecord:
            if (
                not provider_model_id_is_valid(model_id)
                or model_id not in record.eligible_models
            ):
                raise runtime_error(ERROR_MODEL_UNAVAILABLE)
            return replace(record, selected_model=model_id)

        return self._connections.mutate(
            principal,
            connection_id,
            expected_revision,
            update,
        )

    def set_health(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        health: Health,
        expected_revision: int | None = None,
    ) -> ProviderConnection:
        """Update the connection health after validating allowed transitions."""

        def update(record: ConnectionRecord) -> ConnectionRecord:
            if health not in (
                "healthy",
                "reauth_required",
                "unavailable",
                "quota_exhausted",
            ):
                raise runtime_error(ERROR_INVALID_HEALTH)
            if health == "healthy" and not connection_is_qualified(record):
                raise runtime_error(ERROR_QUALIFICATION_REQUIRED)
            return replace(record, health=health)

        return self._connections.mutate(
            principal,
            connection_id,
            expected_revision,
            update,
        )

    def initiate_reauth(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        flow: Flow,
        redirect_uri: str,
        expected_revision: int | None = None,
    ) -> OAuthInitiation:
        """Mark a connection for reauthentication and start its OAuth flow."""

        def mark_pending(record: ConnectionRecord) -> ConnectionRecord:
            if record.completion_adoption is not None:
                raise runtime_error(ERROR_REVISION_CONFLICT)
            return replace(record, health="reauth_required")

        pending = self._connections.mutate(
            principal,
            connection_id,
            expected_revision,
            mark_pending,
        )
        return self._initiate(
            OAuthRequest(
                principal,
                pending.adapter_id,
                flow,
                redirect_uri,
                pending.connection_id,
                pending.revision,
            )
        )

    def revoke(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
        expected_revision: int | None = None,
    ) -> ProviderCleanupReceipt:
        """Revoke a connection and request runtime-owned material destruction."""
        return self._connections.revoke(principal, connection_id, expected_revision)

    def cleanup_receipt(
        self,
        principal: ProviderPrincipal,
        connection_id: str,
    ) -> ProviderCleanupReceipt:
        """Return an owned connection's redacted cleanup receipt."""
        return self._connections.cleanup_receipt(principal, connection_id)


ProviderRuntimeConnectionServiceMixin = _ProviderRuntimeConnectionService
