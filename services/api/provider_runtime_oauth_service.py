"""OAuth orchestration for the composed provider runtime service."""

from __future__ import annotations

from contextlib import suppress
from typing import TYPE_CHECKING

from services.api.provider_oauth_state import OAuthRequest
from services.api.provider_runtime_configuration import connectable_adapter
from services.api.provider_runtime_contracts import (
    ERROR_INVALID_OAUTH_REQUEST,
    Flow,
    OAuthClaim,
    OAuthInitiation,
    OfficialOAuthCompletion,
    ProviderConnection,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderRuntimeError,
    runtime_error,
)
from services.api.provider_runtime_rules import require_mutable, require_reauth_target

if TYPE_CHECKING:
    from services.api.provider_connection_aggregate import ProviderConnectionAggregate
    from services.api.provider_connection_record import ConnectionRecord
    from services.api.provider_oauth_state import ProviderOAuthState


class _ProviderRuntimeOAuthService:
    """Coordinate OAuth state with the durable connection aggregate."""

    def __init__(
        self,
        oauth: ProviderOAuthState,
        connections: ProviderConnectionAggregate,
        persistence: ProviderPersistence,
    ) -> None:
        self._oauth: ProviderOAuthState = oauth
        self._connections: ProviderConnectionAggregate = connections
        self._persistence: ProviderPersistence = persistence

    def initiate(
        self,
        principal: ProviderPrincipal,
        adapter_id: str,
        flow: Flow,
        redirect_uri: str,
        reauth_connection_id: str | None = None,
    ) -> OAuthInitiation:
        """Create a single-use OAuth attempt for a connectable adapter."""
        return self._initiate(
            OAuthRequest(
                principal,
                adapter_id,
                flow,
                redirect_uri,
                reauth_connection_id,
                None,
            )
        )

    def _initiate(self, request: OAuthRequest) -> OAuthInitiation:
        self._connections.load_principal(request.principal)
        adapter = connectable_adapter(request.adapter_id)

        def validate_reauth() -> int | None:
            if request.reauth_connection_id is None:
                return None

            def validate(record: ConnectionRecord) -> int:
                require_mutable(record)
                if record.adapter_id != adapter.adapter_id:
                    raise runtime_error(ERROR_INVALID_OAUTH_REQUEST)
                bound_revision = (
                    record.revision
                    if request.expected_reauth_revision is None
                    else request.expected_reauth_revision
                )
                require_reauth_target(record, bound_revision)
                return bound_revision

            return self._connections.inspect(
                request.principal,
                request.reauth_connection_id,
                validate,
            )

        initiation = self._oauth.initiate(
            request,
            validate_reauth,
        )
        self._connections.record_audit("oauth_initiated", request.adapter_id)
        return initiation

    def complete_callback(
        self,
        principal: ProviderPrincipal,
        state: str,
        redirect_uri: str,
        completion: OfficialOAuthCompletion,
    ) -> ProviderConnection:
        """Complete a callback OAuth attempt."""
        claim = self.claim_oauth(principal, state, "callback", redirect_uri)
        return self.finalize_oauth(principal, claim, completion)

    def complete_device(
        self,
        principal: ProviderPrincipal,
        state: str,
        completion: OfficialOAuthCompletion,
        redirect_uri: str = "/oauth/device",
    ) -> ProviderConnection:
        """Complete a device OAuth attempt."""
        claim = self.claim_oauth(principal, state, "device", redirect_uri)
        return self.finalize_oauth(principal, claim, completion)

    def claim_oauth(
        self,
        principal: ProviderPrincipal,
        state: str,
        flow: Flow,
        redirect_uri: str,
    ) -> OAuthClaim:
        """Atomically validate and consume an owned OAuth state for exchange."""
        return self._oauth.claim(principal, state, flow, redirect_uri)

    def abort_oauth(self, principal: ProviderPrincipal, claim: OAuthClaim) -> None:
        """Abort a claimed exchange after the official broker fails."""
        adapter_id = self._oauth.abort(principal, claim)
        self._connections.record_audit("oauth_aborted", adapter_id)

    def discard_oauth_completion(
        self,
        principal: ProviderPrincipal,
        completion: OfficialOAuthCompletion,
    ) -> None:
        """Destroy exchanged material left unbound by failed finalization."""
        self._persistence.discard_runtime_home(principal, completion.vault_home_ref)

    def finalize_oauth(
        self,
        principal: ProviderPrincipal,
        claim: OAuthClaim,
        completion: OfficialOAuthCompletion,
    ) -> ProviderConnection:
        """Consume one validated claim and persist its official completion."""
        attempt = self._oauth.consume_claim(principal, claim)
        try:
            return self._connections.finalize(principal, attempt, completion)
        except ProviderRuntimeError:
            with suppress(ProviderRuntimeError):
                self.discard_oauth_completion(principal, completion)
            raise

    def cancel_pending(self, principal: ProviderPrincipal, state: str) -> None:
        """Cancel a pending OAuth attempt owned by the principal."""
        adapter_id = self._oauth.cancel(principal, state)
        self._connections.record_audit("oauth_cancelled", adapter_id)


ProviderRuntimeOAuthServiceMixin = _ProviderRuntimeOAuthService
