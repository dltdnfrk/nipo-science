"""Single-use official OAuth state owned independently of connection records."""

from __future__ import annotations

from base64 import urlsafe_b64encode
from dataclasses import dataclass
from hashlib import sha256
from threading import RLock
from typing import TYPE_CHECKING, final
from urllib.parse import urlparse

from services.api.provider_runtime_configuration import NONCE_BYTES, OAUTH_EXPIRATION
from services.api.provider_runtime_contracts import (
    ERROR_INVALID_CONNECTION_ID,
    ERROR_INVALID_NONCE,
    ERROR_INVALID_OAUTH_REQUEST,
    ERROR_OAUTH_BINDING_MISMATCH,
    ERROR_OAUTH_EXPIRED,
    ConnectionNotFoundError,
    Flow,
    OAuthClaim,
    OAuthInitiation,
    ProviderPrincipal,
    normalize_utc,
    runtime_error,
)

if TYPE_CHECKING:
    from collections.abc import Callable
    from datetime import datetime


@dataclass(slots=True)
class _OAuthAttempt:
    state_digest: str
    principal: ProviderPrincipal
    adapter_id: str
    flow: Flow
    redirect_uri: str
    expires_at: datetime
    reauth_connection_id: str | None
    reauth_revision: int | None


@dataclass(frozen=True, slots=True)
class _OAuthRequest:
    principal: ProviderPrincipal
    adapter_id: str
    flow: Flow
    redirect_uri: str
    reauth_connection_id: str | None
    expected_reauth_revision: int | None


@final
class _ProviderOAuthState:
    """Own pending attempts and claimed exchanges behind one lock."""

    def __init__(
        self,
        clock: Callable[[], datetime],
        nonce_factory: Callable[[], bytes],
        id_factory: Callable[[], str],
    ) -> None:
        self._clock = clock
        self._nonce_factory = nonce_factory
        self._id_factory = id_factory
        self._attempts: dict[str, _OAuthAttempt] = {}
        self._claims: dict[str, _OAuthAttempt] = {}
        self._lock = RLock()

    def initiate(
        self,
        request: _OAuthRequest,
        reauth_validator: Callable[[], int | None] | None = None,
    ) -> OAuthInitiation:
        if request.flow not in ("callback", "device") or not _safe_redirect(
            request.redirect_uri
        ):
            raise runtime_error(ERROR_INVALID_OAUTH_REQUEST)
        nonce = self._nonce_factory()
        if len(nonce) != NONCE_BYTES:
            raise runtime_error(ERROR_INVALID_NONCE)
        state = urlsafe_b64encode(nonce).decode("ascii").rstrip("=")
        expires_at = normalize_utc(self._clock()) + OAUTH_EXPIRATION
        digest = _state_digest(state)
        reauth_revision = None if reauth_validator is None else reauth_validator()
        with self._lock:
            self._attempts[digest] = _OAuthAttempt(
                state_digest=digest,
                principal=request.principal,
                adapter_id=request.adapter_id,
                flow=request.flow,
                redirect_uri=request.redirect_uri,
                expires_at=expires_at,
                reauth_connection_id=request.reauth_connection_id,
                reauth_revision=reauth_revision,
            )
        return OAuthInitiation(state, expires_at, request.flow)

    def claim(
        self,
        principal: ProviderPrincipal,
        state: str,
        flow: Flow,
        redirect_uri: str,
    ) -> OAuthClaim:
        digest = _state_digest(state)
        now = normalize_utc(self._clock())
        with self._lock:
            attempt = self._attempts.get(digest)
            if attempt is None or attempt.principal != principal:
                raise ConnectionNotFoundError
            if now >= attempt.expires_at:
                del self._attempts[digest]
                raise runtime_error(ERROR_OAUTH_EXPIRED)
            if attempt.flow != flow or attempt.redirect_uri != redirect_uri:
                raise runtime_error(ERROR_OAUTH_BINDING_MISMATCH)
            del self._attempts[digest]
        claim_id = self._id_factory()
        if not claim_id:
            raise runtime_error(ERROR_INVALID_CONNECTION_ID)
        with self._lock:
            self._claims[claim_id] = attempt
        return OAuthClaim(
            claim_id,
            attempt.adapter_id,
            state,
            attempt.flow,
            attempt.redirect_uri,
            attempt.expires_at,
        )

    def consume_claim(
        self, principal: ProviderPrincipal, claim: OAuthClaim
    ) -> _OAuthAttempt:
        with self._lock:
            attempt = self._claims.pop(claim.claim_id, None)
            if (
                attempt is None
                or attempt.principal != principal
                or attempt.adapter_id != claim.adapter_id
                or attempt.flow != claim.flow
                or attempt.redirect_uri != claim.redirect_uri
            ):
                raise ConnectionNotFoundError
            return attempt

    def abort(self, principal: ProviderPrincipal, claim: OAuthClaim) -> str:
        with self._lock:
            attempt = self._claims.pop(claim.claim_id, None)
            if attempt is None or attempt.principal != principal:
                raise ConnectionNotFoundError
            return attempt.adapter_id

    def cancel(self, principal: ProviderPrincipal, state: str) -> str:
        with self._lock:
            attempt = self._attempts.get(_state_digest(state))
            if attempt is None or attempt.principal != principal:
                raise ConnectionNotFoundError
            del self._attempts[attempt.state_digest]
            return attempt.adapter_id


def _state_digest(state: str) -> str:
    return sha256(state.encode("ascii")).hexdigest()


def _safe_redirect(value: str) -> bool:
    parsed = urlparse(value)
    return (
        bool(value)
        and value.startswith("/")
        and not value.startswith("//")
        and not parsed.scheme
        and not parsed.netloc
    )


OAuthAttempt = _OAuthAttempt
OAuthRequest = _OAuthRequest
ProviderOAuthState = _ProviderOAuthState
