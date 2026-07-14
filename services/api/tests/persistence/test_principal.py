from datetime import UTC, datetime, timedelta
from uuid import UUID

import pytest

from services.api.persistence.principal import (
    PrincipalTokenError,
)
from services.api.persistence.principal import (
    TestPrincipal as Principal,
)
from services.api.persistence.principal import (
    TestPrincipalAdapter as PrincipalAdapter,
)

NOW = datetime(2026, 7, 13, tzinfo=UTC)
ORG_ID = UUID("018f0d7d-6b17-7a91-8b31-2f7331677f21")
USER_ID = UUID("018f0d7d-6b17-7a91-8b31-2f7331677f22")
SIGNING_KEY = bytes(range(32))


@pytest.fixture
def principal() -> Principal:
    return Principal(
        org_id=ORG_ID,
        user_id=USER_ID,
        issued_at=NOW,
        expires_at=NOW + timedelta(minutes=5),
    )


@pytest.fixture
def adapter() -> PrincipalAdapter:
    return PrincipalAdapter(
        environment="test",
        signing_key=SIGNING_KEY,
        active_memberships=frozenset({(ORG_ID, USER_ID)}),
    )


def test_signed_token_is_verified_when_principal_is_current(
    principal: Principal,
    adapter: PrincipalAdapter,
) -> None:
    token = adapter.encode(principal)
    decoded = adapter.decode(token, NOW)
    assert decoded == principal


def test_token_is_rejected_when_signature_is_tampered(
    principal: Principal,
    adapter: PrincipalAdapter,
) -> None:
    token = adapter.encode(principal)
    payload, signature = token.split(".", maxsplit=1)
    replacement = "A" if signature[0] != "A" else "B"
    tampered = f"{payload}.{replacement}{signature[1:]}"
    with pytest.raises(PrincipalTokenError, match="invalid"):
        _ = adapter.decode(tampered, NOW)


def test_token_is_rejected_when_principal_is_expired(
    principal: Principal,
    adapter: PrincipalAdapter,
) -> None:
    token = adapter.encode(principal)
    with pytest.raises(PrincipalTokenError, match="expired"):
        _ = adapter.decode(token, principal.expires_at + timedelta(seconds=1))


def test_adapter_is_disabled_when_environment_is_production(
    principal: Principal,
) -> None:
    adapter = PrincipalAdapter(
        environment="production",
        signing_key=SIGNING_KEY,
        active_memberships=frozenset({(ORG_ID, USER_ID)}),
    )
    with pytest.raises(PrincipalTokenError, match="disabled"):
        _ = adapter.encode(principal)


def test_adapter_is_rejected_when_signing_key_is_too_short() -> None:
    with pytest.raises(PrincipalTokenError, match="invalid"):
        _ = PrincipalAdapter(
            environment="test",
            signing_key=b"short",
            active_memberships=frozenset({(ORG_ID, USER_ID)}),
        )


def test_signed_principal_is_rejected_after_membership_is_removed(
    principal: Principal,
) -> None:
    adapter = PrincipalAdapter(
        environment="test",
        signing_key=SIGNING_KEY,
        active_memberships=frozenset(),
    )
    token = adapter.encode(principal)
    with pytest.raises(PrincipalTokenError, match="unauthorized"):
        _ = adapter.decode(token, NOW)
