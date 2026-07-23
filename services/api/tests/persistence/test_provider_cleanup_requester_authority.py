from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from typing import Final, override

import pytest

from services.api.provider_postgres import (
    PostgresProviderPersistence,
    ProviderConnection,
    ProviderPrincipal,
    ProviderRuntimeError,
    ProviderUpsertControl,
    RuntimeHomeDestroyer,
)
from services.api.tests.persistence.postgres_harness import (
    database_url_asyncpg,
    psql,
)
from services.api.tests.persistence.test_rls import (
    ORG_A,
    ORG_B,
    USER_A,
    USER_B,
    seed_tenants,
)

PROVIDER_A: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e41"
PROVIDER_B: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e42"
SHARED_REF: Final = "vault://runtime/requester-authority-shared"
REPLACEMENT_REF: Final = "vault://runtime/requester-authority-replacement"
EVIDENCE: Final = "a" * 64
pytestmark = pytest.mark.usefixtures("migrated_database")


def _clock() -> datetime:
    return datetime(2026, 7, 16, tzinfo=UTC)


@dataclass(slots=True)
class _Destroyer(RuntimeHomeDestroyer):
    refs: list[str] = field(default_factory=list)

    @override
    def destroy(self, opaque_ref: str) -> str:
        self.refs.append(opaque_ref)
        return EVIDENCE


def _persistence(destroyer: RuntimeHomeDestroyer) -> PostgresProviderPersistence:
    return PostgresProviderPersistence(
        database_url_asyncpg(),
        destroyer,
        clock=_clock,
        cleanup_window=timedelta(hours=1),
    )


def _seed_shared_connections() -> None:
    seed_tenants()
    seeded = psql(
        "DELETE FROM provider_runtime_home_cleanups WHERE "
        f"encrypted_runtime_home_ref IN ('{SHARED_REF}', '{REPLACEMENT_REF}'); "
        f"DELETE FROM provider_connections WHERE id IN ('{PROVIDER_A}', "
        f"'{PROVIDER_B}'); INSERT INTO provider_connections (id, org_id, "
        "requester_user_id, adapter_id, encrypted_runtime_home_ref, "
        "account_metadata, status) VALUES "
        f"('{PROVIDER_A}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{SHARED_REF}', jsonb_build_object('account_id', 'account-a', "
        "'models', jsonb_build_array('codex-mini'), 'provider', "
        "'openai_codex', 'revision', '1'), 'pending'), "
        f"('{PROVIDER_B}', '{ORG_B}', '{USER_B}', 'openai_codex', "
        f"'{SHARED_REF}', jsonb_build_object('account_id', 'account-b', "
        "'models', jsonb_build_array('codex-mini'), 'provider', "
        "'openai_codex', 'revision', '1'), 'pending')",
        check=False,
    )
    assert seeded.returncode == 0, seeded.stderr


def _cleanup() -> None:
    _ = psql(
        "DELETE FROM provider_runtime_home_cleanups WHERE "
        f"encrypted_runtime_home_ref IN ('{SHARED_REF}', '{REPLACEMENT_REF}'); "
        f"DELETE FROM provider_connections WHERE id IN ('{PROVIDER_A}', "
        f"'{PROVIDER_B}')"
    )


def _seed_legacy_scheduled_revoke_collision() -> None:
    seed_tenants()
    requested = _clock().isoformat()
    deadline = (_clock() + timedelta(hours=1)).isoformat()
    seeded = psql(
        "DELETE FROM provider_runtime_home_cleanups WHERE "
        f"encrypted_runtime_home_ref = '{SHARED_REF}'; DELETE FROM "
        f"provider_connections WHERE id IN ('{PROVIDER_A}', '{PROVIDER_B}'); "
        "INSERT INTO provider_connections (id, org_id, requester_user_id, "
        "adapter_id, encrypted_runtime_home_ref, account_metadata, status, "
        "revoked_at) VALUES "
        f"('{PROVIDER_A}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{SHARED_REF}', jsonb_build_object('account_id', 'account-a', "
        "'models', jsonb_build_array('codex-mini'), 'provider', "
        "'openai_codex', 'revision', '2', 'cleanup_status', 'scheduled', "
        f"'cleanup_requested_at', '{requested}', 'destroy_by', '{deadline}'), "
        f"'revoked', '{requested}'), ('{PROVIDER_B}', '{ORG_B}', '{USER_B}', "
        f"'openai_codex', '{SHARED_REF}', jsonb_build_object('account_id', "
        "'account-b', 'models', jsonb_build_array('codex-mini'), 'provider', "
        "'openai_codex', 'revision', '1'), 'pending', NULL)",
        check=False,
    )
    assert seeded.returncode == 0, seeded.stderr


def test_unbound_cleanup_rejects_cross_requester_binding_before_destroy() -> None:
    # Given another requester has an active binding hidden by application RLS.
    _seed_shared_connections()
    _ = psql(f"DELETE FROM provider_connections WHERE id = '{PROVIDER_A}'")
    destroyer = _Destroyer()
    try:
        # When this requester tries to classify that same ref as unbound.
        with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
            _persistence(destroyer).discard_runtime_home(
                ProviderPrincipal(USER_A, ORG_A), SHARED_REF
            )
    finally:
        _cleanup()

    # Then global validation rejects the reservation before external destruction.
    assert destroyer.refs == []


def test_superseded_cleanup_rejects_cross_requester_binding_before_destroy() -> None:
    # Given two requesters share the predecessor ref but RLS exposes only one each.
    _seed_shared_connections()
    destroyer = _Destroyer()
    proposed = ProviderConnection(
        connection_id=PROVIDER_A,
        adapter_id="openai_codex",
        account_id="account-a",
        eligible_models=("codex-mini",),
        selected_model=None,
        health="pending",
        cleanup_verified=False,
        qualified_live=False,
        created_at=_clock(),
        revision=2,
        qualification=None,
    )
    try:
        # When requester A tries to reserve and destroy its predecessor.
        with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
            _persistence(destroyer).upsert(
                ProviderPrincipal(USER_A, ORG_A),
                proposed,
                REPLACEMENT_REF,
                ProviderUpsertControl(1, SHARED_REF),
            )
        row = psql(
            "SELECT encrypted_runtime_home_ref FROM provider_connections WHERE "
            f"id = '{PROVIDER_A}'"
        ).stdout.strip()
    finally:
        _cleanup()

    # Then the replacement transaction rolls back and the destroyer stays untouched.
    assert row == SHARED_REF
    assert destroyer.refs == []


def test_legacy_scheduled_revoke_validates_global_collision_before_resume() -> None:
    # Given a pre-reservation scheduled revoke collides with another requester.
    _seed_legacy_scheduled_revoke_collision()
    destroyer = _Destroyer()
    try:
        # When requester startup tries to resume the legacy scheduled cleanup.
        with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
            _ = _persistence(destroyer).load(ProviderPrincipal(USER_A, ORG_A))
    finally:
        _cleanup()

    # Then global validation refuses the candidate before external destruction.
    assert destroyer.refs == []

