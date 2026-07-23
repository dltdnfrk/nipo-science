from __future__ import annotations

from dataclasses import dataclass, field, replace
from datetime import UTC, datetime, timedelta
from typing import Final, override

import pytest

from services.api.provider_postgres import (
    PostgresProviderPersistence,
    ProviderConnection,
    ProviderPrincipal,
    ProviderRevokeMutation,
    ProviderRuntimeError,
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

PROVIDER_A: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e44"
PROVIDER_B: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e45"
SOURCE_REF: Final = "vault://runtime/revoke-authority-source"
PREDECESSOR_REF: Final = "vault://runtime/revoke-authority-predecessor"
TOMBSTONE_REF: Final = f"vault://runtime/destroyed/{PROVIDER_A}"
EVIDENCE: Final = "b" * 64
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


def _connection() -> ProviderConnection:
    return ProviderConnection(
        connection_id=PROVIDER_A,
        adapter_id="openai_codex",
        account_id="account-a",
        eligible_models=("codex-mini",),
        selected_model=None,
        health="pending",
        cleanup_verified=False,
        qualified_live=False,
        created_at=_clock(),
        revision=1,
        qualification=None,
    )


def _revoke(destroyer: RuntimeHomeDestroyer) -> None:
    current = _connection()
    mutation = ProviderRevokeMutation(
        current,
        replace(current, health="revoked", revision=2),
        SOURCE_REF,
        1,
        _clock(),
        _clock() + timedelta(hours=1),
    )
    persistence = PostgresProviderPersistence(
        database_url_asyncpg(),
        destroyer,
        clock=_clock,
        cleanup_window=timedelta(hours=1),
    )
    _ = persistence.revoke(ProviderPrincipal(USER_A, ORG_A), mutation)


def _cleanup() -> None:
    _ = psql(
        "DELETE FROM provider_runtime_home_cleanups WHERE "
        f"encrypted_runtime_home_ref IN ('{SOURCE_REF}', '{PREDECESSOR_REF}', "
        f"'{TOMBSTONE_REF}'); DELETE FROM provider_connections WHERE id IN "
        f"('{PROVIDER_A}', '{PROVIDER_B}')"
    )


def test_immediate_revoke_rejects_cross_requester_binding_before_destroy() -> None:
    # Given an immediate revoke source is still bound by another requester.
    seed_tenants()
    _ = psql(
        f"DELETE FROM provider_connections WHERE id IN ('{PROVIDER_A}', "
        f"'{PROVIDER_B}'); INSERT INTO provider_connections (id, org_id, "
        "requester_user_id, adapter_id, encrypted_runtime_home_ref, "
        "account_metadata, status) VALUES "
        f"('{PROVIDER_A}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{SOURCE_REF}', jsonb_build_object('revision', '1'), 'pending'), "
        f"('{PROVIDER_B}', '{ORG_B}', '{USER_B}', 'openai_codex', "
        f"'{SOURCE_REF}', jsonb_build_object('revision', '1'), 'pending')"
    )
    destroyer = _Destroyer()
    try:
        # When requester A schedules its immediate destructive revoke.
        with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
            _revoke(destroyer)
    finally:
        _cleanup()

    # Then source+tombstone reservation rejects before external destruction.
    assert destroyer.refs == []


def test_revoke_rejects_pending_superseded_cleanup_before_destroy() -> None:
    # Given the provider still owns a predecessor scheduled for destruction.
    seed_tenants()
    _ = psql(
        f"DELETE FROM provider_connections WHERE id = '{PROVIDER_A}'; INSERT INTO "
        "provider_connections (id, org_id, requester_user_id, adapter_id, "
        "encrypted_runtime_home_ref, superseded_runtime_home_ref, "
        "account_metadata, status) VALUES "
        f"('{PROVIDER_A}', '{ORG_A}', '{USER_A}', 'openai_codex', '{SOURCE_REF}', "
        f"'{PREDECESSOR_REF}', jsonb_build_object('revision', '1'), 'pending'); "
        "INSERT INTO provider_runtime_home_cleanups (org_id, requester_user_id, "
        "encrypted_runtime_home_ref, connection_id, reason, status, requested_at, "
        f"destroy_by) VALUES ('{ORG_A}', '{USER_A}', '{PREDECESSOR_REF}', "
        f"'{PROVIDER_A}', 'superseded', 'scheduled', transaction_timestamp(), "
        "transaction_timestamp() + interval '1 hour')"
    )
    destroyer = _Destroyer()
    try:
        # When revoke tries to attest complete credential-material destruction.
        with pytest.raises(ProviderRuntimeError, match="provider_persistence_failed"):
            _revoke(destroyer)
    finally:
        _cleanup()

    # Then the pending predecessor blocks revoke before the source is destroyed.
    assert destroyer.refs == []
