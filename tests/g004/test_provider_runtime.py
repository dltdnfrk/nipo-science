from __future__ import annotations

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta
from inspect import signature
from threading import Event, Thread
from typing import TYPE_CHECKING, cast, final, override

if TYPE_CHECKING:
    from collections.abc import Callable


import pytest
from services.api import provider_runtime as runtime_facade
from services.api import provider_runtime_configuration as runtime_configuration
from services.api import provider_runtime_contracts as runtime_contracts
from services.api.provider_model_id import PROVIDER_MODEL_ID_MAX_CHARACTERS
from services.api.provider_qualification import (
    QualificationResult,
    evaluate_profile,
)
from services.api.provider_runtime import (
    ERROR_REVISION_CONFLICT,
    PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    ConnectionNotFoundError,
    OfficialOAuthCompletion,
    ProviderCleanupPolicy,
    ProviderCleanupReceipt,
    ProviderConnection,
    ProviderConnectionSnapshot,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderRevokeMutation,
    ProviderRuntimeError,
    ProviderRuntimeIdentity,
    ProviderRuntimeService,
    ProviderUpsertControl,
)

from .provider_qualification_support import TestQualificationAuthority
from .test_provider_qualification import synthetic_profile

_PERSISTENCE_ERROR = "persistence_failed"
_RUNTIME_IDENTITY = ProviderRuntimeIdentity(
    "openai_codex",
    "codex-cli-0.144.1",
    "a" * 64,
)
_AUTHORITY = TestQualificationAuthority(datetime(2026, 7, 13, tzinfo=UTC))
_OUT_OF_CONTRACT_MODEL_ID = "m" * (PROVIDER_MODEL_ID_MAX_CHARACTERS + 1)


def _persistence_failure() -> ProviderRuntimeError:
    return ProviderRuntimeError(_PERSISTENCE_ERROR)


class Clock:
    def __init__(self) -> None:
        self.now: datetime = datetime(2026, 7, 13, tzinfo=UTC)

    def __call__(self) -> datetime:
        return self.now


def _service(clock: Clock | None = None) -> ProviderRuntimeService:
    counter = iter(range(1, 100))
    return ProviderRuntimeService(
        clock or Clock(),
        lambda: next(counter).to_bytes(32),
        lambda: f"connection-{next(counter)}",
        persistence=_TestProviderPersistence(),
        cleanup_policy=replace(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
            runtime_identity=_RUNTIME_IDENTITY,
            qualification_verifier=_AUTHORITY.verifier,
        ),
    )


def test_provider_runtime_public_classes_keep_consumer_identity() -> None:
    # Given: production consumers import provider contracts through the facade.
    facade_contracts = (
        runtime_facade.ConnectionNotFoundError,
        runtime_facade.DispatchAuthorization,
        runtime_facade.OAuthClaim,
        runtime_facade.OAuthInitiation,
        runtime_facade.OfficialOAuthCompletion,
        runtime_facade.ProviderCleanupReceipt,
        runtime_facade.ProviderCompletionAdoption,
        runtime_facade.ProviderConnection,
        runtime_facade.ProviderConnectionSnapshot,
        runtime_facade.ProviderPersistence,
        runtime_facade.ProviderPrincipal,
        runtime_facade.ProviderQualificationIdentity,
        runtime_facade.ProviderRevokeMutation,
        runtime_facade.ProviderRuntimeError,
        runtime_facade.ProviderRuntimeIdentity,
        runtime_facade.ProviderUpsertControl,
    )

    # When: those imports are compared with the canonical source classes.
    source_contracts = (
        runtime_contracts.ConnectionNotFoundError,
        runtime_contracts.DispatchAuthorization,
        runtime_contracts.OAuthClaim,
        runtime_contracts.OAuthInitiation,
        runtime_contracts.OfficialOAuthCompletion,
        runtime_contracts.ProviderCleanupReceipt,
        runtime_contracts.ProviderCompletionAdoption,
        runtime_contracts.ProviderConnection,
        runtime_contracts.ProviderConnectionSnapshot,
        runtime_contracts.ProviderPersistence,
        runtime_contracts.ProviderPrincipal,
        runtime_contracts.ProviderQualificationIdentity,
        runtime_contracts.ProviderRevokeMutation,
        runtime_contracts.ProviderRuntimeError,
        runtime_contracts.ProviderRuntimeIdentity,
        runtime_contracts.ProviderUpsertControl,
    )

    # Then: no compatibility wrapper or duplicate class definition was introduced.
    assert all(
        facade is source
        for facade, source in zip(facade_contracts, source_contracts, strict=True)
    )
    assert runtime_facade.ProviderAdapter is runtime_configuration.ProviderAdapter
    assert (
        runtime_facade.ProviderCleanupPolicy
        is runtime_configuration.ProviderCleanupPolicy
    )


class _TestProviderPersistence(ProviderPersistence):
    """Test-local persistence fake that records writes and cleanup receipts."""

    def __init__(self) -> None:
        self.fail_upsert: bool = False
        self.fail_revoke: bool = False
        self.upserts: list[
            tuple[ProviderPrincipal, ProviderConnection, str, int | None]
        ] = []
        self.revocations: list[tuple[ProviderPrincipal, ProviderRevokeMutation]] = []
        self.discarded_runtime_home_refs: list[str] = []
        self.superseded_runtime_home_refs: list[str] = []
        self.snapshots: dict[
            ProviderPrincipal, dict[str, ProviderConnectionSnapshot]
        ] = {}

    @override
    def load(
        self, principal: ProviderPrincipal
    ) -> tuple[ProviderConnectionSnapshot, ...]:
        return tuple(self.snapshots.get(principal, {}).values())

    @override
    def upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        control: ProviderUpsertControl,
    ) -> None:
        expected_revision = control.expected_revision
        superseded_runtime_home_ref = control.superseded_runtime_home_ref
        if self.fail_upsert:
            raise _persistence_failure()
        current = self.snapshots.get(principal, {}).get(connection.connection_id)
        durable_revision = None if current is None else current.connection.revision
        if durable_revision != expected_revision:
            raise ProviderRuntimeError(ERROR_REVISION_CONFLICT)
        if superseded_runtime_home_ref is not None:
            if (
                current is None
                or current.runtime_home_ref != superseded_runtime_home_ref
            ):
                raise ProviderRuntimeError(ERROR_REVISION_CONFLICT)
            self.superseded_runtime_home_refs.append(superseded_runtime_home_ref)
        self.upserts.append(
            (principal, connection, runtime_home_ref, expected_revision)
        )
        self.snapshots.setdefault(principal, {})[connection.connection_id] = (
            ProviderConnectionSnapshot(
                connection,
                runtime_home_ref,
                completion_adoption=control.completion_adoption,
            )
        )

    @override
    def confirm_completion_adoption(
        self, principal: ProviderPrincipal, connection_id: str, staging_lease_id: str
    ) -> None:
        snapshot = self.snapshots.get(principal, {}).get(connection_id)
        if (
            snapshot is None
            or snapshot.completion_adoption is None
            or snapshot.completion_adoption.staging_lease_id != staging_lease_id
        ):
            raise ProviderRuntimeError(ERROR_REVISION_CONFLICT)
        self.snapshots[principal][connection_id] = replace(
            snapshot, completion_adoption=None
        )

    @override
    def discard_runtime_home(
        self, principal: ProviderPrincipal, runtime_home_ref: str
    ) -> None:
        if any(
            snapshot.runtime_home_ref == runtime_home_ref
            for snapshot in self.snapshots.get(principal, {}).values()
        ):
            return
        self.discarded_runtime_home_refs.append(runtime_home_ref)

    @override
    def revoke(
        self, principal: ProviderPrincipal, mutation: ProviderRevokeMutation
    ) -> ProviderCleanupReceipt:
        if self.fail_revoke:
            raise _persistence_failure()
        current = self.snapshots.get(principal, {}).get(mutation.current.connection_id)
        if (
            current is None
            or current.connection != mutation.current
            or current.connection.revision != mutation.expected_revision
        ):
            raise ProviderRuntimeError(ERROR_REVISION_CONFLICT)
        self.revocations.append((principal, mutation))
        receipt = ProviderCleanupReceipt(
            mutation.proposed.connection_id,
            mutation.proposed.adapter_id,
            mutation.requested_at,
            mutation.destroy_by,
            mutation.requested_at,
            "test-cleanup-evidence",
        )
        self.snapshots.setdefault(principal, {})[mutation.proposed.connection_id] = (
            ProviderConnectionSnapshot(
                mutation.proposed,
                f"vault://runtime/destroyed/{mutation.proposed.connection_id}",
                receipt,
            )
        )
        return receipt


@final
class _DuplicateLoadProviderPersistence(_TestProviderPersistence):
    def __init__(self) -> None:
        super().__init__()
        self.duplicate = False

    @override
    def load(
        self, principal: ProviderPrincipal
    ) -> tuple[ProviderConnectionSnapshot, ...]:
        snapshots = super().load(principal)
        return snapshots + snapshots if self.duplicate else snapshots


@final
class _BlockingProviderPersistence(_TestProviderPersistence):
    def __init__(self) -> None:
        super().__init__()
        self.block_connection_id: str | None = None
        self.upsert_entered = Event()
        self.revoke_entered = Event()
        self.release = Event()

    @override
    def upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        control: ProviderUpsertControl,
    ) -> None:
        if connection.connection_id == self.block_connection_id:
            self.upsert_entered.set()
            assert self.release.wait(timeout=1)
        super().upsert(
            principal,
            connection,
            runtime_home_ref,
            control,
        )

    @override
    def revoke(
        self, principal: ProviderPrincipal, mutation: ProviderRevokeMutation
    ) -> ProviderCleanupReceipt:
        if mutation.current.connection_id == self.block_connection_id:
            self.revoke_entered.set()
            assert self.release.wait(timeout=1)
        return super().revoke(principal, mutation)


def test_provider_runtime_requires_explicit_persistence() -> None:
    with pytest.raises(TypeError, match="persistence"):
        _ = signature(ProviderRuntimeService).bind(Clock())


def test_provider_runtime_requires_explicit_cleanup_policy() -> None:
    with pytest.raises(TypeError, match="cleanup_policy"):
        _ = signature(ProviderRuntimeService).bind(
            Clock(), persistence=_TestProviderPersistence()
        )


@pytest.mark.parametrize("window", [timedelta(0), -timedelta(microseconds=1)])
def test_cleanup_policy_requires_a_positive_destruction_window(
    window: timedelta,
) -> None:
    with pytest.raises(ProviderRuntimeError, match="invalid_cleanup_policy"):
        _ = ProviderCleanupPolicy(runtime_home_destruction_window=window)


def test_cleanup_policy_controls_runtime_home_destruction_deadline() -> None:
    clock = Clock()
    persistence = _TestProviderPersistence()
    service = ProviderRuntimeService(
        clock,
        persistence=persistence,
        cleanup_policy=ProviderCleanupPolicy(
            runtime_home_destruction_window=timedelta(hours=2)
        ),
    )
    owner = _principal()
    connection = _connected(service, owner)

    receipt = service.revoke(owner, connection.connection_id)

    expected = clock.now + timedelta(hours=2)
    assert receipt.destroy_by == expected
    assert persistence.revocations[0][1].destroy_by == expected


def test_completed_cleanup_after_policy_deadline_remains_terminal_after_restart() -> (
    None
):
    clock = Clock()
    persistence = _TestProviderPersistence()
    policy = ProviderCleanupPolicy(runtime_home_destruction_window=timedelta(hours=2))
    service = ProviderRuntimeService(
        clock, persistence=persistence, cleanup_policy=policy
    )
    owner = _principal()
    connection = _connected(service, owner)
    receipt = service.revoke(owner, connection.connection_id)
    snapshot = persistence.snapshots[owner][connection.connection_id]
    clock.now = receipt.destroy_by + timedelta(microseconds=1)
    persistence.snapshots[owner][connection.connection_id] = ProviderConnectionSnapshot(
        snapshot.connection,
        snapshot.runtime_home_ref,
        ProviderCleanupReceipt(
            receipt.connection_id,
            receipt.adapter_id,
            receipt.requested_at,
            receipt.destroy_by,
            clock.now,
            receipt.evidence_sha256,
        ),
    )
    restarted = ProviderRuntimeService(
        clock, persistence=persistence, cleanup_policy=policy
    )

    assert restarted.list_connections(owner) == (snapshot.connection,)


def test_scheduled_cleanup_at_policy_deadline_fails_closed() -> None:
    clock = Clock()
    persistence = _TestProviderPersistence()
    policy = ProviderCleanupPolicy(runtime_home_destruction_window=timedelta(hours=2))
    service = ProviderRuntimeService(
        clock, persistence=persistence, cleanup_policy=policy
    )
    owner = _principal()
    connection = _connected(service, owner)
    receipt = service.revoke(owner, connection.connection_id)
    snapshot = persistence.snapshots[owner][connection.connection_id]
    clock.now = receipt.destroy_by
    persistence.snapshots[owner][connection.connection_id] = ProviderConnectionSnapshot(
        snapshot.connection,
        snapshot.runtime_home_ref,
        cleanup_requested_at=receipt.requested_at,
        destroy_by=receipt.destroy_by,
    )
    restarted = ProviderRuntimeService(
        clock, persistence=persistence, cleanup_policy=policy
    )

    with pytest.raises(ProviderRuntimeError, match="provider_cleanup_overdue"):
        _ = restarted.list_connections(owner)


def test_provider_connections_rehydrate_after_runtime_restart() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    first = ProviderRuntimeService(
        Clock(),
        persistence=persistence,
        cleanup_policy=replace(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
            runtime_identity=_RUNTIME_IDENTITY,
        ),
    )
    connected = _connected(first, owner)
    selected = first.select_model(
        owner,
        connected.connection_id,
        "codex-mini",
        expected_revision=connected.revision,
    )

    restarted = ProviderRuntimeService(
        Clock(),
        persistence=persistence,
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )

    assert restarted.list_connections(owner) == (selected,)
    assert restarted.connection_detail(owner, selected.connection_id) == selected
    assert restarted.list_connections(_principal("other")) == ()


def test_second_service_refreshes_durable_revision_before_mutation() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    first = _service_with_persistence(persistence)
    second = _service_with_persistence(persistence)
    connected = _connected(first, owner)
    _ = second.select_account(owner, connected.connection_id, connected.account_id)
    selected = first.select_model(
        owner,
        connected.connection_id,
        "codex-mini",
        expected_revision=connected.revision,
    )

    updated = second.set_health(owner, connected.connection_id, "unavailable")

    assert updated.revision == selected.revision + 1
    assert updated.selected_model == selected.selected_model


def test_second_service_select_account_observes_terminal_revoke() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    revoker = _service_with_persistence(persistence)
    stale_reader = _service_with_persistence(persistence)
    connected = _connected(revoker, owner)
    _ = stale_reader.select_account(
        owner,
        connected.connection_id,
        connected.account_id,
    )
    _ = revoker.revoke(
        owner,
        connected.connection_id,
        expected_revision=connected.revision,
    )

    with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
        _ = stale_reader.select_account(
            owner,
            connected.connection_id,
            connected.account_id,
        )


def test_second_service_refreshes_durable_revision_before_revoke() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    first = _service_with_persistence(persistence)
    second = _service_with_persistence(persistence)
    connected = _connected(first, owner)
    _ = second.select_account(owner, connected.connection_id, connected.account_id)
    selected = first.select_model(
        owner,
        connected.connection_id,
        "codex-mini",
        expected_revision=connected.revision,
    )

    receipt = second.revoke(owner, connected.connection_id)

    durable = persistence.load(owner)
    assert receipt.connection_id == connected.connection_id
    assert durable[0].connection.health == "revoked"
    assert durable[0].connection.revision == selected.revision + 1


def test_reauth_completion_observes_revoke_from_second_service() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    reauth_service = _service_with_persistence(persistence)
    revoker = _service_with_persistence(persistence)
    connected = _connected(reauth_service, owner)
    pending = reauth_service.initiate_reauth(
        owner,
        connected.connection_id,
        "callback",
        "/oauth/callback",
        expected_revision=connected.revision,
    )
    current = revoker.connection_detail(owner, connected.connection_id)
    _ = revoker.revoke(
        owner,
        connected.connection_id,
        expected_revision=current.revision,
    )
    durable = persistence.load(owner)

    with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
        _ = reauth_service.complete_callback(
            owner,
            pending.state,
            "/oauth/callback",
            _completion(),
        )

    assert persistence.load(owner) == durable


def test_overlapping_reauth_rejects_the_stale_completion() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    service = _service_with_persistence(persistence)
    connected = _connected(service, owner)
    first = service.initiate_reauth(
        owner,
        connected.connection_id,
        "callback",
        "/oauth/callback",
        expected_revision=connected.revision,
    )
    first_pending = service.connection_detail(owner, connected.connection_id)
    second = service.initiate_reauth(
        owner,
        connected.connection_id,
        "callback",
        "/oauth/callback",
        expected_revision=first_pending.revision,
    )
    newest = service.complete_callback(
        owner,
        second.state,
        "/oauth/callback",
        _completion(
            vault_home_ref="vault://runtime/connection/newest",
            account_id="account-newest",
        ),
    )
    durable = persistence.load(owner)

    with pytest.raises(ProviderRuntimeError, match="revision_conflict"):
        _ = service.complete_callback(
            owner,
            first.state,
            "/oauth/callback",
            _completion(
                vault_home_ref="vault://runtime/connection/stale",
                account_id="account-stale",
            ),
        )

    assert persistence.load(owner) == durable
    assert service.connection_detail(owner, connected.connection_id) == newest
    assert persistence.discarded_runtime_home_refs == [
        "vault://runtime/connection/stale"
    ]


def test_reauth_rejects_pending_adoption_without_mutating_durable_state() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    service = _service_with_persistence(persistence)
    state = service.initiate(
        owner,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state
    connection = service.complete_callback(
        owner,
        state,
        "/oauth/callback",
        _completion(),
    )
    durable = persistence.load(owner)

    with pytest.raises(ProviderRuntimeError, match="revision_conflict"):
        _ = service.initiate_reauth(
            owner,
            connection.connection_id,
            "callback",
            "/oauth/callback",
            expected_revision=connection.revision,
        )

    assert persistence.load(owner) == durable
    assert service.connection_detail(owner, connection.connection_id) == connection


def test_provider_restart_rejects_duplicate_persistence_snapshots() -> None:
    persistence = _DuplicateLoadProviderPersistence()
    owner = _principal()
    first = ProviderRuntimeService(
        Clock(),
        persistence=persistence,
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    _ = _connected(first, owner)
    persistence.duplicate = True
    restarted = ProviderRuntimeService(
        Clock(),
        persistence=persistence,
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )

    with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
        _ = restarted.list_connections(owner)


def test_provider_restart_rejects_out_of_contract_model_snapshot() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    first = _service_with_persistence(persistence)
    connection = _connected(first, owner)
    snapshot = persistence.snapshots[owner][connection.connection_id]
    persistence.snapshots[owner][connection.connection_id] = replace(
        snapshot,
        connection=replace(
            snapshot.connection,
            eligible_models=(_OUT_OF_CONTRACT_MODEL_ID,),
        ),
    )
    restarted = _service_with_persistence(persistence)

    with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
        _ = restarted.list_connections(owner)


@final
class _ForgedQualificationResult:
    contract_valid: bool = True
    live_qualified: bool = True
    adapter: str = "openai_codex"
    operator_account_ref: str = "acct_operator_metadata"
    runtime_version: str = "codex-cli-0.144.1"
    executable_sha256: str = "a" * 64
    profile_sha256: str = "b" * 64


def _principal(user: str = "user", org: str = "org") -> ProviderPrincipal:
    return ProviderPrincipal(user, org)


def _completion(
    vault_home_ref: str = "vault://runtime/connection/one",
    account_id: str = "account-one",
    eligible_models: tuple[str, ...] = ("codex-mini", "codex-max"),
    metadata: dict[str, str] | None = None,
) -> OfficialOAuthCompletion:
    return OfficialOAuthCompletion(
        vault_home_ref,
        account_id,
        eligible_models,
        {"issuer": "official"} if metadata is None else metadata,
        "fixture-staging-lease",
        datetime(2026, 7, 13, tzinfo=UTC)
        + PROVIDER_RUNTIME_HOME_CLEANUP_POLICY.runtime_home_destruction_window,
    )


def test_completion_rejects_out_of_contract_provider_model_id() -> None:
    service = _service()
    owner = _principal()
    state = service.initiate(
        owner,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state

    with pytest.raises(ProviderRuntimeError, match="invalid_completion"):
        _ = service.complete_callback(
            owner,
            state,
            "/oauth/callback",
            _completion(eligible_models=(_OUT_OF_CONTRACT_MODEL_ID,)),
        )


def _connected(
    service: ProviderRuntimeService, principal: ProviderPrincipal
) -> ProviderConnection:
    state = service.initiate(
        principal,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state
    connection = service.complete_callback(
        principal,
        state,
        "/oauth/callback",
        _completion(),
    )
    adoption, _ = service.pending_completion_adoptions(principal)[0]
    service.confirm_completion_adoption(
        principal, connection.connection_id, adoption.staging_lease_id
    )
    return connection


def _synthetic_result() -> QualificationResult:
    return evaluate_profile(json.dumps(synthetic_profile()))


def test_provider_registry_matches_launch_requirements() -> None:
    service = _service()

    assert tuple(
        (
            adapter.adapter_id,
            adapter.required,
            adapter.launch_default,
            adapter.connectable,
            adapter.disabled_reason,
        )
        for adapter in service.adapters()
    ) == (
        ("openai_codex", True, True, True, None),
        ("anthropic_claude_code", False, False, False, "not_qualified"),
        ("xai_grok_build", False, False, False, "not_qualified"),
        ("moonshot_kimi_code", False, False, False, "not_qualified"),
        ("zai_glm", False, False, False, "unsupported_auth"),
    )


def test_callback_and_device_completion_are_single_use() -> None:
    service = _service()
    principal = _principal()
    callback = _connected(service, principal)
    assert callback.account_id == "account-one"
    state = service.initiate(
        principal,
        "openai_codex",
        "device",
        "/oauth/device",
    ).state
    device = service.complete_device(principal, state, _completion())
    assert device.adapter_id == "openai_codex"
    with pytest.raises(ConnectionNotFoundError):
        _ = service.complete_device(principal, state, _completion())


def test_state_bindings_expiry_and_cancellation_are_enforced() -> None:
    clock = Clock()
    service = _service(clock)
    owner = _principal()
    state = service.initiate(
        owner,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state
    with pytest.raises(ConnectionNotFoundError):
        _ = service.complete_callback(
            _principal("other"),
            state,
            "/oauth/callback",
            _completion(),
        )
    connection = service.complete_callback(
        owner,
        state,
        "/oauth/callback",
        _completion(),
    )
    assert connection.adapter_id == "openai_codex"
    with pytest.raises(ConnectionNotFoundError):
        _ = service.complete_callback(owner, state, "/oauth/callback", _completion())
    state = service.initiate(
        owner,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state
    with pytest.raises(ProviderRuntimeError, match="oauth_binding_mismatch"):
        _ = service.complete_callback(owner, state, "/other", _completion())
    state = service.initiate(
        owner,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state
    clock.now += timedelta(minutes=11)
    with pytest.raises(ProviderRuntimeError, match="oauth_expired"):
        _ = service.complete_callback(owner, state, "/oauth/callback", _completion())
    clock.now -= timedelta(minutes=11)
    state = service.initiate(
        owner,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state
    service.cancel_pending(owner, state)
    with pytest.raises(ConnectionNotFoundError):
        _ = service.complete_callback(owner, state, "/oauth/callback", _completion())


def test_cross_tenant_is_hidden_and_token_material_and_unsafe_refs_are_rejected() -> (
    None
):
    service = _service()
    owner = _principal()
    connection = _connected(service, owner)
    assert service.list_connections(_principal("user", "other")) == ()
    with pytest.raises(ConnectionNotFoundError):
        _ = service.connection_detail(
            _principal("user", "other"), connection.connection_id
        )
    completions = (
        _completion(metadata={"access_token": "value"}),
        _completion(vault_home_ref="https://example.test/ref"),
    )
    for completion in completions:
        state = service.initiate(
            owner,
            "openai_codex",
            "callback",
            "/oauth/callback",
        ).state
        with pytest.raises(ProviderRuntimeError):
            _ = service.complete_callback(
                owner,
                state,
                "/oauth/callback",
                completion,
            )


def test_qualification_health_reauth_revoke_and_explicit_dispatch() -> None:
    persistence = _TestProviderPersistence()
    service = _service_with_persistence(persistence)
    owner = _principal()
    connection = _connected(service, owner)
    _ = service.select_account(owner, connection.connection_id, "account-one")
    _ = service.select_model(owner, connection.connection_id, "codex-mini")
    with pytest.raises(ProviderRuntimeError, match="qualification_required"):
        _ = service.set_health(owner, connection.connection_id, "healthy")
    with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
        _ = service.dispatch_authorization(
            owner, connection.connection_id, "codex-mini"
        )
    _ = service.set_health(owner, connection.connection_id, "quota_exhausted")
    with pytest.raises(ProviderRuntimeError, match="quota_exhausted"):
        _ = service.dispatch_authorization(
            owner, connection.connection_id, "codex-mini"
        )
    with pytest.raises(ProviderRuntimeError, match="model_unavailable"):
        _ = service.select_model(owner, connection.connection_id, "codex-unknown")
    reauth = service.initiate_reauth(
        owner,
        connection.connection_id,
        "callback",
        "/oauth/callback",
    )
    with pytest.raises(ProviderRuntimeError, match="reauth_required"):
        _ = service.dispatch_authorization(
            owner, connection.connection_id, "codex-mini"
        )
    _ = service.complete_callback(
        owner,
        reauth.state,
        "/oauth/callback",
        _completion(vault_home_ref="vault://runtime/connection/two"),
    )
    assert persistence.superseded_runtime_home_refs == [
        "vault://runtime/connection/one"
    ]
    _ = service.revoke(owner, connection.connection_id)
    with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
        _ = service.dispatch_authorization(
            owner, connection.connection_id, "codex-mini"
        )
    assert all(
        "vault" not in item and "token" not in item
        for receipt_item in service.audit_receipts()
        for item in receipt_item
    )


def test_same_ref_reauthentication_never_destroys_the_active_home() -> None:
    persistence = _TestProviderPersistence()
    service = _service_with_persistence(persistence)
    owner = _principal()
    connection = _connected(service, owner)
    reauth = service.initiate_reauth(
        owner, connection.connection_id, "callback", "/oauth/callback"
    )

    current = service.complete_callback(
        owner, reauth.state, "/oauth/callback", _completion()
    )

    assert current.connection_id == connection.connection_id
    assert persistence.superseded_runtime_home_refs == []


def test_disabled_adapters_and_non_live_results_fail_closed() -> None:
    service = _service()
    owner = _principal()
    for adapter in (
        "anthropic_claude_code",
        "xai_grok_build",
        "moonshot_kimi_code",
        "zai_glm",
    ):
        with pytest.raises(ProviderRuntimeError, match="adapter_disabled"):
            _ = service.initiate(owner, adapter, "callback", "/oauth/callback")
    connection = _connected(service, owner)
    result = _synthetic_result()
    assert result.contract_valid
    assert not result.live_qualified
    with pytest.raises(ProviderRuntimeError, match="qualification_required"):
        _ = service.record_qualification(
            owner,
            connection.connection_id,
            cast("QualificationResult", cast("object", _ForgedQualificationResult())),
        )
    with pytest.raises(ProviderRuntimeError, match="qualification_required"):
        _ = service.record_qualification(owner, connection.connection_id, result)
    manufactured = replace(
        result,
        live_qualified=True,
    )
    with pytest.raises(ProviderRuntimeError, match="qualification_required"):
        _ = service.record_qualification(
            owner,
            connection.connection_id,
            manufactured,
        )


def test_ordinary_runtime_monkeypatch_cannot_manufacture_live_qualification(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = _service()
    owner = _principal()
    connection = _connected(service, owner)

    def issued(*unused_values: object) -> bool:
        del unused_values
        return True

    monkeypatch.setattr(
        "services.api.provider_runtime.qualification_result_is_verified",
        issued,
    )
    result = cast(
        "QualificationResult",
        cast("object", _ForgedQualificationResult()),
    )

    with pytest.raises(ProviderRuntimeError, match="qualification_required"):
        _ = service.record_qualification(
            owner,
            connection.connection_id,
            result,
        )


def test_concurrent_completion_consumes_one_state_once() -> None:
    service = _service()
    owner = _principal()
    state = service.initiate(
        owner,
        "openai_codex",
        "callback",
        "/oauth/callback",
    ).state
    outcomes: list[str] = []

    def complete() -> None:
        try:
            _ = service.complete_callback(
                owner, state, "/oauth/callback", _completion()
            )
            outcomes.append("completed")
        except ConnectionNotFoundError:
            outcomes.append("rejected")

    threads = [Thread(target=complete), Thread(target=complete)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert sorted(outcomes) == ["completed", "rejected"]


def test_persistence_failures_do_not_publish_connection_mutations() -> None:
    clock = Clock()
    persistence = _TestProviderPersistence()
    counter = iter(range(1, 100))
    service = ProviderRuntimeService(
        clock,
        lambda: next(counter).to_bytes(32),
        lambda: f"connection-{next(counter)}",
        persistence=persistence,
        cleanup_policy=PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
    )
    owner = _principal()

    persistence.fail_upsert = True
    state = service.initiate(owner, "openai_codex", "callback", "/oauth/callback").state
    with pytest.raises(ProviderRuntimeError, match=_PERSISTENCE_ERROR):
        _ = service.complete_callback(owner, state, "/oauth/callback", _completion())
    assert service.list_connections(owner) == ()

    persistence.fail_upsert = False
    connection = _connected(service, owner)
    _ = service.select_model(owner, connection.connection_id, "codex-mini")
    healthy = service.connection_detail(owner, connection.connection_id)

    def assert_unchanged(action: Callable[[], object]) -> None:
        before = service.connection_detail(owner, connection.connection_id)
        with pytest.raises(ProviderRuntimeError, match=_PERSISTENCE_ERROR):
            _ = action()
        assert service.connection_detail(owner, connection.connection_id) == before

    persistence.fail_upsert = True
    assert_unchanged(
        lambda: service.select_model(owner, connection.connection_id, "codex-max")
    )
    assert_unchanged(
        lambda: service.set_health(owner, connection.connection_id, "reauth_required")
    )
    assert_unchanged(
        lambda: service.initiate_reauth(
            owner, connection.connection_id, "callback", "/oauth/callback"
        )
    )
    persistence.fail_upsert = False
    reauth = service.initiate_reauth(
        owner,
        connection.connection_id,
        "callback",
        "/oauth/callback",
    )
    pending = service.connection_detail(owner, connection.connection_id)
    assert pending.revision == healthy.revision + 1
    persistence.fail_upsert = True
    with pytest.raises(ProviderRuntimeError, match=_PERSISTENCE_ERROR):
        _ = service.complete_callback(
            owner, reauth.state, "/oauth/callback", _completion(account_id="new")
        )
    assert service.connection_detail(owner, connection.connection_id) == pending

    persistence.fail_upsert = False
    persistence.fail_revoke = True
    assert_unchanged(lambda: service.revoke(owner, connection.connection_id))
    with pytest.raises(ConnectionNotFoundError):
        _ = service.cleanup_receipt(owner, connection.connection_id)


def _service_with_persistence(
    persistence: ProviderPersistence,
) -> ProviderRuntimeService:
    counter = iter(range(1, 100))
    return ProviderRuntimeService(
        Clock(),
        lambda: next(counter).to_bytes(32),
        lambda: f"connection-{next(counter)}",
        persistence=persistence,
        cleanup_policy=replace(
            PROVIDER_RUNTIME_HOME_CLEANUP_POLICY,
            runtime_identity=_RUNTIME_IDENTITY,
            qualification_verifier=_AUTHORITY.verifier,
        ),
    )


def test_blocked_connection_persistence_does_not_block_other_connections() -> None:
    persistence = _BlockingProviderPersistence()
    service = _service_with_persistence(persistence)
    owner = _principal()
    connection_a = _connected(service, owner)
    connection_b = _connected(service, owner)
    persistence.block_connection_id = connection_a.connection_id
    first_finished = Event()
    second_finished = Event()
    outcomes: list[str] = []

    def mutate_a() -> None:
        try:
            _ = service.select_model(
                owner,
                connection_a.connection_id,
                "codex-mini",
                expected_revision=connection_a.revision,
            )
            outcomes.append("first_updated")
        finally:
            first_finished.set()

    def stale_mutate_a() -> None:
        try:
            _ = service.select_model(
                owner,
                connection_a.connection_id,
                "codex-max",
                expected_revision=connection_a.revision,
            )
        except ProviderRuntimeError as error:
            outcomes.append(error.code)
        finally:
            second_finished.set()

    first = Thread(target=mutate_a)
    first.start()
    assert persistence.upsert_entered.wait(timeout=1)
    second = Thread(target=stale_mutate_a)
    second.start()
    assert not second_finished.wait(timeout=0.05)

    assert service.connection_detail(owner, connection_b.connection_id) == connection_b
    updated_b = service.select_model(
        owner,
        connection_b.connection_id,
        "codex-mini",
        expected_revision=connection_b.revision,
    )
    assert updated_b.revision == connection_b.revision + 1

    persistence.release.set()
    assert first_finished.wait(timeout=1)
    assert second_finished.wait(timeout=1)
    first.join()
    second.join()
    assert sorted(outcomes) == ["first_updated", "revision_conflict"]


def test_blocked_revoke_destruction_does_not_block_other_connections() -> None:
    persistence = _BlockingProviderPersistence()
    service = _service_with_persistence(persistence)
    owner = _principal()
    connection_a = _connected(service, owner)
    connection_b = _connected(service, owner)
    persistence.block_connection_id = connection_a.connection_id
    finished = Event()
    receipts: list[ProviderCleanupReceipt] = []

    def revoke_a() -> None:
        try:
            receipts.append(
                service.revoke(
                    owner,
                    connection_a.connection_id,
                    expected_revision=connection_a.revision,
                )
            )
        finally:
            finished.set()

    thread = Thread(target=revoke_a)
    thread.start()
    assert persistence.revoke_entered.wait(timeout=1)

    dispatch_finished = Event()
    dispatch_errors: list[str] = []

    def dispatch_a() -> None:
        try:
            _ = service.dispatch_authorization(
                owner, connection_a.connection_id, "codex-mini"
            )
        except ProviderRuntimeError as error:
            dispatch_errors.append(error.code)
        finally:
            dispatch_finished.set()

    dispatch = Thread(target=dispatch_a)
    dispatch.start()
    assert not dispatch_finished.wait(timeout=0.05)

    assert service.connection_detail(owner, connection_b.connection_id) == connection_b
    updated_b = service.set_health(
        owner,
        connection_b.connection_id,
        "unavailable",
        expected_revision=connection_b.revision,
    )
    assert updated_b.revision == connection_b.revision + 1

    persistence.release.set()
    assert finished.wait(timeout=1)
    assert dispatch_finished.wait(timeout=1)
    thread.join()
    dispatch.join()
    assert receipts[0].connection_id == connection_a.connection_id
    assert dispatch_errors == ["provider_unavailable"]


def test_cleanup_receipt_survives_runtime_restart() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    first = _service_with_persistence(persistence)
    connection = _connected(first, owner)
    receipt = first.revoke(owner, connection.connection_id)

    restarted = _service_with_persistence(persistence)

    assert restarted.cleanup_receipt(owner, connection.connection_id) == receipt
    with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
        _ = restarted.dispatch_authorization(
            owner, connection.connection_id, "codex-mini"
        )


def test_revoked_connection_is_a_terminal_state_across_restart() -> None:
    persistence = _TestProviderPersistence()
    owner = _principal()
    service = _service_with_persistence(persistence)
    connection = _connected(service, owner)
    pending = service.initiate_reauth(
        owner,
        connection.connection_id,
        "callback",
        "/oauth/callback",
        expected_revision=connection.revision,
    )
    current = service.connection_detail(owner, connection.connection_id)
    _ = service.revoke(
        owner,
        connection.connection_id,
        expected_revision=current.revision,
    )
    durable = persistence.load(owner)

    for runtime in (service, _service_with_persistence(persistence)):
        with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
            _ = runtime.select_model(owner, connection.connection_id, "codex-mini")
        with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
            _ = runtime.set_health(owner, connection.connection_id, "unavailable")
        with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
            _ = runtime.initiate_reauth(
                owner,
                connection.connection_id,
                "callback",
                "/oauth/callback",
            )
        assert persistence.load(owner) == durable

    with pytest.raises(ProviderRuntimeError, match="provider_unavailable"):
        _ = service.complete_callback(
            owner,
            pending.state,
            "/oauth/callback",
            _completion(),
        )
    assert persistence.load(owner) == durable


def test_missing_connection_mutations_do_not_retain_keyed_locks() -> None:
    service = _service()
    owner = _principal()

    assert service.active_connection_lock_count() == 0
    for _ in range(3):
        with pytest.raises(ConnectionNotFoundError):
            _ = service.select_model(owner, "missing", "codex-mini")
        assert service.active_connection_lock_count() == 0


def test_foreign_mutation_does_not_wait_for_owner_connection_lock() -> None:
    persistence = _BlockingProviderPersistence()
    service = _service_with_persistence(persistence)
    owner = _principal()
    foreign = _principal("foreign")
    connection = _connected(service, owner)
    persistence.block_connection_id = connection.connection_id
    owner_finished = Event()
    foreign_finished = Event()
    foreign_errors: list[ConnectionNotFoundError] = []

    def mutate_owner() -> None:
        try:
            _ = service.select_model(
                owner,
                connection.connection_id,
                "codex-mini",
                expected_revision=connection.revision,
            )
        finally:
            owner_finished.set()

    def mutate_foreign() -> None:
        try:
            _ = service.select_model(foreign, connection.connection_id, "codex-mini")
        except ConnectionNotFoundError as error:
            foreign_errors.append(error)
        finally:
            foreign_finished.set()

    owner_thread = Thread(target=mutate_owner)
    owner_thread.start()
    assert persistence.upsert_entered.wait(timeout=1)
    assert service.active_connection_lock_count() == 1

    foreign_thread = Thread(target=mutate_foreign)
    foreign_thread.start()
    assert foreign_finished.wait(timeout=0.05)
    foreign_thread.join()
    assert len(foreign_errors) == 1
    assert isinstance(foreign_errors[0], ConnectionNotFoundError)
    assert service.active_connection_lock_count() == 1

    persistence.release.set()
    assert owner_finished.wait(timeout=1)
    owner_thread.join()
    assert service.active_connection_lock_count() == 0
