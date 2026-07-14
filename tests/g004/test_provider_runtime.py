from __future__ import annotations

import json
from datetime import UTC, datetime, timedelta
from inspect import signature
from threading import Event, Thread
from typing import TYPE_CHECKING, cast, final, override

if TYPE_CHECKING:
    from collections.abc import Callable


import pytest
from services.api.provider_qualification import (
    QualificationDecision,
    QualificationResult,
    evaluate_profile,
)
from services.api.provider_runtime import (
    ConnectionNotFoundError,
    OfficialOAuthCompletion,
    ProviderCleanupReceipt,
    ProviderConnection,
    ProviderPersistence,
    ProviderPrincipal,
    ProviderRevokeMutation,
    ProviderRuntimeError,
    ProviderRuntimeService,
)

from .test_provider_qualification import synthetic_profile

_PERSISTENCE_ERROR = "persistence_failed"


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

    @override
    def upsert(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        expected_revision: int | None,
    ) -> None:
        if self.fail_upsert:
            raise _persistence_failure()
        self.upserts.append(
            (principal, connection, runtime_home_ref, expected_revision)
        )

    @override
    def revoke(
        self, principal: ProviderPrincipal, mutation: ProviderRevokeMutation
    ) -> ProviderCleanupReceipt:
        if self.fail_revoke:
            raise _persistence_failure()
        self.revocations.append((principal, mutation))
        return ProviderCleanupReceipt(
            mutation.proposed.connection_id,
            mutation.proposed.adapter_id,
            mutation.requested_at,
            mutation.destroy_by,
            mutation.requested_at,
            "test-cleanup-evidence",
        )

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
        expected_revision: int | None,
    ) -> None:
        if connection.connection_id == self.block_connection_id:
            self.upsert_entered.set()
            assert self.release.wait(timeout=1)
        super().upsert(principal, connection, runtime_home_ref, expected_revision)

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


@final
class _ForgedQualificationResult:
    contract_valid: bool = True
    live_qualified: bool = True
    adapter: str = "openai_codex"
    account_ref: str = "account-one"

    def is_evaluator_issued(self) -> bool:
        return True


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
    return service.complete_callback(
        principal,
        state,
        "/oauth/callback",
        _completion(),
    )


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


def test_cross_tenant_is_hidden_and_token_material_and_unsafe_refs_are_rejected() -> None:
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
    service = _service()
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
    _ = service.complete_callback(owner, reauth.state, "/oauth/callback", _completion())
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
    with pytest.raises(TypeError, match="issued only by evaluate_profile"):
        _ = QualificationResult(
            decision=QualificationDecision(
                contract_valid=True,
                live_qualified=True,
                profile_sha256="digest",
                evidence_kind="captured_live_profile",
                adapter="openai_codex",
                account_ref="account-one",
                runtime_version="runtime",
            ),
            seal=object(),
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
            _ = service.complete_callback(owner, state, "/oauth/callback", _completion())
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
    )
    owner = _principal()

    persistence.fail_upsert = True
    state = service.initiate(
        owner, "openai_codex", "callback", "/oauth/callback"
    ).state
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
        lambda: service.select_model(
            owner, connection.connection_id, "codex-max"
        )
    )
    assert_unchanged(
        lambda: service.set_health(
            owner, connection.connection_id, "reauth_required"
        )
    )
    assert_unchanged(
        lambda: service.initiate_reauth(
            owner, connection.connection_id, "callback", "/oauth/callback"
        )
    )
    reauth = service.initiate(
        owner,
        "openai_codex",
        "callback",
        "/oauth/callback",
        connection.connection_id,
    )
    with pytest.raises(ProviderRuntimeError, match=_PERSISTENCE_ERROR):
        _ = service.complete_callback(
            owner, reauth.state, "/oauth/callback", _completion(account_id="new")
        )
    assert service.connection_detail(owner, connection.connection_id) == healthy

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
    thread.join()
    assert receipts[0].connection_id == connection_a.connection_id


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
