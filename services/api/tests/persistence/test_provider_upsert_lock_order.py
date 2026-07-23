from __future__ import annotations

from datetime import UTC, datetime, timedelta
from typing import Final, cast

import anyio
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from services.api.provider_postgres_connections import (
    ProviderUpsertRequest,
    upsert_provider_connection,
)
from services.api.provider_runtime_contracts import (
    ProviderConnection,
    ProviderPrincipal,
)
from services.api.tests.persistence.postgres_harness import (
    database_url_asyncpg,
    psql,
)
from services.api.tests.persistence.test_rls import ORG_A, USER_A, seed_tenants

PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e43"
ACTIVE_REF: Final = "vault://runtime/upsert-lock-order-active"
REPLACEMENT_REF: Final = "vault://runtime/upsert-lock-order-replacement"
pytestmark = pytest.mark.usefixtures("migrated_database")


def _clock() -> datetime:
    return datetime(2026, 7, 16, tzinfo=UTC)


def _request() -> ProviderUpsertRequest:
    connection = ProviderConnection(
        connection_id=PROVIDER,
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
    return ProviderUpsertRequest(
        ProviderPrincipal(USER_A, ORG_A),
        connection,
        REPLACEMENT_REF,
        1,
        ACTIVE_REF,
        _clock(),
        _clock() + timedelta(hours=1),
        None,
    )


def test_cas_upsert_waits_for_provider_row_before_ref_advisory_locks() -> None:
    # Given another transaction holds the exact provider row targeted by a CAS.
    seed_tenants()
    _ = psql(
        f"DELETE FROM provider_runtime_home_cleanups WHERE "
        f"encrypted_runtime_home_ref IN ('{ACTIVE_REF}', '{REPLACEMENT_REF}'); "
        f"DELETE FROM provider_connections WHERE id = '{PROVIDER}'; INSERT INTO "
        "provider_connections (id, org_id, requester_user_id, adapter_id, "
        "encrypted_runtime_home_ref, account_metadata, status) VALUES "
        f"('{PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', '{ACTIVE_REF}', "
        "jsonb_build_object('account_id', 'account-a', 'models', "
        "jsonb_build_array('codex-mini'), 'provider', 'openai_codex', "
        "'revision', '1'), 'pending')"
    )

    async def exercise() -> tuple[str, bool]:
        engine = create_async_engine(database_url_asyncpg(), poolclass=NullPool)
        started = anyio.Event()

        async def cas_upsert() -> None:
            async with engine.begin() as database:
                _ = await database.execute(text("SET LOCAL ROLE science_workbench_app"))
                _ = await database.execute(
                    text(
                        "SELECT set_config('app.org_id', :org, true), "
                        "set_config('app.user_id', :user, true), "
                        "set_config('application_name', 'upsert-row-first', true)"
                    ),
                    {"org": ORG_A, "user": USER_A},
                )
                started.set()
                await upsert_provider_connection(_request())(database)

        async def blocked_wait_event() -> str:
            with anyio.fail_after(3):
                while True:
                    async with engine.connect() as observer:
                        result = await observer.execute(
                            text(
                                "SELECT wait_event FROM pg_stat_activity WHERE "
                                "application_name = 'upsert-row-first' AND "
                                "state = 'active'"
                            )
                        )
                        wait_event = cast("str | None", result.scalar_one_or_none())
                    if wait_event is not None:
                        return wait_event
                    await anyio.sleep(0.01)

        try:
            wait_event = ""
            advisory_available = False
            async with (
                anyio.create_task_group() as tasks,
                engine.begin() as holder,
            ):
                _ = await holder.execute(
                    text(
                        "SELECT 1 FROM provider_connections WHERE id = "
                        ":provider FOR UPDATE"
                    ),
                    {"provider": PROVIDER},
                )
                _ = tasks.start_soon(cas_upsert)
                await started.wait()
                wait_event = await blocked_wait_event()
                async with engine.begin() as observer:
                    available = await observer.execute(
                        text(
                            "SELECT pg_try_advisory_xact_lock("
                            "hashtextextended(:runtime_ref, 0))"
                        ),
                        {"runtime_ref": ACTIVE_REF},
                    )
                    advisory_available = cast("bool", available.scalar_one())
            return wait_event, advisory_available
        finally:
            await engine.dispose()

    try:
        # When the production CAS starts while that row lock is held.
        wait_event, advisory_available = anyio.run(exercise)
    finally:
        _ = psql(
            f"DELETE FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref IN ('{ACTIVE_REF}', "
            f"'{REPLACEMENT_REF}'); DELETE FROM provider_connections WHERE "
            f"id = '{PROVIDER}'"
        )

    # Then it waits on the row without holding either ref advisory lock.
    assert wait_event in {"transactionid", "tuple"}
    assert advisory_available is True
