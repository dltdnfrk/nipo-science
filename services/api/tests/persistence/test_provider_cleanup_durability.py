from __future__ import annotations

from typing import Final, cast

import anyio
import pytest
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from services.api.tests.persistence.postgres_harness import (
    database_url_asyncpg,
    psql,
)
from services.api.tests.persistence.test_rls import ORG_A, USER_A, seed_tenants

LIVE_CLOCK_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e37"
ROW_LOCK_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e38"
UNBOUND_REF: Final = "vault://runtime/cleanup-live-clock-unbound"
REVOKED_REF: Final = "vault://runtime/cleanup-live-clock-revoked"
ROW_LOCK_ACTIVE_REF: Final = "vault://runtime/cleanup-row-lock-active"
ROW_LOCK_SUPERSEDED_REF: Final = "vault://runtime/cleanup-row-lock-superseded"
EVIDENCE_SHA256: Final = "f" * 64
pytestmark = pytest.mark.usefixtures("migrated_database")


def test_completion_accepts_live_database_time_after_external_destroy() -> None:
    # Given due outbox and revoke work validated in one cleanup transaction.
    seed_tenants()
    _ = psql(
        f"DELETE FROM provider_runtime_home_cleanups WHERE "
        f"encrypted_runtime_home_ref = '{UNBOUND_REF}'; "
        f"DELETE FROM provider_connections WHERE id = '{LIVE_CLOCK_PROVIDER}'; "
        "INSERT INTO provider_connections (id, org_id, requester_user_id, "
        "adapter_id, encrypted_runtime_home_ref, account_metadata, status) VALUES "
        f"('{LIVE_CLOCK_PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{REVOKED_REF}', jsonb_build_object('cleanup_status', 'scheduled', "
        "'cleanup_requested_at', transaction_timestamp() - interval '2 hours', "
        "'destroy_by', transaction_timestamp() - interval '1 hour'), 'revoked'); "
        "INSERT INTO provider_runtime_home_cleanups (org_id, requester_user_id, "
        "encrypted_runtime_home_ref, connection_id, reason, status, requested_at, "
        "destroy_by) VALUES "
        f"('{ORG_A}', '{USER_A}', '{UNBOUND_REF}', NULL, 'unbound', 'scheduled', "
        "transaction_timestamp() - interval '2 hours', "
        "transaction_timestamp() - interval '1 hour')"
    )
    try:
        # When completion receives the live clock after irreversible destruction.
        result = psql(
            "BEGIN; SET ROLE science_workbench_provider_cleanup; "
            "SELECT (public.validate_due_provider_cleanup("
            f"'{ORG_A}', '{USER_A}', NULL::uuid, '{UNBOUND_REF}', 'unbound', "
            "transaction_timestamp()) IS NOT NULL)::text; "
            "SELECT pg_sleep(0.02); SELECT public.complete_provider_cleanup_outbox("
            f"'{ORG_A}', '{USER_A}', NULL::uuid, '{UNBOUND_REF}', 'unbound', "
            f"clock_timestamp(), '{EVIDENCE_SHA256}')::text; "
            "SELECT (public.validate_due_provider_cleanup("
            f"'{ORG_A}', '{USER_A}', '{LIVE_CLOCK_PROVIDER}', '{REVOKED_REF}', "
            "'revoke', transaction_timestamp()) IS NOT NULL)::text; "
            "SELECT pg_sleep(0.02); SELECT public.complete_provider_revoked_cleanup("
            f"'{ORG_A}', '{USER_A}', '{LIVE_CLOCK_PROVIDER}', '{REVOKED_REF}', "
            f"clock_timestamp(), '{EVIDENCE_SHA256}')::text; COMMIT"
        )
    finally:
        _ = psql(
            f"DELETE FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref = '{UNBOUND_REF}'; "
            f"DELETE FROM provider_connections WHERE id = '{LIVE_CLOCK_PROVIDER}'"
        )

    # Then neither completion fails after the external side effect is durable.
    assert tuple(line for line in result.stdout.splitlines() if line) == (
        "true",
        "true",
        "true",
        "true",
    )


def test_superseded_validation_holds_provider_row_through_completion() -> None:
    # Given exact superseded cleanup work and a competing direct app deletion.
    seed_tenants()
    _ = psql(
        f"DELETE FROM provider_runtime_home_cleanups WHERE "
        f"encrypted_runtime_home_ref = '{ROW_LOCK_SUPERSEDED_REF}'; "
        f"DELETE FROM provider_connections WHERE id = '{ROW_LOCK_PROVIDER}'; "
        "INSERT INTO provider_connections (id, org_id, requester_user_id, "
        "adapter_id, encrypted_runtime_home_ref, superseded_runtime_home_ref, "
        "account_metadata, status) VALUES "
        f"('{ROW_LOCK_PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{ROW_LOCK_ACTIVE_REF}', '{ROW_LOCK_SUPERSEDED_REF}', '{{}}', 'pending'); "
        "INSERT INTO provider_runtime_home_cleanups (org_id, requester_user_id, "
        "encrypted_runtime_home_ref, connection_id, reason, status, requested_at, "
        "destroy_by) VALUES "
        f"('{ORG_A}', '{USER_A}', '{ROW_LOCK_SUPERSEDED_REF}', "
        f"'{ROW_LOCK_PROVIDER}', 'superseded', 'scheduled', "
        "transaction_timestamp() - interval '2 hours', "
        "transaction_timestamp() - interval '1 hour')"
    )

    async def exercise() -> tuple[str, bool]:
        engine = create_async_engine(database_url_asyncpg(), poolclass=NullPool)
        started = anyio.Event()

        async def delete_provider() -> None:
            async with engine.begin() as app_database:
                _ = await app_database.execute(
                    text("SET LOCAL ROLE science_workbench_app")
                )
                _ = await app_database.execute(
                    text(
                        "SELECT set_config('app.org_id', :org, true), "
                        "set_config('app.user_id', :user, true), "
                        "set_config('application_name', "
                        "'cleanup-row-lock-probe', true)"
                    ),
                    {"org": ORG_A, "user": USER_A},
                )
                started.set()
                _ = await app_database.execute(
                    text("DELETE FROM provider_connections WHERE id = :provider"),
                    {"provider": ROW_LOCK_PROVIDER},
                )

        async def blocked_wait_event() -> str:
            with anyio.fail_after(3):
                while True:
                    async with engine.connect() as observer:
                        result = await observer.execute(
                            text(
                                "SELECT wait_event FROM pg_stat_activity WHERE "
                                "application_name = 'cleanup-row-lock-probe' AND "
                                "state = 'active'"
                            )
                        )
                        wait_event = cast("str | None", result.scalar_one_or_none())
                    if wait_event is not None:
                        return wait_event
                    await anyio.sleep(0.01)

        try:
            wait_event = ""
            completed = False
            async with (
                anyio.create_task_group() as tasks,
                engine.begin() as cleanup_database,
            ):
                    _ = await cleanup_database.execute(
                        text("SET LOCAL ROLE science_workbench_provider_cleanup")
                    )
                    validation = await cleanup_database.execute(
                        text(
                            "SELECT public.validate_due_provider_cleanup("
                            ":org, :user, :provider, :runtime_ref, 'superseded', "
                            "transaction_timestamp())"
                        ),
                        {
                            "org": ORG_A,
                            "user": USER_A,
                            "provider": ROW_LOCK_PROVIDER,
                            "runtime_ref": ROW_LOCK_SUPERSEDED_REF,
                        },
                    )
                    assert validation.scalar_one() is not None
                    _ = tasks.start_soon(delete_provider)
                    await started.wait()
                    wait_event = await blocked_wait_event()
                    assert wait_event != "advisory"
                    completion = await cleanup_database.execute(
                        text(
                            "SELECT public.complete_provider_cleanup_outbox("
                            ":org, :user, :provider, :runtime_ref, 'superseded', "
                            "clock_timestamp(), :evidence)"
                        ),
                        {
                            "org": ORG_A,
                            "user": USER_A,
                            "provider": ROW_LOCK_PROVIDER,
                            "runtime_ref": ROW_LOCK_SUPERSEDED_REF,
                            "evidence": EVIDENCE_SHA256,
                        },
                    )
                    completed = cast("bool", completion.scalar_one())
            return wait_event, completed
        finally:
            await engine.dispose()

    try:
        # When validation overlaps the competing row mutation through destruction.
        wait_event, completed = anyio.run(exercise)
    finally:
        _ = psql(
            f"DELETE FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref = '{ROW_LOCK_SUPERSEDED_REF}'; "
            f"DELETE FROM provider_connections WHERE id = '{ROW_LOCK_PROVIDER}'"
        )

    # Then direct DML waits on the row and completion cannot deadlock post-destroy.
    assert wait_event in {"transactionid", "tuple"}
    assert completed is True
