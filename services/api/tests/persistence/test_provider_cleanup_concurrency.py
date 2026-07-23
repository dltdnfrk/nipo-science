from __future__ import annotations

from typing import TYPE_CHECKING, Final, cast

import anyio
import pytest
from sqlalchemy import text
from sqlalchemy.exc import DBAPIError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from services.api.tests.persistence.postgres_harness import (
    database_url_asyncpg,
    psql,
)
from services.api.tests.persistence.test_rls import (
    ORG_A,
    USER_A,
    seed_tenants,
)

if TYPE_CHECKING:
    from collections.abc import Mapping

    from sqlalchemy.sql.elements import TextClause

INSERT_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e31"
UPDATE_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e32"
DELETE_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e33"
REUSE_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e34"
UNBOUND_REF: Final = "vault://runtime/cleanup-toctou-unbound"
UPDATE_SOURCE_REF: Final = "vault://runtime/cleanup-toctou-update-source"
SUPERSEDED_REF: Final = "vault://runtime/cleanup-toctou-superseded"
DELETE_ACTIVE_REF: Final = "vault://runtime/cleanup-toctou-delete-active"
EVIDENCE_SHA256: Final = "d" * 64
TEARDOWN_SQL: Final = (
    "DELETE FROM provider_runtime_home_cleanups WHERE "
    f"encrypted_runtime_home_ref IN ('{UNBOUND_REF}', '{SUPERSEDED_REF}'); "
    "DELETE FROM provider_connections WHERE id IN "
    f"('{INSERT_PROVIDER}', '{UPDATE_PROVIDER}', '{DELETE_PROVIDER}', "
    f"'{REUSE_PROVIDER}')"
)
pytestmark = pytest.mark.usefixtures("migrated_database")


def test_cleanup_validation_serializes_direct_runtime_ref_dml() -> None:
    # Given two due cleanup reservations and direct app-role DML targets.
    seed_tenants()
    _ = psql(TEARDOWN_SQL)
    _ = psql(
        "INSERT INTO provider_connections (id, org_id, requester_user_id, "
        "adapter_id, encrypted_runtime_home_ref, superseded_runtime_home_ref, "
        "account_metadata, status) VALUES "
        f"('{UPDATE_PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{UPDATE_SOURCE_REF}', NULL, '{{}}', 'pending'), "
        f"('{DELETE_PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{DELETE_ACTIVE_REF}', '{SUPERSEDED_REF}', '{{}}', 'pending'); "
        "INSERT INTO provider_runtime_home_cleanups (org_id, requester_user_id, "
        "encrypted_runtime_home_ref, connection_id, reason, status, requested_at, "
        "destroy_by) VALUES "
        f"('{ORG_A}', '{USER_A}', '{UNBOUND_REF}', NULL, 'unbound', 'scheduled', "
        "transaction_timestamp() - interval '2 hours', "
        "transaction_timestamp() - interval '1 hour'), "
        f"('{ORG_A}', '{USER_A}', '{SUPERSEDED_REF}', '{DELETE_PROVIDER}', "
        "'superseded', 'scheduled', transaction_timestamp() - interval '2 hours', "
        "transaction_timestamp() - interval '1 hour')"
    )

    async def run_races() -> tuple[tuple[str, ...], tuple[bool, bool]]:
        engine = create_async_engine(database_url_asyncpg(), poolclass=NullPool)
        outcomes: list[str] = []

        async def execute_app_dml(
            statement: TextClause, parameters: Mapping[str, str]
        ) -> None:
            try:
                async with engine.begin() as database:
                    _ = await database.execute(
                        text("SET LOCAL ROLE science_workbench_app")
                    )
                    _ = await database.execute(
                        text(
                            "SELECT set_config('app.org_id', :org, true), "
                            "set_config('app.user_id', :user, true)"
                        ),
                        {"org": ORG_A, "user": USER_A},
                    )
                    _ = await database.execute(text("SET LOCAL lock_timeout = '250ms'"))
                    _ = await database.execute(statement, parameters)
            except DBAPIError as error:
                outcomes.append(str(error.orig))

        try:
            # When unbound cleanup authorization holds its transaction lock.
            async with engine.begin() as cleanup_database:
                _ = await cleanup_database.execute(
                    text("SET LOCAL ROLE science_workbench_provider_cleanup")
                )
                validation = await cleanup_database.execute(
                    text(
                        "SELECT public.validate_due_provider_cleanup("
                        ":org, :user, NULL::uuid, :runtime_ref, 'unbound', "
                        "transaction_timestamp())"
                    ),
                    {"org": ORG_A, "user": USER_A, "runtime_ref": UNBOUND_REF},
                )
                assert validation.scalar_one() is not None
                async with anyio.create_task_group() as tasks:
                    _ = tasks.start_soon(
                        execute_app_dml,
                        text(
                            "INSERT INTO provider_connections (id, org_id, "
                            "requester_user_id, adapter_id, "
                            "encrypted_runtime_home_ref, account_metadata, status) "
                            "VALUES (:provider, :org, :user, 'openai_codex', "
                            ":runtime_ref, '{}'::jsonb, 'pending')"
                        ),
                        {
                            "provider": INSERT_PROVIDER,
                            "org": ORG_A,
                            "user": USER_A,
                            "runtime_ref": UNBOUND_REF,
                        },
                    )
                    _ = tasks.start_soon(
                        execute_app_dml,
                        text(
                            "UPDATE provider_connections SET "
                            "encrypted_runtime_home_ref = :runtime_ref WHERE "
                            "id = :provider"
                        ),
                        {
                            "provider": UPDATE_PROVIDER,
                            "runtime_ref": UNBOUND_REF,
                        },
                    )
                completion = await cleanup_database.execute(
                    text(
                        "SELECT public.complete_provider_cleanup_outbox("
                        ":org, :user, NULL::uuid, :runtime_ref, 'unbound', "
                        "transaction_timestamp(), :evidence)"
                    ),
                    {
                        "org": ORG_A,
                        "user": USER_A,
                        "runtime_ref": UNBOUND_REF,
                        "evidence": EVIDENCE_SHA256,
                    },
                )
                unbound_completed = cast("bool", completion.scalar_one())

            # When a completed cleanup reference is directly rebound.
            await execute_app_dml(
                text(
                    "INSERT INTO provider_connections (id, org_id, "
                    "requester_user_id, adapter_id, encrypted_runtime_home_ref, "
                    "account_metadata, status) VALUES (:provider, :org, :user, "
                    "'openai_codex', :runtime_ref, '{}'::jsonb, 'pending')"
                ),
                {
                    "provider": REUSE_PROVIDER,
                    "org": ORG_A,
                    "user": USER_A,
                    "runtime_ref": UNBOUND_REF,
                },
            )

            # When superseded cleanup authorization overlaps direct deletion.
            async with engine.begin() as cleanup_database:
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
                        "provider": DELETE_PROVIDER,
                        "runtime_ref": SUPERSEDED_REF,
                    },
                )
                assert validation.scalar_one() is not None
                await execute_app_dml(
                    text("DELETE FROM provider_connections WHERE id = :provider"),
                    {"provider": DELETE_PROVIDER},
                )
                completion = await cleanup_database.execute(
                    text(
                        "SELECT public.complete_provider_cleanup_outbox("
                        ":org, :user, :provider, :runtime_ref, 'superseded', "
                        "transaction_timestamp(), :evidence)"
                    ),
                    {
                        "org": ORG_A,
                        "user": USER_A,
                        "provider": DELETE_PROVIDER,
                        "runtime_ref": SUPERSEDED_REF,
                        "evidence": EVIDENCE_SHA256,
                    },
                )
                superseded_completed = cast("bool", completion.scalar_one())
        finally:
            await engine.dispose()
        return tuple(outcomes), (unbound_completed, superseded_completed)

    try:
        outcomes, completions = anyio.run(run_races)
    finally:
        _ = psql(TEARDOWN_SQL)

    # Then direct INSERT/UPDATE/DELETE wait, and destroyed refs cannot be reused.
    assert completions == (True, True)
    assert sum("lock timeout" in outcome for outcome in outcomes) == 3, outcomes
    assert (
        sum(
            "provider runtime home ref has cleanup history" in outcome
            for outcome in outcomes
        )
        == 1
    )
