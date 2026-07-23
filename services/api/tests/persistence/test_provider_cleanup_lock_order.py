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
from services.api.tests.persistence.test_rls import ORG_A, USER_A, seed_tenants

if TYPE_CHECKING:
    from sqlalchemy.sql.elements import TextClause

REVOKED_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e35"
HISTORY_PROVIDER: Final = "018f0d7d-6b17-7a91-8b31-2f7331677e36"
SOURCE_REF: Final = "vault://runtime/zzzz-cleanup-lock-order"
TOMBSTONE_REF: Final = f"vault://runtime/destroyed/{REVOKED_PROVIDER}"
HISTORY_SOURCE_REF: Final = "vault://runtime/zzzz-cleanup-history-source"
HISTORY_TOMBSTONE_REF: Final = f"vault://runtime/destroyed/{HISTORY_PROVIDER}"
EVIDENCE_SHA256: Final = "e" * 64
pytestmark = pytest.mark.usefixtures("migrated_database")


def test_revoked_cleanup_locks_source_and_tombstone_in_sorted_order() -> None:
    # Given a due revoked provider whose tombstone sorts before its source ref.
    seed_tenants()
    _ = psql(f"DELETE FROM provider_connections WHERE id = '{REVOKED_PROVIDER}'")
    _ = psql(
        "INSERT INTO provider_connections (id, org_id, requester_user_id, "
        "adapter_id, encrypted_runtime_home_ref, account_metadata, status) VALUES "
        f"('{REVOKED_PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{SOURCE_REF}', jsonb_build_object('cleanup_status', 'scheduled', "
        "'cleanup_requested_at', transaction_timestamp() - interval '2 hours', "
        "'destroy_by', transaction_timestamp() - interval '1 hour'), 'revoked')"
    )

    async def run_lock_order_probes() -> tuple[tuple[str, bool], ...]:
        engine = create_async_engine(database_url_asyncpg(), poolclass=NullPool)
        parameters = {
            "org": ORG_A,
            "user": USER_A,
            "provider": REVOKED_PROVIDER,
            "source_ref": SOURCE_REF,
            "evidence": EVIDENCE_SHA256,
        }

        async def probe(statement: TextClause) -> tuple[str, bool]:
            async with engine.connect() as cleanup_database:
                transaction = await cleanup_database.begin()
                error_message = ""
                try:
                    _ = await cleanup_database.execute(
                        text("SET LOCAL ROLE science_workbench_provider_cleanup")
                    )
                    _ = await cleanup_database.execute(
                        text("SET LOCAL lock_timeout = '250ms'")
                    )
                    _ = await cleanup_database.execute(statement, parameters)
                except DBAPIError as error:
                    error_message = str(error.orig)
                async with engine.begin() as observer_database:
                    source_lock = await observer_database.execute(
                        text(
                            "SELECT pg_try_advisory_xact_lock("
                            "hashtextextended(:source_ref, 0))"
                        ),
                        {"source_ref": SOURCE_REF},
                    )
                    source_available = cast("bool", source_lock.scalar_one())
                await transaction.rollback()
            return error_message, source_available

        try:
            # When another transaction owns the lexically first tombstone lock.
            async with engine.begin() as holder_database:
                _ = await holder_database.execute(
                    text(
                        "SELECT pg_advisory_xact_lock("
                        "hashtextextended(:tombstone_ref, 0))"
                    ),
                    {"tombstone_ref": TOMBSTONE_REF},
                )
                validation_probe = await probe(
                    text(
                        "SELECT public.validate_due_provider_cleanup("
                        ":org, :user, :provider, :source_ref, 'revoke', "
                        "transaction_timestamp())"
                    )
                )
                completion_probe = await probe(
                    text(
                        "SELECT public.complete_provider_revoked_cleanup("
                        ":org, :user, :provider, :source_ref, "
                        "transaction_timestamp(), :evidence)"
                    )
                )

            # When the ordered locks are released, validation and completion finish.
            async with engine.begin() as cleanup_database:
                _ = await cleanup_database.execute(
                    text("SET LOCAL ROLE science_workbench_provider_cleanup")
                )
                validation = await cleanup_database.execute(
                    text(
                        "SELECT public.validate_due_provider_cleanup("
                        ":org, :user, :provider, :source_ref, 'revoke', "
                        "transaction_timestamp())"
                    ),
                    parameters,
                )
                completion = await cleanup_database.execute(
                    text(
                        "SELECT public.complete_provider_revoked_cleanup("
                        ":org, :user, :provider, :source_ref, "
                        "transaction_timestamp(), :evidence)"
                    ),
                    parameters,
                )
                completed = cast("bool", completion.scalar_one())
                assert validation.scalar_one() is not None
        finally:
            await engine.dispose()
        return validation_probe, completion_probe, ("", completed)

    try:
        probes = anyio.run(run_lock_order_probes)
    finally:
        _ = psql(f"DELETE FROM provider_connections WHERE id = '{REVOKED_PROVIDER}'")

    # Then neither blocked function acquires the later source lock out of order.
    assert all("lock timeout" in error for error, _available in probes[:2])
    assert all(available for _error, available in probes[:2])
    assert probes[2] == ("", True)


def test_revoked_cleanup_rejects_tombstone_with_cleanup_history() -> None:
    # Given a due revoked provider whose terminal tombstone has cleanup history.
    seed_tenants()
    _ = psql(
        f"DELETE FROM provider_runtime_home_cleanups WHERE "
        f"encrypted_runtime_home_ref = '{HISTORY_TOMBSTONE_REF}'; "
        f"DELETE FROM provider_connections WHERE id = '{HISTORY_PROVIDER}'; "
        "INSERT INTO provider_connections (id, org_id, requester_user_id, "
        "adapter_id, encrypted_runtime_home_ref, account_metadata, status) VALUES "
        f"('{HISTORY_PROVIDER}', '{ORG_A}', '{USER_A}', 'openai_codex', "
        f"'{HISTORY_SOURCE_REF}', jsonb_build_object('cleanup_status', 'scheduled', "
        "'cleanup_requested_at', transaction_timestamp() - interval '2 hours', "
        "'destroy_by', transaction_timestamp() - interval '1 hour'), 'revoked'); "
        "INSERT INTO provider_runtime_home_cleanups (org_id, requester_user_id, "
        "encrypted_runtime_home_ref, connection_id, reason, status, requested_at, "
        "destroy_by) VALUES "
        f"('{ORG_A}', '{USER_A}', "
        f"'{HISTORY_TOMBSTONE_REF}', NULL, 'unbound', 'scheduled', "
        "transaction_timestamp() - interval '3 hours', "
        "transaction_timestamp() - interval '2 hours'); UPDATE "
        "provider_runtime_home_cleanups SET status = 'completed', destroyed_at = "
        "transaction_timestamp() - interval '1 hour', evidence_sha256 = "
        f"'{EVIDENCE_SHA256}' WHERE encrypted_runtime_home_ref = "
        f"'{HISTORY_TOMBSTONE_REF}'"
    )
    try:
        # When cleanup validates before irreversible runtime-home destruction.
        rejected = psql(
            "SET ROLE science_workbench_provider_cleanup; SELECT ("
            "public.validate_due_provider_cleanup("
            f"'{ORG_A}', '{USER_A}', '{HISTORY_PROVIDER}', "
            f"'{HISTORY_SOURCE_REF}', 'revoke', transaction_timestamp()) "
            "IS NULL)::text"
        ).stdout.strip()
    finally:
        _ = psql(
            f"DELETE FROM provider_runtime_home_cleanups WHERE "
            f"encrypted_runtime_home_ref = '{HISTORY_TOMBSTONE_REF}'; "
            f"DELETE FROM provider_connections WHERE id = '{HISTORY_PROVIDER}'"
        )

    # Then validation fails closed before an external destroyer may run.
    assert rejected == "true"
