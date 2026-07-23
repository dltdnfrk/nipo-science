"""Atomic PostgreSQL adapter for qualified provider Run dispatch."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING, cast, final, override

import anyio
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from services.api.provider_database_role import dedicated_provider_login_is_confined
from services.api.provider_qualification_postgres import (
    QualificationReceiptPersistenceError,
)
from services.api.provider_run_dispatch_contracts import (
    DispatchedProviderRun,
    ProviderRunDispatcher,
    ProviderRunDispatchError,
    ProviderRunDispatchRequest,
)
from services.api.provider_run_dispatch_policy import (
    ProviderRunAuthorizationPolicy,
    provider_run_dispatch_login_is_valid,
    provider_run_dispatch_request_is_valid,
)

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

    from sqlalchemy.ext.asyncio import AsyncConnection

    from services.api.provider_qualification_receipt import QualificationReceiptVerifier
    from services.api.provider_run_dispatch_policy import ProviderRowValue
    from services.api.provider_runtime_contracts import (
        DispatchAuthorization,
        ProviderPrincipal,
        ProviderRuntimeIdentity,
    )

_ROLE = "science_workbench_dispatcher"


@final
class PostgresProviderRunDispatcher(ProviderRunDispatcher):
    """Read and insert only through a dedicated NOLOGIN dispatch capability."""

    def __init__(
        self,
        database_url: str,
        verifier: QualificationReceiptVerifier,
        runtime_identity: ProviderRuntimeIdentity,
        *,
        expected_login_role: str,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        """Bind a dedicated credential, public verifier, and pinned runtime."""
        if not provider_run_dispatch_login_is_valid(expected_login_role):
            raise ProviderRunDispatchError
        self._database_url = database_url
        self._expected_login_role = expected_login_role
        self._authorization_policy = ProviderRunAuthorizationPolicy(
            verifier,
            runtime_identity,
            clock or _utc_now,
        )

    @override
    def dispatch(
        self,
        principal: ProviderPrincipal,
        request: ProviderRunDispatchRequest,
    ) -> DispatchedProviderRun:
        """Insert only while the signed current connection remains dispatchable."""
        if not provider_run_dispatch_request_is_valid(request):
            raise ProviderRunDispatchError

        async def execute() -> DispatchAuthorization:
            engine = create_async_engine(self._database_url, poolclass=NullPool)
            try:
                async with engine.begin() as database:
                    if not await dedicated_provider_login_is_confined(
                        database,
                        expected_login_role=self._expected_login_role,
                        capability_role=_ROLE,
                    ):
                        raise ProviderRunDispatchError
                    _ = await database.execute(text(f"SET LOCAL ROLE {_ROLE}"))
                    _ = await database.execute(
                        text(
                            "SELECT set_config('app.org_id', :org, true), "
                            "set_config('app.user_id', :user, true)"
                        ),
                        {"org": principal.org_id, "user": principal.user_id},
                    )
                    row = await self._connection_row(database, principal, request)
                    authorization = self._authorization_policy.authorize(
                        principal,
                        request,
                        row,
                    )
                    await self._insert(database, principal, request, authorization)
                    return authorization
            finally:
                await engine.dispose()

        try:
            authorization = anyio.run(execute)
        except ProviderRunDispatchError:
            raise
        except (
            OSError,
            SQLAlchemyError,
            QualificationReceiptPersistenceError,
            ValueError,
        ) as error:
            raise ProviderRunDispatchError from error
        return DispatchedProviderRun(request.run_id, authorization)

    async def _connection_row(
        self,
        database: AsyncConnection,
        principal: ProviderPrincipal,
        request: ProviderRunDispatchRequest,
    ) -> Mapping[str, ProviderRowValue]:
        result = await database.execute(
            text(
                "SELECT p.id::text AS id, p.adapter_id, p.account_metadata, "
                "p.selected_model, p.status, p.qualified_at, "
                "q.id::text AS qualification_receipt_db_id, q.org_id::text AS "
                "qualification_org_id, q.requester_user_id::text AS "
                "qualification_user_id, q.provider_connection_id::text AS "
                "qualification_connection_id, q.connection_revision AS "
                "qualification_connection_revision, q.adapter_id AS "
                "qualification_adapter_id, q.profile_sha256 AS "
                "qualification_profile_db_sha256, q.cases_sha256 AS "
                "qualification_cases_sha256, q.operator_account_ref AS "
                "qualification_operator_account_ref, q.oauth_mode AS "
                "qualification_oauth_mode, q.oauth_provider AS "
                "qualification_oauth_provider, q.runtime_version AS "
                "qualification_runtime_db_version, q.executable_sha256 AS "
                "qualification_executable_db_sha256, q.protocol_attempts AS "
                "qualification_protocol_attempts, q.cleanup_terminal AS "
                "qualification_cleanup_terminal, q.cleanup_redaction_complete AS "
                "qualification_cleanup_redaction_complete, q.authority_key_id AS "
                "qualification_authority_key_id, q.authority_issued_at AS "
                "qualification_authority_issued_at, q.authority_algorithm AS "
                "qualification_authority_algorithm, q.authority_signature AS "
                "qualification_authority_signature, q.receipt_sha256 AS "
                "qualification_receipt_stored_sha256 FROM provider_connections p "
                "JOIN provider_qualification_receipts q ON q.org_id = p.org_id AND "
                "q.requester_user_id = p.requester_user_id AND "
                "q.provider_connection_id = p.id AND q.id = "
                "p.qualification_receipt_id WHERE p.org_id = :org AND "
                "p.requester_user_id = :user AND p.id = :connection"
            ),
            {
                "org": principal.org_id,
                "user": principal.user_id,
                "connection": request.connection_id,
            },
        )
        row = result.mappings().one_or_none()
        if row is None:
            raise ProviderRunDispatchError
        return cast("Mapping[str, ProviderRowValue]", row)

    @staticmethod
    async def _insert(
        database: AsyncConnection,
        principal: ProviderPrincipal,
        request: ProviderRunDispatchRequest,
        authorization: DispatchAuthorization,
    ) -> None:
        result = await database.execute(
            text(
                "INSERT INTO runs (id, org_id, session_id, requester_id, "
                "provider_connection_id, provider_model_id, status, "
                "qualification_receipt_id, qualification_receipt_sha256, "
                "qualification_connection_revision, qualification_profile_sha256, "
                "qualification_runtime_version, qualification_executable_sha256) "
                "VALUES (:run_id, :org_id, :session_id, :requester_id, "
                ":connection_id, :model_id, 'queued', :receipt_id, :receipt_sha256, "
                ":connection_revision, :profile_sha256, :runtime_version, "
                ":executable_sha256)"
            ),
            {
                "run_id": request.run_id,
                "org_id": principal.org_id,
                "session_id": request.session_id,
                "requester_id": principal.user_id,
                "connection_id": authorization.connection_id,
                "model_id": authorization.model_id,
                "receipt_id": authorization.qualification_receipt_id,
                "receipt_sha256": authorization.qualification_receipt_sha256,
                "connection_revision": (
                    authorization.qualification_connection_revision
                ),
                "profile_sha256": authorization.qualification_profile_sha256,
                "runtime_version": authorization.qualification_runtime_version,
                "executable_sha256": authorization.qualification_executable_sha256,
            },
        )
        if result.rowcount != 1:
            raise ProviderRunDispatchError


def _utc_now() -> datetime:
    return datetime.now(UTC)
