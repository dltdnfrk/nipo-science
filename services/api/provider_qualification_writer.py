"""Least-privilege PostgreSQL adoption boundary for signed qualifications."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, final, override

import anyio
from sqlalchemy import bindparam, text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool

from services.api.provider_database_role import dedicated_provider_login_is_confined
from services.api.provider_model_id import provider_model_id_is_valid
from services.api.provider_qualification_postgres import (
    QualificationReceiptPersistenceError,
    append_qualification_receipt,
)
from services.api.provider_qualification_receipt import (
    qualification_receipt_sha256,
)
from services.api.provider_runtime import ProviderRuntimeError

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncConnection, AsyncEngine

    from services.api.provider_qualification_receipt import (
        QualificationReceipt,
        QualificationReceiptAdmissionPolicy,
    )
    from services.api.provider_runtime import ProviderConnection, ProviderPrincipal

_ERROR_PERSISTENCE = "provider_persistence_failed"
_ROLE = "science_workbench_qualification"
_FORBIDDEN_LOGIN_ROLES = frozenset(
    {
        "science_workbench",
        "science_workbench_app",
        "science_workbench_qualification",
    }
)
_METADATA_BIND = bindparam("qualification_metadata", type_=JSONB)


@dataclass(frozen=True, slots=True)
class _QualificationAdoption:
    principal: ProviderPrincipal
    connection: ProviderConnection
    runtime_home_ref: str
    receipt: QualificationReceipt
    expected_revision: int


class QualificationWriter(Protocol):
    """Adopt only the receipt supplied to an exact provider CAS mutation."""

    def adopt(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        receipt: QualificationReceipt,
        *,
        expected_revision: int,
    ) -> None:
        """Append the verified receipt and select only that receipt atomically."""
        ...


class QualificationWriterError(ProviderRuntimeError):
    """Stable failure for an unavailable or rejected adoption boundary."""

    def __init__(self) -> None:
        """Avoid disclosing authority or database details to callers."""
        super().__init__(_ERROR_PERSISTENCE)


@final
class PostgresQualificationWriter(QualificationWriter):
    """Use a dedicated login and the NOLOGIN qualification-adopter role."""

    def __init__(
        self,
        database_url: str,
        admission_policy: QualificationReceiptAdmissionPolicy,
        *,
        expected_login_role: str,
    ) -> None:
        """Bind a dedicated credential, expected login, and public verifier."""
        if (
            not expected_login_role
            or expected_login_role in _FORBIDDEN_LOGIN_ROLES
            or not expected_login_role.replace("_", "").isalnum()
        ):
            raise QualificationWriterError
        self._database_url = database_url
        self._admission_policy = admission_policy
        self._expected_login_role = expected_login_role

    @override
    def adopt(
        self,
        principal: ProviderPrincipal,
        connection: ProviderConnection,
        runtime_home_ref: str,
        receipt: QualificationReceipt,
        *,
        expected_revision: int,
    ) -> None:
        """Adopt one exact valid receipt under forced requester-scoped RLS."""
        if not self._admission_policy.admits(receipt) or not _valid_adoption(
            principal,
            connection,
            runtime_home_ref,
            receipt,
            expected_revision,
        ):
            raise QualificationWriterError
        adoption = _QualificationAdoption(
            principal,
            connection,
            runtime_home_ref,
            receipt,
            expected_revision,
        )

        async def run() -> None:
            engine = create_async_engine(self._database_url, poolclass=NullPool)
            try:
                await self._transaction(engine, adoption)
            finally:
                await engine.dispose()

        try:
            anyio.run(run)
        except QualificationWriterError:
            raise
        except (
            OSError,
            SQLAlchemyError,
            QualificationReceiptPersistenceError,
        ) as error:
            raise QualificationWriterError from error

    async def _transaction(
        self,
        engine: AsyncEngine,
        adoption: _QualificationAdoption,
    ) -> None:
        principal = adoption.principal
        connection = adoption.connection
        receipt = adoption.receipt
        async with engine.begin() as database:
            await self._assert_login_boundary(database)
            _ = await database.execute(text(f"SET LOCAL ROLE {_ROLE}"))
            _ = await database.execute(
                text(
                    "SELECT set_config('app.org_id', :org, true), "
                    "set_config('app.user_id', :user, true)"
                ),
                {"org": principal.org_id, "user": principal.user_id},
            )
            await append_qualification_receipt(
                database,
                principal,
                connection,
                receipt,
            )
            result = await database.execute(
                text(
                    "UPDATE provider_connections SET account_metadata = "
                    "account_metadata || :qualification_metadata, qualified_at = "
                    "COALESCE(qualified_at, CURRENT_TIMESTAMP), "
                    "qualification_receipt_id = :receipt WHERE org_id = :org AND "
                    "requester_user_id = :user AND id = :connection AND adapter_id "
                    "= :adapter AND encrypted_runtime_home_ref = :runtime_ref AND "
                    "selected_model IS NOT DISTINCT FROM :model AND status = :status "
                    "AND created_at = :created_at AND status <> 'revoked' AND "
                    "account_metadata ->> 'revision' = :expected_revision AND "
                    "account_metadata ->> 'account_id' = :account AND "
                    "account_metadata ->> 'provider' = :adapter AND "
                    "account_metadata -> 'models' = :models"
                ).bindparams(_METADATA_BIND, bindparam("models", type_=JSONB)),
                {
                    "qualification_metadata": _qualification_metadata(connection),
                    "receipt": receipt.receipt_id,
                    "org": principal.org_id,
                    "user": principal.user_id,
                    "connection": connection.connection_id,
                    "adapter": connection.adapter_id,
                    "runtime_ref": adoption.runtime_home_ref,
                    "model": connection.selected_model,
                    "status": connection.health,
                    "created_at": connection.created_at,
                    "expected_revision": str(adoption.expected_revision),
                    "account": connection.account_id,
                    "models": list(connection.eligible_models),
                },
            )
            if result.rowcount != 1:
                raise QualificationWriterError

    async def _assert_login_boundary(self, database: AsyncConnection) -> None:
        if not await dedicated_provider_login_is_confined(
            database,
            expected_login_role=self._expected_login_role,
            capability_role=_ROLE,
        ):
            raise QualificationWriterError


def _valid_adoption(
    principal: ProviderPrincipal,
    connection: ProviderConnection,
    runtime_home_ref: str,
    receipt: QualificationReceipt,
    expected_revision: int,
) -> bool:
    qualification = connection.qualification
    subject = receipt.claim.subject
    return (
        bool(runtime_home_ref)
        and bool(connection.eligible_models)
        and all(
            provider_model_id_is_valid(model) for model in connection.eligible_models
        )
        and (
            connection.selected_model is None
            or provider_model_id_is_valid(connection.selected_model)
        )
        and expected_revision >= 1
        and connection.revision == expected_revision + 1
        and connection.qualified_live
        and connection.cleanup_verified
        and qualification is not None
        and qualification.receipt == receipt
        and qualification.receipt_sha256 == qualification_receipt_sha256(receipt)
        and subject.org_id == principal.org_id
        and subject.user_id == principal.user_id
        and subject.connection_id == connection.connection_id
        and subject.connection_revision == connection.revision
        and receipt.claim.adapter_id == connection.adapter_id
        and receipt.claim.profile_sha256 == qualification.profile_sha256
        and receipt.claim.runtime_version == qualification.runtime.runtime_version
        and receipt.claim.executable_sha256
        == qualification.runtime.executable_sha256
    )


def _qualification_metadata(
    connection: ProviderConnection,
) -> dict[str, str]:
    qualification = connection.qualification
    if qualification is None:
        raise QualificationWriterError
    return {
        "revision": str(connection.revision),
        "qualification_receipt_id": qualification.receipt.receipt_id,
        "qualification_runtime_version": qualification.runtime.runtime_version,
        "qualification_executable_sha256": qualification.runtime.executable_sha256,
        "qualification_profile_sha256": qualification.profile_sha256,
    }
