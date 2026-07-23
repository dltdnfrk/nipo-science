"""Immutable internal provider connection record transformations."""

from __future__ import annotations

from dataclasses import dataclass, replace
from typing import TYPE_CHECKING

from services.api.provider_runtime_contracts import (
    ProviderCompletionAdoption,
    normalize_utc,
)

if TYPE_CHECKING:
    from datetime import datetime

    from services.api.provider_oauth_state import OAuthAttempt
    from services.api.provider_runtime_contracts import (
        Health,
        OfficialOAuthCompletion,
        ProviderPrincipal,
        ProviderQualificationIdentity,
    )


@dataclass(frozen=True, slots=True)
class _ConnectionRecord:
    connection_id: str
    principal: ProviderPrincipal
    adapter_id: str
    account_id: str
    eligible_models: tuple[str, ...]
    selected_model: str | None
    health: Health
    cleanup_verified: bool
    qualified_live: bool
    created_at: datetime
    runtime_home_ref: str
    revision: int
    qualification: ProviderQualificationIdentity | None
    completion_adoption: ProviderCompletionAdoption | None = None

    @classmethod
    def from_new_completion(
        cls,
        attempt: OAuthAttempt,
        completion: OfficialOAuthCompletion,
        connection_id: str,
        created_at: datetime,
    ) -> _ConnectionRecord:
        adoption = ProviderCompletionAdoption(
            connection_id,
            completion.staging_lease_id,
            completion.vault_home_ref,
            normalize_utc(completion.destroy_by),
        )
        return cls(
            connection_id=connection_id,
            principal=attempt.principal,
            adapter_id=attempt.adapter_id,
            account_id=completion.account_id,
            eligible_models=completion.eligible_models,
            selected_model=None,
            health="pending",
            cleanup_verified=False,
            qualified_live=False,
            created_at=created_at,
            runtime_home_ref=completion.vault_home_ref,
            revision=1,
            qualification=None,
            completion_adoption=adoption,
        )

    def with_reauthentication(
        self,
        completion: OfficialOAuthCompletion,
    ) -> _ConnectionRecord:
        adoption = ProviderCompletionAdoption(
            self.connection_id,
            completion.staging_lease_id,
            completion.vault_home_ref,
            normalize_utc(completion.destroy_by),
        )
        return replace(
            self,
            account_id=completion.account_id,
            eligible_models=completion.eligible_models,
            selected_model=None,
            cleanup_verified=False,
            qualified_live=False,
            health="pending",
            runtime_home_ref=completion.vault_home_ref,
            revision=self.revision + 1,
            qualification=None,
            completion_adoption=adoption,
        )


ConnectionRecord = _ConnectionRecord
