from __future__ import annotations

from datetime import UTC, datetime

import pytest
from services.api.provider_postgres_rows import provider_snapshot_from_row
from services.api.provider_postgres_support import (
    ProviderJsonValue,
    ProviderPersistenceError,
    ProviderRowValue,
)


@pytest.mark.parametrize(
    "metadata",
    [
        {
            "account_id": "account-redacted",
            "models": ["codex-mini"],
            "provider": "openai_codex",
            "revision": "1",
            "cleanup_status": ["scheduled"],
        },
        {
            "account_id": "account-redacted",
            "models": ["codex-mini", 7],
            "provider": "openai_codex",
            "revision": "1",
        },
    ],
)
def test_row_decoder_rejects_malformed_json_with_stable_error(
    metadata: dict[str, ProviderJsonValue],
) -> None:
    row: dict[str, ProviderRowValue] = {
        "id": "018f0d7d-6b17-7a91-8b31-2f7331677d10",
        "adapter_id": "openai_codex",
        "encrypted_runtime_home_ref": "vault://runtime/connection/decoder",
        "superseded_runtime_home_ref": None,
        "account_metadata": metadata,
        "selected_model": None,
        "status": "pending",
        "qualified_at": None,
        "created_at": datetime(2026, 7, 16, tzinfo=UTC),
    }

    with pytest.raises(
        ProviderPersistenceError,
        match="provider_persistence_failed",
    ):
        _ = provider_snapshot_from_row(row)
