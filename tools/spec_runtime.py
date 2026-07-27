"""Provider runtime invariants for the normative SPEC verifier."""

from __future__ import annotations

from typing import Final

from tools.spec_contract import (
    JsonValue,
    add_error,
    child_map,
    child_str,
)

_V05_PROVIDER_REGISTRY_SIZE: Final = 13
_V05_MASTER_KEY_BYTES: Final = 32


def verify_runtime_v05(root: dict[str, JsonValue], errors: list[str]) -> None:
    """Append failures for v0.5 provider, execution, and credential invariants."""
    providers = child_map(root, "providers")
    add_error(
        child_str(providers, "account_model")
        == "researcher_own_subscription_or_api_key",
        "researcher-owned provider accounts",
        errors,
    )
    add_error(
        child_str(providers, "automatic_fallback") == "forbidden",
        "no automatic fallback",
        errors,
    )
    add_error(
        providers.get("required_default") is None
        and providers.get("registry_size") == _V05_PROVIDER_REGISTRY_SIZE
        and child_str(providers, "qualification_authority") == "absent"
        and child_str(providers, "signed_receipt_chain") == "absent"
        and child_str(providers, "organization_binding") == "absent",
        "hosted provider authority absent",
        errors,
    )
    execution = child_map(root, "execution")
    add_error(
        child_str(execution, "language") == "deterministic_python"
        and child_str(execution, "isolation_level") == "in_process",
        "disclosed in-process isolation",
        errors,
    )
    add_error(
        execution.get("literal_control_claims") == []
        and child_str(execution, "sandbox_claim")
        == "forbidden_without_an_outcome_test_of_the_specific_denial",
        "no unmeasured sandbox claims",
        errors,
    )
    credentials = child_map(root, "credentials")
    master_key = child_map(credentials, "master_key")
    provider_keys = child_map(credentials, "provider_keys")
    add_error(
        child_str(credentials, "plaintext_at_rest") == "forbidden"
        and child_str(master_key, "holder") == "macos_keychain_generic_password"
        and master_key.get("bytes") == _V05_MASTER_KEY_BYTES
        and child_str(provider_keys, "cipher") == "aes_256_gcm"
        and child_str(provider_keys, "additional_authenticated_data") == "provider_id",
        "keychain-held AES-256-GCM credential custody",
        errors,
    )
