"""Provider runtime invariants for the normative SPEC verifier."""

from __future__ import annotations

from typing import Final

from tools.spec_contract import (
    JsonValue,
    add_error,
    child_bool,
    child_map,
    child_str,
    child_strs,
)


def verify_runtime(root: dict[str, JsonValue], errors: list[str]) -> None:
    """Append failures for OAuth, selection, fallback, and adapter invariants."""
    runtime = child_map(root, "provider_runtime")
    add_error(
        child_str(runtime, "adapter_contract") == "AgentRuntimeAdapter",
        "runtime adapter",
        errors,
    )
    add_error(
        child_str(runtime, "connection_entity") == "provider_connections"
        and child_str(runtime, "connection_owner") == "requester_user_id",
        "requester-owned connections",
        errors,
    )
    add_error(
        child_str(runtime, "auth_mode") == "official_subscription_oauth",
        "OAuth-only runtime auth",
        errors,
    )
    add_error(
        child_str(runtime, "run_selection") == "explicit_provider_connection_id",
        "per-Run selection",
        errors,
    )
    add_error(
        child_str(runtime, "required_default") == "openai_codex",
        "required runtime default",
        errors,
    )
    add_error(
        child_strs(runtime, "required_runtimes") == ("openai_codex",),
        "required runtime set",
        errors,
    )
    add_error(
        child_str(runtime, "automatic_fallback") == "forbidden",
        "no automatic fallback",
        errors,
    )
    forbidden_auth = {"api_key", "byok", "unofficial_token", "browser_cookie_reuse"}
    add_error(
        set(child_strs(runtime, "forbidden_auth")) == forbidden_auth,
        "forbidden runtime auth modes",
        errors,
    )
    adapters = child_map(runtime, "adapters")
    adapter_ids = {
        "openai_codex",
        "anthropic_claude_code",
        "xai_grok_build",
        "moonshot_kimi_code",
        "zai_glm",
    }
    add_error(set(adapters) == adapter_ids, "runtime registry", errors)
    codex = child_map(adapters, "openai_codex")
    add_error(
        child_str(codex, "tier") == "required" and child_bool(codex, "launch_default"),
        "required openai_codex",
        errors,
    )
    optional_ids = ("anthropic_claude_code", "xai_grok_build", "moonshot_kimi_code")
    for adapter_id in optional_ids:
        adapter = child_map(adapters, adapter_id)
        add_error(
            child_str(adapter, "activation") == "fail_closed_live_qualification"
            and child_str(adapter, "failure_policy") == "disabled",
            "optional adapters fail-closed",
            errors,
        )
    glm = child_map(adapters, "zai_glm")
    add_error(
        child_str(glm, "activation") == "disabled"
        and child_str(glm, "reason") == "unsupported_auth"
        and child_str(glm, "connect_action") == "unavailable",
        "GLM unsupported_auth",
        errors,
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
