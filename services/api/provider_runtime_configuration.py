"""Fixed provider registry and deployment-owned runtime policy."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import timedelta
from typing import TYPE_CHECKING, Final
from urllib.parse import urlparse

from services.api.provider_runtime_contracts import (
    ERROR_ADAPTER_DISABLED,
    ERROR_INVALID_CLEANUP_POLICY,
    ERROR_QUALIFICATION_REQUIRED,
    ProviderRuntimeIdentity,
    runtime_error,
)

if TYPE_CHECKING:
    from services.api.provider_qualification_receipt import QualificationReceiptVerifier

NONCE_BYTES: Final[int] = 32
SHA256_HEX_LENGTH: Final[int] = 64
OAUTH_EXPIRATION: Final[timedelta] = timedelta(minutes=10)


@dataclass(frozen=True, slots=True)
class ProviderAdapter:
    """A supported provider adapter and its launch availability."""

    adapter_id: str
    display_name: str
    availability_label: str
    required: bool
    launch_default: bool
    connectable: bool
    disabled_reason: str | None = None


ADAPTERS: Final[tuple[ProviderAdapter, ...]] = (
    ProviderAdapter(
        adapter_id="openai_codex",
        display_name="OpenAI Codex",
        availability_label="연결 가능",
        required=True,
        launch_default=True,
        connectable=True,
    ),
    ProviderAdapter(
        adapter_id="anthropic_claude_code",
        display_name="Anthropic Claude Code",
        availability_label="자격 검증 전에는 사용할\u00a0수\u00a0없음",
        required=False,
        launch_default=False,
        connectable=False,
        disabled_reason="not_qualified",
    ),
    ProviderAdapter(
        adapter_id="xai_grok_build",
        display_name="xAI Grok Build",
        availability_label="자격 검증 전에는 사용할\u00a0수\u00a0없음",
        required=False,
        launch_default=False,
        connectable=False,
        disabled_reason="not_qualified",
    ),
    ProviderAdapter(
        adapter_id="moonshot_kimi_code",
        display_name="Moonshot Kimi Code",
        availability_label="자격 검증 전에는 사용할\u00a0수\u00a0없음",
        required=False,
        launch_default=False,
        connectable=False,
        disabled_reason="not_qualified",
    ),
    ProviderAdapter(
        adapter_id="zai_glm",
        display_name="Z.ai GLM",
        availability_label="GLM 비활성화 · unsupported_auth",
        required=False,
        launch_default=False,
        connectable=False,
        disabled_reason="unsupported_auth",
    ),
)
_ADAPTER_BY_ID: Final[dict[str, ProviderAdapter]] = {
    adapter.adapter_id: adapter for adapter in ADAPTERS
}


@dataclass(frozen=True, slots=True)
class ProviderCleanupPolicy:
    """Composition-owned deadline for destroying revoked runtime homes."""

    runtime_home_destruction_window: timedelta
    runtime_identity: ProviderRuntimeIdentity | None = None
    qualification_verifier: QualificationReceiptVerifier | None = None

    def __post_init__(self) -> None:
        """Reject deadlines that cannot provide a positive cleanup window."""
        if self.runtime_home_destruction_window <= timedelta(0):
            raise runtime_error(ERROR_INVALID_CLEANUP_POLICY)
        if self.runtime_identity is not None and not _runtime_identity_is_valid(
            self.runtime_identity
        ):
            raise runtime_error(ERROR_QUALIFICATION_REQUIRED)


PROVIDER_RUNTIME_HOME_CLEANUP_POLICY: Final = ProviderCleanupPolicy(
    runtime_home_destruction_window=timedelta(hours=24)
)


def _connectable_adapter(adapter_id: str) -> ProviderAdapter:
    adapter = _ADAPTER_BY_ID.get(adapter_id)
    if adapter is None or not adapter.connectable:
        raise runtime_error(ERROR_ADAPTER_DISABLED)
    return adapter


def _provider_adapter_exists(adapter_id: str) -> bool:
    return adapter_id in _ADAPTER_BY_ID


def _runtime_identity_is_valid(identity: ProviderRuntimeIdentity) -> bool:
    return (
        _provider_adapter_exists(identity.adapter_id)
        and identity.runtime_version.startswith("codex-cli-")
        and len(identity.executable_sha256) == SHA256_HEX_LENGTH
        and all(
            character in "0123456789abcdef" for character in identity.executable_sha256
        )
    )


def is_safe_runtime_home_ref(value: str) -> bool:
    """Accept only opaque runtime-vault references without traversal syntax."""
    parsed = urlparse(value)
    return (
        parsed.scheme == "vault"
        and parsed.netloc == "runtime"
        and parsed.path.startswith("/")
        and ".." not in parsed.path
        and not parsed.query
        and not parsed.fragment
    )


connectable_adapter = _connectable_adapter
provider_adapter_exists = _provider_adapter_exists
