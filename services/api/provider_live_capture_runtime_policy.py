"""Pinned deployment runtime-policy parsing for live qualification."""

from __future__ import annotations

import platform
import re
from dataclasses import dataclass
from hashlib import sha256
from hmac import compare_digest
from typing import TYPE_CHECKING, Final

from services.api.provider_live_capture_boundary import (
    decode_external_json,
    list_value,
    mapping,
    nested_mapping,
    text,
)
from services.api.provider_live_capture_errors import (
    ERROR_RUNTIME_POLICY,
    capture_error,
)
from services.api.provider_qualification_authority_files import (
    UnsafeAuthorityPathError,
    read_secure_authority_file,
)
from services.api.provider_runtime import ProviderRuntimeIdentity

if TYPE_CHECKING:
    from collections.abc import Mapping
    from pathlib import Path

_MAX_RUNTIME_POLICY_BYTES: Final = 64 * 1024
_BINARY_SHA256: Final = re.compile(r"^[0-9a-f]{64}$")


@dataclass(frozen=True, slots=True)
class ApprovedRuntimePolicy:
    """Deployment approval for one exact runtime artifact and platform."""

    policy_id: str
    identity: ProviderRuntimeIdentity
    platform_system: str
    platform_machine: str


def load_approved_runtime_policy(
    policy_id: str,
    policy_file: Path,
    *,
    expected_sha256: str,
) -> ApprovedRuntimePolicy:
    """Resolve one deployment policy file pinned to its exact protected bytes."""
    if not _BINARY_SHA256.fullmatch(expected_sha256):
        raise capture_error(ERROR_RUNTIME_POLICY)
    try:
        source = read_secure_authority_file(
            policy_file,
            maximum_bytes=_MAX_RUNTIME_POLICY_BYTES,
        )
        if not compare_digest(sha256(source).hexdigest(), expected_sha256):
            raise capture_error(ERROR_RUNTIME_POLICY)
        decoded = decode_external_json(
            source,
            maximum_bytes=_MAX_RUNTIME_POLICY_BYTES,
            error_message=ERROR_RUNTIME_POLICY,
        )
    except (OSError, UnsafeAuthorityPathError) as error:
        raise capture_error(ERROR_RUNTIME_POLICY) from error
    root = mapping(decoded, "runtime policies")
    if set(root) != {"schema_version", "policies"} or root["schema_version"] != 1:
        raise capture_error(ERROR_RUNTIME_POLICY)
    matches: list[Mapping[str, object]] = []
    for value in list_value(root["policies"], "runtime policies.policies"):
        item = nested_mapping(value)
        if item is not None and item.get("policy_id") == policy_id:
            matches.append(item)
    if len(matches) != 1:
        raise capture_error(ERROR_RUNTIME_POLICY)
    item = mapping(matches[0], "runtime policy")
    required = {
        "policy_id",
        "adapter_id",
        "platform_system",
        "platform_machine",
        "runtime_version",
        "executable_sha256",
    }
    if set(item) != required:
        raise capture_error(ERROR_RUNTIME_POLICY)
    approved = ApprovedRuntimePolicy(
        text(item["policy_id"], "runtime policy.policy_id"),
        ProviderRuntimeIdentity(
            text(item["adapter_id"], "runtime policy.adapter_id"),
            text(item["runtime_version"], "runtime policy.runtime_version"),
            text(item["executable_sha256"], "runtime policy.executable_sha256"),
        ),
        text(item["platform_system"], "runtime policy.platform_system"),
        text(item["platform_machine"], "runtime policy.platform_machine"),
    )
    if (
        approved.identity.adapter_id != "openai_codex"
        or not _BINARY_SHA256.fullmatch(approved.identity.executable_sha256)
        or not approved.identity.runtime_version.startswith("codex-cli-")
        or approved.platform_system != platform.system()
        or approved.platform_machine != platform.machine()
    ):
        raise capture_error(ERROR_RUNTIME_POLICY)
    return approved
