from pathlib import Path

import pytest
from tools.platform_policy.static_check_types import StaticCheckError
from tools.platform_policy.static_checks import check_secrets

_REJECT_NODE = (
    "packages/contracts/python/tests/test_protocol_security_red.py::"
    "test_security_review_rejects_nested_secret_shaped_value"
)
_ALLOW_NODE = (
    "packages/contracts/python/tests/test_protocol_security_red.py::"
    "test_security_review_allows_benign_secret_like_value"
)


@pytest.mark.parametrize(
    "credential",
    [
        "sk-" + "live_" + ("q" * 20),
        "access_token=" + "live." + ("r" * 24),
    ],
    ids=("provider-token", "bare-assignment"),
)
def test_security_tools_evidence_credential_is_rejected(
    tmp_path: Path,
    credential: str,
) -> None:
    # Given: retained evidence contains a provider-shaped credential.
    evidence = tmp_path / "tools/evidence/provider-runtime.log"
    evidence.parent.mkdir(parents=True)
    _ = evidence.write_text(credential)

    # When / Then: evidence is scanned instead of skipped by path.
    with pytest.raises(StaticCheckError, match="credential-plaintext"):
        _ = check_secrets(tmp_path)


@pytest.mark.parametrize(
    "line",
    [
        f"{_REJECT_NODE}[Bearer {'x' * 24}] PASSED [ 48%]",
        f"{_REJECT_NODE}[Authorization: Basic {'eHh4' * 6}] PASSED [ 48%]",
        f"{_REJECT_NODE}[client_secret={'x' * 24}] PASSED [ 48%]",
        f"{_REJECT_NODE}[api-key: {'x' * 24}] PASSED [ 49%]",
        f"{_REJECT_NODE}[sk-{'x' * 24}] PASSED [ 49%]",
        f"{_REJECT_NODE}[ghp_{'x' * 24}] PASSED [ 49%]",
        f"{_REJECT_NODE}[AKIA{'A' * 16}] PASSED [ 50%]",
        f"{_REJECT_NODE}[{'-' * 5}BEGIN PRIVATE KEY{'-' * 5}] PASSED [ 50%]",
        f"{_ALLOW_NODE}[https://example.test/sk-{'x' * 24}] PASSED [ 52%]",
        f"{_ALLOW_NODE}[error: invalid sk-{'x' * 24}] PASSED [ 53%]",
    ],
    ids=(
        "bearer",
        "basic",
        "client-secret",
        "api-key",
        "provider-token",
        "github-token",
        "aws-key",
        "private-key-marker",
        "documented-url",
        "documented-error",
    ),
)
def test_unit_exact_documented_synthetic_evidence_fixture_is_allowed(
    tmp_path: Path,
    line: str,
) -> None:
    # Given: this exact test node and placeholder are retained historical evidence.
    evidence = tmp_path / "tools/evidence/ulw-g001-typed-contracts.log"
    evidence.parent.mkdir(parents=True)
    _ = evidence.write_text(line + "\n")

    # When
    count = check_secrets(tmp_path)

    # Then
    assert count == 1


@pytest.mark.parametrize(
    "relative_path",
    [
        "tools/evidence/renamed.log",
        "docs/ulw-g001-typed-contracts.md",
    ],
)
def test_security_synthetic_fixture_allowlist_is_path_exact(
    tmp_path: Path,
    relative_path: str,
) -> None:
    # Given: the known placeholder appears outside its one justified evidence file.
    candidate = tmp_path / relative_path
    candidate.parent.mkdir(parents=True)
    _ = candidate.write_text("sk-" + ("x" * 24))

    # When / Then
    with pytest.raises(StaticCheckError, match="credential-plaintext"):
        _ = check_secrets(tmp_path)


def test_security_synthetic_fixture_allowlist_is_value_exact(
    tmp_path: Path,
) -> None:
    # Given: a different token is injected into the allowlisted evidence path.
    evidence = tmp_path / "tools/evidence/ulw-g001-typed-contracts.log"
    evidence.parent.mkdir(parents=True)
    _ = evidence.write_text("sk-" + ("x" * 23) + "y")

    # When / Then
    with pytest.raises(StaticCheckError, match="credential-plaintext"):
        _ = check_secrets(tmp_path)


def test_security_synthetic_fixture_allowlist_is_context_exact(
    tmp_path: Path,
) -> None:
    # Given: an allowed placeholder is placed on an unrelated line in the same file.
    evidence = tmp_path / "tools/evidence/ulw-g001-typed-contracts.log"
    evidence.parent.mkdir(parents=True)
    _ = evidence.write_text("unrelated-observation[sk-" + ("x" * 24) + "]\n")

    # When / Then
    with pytest.raises(StaticCheckError, match="credential-plaintext"):
        _ = check_secrets(tmp_path)


def test_security_machine_specific_home_in_evidence_is_rejected(
    tmp_path: Path,
) -> None:
    # Given: retained evidence reveals a developer home and checkout location.
    evidence = tmp_path / "tools/evidence/runtime.log"
    evidence.parent.mkdir(parents=True)
    machine_path = "/" + "Users/developer/project/.venv/bin/python"
    _ = evidence.write_text(f"interpreter: {machine_path}\n")

    # When / Then
    with pytest.raises(StaticCheckError, match="machine-path-plaintext"):
        _ = check_secrets(tmp_path)
