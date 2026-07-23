"""Repository credential and retained-evidence scanning policy."""

from __future__ import annotations

import re
import stat
import unicodedata
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator
    from pathlib import Path

from .static_check_types import StaticCheckCode, StaticCheckError

PROVIDER_VALUE_REGEX: Final = (
    r"\b(?:(?:sk|gh[pousr]|glpat|xox[baprs])[-_][A-Za-z0-9_-]{16,}|"
    r"github_pat_[A-Za-z0-9_]{20,}|AIza[0-9A-Za-z_-]{30,})\b"
)
AWS_KEY_PATTERN: Final = r"\bAKIA[0-9A-Z]{16}\b"
CREDENTIAL_VALUE_REGEX: Final = r"[A-Za-z0-9][A-Za-z0-9._~+/=-]{19,}"
CREDENTIAL_NAME_PATTERN: Final = (
    r"(?:api[_ -]?key|access[_ -]?token|auth[_ -]?token|client[_ -]?secret|"
    r"refresh[_ -]?token|service[_ -]?token|private[_ -]?key|password|passwd|"
    r"authorization|proxy[_ -]?authorization|x[_ -]?api[_ -]?key)"
)
QUOTED_ASSIGNMENT_PATTERN: Final = (
    rf"[\"']?{CREDENTIAL_NAME_PATTERN}[\"']?\s*[:=]\s*[\"']"
    rf"(?:bearer\s+)?{CREDENTIAL_VALUE_REGEX}[\"']"
)
BARE_ASSIGNMENT_PATTERN: Final = re.compile(
    rf"(?mi)^\s*(?:export\s+)?[\"']?{CREDENTIAL_NAME_PATTERN}[\"']?"
    rf"\s*[:=]\s*(?:bearer\s+)?{CREDENTIAL_VALUE_REGEX}\s*$"
)
AUTH_PATTERN: Final = rf"\bBearer\s+{CREDENTIAL_VALUE_REGEX}"
BASIC_AUTH_PATTERN: Final = rf"\bBasic\s+{CREDENTIAL_VALUE_REGEX}"
PRIVATE_KEY_PATTERN: Final = r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"
SECRET_PATTERN: Final = re.compile(
    rf"{PROVIDER_VALUE_REGEX}|{AWS_KEY_PATTERN}|{QUOTED_ASSIGNMENT_PATTERN}|"
    rf"{AUTH_PATTERN}|{BASIC_AUTH_PATTERN}|{PRIVATE_KEY_PATTERN}",
    flags=re.IGNORECASE | re.MULTILINE,
)
EVIDENCE_ASSIGNMENT_PATTERN: Final = re.compile(
    rf"{CREDENTIAL_NAME_PATTERN}[\"']?\s*[:=]\s*[\"']?"
    rf"(?:bearer\s+)?{CREDENTIAL_VALUE_REGEX}",
    flags=re.IGNORECASE,
)
MACHINE_HOME_PATTERN: Final = re.compile(
    r"(?:/(?:Users|home)/[^/\s\"']+/|[A-Z]:\\Users\\[^\\\s\"']+\\)",
    flags=re.IGNORECASE,
)
SCANNED_SUFFIXES: Final = frozenset(
    {
        ".bash",
        ".cfg",
        ".conf",
        ".css",
        ".env",
        ".example",
        ".fish",
        ".go",
        ".graphql",
        ".hcl",
        ".html",
        ".ini",
        ".j2",
        ".java",
        ".js",
        ".json",
        ".jsonc",
        ".jsx",
        ".kt",
        ".kts",
        ".md",
        ".mjs",
        ".mts",
        ".properties",
        ".proto",
        ".py",
        ".rb",
        ".rs",
        ".sh",
        ".sql",
        ".stub",
        ".svelte",
        ".template",
        ".tf",
        ".tfvars",
        ".tmpl",
        ".toml",
        ".tpl",
        ".ts",
        ".tsx",
        ".txt",
        ".vue",
        ".xml",
        ".yaml",
        ".yml",
        ".zsh",
    }
)
SCANNED_NAMES: Final = frozenset(
    {".dockerignore", ".editorconfig", ".gitignore", ".npmrc", "Makefile"}
)
SCANNED_NAME_PREFIXES: Final = ("Containerfile", "Dockerfile")
EXCLUDED_DIRECTORY_NAMES: Final = frozenset(
    {
        ".basedpyright",
        ".cache",
        ".git",
        ".next",
        ".pytest_cache",
        ".ruff_cache",
        ".tools",
        ".venv",
        "__pycache__",
        "build",
        "coverage",
        "dist",
        "node_modules",
    }
)
UNQUOTED_CREDENTIAL_SUFFIXES: Final = frozenset(
    {".conf", ".env", ".ini", ".properties", ".tfvars", ".toml", ".yaml", ".yml"}
)
TOOLS_EVIDENCE_PREFIX: Final = "tools/evidence/"
EXCLUDED_PREFIXES: Final = (".ci/evidence/",)
SYNTHETIC_EVIDENCE_PATH: Final = "tools/evidence/ulw-g001-typed-contracts.log"
_REJECT_NODE: Final = (
    "packages/contracts/python/tests/test_protocol_security_red.py::"
    "test_security_review_rejects_nested_secret_shaped_value"
)
_ALLOW_NODE: Final = (
    "packages/contracts/python/tests/test_protocol_security_red.py::"
    "test_security_review_allows_benign_secret_like_value"
)
# Exact historical pytest lines; path, placeholder, context, and outcome all bind.
SYNTHETIC_EVIDENCE_LINES: Final = frozenset(
    {
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
    }
)


def check_secrets(root: Path) -> int:
    """Scan project text files for credential-shaped plaintext."""
    scanned = 0
    for path in _secret_candidates(root):
        raw = path.read_bytes()
        if b"\0" in raw:
            continue
        scanned += 1
        normalized = unicodedata.normalize("NFKC", raw.decode(errors="replace"))
        location = path.relative_to(root).as_posix()
        is_evidence = location.startswith(TOOLS_EVIDENCE_PREFIX)
        if is_evidence and MACHINE_HOME_PATTERN.search(normalized) is not None:
            raise StaticCheckError(StaticCheckCode.MACHINE_PATH_PLAINTEXT, path)
        has_credential = any(
            not _synthetic_evidence_match_is_allowed(location, normalized, matched)
            for matched in SECRET_PATTERN.finditer(normalized)
        )
        if is_evidence:
            has_credential = has_credential or any(
                not _synthetic_evidence_match_is_allowed(location, normalized, matched)
                for matched in EVIDENCE_ASSIGNMENT_PATTERN.finditer(normalized)
            )
        scans_unquoted = (
            path.suffix.casefold() in UNQUOTED_CREDENTIAL_SUFFIXES
            or path.name.startswith(".env")
            or bool(path.stat().st_mode & stat.S_IXUSR)
        )
        if has_credential or (
            scans_unquoted and BARE_ASSIGNMENT_PATTERN.search(normalized)
        ):
            raise StaticCheckError(StaticCheckCode.CREDENTIAL_PLAINTEXT, path)
    if scanned <= 0:
        raise StaticCheckError(StaticCheckCode.EMPTY_SECRET_SCAN, root)
    return scanned


def _synthetic_evidence_match_is_allowed(
    location: str,
    normalized: str,
    matched: re.Match[str],
) -> bool:
    if location != SYNTHETIC_EVIDENCE_PATH:
        return False
    line_start = normalized.rfind("\n", 0, matched.start()) + 1
    next_newline = normalized.find("\n", matched.end())
    line_end = len(normalized) if next_newline < 0 else next_newline
    return normalized[line_start:line_end] in SYNTHETIC_EVIDENCE_LINES


def _secret_candidates(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        location = relative.as_posix()
        is_evidence = location.startswith(TOOLS_EVIDENCE_PREFIX)
        excluded = any(
            part in EXCLUDED_DIRECTORY_NAMES for part in relative.parts
        ) or any(location.startswith(prefix) for prefix in EXCLUDED_PREFIXES)
        executable = bool(path.stat().st_mode & stat.S_IXUSR)
        candidate = (
            is_evidence
            or len(relative.parts) == 1
            or path.suffix.casefold() in SCANNED_SUFFIXES
            or path.name in SCANNED_NAMES
            or path.name.startswith(SCANNED_NAME_PREFIXES)
            or path.name.startswith(".env")
            or executable
        )
        if candidate and not excluded:
            yield path
