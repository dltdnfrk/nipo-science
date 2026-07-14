"""Dependency inventory, credential scan, and codegen drift checks."""

from __future__ import annotations

import re
import stat
import sys
import unicodedata
from dataclasses import dataclass
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING, Final, override

if TYPE_CHECKING:
    from collections.abc import Iterator

from .ci_contract import GeneratedContract, verify_generated_contract

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
PRIVATE_KEY_PATTERN: Final = r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----"
SECRET_PATTERNS: Final = (
    PROVIDER_VALUE_REGEX,
    AWS_KEY_PATTERN,
    QUOTED_ASSIGNMENT_PATTERN,
    AUTH_PATTERN,
    PRIVATE_KEY_PATTERN,
)
SECRET_PATTERN: Final = re.compile(
    "|".join(SECRET_PATTERNS),
    flags=re.IGNORECASE | re.MULTILINE,
)
ACTION_PATTERN: Final = re.compile(r"uses:\s*([^\s#]+)")
ACTION_SHA_PATTERN: Final = re.compile(r"^[^@]+@[0-9a-f]{40}$")
WORKFLOW_SUFFIXES: Final = frozenset({".yaml", ".yml"})
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
EXCLUDED_PREFIXES: Final = (".ci/evidence/", "tools/evidence/")
CLI_ARG_COUNT: Final = 3


class StaticMode(StrEnum):
    """Supported machine-invoked static checks."""

    SBOM = "sbom"
    SECRET_SCAN = "secret-scan"  # noqa: S105 -- A mode label, never a credential.
    DRIFT_SCAN = "drift-scan"


class StaticCheckCode(StrEnum):
    """Stable failures emitted by static checks."""

    MISSING_UV_LOCK = "missing-uv-lock"
    MISSING_PNPM_LOCK = "missing-pnpm-lock"
    EMPTY_SBOM = "empty-sbom"
    CREDENTIAL_PLAINTEXT = "credential-plaintext"
    EMPTY_SECRET_SCAN = "empty-secret-scan"  # noqa: S105 -- Stable error code.
    USAGE = "usage"
    UNKNOWN_CHECK = "unknown-check"
    UNPINNED_WORKFLOW_ACTION = "unpinned-workflow-action"


@dataclass(frozen=True, slots=True)
class StaticCheckError(Exception):
    """Rejects an invalid static check request or discovered violation."""

    code: StaticCheckCode
    path: Path

    @override
    def __str__(self) -> str:
        """Describe the stable failure code and affected path."""
        return f"{self.code}: {self.path}"


def check_sbom(root: Path) -> int:
    """Inventory locked Python and pnpm package entries."""
    uv_lock = root / "uv.lock"
    pnpm_lock = root / "pnpm-lock.yaml"
    if not uv_lock.is_file():
        raise StaticCheckError(StaticCheckCode.MISSING_UV_LOCK, uv_lock)
    if not pnpm_lock.is_file():
        raise StaticCheckError(StaticCheckCode.MISSING_PNPM_LOCK, pnpm_lock)
    count = uv_lock.read_text().count("[[package]]")
    count += sum(
        1
        for line in pnpm_lock.read_text().splitlines()
        if line.startswith("  ") and line.rstrip().endswith(":") and "@" in line
    )
    count += check_workflow_actions(root)
    if count <= 0:
        raise StaticCheckError(StaticCheckCode.EMPTY_SBOM, root)
    return count


def check_workflow_actions(root: Path) -> int:
    """Require every non-local workflow action to use a full commit SHA."""
    count = 0
    for workflow in (root / ".github/workflows").rglob("*"):
        if not workflow.is_file() or workflow.suffix not in WORKFLOW_SUFFIXES:
            continue
        for matched in ACTION_PATTERN.finditer(workflow.read_text()):
            reference = matched.group(1)
            if reference.startswith("./"):
                continue
            count += 1
            if ACTION_SHA_PATTERN.fullmatch(reference) is None:
                raise StaticCheckError(
                    StaticCheckCode.UNPINNED_WORKFLOW_ACTION,
                    workflow,
                )
    return count


def check_secrets(root: Path) -> int:
    """Scan project text files for credential-shaped plaintext."""
    scanned = 0
    for path in _secret_candidates(root):
        raw = path.read_bytes()
        if b"\0" in raw:
            continue
        scanned += 1
        normalized = unicodedata.normalize("NFKC", raw.decode(errors="replace"))
        has_credential = SECRET_PATTERN.search(normalized) is not None
        scans_unquoted = (
            path.suffix.casefold() in UNQUOTED_CREDENTIAL_SUFFIXES
            or path.name.startswith(".env")
            or bool(path.stat().st_mode & stat.S_IXUSR)
        )
        if has_credential or (
            scans_unquoted and BARE_ASSIGNMENT_PATTERN.search(normalized)
        ):
            raise StaticCheckError(
                StaticCheckCode.CREDENTIAL_PLAINTEXT,
                path,
            )
    if scanned <= 0:
        raise StaticCheckError(StaticCheckCode.EMPTY_SECRET_SCAN, root)
    return scanned


def _secret_candidates(root: Path) -> Iterator[Path]:
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        relative = path.relative_to(root)
        location = relative.as_posix()
        excluded = any(
            part in EXCLUDED_DIRECTORY_NAMES for part in relative.parts
        ) or any(location.startswith(prefix) for prefix in EXCLUDED_PREFIXES)
        executable = bool(path.stat().st_mode & stat.S_IXUSR)
        candidate = (
            len(relative.parts) == 1
            or path.suffix.casefold() in SCANNED_SUFFIXES
            or path.name in SCANNED_NAMES
            or path.name.startswith(SCANNED_NAME_PREFIXES)
            or path.name.startswith(".env")
            or executable
        )
        if candidate and not excluded:
            yield path


def check_drift(root: Path) -> int:
    """Compare the checked-in OpenAPI type and mock catalog byte-for-byte."""
    verify_generated_contract(
        GeneratedContract.from_paths(
            root / "packages/contracts/openapi/openapi.json",
            root / ".ci/generated/openapi-catalog.json",
        )
    )
    return 1


def main() -> int:
    """Run exactly one named non-vacuous static check."""
    if len(sys.argv) != CLI_ARG_COUNT:
        raise StaticCheckError(StaticCheckCode.USAGE, Path.cwd())
    try:
        mode = StaticMode(sys.argv[1])
    except ValueError as error:
        raise StaticCheckError(
            StaticCheckCode.UNKNOWN_CHECK,
            Path(sys.argv[1]),
        ) from error
    root = Path(sys.argv[2]).resolve()
    count = _run(mode, root)
    _ = sys.stdout.write(f"CHECKS_EXECUTED={count}\n")
    return 0


def _run(mode: StaticMode, root: Path) -> int:
    checks = {
        StaticMode.SBOM: check_sbom,
        StaticMode.SECRET_SCAN: check_secrets,
        StaticMode.DRIFT_SCAN: check_drift,
    }
    return checks[mode](root)


if __name__ == "__main__":
    raise SystemExit(main())
