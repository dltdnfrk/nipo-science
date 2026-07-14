"""Inspect source and manifest text for repository boundary violations."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Final, NamedTuple

if TYPE_CHECKING:
    from pathlib import Path

from tools.boundary_write_rules import find_outside_writes

SOURCE_SUFFIXES: Final = frozenset(
    {".bash", ".cjs", ".js", ".mjs", ".mts", ".py", ".sh", ".ts", ".tsx", ".zsh"}
)
MANIFEST_NAMES: Final = frozenset(
    {
        "Cargo.toml",
        "go.mod",
        "package.json",
        "pnpm-workspace.yaml",
        "pnpm-workspace.yml",
        "pyproject.toml",
    }
)
WORKSPACE_NAMES: Final = frozenset(
    {
        "Cargo.toml",
        "go.work",
        "package.json",
        "pnpm-workspace.yaml",
        "pnpm-workspace.yml",
    }
)
BUILD_NAMES: Final = frozenset(
    {
        "Dockerfile",
        "Containerfile",
        "Makefile",
        "Taskfile.yml",
        "compose.yaml",
        "compose.yml",
        "docker-compose.yaml",
        "docker-compose.yml",
    }
)
SIBLING_PATH = r"(?:(?:\.\./)+|/)(?:drylab|ontologylab)(?:/|[\"'\s),}]|$)"
SIBLING_PATH_RE: Final = re.compile(SIBLING_PATH)
PYTHON_IMPORT_RE: Final = re.compile(
    r"(?m)^\s*(?:from|import)\s+(?:drylab|ontologylab)(?:\.|\s|$)"
)
MODULE_IMPORT_RE: Final = re.compile(
    r"(?:from\s+|import\s*\(|require\s*\()\s*[\"'][^\"']*(?:drylab|ontologylab)(?:/|[\"'])"
)
PATH_DEPENDENCY_RE: Final = re.compile(
    rf"(?:file:|link:|workspace:|\bpath\s*[=:])[^\n]*{SIBLING_PATH}",
    re.IGNORECASE,
)
OUTSIDE_PATH_RE: Final = re.compile(r"(?:^|[\"'\s:=,\[])\.\./", re.MULTILINE)
BUILD_INPUT_RE: Final = re.compile(
    r"(?mi)^\s*(?:(?:COPY|ADD)(?:\s+--\S+)*\s+(?:\[\s*[\"']?)?\.\./|(?:context|dockerfile)\s*:\s*[\"']?\.\./)"
)
WRITE_HINT_RE: Final = re.compile(
    r"(?:>{1,2}\s*|\b(?:cp|install|mkdir|mv|rm|tee|touch)\b|\.write_(?:bytes|text)\s*\(|\.mkdir\s*\(|\.touch\s*\(|open\s*\([^\n]*,[^\n]*[\"'][wax+])"
)


class Violation(NamedTuple):
    """One repository boundary violation with a source location."""

    kind: str
    path: Path
    line: int
    detail: str


def line_number(text: str, offset: int) -> int:
    """Map a text offset to its one-based source line."""
    return text.count("\n", 0, offset) + 1


def inspect_text(path: Path, root: Path) -> tuple[Violation, ...]:
    """Inspect one text file for imports, paths, manifests, and write escapes."""
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError:
        return ()
    relative = path.relative_to(root)
    found: list[Violation] = []

    if path.suffix in SOURCE_SUFFIXES:
        found.extend(
            Violation(
                "sibling-import",
                relative,
                line_number(text, match.start()),
                match.group(0).strip(),
            )
            for match in PYTHON_IMPORT_RE.finditer(text)
        )
        found.extend(
            Violation(
                "sibling-import",
                relative,
                line_number(text, match.start()),
                match.group(0).strip(),
            )
            for match in MODULE_IMPORT_RE.finditer(text)
        )
        for match in SIBLING_PATH_RE.finditer(text):
            start = text.rfind("\n", 0, match.start()) + 1
            end = text.find("\n", match.end())
            line = text[start:] if end == -1 else text[start:end]
            if WRITE_HINT_RE.search(line):
                found.append(
                    Violation(
                        "sibling-write-path",
                        relative,
                        line_number(text, match.start()),
                        line.strip(),
                    )
                )
        found.extend(
            Violation("outside-write-path", relative, finding.line, finding.detail)
            for finding in find_outside_writes(path, root, text)
        )

    if path.name in MANIFEST_NAMES:
        found.extend(
            Violation(
                "sibling-path-dependency",
                relative,
                line_number(text, match.start()),
                match.group(0).strip(),
            )
            for match in PATH_DEPENDENCY_RE.finditer(text)
        )

    workspace_manifest = path.name in WORKSPACE_NAMES and (
        path.name != "package.json" or '"workspaces"' in text
    )
    if workspace_manifest:
        found.extend(
            Violation(
                "workspace-reference",
                relative,
                line_number(text, match.start()),
                match.group(0).strip(),
            )
            for match in OUTSIDE_PATH_RE.finditer(text)
        )

    build_file = path.name in BUILD_NAMES or path.name.startswith(
        ("Dockerfile.", "Containerfile.")
    )
    if build_file:
        found.extend(
            Violation(
                "outside-build-input",
                relative,
                line_number(text, match.start()),
                match.group(0).strip(),
            )
            for match in BUILD_INPUT_RE.finditer(text)
        )
    return tuple(found)
