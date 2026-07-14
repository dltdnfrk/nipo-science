#!/usr/bin/env -S uv run --script
# /// script
# requires-python = ">=3.8"
# dependencies = []
# ///

"""Scan a repository root for cross-workspace references and escaping writes."""

# ─── How to run ───
# 1. Install uv (if not installed):
#      curl -LsSf https://astral.sh/uv/install.sh | sh
# 2. Run directly (no venv or dependency install needed):
#      uv run tools/check_boundaries.py [TARGET_ROOT]
# 3. Or make executable and run:
#      chmod +x tools/check_boundaries.py && ./tools/check_boundaries.py [TARGET_ROOT]
# ─────────────────

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Final, NamedTuple

TOOLS_PARENT = Path(__file__).resolve().parents[1]
if str(TOOLS_PARENT) not in sys.path:
    sys.path.insert(0, str(TOOLS_PARENT))

from tools.boundary_text_rules import Violation, inspect_text  # noqa: E402

IGNORED_DIRECTORIES: Final = frozenset(
    {
        ".cache",
        ".git",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tools",
        ".venv",
        "__pycache__",
        "node_modules",
    }
)
ROOT_ONLY_IGNORED_DIRECTORIES: Final = frozenset(
    {"artifacts", "playwright-report", "test-results"}
)
IGNORED_DIRECTORY_PREFIXES: Final = frozenset(
    {(".ci", "evidence"), (".ci", "failed-attempts")}
)


class ScanResult(NamedTuple):
    """Boundary violations and the number of regular files inspected."""

    violations: tuple[Violation, ...]
    scanned_files: int


def is_inside(path: Path, root: Path) -> bool:
    """Return whether a resolved path is contained by the scan root."""
    try:
        _ = path.relative_to(root)
    except ValueError:
        return False
    return True


def inspect_symlink(path: Path, root: Path) -> Violation | None:
    """Return a violation when a symlink target escapes the scan root."""
    target = path.resolve(strict=False)
    if is_inside(target, root):
        return None
    return Violation(
        "escaping-symlink",
        path.relative_to(root),
        0,
        f"target resolves outside root: {target}",
    )


def is_ignored_directory(path: Path, root: Path) -> bool:
    """Return whether a directory is generated rather than source."""
    relative = path.relative_to(root).parts
    return (
        path.name in IGNORED_DIRECTORIES
        or (len(relative) == 1 and path.name in ROOT_ONLY_IGNORED_DIRECTORIES)
        or any(
            relative[: len(prefix)] == prefix for prefix in IGNORED_DIRECTORY_PREFIXES
        )
    )


def scan(root: Path) -> ScanResult:
    """Recursively scan one root without traversing ignored or linked directories."""
    violations: list[Violation] = []
    scanned_files = 0
    for current, directories, files in os.walk(root, followlinks=False):
        current_path = Path(current)
        retained: list[str] = []
        for name in sorted(directories):
            path = current_path / name
            if is_ignored_directory(path, root):
                continue
            if path.is_symlink():
                violation = inspect_symlink(path, root)
                if violation is not None:
                    violations.append(violation)
            else:
                retained.append(name)
        directories[:] = retained

        for name in sorted(files):
            path = current_path / name
            if path.is_symlink():
                violation = inspect_symlink(path, root)
                if violation is not None:
                    violations.append(violation)
                continue
            scanned_files += 1
            violations.extend(inspect_text(path, root))
    return ScanResult(tuple(violations), scanned_files)


def main(arguments: list[str]) -> int:
    """Run the boundary checker command-line interface."""
    if arguments == ["--help"]:
        _ = sys.stdout.write("usage: check_boundaries.py [TARGET_ROOT]\n")
        return 0
    if len(arguments) > 1:
        _ = sys.stderr.write("usage: check_boundaries.py [TARGET_ROOT]\n")
        return 2
    root = Path(arguments[0] if arguments else ".").resolve()
    if not root.is_dir():
        _ = sys.stderr.write(
            f"boundary-check: target root is not a directory: {root}\n"
        )
        return 2

    result = scan(root)
    if result.violations:
        for violation in result.violations:
            location = (
                f"{violation.path}:{violation.line}"
                if violation.line
                else str(violation.path)
            )
            prefix = f"BOUNDARY VIOLATION [{violation.kind}] {location}: "
            message = f"{prefix}{violation.detail}\n"
            _ = sys.stdout.write(message)
        return 1
    _ = sys.stdout.write(
        f"boundary-check: PASS ({result.scanned_files} files checked)\n"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
