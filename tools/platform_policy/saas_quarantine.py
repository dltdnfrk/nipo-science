"""SaaS quarantine inventory and import boundary for the local-first cutover.

ADR-0011 retires the hosted multi-tenant service plane in staged deletions
while ``apps/local`` (nipo_local) keeps reusing a fixed closure of
``services.api.artifacts`` modules plus ``packages/science`` and
``packages/contracts``. This module declares both inventories declaratively
and fails when keep-side code imports a deletion-scheduled SaaS module, when
a declared closure module disappears from disk, or when a deletion-scheduled
pattern no longer matches any module (a stale entry means a deletion stage
landed without updating this inventory in the same commit).

Imports *within* the deletion-scheduled zone are intentionally allowed: the
zone is removed wholesale, so SaaS modules importing each other is not drift.
The boundary that must hold from Stage 0 onward is that the keep side —
nipo_local and the reuse closure itself — never depends on the zone.

``services/api/artifacts/__init__.py`` is deliberately not audited: it still
re-exports ``PostgresArtifactStore`` until the Stage 2 same-commit pruning
drops that name together with the postgres modules.
"""

from __future__ import annotations

import ast
import fnmatch
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from collections.abc import Iterator

__all__ = [
    "ALLOWED_REUSE_CLOSURE",
    "AUDITED_PACKAGE_ROOTS",
    "DELETION_SCHEDULED_MODULES",
    "main",
    "scan",
]

_ARTIFACTS_PACKAGE: Final = "services.api.artifacts"
_ARTIFACTS_ROOT: Final = "services/api/artifacts"

_CLOSURE_MODULE_NAMES: Final = (
    "models",
    "runtime",
    "store_contract",
    "memory_recovery",
    "service",
    "watcher",
    "signing",
    "recovery",
    "blob_store",
    "blob_filesystem",
    "file_recovery",
    "file_recovery_storage",
    "store",
)

ALLOWED_REUSE_CLOSURE: Final = frozenset(
    {_ARTIFACTS_PACKAGE}
    | {f"{_ARTIFACTS_PACKAGE}.{name}" for name in _CLOSURE_MODULE_NAMES}
)
"""Dotted modules nipo_local may keep importing after the SaaS plane is gone.

Includes the indirect ``__init__`` re-export closure (``blob_store``,
``blob_filesystem``, ``file_recovery``, ``file_recovery_storage``, ``store``)
and ``signing`` (pulled in through ``service``), per the Stage 0 acceptance.
"""

DELETION_SCHEDULED_MODULES: Final = (
    "services.api.product_*",
    "services.api.provider_*",
    "services.api.tool_governance",
    "services.api.connector_registry",
    "services.api.bounded_http",
    "services.api.artifact_ui_*",
    "services.api.artifact_production_app",
    "services.api.dry_lab_fixture",
    "services.api.persistence",
    "services.api.upload",
    "services.api.migrations",
    "services.api.artifacts.composition",
    "services.api.artifacts.http",
    "services.api.artifacts.scope_resolver",
    "services.api.artifacts.postgres_*",
    "services.local",
    "services.worker",
)
"""Fnmatch patterns over dotted module names scheduled for staged deletion."""

AUDITED_PACKAGE_ROOTS: Final = (
    "apps/local",
    "packages/science",
    "packages/contracts/python",
)
"""Keep-side trees scanned recursively; closure files are scanned directly."""

_CLI_OK: Final = 0
_CLI_VIOLATIONS: Final = 1
_CLI_USAGE: Final = 2


def _matches(pattern: str, name: str) -> bool:
    """Return whether a dotted module name is covered by an inventory pattern.

    Args:
        pattern: Fnmatch pattern over dotted module names.
        name: Dotted module name to classify.

    Returns:
        True when the name itself or any of its parent packages matches.
    """
    parts = name.split(".")
    prefixes = [".".join(parts[:index]) for index in range(1, len(parts) + 1)]
    return any(fnmatch.fnmatchcase(prefix, pattern) for prefix in prefixes)


def _is_deletion_scheduled(name: str) -> bool:
    """Return whether a dotted module name belongs to the SaaS deletion zone.

    Args:
        name: Dotted module name to classify.

    Returns:
        True when any deletion-scheduled pattern covers the name.
    """
    return any(_matches(pattern, name) for pattern in DELETION_SCHEDULED_MODULES)


def _is_closure_parent(name: str) -> bool:
    """Return whether a name is a strict parent package of the closure.

    Args:
        name: Dotted module name to classify.

    Returns:
        True for namespace packages such as ``services`` or ``services.api``.
    """
    return any(item.startswith(f"{name}.") for item in ALLOWED_REUSE_CLOSURE)


def _classify(relative: str, name: str) -> str | None:
    """Classify one imported dotted name as a violation or allowed.

    Args:
        relative: Repository-relative path of the importing file.
        name: Dotted module name being imported.

    Returns:
        A violation identifier, or None when the import is allowed.
    """
    if not name.startswith("services"):
        return None
    if _is_deletion_scheduled(name):
        return f"saas-quarantine-import:{relative}:{name}"
    if name in ALLOWED_REUSE_CLOSURE or _is_closure_parent(name):
        return None
    if name.startswith("services.api."):
        return f"saas-quarantine-unclassified:{relative}:{name}"
    return None


def _resolve_from(node: ast.ImportFrom, package: tuple[str, ...]) -> str:
    """Resolve an ImportFrom node to an absolute dotted module name.

    Args:
        node: The import node to resolve.
        package: Dotted package parts of the importing file's directory.

    Returns:
        The absolute dotted name the import binds against.
    """
    if node.level == 0:
        return node.module or ""
    anchor = package[: len(package) - node.level + 1]
    suffix = tuple(node.module.split(".")) if node.module else ()
    return ".".join((*anchor, *suffix))


def _file_violations(root: Path, path: Path) -> list[str]:
    """Collect quarantine violations from one audited Python file.

    Args:
        root: Repository root used for relative reporting.
        path: Python file to inspect.

    Returns:
        Violation identifiers found in the file's import statements.
    """
    relative = path.relative_to(root).as_posix()
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=relative)
    except SyntaxError:
        return [f"saas-quarantine-syntax:{relative}"]
    package = tuple(path.parent.relative_to(root).parts)
    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            violations.extend(
                violation
                for alias in node.names
                if (violation := _classify(relative, alias.name)) is not None
            )
        elif isinstance(node, ast.ImportFrom):
            resolved = _resolve_from(node, package)
            violation = _classify(relative, resolved)
            if violation is not None:
                violations.append(violation)
            elif not _is_deletion_scheduled(resolved):
                violations.extend(
                    f"saas-quarantine-import:{relative}:{candidate}"
                    for alias in node.names
                    if _is_deletion_scheduled(candidate := f"{resolved}.{alias.name}")
                )
    return violations


def _iter_audited_files(root: Path) -> Iterator[Path]:
    """Yield keep-side Python files subject to the import boundary.

    Args:
        root: Repository root containing the audited trees.

    Yields:
        Python files under the audited roots plus each closure module file.
    """
    for relative_root in AUDITED_PACKAGE_ROOTS:
        base = root / relative_root
        if base.is_dir():
            yield from (
                path
                for path in sorted(base.rglob("*.py"))
                if "__pycache__" not in path.parts
            )
    artifacts = root / _ARTIFACTS_ROOT
    for name in _CLOSURE_MODULE_NAMES:
        candidate = artifacts / f"{name}.py"
        if candidate.is_file():
            yield candidate


def _closure_violations(root: Path) -> list[str]:
    """Report declared closure modules that are missing from disk.

    Args:
        root: Repository root containing ``services/api/artifacts``.

    Returns:
        One violation per missing closure module; guards the reuse closure
        against accidental deletion during the staged cutover.
    """
    artifacts = root / _ARTIFACTS_ROOT
    violations = [
        f"saas-quarantine-missing-closure:{_ARTIFACTS_PACKAGE}.{name}"
        for name in _CLOSURE_MODULE_NAMES
        if not (artifacts / f"{name}.py").is_file()
    ]
    if not (artifacts / "__init__.py").is_file():
        violations.append(f"saas-quarantine-missing-closure:{_ARTIFACTS_PACKAGE}")
    return violations


def _service_module_names(root: Path) -> tuple[str, ...]:
    """List dotted module names of every Python file under ``services``.

    Args:
        root: Repository root containing the ``services`` tree.

    Returns:
        Dotted names with package ``__init__`` files collapsed to the package.
    """
    services = root / "services"
    if not services.is_dir():
        return ()
    names: list[str] = []
    for path in sorted(services.rglob("*.py")):
        if "__pycache__" in path.parts:
            continue
        parts = list(path.relative_to(root).with_suffix("").parts)
        if parts[-1] == "__init__":
            _ = parts.pop()
        names.append(".".join(parts))
    return tuple(names)


def _stale_pattern_violations(root: Path) -> list[str]:
    """Report deletion-scheduled patterns that no longer match the tree.

    Args:
        root: Repository root containing the ``services`` tree.

    Returns:
        One violation per pattern with no matching module on disk; a stale
        pattern means a deletion stage landed without an inventory update.
    """
    modules = _service_module_names(root)
    return [
        f"saas-quarantine-stale-pattern:{pattern}"
        for pattern in DELETION_SCHEDULED_MODULES
        if not any(_matches(pattern, module) for module in modules)
    ]


def scan(root: Path) -> tuple[str, ...]:
    """Return every quarantine violation for the given repository root.

    Args:
        root: Repository root to check.

    Returns:
        Sorted violation identifiers; empty when the quarantine holds.
    """
    violations = [*_closure_violations(root), *_stale_pattern_violations(root)]
    for path in _iter_audited_files(root):
        violations.extend(_file_violations(root, path))
    return tuple(sorted(violations))


def main(arguments: list[str]) -> int:
    """Run the quarantine check command-line interface.

    Args:
        arguments: Command-line arguments excluding the interpreter name;
            accepts at most one repository root, defaulting to the current
            directory.

    Returns:
        0 when the quarantine holds, 1 on violations, 2 on usage errors.
    """
    if arguments == ["--help"]:
        _ = sys.stdout.write("usage: saas_quarantine.py [ROOT]\n")
        return _CLI_OK
    if len(arguments) > 1:
        _ = sys.stderr.write("usage: saas_quarantine.py [ROOT]\n")
        return _CLI_USAGE
    root = Path(arguments[0] if arguments else ".").resolve()
    if not root.is_dir():
        _ = sys.stderr.write(f"quarantine-check: root missing: {root}\n")
        return _CLI_USAGE
    violations = scan(root)
    for violation in violations:
        _ = sys.stdout.write(f"QUARANTINE VIOLATION [{violation}]\n")
    if violations:
        return _CLI_VIOLATIONS
    _ = sys.stdout.write("quarantine-check: PASS\n")
    return _CLI_OK


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
