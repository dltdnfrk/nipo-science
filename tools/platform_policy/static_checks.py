"""Dependency inventory and credential scan checks."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Final

from .secret_scan import check_secrets
from .static_check_types import StaticCheckCode, StaticCheckError, StaticMode
from .workflow_policy import check_workflow_actions

__all__ = ["check_secrets"]

CLI_ARG_COUNT: Final = 3


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
    }
    return checks[mode](root)


if __name__ == "__main__":
    raise SystemExit(main())
