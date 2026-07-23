"""Emit the canonical checkout identity for the GitHub Actions environment."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from collections.abc import Sequence

from .release_contract import source_tree_sha256


def main(arguments: Sequence[str] | None = None) -> int:
    """Print one environment-file assignment for an exact checkout root."""
    supplied = tuple(sys.argv[1:] if arguments is None else arguments)
    if len(supplied) != 1:
        return 2
    root = Path(supplied[0]).resolve(strict=True)
    if not root.is_dir():
        return 2
    _ = sys.stdout.write(f"CI_SOURCE_TREE_SHA256={source_tree_sha256(root)}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
