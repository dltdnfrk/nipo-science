"""Resolve static path values relative to the boundary scan root."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TYPE_CHECKING, Final, NamedTuple

if TYPE_CHECKING:
    from tools.boundary_ast_rules import ImportAliases

OUTSIDE_COMPONENT_RE: Final = re.compile(r"(?:^|[/\\\s\"'])\.\.(?:[/\\]|$)")
TEMPORARY_ROOT: Final = ".boundary-temporary"
CONFINED_RELATIVE: Final = ".boundary-confined"


class PathValue(NamedTuple):
    """A resolved path fragment and its certainty and escape state."""

    raw: str
    escapes: bool
    complete: bool


def escapes_target(raw: str) -> bool:
    """Return whether a raw path contains a parent-directory component."""
    return OUTSIDE_COMPONENT_RE.search(raw.replace("\\", "/")) is not None


class PathContext(NamedTuple):
    """Resolution context for one Python source file."""

    source: Path
    root: Path
    aliases: ImportAliases

    def value(self, raw: str, complete: bool = True) -> PathValue:
        """Resolve one raw path against the target root."""
        if not complete:
            return PathValue(raw=raw, escapes=escapes_target(raw), complete=False)
        candidate = Path(raw)
        resolved = (
            candidate if candidate.is_absolute() else self.root / candidate
        ).resolve(strict=False)
        try:
            _ = resolved.relative_to(self.root)
        except ValueError:
            return PathValue(raw=raw, escapes=True, complete=True)
        return PathValue(raw=raw, escapes=False, complete=True)

    def join(self, left: PathValue | None, right: PathValue | None) -> PathValue | None:
        """Join two possibly incomplete path values."""
        if left is None:
            return (
                None
                if right is None
                else PathValue(raw=right.raw, escapes=right.escapes, complete=False)
            )
        if right is None:
            return PathValue(
                raw=left.raw,
                escapes=not left.raw.startswith(TEMPORARY_ROOT),
                complete=False,
            )
        if left.complete and right.complete:
            return self.value(str(Path(left.raw) / right.raw))
        raw = f"{left.raw}/{right.raw}"
        uncertain = (
            not left.complete or not right.complete
        ) and not left.raw.startswith(TEMPORARY_ROOT)
        return PathValue(
            raw=raw,
            escapes=uncertain or left.escapes or right.escapes or escapes_target(raw),
            complete=False,
        )

    def concat(
        self, left: PathValue | None, right: PathValue | None
    ) -> PathValue | None:
        """Concatenate two possibly incomplete string path values."""
        if left is None:
            return (
                None
                if right is None
                else PathValue(raw=right.raw, escapes=right.escapes, complete=False)
            )
        if right is None:
            return PathValue(raw=left.raw, escapes=left.escapes, complete=False)
        raw = left.raw + right.raw
        if left.complete and right.complete:
            return self.value(raw)
        return PathValue(
            raw=raw,
            escapes=left.escapes or right.escapes or escapes_target(raw),
            complete=False,
        )
