"""Owner-private storage boundaries supplied by live-capture deployments."""

from __future__ import annotations

import os
import stat
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Final, assert_never

from services.api.provider_live_capture_errors import (
    ERROR_CAPTURE_ROOTS,
    ERROR_OUTPUT_BOUNDARY,
    ERROR_OUTPUT_EXISTS,
    capture_error,
)

OUTPUT_ROOT_ENV: Final = "PROVIDER_LIVE_CAPTURE_OUTPUT_ROOT"
SCRATCH_ROOT_ENV: Final = "PROVIDER_LIVE_CAPTURE_SCRATCH_ROOT"
_PRIVATE_DIRECTORY_MODE: Final = 0o700


@dataclass(frozen=True, slots=True)
class CaptureRoots:
    """Validated output and transient-work roots owned by the capture process."""

    output: Path
    scratch: Path

    def validate(self) -> CaptureRoots:
        """Require distinct canonical absolute owner-private directories."""
        output = _private_root(self.output)
        scratch = _private_root(self.scratch)
        if output == scratch:
            raise capture_error(ERROR_CAPTURE_ROOTS)
        return CaptureRoots(output, scratch)

    def resolve_output(self, output: Path) -> Path:
        """Resolve one absolute artifact path within the current output root."""
        roots = self.validate()
        if not output.is_absolute():
            raise capture_error(ERROR_OUTPUT_BOUNDARY)
        try:
            relative = output.resolve().relative_to(roots.output)
        except (OSError, ValueError) as error:
            raise capture_error(ERROR_OUTPUT_BOUNDARY) from error
        if relative == Path():
            raise capture_error(ERROR_OUTPUT_BOUNDARY)
        return roots.output / relative


@dataclass(frozen=True, slots=True)
class CaptureTarget:
    """One profile artifact bound to explicit output and scratch roots."""

    output: Path
    roots: CaptureRoots


type CaptureTargetInput = Path | CaptureTarget


def configured_capture_roots() -> CaptureRoots:
    """Load the two required roots without a source-tree or platform fallback."""
    output = os.environ.get(OUTPUT_ROOT_ENV)
    scratch = os.environ.get(SCRATCH_ROOT_ENV)
    if output is None or scratch is None:
        raise capture_error(ERROR_CAPTURE_ROOTS)
    return CaptureRoots(Path(output), Path(scratch)).validate()


def resolve_capture_target(target: CaptureTargetInput) -> CaptureTarget:
    """Resolve an injected target or load required deployment root settings."""
    match target:
        case CaptureTarget(output=output, roots=roots):
            validated_roots = roots.validate()
        case Path() as output:
            validated_roots = configured_capture_roots()
        case _ as unreachable:
            assert_never(unreachable)
    return CaptureTarget(validated_roots.resolve_output(output), validated_roots)


def atomic_publish(roots: CaptureRoots, output: Path, content: str) -> None:
    """Publish once under the configured output root without replacement."""
    resolved_output = roots.resolve_output(output)
    resolved_output.parent.mkdir(
        mode=_PRIVATE_DIRECTORY_MODE,
        parents=True,
        exist_ok=True,
    )
    if resolved_output.exists():
        raise capture_error(ERROR_OUTPUT_EXISTS)
    descriptor, temporary = tempfile.mkstemp(
        prefix=".capture-",
        dir=resolved_output.parent,
    )
    temporary_path = Path(temporary)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            _ = handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            _ = os.link(temporary_path, resolved_output)
        except FileExistsError as error:
            raise capture_error(ERROR_OUTPUT_EXISTS) from error
    finally:
        _ = temporary_path.unlink(missing_ok=True)


def require_private_scratch_root(root: Path) -> Path:
    """Revalidate a deployment scratch root immediately before transient writes."""
    return _private_root(root)


def _private_root(root: Path) -> Path:
    if not root.is_absolute():
        raise capture_error(ERROR_CAPTURE_ROOTS)
    try:
        root_stat = root.lstat()
        resolved = root.resolve(strict=True)
    except OSError as error:
        raise capture_error(ERROR_CAPTURE_ROOTS) from error
    if (
        resolved != root
        or not stat.S_ISDIR(root_stat.st_mode)
        or root_stat.st_uid != os.getuid()
        or stat.S_IMODE(root_stat.st_mode) != _PRIVATE_DIRECTORY_MODE
    ):
        raise capture_error(ERROR_CAPTURE_ROOTS)
    return resolved
