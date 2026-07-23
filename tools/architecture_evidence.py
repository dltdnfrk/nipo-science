"""Validate architecture evidence references against checked-in digest sidecars."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path, PurePosixPath
from typing import TYPE_CHECKING, Final

if TYPE_CHECKING:
    from tools.architecture_manifest import JsonValue

EVIDENCE_PREFIX: Final = ("tools", "evidence")
MIN_EVIDENCE_PARTS: Final = 3
CHECKSUM_FIELD_COUNT: Final = 2


def _is_regular_without_symlinks(project_root: Path, path: Path) -> bool:
    try:
        relative = path.relative_to(project_root)
    except ValueError:
        return False
    current = project_root
    for part in relative.parts:
        current /= part
        if current.is_symlink():
            return False
    return path.is_file()


def _evidence_checksum(sidecar: Path, evidence: str) -> str | None:
    try:
        records = tuple(
            fields
            for line in sidecar.read_text(encoding="utf-8").splitlines()
            if len(fields := line.split()) == CHECKSUM_FIELD_COUNT
            and fields[1] == evidence
        )
    except (OSError, UnicodeError):
        return None
    if len(records) != 1:
        return None
    digest = records[0][0]
    return digest if re.fullmatch(r"[0-9a-f]{64}", digest) else None


def check_evidence_reference(
    project_root: Path,
    evidence: JsonValue,
    threat_id: JsonValue,
) -> str | None:
    """Return the exact violation for an unsafe or unbound evidence reference."""
    if not isinstance(evidence, str):
        return f"invalid-evidence-path:{threat_id}"
    relative = PurePosixPath(evidence)
    if (
        relative.is_absolute()
        or relative.parts[:2] != EVIDENCE_PREFIX
        or len(relative.parts) < MIN_EVIDENCE_PARTS
        or ".." in relative.parts
        or "\\" in evidence
    ):
        return f"invalid-evidence-path:{threat_id}"
    path = project_root.joinpath(*relative.parts)
    if not _is_regular_without_symlinks(project_root, path):
        return f"missing-evidence:{threat_id}"
    sidecar = path.with_suffix(".sha256")
    if not _is_regular_without_symlinks(project_root, sidecar):
        return f"missing-evidence-checksum:{threat_id}"
    expected = _evidence_checksum(sidecar, evidence)
    try:
        observed = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        observed = None
    if expected is None:
        violation = f"invalid-evidence-checksum:{threat_id}"
    elif observed is None:
        violation = f"missing-evidence:{threat_id}"
    elif observed != expected:
        violation = f"evidence-digest-mismatch:{threat_id}"
    else:
        violation = None
    return violation
