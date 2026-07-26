"""Local-first runtime configuration.

Nipo Science local runs as a single-user application on the researcher's own
machine. The multi-tenant identity fields required by the shared Artifact
models (`org_id`, `requester_id`, ...) are satisfied here by fixed local
constants so that `ArtifactService` and the Artifact model contracts are reused
verbatim rather than forked.

Data lives under `~/.nipo-science`, deliberately outside `~/Documents`:
macOS 'Desktop & Documents' iCloud sync covers `~/Documents`, and research
inputs plus the knowledge store must not be uploaded implicitly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Final
from uuid import UUID

# Fixed single-user identity. These are valid UUIDv7 values so they satisfy the
# `Uuid7` field type used across the shared Artifact models.
LOCAL_ORG_ID: Final = UUID("01900000-0000-7000-8000-000000000001")
LOCAL_USER_ID: Final = UUID("01900000-0000-7000-8000-000000000002")
DEFAULT_PROJECT_ID: Final = UUID("01900000-0000-7000-8000-000000000003")

# The local runtime executes deterministic Python in-process; there is no
# qualified remote runtime binding. These constants fill the provenance fields
# that the shared ArtifactVersion model requires.
LOCAL_RUNTIME_ADAPTER_ID: Final = "local_deterministic"
LOCAL_RUNTIME_CONNECTION_ID: Final = UUID("01900000-0000-7000-8000-000000000004")

DEFAULT_ROOT: Final = Path.home() / ".nipo-science"

# The data root holds research inputs, the knowledge store, and sealed provider
# credentials. Nothing here is readable by another account on this machine.
ROOT_MODE: Final = 0o700


@dataclass(frozen=True, slots=True)
class LocalPaths:
    """Resolved on-disk layout for one local installation."""

    root: Path

    @property
    def database(self) -> Path:
        """SQLite file holding Artifact, Version, and Session records."""
        return self.root / "nipo.sqlite3"

    @property
    def blobs(self) -> Path:
        """Content-addressed Artifact payload bytes."""
        return self.root / "blobs"

    @property
    def credentials(self) -> Path:
        """Provider credential store. Never leaves this machine."""
        return self.root / "credentials.json"

    @property
    def settings(self) -> Path:
        """Provider selection and composer defaults."""
        return self.root / "settings.json"

    def ensure(self) -> None:
        """Create the owner-only directory layout if it does not exist yet.

        `mkdir` applies the process umask to its `mode`, and `exist_ok` leaves a
        directory created by an earlier version untouched, so each directory is
        chmod'ed explicitly afterwards. That makes the mode independent of the
        umask and repairs a root that predates this rule.
        """
        for directory in (self.root, self.blobs):
            directory.mkdir(parents=True, exist_ok=True, mode=ROOT_MODE)
            directory.chmod(ROOT_MODE)


def resolve_paths(root: Path | None = None) -> LocalPaths:
    """Resolve the local layout, honouring an explicit override for tests."""
    return LocalPaths(root=(root or DEFAULT_ROOT).expanduser())
