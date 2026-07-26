"""Read-only identifier projections the local HTTP surface needs to list.

`LocalArtifactStore` reads exactly one Artifact and exactly one Version at a
time, because that is all the shared `ArtifactStore` contract asks of it. A
browser front end additionally needs to *enumerate*: which Artifacts exist in
a Project, and which Versions an Artifact has. This module supplies only that
enumeration.

Two deliberate limits keep the coupling honest:

* It returns identifiers and nothing else. Every field the front end renders
  is then read back through `LocalArtifactStore`, so the store stays the sole
  authority on record shape, archival visibility, and digest verification. A
  schema change in `store.py` can therefore break a listing's *order*, never a
  response's *content*.
* The connection is opened with `PRAGMA query_only = 1`. That is enforced by
  SQLite rather than promised by review: a stray write on this connection
  fails at the engine, so this module cannot corrupt the durable state its
  owner is responsible for.

This is a seam, not an architecture. When `store.py` grows `artifacts()` and
`versions()` projections of its own, delete this module and call them.
"""

import sqlite3
from contextlib import suppress
from typing import TYPE_CHECKING, cast, final
from uuid import UUID

from services.api.artifacts.store_contract import ArtifactStoreError

if TYPE_CHECKING:
    from services.api.artifacts.models import ArtifactScope

    from .config import LocalPaths

ARTIFACT_IDS: str = """
SELECT a.id
FROM artifacts a
WHERE a.org_id = ? AND a.project_id = ?
ORDER BY a.created_at DESC, a.id DESC
"""

VERSION_IDS: str = """
SELECT v.id
FROM artifact_versions v
WHERE v.org_id = ? AND v.project_id = ? AND v.artifact_id = ?
ORDER BY v.version_no ASC
"""


@final
class LocalReadModel:
    """Enumerate Artifact and Version identifiers over a query-only connection."""

    def __init__(self, paths: "LocalPaths", timeout: float = 5.0) -> None:
        """Open a query-only connection to an existing local database.

        Args:
            paths: The resolved layout whose database is already initialized
                by `LocalArtifactStore`; this module never creates schema.
            timeout: Seconds to wait on the SQLite lock before failing.

        Raises:
            ArtifactStoreError: The database could not be opened read-only.
        """
        try:
            self._connection = sqlite3.connect(
                paths.database,
                isolation_level=None,
                check_same_thread=False,
                timeout=timeout,
            )
            _ = self._connection.execute("PRAGMA query_only = 1")
        except sqlite3.Error as error:
            raise ArtifactStoreError from error

    def __enter__(self) -> "LocalReadModel":
        """Return the open projection for scoped local use."""
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: object,
    ) -> None:
        """Close the underlying connection."""
        self.close()

    def close(self) -> None:
        """Release the query-only SQLite connection."""
        with suppress(sqlite3.Error):
            self._connection.close()

    def artifact_ids(self, scope: "ArtifactScope") -> tuple[UUID, ...]:
        """List one Project's Artifact identifiers, newest first."""
        return self._identifiers(
            ARTIFACT_IDS,
            (str(scope.org_id), str(scope.project_id)),
        )

    def version_ids(
        self,
        scope: "ArtifactScope",
        artifact_id: UUID,
    ) -> tuple[UUID, ...]:
        """List one Artifact's Version identifiers in commit order."""
        return self._identifiers(
            VERSION_IDS,
            (str(scope.org_id), str(scope.project_id), str(artifact_id)),
        )

    def _identifiers(
        self,
        statement: str,
        parameters: tuple[str, ...],
    ) -> tuple[UUID, ...]:
        """Run one projection and parse its single identifier column."""
        try:
            rows = cast(
                "list[tuple[object, ...]]",
                self._connection.execute(statement, parameters).fetchall(),
            )
        except sqlite3.Error as error:
            raise ArtifactStoreError from error
        identifiers: list[UUID] = []
        for row in rows:
            value = row[0]
            if not isinstance(value, str):
                raise ArtifactStoreError
            identifiers.append(UUID(value))
        return tuple(identifiers)
