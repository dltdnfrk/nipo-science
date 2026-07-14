"""Immutable Artifact Version orchestration over watcher and store boundaries."""

from datetime import UTC, datetime, timedelta
from threading import RLock
from typing import Final, assert_never, final
from uuid import UUID

from .models import (
    ArtifactError,
    ArtifactErrorCode,
    ArtifactRecord,
    ArtifactScope,
    ArtifactVersion,
    Clock,
    DownloadClaims,
    IdFactory,
    SessionArtifactLink,
    SignedDownload,
    VersionDraft,
    WatcherClaim,
)
from .signing import DownloadSigner
from .store_contract import (
    ArtifactCommitError,
    ArtifactStore,
    ArtifactStoreError,
    BlobIntegrityError,
    StoreOutcome,
)
from .watcher import OutputWatcher

MAX_DOWNLOAD_TTL: Final = timedelta(minutes=10)
MIN_DOWNLOAD_TTL: Final = timedelta(milliseconds=1)
MAX_ARTIFACT_NAME_CHARACTERS: Final = 255


@final
class ArtifactService:
    """Create and read immutable Versions without trusting sandbox object keys."""

    def __init__(
        self,
        store: ArtifactStore,
        watcher: OutputWatcher,
        ids: IdFactory,
        clock: Clock,
        download_signing_key: bytes,
    ) -> None:
        """Bind trusted adapters used by all Artifact transitions."""
        self._store = store
        self._watcher = watcher
        self._ids = ids
        self._clock = clock
        self._signer = DownloadSigner(download_signing_key)
        self._lock = RLock()

    def create_artifact(self, scope: ArtifactScope, name: str) -> ArtifactRecord:
        """Create one server-owned Project Artifact identity."""
        normalized = " ".join(name.split())
        if not normalized or len(normalized) > MAX_ARTIFACT_NAME_CHARACTERS:
            raise ArtifactError(ArtifactErrorCode.NOT_FOUND)
        artifact = ArtifactRecord(
            id=self._ids.new_uuid7(),
            org_id=scope.org_id,
            project_id=scope.project_id,
            name=normalized,
            created_at=self._clock.now(),
        )
        self._require_created(self._store.create_artifact(scope, artifact))
        return artifact

    def create_version(
        self,
        scope: ArtifactScope,
        draft: VersionDraft,
    ) -> ArtifactVersion:
        """Create one monotonic Version with atomic CAS and pinned lineage."""
        with self._lock:
            claim = self._watcher.claim(
                scope,
                draft.producing_execution_id,
                draft.watcher_reference,
            )
            output = claim.output
            if (
                draft.runtime_adapter_id != output.runtime_adapter_id
                or draft.runtime_connection_id != output.runtime_connection_id
            ):
                self._watcher.release(claim)
                raise ArtifactError(ArtifactErrorCode.WATCHER_REFERENCE_INVALID)
            version = ArtifactVersion(
                id=self._ids.new_uuid7(),
                org_id=scope.org_id,
                project_id=scope.project_id,
                artifact_id=draft.artifact_id,
                version_no=draft.base_version_no + 1,
                object_key=self._store.object_key(scope, output.content_sha256),
                content_sha256=output.content_sha256,
                size_bytes=len(output.payload),
                media_type=output.media_type,
                producing_execution_id=draft.producing_execution_id,
                environment_sha256=draft.environment_sha256,
                code_sha256=draft.code_sha256,
                runtime_adapter_id=output.runtime_adapter_id,
                runtime_connection_id=output.runtime_connection_id,
                skill_content_hashes=draft.skill_content_hashes,
                source_hashes=draft.source_hashes,
                input_version_ids=tuple(sorted(draft.input_version_ids)),
                created_at=self._clock.now(),
            )
            try:
                outcome = self._store.commit_version(
                    scope,
                    draft.base_version_no,
                    version,
                    output.payload,
                )
            except BlobIntegrityError:
                self._watcher.release(claim)
                raise ArtifactError(ArtifactErrorCode.CHECKSUM_MISMATCH) from None
            except ArtifactCommitError as error:
                return self._reconcile_commit(scope, claim, version, error)
            if outcome is StoreOutcome.CREATED:
                self._watcher.finalize(claim)
            else:
                self._watcher.release(claim)
        self._require_created(outcome)
        return version

    def read_version(self, scope: ArtifactScope, version_id: UUID) -> ArtifactVersion:
        """Read one exact immutable Version or disclose no foreign existence."""
        version = self._store.version(scope, version_id)
        if version is None:
            raise ArtifactError(ArtifactErrorCode.NOT_FOUND)
        return version

    def read_content(self, scope: ArtifactScope, version_id: UUID) -> bytes:
        """Read checksum-verified bytes for one exact Version."""
        try:
            payload = self._store.read_content(scope, version_id)
        except BlobIntegrityError:
            raise ArtifactError(ArtifactErrorCode.CHECKSUM_MISMATCH) from None
        if payload is None:
            raise ArtifactError(ArtifactErrorCode.NOT_FOUND)
        return payload

    def lineage(self, scope: ArtifactScope, version_id: UUID) -> tuple[UUID, ...]:
        """Return immutable dependency Version IDs."""
        lineage = self._store.lineage(scope, version_id)
        if lineage is None:
            raise ArtifactError(ArtifactErrorCode.NOT_FOUND)
        return lineage

    def attach_session(
        self,
        scope: ArtifactScope,
        session_id: UUID,
        version_id: UUID,
    ) -> SessionArtifactLink:
        """Attach an exact Version to one same-Project Session once."""
        link = SessionArtifactLink(
            org_id=scope.org_id,
            project_id=scope.project_id,
            session_id=session_id,
            artifact_version_id=version_id,
            revision=1,
            created_at=self._clock.now(),
        )
        outcome = self._store.attach_session(scope, link)
        self._require_created(outcome)
        return link

    def issue_download(
        self,
        scope: ArtifactScope,
        version_id: UUID,
        ttl: timedelta,
    ) -> SignedDownload:
        """Issue an authorized download token for at most ten minutes."""
        if ttl < MIN_DOWNLOAD_TTL or ttl > MAX_DOWNLOAD_TTL:
            raise ArtifactError(ArtifactErrorCode.DOWNLOAD_TTL_INVALID)
        _ = self.read_version(scope, version_id)
        if self._store.project_archived(scope):
            raise ArtifactError(ArtifactErrorCode.PROJECT_ARCHIVED)
        now = self._clock.now()
        ttl_microseconds = ttl // timedelta(microseconds=1)
        if ttl_microseconds % 1_000 != 0:
            raise ArtifactError(ArtifactErrorCode.DOWNLOAD_TTL_INVALID)
        epoch = datetime(1970, 1, 1, tzinfo=UTC)
        deadline_microseconds = (now + ttl - epoch) // timedelta(microseconds=1)
        requested_expires_ms = (deadline_microseconds + 999) // 1_000
        maximum_microseconds = (now + MAX_DOWNLOAD_TTL - epoch) // timedelta(
            microseconds=1
        )
        maximum_expires_ms = maximum_microseconds // 1_000
        expires_unix_ms = min(requested_expires_ms, maximum_expires_ms)
        expires_at = epoch + timedelta(milliseconds=expires_unix_ms)
        claims = DownloadClaims(
            org_id=scope.org_id,
            project_id=scope.project_id,
            version_id=version_id,
            expires_unix_ms=expires_unix_ms,
        )
        return SignedDownload(
            token=self._signer.issue(claims),
            expires_at=expires_at,
        )

    def redeem_download(self, scope: ArtifactScope, token: str) -> bytes:
        """Redeem current claims only for their exact active Project scope."""
        claims = self._signer.verify(token, self._clock.now())
        if claims.org_id != scope.org_id or claims.project_id != scope.project_id:
            raise ArtifactError(ArtifactErrorCode.NOT_FOUND)
        try:
            outcome, payload = self._store.redeem_content(scope, claims.version_id)
        except BlobIntegrityError:
            raise ArtifactError(ArtifactErrorCode.CHECKSUM_MISMATCH) from None
        self._require_created(outcome)
        if payload is None:
            raise ArtifactError(ArtifactErrorCode.NOT_FOUND)
        return payload

    def _reconcile_commit(
        self,
        scope: ArtifactScope,
        claim: WatcherClaim,
        version: ArtifactVersion,
        error: ArtifactCommitError,
    ) -> ArtifactVersion:
        try:
            persisted = self._store.version(scope, version.id)
        except ArtifactStoreError:
            self._watcher.finalize(claim)
            raise error from None
        if persisted == version:
            self._watcher.finalize(claim)
            return version
        self._watcher.release(claim)
        raise error from None

    @staticmethod
    def _require_created(outcome: StoreOutcome) -> None:
        match outcome:
            case StoreOutcome.CREATED:
                return
            case StoreOutcome.NOT_FOUND:
                code = ArtifactErrorCode.NOT_FOUND
            case StoreOutcome.ARCHIVED:
                code = ArtifactErrorCode.PROJECT_ARCHIVED
            case StoreOutcome.STALE:
                code = ArtifactErrorCode.STALE_BASE
            case StoreOutcome.INVALID_LINEAGE:
                code = ArtifactErrorCode.INVALID_LINEAGE
            case StoreOutcome.ASSOCIATION_EXISTS:
                code = ArtifactErrorCode.ASSOCIATION_EXISTS
            case _:
                assert_never(outcome)
        raise ArtifactError(code)
