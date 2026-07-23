"""Atomic private-file storage used by the Artifact recovery authority."""

import fcntl
import hashlib
import hmac
import os
import stat
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path
from threading import RLock, local
from typing import Annotated, ClassVar, Final, final
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .blob_filesystem import open_blob_directory, prepare_private_root
from .models import MAX_ARTIFACT_OUTPUT_BYTES, WatcherOutput
from .recovery import (
    ArtifactRecoveryError,
    CompletedArtifactCommit,
    PendingArtifactCommit,
)
from .store_contract import BlobIntegrityError, BlobWriteError

_FILE_MODE: Final = 0o600
_NO_FOLLOW: Final = getattr(os, "O_NOFOLLOW", 0)
_MIN_INTEGRITY_KEY_BYTES: Final = 32
_RECOVERY_PAYLOAD_COPIES: Final = 2
_RECOVERY_METADATA_BYTES: Final = 8 * 1024 * 1024
_LOCK_NAME: Final = ".authority.lock"


def recovery_record_bytes_limit(payload_bytes: int) -> int:
    """Bound two base64 payload copies plus constrained provenance metadata."""
    encoded_payload_bytes = 4 * ((payload_bytes + 2) // 3)
    return _RECOVERY_PAYLOAD_COPIES * encoded_payload_bytes + _RECOVERY_METADATA_BYTES


MAX_RECOVERY_RECORD_BYTES: Final = recovery_record_bytes_limit(
    MAX_ARTIFACT_OUTPUT_BYTES
)


class FileRecoveryState(BaseModel):
    """One atomically replaced output, claim fence, and reconciliation."""

    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    output: WatcherOutput
    claim_token: UUID | None = None
    consumed_token: UUID | None = None
    reconciliation: (
        Annotated[
            PendingArtifactCommit | CompletedArtifactCommit,
            Field(discriminator="kind"),
        ]
        | None
    ) = None


class _Envelope(BaseModel):
    model_config: ClassVar[ConfigDict] = ConfigDict(
        frozen=True,
        extra="forbid",
        strict=True,
    )

    body: FileRecoveryState
    integrity_hmac_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")


@final
class _LockDepth(local):
    depth: int = 0


@final
class FileRecoveryStorage:
    """Provide integrity-checked atomic records and cross-process locking."""

    def __init__(self, root: Path, *, integrity_key: bytes) -> None:
        """Prepare an explicit private durable root."""
        if len(integrity_key) < _MIN_INTEGRITY_KEY_BYTES or _NO_FOLLOW == 0:
            raise ArtifactRecoveryError
        self._integrity_key = bytes(integrity_key)
        try:
            durable_root = prepare_private_root(root)
            root_descriptor = open_blob_directory(durable_root, (), create=False)
            try:
                records_descriptor = open_blob_directory(
                    durable_root,
                    ("records",),
                    create=True,
                )
                try:
                    os.fsync(records_descriptor)
                finally:
                    os.close(records_descriptor)
                os.fsync(root_descriptor)
                lock_descriptor = os.open(
                    _LOCK_NAME,
                    os.O_CREAT
                    | os.O_RDWR
                    | os.O_CLOEXEC
                    | os.O_NONBLOCK
                    | _NO_FOLLOW,
                    _FILE_MODE,
                    dir_fd=root_descriptor,
                )
                try:
                    metadata = os.fstat(lock_descriptor)
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ArtifactRecoveryError
                    os.fchmod(lock_descriptor, _FILE_MODE)
                    os.fsync(lock_descriptor)
                finally:
                    os.close(lock_descriptor)
                os.fsync(root_descriptor)
            finally:
                os.close(root_descriptor)
        except ArtifactRecoveryError:
            raise
        except (BlobIntegrityError, BlobWriteError, OSError) as error:
            raise ArtifactRecoveryError from error
        self._records = durable_root / "records"
        self._lock_path = durable_root / _LOCK_NAME
        self._thread_lock = RLock()
        self._lock_depth = _LockDepth()

    @contextmanager
    def locked(self, reference: str) -> Generator[None, None, None]:
        """Serialize transitions across threads and adapter instances."""
        del reference
        with self._thread_lock:
            if self._lock_depth.depth:
                self._lock_depth.depth += 1
                try:
                    yield
                finally:
                    self._lock_depth.depth -= 1
                return
            descriptor = os.open(
                self._lock_path,
                os.O_RDWR | os.O_CLOEXEC | _NO_FOLLOW,
            )
            with os.fdopen(descriptor, "rb+", closefd=True) as lock_file:
                fcntl.flock(lock_file.fileno(), fcntl.LOCK_EX)
                self._lock_depth.depth = 1
                try:
                    yield
                finally:
                    self._lock_depth.depth = 0
                    fcntl.flock(lock_file.fileno(), fcntl.LOCK_UN)

    def read(self, reference: str) -> FileRecoveryState | None:
        """Load and verify one reference record."""
        path = self._path(reference)
        encoded = _read_regular_file(path)
        if encoded is None:
            return None
        try:
            envelope = _Envelope.model_validate_json(encoded)
        except ValidationError as error:
            raise ArtifactRecoveryError from error
        body = envelope.body
        if body.output.reference != reference or not hmac.compare_digest(
            _integrity(self._integrity_key, body),
            envelope.integrity_hmac_sha256,
        ):
            raise ArtifactRecoveryError
        if (
            hashlib.sha256(body.output.payload).hexdigest()
            != body.output.content_sha256
        ):
            raise ArtifactRecoveryError
        return body

    def write(self, body: FileRecoveryState) -> None:
        """Atomically replace one integrity-bound reference record."""
        envelope = _Envelope(
            body=body,
            integrity_hmac_sha256=_integrity(self._integrity_key, body),
        )
        encoded = envelope.model_dump_json().encode()
        if len(encoded) > MAX_RECOVERY_RECORD_BYTES:
            raise ArtifactRecoveryError
        _atomic_write(
            self._path(body.output.reference),
            encoded,
        )

    def _path(self, reference: str) -> Path:
        digest = hashlib.sha256(reference.encode()).hexdigest()
        return self._records / f"{digest}.json"


def _atomic_write(path: Path, payload: bytes) -> None:
    temporary: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(dir=path.parent)
        temporary = Path(temporary_name)
        os.fchmod(descriptor, _FILE_MODE)
        with os.fdopen(descriptor, "wb", closefd=True) as output:
            _ = output.write(payload)
            output.flush()
            os.fsync(output.fileno())
        _ = temporary.replace(path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except OSError as error:
        raise ArtifactRecoveryError from error
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def _read_regular_file(path: Path) -> bytes | None:
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK | _NO_FOLLOW,
        )
    except FileNotFoundError:
        return None
    except OSError as error:
        raise ArtifactRecoveryError from error
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_size > MAX_RECOVERY_RECORD_BYTES
        ):
            raise ArtifactRecoveryError
        with os.fdopen(descriptor, "rb", closefd=False) as source:
            encoded = source.read(MAX_RECOVERY_RECORD_BYTES + 1)
    except OSError as error:
        raise ArtifactRecoveryError from error
    else:
        if len(encoded) > MAX_RECOVERY_RECORD_BYTES:
            raise ArtifactRecoveryError
        return encoded
    finally:
        os.close(descriptor)


def _integrity(key: bytes, body: BaseModel) -> str:
    return hmac.new(
        key,
        body.model_dump_json().encode(),
        hashlib.sha256,
    ).hexdigest()
