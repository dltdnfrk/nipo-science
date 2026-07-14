"""Atomic quarantine-to-clean scientific ingestion orchestration."""

import hashlib
import uuid
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from typing import Final, assert_never

from services.local.scanner import (
    ScanClean,
    ScannerUnavailable,
    ScanProtocolError,
    ThreatFound,
    UploadTooLarge,
)

from .formats import identify_format, normalize_filename
from .models import (
    CleanUpload,
    UploadError,
    UploadErrorCode,
    UploadKey,
    UploadRequest,
    UploadScope,
)
from .previews import parse_preview
from .scanning import MalwareScanner
from .store import QuarantineStore

MAX_FILE_BYTES: Final = 50 * 1024 * 1024
MAX_REQUEST_BYTES: Final = 100 * 1024 * 1024
MAX_REQUEST_FILES: Final = 10
MAX_CHUNKS_PER_FILE: Final = 8_192


@dataclass(frozen=True, slots=True)
class _StagedUpload:
    key: UploadKey
    scope: UploadScope
    filename: str
    declared_mime: str
    byte_size: int
    payload: bytes


@dataclass(frozen=True, slots=True)
class IngestionService:
    """Stream multipart chunks through private quarantine and strict checks."""

    store: QuarantineStore
    scanner: MalwareScanner

    def ingest(self, request: UploadRequest) -> tuple[CleanUpload, ...]:
        """Atomically ingest a request or discard every object on rejection."""
        if len(request.files) > MAX_REQUEST_FILES:
            raise UploadError(UploadErrorCode.TOO_MANY_FILES)
        keys: list[UploadKey] = []
        clean: list[CleanUpload] = []
        request_size = 0
        complete = False
        try:
            for part in request.files:
                filename = normalize_filename(part.filename)
                scope = request.scope
                key = UploadKey(
                    f"org/{scope.org_id}/project/{scope.project_id}/quarantine/"
                    f"{uuid.uuid4()}"
                )
                keys.append(key)
                self._begin(scope, key)
                file_size = 0
                chunk_count = 0
                for chunk_count, chunk in enumerate(
                    _iter_chunks(part.chunks, filename), start=1
                ):
                    if chunk_count > MAX_CHUNKS_PER_FILE:
                        raise UploadError(UploadErrorCode.TRANSPORT_INVALID, filename)
                    file_size += len(chunk)
                    request_size += len(chunk)
                    _enforce_sizes(file_size, request_size, filename)
                    self._append(scope, key, chunk)
                if chunk_count == 0:
                    raise UploadError(UploadErrorCode.TRANSPORT_INVALID, filename)
                payload = self._read_quarantine(scope, key)
                clean.append(
                    self._inspect(
                        _StagedUpload(
                            key=key,
                            scope=scope,
                            filename=filename,
                            declared_mime=part.declared_mime,
                            byte_size=file_size,
                            payload=payload,
                        )
                    )
                )
                del payload
            self._promote_all(request.scope, tuple(keys))
            complete = True
        finally:
            if not complete and not self._discard_all(request.scope, keys):
                raise UploadError(UploadErrorCode.STORAGE_FAILED) from None
        return tuple(clean)

    def _begin(self, scope: UploadScope, key: UploadKey) -> None:
        try:
            self.store.begin(scope, key)
        except Exception:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK -- adapter boundary.
            raise UploadError(UploadErrorCode.STORAGE_FAILED) from None

    def _append(self, scope: UploadScope, key: UploadKey, chunk: bytes) -> None:
        try:
            self.store.append(scope, key, chunk)
        except Exception:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK -- adapter boundary.
            raise UploadError(UploadErrorCode.STORAGE_FAILED) from None

    def _read_quarantine(self, scope: UploadScope, key: UploadKey) -> bytes:
        try:
            return self.store.read_quarantine(scope, key)
        except Exception:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK -- adapter boundary.
            raise UploadError(UploadErrorCode.STORAGE_FAILED) from None

    def _promote_all(self, scope: UploadScope, keys: tuple[UploadKey, ...]) -> None:
        try:
            self.store.promote_all(scope, keys)
        except Exception:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK -- adapter boundary.
            raise UploadError(UploadErrorCode.STORAGE_FAILED) from None

    def _discard_all(self, scope: UploadScope, keys: list[UploadKey]) -> bool:
        try:
            self.store.discard_all(scope, tuple(keys))
        except Exception:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK -- cleanup boundary.
            return False
        return True

    def _inspect(self, item: _StagedUpload) -> CleanUpload:
        rule = identify_format(item.filename, item.declared_mime, item.payload)
        try:
            result = self.scanner.scan(item.payload)
        except Exception:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK -- adapter boundary.
            raise UploadError(UploadErrorCode.SCANNER_FAILED, item.filename) from None
        match result:
            case ScanClean():
                pass
            case ThreatFound():
                raise UploadError(UploadErrorCode.MALWARE_DETECTED, item.filename)
            case ScannerUnavailable() | ScanProtocolError():
                raise UploadError(UploadErrorCode.SCANNER_FAILED, item.filename)
            case UploadTooLarge():
                raise UploadError(UploadErrorCode.FILE_TOO_LARGE, item.filename)
            case _:
                assert_never(result)
        return CleanUpload(
            key=item.key,
            scope=item.scope,
            filename=item.filename,
            media_type=rule.media_type,
            format=rule.format,
            byte_size=item.byte_size,
            sha256=hashlib.sha256(item.payload).hexdigest(),
            preview=parse_preview(rule.format, item.payload, item.filename),
        )


def _enforce_sizes(file_size: int, request_size: int, filename: str) -> None:
    if file_size > MAX_FILE_BYTES:
        raise UploadError(UploadErrorCode.FILE_TOO_LARGE, filename)
    if request_size > MAX_REQUEST_BYTES:
        raise UploadError(UploadErrorCode.REQUEST_TOO_LARGE)


def _iter_chunks(chunks: Iterable[bytes], filename: str) -> Iterator[bytes]:
    try:
        iterator = iter(chunks)
        while True:
            yield next(iterator)
    except StopIteration:
        return
    except Exception:  # noqa: BLE001  # noqa: BROAD_EXCEPT_OK -- transport boundary.
        raise UploadError(UploadErrorCode.TRANSPORT_INVALID, filename) from None
