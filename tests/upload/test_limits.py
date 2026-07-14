from collections.abc import Iterator

import pytest
from services.api.upload import (
    IngestionService,
    InMemoryQuarantineStore,
    UploadError,
    UploadErrorCode,
    UploadPart,
    UploadRequest,
)
from services.api.upload.service import MAX_CHUNKS_PER_FILE, MAX_FILE_BYTES

from .fixtures import TEST_SCOPE, pdf, png
from .support import CleanScanner


def test_file_limit_rejects_50_mib_plus_one_without_orphan() -> None:
    # Given: one file exceeds the 50 MiB ceiling by one byte.
    payload = b"x" * (MAX_FILE_BYTES + 1)
    item = UploadPart(
        filename="large.txt", declared_mime="text/plain", chunks=(payload,)
    )

    # When / Then: the file is rejected and its partial quarantine is removed.
    store = InMemoryQuarantineStore()
    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(
            UploadRequest(scope=TEST_SCOPE, files=(item,))
        )
    assert captured.value.code is UploadErrorCode.FILE_TOO_LARGE
    assert store.object_count_for(TEST_SCOPE) == 0


def test_request_limit_rejects_more_than_100_mib_atomically() -> None:
    # Given: three individually valid files exceed 100 MiB together.
    chunk = b"x" * (34 * 1024 * 1024)
    files = tuple(
        UploadPart(
            filename=f"part-{index}.txt", declared_mime="text/plain", chunks=(chunk,)
        )
        for index in range(3)
    )

    # When / Then: aggregate enforcement deletes every staged object.
    store = InMemoryQuarantineStore()
    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(
            UploadRequest(scope=TEST_SCOPE, files=files)
        )
    assert captured.value.code is UploadErrorCode.REQUEST_TOO_LARGE
    assert store.object_count_for(TEST_SCOPE) == 0


def test_file_count_limit_rejects_eleven_files_before_staging() -> None:
    # Given: a multipart request contains eleven files.
    files = tuple(
        UploadPart(
            filename=f"part-{index}.txt", declared_mime="text/plain", chunks=(b"x",)
        )
        for index in range(11)
    )

    # When / Then: count enforcement occurs before object creation.
    store = InMemoryQuarantineStore()
    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(
            UploadRequest(scope=TEST_SCOPE, files=files)
        )
    assert captured.value.code is UploadErrorCode.TOO_MANY_FILES
    assert store.object_count_for(TEST_SCOPE) == 0


def test_lazy_chunk_stream_is_bounded_during_consumption() -> None:
    # Given: a one-shot transport stream yields one chunk beyond its ceiling.
    chunks = (b"x" for _ in range(MAX_CHUNKS_PER_FILE + 1))
    item = UploadPart(filename="chunks.txt", declared_mime="text/plain", chunks=chunks)
    store = InMemoryQuarantineStore()

    # When / Then: consumption stops with a stable error and no staged object.
    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(
            UploadRequest(scope=TEST_SCOPE, files=(item,))
        )
    assert captured.value.code is UploadErrorCode.TRANSPORT_INVALID
    assert store.object_count_for(TEST_SCOPE) == 0


def test_transport_iterator_failure_maps_to_stable_rejection() -> None:
    def broken_chunks() -> Iterator[bytes]:
        yield b"partial"
        raise OSError

    item = UploadPart(
        filename="broken.txt", declared_mime="text/plain", chunks=broken_chunks()
    )
    store = InMemoryQuarantineStore()

    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(
            UploadRequest(scope=TEST_SCOPE, files=(item,))
        )
    assert captured.value.code is UploadErrorCode.TRANSPORT_INVALID
    assert store.object_count_for(TEST_SCOPE) == 0


def test_transport_chunks_require_strict_bytes() -> None:
    item = UploadPart.model_validate(
        {
            "filename": "coerced.txt",
            "declared_mime": "text/plain",
            "chunks": ["not bytes"],
        }
    )
    store = InMemoryQuarantineStore()

    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(
            UploadRequest(scope=TEST_SCOPE, files=(item,))
        )
    assert captured.value.code is UploadErrorCode.TRANSPORT_INVALID
    assert store.object_count_for(TEST_SCOPE) == 0


@pytest.mark.parametrize(
    ("filename", "mime", "payload", "expected"),
    [
        ("large.pdf", "application/pdf", pdf(201), UploadErrorCode.PDF_PAGE_LIMIT),
        (
            "large.png",
            "image/png",
            png(10_000, 5_001),
            UploadErrorCode.IMAGE_PIXEL_LIMIT,
        ),
    ],
)
def test_parser_limits_reject_pages_and_pixels(
    filename: str,
    mime: str,
    payload: bytes,
    expected: UploadErrorCode,
) -> None:
    # Given: compact metadata declares an over-limit scientific input.
    item = UploadPart(filename=filename, declared_mime=mime, chunks=(payload,))

    # When / Then: parser rejects it without retaining quarantine bytes.
    store = InMemoryQuarantineStore()
    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(
            UploadRequest(scope=TEST_SCOPE, files=(item,))
        )
    assert captured.value.code is expected
    assert store.object_count_for(TEST_SCOPE) == 0
