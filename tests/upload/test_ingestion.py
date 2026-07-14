import pytest
from services.api.upload import (
    IngestionService,
    InMemoryQuarantineStore,
    UploadError,
    UploadErrorCode,
    UploadPart,
    UploadRequest,
)
from services.api.upload.models import ImagePreview, TabularPreview
from services.api.upload.store import ObjectNotReadableError

from .fixtures import OTHER_SCOPE, TEST_SCOPE, pdf, tiff
from .support import (
    CleanScanner,
    ExplodingScanner,
    FailedScanner,
    PartialPromotionFailureStore,
    ThreatScanner,
)

EICAR_TEST_BYTES = (
    b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def part(filename: str, mime: str, payload: bytes) -> UploadPart:
    midpoint = max(1, len(payload) // 2)
    return UploadPart(
        filename=filename,
        declared_mime=mime,
        chunks=(payload[:midpoint], payload[midpoint:]),
    )


def test_ingest_promotes_csv_tiff_and_pdf_only_after_clean_scan() -> None:
    # Given: three scientific inputs are streamed into a private store.
    store = InMemoryQuarantineStore()
    service = IngestionService(store, CleanScanner(store, TEST_SCOPE))
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            part(
                "\uff24\uff41\uff54\uff41\uff0e\uff23\uff33\uff36",
                "text/csv",
                b"time,value\n0,1\n",
            ),
            part("image.tiff", "image/tiff", tiff()),
            part("report.pdf", "application/pdf", pdf()),
        ),
    )

    # When: every format and scanner check succeeds.
    uploads = service.ingest(request)

    # Then: metadata is normalized, typed, and every object is readable.
    assert [upload.filename for upload in uploads] == [
        "Data.csv",
        "image.tiff",
        "report.pdf",
    ]
    assert isinstance(uploads[0].preview, TabularPreview)
    assert uploads[0].preview.rows[1] == ("0", "1")
    assert isinstance(uploads[1].preview, ImagePreview)
    assert uploads[1].preview.width * uploads[1].preview.height == 6
    assert all(store.read_agent(TEST_SCOPE, upload.key) for upload in uploads)


@pytest.mark.parametrize(
    ("scanner", "expected"),
    [
        (ThreatScanner(), UploadErrorCode.MALWARE_DETECTED),
        (FailedScanner(), UploadErrorCode.SCANNER_FAILED),
    ],
)
def test_ingest_fails_closed_without_orphans_on_scanner_rejection(
    scanner: ThreatScanner | FailedScanner,
    expected: UploadErrorCode,
) -> None:
    # Given: a valid text upload reaches a non-clean scanner outcome.
    store = InMemoryQuarantineStore()
    service = IngestionService(store, scanner)
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(part("eicar.txt", "text/plain", EICAR_TEST_BYTES),),
    )

    # When / Then: the stable error is returned and quarantine is empty.
    with pytest.raises(UploadError) as captured:
        _ = service.ingest(request)
    assert captured.value.code is expected
    assert store.object_count_for(TEST_SCOPE) == 0


def test_tabular_preview_is_bounded_by_rows_columns_and_cell_size() -> None:
    # Given: a CSV is larger than every preview dimension.
    header = ",".join(f"column-{index}" for index in range(60))
    row = ",".join("x" * 300 for _ in range(60))
    payload = (header + "\n" + "\n".join(row for _ in range(25))).encode()
    service = IngestionService(InMemoryQuarantineStore(), CleanScanner())

    # When: the valid table is parsed.
    upload = service.ingest(
        UploadRequest(
            scope=TEST_SCOPE,
            files=(part("wide.csv", "text/csv", payload),),
        )
    )[0]

    # Then: preview content is typed and strictly bounded.
    assert isinstance(upload.preview, TabularPreview)
    assert len(upload.preview.rows) == 20
    assert all(len(values) <= 50 for values in upload.preview.rows)
    assert max(len(value) for values in upload.preview.rows for value in values) <= 256
    assert upload.preview.truncated


def test_ingest_rolls_back_earlier_valid_files_when_later_file_fails() -> None:
    # Given: a clean CSV precedes an invalid archive in one request.
    store = InMemoryQuarantineStore()
    service = IngestionService(store, CleanScanner())
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            part("data.csv", "text/csv", b"x,y\n1,2\n"),
            part("payload.zip", "application/zip", b"PK\x03\x04bad"),
        ),
    )

    # When / Then: request atomicity leaves no readable or orphan object.
    with pytest.raises(UploadError, match=UploadErrorCode.ARCHIVE_REJECTED):
        _ = service.ingest(request)
    assert store.object_count_for(TEST_SCOPE) == 0


def test_scanner_exception_maps_to_stable_failure_without_orphan() -> None:
    # Given: the scanner raises an operational exception instead of a typed outcome.
    store = InMemoryQuarantineStore()
    service = IngestionService(store, ExplodingScanner())
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(part("data.csv", "text/csv", b"x,y\n1,2\n"),),
    )

    # When / Then: the boundary fails closed and removes quarantine bytes.
    with pytest.raises(UploadError) as captured:
        _ = service.ingest(request)
    assert captured.value.code is UploadErrorCode.SCANNER_FAILED
    assert store.object_count_for(TEST_SCOPE) == 0


def test_partial_promotion_failure_removes_clean_and_quarantine_objects() -> None:
    # Given: a store violates its atomic promotion contract after exposing one object.
    store = PartialPromotionFailureStore()
    service = IngestionService(store, CleanScanner())
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            part("one.csv", "text/csv", b"x,y\n1,2\n"),
            part("two.csv", "text/csv", b"x,y\n3,4\n"),
        ),
    )

    # When / Then: compensating cleanup removes every visibility state.
    with pytest.raises(UploadError) as captured:
        _ = service.ingest(request)
    assert captured.value.code is UploadErrorCode.STORAGE_FAILED
    assert store.object_count_for(TEST_SCOPE) == 0


def test_clean_bytes_are_immutable_and_tenant_scoped_after_promotion() -> None:
    # Given: one tenant promotes scanned bytes to a clean object.
    store = InMemoryQuarantineStore()
    upload = IngestionService(store, CleanScanner()).ingest(
        UploadRequest(
            scope=TEST_SCOPE,
            files=(part("data.csv", "text/csv", b"x,y\n1,2\n"),),
        )
    )[0]

    # When / Then: neither post-scan append nor a foreign scope can read the bytes.
    with pytest.raises(RuntimeError):
        store.append(TEST_SCOPE, upload.key, b"unscanned")
    with pytest.raises(ObjectNotReadableError):
        _ = store.read_agent(OTHER_SCOPE, upload.key)
    assert store.read_agent(TEST_SCOPE, upload.key) == b"x,y\n1,2\n"
    assert str(upload.key).startswith(
        f"org/{TEST_SCOPE.org_id}/project/{TEST_SCOPE.project_id}/quarantine/"
    )
