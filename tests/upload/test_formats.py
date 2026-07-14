import pytest
from services.api.upload import (
    IngestionService,
    InMemoryQuarantineStore,
    UploadError,
    UploadErrorCode,
    UploadPart,
    UploadRequest,
)
from services.api.upload.models import WorkbookPreview

from .fixtures import (
    TEST_SCOPE,
    corrupt_zip_member,
    generic_zip,
    jpeg,
    multi_frame_tiff,
    pdf,
    png,
    tiff,
    xlsx,
)
from .support import CleanScanner


@pytest.mark.parametrize(
    ("filename", "mime", "payload"),
    [
        ("report.pdf", "application/pdf", pdf()),
        ("image.png", "image/png", png()),
        ("image.jpg", "image/jpeg", jpeg()),
        ("image.tif", "image/tiff", tiff()),
        ("data.csv", "text/csv", b"x,y\n1,2\n"),
        ("data.tsv", "text/tab-separated-values", b"x\ty\n1\t2\n"),
        ("data.json", "application/json", b'{"value":1}'),
        (
            "data.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            xlsx(),
        ),
        ("notes.txt", "text/plain", b"bounded notes"),
        ("notes.md", "text/markdown", b"# bounded notes"),
    ],
)
def test_allowlist_accepts_every_documented_format(
    filename: str,
    mime: str,
    payload: bytes,
) -> None:
    # Given: extension, MIME, and content agree for one allowed format.
    service = IngestionService(InMemoryQuarantineStore(), CleanScanner())
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(UploadPart(filename=filename, declared_mime=mime, chunks=(payload,)),),
    )

    # When: the file crosses ingestion.
    uploads = service.ingest(request)

    # Then: exactly one typed bounded preview is emitted.
    assert len(uploads) == 1


@pytest.mark.parametrize(
    ("filename", "mime", "payload", "expected"),
    [
        ("../data.csv", "text/csv", b"x,y\n", UploadErrorCode.FILENAME_INVALID),
        ("data.csv", "application/json", b"x,y\n", UploadErrorCode.MEDIA_TYPE_MISMATCH),
        ("data.csv", "text/csv", b"PK\x03\x04x,y\n", UploadErrorCode.ARCHIVE_REJECTED),
        (
            "image.png",
            "image/png",
            png() + b"PK\x03\x04",
            UploadErrorCode.POLYGLOT_REJECTED,
        ),
        (
            "generic.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            generic_zip(),
            UploadErrorCode.ARCHIVE_REJECTED,
        ),
    ],
)
def test_ingest_rejects_filename_mime_magic_and_polyglot_disagreement(
    filename: str,
    mime: str,
    payload: bytes,
    expected: UploadErrorCode,
) -> None:
    # Given: one upload violates a boundary agreement.
    store = InMemoryQuarantineStore()
    service = IngestionService(store, CleanScanner())
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(UploadPart(filename=filename, declared_mime=mime, chunks=(payload,)),),
    )

    # When / Then: the stable rejection leaves no object.
    with pytest.raises(UploadError) as captured:
        _ = service.ingest(request)
    assert captured.value.code is expected
    assert store.object_count_for(TEST_SCOPE) == 0


@pytest.mark.parametrize(
    "payload",
    [xlsx(member_name="../escape.xml"), xlsx(symlink=True)],
)
def test_xlsx_rejects_traversal_and_symlink_members(payload: bytes) -> None:
    # Given: an XLSX ZIP contains a path or link attack.
    store = InMemoryQuarantineStore()
    service = IngestionService(store, CleanScanner())
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            UploadPart(
                filename="attack.xlsx",
                declared_mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                chunks=(payload,),
            ),
        ),
    )

    # When / Then: container validation rejects it without an orphan.
    with pytest.raises(UploadError, match=UploadErrorCode.ARCHIVE_REJECTED):
        _ = service.ingest(request)
    assert store.object_count_for(TEST_SCOPE) == 0


@pytest.mark.parametrize(
    ("filename", "mime", "payload"),
    [
        ("image.tiff", "image/tiff", tiff() + b"\x1f\x8b\x08payload"),
        (
            "image.jpg",
            "image/jpeg",
            jpeg()[:-2] + b"\x1f\x8b\x08payload" + jpeg()[-2:],
        ),
        ("image.tiff", "image/tiff", tiff() + b"Rar!\x1a\x07payload"),
    ],
)
def test_non_zip_archive_polyglots_are_rejected(
    filename: str,
    mime: str,
    payload: bytes,
) -> None:
    # Given: a valid image envelope also contains an embedded archive signature.
    store = InMemoryQuarantineStore()
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(UploadPart(filename=filename, declared_mime=mime, chunks=(payload,)),),
    )

    # When / Then: embedded non-ZIP archives are rejected before scanning.
    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(request)
    assert captured.value.code is UploadErrorCode.POLYGLOT_REJECTED
    assert store.object_count_for(TEST_SCOPE) == 0


@pytest.mark.parametrize(
    "payload",
    [
        xlsx(extra_member="XL/WORKBOOK.XML"),
        xlsx(extra_member="xl/embeddings/object.bin"),
        xlsx(external_relationship=True),
        xlsx(escaped_external_relationship=True),
        xlsx(extra_member="xl/media/hidden.dat"),
        xlsx(member_name="\uff0e\uff0e/escape.xml"),
        xlsx(extra_member="xl/worksheets/undeclared.xml"),
        xlsx(member_name="xl/worksheets/%2e%2e/escape.xml"),
        xlsx(relationship_target="https://example.invalid/payload"),
        xlsx(utf16_relationship=True),
        xlsx(relationship_type_namespace="urn:untrusted"),
    ],
)
def test_xlsx_rejects_collisions_active_content_and_external_links(
    payload: bytes,
) -> None:
    # Given: an OOXML container has an ambiguous or active package graph.
    store = InMemoryQuarantineStore()
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            UploadPart(
                filename="attack.xlsx",
                declared_mime=(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                ),
                chunks=(payload,),
            ),
        ),
    )

    # When / Then: the package is never promoted.
    with pytest.raises(UploadError, match=UploadErrorCode.ARCHIVE_REJECTED):
        _ = IngestionService(store, CleanScanner()).ingest(request)
    assert store.object_count_for(TEST_SCOPE) == 0


def test_xlsx_accepts_standard_safe_workbook_components() -> None:
    store = InMemoryQuarantineStore()
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            UploadPart(
                filename="styled.xlsx",
                declared_mime=(
                    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
                ),
                chunks=(
                    xlsx(
                        standard_components=True,
                        relationship_target="/xl/worksheets/sheet1.xml",
                        worksheet_padding=1024 * 1024,
                    ),
                ),
            ),
        ),
    )

    uploads = IngestionService(store, CleanScanner()).ingest(request)

    assert uploads[0].preview == WorkbookPreview(
        sheet_names=("Measurements",), truncated=False
    )
    assert store.object_count_for(TEST_SCOPE) == 1


def test_marker_only_pdf_is_rejected_as_structurally_invalid() -> None:
    # Given: bytes spoof only the old PDF header, Page token, and EOF marker.
    payload = b"%PDF-1.7\n<< /Type /Page >>\n%%EOF"
    store = InMemoryQuarantineStore()
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            UploadPart(
                filename="fake.pdf", declared_mime="application/pdf", chunks=(payload,)
            ),
        ),
    )

    # When / Then: pypdf rejects the marker shell and no object remains.
    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(request)
    assert captured.value.code is UploadErrorCode.STRUCTURE_INVALID
    assert store.object_count_for(TEST_SCOPE) == 0


@pytest.mark.parametrize(
    ("filename", "mime", "payload"),
    [
        ("truncated.tiff", "image/tiff", tiff()[:-1]),
        ("truncated-frames.tiff", "image/tiff", multi_frame_tiff()[:-192]),
        (
            "corrupt.xlsx",
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            corrupt_zip_member(xlsx(), "xl/worksheets/sheet1.xml"),
        ),
    ],
)
def test_incomplete_decodable_members_are_rejected(
    filename: str,
    mime: str,
    payload: bytes,
) -> None:
    # Given: a file has valid outer metadata but truncated image data or a bad ZIP CRC.
    store = InMemoryQuarantineStore()
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(UploadPart(filename=filename, declared_mime=mime, chunks=(payload,)),),
    )

    # When / Then: full decoding rejects the object before clean promotion.
    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(request)
    assert captured.value.code is UploadErrorCode.STRUCTURE_INVALID
    assert store.object_count_for(TEST_SCOPE) == 0
