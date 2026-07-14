import pytest
from services.api.upload import (
    IngestionService,
    InMemoryQuarantineStore,
    UploadError,
    UploadErrorCode,
    UploadPart,
    UploadRequest,
)
from services.api.upload.models import (
    JsonPreview,
    ScientificPreview,
    TabularPreview,
    WorkbookPreview,
)
from services.api.upload.previews import MAX_PREVIEW_SOURCE_BYTES

from .fixtures import TEST_SCOPE, xlsx
from .support import CleanScanner


def _preview(filename: str, mime: str, payload: bytes) -> ScientificPreview:
    uploads = IngestionService(InMemoryQuarantineStore(), CleanScanner()).ingest(
        UploadRequest(
            scope=TEST_SCOPE,
            files=(
                UploadPart(
                    filename=filename,
                    declared_mime=mime,
                    chunks=(payload,),
                ),
            ),
        )
    )
    return uploads[0].preview


def test_xlsx_accepts_canonical_absolute_package_root_targets() -> None:
    preview = _preview(
        "absolute.xlsx",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        xlsx(
            standard_components=True,
            relationship_target="/xl/worksheets/sheet1.xml",
            root_absolute_targets=True,
        ),
    )

    assert preview == WorkbookPreview(sheet_names=("Measurements",), truncated=False)


def test_csv_preview_preserves_valid_utf8_across_source_boundary() -> None:
    prefix = b"name,value\nrow,"
    padding = b"x" * (MAX_PREVIEW_SOURCE_BYTES - len(prefix) - 1)
    preview = _preview("boundary.csv", "text/csv", prefix + padding + "한\n".encode())

    assert isinstance(preview, TabularPreview)
    assert preview.truncated is True


def test_csv_preview_truncates_valid_large_fields() -> None:
    preview = _preview(
        "large-field.csv", "text/csv", b"name,value\nrow," + b"x" * 200_000
    )

    assert isinstance(preview, TabularPreview)
    assert len(preview.rows[1][1]) == 256
    assert preview.truncated is True


def test_json_validation_uses_upload_limit_not_preview_limit() -> None:
    payload = b'{"value":"' + b"x" * (4 * 1024 * 1024) + b'"}'
    preview = _preview("large.json", "application/json", payload)

    assert isinstance(preview, JsonPreview)
    assert len(preview.excerpt) == 4_096
    assert preview.truncated is True


@pytest.mark.parametrize(
    ("payload", "root_type"),
    [
        (b'"scientific result"', "str"),
        (b"42", "int"),
        (b"true", "bool"),
        (b"null", "NoneType"),
        (b"-1.25e3", "float"),
    ],
)
def test_json_preview_accepts_standard_scalar_roots(
    payload: bytes, root_type: str
) -> None:
    preview = _preview("scalar.json", "application/json", payload)

    assert isinstance(preview, JsonPreview)
    assert preview.root_type == root_type


@pytest.mark.parametrize(
    ("filename", "mime", "payload"),
    [
        ("column.csv", "text/csv", b"value\n1\n"),
        ("column.tsv", "text/tab-separated-values", b"value\n1\n"),
    ],
)
def test_tabular_preview_accepts_single_column_documents(
    filename: str, mime: str, payload: bytes
) -> None:
    preview = _preview(filename, mime, payload)

    assert preview == TabularPreview(rows=(("value",), ("1",)), truncated=False)


def test_csv_preview_strips_a_leading_utf8_bom() -> None:
    preview = _preview("bom.csv", "text/csv", b"\xef\xbb\xbfvalue\n1\n")

    assert preview == TabularPreview(rows=(("value",), ("1",)), truncated=False)


@pytest.mark.parametrize("payload", [b'{"value":NaN}', b'{"value":1e999}'])
def test_json_preview_rejects_non_finite_numbers(payload: bytes) -> None:
    store = InMemoryQuarantineStore()
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            UploadPart(
                filename="non-finite.json",
                declared_mime="application/json",
                chunks=(payload,),
            ),
        ),
    )

    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(request)

    assert captured.value.code is UploadErrorCode.STRUCTURE_INVALID
    assert store.object_count_for(TEST_SCOPE) == 0


@pytest.mark.parametrize(
    ("filename", "mime", "payload"),
    [
        ("malformed.csv", "text/csv", b'value\n"unterminated'),
        (
            "malformed.tsv",
            "text/tab-separated-values",
            b'value\n"unterminated',
        ),
        ("malformed.csv", "text/csv", b'a,b\nx"junk,y\n'),
        (
            "malformed.tsv",
            "text/tab-separated-values",
            b'a\tb\nx"junk\ty\n',
        ),
    ],
)
def test_tabular_preview_rejects_malformed_quoted_fields(
    filename: str, mime: str, payload: bytes
) -> None:
    store = InMemoryQuarantineStore()
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            UploadPart(
                filename=filename,
                declared_mime=mime,
                chunks=(payload,),
            ),
        ),
    )

    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(request)

    assert captured.value.code is UploadErrorCode.STRUCTURE_INVALID
    assert store.object_count_for(TEST_SCOPE) == 0


def test_structured_text_accepts_valid_unicode_format_and_separator_characters() -> (
    None
):
    json_preview = _preview(
        "unicode.json",
        "application/json",
        '{"line":"a\u2028b"}'.encode(),
    )
    csv_preview = _preview(
        "unicode.csv",
        "text/csv",
        "value\na\u200bb\n".encode(),
    )

    assert isinstance(json_preview, JsonPreview)
    assert json_preview.root_type == "dict"
    assert csv_preview == TabularPreview(
        rows=(("value",), ("a\u200bb",)), truncated=False
    )


@pytest.mark.parametrize(
    ("filename", "mime"),
    [
        ("long-quoted.csv", "text/csv"),
        ("long-quoted.tsv", "text/tab-separated-values"),
    ],
)
def test_tabular_preview_accepts_a_valid_quoted_field_past_preview_bytes(
    filename: str, mime: str
) -> None:
    payload = b'value\n"' + b"x" * (MAX_PREVIEW_SOURCE_BYTES + 50) + b'"\n'
    preview = _preview(filename, mime, payload)

    assert preview == TabularPreview(
        rows=(("value",), ("x" * 256,)),
        truncated=True,
    )


@pytest.mark.parametrize(
    ("filename", "mime", "payload", "expected"),
    [
        (
            "quoted.csv",
            "text/csv",
            b'a,b\r\n"one,two","say ""hi"""\r\n',
            (("a", "b"), ("one,two", 'say "hi"')),
        ),
        (
            "quoted.tsv",
            "text/tab-separated-values",
            b'a\tb\n"one\ttwo"\t"line1\nline2"\n',
            (("a", "b"), ("one\ttwo", "line1\nline2")),
        ),
    ],
)
def test_tabular_preview_preserves_standard_quoted_content(
    filename: str,
    mime: str,
    payload: bytes,
    expected: tuple[tuple[str, ...], ...],
) -> None:
    preview = _preview(filename, mime, payload)

    assert preview == TabularPreview(rows=expected, truncated=False)


@pytest.mark.parametrize(
    "payload",
    [
        b"value\n" + b"ok\n" * 20 + b'"unterminated',
        b'value\n"' + b"x" * (MAX_PREVIEW_SOURCE_BYTES + 50),
    ],
)
def test_tabular_preview_validates_malformed_content_beyond_preview(
    payload: bytes,
) -> None:
    store = InMemoryQuarantineStore()
    request = UploadRequest(
        scope=TEST_SCOPE,
        files=(
            UploadPart(
                filename="late-malformed.csv",
                declared_mime="text/csv",
                chunks=(payload,),
            ),
        ),
    )

    with pytest.raises(UploadError) as captured:
        _ = IngestionService(store, CleanScanner()).ingest(request)

    assert captured.value.code is UploadErrorCode.STRUCTURE_INVALID
    assert store.object_count_for(TEST_SCOPE) == 0
