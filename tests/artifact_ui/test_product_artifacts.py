import hashlib
from io import BytesIO
from typing import cast

import pytest
from pypdf import PdfReader
from services.api.product_artifact_types import (
    ArtifactVersionConflictError,
    ArtifactVersionDraft,
    UnsupportedArtifactMediaError,
)
from services.api.product_artifacts import ProductArtifactService


def _interactive_pdf(
    *,
    catalog_extra: bytes = b"",
    page_extra: bytes = b"",
    extra_objects: tuple[bytes, ...] = (),
) -> bytes:
    parts = [b"%PDF-1.4\n"]
    objects = (
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R " + catalog_extra + b">>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] "
        b"/Contents 4 0 R " + page_extra + b">>\nendobj\n",
        b"4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n",
        *extra_objects,
    )
    offsets: list[int] = []
    for item in objects:
        offsets.append(sum(len(part) for part in parts))
        parts.append(item)
    xref_offset = sum(len(part) for part in parts)
    rows = [f"xref\n0 {len(objects) + 1}\n0000000000 65535 f \n".encode()]
    rows.extend(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    parts.extend(rows)
    parts.append(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\nstartxref\n".encode()
        + str(xref_offset).encode()
        + b"\n%%EOF\n"
    )
    return b"".join(parts)


def test_versions_are_immutable_monotonic_and_diffable() -> None:
    service = ProductArtifactService()
    first = service.create_version(
        ArtifactVersionDraft(
            organization_id="org-a",
            artifact_id="artifact-spectrum",
            name="normalized.csv",
            media_type="text/csv",
            content=b"wavelength,intensity\n500,19\n",
            producer_execution_id="execution-1",
            environment_sha256="a" * 64,
            lineage_version_ids=("input-v1",),
        ),
        base_version_no=0,
    )
    second = service.create_version(
        ArtifactVersionDraft(
            organization_id="org-a",
            artifact_id="artifact-spectrum",
            name="normalized.csv",
            media_type="text/csv",
            content=b"wavelength,intensity\n500,20\n",
            producer_execution_id="execution-2",
            environment_sha256="b" * 64,
            lineage_version_ids=(first.id,),
        ),
        base_version_no=1,
    )

    detail = service.detail("org-a", "artifact-spectrum")

    assert detail is not None
    assert tuple(version.version_no for version in detail.versions) == (1, 2)
    assert detail.selected == second
    assert detail.previous == first
    assert detail.changed_bytes > 0
    assert first.sha256 == hashlib.sha256(first.content).hexdigest()
    with pytest.raises(ArtifactVersionConflictError):
        _ = service.create_version(
            ArtifactVersionDraft(
                organization_id="org-a",
                artifact_id="artifact-spectrum",
                name="normalized.csv",
                media_type="text/csv",
                content=b"stale",
                producer_execution_id="execution-3",
                environment_sha256="c" * 64,
                lineage_version_ids=(second.id,),
            ),
            base_version_no=1,
        )


def test_version_attachment_preview_and_tenant_boundaries_are_explicit() -> None:
    service = ProductArtifactService.with_fixture()
    detail = service.detail("org-mineral", "artifact-spectrum")
    assert detail is not None

    attached = service.attach("org-mineral", detail.selected.id, "session-demo")
    detached = service.detach("org-mineral", detail.selected.id, "session-demo")
    preview = service.preview(detail.selected.preview_token)

    assert attached == ("session-demo",)
    assert detached == ()
    assert preview == detail.selected
    assert service.detail("org-foreign", "artifact-spectrum") is None
    assert service.download("org-foreign", detail.selected.id) is None


def test_active_content_cannot_become_a_preview_artifact() -> None:
    service = ProductArtifactService()

    with pytest.raises(UnsupportedArtifactMediaError):
        _ = service.create_version(
            ArtifactVersionDraft(
                organization_id="org-a",
                artifact_id="artifact-html",
                name="unsafe.html",
                media_type="text/html",
                content=b"<script>alert(1)</script>",
                producer_execution_id="execution-1",
                environment_sha256="d" * 64,
                lineage_version_ids=("input-v1",),
            ),
            base_version_no=0,
        )


@pytest.mark.parametrize(
    ("name", "media_type", "content"),
    [
        ("../unsafe.md", "text/csv", b"value\n1\n"),
        ("unsafe.md", "text/markdown", b"[click](javascript:alert(1))"),
        ("data.csv", "text/csv", b"<html><script>alert(1)</script></html>"),
        (
            "report.pdf",
            "application/pdf",
            b"%PDF-1.4\n1 0 obj<</OpenAction 2 0 R /JavaScript(1)>>endobj\n%%EOF",
        ),
        ("preview.png", "image/png", b"\x89PNG\r\n\x1a\nIEND"),
        (
            "formula.csv",
            "text/csv",
            b'name,value\nprobe,=WEBSERVICE("https://example.invalid")\n',
        ),
    ],
)
def test_malicious_name_or_active_bytes_are_rejected(
    name: str, media_type: str, content: bytes
) -> None:
    service = ProductArtifactService()

    with pytest.raises(UnsupportedArtifactMediaError):
        _ = service.create_version(
            ArtifactVersionDraft(
                organization_id="org-a",
                artifact_id="artifact-unsafe",
                name=name,
                media_type=media_type,
                content=content,
                producer_execution_id="execution-1",
                environment_sha256="d" * 64,
                lineage_version_ids=("input-v1",),
            ),
            base_version_no=0,
        )


def test_version_content_is_copied_and_explicit_versions_are_selectable() -> None:
    service = ProductArtifactService()
    mutable = bytearray(b"value\n1\n")
    version = service.create_version(
        ArtifactVersionDraft(
            organization_id="org-a",
            artifact_id="artifact-table",
            name="data.csv",
            media_type="text/csv",
            content=cast("bytes", cast("object", mutable)),
            producer_execution_id="execution-1",
            environment_sha256="e" * 64,
            lineage_version_ids=("input-v1",),
        ),
        base_version_no=0,
    )
    mutable[-2] = ord("9")

    detail = service.detail("org-a", "artifact-table", version.id)

    assert detail is not None
    assert detail.selected == version
    assert detail.selected.content == b"value\n1\n"
    assert detail.selected.sha256 == hashlib.sha256(detail.selected.content).hexdigest()


def test_signed_numeric_csv_cells_remain_valid_scientific_values() -> None:
    version = ProductArtifactService().create_version(
        ArtifactVersionDraft(
            organization_id="org-a",
            artifact_id="artifact-signed-values",
            name="signed.csv",
            media_type="text/csv",
            content=b"value\n-1.25\n+2.5e3\n",
            producer_execution_id="execution-1",
            environment_sha256="f" * 64,
            lineage_version_ids=("input-v1",),
        ),
        base_version_no=0,
    )

    assert version.content == b"value\n-1.25\n+2.5e3\n"


def test_fixture_pdf_is_well_formed_and_has_no_active_actions() -> None:
    service = ProductArtifactService.with_fixture()
    detail = service.detail("org-mineral", "artifact-report", "artifact-report-v1")

    assert detail is not None
    content = detail.selected.content
    assert content.startswith(b"%PDF-")
    assert b"startxref" in content
    assert content.rstrip().endswith(b"%%EOF")
    assert b"/JavaScript" not in content
    assert b"/OpenAction" not in content
    assert len(PdfReader(BytesIO(content), strict=True).pages) == 1


@pytest.mark.parametrize(
    "content",
    [
        _interactive_pdf(
            catalog_extra=b"/Open#41ction 5 0 R ",
            extra_objects=(
                b"5 0 obj\n<< /S /Java#53cript /J#53 (active) >>\nendobj\n",
            ),
        ),
        _interactive_pdf(
            page_extra=b"/Annots [5 0 R] ",
            extra_objects=(
                b"5 0 obj\n<< /Subtype /Link /A << /S /URI "
                b"/URI (https://example.invalid) >> >>\nendobj\n",
            ),
        ),
        _interactive_pdf(
            catalog_extra=b"/AcroForm 5 0 R ",
            extra_objects=(
                b"5 0 obj\n<< /XFA 6 0 R >>\nendobj\n",
                b"6 0 obj\n<< /Length 24 >>\nstream\n"
                b"application/x-javascript\nendstream\nendobj\n",
            ),
        ),
    ],
)
def test_pdf_interactive_structures_cannot_hide_active_content(content: bytes) -> None:
    assert len(PdfReader(BytesIO(content), strict=True).pages) == 1
    with pytest.raises(UnsupportedArtifactMediaError):
        _ = ProductArtifactService().create_version(
            ArtifactVersionDraft(
                organization_id="org-a",
                artifact_id="artifact-unsafe",
                name="report.pdf",
                media_type="application/pdf",
                content=content,
                producer_execution_id="execution-1",
                environment_sha256="d" * 64,
                lineage_version_ids=("input-v1",),
            ),
            base_version_no=0,
        )
