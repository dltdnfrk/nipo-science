from io import BytesIO

from pypdf import PdfReader, PdfWriter
from services.api.product_artifact_types import ArtifactVersionDraft
from services.api.product_artifacts import ProductArtifactService


def test_passive_pdf_metadata_names_do_not_match_action_names_by_prefix() -> None:
    writer = PdfWriter()
    _ = writer.add_blank_page(width=72, height=72)
    writer.add_metadata({"/Author": "Mineral Lab", "/Title": "Passive report"})
    output = BytesIO()
    _ = writer.write(output)
    content = output.getvalue()

    version = ProductArtifactService().create_version(
        ArtifactVersionDraft(
            organization_id="org-a",
            artifact_id="artifact-passive-report",
            name="report.pdf",
            media_type="application/pdf",
            content=content,
            producer_execution_id="execution-1",
            environment_sha256="a" * 64,
            lineage_version_ids=("input-v1",),
        ),
        base_version_no=0,
    )

    assert len(PdfReader(BytesIO(version.content), strict=True).pages) == 1
