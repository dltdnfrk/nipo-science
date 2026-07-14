"""Deterministic passive Artifact fixtures for the test principal."""

from __future__ import annotations

import base64
from collections.abc import Callable
from typing import Final

from services.api.product_artifact_types import ArtifactVersion, ArtifactVersionDraft
from services.api.product_pdf_validation import minimal_passive_pdf

type VersionCreator = Callable[[ArtifactVersionDraft, int], ArtifactVersion]

_ENVIRONMENT: Final = "e" * 64
_PNG: Final = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNk+A8AAQUBAScY42YAAAAASUVORK5CYII="
)


def seed_artifact_fixtures(create: VersionCreator) -> None:
    """Create tenant-visible CSV/PNG/PDF V1/V2 plus one foreign Version."""
    fixtures = (
        (
            "artifact-spectrum",
            "normalized.csv",
            "text/csv",
            b"wavelength,intensity\n500,19\n",
        ),
        ("artifact-image", "preview.png", "image/png", _PNG),
        ("artifact-report", "analysis.pdf", "application/pdf", minimal_passive_pdf()),
    )
    for artifact_id, name, media_type, content in fixtures:
        first = create(
            ArtifactVersionDraft(
                organization_id="org-mineral",
                artifact_id=artifact_id,
                name=name,
                media_type=media_type,
                content=content,
                producer_execution_id="execution-1",
                environment_sha256=_ENVIRONMENT,
                lineage_version_ids=("input-v1",),
            ),
            0,
        )
        _ = create(
            ArtifactVersionDraft(
                organization_id="org-mineral",
                artifact_id=artifact_id,
                name=name,
                media_type=media_type,
                content=content + (b"\n" if media_type == "text/csv" else b""),
                producer_execution_id="execution-2",
                environment_sha256=_ENVIRONMENT,
                lineage_version_ids=(first.id,),
            ),
            1,
        )
    _ = create(
        ArtifactVersionDraft(
            organization_id="org-foreign",
            artifact_id="artifact-foreign",
            name="hidden.csv",
            media_type="text/csv",
            content=b"hidden\n",
            producer_execution_id="execution-foreign",
            environment_sha256=_ENVIRONMENT,
            lineage_version_ids=("foreign-input",),
        ),
        0,
    )
