"""Deterministic multimodal probe-analysis orchestration."""

import json
from uuid import UUID

from .hypotheses import build_evidence, build_hypotheses, render_hypothesis_csv
from .image import normalize_image
from .inputs import ProbeInput
from .normalization import normalize_report, normalize_table
from .outputs import (
    AnalysisIssue,
    HypothesisBranch,
    NormalizedImage,
    NormalizedReport,
    NormalizedSpectrum,
    NormalizedTable,
    OutcomeStatus,
    ProbeAnalysis,
)
from .plots import render_spectrum_png
from .spectrum import normalize_spectrum

LIMITATIONS = (
    "Research-support output only.",
    "Missing or invalid inputs remain explicit and are never imputed.",
    "Branch observations do not establish causality.",
)


def analyze_probe(source: ProbeInput) -> ProbeAnalysis:
    """Normalize inputs and emit bounded GS04 branches and evidence records."""
    table = normalize_table(source.table) if source.table is not None else None
    spectrum = (
        normalize_spectrum(source.spectrum) if source.spectrum is not None else None
    )
    image = normalize_image(source.image) if source.image is not None else None
    report = normalize_report(source.report) if source.report is not None else None
    outputs = tuple(
        item for item in (table, spectrum, image, report) if item is not None
    )
    issues = tuple(issue for output in outputs for issue in output.issues)
    if not outputs:
        issues = (
            AnalysisIssue(
                code="input_required",
                message="At least one scientific modality is required",
            ),
        )
        status = OutcomeStatus.INSUFFICIENT_DATA
    elif any(output.status is OutcomeStatus.INVALID_DATA for output in outputs):
        status = OutcomeStatus.INVALID_DATA
    elif any(output.status is OutcomeStatus.INSUFFICIENT_DATA for output in outputs):
        status = OutcomeStatus.INSUFFICIENT_DATA
    else:
        status = OutcomeStatus.VALID
    hypotheses = build_hypotheses(status, table, spectrum, image)
    lineage = _lineage(table, spectrum, image, report)
    evidence = build_evidence(
        hypotheses,
        lineage,
        _support_payloads(table, spectrum, image, report),
    )
    plot = (
        render_spectrum_png(spectrum)
        if spectrum is not None and spectrum.status is OutcomeStatus.VALID
        else None
    )
    return ProbeAnalysis(
        status=status,
        table=table,
        spectrum=spectrum,
        image=image,
        report=report,
        hypotheses=hypotheses,
        evidence=evidence,
        spectrum_plot_png=plot,
        hypothesis_table_csv=render_hypothesis_csv(hypotheses),
        issues=issues,
        limitations=LIMITATIONS,
    )


def _lineage(
    table: NormalizedTable | None,
    spectrum: NormalizedSpectrum | None,
    image: NormalizedImage | None,
    report: NormalizedReport | None,
) -> dict[HypothesisBranch, tuple[UUID, ...]]:
    table_ids = () if table is None else table.lineage_version_ids
    spectrum_ids = () if spectrum is None else spectrum.lineage_version_ids
    image_ids = () if image is None else image.lineage_version_ids
    report_ids = () if report is None else report.lineage_version_ids
    return {
        HypothesisBranch.MOLECULAR: spectrum_ids,
        HypothesisBranch.OPTICAL: image_ids,
        HypothesisBranch.EXPERIMENTAL_ARTIFACT: (
            *table_ids,
            *spectrum_ids,
            *image_ids,
            *report_ids,
        ),
    }


def _support_payloads(
    table: NormalizedTable | None,
    spectrum: NormalizedSpectrum | None,
    image: NormalizedImage | None,
    report: NormalizedReport | None,
) -> dict[HypothesisBranch, bytes]:
    table_bytes = b"" if table is None else _canonical_output_bytes(table)
    spectrum_bytes = b"" if spectrum is None else _canonical_output_bytes(spectrum)
    image_bytes = b"" if image is None else _canonical_output_bytes(image)
    report_bytes = b"" if report is None else _canonical_output_bytes(report)
    return {
        HypothesisBranch.MOLECULAR: spectrum_bytes,
        HypothesisBranch.OPTICAL: image_bytes,
        HypothesisBranch.EXPERIMENTAL_ARTIFACT: b"\x1f".join(
            (table_bytes, spectrum_bytes, image_bytes, report_bytes)
        ),
    }


def _canonical_output_bytes(
    output: NormalizedTable | NormalizedSpectrum | NormalizedImage | NormalizedReport,
) -> bytes:
    lineage = tuple(sorted(set(output.lineage_version_ids)))
    canonical = output.model_copy(update={"lineage_version_ids": lineage})
    return json.dumps(
        canonical.model_dump(mode="json"),
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode()
