"""Bounded GS04 hypothesis branches and immutable evidence helpers."""

import csv
import hashlib
import io
import json
from uuid import UUID

from .outputs import (
    EvidenceRecord,
    HypothesisBranch,
    HypothesisRecord,
    HypothesisState,
    NormalizedImage,
    NormalizedSpectrum,
    NormalizedTable,
    OutcomeStatus,
)

BRANCH_ORDER = (
    HypothesisBranch.MOLECULAR,
    HypothesisBranch.OPTICAL,
    HypothesisBranch.EXPERIMENTAL_ARTIFACT,
)
LIMITATION = "Research-support observation only; causality is not established."


def build_hypotheses(
    status: OutcomeStatus,
    table: NormalizedTable | None,
    spectrum: NormalizedSpectrum | None,
    image: NormalizedImage | None,
) -> tuple[HypothesisRecord, ...]:
    """Build molecular, optical, and experimental-artifact branches in order."""
    if status is not OutcomeStatus.VALID:
        return tuple(_insufficient(branch) for branch in BRANCH_ORDER)
    return (
        _molecular(spectrum),
        _optical(image),
        _experimental_artifact(table, spectrum, image),
    )


def build_evidence(
    hypotheses: tuple[HypothesisRecord, ...],
    lineage: dict[HypothesisBranch, tuple[UUID, ...]],
    support_payloads: dict[HypothesisBranch, bytes],
) -> tuple[EvidenceRecord, ...]:
    """Hash canonical branch records together with sorted immutable lineage."""
    records: list[EvidenceRecord] = []
    for index, hypothesis in enumerate(hypotheses, start=1):
        source_ids = tuple(sorted(set(lineage[hypothesis.branch])))
        canonical = json.dumps(
            {
                "hypothesis": hypothesis.model_dump(mode="json"),
                "sources": [str(value) for value in source_ids],
                "support_sha256": hashlib.sha256(
                    support_payloads[hypothesis.branch]
                ).hexdigest(),
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode()
        records.append(
            EvidenceRecord(
                claim_id=f"probe.{hypothesis.branch}.{index}",
                branch=hypothesis.branch,
                evidence_kind=(
                    "insufficient"
                    if hypothesis.state is HypothesisState.INSUFFICIENT
                    else "derived_observation"
                ),
                source_version_ids=source_ids,
                supporting_sha256=hashlib.sha256(canonical).hexdigest(),
                locator={
                    HypothesisBranch.MOLECULAR: "spectrum:normalized",
                    HypothesisBranch.OPTICAL: "image:regions",
                    HypothesisBranch.EXPERIMENTAL_ARTIFACT: "multimodal:quality",
                }[hypothesis.branch],
            )
        )
    return tuple(records)


def render_hypothesis_csv(hypotheses: tuple[HypothesisRecord, ...]) -> bytes:
    """Render a deterministic UTF-8 hypothesis table with fixed columns."""
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(("branch", "state", "observation", "control", "conclusion_scope"))
    for hypothesis in hypotheses:
        writer.writerow(
            (
                hypothesis.branch,
                hypothesis.state,
                hypothesis.observation,
                hypothesis.control,
                hypothesis.conclusion_scope,
            )
        )
    return output.getvalue().encode()


def _insufficient(branch: HypothesisBranch) -> HypothesisRecord:
    return HypothesisRecord(
        branch=branch,
        state=HypothesisState.INSUFFICIENT,
        observation="Required calibrated observations are unavailable.",
        control="Provide units, calibration, and immutable source lineage.",
        limitation=LIMITATION,
        conclusion_scope="non_diagnostic",
    )


def _molecular(spectrum: NormalizedSpectrum | None) -> HypothesisRecord:
    if spectrum is None or not spectrum.peaks:
        return _insufficient(HypothesisBranch.MOLECULAR)
    peak = max(spectrum.peaks, key=lambda item: item.corrected_intensity)
    wavelength_unit = next(
        unit.ucum_code for unit in spectrum.units if unit.quantity == "wavelength"
    )
    return HypothesisRecord(
        branch=HypothesisBranch.MOLECULAR,
        state=HypothesisState.PLAUSIBLE,
        observation=(
            f"Calibrated corrected signal has a local maximum at "
            f"{peak.wavelength:g} {wavelength_unit}."
        ),
        control="Compare a reference-standard spectrum under the same conditions.",
        limitation=LIMITATION,
        conclusion_scope="non_diagnostic",
    )


def _optical(image: NormalizedImage | None) -> HypothesisRecord:
    if image is None or not image.regions:
        return _insufficient(HypothesisBranch.OPTICAL)
    return HypothesisRecord(
        branch=HypothesisBranch.OPTICAL,
        state=HypothesisState.PLAUSIBLE,
        observation=f"Image contains {len(image.regions)} calibrated color region(s).",
        control="Repeat with fixed illumination, exposure, and blank reference.",
        limitation=LIMITATION,
        conclusion_scope="non_diagnostic",
    )


def _experimental_artifact(
    table: NormalizedTable | None,
    spectrum: NormalizedSpectrum | None,
    image: NormalizedImage | None,
) -> HypothesisRecord:
    missing = max(table.missing_fraction, default=0.0) if table is not None else 0.0
    modalities = sum(value is not None for value in (table, spectrum, image))
    return HypothesisRecord(
        branch=HypothesisBranch.EXPERIMENTAL_ARTIFACT,
        state=HypothesisState.OBSERVED,
        observation=(
            f"Cross-check covers {modalities} modality(ies); maximum table "
            f"missingness is {missing:.6f}."
        ),
        control="Repeat acquisition with randomized order and independent controls.",
        limitation=LIMITATION,
        conclusion_scope="non_diagnostic",
    )
