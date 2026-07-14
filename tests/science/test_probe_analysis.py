import hashlib
from uuid import UUID

import pytest
from pydantic import ValidationError

from science_workbench_science import (
    BRANCH_ORDER,
    InputMetadata,
    OutcomeStatus,
    ProbeInput,
    analyze_probe,
)

from .fixtures import (
    VERSION_SPECTRUM,
    image_input,
    probe_input,
    report_input,
    spectrum_input,
)


def test_probe_analysis_emits_three_branches_table_plot_and_evidence() -> None:
    result = analyze_probe(probe_input())

    assert result.status is OutcomeStatus.VALID
    assert tuple(item.branch for item in result.hypotheses) == BRANCH_ORDER
    assert all(item.conclusion_scope == "non_diagnostic" for item in result.hypotheses)
    assert len(result.evidence) == 3
    assert all(len(item.supporting_sha256) == 64 for item in result.evidence)
    assert result.spectrum_plot_png is not None
    assert result.hypothesis_table_csv.startswith(
        b"branch,state,observation,control,conclusion_scope\n"
    )
    rendered = " ".join(
        item.observation + " " + item.limitation for item in result.hypotheses
    ).lower()
    assert "diagnosis" not in rendered
    assert "diagnose" not in rendered


def test_missing_units_or_calibration_returns_bounded_insufficient_data() -> None:
    spectrum = spectrum_input()
    incomplete = spectrum.model_copy(
        update={
            "metadata": InputMetadata(
                units=(),
                calibration=None,
                lineage_version_ids=spectrum.metadata.lineage_version_ids,
                research_only=True,
                non_clinical=True,
            )
        }
    )

    result = analyze_probe(ProbeInput(spectrum=incomplete))

    assert result.status is OutcomeStatus.INSUFFICIENT_DATA
    assert result.spectrum_plot_png is None
    assert tuple(item.branch for item in result.hypotheses) == BRANCH_ORDER
    assert all(item.state == "insufficient" for item in result.hypotheses)
    assert {issue.code for issue in result.issues} == {
        "calibration_required",
        "units_required",
    }


def test_malformed_numeric_shape_is_explicit_invalid_data_not_exception() -> None:
    spectrum = spectrum_input().model_copy(update={"intensities": (1.0, 2.0)})

    result = analyze_probe(ProbeInput(spectrum=spectrum))

    assert result.status is OutcomeStatus.INVALID_DATA
    assert {issue.code for issue in result.issues} == {"spectrum_shape_invalid"}
    assert all(item.conclusion_scope == "non_diagnostic" for item in result.hypotheses)


def test_full_analysis_is_structurally_identical_across_two_runs() -> None:
    first = analyze_probe(probe_input())
    second = analyze_probe(probe_input())

    assert first == second
    assert first.spectrum_plot_png == second.spectrum_plot_png
    assert first.hypothesis_table_csv == second.hypothesis_table_csv
    assert hashlib.sha256(first.hypothesis_table_csv).hexdigest() == (
        "d1bf965a140d71134652b911a482d47e5d3022f6f472c77cd0e9e5bca56f927e"
    )
    assert first.evidence == second.evidence
    assert tuple(item.supporting_sha256 for item in first.evidence) == (
        "1c0bdd70c67945c75502fb8e9dbcdc0bd4e4ecd37c37fac062ebbe9a41baff4e",
        "31efd838552f30b9643d94ec5a4a32ca5e9be38e166f8b46013b22060a88c8e7",
        "9b7a0cfd80ddc2214f843dbd7c1735584004d99d91b2f86a0a1df5fbe0e29802",
    )


def test_incomplete_unit_quantities_and_duplicate_lineage_are_insufficient() -> None:
    spectrum = spectrum_input()
    incomplete = spectrum.metadata.model_copy(
        update={
            "units": (spectrum.metadata.units[0],),
            "lineage_version_ids": (VERSION_SPECTRUM, VERSION_SPECTRUM),
        }
    )

    result = analyze_probe(
        ProbeInput(spectrum=spectrum.model_copy(update={"metadata": incomplete}))
    )

    assert result.status is OutcomeStatus.INSUFFICIENT_DATA
    assert {issue.code for issue in result.issues} == {
        "lineage_duplicate",
        "units_incomplete",
    }


def test_nonfinite_spectrum_and_bad_image_shape_are_invalid() -> None:
    spectrum = spectrum_input().model_copy(
        update={"intensities": (10.0, 12.0, float("nan"), 14.0, 12.0)}
    )
    image = image_input().model_copy(update={"pixels": image_input().pixels[:-1]})

    result = analyze_probe(ProbeInput(spectrum=spectrum, image=image))

    assert result.status is OutcomeStatus.INVALID_DATA
    assert {issue.code for issue in result.issues} == {
        "image_shape_invalid",
        "spectrum_shape_invalid",
    }


def test_empty_probe_and_empty_report_are_explicitly_bounded() -> None:
    empty = analyze_probe(ProbeInput())
    report = report_input().model_copy(update={"text": " \n\n "})
    invalid_report = analyze_probe(ProbeInput(report=report))

    assert empty.status is OutcomeStatus.INSUFFICIENT_DATA
    assert {issue.code for issue in empty.issues} == {"input_required"}
    assert invalid_report.status is OutcomeStatus.INVALID_DATA
    assert {issue.code for issue in invalid_report.issues} == {"report_empty"}


def test_lineage_rejects_non_uuid7_identity_at_the_input_boundary() -> None:
    spectrum = spectrum_input()

    with pytest.raises(ValidationError, match="uuid7"):
        _ = InputMetadata(
            units=spectrum.metadata.units,
            calibration=spectrum.metadata.calibration,
            lineage_version_ids=(UUID("12345678-1234-4234-8234-123456789abc"),),
            research_only=True,
            non_clinical=True,
        )


def test_oversized_report_is_rejected_before_text_normalization() -> None:
    report = report_input().model_copy(update={"text": "x" * 1_000_001})

    result = analyze_probe(ProbeInput(report=report))

    assert result.status is OutcomeStatus.INVALID_DATA
    assert {issue.code for issue in result.issues} == {"report_size_invalid"}


def test_missing_spectrum_values_and_empty_table_are_not_imputed() -> None:
    spectrum = spectrum_input().model_copy(
        update={"intensities": (10.0, None, 30.0, 14.0, 12.0)}
    )
    table = probe_input().table
    assert table is not None
    empty_table = table.model_copy(update={"rows": ()})

    result = analyze_probe(ProbeInput(spectrum=spectrum, table=empty_table))

    assert result.status is OutcomeStatus.INSUFFICIENT_DATA
    assert result.spectrum is not None
    assert result.spectrum.missing_fraction == 0.2
    assert result.spectrum.corrected == ()
    assert {issue.code for issue in result.issues} == {
        "spectrum_missing_values",
        "table_empty",
    }
