from science_workbench_science import (
    OutcomeStatus,
    ProbeInput,
    analyze_probe,
    normalize_report,
    normalize_table,
)

from .fixtures import probe_input, report_input, table_input


def test_table_normalization_preserves_units_missingness_and_lineage() -> None:
    normalized = normalize_table(table_input())

    assert normalized.status is OutcomeStatus.VALID
    assert normalized.missing_fraction == (0.0, 0.333333)
    assert normalized.statistics[0].mean == 2.0
    assert normalized.statistics[0].population_stddev == 0.816497
    assert normalized.statistics[1].mean == 12.0
    assert normalized.statistics[1].population_stddev == 2.0
    assert normalized.units[1].quantity == "signal"
    assert normalized.calibration == table_input().metadata.calibration
    assert normalized.lineage_version_ids == table_input().metadata.lineage_version_ids


def test_report_normalization_is_bounded_and_deterministic() -> None:
    normalized = normalize_report(report_input())

    assert normalized.status is OutcomeStatus.VALID
    assert normalized.text == "Probe report\n\nSignal increased at 500 nm."
    assert normalized.paragraphs == ("Probe report", "Signal increased at 500 nm.")
    assert normalized.word_count == 7
    assert normalized.lineage_version_ids == report_input().metadata.lineage_version_ids


def test_unrepresentable_table_statistics_are_explicit_invalid_data() -> None:
    table = table_input().model_copy(
        update={"rows": ((1e308, 1e308), (1e308, 1e308), (-1e308, -1e308))}
    )

    result = analyze_probe(ProbeInput(table=table))

    assert result.status is OutcomeStatus.INVALID_DATA
    assert {issue.code for issue in result.issues} == {"table_statistics_invalid"}
    assert result.table is not None
    assert result.table.statistics == ()


def test_unpaired_unicode_surrogate_is_explicit_invalid_data() -> None:
    report = report_input().model_copy(update={"text": "invalid\ud800report"})

    result = analyze_probe(ProbeInput(report=report))

    assert result.status is OutcomeStatus.INVALID_DATA
    assert {issue.code for issue in result.issues} == {"report_unicode_invalid"}
    assert result.report is not None
    assert result.report.text == ""


def test_evidence_hashes_are_canonical_over_lineage_order() -> None:
    table = probe_input().table
    assert table is not None
    first_metadata = table.metadata.model_copy(
        update={
            "lineage_version_ids": (
                table.metadata.lineage_version_ids[0],
                report_input().metadata.lineage_version_ids[0],
            )
        }
    )
    second_metadata = first_metadata.model_copy(
        update={
            "lineage_version_ids": tuple(reversed(first_metadata.lineage_version_ids))
        }
    )

    first = analyze_probe(
        ProbeInput(table=table.model_copy(update={"metadata": first_metadata}))
    )
    second = analyze_probe(
        ProbeInput(table=table.model_copy(update={"metadata": second_metadata}))
    )

    assert first.evidence == second.evidence


def test_nonfinite_invalid_inputs_keep_distinct_evidence_hashes() -> None:
    hashes: set[str] = set()
    for value in (float("nan"), float("inf"), float("-inf")):
        table = table_input().model_copy(update={"rows": ((value, 1.0),)})
        result = analyze_probe(ProbeInput(table=table))

        assert result.status is OutcomeStatus.INVALID_DATA
        hashes.add(result.evidence[-1].supporting_sha256)

    assert len(hashes) == 3


def test_surrogates_in_support_metadata_are_bounded_without_serialization_error() -> (
    None
):
    table = table_input()
    bad_columns = table.model_copy(update={"columns": ("sample\ud800", "signal")})
    calibration = table.metadata.calibration
    assert calibration is not None
    bad_calibration = calibration.model_copy(update={"method": "invalid\ud800method"})
    bad_metadata = table.metadata.model_copy(update={"calibration": bad_calibration})

    column_result = analyze_probe(ProbeInput(table=bad_columns))
    calibration_result = analyze_probe(
        ProbeInput(table=table.model_copy(update={"metadata": bad_metadata}))
    )

    assert column_result.status is OutcomeStatus.INVALID_DATA
    assert {issue.code for issue in column_result.issues} == {
        "table_shape_invalid",
        "units_incomplete",
    }
    assert calibration_result.status is OutcomeStatus.INSUFFICIENT_DATA
    assert {issue.code for issue in calibration_result.issues} == {
        "metadata_unicode_invalid"
    }
