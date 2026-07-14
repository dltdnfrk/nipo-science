"""Deterministic numeric table and report normalization."""

import re
import statistics
import unicodedata

from .inputs import ReportInput, TableInput
from .outputs import (
    AnalysisIssue,
    ColumnStatistics,
    NormalizedReport,
    NormalizedTable,
    OutcomeStatus,
)
from .validation import (
    finite,
    metadata_issues,
    round_fixed,
    valid_unicode_scalar_text,
)

MAX_TABLE_COLUMNS = 1_024
MAX_TABLE_ROWS = 100_000
MAX_REPORT_CHARACTERS = 1_000_000


def normalize_table(source: TableInput) -> NormalizedTable:
    """Normalize a numeric table without imputing missing observations."""
    metadata_failures = metadata_issues(
        source.metadata,
        frozenset(source.columns),
    )
    shape_valid = (
        bool(source.columns)
        and len(source.columns) <= MAX_TABLE_COLUMNS
        and len(source.rows) <= MAX_TABLE_ROWS
        and len(set(source.columns)) == len(source.columns)
        and all(valid_unicode_scalar_text(column) for column in source.columns)
        and all(len(row) == len(source.columns) for row in source.rows)
    )
    numeric_values = (
        tuple(value for row in source.rows for value in row if value is not None)
        if shape_valid
        else ()
    )
    if not shape_valid or not finite(numeric_values):
        issue = AnalysisIssue(
            code="table_shape_invalid",
            message="Table rows must match finite declared columns",
        )
        return NormalizedTable(
            status=OutcomeStatus.INVALID_DATA,
            columns=source.columns,
            rows=source.rows,
            units=source.metadata.units,
            calibration=source.metadata.calibration,
            missing_fraction=(),
            statistics=(),
            lineage_version_ids=source.metadata.lineage_version_ids,
            issues=(*metadata_failures, issue),
        )
    row_count = len(source.rows)
    missing = tuple(
        round_fixed(
            sum(row[index] is None for row in source.rows) / row_count
            if row_count
            else 1.0
        )
        for index in range(len(source.columns))
    )
    try:
        summaries = tuple(
            _column_statistics(source, index) for index in range(len(source.columns))
        )
    except OverflowError:
        issue = AnalysisIssue(
            code="table_statistics_invalid",
            message="Table statistics exceed the finite processing range",
        )
        return NormalizedTable(
            status=OutcomeStatus.INVALID_DATA,
            columns=source.columns,
            rows=source.rows,
            units=source.metadata.units,
            calibration=source.metadata.calibration,
            missing_fraction=missing,
            statistics=(),
            lineage_version_ids=source.metadata.lineage_version_ids,
            issues=(*metadata_failures, issue),
        )
    if not source.rows:
        metadata_failures = (
            *metadata_failures,
            AnalysisIssue(code="table_empty", message="Table contains no rows"),
        )
    return NormalizedTable(
        status=(
            OutcomeStatus.INSUFFICIENT_DATA
            if metadata_failures
            else OutcomeStatus.VALID
        ),
        columns=source.columns,
        rows=source.rows,
        units=source.metadata.units,
        calibration=source.metadata.calibration,
        missing_fraction=missing,
        statistics=summaries,
        lineage_version_ids=source.metadata.lineage_version_ids,
        issues=metadata_failures,
    )


def normalize_report(source: ReportInput) -> NormalizedReport:
    """Normalize Unicode and whitespace while retaining paragraph boundaries."""
    metadata_failures = metadata_issues(source.metadata, frozenset({"document"}))
    oversized = len(source.text) > MAX_REPORT_CHARACTERS
    invalid_unicode = not valid_unicode_scalar_text(source.text)
    normalized = (
        ""
        if oversized or invalid_unicode
        else unicodedata.normalize("NFKC", source.text).strip()
    )
    paragraphs = tuple(
        collapsed
        for part in re.split(r"\n\s*\n", normalized)
        if (collapsed := " ".join(part.split()))
    )
    text = "\n\n".join(paragraphs)
    invalid = not text
    issues = metadata_failures
    if invalid:
        code = (
            "report_size_invalid"
            if oversized
            else "report_unicode_invalid"
            if invalid_unicode
            else "report_empty"
        )
        message = (
            "Report exceeds the processing limit"
            if oversized
            else "Report contains invalid Unicode scalar data"
            if invalid_unicode
            else "Report text is empty"
        )
        issues = (
            *issues,
            AnalysisIssue(
                code=code,
                message=message,
            ),
        )
    return NormalizedReport(
        status=(
            OutcomeStatus.INVALID_DATA
            if invalid
            else OutcomeStatus.INSUFFICIENT_DATA
            if metadata_failures
            else OutcomeStatus.VALID
        ),
        text=text,
        paragraphs=paragraphs,
        word_count=len(text.split()),
        missing_fraction=1.0 if invalid else 0.0,
        units=source.metadata.units,
        calibration=source.metadata.calibration,
        lineage_version_ids=source.metadata.lineage_version_ids,
        issues=issues,
    )


def _column_statistics(source: TableInput, index: int) -> ColumnStatistics:
    values = tuple(value for row in source.rows if (value := row[index]) is not None)
    missing_count = len(source.rows) - len(values)
    if not values:
        return ColumnStatistics(
            column=source.columns[index],
            count=0,
            missing_count=missing_count,
            minimum=None,
            maximum=None,
            mean=None,
            median=None,
            population_stddev=None,
        )
    minimum = round_fixed(min(values))
    maximum = round_fixed(max(values))
    mean = round_fixed(statistics.fmean(values))
    median = round_fixed(statistics.median(values))
    population_stddev = round_fixed(statistics.pstdev(values))
    if not finite((minimum, maximum, mean, median, population_stddev)):
        raise OverflowError
    return ColumnStatistics(
        column=source.columns[index],
        count=len(values),
        missing_count=missing_count,
        minimum=minimum,
        maximum=maximum,
        mean=mean,
        median=median,
        population_stddev=population_stddev,
    )
