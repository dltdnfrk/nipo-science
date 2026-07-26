"""Behavioural tests for the sidecar-manifest measurement loaders.

Every test writes real files into ``tmp_path`` and loads them through the
public API; no file object is mocked, because the defects worth catching here
live in encoding, parsing, and refusal behaviour rather than in call wiring.

Expected values are spelled out as literals. Nothing is imported from
``nipo_local.loaders`` except the callables and exception types under test, so
a mutated constant in the module cannot quietly satisfy its own assertion --
the required quantity names, the manifest version string, the sidecar suffix,
and the science package's issue codes are all written out by hand below.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import TYPE_CHECKING
from uuid import UUID

import pytest
from PIL import Image

from nipo_local.loaders import (
    DataFileNotFoundError,
    LoaderError,
    MalformedDataError,
    ManifestKindMismatchError,
    ManifestNotFoundError,
    ManifestSchemaError,
    ManifestSyntaxError,
    MetadataPolicy,
    MetadataRejectedError,
    load_image,
    load_probe,
    load_report,
    load_spectrum,
    load_table,
    manifest_path_for,
    read_manifest,
)
from science_workbench_science import OutcomeStatus, analyze_probe

if TYPE_CHECKING:
    from pathlib import Path

LINEAGE_UUID7 = "01900000-0000-7000-8000-00000000000a"
SECOND_UUID7 = "01900000-0000-7000-8000-00000000000b"
UUID_V4 = "00000000-0000-4000-8000-000000000000"
DIGEST = "3b1f" + "0" * 60

MANIFEST_VERSION = "nipo.local.input-manifest.v1"
DEFAULT_LINEAGE = f'[lineage]\nversion_ids = ["{LINEAGE_UUID7}"]\n'
DEFAULT_CALIBRATION = (
    "[calibration]\n"
    'method = "two-point NIST-traceable"\n'
    'reference = "SRM 2242a"\n'
    "calibrated_at = 2026-01-04T09:30:00Z\n"
    f'calibration_sha256 = "{DIGEST}"\n'
)

SPECTRUM_BODY = "wavelength,intensity\n400,1.0\n410,5.0\n420,2.0\n430,7.0\n440,3.0\n"


def _units(*pairs: tuple[str, str]) -> str:
    return "\n".join(
        f'[[units]]\nquantity = "{quantity}"\nucum_code = "{code}"\n'
        for quantity, code in pairs
    )


SPECTRUM_UNITS = _units(("wavelength", "nm"), ("intensity", "1"))
TABLE_UNITS = _units(("mass", "g"), ("volume", "mL"))
IMAGE_UNITS = _units(("color", "1"))
REPORT_UNITS = _units(("document", "1"))
IMAGE_EXTRA = "[image]\nregion_threshold = 12.5\n"


def _manifest(  # noqa: PLR0913
    kind: str,
    units: str,
    *,
    version: str = MANIFEST_VERSION,
    research_only: str = "true",
    non_clinical: str = "true",
    calibration: str = DEFAULT_CALIBRATION,
    lineage: str = DEFAULT_LINEAGE,
    extra: str = "",
) -> str:
    parts = [
        f'manifest_version = "{version}"\n',
        f'kind = "{kind}"\n',
        f"[scope]\nresearch_only = {research_only}\nnon_clinical = {non_clinical}\n",
        units,
        calibration,
        lineage,
        extra,
    ]
    return "\n".join(part for part in parts if part)


def _mentions(error: ManifestSchemaError, fragment: str) -> bool:
    """Search the structured problem list, never the path-bearing message.

    ``pytest``'s ``tmp_path`` embeds the test's own name, so asserting a
    substring against ``str(error)`` can pass purely because the word appears
    in the directory name.
    """
    return any(fragment in problem for problem in error.problems)


def _write(tmp_path: Path, name: str, body: str, manifest: str) -> Path:
    data = tmp_path / name
    _ = data.write_text(body, encoding="utf-8")
    _ = (tmp_path / f"{name}.manifest.toml").write_text(manifest, encoding="utf-8")
    return data


def _spectrum_file(  # noqa: PLR0913
    tmp_path: Path,
    body: str = SPECTRUM_BODY,
    *,
    version: str = MANIFEST_VERSION,
    research_only: str = "true",
    non_clinical: str = "true",
    calibration: str = DEFAULT_CALIBRATION,
    lineage: str = DEFAULT_LINEAGE,
    extra: str = "",
) -> Path:
    manifest = _manifest(
        "spectrum",
        SPECTRUM_UNITS,
        version=version,
        research_only=research_only,
        non_clinical=non_clinical,
        calibration=calibration,
        lineage=lineage,
        extra=extra,
    )
    return _write(tmp_path, "spectrum.csv", body, manifest)


TABLE_BODY = "mass,volume\n1.5,2.0\n,3.0\n4.5,\n"


def _table_file(
    tmp_path: Path,
    body: str = TABLE_BODY,
    units: str = TABLE_UNITS,
) -> Path:
    return _write(tmp_path, "table.csv", body, _manifest("table", units))


def _image_file(
    tmp_path: Path,
    name: str = "field.png",
    *,
    extra: str = IMAGE_EXTRA,
    kind: str = "image",
) -> Path:
    image = Image.new("RGB", (3, 2), (10, 20, 30))
    image.putpixel((1, 0), (200, 100, 50))
    image.save(tmp_path / name)
    _ = (tmp_path / f"{name}.manifest.toml").write_text(
        _manifest(kind, IMAGE_UNITS, extra=extra), encoding="utf-8"
    )
    return tmp_path / name


# --------------------------------------------------------------------------
# sidecar discovery
# --------------------------------------------------------------------------


def test_manifest_path_appends_suffix_to_full_filename(tmp_path: Path) -> None:
    assert manifest_path_for(tmp_path / "run-7.csv").name == "run-7.csv.manifest.toml"


def test_missing_manifest_names_the_expected_sidecar(tmp_path: Path) -> None:
    data = tmp_path / "spectrum.csv"
    _ = data.write_text(SPECTRUM_BODY, encoding="utf-8")
    with pytest.raises(ManifestNotFoundError) as caught:
        _ = load_spectrum(data)
    message = str(caught.value)
    assert "spectrum.csv.manifest.toml" in message
    assert "spectrum.csv" in message


def test_missing_data_file_is_reported_before_the_manifest(tmp_path: Path) -> None:
    _ = (tmp_path / "gone.csv.manifest.toml").write_text(
        _manifest("spectrum", SPECTRUM_UNITS), encoding="utf-8"
    )
    with pytest.raises(DataFileNotFoundError) as caught:
        _ = load_spectrum(tmp_path / "gone.csv")
    assert caught.value.path.name == "gone.csv"


def test_missing_data_file_outranks_a_broken_manifest(tmp_path: Path) -> None:
    """A file that is not there is the more fundamental problem to report."""
    _ = (tmp_path / "gone.csv.manifest.toml").write_text(
        "kind = [unclosed\n", encoding="utf-8"
    )
    with pytest.raises(DataFileNotFoundError):
        _ = load_spectrum(tmp_path / "gone.csv")


def test_unparsable_toml_reports_a_syntax_error(tmp_path: Path) -> None:
    data = _write(tmp_path, "spectrum.csv", SPECTRUM_BODY, "kind = [unclosed\n")
    with pytest.raises(ManifestSyntaxError) as caught:
        _ = load_spectrum(data)
    assert caught.value.path.name == "spectrum.csv.manifest.toml"


# --------------------------------------------------------------------------
# manifest schema strictness
# --------------------------------------------------------------------------


def test_unknown_top_level_key_is_rejected_by_name(tmp_path: Path) -> None:
    manifest = (
        f'manifest_version = "{MANIFEST_VERSION}"\n'
        'kind = "spectrum"\n'
        'operator = "kim"\n'
        "[scope]\nresearch_only = true\nnon_clinical = true\n"
        f"{SPECTRUM_UNITS}\n{DEFAULT_CALIBRATION}{DEFAULT_LINEAGE}"
    )
    data = _write(tmp_path, "spectrum.csv", SPECTRUM_BODY, manifest)
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert caught.value.problems == ("unknown key 'operator'",)


def test_unknown_nested_key_is_rejected_with_its_path(tmp_path: Path) -> None:
    calibration = DEFAULT_CALIBRATION + "temperature_c = 21.5\n"
    data = _spectrum_file(tmp_path, calibration=calibration)
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert caught.value.problems == ("unknown key 'calibration.temperature_c'",)


def test_missing_scope_section_is_reported_as_a_missing_key(tmp_path: Path) -> None:
    manifest = (
        f'manifest_version = "{MANIFEST_VERSION}"\n'
        'kind = "spectrum"\n'
        f"{SPECTRUM_UNITS}\n{DEFAULT_CALIBRATION}{DEFAULT_LINEAGE}"
    )
    data = _write(tmp_path, "spectrum.csv", SPECTRUM_BODY, manifest)
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert caught.value.problems == ("missing required key 'scope'",)


def test_wrong_manifest_version_is_rejected(tmp_path: Path) -> None:
    data = _spectrum_file(tmp_path, version="nipo.local.input-manifest.v99")
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert _mentions(caught.value, "manifest_version must be")


def test_research_only_false_is_refused(tmp_path: Path) -> None:
    data = _spectrum_file(tmp_path, research_only="false")
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert "scope.research_only must be true" in caught.value.problems


def test_non_clinical_false_is_refused(tmp_path: Path) -> None:
    data = _spectrum_file(tmp_path, non_clinical="false")
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert "scope.non_clinical must be true" in caught.value.problems


def test_unknown_kind_value_is_rejected(tmp_path: Path) -> None:
    data = _write(
        tmp_path,
        "spectrum.csv",
        SPECTRUM_BODY,
        _manifest("chromatogram", SPECTRUM_UNITS),
    )
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert _mentions(caught.value, "kind")


def test_loading_a_table_manifest_as_a_spectrum_is_refused(tmp_path: Path) -> None:
    data = _write(
        tmp_path,
        "spectrum.csv",
        SPECTRUM_BODY,
        _manifest("table", SPECTRUM_UNITS),
    )
    with pytest.raises(ManifestKindMismatchError) as caught:
        _ = load_spectrum(data)
    assert caught.value.declared == "table"
    assert caught.value.requested == "spectrum"


def test_read_manifest_exposes_declared_units_and_lineage(tmp_path: Path) -> None:
    manifest = read_manifest(_spectrum_file(tmp_path))
    assert manifest.kind == "spectrum"
    assert [(unit.quantity, unit.ucum_code) for unit in manifest.units] == [
        ("wavelength", "nm"),
        ("intensity", "1"),
    ]
    assert manifest.lineage is not None
    assert manifest.lineage.version_ids == [LINEAGE_UUID7]


# --------------------------------------------------------------------------
# calibration and lineage
# --------------------------------------------------------------------------


def test_naive_calibration_timestamp_is_refused_not_assumed_utc(
    tmp_path: Path,
) -> None:
    calibration = DEFAULT_CALIBRATION.replace(
        "calibrated_at = 2026-01-04T09:30:00Z",
        "calibrated_at = 2026-01-04T09:30:00",
    )
    data = _spectrum_file(tmp_path, calibration=calibration)
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert _mentions(caught.value, "no UTC offset")


def test_offset_timestamp_is_converted_to_the_same_utc_instant(
    tmp_path: Path,
) -> None:
    calibration = DEFAULT_CALIBRATION.replace(
        "calibrated_at = 2026-01-04T09:30:00Z",
        "calibrated_at = 2026-01-04T18:30:00+09:00",
    )
    loaded = load_spectrum(_spectrum_file(tmp_path, calibration=calibration))
    calibrated = loaded.metadata.calibration
    assert calibrated is not None
    assert calibrated.calibrated_at == datetime(2026, 1, 4, 9, 30, tzinfo=UTC)


def test_absent_calibration_surfaces_the_science_calibration_code(
    tmp_path: Path,
) -> None:
    data = _spectrum_file(tmp_path, calibration="")
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_spectrum(data)
    assert [issue.code for issue in caught.value.issues] == ["calibration_required"]


def test_absent_calibration_is_never_replaced_with_a_default(tmp_path: Path) -> None:
    loaded = load_spectrum(
        _spectrum_file(tmp_path, calibration=""), MetadataPolicy.DEFER
    )
    assert loaded.metadata.calibration is None


def test_short_calibration_digest_is_rejected(tmp_path: Path) -> None:
    calibration = DEFAULT_CALIBRATION.replace(DIGEST, "abc123")
    data = _spectrum_file(tmp_path, calibration=calibration)
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert _mentions(caught.value, "calibration_sha256")


def test_uppercase_calibration_digest_is_refused_not_lowercased(
    tmp_path: Path,
) -> None:
    calibration = DEFAULT_CALIBRATION.replace(DIGEST, DIGEST.upper())
    data = _spectrum_file(tmp_path, calibration=calibration)
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert _mentions(caught.value, "calibration_sha256")


def test_absent_lineage_surfaces_the_science_lineage_code(tmp_path: Path) -> None:
    data = _spectrum_file(tmp_path, lineage="")
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_spectrum(data)
    assert [issue.code for issue in caught.value.issues] == ["lineage_required"]


def test_absent_lineage_is_never_replaced_with_a_generated_id(tmp_path: Path) -> None:
    loaded = load_spectrum(_spectrum_file(tmp_path, lineage=""), MetadataPolicy.DEFER)
    assert loaded.metadata.lineage_version_ids == ()


def test_non_uuid_lineage_entry_is_rejected(tmp_path: Path) -> None:
    data = _spectrum_file(tmp_path, lineage='[lineage]\nversion_ids = ["run-7"]\n')
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert _mentions(caught.value, "'run-7' is not a UUID")


def test_uuid_version_4_lineage_entry_is_rejected(tmp_path: Path) -> None:
    data = _spectrum_file(tmp_path, lineage=f'[lineage]\nversion_ids = ["{UUID_V4}"]\n')
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert _mentions(caught.value, "lineage_version_ids")


def test_multiple_lineage_ids_are_preserved_in_order(tmp_path: Path) -> None:
    lineage = f'[lineage]\nversion_ids = ["{LINEAGE_UUID7}", "{SECOND_UUID7}"]\n'
    loaded = load_spectrum(_spectrum_file(tmp_path, lineage=lineage))
    assert loaded.metadata.lineage_version_ids == (
        UUID(LINEAGE_UUID7),
        UUID(SECOND_UUID7),
    )


def test_duplicate_lineage_ids_surface_the_science_duplicate_code(
    tmp_path: Path,
) -> None:
    lineage = f'[lineage]\nversion_ids = ["{LINEAGE_UUID7}", "{LINEAGE_UUID7}"]\n'
    data = _spectrum_file(tmp_path, lineage=lineage)
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_spectrum(data)
    assert "lineage_duplicate" in [issue.code for issue in caught.value.issues]


# --------------------------------------------------------------------------
# unit declarations, checked against the science package's own codes
# --------------------------------------------------------------------------


def test_no_units_surfaces_units_required(tmp_path: Path) -> None:
    data = _write(tmp_path, "spectrum.csv", SPECTRUM_BODY, _manifest("spectrum", ""))
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_spectrum(data)
    assert [issue.code for issue in caught.value.issues] == ["units_required"]


def test_partial_units_surfaces_units_incomplete(tmp_path: Path) -> None:
    data = _write(
        tmp_path,
        "spectrum.csv",
        SPECTRUM_BODY,
        _manifest("spectrum", _units(("wavelength", "nm"))),
    )
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_spectrum(data)
    assert [issue.code for issue in caught.value.issues] == ["units_incomplete"]


def test_repeated_quantity_surfaces_units_ambiguous(tmp_path: Path) -> None:
    units = _units(("wavelength", "nm"), ("intensity", "1"), ("intensity", "cd"))
    data = _write(tmp_path, "spectrum.csv", SPECTRUM_BODY, _manifest("spectrum", units))
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_spectrum(data)
    assert "units_ambiguous" in [issue.code for issue in caught.value.issues]


def test_non_length_wavelength_unit_surfaces_the_incompatible_code(
    tmp_path: Path,
) -> None:
    units = _units(("wavelength", "s"), ("intensity", "1"))
    data = _write(tmp_path, "spectrum.csv", SPECTRUM_BODY, _manifest("spectrum", units))
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_spectrum(data)
    assert "wavelength_unit_incompatible" in [
        issue.code for issue in caught.value.issues
    ]


def test_declared_units_reach_the_typed_input(tmp_path: Path) -> None:
    loaded = load_spectrum(_spectrum_file(tmp_path))
    assert [(unit.quantity, unit.ucum_code) for unit in loaded.metadata.units] == [
        ("wavelength", "nm"),
        ("intensity", "1"),
    ]


# --------------------------------------------------------------------------
# spectrum CSV
# --------------------------------------------------------------------------


def test_spectrum_values_load_exactly(tmp_path: Path) -> None:
    loaded = load_spectrum(_spectrum_file(tmp_path))
    assert loaded.wavelengths == (400.0, 410.0, 420.0, 430.0, 440.0)
    assert loaded.intensities == (1.0, 5.0, 2.0, 7.0, 3.0)


def test_blank_intensity_stays_missing_and_is_not_zero_filled(
    tmp_path: Path,
) -> None:
    body = "wavelength,intensity\n400,1.0\n410,\n420,2.0\n"
    loaded = load_spectrum(_spectrum_file(tmp_path, body))
    assert loaded.intensities == (1.0, None, 2.0)
    assert loaded.intensities[1] is None


def test_blank_intensity_row_is_not_dropped(tmp_path: Path) -> None:
    body = "wavelength,intensity\n400,\n410,\n420,2.0\n"
    loaded = load_spectrum(_spectrum_file(tmp_path, body))
    assert len(loaded.wavelengths) == 3
    assert loaded.wavelengths == (400.0, 410.0, 420.0)
    assert loaded.intensities == (None, None, 2.0)


def test_whitespace_only_intensity_is_missing_not_a_parse_error(
    tmp_path: Path,
) -> None:
    body = "wavelength,intensity\n400,1.0\n410,   \n420,2.0\n"
    loaded = load_spectrum(_spectrum_file(tmp_path, body))
    assert loaded.intensities == (1.0, None, 2.0)


def test_blank_wavelength_is_refused_because_it_cannot_be_missing(
    tmp_path: Path,
) -> None:
    body = "wavelength,intensity\n400,1.0\n,5.0\n"
    with pytest.raises(MalformedDataError) as caught:
        _ = load_spectrum(_spectrum_file(tmp_path, body))
    detail = caught.value.detail
    assert "line 3" in detail
    assert "wavelength" in detail
    assert caught.value.path.name == "spectrum.csv"


def test_non_numeric_cell_names_the_line_and_column(tmp_path: Path) -> None:
    body = "wavelength,intensity\n400,1.0\n410,below detection\n"
    with pytest.raises(MalformedDataError) as caught:
        _ = load_spectrum(_spectrum_file(tmp_path, body))
    detail = caught.value.detail
    assert "line 3" in detail
    assert "intensity" in detail
    assert "below detection" in detail
    assert caught.value.path.name == "spectrum.csv"


@pytest.mark.parametrize("token", ["nan", "NaN", "inf", "-inf", "Infinity"])
def test_non_finite_tokens_are_refused(tmp_path: Path, token: str) -> None:
    body = f"wavelength,intensity\n400,1.0\n410,{token}\n"
    with pytest.raises(MalformedDataError) as caught:
        _ = load_spectrum(_spectrum_file(tmp_path, body))
    assert "not finite" in caught.value.detail


def test_transposed_header_is_refused_rather_than_silently_swapped(
    tmp_path: Path,
) -> None:
    body = "intensity,wavelength\n1.0,400\n5.0,410\n"
    with pytest.raises(MalformedDataError) as caught:
        _ = load_spectrum(_spectrum_file(tmp_path, body))
    assert "header must be exactly" in caught.value.detail


def test_header_casing_and_padding_are_tolerated(tmp_path: Path) -> None:
    body = " Wavelength , INTENSITY \n400,1.0\n410,5.0\n"
    loaded = load_spectrum(_spectrum_file(tmp_path, body))
    assert loaded.wavelengths == (400.0, 410.0)


def test_third_column_is_refused(tmp_path: Path) -> None:
    body = "wavelength,intensity\n400,1.0,extra\n"
    with pytest.raises(MalformedDataError) as caught:
        _ = load_spectrum(_spectrum_file(tmp_path, body))
    assert "3 fields" in caught.value.detail


def test_empty_spectrum_file_is_refused_as_empty_not_as_a_header_problem(
    tmp_path: Path,
) -> None:
    with pytest.raises(MalformedDataError) as caught:
        _ = load_spectrum(_spectrum_file(tmp_path, ""))
    assert "file is empty" in caught.value.detail


def test_empty_table_file_is_refused(tmp_path: Path) -> None:
    with pytest.raises(MalformedDataError) as caught:
        _ = load_table(_table_file(tmp_path, ""))
    assert "file is empty" in caught.value.detail


def test_header_only_spectrum_loads_as_no_observations(tmp_path: Path) -> None:
    loaded = load_spectrum(_spectrum_file(tmp_path, "wavelength,intensity\n"))
    assert loaded.wavelengths == ()
    assert loaded.intensities == ()


def test_byte_order_mark_does_not_break_the_header(tmp_path: Path) -> None:
    data = tmp_path / "spectrum.csv"
    _ = data.write_bytes(b"\xef\xbb\xbf" + SPECTRUM_BODY.encode())
    _ = (tmp_path / "spectrum.csv.manifest.toml").write_text(
        _manifest("spectrum", SPECTRUM_UNITS), encoding="utf-8"
    )
    assert load_spectrum(data).wavelengths == (400.0, 410.0, 420.0, 430.0, 440.0)


def test_undecodable_bytes_are_refused(tmp_path: Path) -> None:
    data = tmp_path / "spectrum.csv"
    _ = data.write_bytes(b"wavelength,intensity\n400,\xff\xfe1.0\n")
    _ = (tmp_path / "spectrum.csv.manifest.toml").write_text(
        _manifest("spectrum", SPECTRUM_UNITS), encoding="utf-8"
    )
    with pytest.raises(MalformedDataError) as caught:
        _ = load_spectrum(data)
    assert "not valid UTF-8" in caught.value.detail


# --------------------------------------------------------------------------
# table CSV
# --------------------------------------------------------------------------


def test_table_rows_preserve_missing_cells(tmp_path: Path) -> None:
    loaded = load_table(_table_file(tmp_path))
    assert loaded.columns == ("mass", "volume")
    assert loaded.rows == ((1.5, 2.0), (None, 3.0), (4.5, None))


def test_table_requires_a_unit_for_every_column(tmp_path: Path) -> None:
    data = _table_file(tmp_path, units=_units(("mass", "g")))
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_table(data)
    assert [issue.code for issue in caught.value.issues] == ["units_incomplete"]


def test_repeated_table_column_names_are_refused(tmp_path: Path) -> None:
    data = _table_file(tmp_path, "mass,mass\n1.0,2.0\n")
    with pytest.raises(MalformedDataError) as caught:
        _ = load_table(data)
    assert "column names repeat" in caught.value.detail


def test_blank_table_column_name_is_refused(tmp_path: Path) -> None:
    data = _table_file(tmp_path, "mass,\n1.0,2.0\n")
    with pytest.raises(MalformedDataError) as caught:
        _ = load_table(data)
    assert "non-blank name" in caught.value.detail


def test_ragged_table_row_is_refused(tmp_path: Path) -> None:
    data = _table_file(tmp_path, "mass,volume\n1.0,2.0\n3.0\n")
    with pytest.raises(MalformedDataError) as caught:
        _ = load_table(data)
    assert "line 3" in caught.value.detail
    assert "1 fields" in caught.value.detail


# --------------------------------------------------------------------------
# image
# --------------------------------------------------------------------------


def test_png_loads_row_major_rgb_pixels(tmp_path: Path) -> None:
    loaded = load_image(_image_file(tmp_path))
    assert loaded.width == 3
    assert loaded.height == 2
    assert len(loaded.pixels) == 6
    assert loaded.pixels[0] == (10, 20, 30)
    assert loaded.pixels[1] == (200, 100, 50)
    assert loaded.pixels[5] == (10, 20, 30)


def test_image_region_threshold_comes_from_the_manifest(tmp_path: Path) -> None:
    assert load_image(_image_file(tmp_path)).region_threshold == 12.5


def test_image_without_region_threshold_is_refused(tmp_path: Path) -> None:
    data = _image_file(tmp_path, extra="")
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_image(data)
    assert _mentions(caught.value, "region_threshold is required")


def test_image_section_on_a_spectrum_manifest_is_refused(tmp_path: Path) -> None:
    data = _spectrum_file(tmp_path, extra=IMAGE_EXTRA)
    with pytest.raises(ManifestSchemaError) as caught:
        _ = load_spectrum(data)
    assert _mentions(caught.value, "[image] is only valid")


def test_jpeg_loads(tmp_path: Path) -> None:
    loaded = load_image(_image_file(tmp_path, "field.jpg"))
    assert loaded.width == 3
    assert loaded.height == 2
    assert len(loaded.pixels) == 6


def test_grayscale_png_is_widened_to_rgb(tmp_path: Path) -> None:
    Image.new("L", (2, 2), 128).save(tmp_path / "gray.png")
    _ = (tmp_path / "gray.png.manifest.toml").write_text(
        _manifest("image", IMAGE_UNITS, extra=IMAGE_EXTRA), encoding="utf-8"
    )
    assert load_image(tmp_path / "gray.png").pixels[0] == (128, 128, 128)


def test_non_image_bytes_are_refused(tmp_path: Path) -> None:
    data = tmp_path / "field.png"
    _ = data.write_bytes(b"this is not a png")
    _ = (tmp_path / "field.png.manifest.toml").write_text(
        _manifest("image", IMAGE_UNITS, extra=IMAGE_EXTRA), encoding="utf-8"
    )
    with pytest.raises(MalformedDataError) as caught:
        _ = load_image(data)
    assert "Pillow can decode" in caught.value.detail
    assert caught.value.path.name == "field.png"


def test_image_without_color_unit_surfaces_units_incomplete(tmp_path: Path) -> None:
    Image.new("RGB", (2, 2), (1, 2, 3)).save(tmp_path / "field.png")
    _ = (tmp_path / "field.png.manifest.toml").write_text(
        _manifest("image", _units(("brightness", "1")), extra=IMAGE_EXTRA),
        encoding="utf-8",
    )
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_image(tmp_path / "field.png")
    assert [issue.code for issue in caught.value.issues] == ["units_incomplete"]


def test_image_beyond_the_pixel_limit_is_refused(tmp_path: Path) -> None:
    # 2100 x 2000 = 4_200_000 pixels, past the documented 4_000_000 guard.
    Image.new("RGB", (2100, 2000), (1, 2, 3)).save(tmp_path / "field.png")
    _ = (tmp_path / "field.png.manifest.toml").write_text(
        _manifest("image", IMAGE_UNITS, extra=IMAGE_EXTRA), encoding="utf-8"
    )
    with pytest.raises(MalformedDataError) as caught:
        _ = load_image(tmp_path / "field.png")
    assert "2100x2000" in caught.value.detail
    assert "pixel" in caught.value.detail


def test_image_beyond_the_byte_limit_is_refused(tmp_path: Path) -> None:
    data = tmp_path / "field.png"
    with data.open("wb") as handle:
        _ = handle.seek(65 * 1024 * 1024)
        _ = handle.write(b"x")
    _ = (tmp_path / "field.png.manifest.toml").write_text(
        _manifest("image", IMAGE_UNITS, extra=IMAGE_EXTRA), encoding="utf-8"
    )
    with pytest.raises(MalformedDataError) as caught:
        _ = load_image(data)
    assert "above the" in caught.value.detail
    assert "byte loader limit" in caught.value.detail


def test_text_beyond_the_byte_limit_is_refused_before_it_is_read(
    tmp_path: Path,
) -> None:
    data = tmp_path / "spectrum.csv"
    with data.open("wb") as handle:
        _ = handle.seek(65 * 1024 * 1024)
        _ = handle.write(b"x")
    _ = (tmp_path / "spectrum.csv.manifest.toml").write_text(
        _manifest("spectrum", SPECTRUM_UNITS), encoding="utf-8"
    )
    with pytest.raises(MalformedDataError) as caught:
        _ = load_spectrum(data)
    assert "above the" in caught.value.detail
    assert "byte loader limit" in caught.value.detail


# --------------------------------------------------------------------------
# report
# --------------------------------------------------------------------------


def test_report_text_loads_verbatim(tmp_path: Path) -> None:
    body = "# Run 7\n\nThe sample showed two peaks.\n"
    data = _write(tmp_path, "notes.md", body, _manifest("report", REPORT_UNITS))
    assert load_report(data).text == body


def test_report_without_document_unit_surfaces_units_incomplete(
    tmp_path: Path,
) -> None:
    data = _write(
        tmp_path,
        "notes.md",
        "text",
        _manifest("report", _units(("intensity", "1"))),
    )
    with pytest.raises(MetadataRejectedError) as caught:
        _ = load_report(data)
    assert [issue.code for issue in caught.value.issues] == ["units_incomplete"]


def test_report_with_undecodable_bytes_is_refused(tmp_path: Path) -> None:
    data = tmp_path / "notes.md"
    _ = data.write_bytes(b"\xff\xfe broken")
    _ = (tmp_path / "notes.md.manifest.toml").write_text(
        _manifest("report", REPORT_UNITS), encoding="utf-8"
    )
    with pytest.raises(MalformedDataError) as caught:
        _ = load_report(data)
    assert "not valid UTF-8" in caught.value.detail


# --------------------------------------------------------------------------
# composition and the analyze_probe round trip
# --------------------------------------------------------------------------


def test_load_probe_without_any_file_is_refused() -> None:
    with pytest.raises(ValueError, match="at least one"):
        _ = load_probe()


def test_load_probe_composes_every_supplied_modality(tmp_path: Path) -> None:
    probe = load_probe(
        spectrum=_spectrum_file(tmp_path),
        table=_table_file(tmp_path),
        image=_image_file(tmp_path),
        report=_write(
            tmp_path, "notes.md", "Observed.", _manifest("report", REPORT_UNITS)
        ),
    )
    assert probe.spectrum is not None
    assert probe.table is not None
    assert probe.image is not None
    assert probe.report is not None


def test_correctly_manifested_spectrum_analyses_as_valid(tmp_path: Path) -> None:
    analysis = analyze_probe(load_probe(spectrum=_spectrum_file(tmp_path)))
    assert analysis.status is OutcomeStatus.VALID
    assert analysis.issues == ()
    assert analysis.spectrum is not None
    assert analysis.spectrum.status is OutcomeStatus.VALID


def test_manifest_without_lineage_analyses_as_insufficient_data(
    tmp_path: Path,
) -> None:
    probe = load_probe(
        spectrum=_spectrum_file(tmp_path, lineage=""),
        policy=MetadataPolicy.DEFER,
    )
    analysis = analyze_probe(probe)
    assert analysis.status is OutcomeStatus.INSUFFICIENT_DATA
    assert [issue.code for issue in analysis.issues] == ["lineage_required"]


def test_missing_intensity_reaches_analysis_as_missing_not_imputed(
    tmp_path: Path,
) -> None:
    body = "wavelength,intensity\n400,1.0\n410,\n420,2.0\n430,7.0\n"
    analysis = analyze_probe(load_probe(spectrum=_spectrum_file(tmp_path, body)))
    assert analysis.status is OutcomeStatus.INSUFFICIENT_DATA
    assert "spectrum_missing_values" in [issue.code for issue in analysis.issues]
    assert analysis.spectrum is not None
    assert analysis.spectrum.intensities == (1.0, None, 2.0, 7.0)
    assert analysis.spectrum.missing_fraction == 0.25


def test_strict_policy_is_the_default_for_every_loader(tmp_path: Path) -> None:
    with pytest.raises(MetadataRejectedError):
        _ = load_probe(spectrum=_spectrum_file(tmp_path, lineage=""))


def test_defer_policy_never_invents_metadata(tmp_path: Path) -> None:
    loaded = load_spectrum(
        _spectrum_file(tmp_path, lineage="", calibration=""),
        MetadataPolicy.DEFER,
    )
    assert loaded.metadata.lineage_version_ids == ()
    assert loaded.metadata.calibration is None


def test_every_refusal_derives_from_the_loader_base_error(tmp_path: Path) -> None:
    data = tmp_path / "spectrum.csv"
    _ = data.write_text(SPECTRUM_BODY, encoding="utf-8")
    with pytest.raises(LoaderError) as caught:
        _ = load_spectrum(data)
    assert caught.value.path.name == "spectrum.csv.manifest.toml"
