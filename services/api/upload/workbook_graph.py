"""Closed relationship-graph validation for safe XLSX workbook parts."""

import zipfile
from pathlib import PurePosixPath
from typing import Final

from .models import UploadError, UploadErrorCode
from .workbook_opc import read_relationships, read_xml
from .workbook_rules import (
    DOCUMENT_REL_NS,
    OFFICE_DOCUMENT_REL,
    OPTIONAL_PARTS,
    ROOT_RELATION_TARGETS,
    SHEET_NS,
    WORKBOOK_RELATION_TARGETS,
    WORKSHEET_REL,
)

MAX_SHEET_NAME_CHARACTERS: Final = 128


def validate_workbook_graph(
    workbook: zipfile.ZipFile,
    filename: str,
) -> tuple[str, ...]:
    """Return sheet names after validating the closed workbook graph."""
    members = set(workbook.namelist())
    _validate_root_graph(workbook, members, filename)
    worksheets = _validate_workbook_relationships(workbook, members, filename)
    sheet_names = _validate_sheet_graph(workbook, worksheets, filename)
    _validate_optional_roots(workbook, members, filename)
    return sheet_names


def _validate_root_graph(
    workbook: zipfile.ZipFile,
    members: set[str],
    filename: str,
) -> None:
    relationships = read_relationships(
        workbook,
        "_rels/.rels",
        frozenset(ROOT_RELATION_TARGETS),
        filename,
    )
    resolved = tuple(
        (relation_id, relation_type, target.removeprefix("/"))
        for relation_id, relation_type, target in relationships
    )
    relation_types = [relation_type for _, relation_type, _ in resolved]
    targets = {target for _, _, target in resolved}
    packaged = {
        name
        for name in members
        if name in OPTIONAL_PARTS and name.startswith("docProps/")
    }
    if (
        len(set(relation_types)) != len(relation_types)
        or relation_types.count(OFFICE_DOCUMENT_REL) != 1
        or targets != {"xl/workbook.xml", *packaged}
        or any(
            ROOT_RELATION_TARGETS[relation_type] != target
            for _, relation_type, target in resolved
        )
    ):
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)


def _validate_workbook_relationships(
    workbook: zipfile.ZipFile,
    members: set[str],
    filename: str,
) -> dict[str, str]:
    relationships = read_relationships(
        workbook,
        "xl/_rels/workbook.xml.rels",
        frozenset(WORKBOOK_RELATION_TARGETS) | {WORKSHEET_REL},
        filename,
    )
    worksheets: dict[str, str] = {}
    singleton_types: set[str] = set()
    resolved_targets: set[str] = set()
    for relation_id, relation_type, target in relationships:
        resolved = _resolve_workbook_target(target, filename)
        if relation_type == WORKSHEET_REL:
            if not resolved.startswith("xl/worksheets/"):
                raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
            worksheets[relation_id] = resolved
        elif (
            relation_type in singleton_types
            or WORKBOOK_RELATION_TARGETS[relation_type] != resolved
        ):
            raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
        else:
            singleton_types.add(relation_type)
        if resolved in resolved_targets:
            raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
        resolved_targets.add(resolved)
    packaged = {
        name
        for name in members
        if name.startswith("xl/")
        and name not in {"xl/workbook.xml", "xl/_rels/workbook.xml.rels"}
    }
    if packaged != resolved_targets:
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
    return worksheets


def _validate_sheet_graph(
    workbook: zipfile.ZipFile,
    worksheets: dict[str, str],
    filename: str,
) -> tuple[str, ...]:
    root = read_xml(workbook, "xl/workbook.xml", filename)
    sheets = root.find(f"{{{SHEET_NS}}}sheets")
    if root.tag != f"{{{SHEET_NS}}}workbook" or sheets is None:
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    names: list[str] = []
    relation_ids: list[str] = []
    sheet_ids: list[str] = []
    for sheet in sheets:
        name = sheet.attrib.get("name", "")
        relation_id = sheet.attrib.get(f"{{{DOCUMENT_REL_NS}}}id", "")
        sheet_id = sheet.attrib.get("sheetId", "")
        target = worksheets.get(relation_id)
        if target is None or not _sheet_is_valid(sheet.tag, name, sheet_id):
            raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
        if read_xml(workbook, target, filename).tag != f"{{{SHEET_NS}}}worksheet":
            raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
        names.append(name)
        relation_ids.append(relation_id)
        sheet_ids.append(sheet_id)
    if (
        len(set(relation_ids)) != len(relation_ids)
        or set(relation_ids) != set(worksheets)
        or len(set(sheet_ids)) != len(sheet_ids)
        or len({name.casefold() for name in names}) != len(names)
    ):
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
    return tuple(names)


def _sheet_is_valid(
    tag: str,
    name: str,
    sheet_id: str,
) -> bool:
    return (
        tag == f"{{{SHEET_NS}}}sheet"
        and bool(name)
        and len(name) <= MAX_SHEET_NAME_CHARACTERS
        and sheet_id.isdigit()
    )


def _validate_optional_roots(
    workbook: zipfile.ZipFile,
    members: set[str],
    filename: str,
) -> None:
    for member_name in members & OPTIONAL_PARTS.keys():
        if (
            read_xml(workbook, member_name, filename).tag
            != OPTIONAL_PARTS[member_name][1]
        ):
            raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)


def _resolve_workbook_target(target: str, filename: str) -> str:
    path = (
        PurePosixPath(target.removeprefix("/"))
        if target.startswith("/")
        else PurePosixPath("xl") / target
    )
    if path.is_absolute() or ".." in path.parts:
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
    normalized = path.as_posix()
    if not normalized.startswith("xl/") or not normalized.endswith(".xml"):
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
    return normalized
