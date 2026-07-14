"""Strict OPC relationship and XML graph validation for XLSX uploads."""

import unicodedata
import zipfile
from pathlib import PurePosixPath
from typing import Final
from xml.etree import ElementTree as ET

from .models import UploadError, UploadErrorCode
from .workbook_rules import (
    CONTENT_TYPES_NS,
    OPTIONAL_PARTS,
    PACKAGE_REL_NS,
    RELATIONSHIPS_CONTENT_TYPE,
    ROOT_RELATION_TARGETS,
    WORKBOOK_CONTENT_TYPE,
    WORKBOOK_RELATION_TARGETS,
    WORKSHEET_CONTENT_TYPE,
    WORKSHEET_REL,
    XML_CONTENT_TYPE,
)

MAX_CONTROL_XML_BYTES: Final = 1024 * 1024
MAX_DATA_XML_BYTES: Final = 16 * 1024 * 1024
type Relationship = tuple[str, str, str]


def validate_package_controls(
    workbook: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    filename: str,
) -> None:
    """Reject unsafe content types and package relationships."""
    _validate_content_types(workbook, members, filename)
    _ = read_relationships(
        workbook,
        "_rels/.rels",
        frozenset(ROOT_RELATION_TARGETS),
        filename,
    )
    _ = read_relationships(
        workbook,
        "xl/_rels/workbook.xml.rels",
        frozenset(WORKBOOK_RELATION_TARGETS) | {WORKSHEET_REL},
        filename,
    )


def read_xml(
    workbook: zipfile.ZipFile,
    member_name: str,
    filename: str,
) -> ET.Element:
    """Parse bounded UTF-8 XML with DTD and entity declarations disabled."""
    info = workbook.getinfo(member_name)
    if info.file_size > _xml_byte_limit(member_name):
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    payload = workbook.read(info)
    try:
        text = payload.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename) from None
    upper = text.upper()
    if "<!DOCTYPE" in upper or "<!ENTITY" in upper:
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    try:
        return ET.fromstring(text)  # noqa: S314 -- DTD and entities rejected above.
    except ET.ParseError:
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename) from None


def _validate_content_types(
    workbook: zipfile.ZipFile,
    members: list[zipfile.ZipInfo],
    filename: str,
) -> None:
    root = read_xml(workbook, "[Content_Types].xml", filename)
    if root.tag != f"{{{CONTENT_TYPES_NS}}}Types":
        raise UploadError(UploadErrorCode.STRUCTURE_INVALID, filename)
    defaults = [
        (item.attrib.get("Extension", ""), item.attrib.get("ContentType", ""))
        for item in root
        if item.tag == f"{{{CONTENT_TYPES_NS}}}Default"
    ]
    overrides = [
        (item.attrib.get("PartName", ""), item.attrib.get("ContentType", ""))
        for item in root
        if item.tag == f"{{{CONTENT_TYPES_NS}}}Override"
    ]
    if (
        len(defaults) + len(overrides) != len(root)
        or len({extension for extension, _ in defaults}) != len(defaults)
        or dict(defaults)
        != {"rels": RELATIONSHIPS_CONTENT_TYPE, "xml": XML_CONTENT_TYPE}
        or len({part for part, _ in overrides}) != len(overrides)
    ):
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
    expected = {"/xl/workbook.xml": WORKBOOK_CONTENT_TYPE}
    for member in members:
        name = member.filename
        if name.startswith("xl/worksheets/"):
            expected[f"/{name}"] = WORKSHEET_CONTENT_TYPE
        elif name in OPTIONAL_PARTS:
            expected[f"/{name}"] = OPTIONAL_PARTS[name][0]
    if dict(overrides) != expected:
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)


def read_relationships(
    workbook: zipfile.ZipFile,
    member_name: str,
    allowed_types: frozenset[str],
    filename: str,
) -> tuple[Relationship, ...]:
    """Parse unique internal relationships restricted to approved exact types."""
    root = read_xml(workbook, member_name, filename)
    if root.tag != f"{{{PACKAGE_REL_NS}}}Relationships":
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
    relationships: list[Relationship] = []
    for item in root:
        relation_id = item.attrib.get("Id", "")
        relation_type = item.attrib.get("Type", "")
        target = item.attrib.get("Target", "")
        if not relation_id or not _relationship_is_safe(item, allowed_types):
            raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
        relationships.append((relation_id, relation_type, target))
    if len({relation_id for relation_id, _, _ in relationships}) != len(relationships):
        raise UploadError(UploadErrorCode.ARCHIVE_REJECTED, filename)
    return tuple(relationships)


def _relationship_is_safe(
    item: ET.Element,
    allowed_types: frozenset[str],
) -> bool:
    relation_type = item.attrib.get("Type", "")
    target = item.attrib.get("Target", "")
    normalized = unicodedata.normalize("NFKC", target)
    path = PurePosixPath(target)
    return (
        item.tag == f"{{{PACKAGE_REL_NS}}}Relationship"
        and item.attrib.get("TargetMode", "").casefold() in {"", "internal"}
        and relation_type in allowed_types
        and bool(target)
        and normalized == target
        and "%" not in target
        and "://" not in target
        and "?" not in target
        and "#" not in target
        and "\\" not in target
        and not target.startswith("//")
        and ".." not in path.parts
        and path.as_posix() == target
    )


def _xml_byte_limit(member_name: str) -> int:
    if member_name.startswith("xl/worksheets/") or member_name in {
        "xl/styles.xml",
        "xl/sharedStrings.xml",
        "xl/theme/theme1.xml",
        "xl/calcChain.xml",
    }:
        return MAX_DATA_XML_BYTES
    return MAX_CONTROL_XML_BYTES
