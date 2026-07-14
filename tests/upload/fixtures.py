import io
import struct
import zipfile
import zlib
from uuid import UUID

from PIL import Image
from pypdf import PdfWriter
from services.api.upload import UploadScope

TEST_SCOPE = UploadScope(
    org_id=UUID("018f47a0-7b9c-7a01-8def-0123456789ab"),
    project_id=UUID("018f47a0-7b9c-7a03-8def-0123456789ab"),
    requester_id=UUID("018f47a0-7b9c-7a02-8def-0123456789ab"),
)
OTHER_SCOPE = UploadScope(
    org_id=UUID("018f47a0-7b9c-7aff-8def-0123456789ab"),
    project_id=UUID("018f47a0-7b9c-7afe-8def-0123456789ab"),
    requester_id=UUID("018f47a0-7b9c-7afd-8def-0123456789ab"),
)


def pdf(page_count: int = 1) -> bytes:
    output = io.BytesIO()
    writer = PdfWriter()
    for _ in range(page_count):
        _ = writer.add_blank_page(width=72, height=72)
    _ = writer.write(output)
    return output.getvalue()


def png(width: int = 2, height: int = 3) -> bytes:
    if width * height <= 1_000_000:
        return _image("PNG", width, height)

    def chunk(kind: bytes, data: bytes) -> bytes:
        checksum = zlib.crc32(kind + data).to_bytes(4, "big")
        return len(data).to_bytes(4, "big") + kind + data + checksum

    header = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    return b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", header) + chunk(b"IEND", b"")


def jpeg(width: int = 2, height: int = 3) -> bytes:
    return _image("JPEG", width, height)


def tiff(width: int = 2, height: int = 3) -> bytes:
    return _image("TIFF", width, height)


def multi_frame_tiff() -> bytes:
    output = io.BytesIO()
    first = Image.new("RGB", (8, 8), color=(12, 34, 56))
    second = Image.new("RGB", (8, 8), color=(65, 43, 21))
    first.save(output, format="TIFF", save_all=True, append_images=(second,))
    return output.getvalue()


def _image(format_: str, width: int, height: int) -> bytes:
    output = io.BytesIO()
    image = Image.new("RGB", (width, height), color=(12, 34, 56))
    image.save(output, format=format_)
    return output.getvalue()


def xlsx(
    *,
    member_name: str = "xl/worksheets/sheet1.xml",
    symlink: bool = False,
    external_relationship: bool = False,
    escaped_external_relationship: bool = False,
    relationship_target: str = "worksheets/sheet1.xml",
    utf16_relationship: bool = False,
    extra_member: str | None = None,
    relationship_type_namespace: str | None = None,
    standard_components: bool = False,
    worksheet_padding: int = 0,
    root_absolute_targets: bool = False,
) -> bytes:
    content_types_ns = "http://schemas.openxmlformats.org/package/2006/content-types"
    package_rels_ns = "http://schemas.openxmlformats.org/package/2006/relationships"
    sheet_ns = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
    document_rels_ns = (
        "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    )
    relation_ns = relationship_type_namespace or document_rels_ns
    root_prefix = "/" if root_absolute_targets else ""
    package_metadata_ns = (
        "http://schemas.openxmlformats.org/package/2006/relationships/metadata"
    )
    optional_content_types = (
        '<Override PartName="/xl/styles.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.spreadsheetml.styles+xml"/>'
        '<Override PartName="/xl/sharedStrings.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.spreadsheetml.sharedStrings+xml"/>'
        '<Override PartName="/xl/theme/theme1.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.theme+xml"/>'
        '<Override PartName="/docProps/core.xml" ContentType="application/vnd.'
        'openxmlformats-package.core-properties+xml"/>'
        '<Override PartName="/docProps/app.xml" ContentType="application/vnd.'
        'openxmlformats-officedocument.extended-properties+xml"/>'
        if standard_components
        else ""
    )
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as workbook:
        workbook.writestr(
            "[Content_Types].xml",
            f'<Types xmlns="{content_types_ns}"><Default Extension="rels" '
            f'ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml" '
            'ContentType="application/vnd.openxmlformats-officedocument.'
            'spreadsheetml.sheet.main+xml"/><Override '
            f'PartName="/{member_name}" ContentType="application/vnd.'
            'openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            f"{optional_content_types}</Types>",
        )
        root_properties = (
            f'<Relationship Id="rId2" Type="{package_metadata_ns}/core-properties" '
            f'Target="{root_prefix}docProps/core.xml"/><Relationship Id="rId3" '
            f'Type="{document_rels_ns}/extended-properties" '
            f'Target="{root_prefix}docProps/app.xml"/>'
            if standard_components
            else ""
        )
        workbook.writestr(
            "_rels/.rels",
            f'<Relationships xmlns="{package_rels_ns}"><Relationship Id="rId1" '
            f'Type="{relation_ns}/officeDocument" '
            f'Target="{root_prefix}xl/workbook.xml"/>{root_properties}</Relationships>',
        )
        optional_relationships = (
            f'<Relationship Id="rId2" Type="{relation_ns}/styles" '
            'Target="styles.xml"/><Relationship Id="rId3" '
            f'Type="{relation_ns}/sharedStrings" Target="sharedStrings.xml"/>'
            f'<Relationship Id="rId4" Type="{relation_ns}/theme" '
            'Target="theme/theme1.xml"/>'
            if standard_components
            else ""
        )
        relationships = (
            f'<Relationships xmlns="{package_rels_ns}"><Relationship Id="rId1" '
            f'Type="{relation_ns}/worksheet" Target="{relationship_target}"'
            + (
                ' TargetMode="&#x45;xternal"'
                if escaped_external_relationship
                else ' TargetMode="External"'
                if external_relationship
                else ""
            )
            + "/>"
            + optional_relationships
            + "</Relationships>"
        )
        workbook.writestr(
            "xl/_rels/workbook.xml.rels",
            relationships.encode("utf-16") if utf16_relationship else relationships,
        )
        workbook.writestr(
            "xl/workbook.xml",
            f'<workbook xmlns="{sheet_ns}" xmlns:r="{document_rels_ns}"><sheets>'
            '<sheet name="Measurements" sheetId="1" r:id="rId1"/>'
            "</sheets></workbook>",
        )
        info = zipfile.ZipInfo(member_name)
        if symlink:
            info.external_attr = 0o120777 << 16
        workbook.writestr(
            info,
            f'<worksheet xmlns="{sheet_ns}"><sheetData/>{" " * worksheet_padding}'
            "</worksheet>",
        )
        if standard_components:
            workbook.writestr("xl/styles.xml", f'<styleSheet xmlns="{sheet_ns}"/>')
            workbook.writestr(
                "xl/sharedStrings.xml", f'<sst xmlns="{sheet_ns}" count="0"/>'
            )
            workbook.writestr(
                "xl/theme/theme1.xml",
                '<a:theme xmlns:a="http://schemas.openxmlformats.org/drawingml/'
                '2006/main" name="Office"/>',
            )
            workbook.writestr(
                "docProps/core.xml",
                '<cp:coreProperties xmlns:cp="http://schemas.openxmlformats.org/'
                'package/2006/metadata/core-properties"/>',
            )
            workbook.writestr(
                "docProps/app.xml",
                '<Properties xmlns="http://schemas.openxmlformats.org/'
                'officeDocument/2006/extended-properties"/>',
            )
        if extra_member is not None:
            workbook.writestr(extra_member, "payload")
    return output.getvalue()


def corrupt_zip_member(payload: bytes, member_name: str) -> bytes:
    damaged = bytearray(payload)
    with zipfile.ZipFile(io.BytesIO(payload)) as archive:
        info = archive.getinfo(member_name)
    offset = info.header_offset
    name_size = int.from_bytes(payload[offset + 26 : offset + 28], "little")
    extra_size = int.from_bytes(payload[offset + 28 : offset + 30], "little")
    data_offset = offset + 30 + name_size + extra_size
    damaged[data_offset + max(0, info.compress_size // 2)] ^= 1
    return bytes(damaged)


def generic_zip() -> bytes:
    output = io.BytesIO()
    with zipfile.ZipFile(output, "w") as archive:
        archive.writestr("payload.txt", "archive")
    return output.getvalue()
