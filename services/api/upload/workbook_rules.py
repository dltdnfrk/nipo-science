"""Safe XLSX part, relationship, content-type, and root-element rules."""

from typing import Final

CONTENT_TYPES_NS: Final = "http://schemas.openxmlformats.org/package/2006/content-types"
PACKAGE_REL_NS: Final = "http://schemas.openxmlformats.org/package/2006/relationships"
SHEET_NS: Final = "http://schemas.openxmlformats.org/spreadsheetml/2006/main"
DOCUMENT_REL_NS: Final = (
    "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
)
CORE_REL_NS: Final = (
    "http://schemas.openxmlformats.org/package/2006/relationships/metadata"
)
DRAWING_NS: Final = "http://schemas.openxmlformats.org/drawingml/2006/main"
CORE_PROPERTIES_NS: Final = (
    "http://schemas.openxmlformats.org/package/2006/metadata/core-properties"
)
EXTENDED_PROPERTIES_NS: Final = (
    "http://schemas.openxmlformats.org/officeDocument/2006/extended-properties"
)
CUSTOM_PROPERTIES_NS: Final = (
    "http://schemas.openxmlformats.org/officeDocument/2006/custom-properties"
)

OFFICE_DOCUMENT_REL: Final = f"{DOCUMENT_REL_NS}/officeDocument"
WORKSHEET_REL: Final = f"{DOCUMENT_REL_NS}/worksheet"
STYLES_REL: Final = f"{DOCUMENT_REL_NS}/styles"
SHARED_STRINGS_REL: Final = f"{DOCUMENT_REL_NS}/sharedStrings"
THEME_REL: Final = f"{DOCUMENT_REL_NS}/theme"
CALC_CHAIN_REL: Final = f"{DOCUMENT_REL_NS}/calcChain"
EXTENDED_PROPERTIES_REL: Final = f"{DOCUMENT_REL_NS}/extended-properties"
CUSTOM_PROPERTIES_REL: Final = f"{DOCUMENT_REL_NS}/custom-properties"
CORE_PROPERTIES_REL: Final = f"{CORE_REL_NS}/core-properties"

WORKBOOK_CONTENT_TYPE: Final = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"
)
WORKSHEET_CONTENT_TYPE: Final = (
    "application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"
)
RELATIONSHIPS_CONTENT_TYPE: Final = (
    "application/vnd.openxmlformats-package.relationships+xml"
)
XML_CONTENT_TYPE: Final = "application/xml"

OPTIONAL_PARTS: Final[dict[str, tuple[str, str]]] = {
    "xl/styles.xml": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.styles+xml",
        f"{{{SHEET_NS}}}styleSheet",
    ),
    "xl/sharedStrings.xml": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sharedStrings+xml",
        f"{{{SHEET_NS}}}sst",
    ),
    "xl/theme/theme1.xml": (
        "application/vnd.openxmlformats-officedocument.theme+xml",
        f"{{{DRAWING_NS}}}theme",
    ),
    "xl/calcChain.xml": (
        "application/vnd.openxmlformats-officedocument.spreadsheetml.calcChain+xml",
        f"{{{SHEET_NS}}}calcChain",
    ),
    "docProps/core.xml": (
        "application/vnd.openxmlformats-package.core-properties+xml",
        f"{{{CORE_PROPERTIES_NS}}}coreProperties",
    ),
    "docProps/app.xml": (
        "application/vnd.openxmlformats-officedocument.extended-properties+xml",
        f"{{{EXTENDED_PROPERTIES_NS}}}Properties",
    ),
    "docProps/custom.xml": (
        "application/vnd.openxmlformats-officedocument.custom-properties+xml",
        f"{{{CUSTOM_PROPERTIES_NS}}}Properties",
    ),
}

ROOT_RELATION_TARGETS: Final[dict[str, str]] = {
    OFFICE_DOCUMENT_REL: "xl/workbook.xml",
    CORE_PROPERTIES_REL: "docProps/core.xml",
    EXTENDED_PROPERTIES_REL: "docProps/app.xml",
    CUSTOM_PROPERTIES_REL: "docProps/custom.xml",
}

WORKBOOK_RELATION_TARGETS: Final[dict[str, str]] = {
    STYLES_REL: "xl/styles.xml",
    SHARED_STRINGS_REL: "xl/sharedStrings.xml",
    THEME_REL: "xl/theme/theme1.xml",
    CALC_CHAIN_REL: "xl/calcChain.xml",
}
