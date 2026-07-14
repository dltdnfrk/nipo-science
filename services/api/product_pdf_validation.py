"""Fail-closed structural validation for passive PDF Artifact previews."""

from __future__ import annotations

import io
from typing import TYPE_CHECKING, Final, Never, Protocol, assert_never, cast

from pypdf import PdfReader
from pypdf.errors import PdfReadError
from pypdf.generic import (
    ArrayObject,
    DictionaryObject,
    IndirectObject,
    NameObject,
    PdfObject,
)

from services.api.product_artifact_types import UnsupportedArtifactMediaError

if TYPE_CHECKING:
    from collections.abc import Iterable

_ACTIVE_NAMES: Final = frozenset(
    {
        "/a",
        "/aa",
        "/acroform",
        "/annots",
        "/collection",
        "/ef",
        "/embeddedfile",
        "/filespec",
        "/goto",
        "/gotor",
        "/hide",
        "/importdata",
        "/javascript",
        "/js",
        "/launch",
        "/movie",
        "/named",
        "/names",
        "/objstm",
        "/openaction",
        "/rendition",
        "/resetform",
        "/richmedia",
        "/setocgstate",
        "/sound",
        "/submitform",
        "/thread",
        "/trans",
        "/uri",
        "/xfa",
    }
)
_MAX_OBJECTS: Final = 4096


class _TraversalValue(Protocol):
    def hash_bin(self) -> int: ...


def validate_passive_pdf(content: bytes, media_type: str) -> None:
    """Reject malformed, encrypted, compressed-object, or interactive PDFs."""
    if (
        not content.startswith(b"%PDF-")
        or b"startxref" not in content[-256:]
        or not content.rstrip().endswith(b"%%EOF")
    ):
        raise UnsupportedArtifactMediaError(media_type)
    try:
        reader = PdfReader(io.BytesIO(content), strict=True)
        remaining = [_MAX_OBJECTS]
        if (
            reader.is_encrypted
            or not reader.pages
            or _contains_active_name(reader.trailer, set(), remaining)
        ):
            raise UnsupportedArtifactMediaError(media_type)
    except (
        PdfReadError,
        OSError,
        ValueError,
        TypeError,
        KeyError,
        RecursionError,
    ) as error:
        raise UnsupportedArtifactMediaError(media_type) from error


def minimal_passive_pdf() -> bytes:
    """Build a deterministic one-page PDF with a valid cross-reference table."""
    parts = [b"%PDF-1.4\n%\xe2\xe3\xcf\xd3\n"]
    objects = (
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n",
        b"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n",
        b"3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 72 72] "
        b"/Contents 4 0 R >>\nendobj\n",
        b"4 0 obj\n<< /Length 0 >>\nstream\n\nendstream\nendobj\n",
    )
    offsets: list[int] = []
    for item in objects:
        offsets.append(sum(len(part) for part in parts))
        parts.append(item)
    xref_offset = sum(len(part) for part in parts)
    rows = [b"xref\n0 5\n0000000000 65535 f \n"]
    rows.extend(f"{offset:010d} 00000 n \n".encode() for offset in offsets)
    parts.extend(rows)
    parts.append(
        b"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n"
        + str(xref_offset).encode()
        + b"\n%%EOF\n"
    )
    return b"".join(parts)


def _contains_active_name(
    value: _TraversalValue | None,
    seen: set[tuple[int, int]],
    remaining: list[int],
) -> bool:
    remaining[0] -= 1
    if remaining[0] < 0:
        return True
    result = False
    match value:
        case IndirectObject():
            identity = (value.idnum, value.generation)
            if identity not in seen:
                seen.add(identity)
                result = _contains_active_name(value.get_object(), seen, remaining)
        case NameObject():
            result = str(value).casefold() in _ACTIVE_NAMES
        case DictionaryObject():
            entries = cast(
                "Iterable[tuple[_TraversalValue, _TraversalValue]]",
                value.items(),
            )
            result = any(
                _contains_active_name(key, seen, remaining)
                or _contains_active_name(item, seen, remaining)
                for key, item in entries
            )
        case ArrayObject():
            items = cast("Iterable[_TraversalValue]", value)
            result = any(
                _contains_active_name(item, seen, remaining) for item in items
            )
        case PdfObject() | None:
            pass
        case _ as unreachable:
            assert_never(cast("Never", unreachable))
    return result
