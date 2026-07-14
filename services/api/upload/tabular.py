"""Strict full-document CSV and TSV validation with bounded previews."""

from codecs import getincrementaldecoder
from enum import StrEnum
from typing import Final, assert_never, final

from .models import TabularPreview, UploadError, UploadErrorCode

MAX_PREVIEW_ROWS: Final = 20
MAX_PREVIEW_COLUMNS: Final = 50
MAX_CELL_CHARACTERS: Final = 256
DECODE_CHUNK_BYTES: Final = 64 * 1024


class _ParserState(StrEnum):
    FIELD_START = "field_start"
    UNQUOTED = "unquoted"
    QUOTED = "quoted"
    AFTER_QUOTE = "after_quote"


@final
class _TabularParser:
    __slots__ = (
        "_cell",
        "_column_number",
        "_delimiter",
        "_filename",
        "_record_open",
        "_row",
        "_row_number",
        "_rows",
        "_skip_lf",
        "_state",
        "_truncated",
    )

    def __init__(self, delimiter: str, filename: str) -> None:
        self._delimiter = delimiter
        self._filename = filename
        self._state = _ParserState.FIELD_START
        self._rows: list[tuple[str, ...]] = []
        self._row: list[str] = []
        self._cell: list[str] = []
        self._row_number = 0
        self._column_number = 0
        self._record_open = False
        self._skip_lf = False
        self._truncated = False

    def parse(self, payload: bytes) -> TabularPreview:
        decoder = getincrementaldecoder("utf-8-sig")()
        try:
            for offset in range(0, len(payload), DECODE_CHUNK_BYTES):
                self._consume_text(
                    decoder.decode(payload[offset : offset + DECODE_CHUNK_BYTES])
                )
            self._consume_text(decoder.decode(b"", final=True))
        except UnicodeDecodeError:
            raise self._invalid() from None
        self._finish_document()
        if not self._rows:
            raise self._invalid()
        return TabularPreview(rows=tuple(self._rows), truncated=self._truncated)

    def _consume_text(self, text: str) -> None:
        for character in text:
            if self._skip_lf:
                self._skip_lf = False
                if character == "\n":
                    continue
            match self._state:
                case _ParserState.FIELD_START:
                    self._consume_field_start(character)
                case _ParserState.UNQUOTED:
                    self._consume_unquoted(character)
                case _ParserState.QUOTED:
                    self._consume_quoted(character)
                case _ParserState.AFTER_QUOTE:
                    self._consume_after_quote(character)
                case _:
                    assert_never(self._state)

    def _consume_field_start(self, character: str) -> None:
        self._record_open = True
        if character == '"':
            self._state = _ParserState.QUOTED
        elif character == self._delimiter:
            self._finish_cell()
        elif character in "\r\n":
            self._finish_row(character)
        else:
            self._state = _ParserState.UNQUOTED
            self._append(character)

    def _consume_unquoted(self, character: str) -> None:
        if character == '"':
            raise self._invalid()
        if character == self._delimiter:
            self._finish_cell()
        elif character in "\r\n":
            self._finish_row(character)
        else:
            self._append(character)

    def _consume_quoted(self, character: str) -> None:
        if character == '"':
            self._state = _ParserState.AFTER_QUOTE
        else:
            self._append(character)

    def _consume_after_quote(self, character: str) -> None:
        if character == '"':
            self._state = _ParserState.QUOTED
            self._append(character)
        elif character == self._delimiter:
            self._finish_cell()
        elif character in "\r\n":
            self._finish_row(character)
        else:
            raise self._invalid()

    def _append(self, character: str) -> None:
        self._record_open = True
        if (
            self._row_number >= MAX_PREVIEW_ROWS
            or self._column_number >= MAX_PREVIEW_COLUMNS
        ):
            self._truncated = True
            return
        if len(self._cell) < MAX_CELL_CHARACTERS:
            self._cell.append(character)
        else:
            self._truncated = True

    def _finish_cell(self) -> None:
        self._record_open = True
        if self._row_number >= MAX_PREVIEW_ROWS:
            self._truncated = True
        elif self._column_number < MAX_PREVIEW_COLUMNS:
            self._row.append("".join(self._cell))
        else:
            self._truncated = True
        self._column_number += 1
        self._cell = []
        self._state = _ParserState.FIELD_START

    def _finish_row(self, terminator: str | None = None) -> None:
        self._finish_cell()
        if self._row_number < MAX_PREVIEW_ROWS:
            self._rows.append(tuple(self._row))
        else:
            self._truncated = True
        self._row_number += 1
        self._column_number = 0
        self._row = []
        self._record_open = False
        self._skip_lf = terminator == "\r"

    def _finish_document(self) -> None:
        if self._state is _ParserState.QUOTED:
            raise self._invalid()
        if self._record_open:
            self._finish_row()

    def _invalid(self) -> UploadError:
        return UploadError(UploadErrorCode.STRUCTURE_INVALID, self._filename)


def parse_tabular_preview(
    payload: bytes,
    delimiter: str,
    filename: str,
) -> TabularPreview:
    """Validate one complete RFC-style table while retaining bounded cells."""
    return _TabularParser(delimiter, filename).parse(payload)
