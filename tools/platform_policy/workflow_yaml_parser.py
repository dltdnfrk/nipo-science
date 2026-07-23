"""Strict parser for the small YAML subset accepted by CI workflows."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Never

from .static_check_types import StaticCheckCode, StaticCheckError

if TYPE_CHECKING:
    from pathlib import Path

MIN_QUOTED_SCALAR_LENGTH = 2
KEY_PATTERN: Final = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]*$")
UNSUPPORTED_NODE_PATTERN: Final = re.compile(
    r"(?:^|[\s\[{,])(?:&[A-Za-z0-9_-]+|\*[A-Za-z0-9_-]+|![^\s\]},]*)"
)


@dataclass(frozen=True, slots=True)
class YamlScalar:
    """One scalar value in the supported workflow subset."""

    value: str


@dataclass(frozen=True, slots=True)
class YamlMapping:
    """One duplicate-free mapping in the supported workflow subset."""

    values: tuple[tuple[str, YamlValue], ...]


@dataclass(frozen=True, slots=True)
class YamlSequence:
    """One sequence in the supported workflow subset."""

    values: tuple[YamlValue, ...]


type YamlValue = YamlScalar | YamlMapping | YamlSequence


@dataclass(frozen=True, slots=True)
class _WorkflowLine:
    indent: int
    text: str
    block: str | None


@dataclass(frozen=True, slots=True)
class _WorkflowParser:
    lines: tuple[_WorkflowLine, ...]
    path: Path

    def parse(self) -> YamlMapping:
        if not self.lines or self.lines[0].indent != 0:
            _fail(self.path)
        node, index = self._node(0, 0)
        if index != len(self.lines) or not isinstance(node, YamlMapping):
            _fail(self.path)
        return node

    def _node(self, index: int, indent: int) -> tuple[YamlValue, int]:
        if self.lines[index].text.startswith("- "):
            return self._sequence(index, indent)
        return self._mapping(index, indent)

    def _mapping(self, index: int, indent: int) -> tuple[YamlMapping, int]:
        values: list[tuple[str, YamlValue]] = []
        while index < len(self.lines) and self.lines[index].indent >= indent:
            line = self.lines[index]
            if line.indent != indent or line.text.startswith("- "):
                break
            key, raw = _entry(line.text, self.path)
            index += 1
            if line.block is not None:
                value: YamlValue = YamlScalar(line.block)
            elif raw:
                value = YamlScalar(_plain_scalar(raw, self.path))
            elif index < len(self.lines) and self.lines[index].indent > indent:
                value, index = self._node(index, self.lines[index].indent)
            else:
                value = YamlScalar("")
            if any(existing == key for existing, _ in values):
                _fail(self.path)
            values.append((key, value))
        return YamlMapping(tuple(values)), index

    def _sequence(self, index: int, indent: int) -> tuple[YamlSequence, int]:
        values: list[YamlValue] = []
        while index < len(self.lines):
            line = self.lines[index]
            if line.indent != indent or not line.text.startswith("- "):
                break
            remainder = line.text[2:].strip()
            index += 1
            if ":" not in remainder:
                values.append(YamlScalar(_plain_scalar(remainder, self.path)))
                continue
            key, raw = _entry(remainder, self.path)
            item_indent = indent + 2
            if line.block is not None:
                first: YamlValue = YamlScalar(line.block)
            elif raw:
                first = YamlScalar(_plain_scalar(raw, self.path))
            elif index < len(self.lines) and self.lines[index].indent > item_indent:
                first, index = self._node(index, self.lines[index].indent)
            else:
                first = YamlScalar("")
            fields: list[tuple[str, YamlValue]] = [(key, first)]
            if index < len(self.lines) and self.lines[index].indent == item_indent:
                tail, index = self._node(index, item_indent)
                if not isinstance(tail, YamlMapping):
                    _fail(self.path)
                fields.extend(tail.values)
            if len({name for name, _ in fields}) != len(fields):
                _fail(self.path)
            values.append(YamlMapping(tuple(fields)))
        return YamlSequence(tuple(values)), index


def parse_yaml_mapping(content: str, path: Path) -> YamlMapping:
    """Parse workflow text into one duplicate-free mapping."""
    return _WorkflowParser(_tokenize(content, path), path).parse()


def unquote_scalar(value: str) -> str:
    """Remove one matching quote pair from a strict scalar."""
    if (
        len(value) >= MIN_QUOTED_SCALAR_LENGTH
        and value[0] == value[-1]
        and value[0] in {'"', "'"}
    ):
        return value[1:-1]
    return value


def _tokenize(content: str, path: Path) -> tuple[_WorkflowLine, ...]:
    raw_lines = content.splitlines()
    tokens: list[_WorkflowLine] = []
    index = 0
    while index < len(raw_lines):
        raw = raw_lines[index]
        stripped = raw.lstrip(" ")
        if stripped.startswith("\t"):
            _fail(path)
        if not stripped or stripped.startswith("#"):
            index += 1
            continue
        indent = len(raw) - len(stripped)
        text = stripped.rstrip()
        marker = next((item for item in (": |", ": |-") if text.endswith(item)), None)
        if marker is None:
            tokens.append(_WorkflowLine(indent, text, None))
            index += 1
            continue
        index += 1
        block_lines: list[str] = []
        while index < len(raw_lines):
            candidate = raw_lines[index]
            candidate_indent = len(candidate) - len(candidate.lstrip(" "))
            if candidate.strip() and candidate_indent <= indent:
                break
            block_lines.append(candidate)
            index += 1
        content_indents = [
            len(line) - len(line.lstrip(" ")) for line in block_lines if line.strip()
        ]
        block_indent = min(content_indents, default=indent + 2)
        block = "\n".join(
            line[block_indent:] if line.strip() else "" for line in block_lines
        )
        tokens.append(_WorkflowLine(indent, text[: -len(marker)] + ":", block))
    return tuple(tokens)


def _entry(text: str, path: Path) -> tuple[str, str]:
    key, separator, value = text.partition(":")
    if not separator or KEY_PATTERN.fullmatch(key) is None:
        _fail(path)
    return key, value.strip()


def _plain_scalar(value: str, path: Path) -> str:
    if "#" in value or "\\" in value or UNSUPPORTED_NODE_PATTERN.search(value):
        _fail(path)
    return unquote_scalar(value)


def _fail(path: Path) -> Never:
    raise StaticCheckError(StaticCheckCode.MISSING_EXTERNAL_CI_AUTHORITY, path)
