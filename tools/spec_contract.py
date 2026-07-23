"""Typed parsing primitives and invariant constants for SPEC verification."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import TYPE_CHECKING, Final, Protocol, override

if TYPE_CHECKING:
    from pathlib import Path

type JsonValue = (
    str | int | float | bool | None | list["JsonValue"] | dict[str, "JsonValue"]
)

P0_IDS: Final = (*tuple(f"F{number:02d}" for number in range(1, 12)), "F13")
AC_IDS: Final = (
    "AC-F01",
    "AC-F01-B",
    "AC-F01-C",
    "AC-F01-D",
    "AC-F01-E",
    "AC-F02",
    "AC-F03",
    "AC-F04",
    "AC-F04-B",
    "AC-F05",
    "AC-F05-B",
    "AC-F06",
    "AC-F06-B",
    "AC-F07",
    "AC-F08",
    "AC-F09",
    "AC-F10",
    "AC-F11",
    "AC-F11-B",
    "AC-F13",
    "AC-F13-B",
    "AC-F13-C",
    "AC-F13-D",
    "AC-PROVIDER-AUTHORITY",
    "AC-PROVIDER-RUN-BINDING",
    "AC-PROVIDER-MIGRATION",
    "AC-SAFE",
    "AC-TENANT",
    "AC-COMPLIANCE",
    "AC-DATA",
    "AC-NFR",
)
SEC_IDS: Final = tuple(f"SEC{number:02d}" for number in range(1, 17))
NFR_IDS: Final = tuple(f"NFR{number:02d}" for number in range(1, 11))
GS_IDS: Final = tuple(f"GS{number:02d}" for number in range(1, 11))
RV_IDS: Final = tuple(f"RV{number:02d}" for number in range(1, 6))
EXPECTED_IDS: Final = frozenset(P0_IDS + AC_IDS + SEC_IDS + NFR_IDS + GS_IDS + RV_IDS)
SKILL_IDS: Final = ("literature-review", "source-attribution", "probe-diagnostic")
DRY_LAB_CHAIN: Final = (
    "scientific_input",
    "research_intent",
    "immutable_action_plan",
    "isolated_python",
    "csv",
    "png",
    "markdown",
    "ledger",
    "provenance",
    "persisted_review",
    "export",
)
STACK: Final = {
    "node": "24.17.0",
    "pnpm": "11.12.0",
    "python": "3.12.13",
    "uv": "0.11.28",
    "postgresql": "18.4",
}


class JsonDecoder(Protocol):
    """Decode JSON text into the recursive manifest value type."""

    def __call__(self, value: str, /) -> JsonValue:
        """Decode one JSON document."""
        ...


class ContractParseError(Exception):
    """Report a typed manifest boundary parse failure."""

    location: str
    expected: str

    def __init__(self, location: str, expected: str) -> None:
        """Initialize the failed location and expected value shape."""
        super().__init__(location, expected)
        self.location = location
        self.expected = expected

    @override
    def __str__(self) -> str:
        return f"{self.location}: expected {self.expected}"


class VerificationError(Exception):
    """Report one or more normative invariant failures."""

    errors: tuple[str, ...]

    def __init__(self, errors: tuple[str, ...]) -> None:
        """Initialize the ordered invariant failure messages."""
        super().__init__(*errors)
        self.errors = errors

    @override
    def __str__(self) -> str:
        return "; ".join(self.errors)


@dataclass(frozen=True, slots=True)
class VerificationReport:
    """Summarize a successfully verified normative contract."""

    spec_version: str
    requirement_count: int
    p0_count: int


def add_error(condition: bool, label: str, errors: list[str]) -> None:
    """Append a named invariant failure when its condition is false."""
    if not condition:
        errors.append(label)


def as_map(value: JsonValue, location: str) -> dict[str, JsonValue]:
    """Parse a JSON value as a mapping at the named location."""
    if not isinstance(value, dict):
        raise ContractParseError(location, "mapping")
    return value


def child_map(parent: dict[str, JsonValue], key: str) -> dict[str, JsonValue]:
    """Parse a named child as a mapping."""
    return as_map(parent.get(key), key)


def child_str(parent: dict[str, JsonValue], key: str) -> str:
    """Parse a named child as a string."""
    value = parent.get(key)
    if not isinstance(value, str):
        raise ContractParseError(key, "string")
    return value


def child_bool(parent: dict[str, JsonValue], key: str) -> bool:
    """Parse a named child as a boolean."""
    value = parent.get(key)
    if not isinstance(value, bool):
        raise ContractParseError(key, "boolean")
    return value


def child_strs(parent: dict[str, JsonValue], key: str) -> tuple[str, ...]:
    """Parse a named child as an immutable string sequence."""
    value = parent.get(key)
    if not isinstance(value, list):
        raise ContractParseError(key, "string list")
    items: list[str] = []
    for item in value:
        if not isinstance(item, str):
            raise ContractParseError(key, "string list")
        items.append(item)
    return tuple(items)


def decode_json(decoder: JsonDecoder, text: str) -> JsonValue:
    """Apply a typed decoder to untrusted JSON text."""
    return decoder(text)


def load_root(path: Path) -> dict[str, JsonValue]:
    """Load the JSON-compatible YAML manifest as a root mapping."""
    text = path.read_text(encoding="utf-8")
    return as_map(decode_json(json.loads, text), "root")


def frontmatter_version(path: Path) -> str:
    """Parse and return the normative Markdown frontmatter version."""
    lines = path.read_text(encoding="utf-8").splitlines()
    if not lines or lines[0] != "---":
        raise ContractParseError(str(path), "normative frontmatter")
    try:
        end = lines.index("---", 1)
    except ValueError as error:
        raise ContractParseError(str(path), "closed normative frontmatter") from error
    if any(": " not in line for line in lines[1:end]):
        raise ContractParseError(str(path), "key/value frontmatter")
    fields = dict(line.split(": ", 1) for line in lines[1:end])
    if fields.get("status") != "normative":
        raise ContractParseError(str(path), "normative status")
    manifest_path = "docs/requirements/requirements.yaml"
    if fields.get("requirements_manifest") != manifest_path:
        raise ContractParseError(str(path), "canonical requirements manifest path")
    return fields.get("version", "").strip('"')
