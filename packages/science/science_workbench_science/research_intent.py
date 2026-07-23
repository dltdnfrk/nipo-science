"""Immutable, why-first research intent for bounded scientific execution."""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from enum import StrEnum
from hashlib import sha256
from typing import Final, TypedDict, cast

_CODE_INVALID: Final = "research-intent-invalid"
_MAX_TEXT_CHARACTERS: Final = 2_000
_MAX_ITEM_CHARACTERS: Final = 500
_MAX_ITEMS: Final = 8
_SURROGATE_LO: Final = 0xD800
_SURROGATE_HI: Final = 0xE000
_RESEARCH_BOUNDARY_WHITESPACE: Final = frozenset(
    (
        *range(0x0009, 0x000E),
        *range(0x001C, 0x0021),
        0x0085,
        0x00A0,
        0x1680,
        *range(0x2000, 0x200B),
        0x2028,
        0x2029,
        0x202F,
        0x205F,
        0x3000,
        0xFEFF,
    )
)
_REQUIRED_FIELDS: Final = frozenset(
    {
        "question",
        "rationale",
        "intended_benefit",
        "success_criteria",
        "constraints",
        "stop_conditions",
        "research_mode",
        "data_origin",
    }
)
_OPTIONAL_FIELDS: Final = frozenset(
    {"synthetic_generator_ref", "synthetic_validator_ref"}
)


class ResearchIntentError(ValueError):
    """Stable rejection for an incomplete or ambiguous research intent."""

    code: str

    def __init__(self) -> None:
        """Create a non-secret validation failure."""
        super().__init__(_CODE_INVALID)
        self.code = _CODE_INVALID


class ResearchMode(StrEnum):
    """Declared authority level for one approved plan."""

    AI_FOR_SCIENCE = "ai_for_science"
    COPILOT = "copilot"
    BOUNDED_AGENTIC = "bounded_agentic"


class DataOrigin(StrEnum):
    """Origin class of data admitted to the plan."""

    OBSERVED = "observed"
    SYNTHETIC = "synthetic"
    MIXED = "mixed"


class ResearchIntentProjection(TypedDict):
    """JSON-compatible public shape of one validated research intent."""

    question: str
    rationale: str
    intended_benefit: str
    success_criteria: list[str]
    constraints: list[str]
    stop_conditions: list[str]
    research_mode: str
    data_origin: str
    synthetic_generator_ref: str | None
    synthetic_validator_ref: str | None


@dataclass(frozen=True, slots=True)
class ResearchIntent:
    """Human-owned scientific purpose and validation boundary."""

    question: str
    rationale: str
    intended_benefit: str
    success_criteria: tuple[str, ...]
    constraints: tuple[str, ...]
    stop_conditions: tuple[str, ...]
    research_mode: ResearchMode
    data_origin: DataOrigin
    synthetic_generator_ref: str | None = None
    synthetic_validator_ref: str | None = None

    def __post_init__(self) -> None:
        """Enforce the same validation for direct construction."""
        validated = _validated_research_intent_fields(
            {
                "question": self.question,
                "rationale": self.rationale,
                "intended_benefit": self.intended_benefit,
                "success_criteria": self.success_criteria,
                "constraints": self.constraints,
                "stop_conditions": self.stop_conditions,
                "research_mode": self.research_mode,
                "data_origin": self.data_origin,
                "synthetic_generator_ref": self.synthetic_generator_ref,
                "synthetic_validator_ref": self.synthetic_validator_ref,
            }
        )
        enums_are_typed = (
            self.research_mode is validated[6] and self.data_origin is validated[7]
        )
        if not enums_are_typed:
            raise ResearchIntentError
        if (
            self.question,
            self.rationale,
            self.intended_benefit,
            self.success_criteria,
            self.constraints,
            self.stop_conditions,
            self.research_mode,
            self.data_origin,
            self.synthetic_generator_ref,
            self.synthetic_validator_ref,
        ) != validated:
            raise ResearchIntentError

    def to_dict(self) -> ResearchIntentProjection:
        """Return the canonical JSON-compatible representation."""
        return {
            "question": self.question,
            "rationale": self.rationale,
            "intended_benefit": self.intended_benefit,
            "success_criteria": list(self.success_criteria),
            "constraints": list(self.constraints),
            "stop_conditions": list(self.stop_conditions),
            "research_mode": self.research_mode.value,
            "data_origin": self.data_origin.value,
            "synthetic_generator_ref": self.synthetic_generator_ref,
            "synthetic_validator_ref": self.synthetic_validator_ref,
        }

    @property
    def canonical_bytes(self) -> bytes:
        """Serialize deterministically for approval and provenance binding."""
        return json.dumps(
            self.to_dict(),
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")

    @property
    def sha256(self) -> str:
        """Return the immutable intent identity."""
        return sha256(self.canonical_bytes).hexdigest()


def research_intent_from_mapping(value: object) -> ResearchIntent:
    """Validate a strict JSON-like research intent without coercion."""
    validated = _validated_research_intent_fields(value)
    return ResearchIntent(*validated)


def _validated_research_intent_fields(
    value: object,
) -> tuple[
    str,
    str,
    str,
    tuple[str, ...],
    tuple[str, ...],
    tuple[str, ...],
    ResearchMode,
    DataOrigin,
    str | None,
    str | None,
]:
    if not isinstance(value, Mapping):
        raise ResearchIntentError
    mapping = cast("Mapping[object, object]", value)
    keys = set(mapping)
    if not keys >= _REQUIRED_FIELDS or not keys <= _REQUIRED_FIELDS | _OPTIONAL_FIELDS:
        raise ResearchIntentError

    try:
        research_mode = ResearchMode(_required_string(mapping, "research_mode"))
        data_origin = DataOrigin(_required_string(mapping, "data_origin"))
    except ValueError as error:
        raise ResearchIntentError from error

    generator_ref = _optional_string(mapping, "synthetic_generator_ref")
    validator_ref = _optional_string(mapping, "synthetic_validator_ref")
    if data_origin is DataOrigin.OBSERVED:
        if generator_ref is not None or validator_ref is not None:
            raise ResearchIntentError
    elif (
        generator_ref is None or validator_ref is None or generator_ref == validator_ref
    ):
        raise ResearchIntentError

    return (
        _required_string(mapping, "question"),
        _required_string(mapping, "rationale"),
        _required_string(mapping, "intended_benefit"),
        _required_items(mapping, "success_criteria"),
        _required_items(mapping, "constraints"),
        _required_items(mapping, "stop_conditions"),
        research_mode,
        data_origin,
        generator_ref,
        validator_ref,
    )


def _required_string(value: Mapping[object, object], key: str) -> str:
    item = value.get(key)
    if not isinstance(item, str):
        raise ResearchIntentError
    if (
        not _canonical_research_text(item)
        or len(item) > _MAX_TEXT_CHARACTERS
    ):
        raise ResearchIntentError
    return item


def _optional_string(value: Mapping[object, object], key: str) -> str | None:
    item = value.get(key)
    if item is None:
        return None
    if not isinstance(item, str):
        raise ResearchIntentError
    if (
        not _canonical_research_text(item)
        or len(item) > _MAX_ITEM_CHARACTERS
    ):
        raise ResearchIntentError
    return item


def _required_items(value: Mapping[object, object], key: str) -> tuple[str, ...]:
    items = value.get(key)
    if (
        not isinstance(items, Sequence)
        or isinstance(items, (str, bytes, bytearray))
        or not 1 <= len(items) <= _MAX_ITEMS
    ):
        raise ResearchIntentError
    normalized: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ResearchIntentError
        if (
            not _canonical_research_text(item)
            or len(item) > _MAX_ITEM_CHARACTERS
        ):
            raise ResearchIntentError
        normalized.append(item)
    if len(set(normalized)) != len(normalized):
        raise ResearchIntentError
    return tuple(normalized)


def _canonical_research_text(value: str) -> bool:
    return bool(
        value
        and not any(_SURROGATE_LO <= ord(char) < _SURROGATE_HI for char in value)
        and unicodedata.normalize("NFC", value) == value
        and ord(value[0]) not in _RESEARCH_BOUNDARY_WHITESPACE
        and ord(value[-1]) not in _RESEARCH_BOUNDARY_WHITESPACE
    )
