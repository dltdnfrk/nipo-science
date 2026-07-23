"""Closed JSON schema generation for one live qualification case."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from services.api.provider_live_capture_cases import CaptureCase


def response_schema(case: CaptureCase) -> str:
    """Build a closed response shape without embedding expected answers."""
    properties: dict[str, object] = {
        "scenario_id": {"type": "string", "enum": [case.scenario_id]},
        "decision_code": {"type": "string"},
        "scientific_result": {"type": "string"},
        "artifact_manifest": {"type": "string"},
        "evidence_identifiers": {
            "type": "array",
            "items": {"type": "string"},
        },
        "limitations": {
            "type": "array",
            "items": {"type": "string"},
        },
    }
    return json.dumps(
        {
            "type": "object",
            "additionalProperties": False,
            "required": list(properties),
            "properties": properties,
        },
        sort_keys=True,
    )
