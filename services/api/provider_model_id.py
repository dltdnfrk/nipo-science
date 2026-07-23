"""Canonical provider model identifier contract."""

from typing import Final

PROVIDER_MODEL_ID_MAX_CHARACTERS: Final = 255


def provider_model_id_is_valid(value: str) -> bool:
    """Return whether a model ID fits every provider storage and API boundary."""
    return bool(value) and len(value) <= PROVIDER_MODEL_ID_MAX_CHARACTERS
