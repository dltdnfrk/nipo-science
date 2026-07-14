from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, override

from .dry_lab_artifact_integrity import artifact_integrity_errors
from .dry_lab_review_integrity import review_integrity_errors

if TYPE_CHECKING:
    from .dry_lab_integrity_types import DryLabIntegrityContract


@dataclass(frozen=True, slots=True)
class DryLabIntegrityError(ValueError):
    message: str

    @override
    def __str__(self) -> str:
        return self.message


def assert_dry_lab_integrity(contract: DryLabIntegrityContract) -> None:
    errors = (*artifact_integrity_errors(contract), *review_integrity_errors(contract))
    if errors:
        raise DryLabIntegrityError(message=errors[0])
