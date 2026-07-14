"""Adapter from scientific ingestion to the local ClamAV boundary."""

from dataclasses import dataclass
from typing import Protocol

from services.local.config import LocalConfig
from services.local.scanner import ScanResult, scan_stream


class MalwareScanner(Protocol):
    """Fail-closed scanner interface consumed by ingestion."""

    def scan(self, payload: bytes) -> ScanResult:
        """Return only a closed scanner outcome for the supplied bytes."""
        ...


@dataclass(frozen=True, slots=True)
class LocalClamScanner:
    """Use the established ClamAV INSTREAM transport boundary."""

    config: LocalConfig

    def scan(self, payload: bytes) -> ScanResult:
        """Scan a complete bounded quarantine object via INSTREAM."""
        return scan_stream(self.config, payload)
