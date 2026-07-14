from dataclasses import dataclass
from typing import override

from services.api.upload.models import UploadKey, UploadScope
from services.api.upload.store import (
    InMemoryQuarantineStore,
    ObjectNotReadableError,
    StoredObject,
    StoredState,
)
from services.local.scanner import (
    ScanClean,
    ScannerUnavailable,
    ScanResult,
    ThreatFound,
)


@dataclass(frozen=True, slots=True)
class CleanScanner:
    store: InMemoryQuarantineStore | None = None
    scope: UploadScope | None = None

    def scan(self, payload: bytes) -> ScanResult:
        _ = payload
        if self.store is not None and self.scope is not None:
            for key in self.store.keys_for(self.scope):
                try:
                    _ = self.store.read_agent(self.scope, key)
                except ObjectNotReadableError:
                    continue
                raise AssertionError(key)
        return ScanClean()


@dataclass(frozen=True, slots=True)
class ThreatScanner:
    def scan(self, payload: bytes) -> ScanResult:
        _ = payload
        return ThreatFound(signature="Win.Test.EICAR_HDB-1")


@dataclass(frozen=True, slots=True)
class FailedScanner:
    def scan(self, payload: bytes) -> ScanResult:
        _ = payload
        return ScannerUnavailable()


@dataclass(frozen=True, slots=True)
class ExplodingScanner:
    def scan(self, payload: bytes) -> ScanResult:
        _ = payload
        raise TimeoutError


class PartialPromotionFailureStore(InMemoryQuarantineStore):
    @override
    def promote_all(self, scope: UploadScope, keys: tuple[UploadKey, ...]) -> None:
        current = self._objects[keys[0]]
        self._objects[keys[0]] = StoredObject(
            bytes(current.payload), StoredState.CLEAN, scope
        )
        raise RuntimeError
