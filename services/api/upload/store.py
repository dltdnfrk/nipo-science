"""Quarantine object-store contract and deterministic in-memory adapter."""

from dataclasses import dataclass
from enum import StrEnum
from threading import RLock
from typing import Protocol, final, override

from .models import UploadKey, UploadScope


class StoredState(StrEnum):
    """Object states that gate agent readability."""

    QUARANTINE = "quarantine"
    CLEAN = "clean"


@dataclass(frozen=True, slots=True)
class StoredObject:
    """Object-state snapshot whose payload buffer is private to the adapter."""

    payload: bytearray | bytes
    state: StoredState
    scope: UploadScope


@final
class ObjectNotReadableError(Exception):
    """Raised when an agent requests a non-clean object."""

    __slots__ = ("key",)

    def __init__(self, key: UploadKey) -> None:
        """Retain the opaque object key for the stable error message."""
        super().__init__(key)
        self.key = key

    @override
    def __str__(self) -> str:
        """Identify the unreadable key without exposing object content."""
        return f"upload object is not clean: {self.key}"


class QuarantineStore(Protocol):
    """Minimal private-store operations required by ingestion."""

    def begin(self, scope: UploadScope, key: UploadKey) -> None:
        """Create an empty quarantine object."""
        ...

    def append(self, scope: UploadScope, key: UploadKey, chunk: bytes) -> None:
        """Append one bounded transport chunk."""
        ...

    def read_quarantine(self, scope: UploadScope, key: UploadKey) -> bytes:
        """Read private quarantine bytes for trusted inspection."""
        ...

    def promote_all(self, scope: UploadScope, keys: tuple[UploadKey, ...]) -> None:
        """Atomically transition a verified request to clean."""
        ...

    def discard(self, scope: UploadScope, key: UploadKey) -> None:
        """Delete an object idempotently."""
        ...

    def discard_all(self, scope: UploadScope, keys: tuple[UploadKey, ...]) -> None:
        """Atomically remove every object in a failed request."""
        ...


class InMemoryQuarantineStore:
    """Mutable test/local adapter whose mutation models object transitions."""

    def __init__(self) -> None:
        """Initialize an empty mutable object map."""
        self._objects: dict[UploadKey, StoredObject] = {}
        self._lock: RLock = RLock()

    def begin(self, scope: UploadScope, key: UploadKey) -> None:
        """Create an empty private quarantine object."""
        with self._lock:
            if key in self._objects:
                raise RuntimeError
            self._objects[key] = StoredObject(
                bytearray(), StoredState.QUARANTINE, scope
            )

    def append(self, scope: UploadScope, key: UploadKey, chunk: bytes) -> None:
        """Append one transport chunk while preserving quarantine state."""
        with self._lock:
            current = self._objects[key]
            if (
                current.scope != scope
                or current.state is not StoredState.QUARANTINE
                or not isinstance(current.payload, bytearray)
            ):
                raise RuntimeError
            current.payload.extend(chunk)

    def read_quarantine(self, scope: UploadScope, key: UploadKey) -> bytes:
        """Read private bytes for the trusted scanner/parser pipeline."""
        with self._lock:
            current = self._objects[key]
            if current.scope != scope or current.state is not StoredState.QUARANTINE:
                raise RuntimeError
            return bytes(current.payload)

    def promote_all(self, scope: UploadScope, keys: tuple[UploadKey, ...]) -> None:
        """Make a complete verified request agent-readable atomically."""
        with self._lock:
            if any(
                key not in self._objects
                or self._objects[key].scope != scope
                or self._objects[key].state is not StoredState.QUARANTINE
                for key in keys
            ):
                raise RuntimeError
            replacements = {
                key: StoredObject(
                    bytes(self._objects[key].payload), StoredState.CLEAN, scope
                )
                for key in keys
            }
            self._objects.update(replacements)

    def discard(self, scope: UploadScope, key: UploadKey) -> None:
        """Delete a staged or promoted object idempotently."""
        with self._lock:
            current = self._objects.get(key)
            if current is not None and current.scope != scope:
                raise ObjectNotReadableError(key)
            _ = self._objects.pop(key, None)

    def discard_all(self, scope: UploadScope, keys: tuple[UploadKey, ...]) -> None:
        """Remove a complete failed request while holding the visibility lock."""
        with self._lock:
            if any(
                key in self._objects and self._objects[key].scope != scope
                for key in keys
            ):
                raise ObjectNotReadableError(keys[0])
            for key in keys:
                _ = self._objects.pop(key, None)

    def read_agent(self, scope: UploadScope, key: UploadKey) -> bytes:
        """Return bytes only after the explicit clean transition."""
        with self._lock:
            current = self._objects.get(key)
            if (
                current is None
                or current.scope != scope
                or current.state is not StoredState.CLEAN
            ):
                raise ObjectNotReadableError(key)
            if not isinstance(current.payload, bytes):
                raise TypeError
            return current.payload

    def object_count_for(self, scope: UploadScope) -> int:
        """Count only objects authorized for the supplied tenant scope."""
        with self._lock:
            return sum(current.scope == scope for current in self._objects.values())

    def keys_for(self, scope: UploadScope) -> tuple[UploadKey, ...]:
        """Expose only the caller's staged keys without granting payload access."""
        with self._lock:
            return tuple(
                key for key, current in self._objects.items() if current.scope == scope
            )
