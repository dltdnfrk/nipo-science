"""Production UTC clock and UUIDv7 identity sources."""

import secrets
import time
from datetime import UTC, datetime
from typing import Final, final
from uuid import UUID

UUID7_VERSION: Final = 7
UUID_VARIANT: Final = 0b10


@final
class SystemClock:
    """Read the system clock as aware UTC."""

    def now(self) -> datetime:
        """Return the current aware UTC time."""
        return datetime.now(UTC)


@final
class Uuid7Factory:
    """Generate RFC 9562 UUIDv7 values from milliseconds and randomness."""

    def new_uuid7(self) -> UUID:
        """Return one time-ordered UUIDv7."""
        unix_ms = time.time_ns() // 1_000_000
        random_a = secrets.randbits(12)
        random_b = secrets.randbits(62)
        value = (
            (unix_ms << 80)
            | (UUID7_VERSION << 76)
            | (random_a << 64)
            | (UUID_VARIANT << 62)
            | random_b
        )
        return UUID(int=value)
