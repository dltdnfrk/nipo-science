from datetime import UTC

from services.api.artifacts import SystemClock, Uuid7Factory


def test_runtime_sources_emit_utc_and_uuid7() -> None:
    now = SystemClock().now()
    identifier = Uuid7Factory().new_uuid7()

    assert now.tzinfo is UTC
    assert identifier.version == 7
    assert identifier.variant == "specified in RFC 4122"
