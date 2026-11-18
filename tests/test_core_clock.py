from datetime import UTC, datetime

from app.core.clock import SystemClock, parse_utc, utc_now, utc_now_iso


def test_utc_now_is_timezone_aware_utc() -> None:
    value = utc_now()
    assert value.tzinfo is not None
    assert value.utcoffset() is not None
    assert value.utcoffset().total_seconds() == 0


def test_utc_now_iso_uses_millisecond_z_format_by_default() -> None:
    value = utc_now_iso()
    assert value.endswith("Z")
    assert "+00:00" not in value
    assert len(value) == len("2026-01-01T00:00:00.000Z")
    assert value[19] == "."


def test_utc_now_iso_auto_preserves_legacy_now_iso_shape() -> None:
    value = utc_now_iso(timespec="auto")
    assert value.endswith("Z")
    assert "+00:00" not in value


def test_parse_utc_accepts_z_offsets_and_naive_values() -> None:
    assert parse_utc("2026-01-01T00:00:00Z") == datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_utc("2026-01-01T08:00:00+08:00") == datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_utc("2026-01-01T00:00:00") == datetime(2026, 1, 1, tzinfo=UTC)
    assert parse_utc("not-a-timestamp") is None
    assert parse_utc(None) is None


def test_system_clock_exposes_wall_monotonic_and_sleep() -> None:
    clock = SystemClock()
    assert clock.utc_now().tzinfo is not None
    assert clock.monotonic() >= 0
    clock.sleep(0)
