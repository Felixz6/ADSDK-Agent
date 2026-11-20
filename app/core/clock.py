"""Central UTC wall-clock and monotonic clock helpers.

Time is an external dependency.  Keeping the protocol and system adapter in
one place avoids subtly different timestamp formats across artifacts.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any, Literal, Protocol

TimeSpec = Literal["auto", "hours", "minutes", "seconds", "milliseconds", "microseconds"]


def utc_now() -> datetime:
    """Return the current timezone-aware UTC datetime."""

    return datetime.now(UTC)


def utc_now_iso(timespec: TimeSpec = "milliseconds") -> str:
    """Return an ISO-8601 UTC timestamp with a trailing ``Z``.

    ``timespec="auto"`` preserves the historical ``tools.utils.now_iso``
    format; most structured artifacts use millisecond precision.
    """

    return utc_now().isoformat(timespec=timespec).replace("+00:00", "Z")


def parse_utc(value: Any) -> datetime | None:
    """Parse an ISO-8601 timestamp into an aware UTC datetime.

    Missing, non-string, blank, and malformed values return ``None``.
    Naive timestamps are interpreted as UTC, matching the legacy helpers.
    """

    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except (TypeError, ValueError):
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


class Clock(Protocol):
    """Injectable clock for wall time, elapsed time, and bounded sleeps."""

    def utc_now(self) -> datetime: ...

    def monotonic(self) -> float: ...

    def sleep(self, seconds: float) -> None: ...


class SystemClock:
    """Real clock backed by the operating system."""

    def utc_now(self) -> datetime:
        return utc_now()

    def monotonic(self) -> float:
        return time.monotonic()

    def sleep(self, seconds: float) -> None:
        time.sleep(seconds)


__all__ = [
    "Clock",
    "SystemClock",
    "TimeSpec",
    "parse_utc",
    "utc_now",
    "utc_now_iso",
]
