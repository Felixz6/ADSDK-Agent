"""Monotonic dynamic-collection timing and consent-boundary rules."""

from __future__ import annotations

import json
import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Protocol


class TimelineClock(Protocol):
    def utc_now(self) -> datetime: ...

    def monotonic(self) -> float: ...


class SystemTimelineClock:
    def utc_now(self) -> datetime:
        return datetime.now(timezone.utc)

    def monotonic(self) -> float:
        return time.monotonic()


@dataclass(frozen=True, slots=True)
class EvidenceTimestamp:
    """One observation expressed in wall-clock UTC and monotonic time."""

    timestamp_utc: datetime
    monotonic_ms: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp_utc": self.timestamp_utc.astimezone(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "monotonic_ms": self.monotonic_ms,
        }


@dataclass
class DynamicTimeline:
    """Single source of truth for a dynamic collection's timing landmarks."""

    clock: TimelineClock = field(default_factory=SystemTimelineClock)
    session_created_at: EvidenceTimestamp = field(init=False)
    hook_ready_at: EvidenceTimestamp | None = None
    app_resumed_at: EvidenceTimestamp | None = None
    collection_started_at: EvidenceTimestamp | None = None
    consent_at: EvidenceTimestamp | None = None
    collection_ended_at: EvidenceTimestamp | None = None

    def __post_init__(self) -> None:
        self.session_created_at = self._now()

    def _now(self) -> EvidenceTimestamp:
        wall = self.clock.utc_now()
        if wall.tzinfo is None:
            wall = wall.replace(tzinfo=timezone.utc)
        else:
            wall = wall.astimezone(timezone.utc)
        monotonic_value = float(self.clock.monotonic()) * 1000.0
        if not math.isfinite(monotonic_value) or monotonic_value < 0:
            raise ValueError("clock returned an invalid monotonic value")
        return EvidenceTimestamp(wall, monotonic_value)

    def _mark(self, attribute: str) -> EvidenceTimestamp:
        current = getattr(self, attribute)
        if current is None:
            current = self._now()
            setattr(self, attribute, current)
        return current

    def mark_hook_ready(self) -> EvidenceTimestamp:
        return self._mark("hook_ready_at")

    def mark_app_resumed(self) -> EvidenceTimestamp:
        if self.hook_ready_at is None:
            raise RuntimeError("app cannot resume before hook_ready")
        return self._mark("app_resumed_at")

    def mark_collection_started(self) -> EvidenceTimestamp:
        if self.hook_ready_at is None:
            raise RuntimeError("collection cannot start before hook_ready")
        return self._mark("collection_started_at")

    def mark_consent(self) -> EvidenceTimestamp:
        if self.collection_started_at is None:
            raise RuntimeError("consent cannot be recorded before collection start")
        return self._mark("consent_at")

    def mark_collection_ended(self) -> EvidenceTimestamp:
        return self._mark("collection_ended_at")

    @property
    def consent_delay_seconds(self) -> float | None:
        if self.collection_started_at is None or self.consent_at is None:
            return None
        return (
            self.consent_at.monotonic_ms
            - self.collection_started_at.monotonic_ms
        ) / 1000.0

    def consent_deadline_monotonic_ms(self, delay_seconds: float) -> float:
        if self.collection_started_at is None:
            raise RuntimeError("collection has not started")
        if delay_seconds < 0 or not math.isfinite(delay_seconds):
            raise ValueError("consent delay must be a finite non-negative value")
        return self.collection_started_at.monotonic_ms + delay_seconds * 1000.0

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for name in (
            "session_created_at",
            "hook_ready_at",
            "app_resumed_at",
            "collection_started_at",
            "consent_at",
            "collection_ended_at",
        ):
            value = getattr(self, name)
            result[name] = value.to_dict() if value is not None else None
        result["consent_delay_seconds"] = self.consent_delay_seconds
        return result


def classify_consent_state(
    event_monotonic_ms: float | int | None,
    consent_monotonic_ms: float | int | None,
) -> str:
    """Classify the exact consent boundary using only monotonic evidence."""

    if isinstance(event_monotonic_ms, bool) or isinstance(
        consent_monotonic_ms, bool
    ):
        return "unknown"
    if not isinstance(event_monotonic_ms, (int, float)) or not isinstance(
        consent_monotonic_ms, (int, float)
    ):
        return "unknown"
    event_value = float(event_monotonic_ms)
    consent_value = float(consent_monotonic_ms)
    if (
        not math.isfinite(event_value)
        or not math.isfinite(consent_value)
        or event_value < 0
        or consent_value < 0
    ):
        return "unknown"
    return "pre_consent" if event_value < consent_value else "post_consent"


def _parse_iso(ts: str | None) -> datetime | None:
    if not isinstance(ts, str) or not ts:
        return None
    value = ts.strip()
    if not value:
        return None
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def _load_events(events_json_path: str) -> List[Dict[str, Any]]:
    with open(events_json_path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return [item for item in data if isinstance(item, dict)]
    if isinstance(data, dict) and isinstance(data.get("events"), list):
        return [
            item
            for item in data["events"]
            if isinstance(item, dict)
        ]
    raise ValueError("events evidence must be a JSON array or events envelope")


def _find_consent_event(
    events: List[Dict[str, Any]],
) -> Dict[str, Any] | None:
    for event in events:
        if (
            event.get("type") == "control"
            and event.get("event") == "consent_granted"
        ):
            return event
    return None


def _find_legacy_consent_index(
    events: List[Dict[str, Any]],
) -> int | None:
    for idx, event in enumerate(events):
        result_text = str(event.get("result", ""))
        if "consent event" in result_text:
            return idx
    return None


def _is_sensitive_event(event: Dict[str, Any]) -> bool:
    return event.get("api") in {
        "Settings.Secure.getString",
        "ClipboardManager.getPrimaryClip",
    }


def _is_android_id_event(event: Dict[str, Any]) -> bool:
    return (
        event.get("api") == "Settings.Secure.getString"
        and (
            event.get("identifier_type") == "android_id"
            or event.get("arg") == "android_id"
        )
    )


def evaluate_timeline_rules(
    events_json_path: str,
    consent_time: str | None,
    pre_consent_seconds: int = 10,
    post_consent_seconds: int = 10,
    evidence_available: bool = True,
) -> Dict[str, Any]:
    """Evaluate strict pre-consent rules.

    New structured evidence is classified exclusively by the monotonic
    ``consent_granted`` control record.  The wall-clock fallback is retained
    for older already-normalized JSON arrays that contain explicit timestamps;
    records marked as legacy/unreliable are never classified by file order.
    """

    warnings: list[str] = []
    try:
        events = _load_events(events_json_path) if evidence_available else []
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        events = []
        evidence_available = False
        warnings.append(
            f"events evidence could not be evaluated: {type(exc).__name__}"
        )

    consent_event = _find_consent_event(events)
    consent_monotonic_ms: float | None = None
    if consent_event is not None:
        candidate = consent_event.get("monotonic_ms")
        if isinstance(candidate, (int, float)) and not isinstance(candidate, bool):
            candidate_float = float(candidate)
            if math.isfinite(candidate_float) and candidate_float >= 0:
                consent_monotonic_ms = candidate_float
        if consent_monotonic_ms is None:
            warnings.append("consent control event has no valid monotonic time")

    consent_dt = _parse_iso(
        str(consent_event.get("timestamp_utc"))
        if consent_event is not None and consent_event.get("timestamp_utc")
        else consent_time
    )
    legacy_consent_dt = _parse_iso(consent_time)

    pre_window_start = (
        legacy_consent_dt
        - timedelta(seconds=max(0, pre_consent_seconds))
        if legacy_consent_dt
        else None
    )
    pre_window_end = legacy_consent_dt
    post_window_end = (
        legacy_consent_dt
        + timedelta(seconds=max(0, post_consent_seconds))
        if legacy_consent_dt
        else None
    )

    pre_sensitive_count = 0
    pre_android_id_count = 0
    pre_clipboard_count = 0
    unknown_timing_count = 0
    sensitive_count = 0
    structured_boundary = consent_event is not None
    legacy_unreliable = False

    for event in events:
        if not _is_sensitive_event(event):
            continue
        sensitive_count += 1
        in_pre_window = False

        if structured_boundary:
            state = classify_consent_state(
                event.get("monotonic_ms"),
                consent_monotonic_ms,
            )
            if state == "unknown":
                unknown_timing_count += 1
                continue
            event_monotonic = float(event["monotonic_ms"])
            pre_start_monotonic = (
                consent_monotonic_ms
                - max(0, pre_consent_seconds) * 1000.0
                if consent_monotonic_ms is not None
                else None
            )
            in_pre_window = (
                state == "pre_consent"
                and pre_start_monotonic is not None
                and event_monotonic >= pre_start_monotonic
            )
        else:
            timing_reliable = event.get("timing_reliable")
            if event.get("legacy_format") is True or timing_reliable is False:
                legacy_unreliable = True
                unknown_timing_count += 1
                continue
            event_dt = _parse_iso(event.get("timestamp"))
            if legacy_consent_dt is None or event_dt is None:
                unknown_timing_count += 1
                continue
            in_pre_window = (
                pre_window_start is not None
                and pre_window_start <= event_dt < legacy_consent_dt
            )

        if not in_pre_window:
            continue
        pre_sensitive_count += 1
        if _is_android_id_event(event):
            pre_android_id_count += 1
        if event.get("api") == "ClipboardManager.getPrimaryClip":
            pre_clipboard_count += 1

    if legacy_unreliable:
        warnings.append(
            "legacy hook timing is unreliable; consent-window rules were not evaluated"
        )
    if unknown_timing_count:
        warnings.append(
            f"{unknown_timing_count} sensitive event(s) have unknown consent timing"
        )

    boundary_available = (
        consent_monotonic_ms is not None
        if structured_boundary
        else legacy_consent_dt is not None and not legacy_unreliable
    )
    can_evaluate = (
        evidence_available
        and boundary_available
        and unknown_timing_count == 0
    )
    if not can_evaluate:
        pre_sensitive_evaluation = "not_evaluated"
        pre_high_freq_evaluation = "not_evaluated"
    else:
        pre_sensitive_evaluation = (
            "matched" if pre_sensitive_count > 0 else "not_matched"
        )
        pre_high_freq_evaluation = (
            "matched"
            if pre_android_id_count > 3 or pre_clipboard_count > 1
            else "not_matched"
        )

    def legacy_status(value: str) -> str:
        if value == "matched":
            return "suspicious"
        if value == "not_matched":
            return "not_detected"
        return value

    return {
        "window": {
            "consent_time": (
                consent_dt.isoformat().replace("+00:00", "Z")
                if consent_dt
                else consent_time
            ),
            "consent_monotonic_ms": consent_monotonic_ms,
            "pre_window_start_monotonic_ms": (
                consent_monotonic_ms
                - max(0, pre_consent_seconds) * 1000.0
                if consent_monotonic_ms is not None
                else None
            ),
            "post_window_end_monotonic_ms": (
                consent_monotonic_ms
                + max(0, post_consent_seconds) * 1000.0
                if consent_monotonic_ms is not None
                else None
            ),
            "pre_consent_seconds": pre_consent_seconds,
            "post_consent_seconds": post_consent_seconds,
            "pre_window_start": (
                pre_window_start.isoformat().replace("+00:00", "Z")
                if pre_window_start
                else None
            ),
            "pre_window_end": (
                pre_window_end.isoformat().replace("+00:00", "Z")
                if pre_window_end
                else None
            ),
            "post_window_end": (
                post_window_end.isoformat().replace("+00:00", "Z")
                if post_window_end
                else None
            ),
        },
        "rules": [
            {
                "rule_id": "pre_consent_sensitive_access_strict",
                "status": pre_sensitive_evaluation,
                "legacy_status": legacy_status(pre_sensitive_evaluation),
                "pre_sensitive_count": pre_sensitive_count,
                "unknown_timing_count": unknown_timing_count,
            },
            {
                "rule_id": "pre_consent_high_frequency_sensitive_access",
                "status": pre_high_freq_evaluation,
                "legacy_status": legacy_status(pre_high_freq_evaluation),
                "pre_android_id_count": pre_android_id_count,
                "pre_clipboard_count": pre_clipboard_count,
                "android_id_threshold": 3,
                "clipboard_threshold": 1,
            },
        ],
        "summary": {
            "pre_consent_sensitive_access_strict": legacy_status(
                pre_sensitive_evaluation
            ),
            "pre_consent_high_frequency_sensitive_access": legacy_status(
                pre_high_freq_evaluation
            ),
        },
        "evaluation_summary": {
            "pre_consent_sensitive_access_strict": pre_sensitive_evaluation,
            "pre_consent_high_frequency_sensitive_access": pre_high_freq_evaluation,
        },
        "warnings": warnings,
    }
