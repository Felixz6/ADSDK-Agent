import json
from datetime import datetime, timedelta, timezone

from app.tools.hook_parser import parse_hook_to_events_json
from app.tools.timeline_rules import (
    DynamicTimeline,
    classify_consent_state,
    evaluate_timeline_rules,
)


class FakeClock:
    def __init__(self) -> None:
        self.wall = datetime(2026, 1, 1, 12, 0, tzinfo=timezone.utc)
        self.monotonic_value = 100.0

    def utc_now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.monotonic_value

    def advance(self, seconds: float, *, wall_seconds: float | None = None) -> None:
        self.monotonic_value += seconds
        self.wall += timedelta(
            seconds=seconds if wall_seconds is None else wall_seconds
        )


def test_collection_and_consent_use_monotonic_baseline_despite_wall_clock_jump():
    clock = FakeClock()
    timing = DynamicTimeline(clock=clock)
    timing.mark_hook_ready()
    timing.mark_app_resumed()
    collection_start = timing.mark_collection_started()

    clock.advance(8.0, wall_seconds=-3600.0)
    consent = timing.mark_consent()

    assert consent.monotonic_ms - collection_start.monotonic_ms == 8000.0
    assert consent.timestamp_utc < collection_start.timestamp_utc
    assert timing.consent_delay_seconds == 8.0


def test_consent_boundary_is_exact_and_missing_monotonic_is_unknown():
    assert classify_consent_state(999.999, 1000.0) == "pre_consent"
    assert classify_consent_state(1000.0, 1000.0) == "post_consent"
    assert classify_consent_state(1000.001, 1000.0) == "post_consent"
    assert classify_consent_state(None, 1000.0) == "unknown"
    assert classify_consent_state(1000.0, None) == "unknown"


def test_structured_control_event_is_single_consent_boundary(tmp_path):
    events = [
        {
            "protocol_version": "1.0",
            "schema_version": "1.0",
            "type": "event",
            "event_id": "before",
            "run_id": "run-1",
            "session_id": "session-1",
            "timestamp_utc": "2026-01-01T00:00:01.000Z",
            "monotonic_ms": 999.999,
            "pid": 1,
            "process_name": "target",
            "thread_id": 1,
            "category": "identifier_access",
            "action": "android_id_read",
            "api": "Settings.Secure.getString",
            "identifier_type": "android_id",
            "identifier_present": True,
            "value_token": "redacted:fixture",
            "raw_retained": False,
            "stack": [],
            "metadata": {},
        },
        {
            "protocol_version": "1.0",
            "schema_version": "1.0",
            "type": "control",
            "event_id": "consent",
            "event": "consent_granted",
            "run_id": "run-1",
            "session_id": "session-1",
            "timestamp_utc": "2026-01-01T00:00:02.000Z",
            "monotonic_ms": 1000.0,
            "pid": 1,
            "source": "configured_delay",
            "metadata": {},
        },
        {
            "protocol_version": "1.0",
            "schema_version": "1.0",
            "type": "event",
            "event_id": "at-boundary",
            "run_id": "run-1",
            "session_id": "session-1",
            "timestamp_utc": "2026-01-01T00:00:02.000Z",
            "monotonic_ms": 1000.0,
            "pid": 1,
            "process_name": "target",
            "thread_id": 1,
            "category": "identifier_access",
            "action": "android_id_read",
            "api": "Settings.Secure.getString",
            "identifier_type": "android_id",
            "identifier_present": True,
            "value_token": "redacted:fixture",
            "raw_retained": False,
            "stack": [],
            "metadata": {},
        },
    ]
    path = tmp_path / "events.json"
    path.write_text(json.dumps(events), encoding="utf-8")

    findings = evaluate_timeline_rules(
        str(path),
        consent_time=None,
        pre_consent_seconds=10,
        post_consent_seconds=10,
    )

    assert findings["rules"][0]["pre_sensitive_count"] == 1
    assert findings["window"]["consent_monotonic_ms"] == 1000.0


def test_legacy_hook_without_reliable_timestamp_is_not_evaluated(tmp_path):
    hook_log = tmp_path / "hook.log"
    hook_log.write_text(
        "\n".join(
            [
                "[HOOK] ClipboardManager.getPrimaryClip called",
                "[INFO] 2026-01-01T00:00:10Z consent event",
            ]
        )
        + "\n",
        encoding="utf-8",
    )
    events_json = tmp_path / "events.json"
    parse_hook_to_events_json(str(hook_log), str(events_json))

    findings = evaluate_timeline_rules(
        str(events_json),
        consent_time="2026-01-01T00:00:10Z",
    )

    assert {
        rule["status"]
        for rule in findings["rules"]
    } == {"not_evaluated"}
    assert findings["warnings"]

