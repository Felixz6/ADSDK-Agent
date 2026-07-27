import json

import pytest

from app.core.redaction import Redactor
from app.tools.frida_events import (
    FridaEventValidationError,
    StructuredEventWriter,
    normalize_frida_payload,
)
from app.tools.hook_parser import parse_hook_log, parse_hook_to_events_json


RAW_IDENTIFIER = "fixture-sensitive-id-2026-NEVER-PERSIST"


def _identifier_event(**overrides) -> dict:
    payload = {
        "protocol_version": "1.0",
        "schema_version": "1.0",
        "type": "event",
        "event_id": "event-1",
        "run_id": "run-1",
        "session_id": "session-1",
        "timestamp_utc": "2026-01-01T00:00:01.234Z",
        "monotonic_ms": 2345.67,
        "pid": 123,
        "process_name": "com.example.app",
        "thread_id": 20,
        "thread_name": "main",
        "category": "identifier_access",
        "api": "Settings.Secure.getString",
        "action": "android_id_read",
        "identifier_type": "android_id",
        "identifier_present": True,
        "raw_value": RAW_IDENTIFIER,
        "raw_retained": False,
        "stack": [],
        "metadata": {"value_length": len(RAW_IDENTIFIER)},
    }
    payload.update(overrides)
    return payload


def _assert_secret_absent(text: str) -> None:
    if RAW_IDENTIFIER in text:
        pytest.fail("sensitive identifier leaked into a persisted artifact")


def test_typed_normalization_hmacs_raw_value_and_domain_separates_identifier_type():
    redactor = Redactor(secret="test-secret-material")
    first = normalize_frida_payload(
        _identifier_event(),
        run_id="run-1",
        session_id="session-1",
        redactor=redactor,
    )
    second = normalize_frida_payload(
        _identifier_event(event_id="event-2"),
        run_id="run-1",
        session_id="session-1",
        redactor=redactor,
    )
    other_kind = normalize_frida_payload(
        _identifier_event(
            event_id="event-3",
            identifier_type="oaid",
        ),
        run_id="run-1",
        session_id="session-1",
        redactor=redactor,
    )

    assert first.value_token == second.value_token
    assert first.value_token != other_kind.value_token
    assert first.value_token.startswith("redacted:")
    assert first.raw_retained is False
    _assert_secret_absent(first.model_dump_json())


def test_jsonl_writer_persists_only_valid_sanitized_events(tmp_path):
    jsonl_path = tmp_path / "events.raw.jsonl"
    error_path = tmp_path / "frida.protocol-errors.jsonl"
    writer = StructuredEventWriter(
        jsonl_path,
        run_id="run-1",
        session_id="session-1",
        protocol_error_path=error_path,
        redactor=Redactor(secret="test-secret-material"),
    )

    event = writer.append(_identifier_event())
    assert event is not None
    _assert_secret_absent(jsonl_path.read_text(encoding="utf-8"))

    invalid = _identifier_event(
        event_id="invalid-event",
        monotonic_ms="not-a-number",
    )
    assert writer.append(invalid) is None

    assert len(writer.valid_events) == 1
    assert len(writer.protocol_errors) == 1
    assert writer.protocol_errors[0]["code"] == "validation_error"
    _assert_secret_absent(error_path.read_text(encoding="utf-8"))


def test_validation_errors_never_echo_raw_payload():
    with pytest.raises(FridaEventValidationError) as captured:
        normalize_frida_payload(
            _identifier_event(monotonic_ms="bad-value"),
            run_id="run-1",
            session_id="session-1",
        )

    _assert_secret_absent(str(captured.value))


def test_structured_jsonl_reader_and_legacy_reader_are_both_supported(tmp_path):
    structured_path = tmp_path / "events.raw.jsonl"
    writer = StructuredEventWriter(
        structured_path,
        run_id="run-1",
        session_id="session-1",
        redactor=Redactor(secret="test-secret-material"),
    )
    writer.append(_identifier_event())

    events_json = tmp_path / "events.json"
    structured_events = parse_hook_to_events_json(
        str(structured_path),
        str(events_json),
    )
    assert len(structured_events) == 1
    assert structured_events[0]["legacy_format"] is False
    assert structured_events[0]["timing_reliable"] is True
    _assert_secret_absent(events_json.read_text(encoding="utf-8"))

    legacy_path = tmp_path / "hook.log"
    legacy_path.write_text(
        "[HOOK] ClipboardManager.getPrimaryClip called\n",
        encoding="utf-8",
    )
    legacy_events = parse_hook_log(str(legacy_path))
    assert len(legacy_events) == 1
    assert legacy_events[0]["legacy_format"] is True
    assert legacy_events[0]["timing_reliable"] is False
    assert legacy_events[0]["consent_state"] == "unknown"
    assert legacy_events[0]["limitation"]


def test_malformed_structured_line_is_not_promoted_to_raw_event(tmp_path):
    source = tmp_path / "events.raw.jsonl"
    source.write_text('{"type":"event","raw_value":"secret"\n', encoding="utf-8")

    events = parse_hook_log(str(source))

    assert events == []

