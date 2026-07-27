import json

from app.config import SCHEMA_VERSION
from app.tools.hook_parser import parse_hook_log, parse_hook_to_events_json


def test_parse_hook_log_and_write_events_json(tmp_path):
    hook_log = tmp_path / "hook.log"
    raw_android_id = "RAW-ANDROID-ID-ZZ"
    hook_log.write_text(
        "\n".join(
            [
                "[INFO] 2026-03-13T10:00:00Z capture window start seconds=15",
                (
                    "[HOOK] Settings.Secure.getString "
                    f"name=android_id ret={raw_android_id}"
                ),
                "[HOOK] ClipboardManager.getPrimaryClip called",
                "[ERROR] frida disconnected",
            ]
        )
        + "\n",
        encoding="utf-8",
    )

    events = parse_hook_log(str(hook_log))
    assert len(events) == 4
    assert events[1]["api"] == "Settings.Secure.getString"
    assert events[1]["arg"] == "android_id"
    assert events[1]["schema_version"] == SCHEMA_VERSION
    assert events[1]["redacted"] is True
    assert events[1]["identifier_type"] == "android_id"
    assert events[1]["raw_retained"] is False
    assert events[1]["result"].startswith("redacted:")
    assert raw_android_id not in events[1]["result"]
    assert events[2]["api"] == "ClipboardManager.getPrimaryClip"

    events_json = tmp_path / "events.json"
    written_events = parse_hook_to_events_json(str(hook_log), str(events_json))
    assert len(written_events) == 4
    assert events_json.exists()

    payload = json.loads(events_json.read_text(encoding="utf-8"))
    assert payload[0]["event_type"] == "info"
    assert {
        "schema_version",
        "timestamp",
        "event_type",
        "api",
        "arg",
        "result",
        "source",
    } <= set(payload[1])
    assert raw_android_id not in events_json.read_text(encoding="utf-8")


def test_hook_diagnostics_redact_known_device_serial(tmp_path):
    hook_log = tmp_path / "hook.log"
    serial = "emulator-5554"
    hook_log.write_text(
        f"[ERROR] frida device {serial} disconnected\n",
        encoding="utf-8",
    )

    events_json = tmp_path / "events.json"
    events = parse_hook_to_events_json(
        str(hook_log),
        str(events_json),
        sensitive_identifiers={"device_serial": serial},
    )

    assert serial not in json.dumps(events, ensure_ascii=False)
    assert serial not in events_json.read_text(encoding="utf-8")
    assert events[0]["result"].count("redacted:") == 1
