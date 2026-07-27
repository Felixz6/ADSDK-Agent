import json

from app.tools.timeline_rules import evaluate_timeline_rules


def test_timeline_rules_pre_consent_and_high_frequency(tmp_path):
    events = [
        {
            "timestamp": "2026-03-14T10:00:02Z",
            "event_type": "sensitive_api",
            "api": "Settings.Secure.getString",
            "arg": "android_id",
            "result": "abc",
            "source": "frida",
        },
        {
            "timestamp": "2026-03-14T10:00:03Z",
            "event_type": "sensitive_api",
            "api": "ClipboardManager.getPrimaryClip",
            "arg": None,
            "result": "called",
            "source": "frida",
        },
        {
            "timestamp": "2026-03-14T10:00:04Z",
            "event_type": "sensitive_api",
            "api": "ClipboardManager.getPrimaryClip",
            "arg": None,
            "result": "called",
            "source": "frida",
        },
        {
            "timestamp": "2026-03-14T10:00:12Z",
            "event_type": "sensitive_api",
            "api": "Settings.Secure.getString",
            "arg": "android_id",
            "result": "def",
            "source": "frida",
        },
    ]
    events_json = tmp_path / "events.json"
    events_json.write_text(json.dumps(events, ensure_ascii=False), encoding="utf-8")

    findings = evaluate_timeline_rules(
        events_json_path=str(events_json),
        consent_time="2026-03-14T10:00:10Z",
        pre_consent_seconds=10,
        post_consent_seconds=10,
    )

    assert findings["summary"]["pre_consent_sensitive_access_strict"] == "suspicious"
    assert findings["summary"]["pre_consent_high_frequency_sensitive_access"] == "suspicious"


def test_timeline_rules_without_consent_time(tmp_path):
    events_json = tmp_path / "events.json"
    events_json.write_text("[]", encoding="utf-8")

    findings = evaluate_timeline_rules(
        events_json_path=str(events_json),
        consent_time=None,
        pre_consent_seconds=10,
        post_consent_seconds=10,
    )

    assert findings["summary"]["pre_consent_sensitive_access_strict"] == "not_evaluated"
    assert (
        findings["summary"]["pre_consent_high_frequency_sensitive_access"]
        == "not_evaluated"
    )
    assert (
        findings["evaluation_summary"]["pre_consent_sensitive_access_strict"]
        == "not_evaluated"
    )
    assert {
        rule["status"]
        for rule in findings["rules"]
    } == {"not_evaluated"}
