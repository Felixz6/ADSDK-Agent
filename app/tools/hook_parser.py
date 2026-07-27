import json
import os
import re
from typing import Any, Dict, List

from app.config import REDACTION_HMAC_KEY, SCHEMA_VERSION
from app.core.artifacts import atomic_write_json
from app.core.redaction import Redactor
from app.tools.frida_events import (
    FridaEventValidationError,
    normalize_frida_payload,
)

ISO_TS_PATTERN = re.compile(r"(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)")
SECURE_PATTERN = re.compile(
    r"^\[HOOK\]\s+Settings\.Secure\.getString\s+name=(?P<name>\S+)\s+ret=(?P<ret>.*)$"
)
CLIPBOARD_PATTERN = re.compile(r"^\[HOOK\]\s+ClipboardManager\.getPrimaryClip\s+called$")
_REDACTOR = Redactor(secret=REDACTION_HMAC_KEY)
_IDENTIFIER_NAMES = {
    "android_id",
    "oaid",
    "gaid",
    "advertising_id",
    "imei",
    "meid",
    "device_id",
    "serial",
}


def _base_event() -> Dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "timestamp": None,
        "event_type": None,
        "api": None,
        "arg": None,
        "result": None,
        "source": "frida",
        "legacy_format": True,
        "timing_reliable": False,
        "consent_state": "unknown",
        "limitation": (
            "legacy hook line has no trustworthy monotonic timestamp; "
            "consent-window classification is unavailable"
        ),
    }


def _extract_timestamp(line: str) -> str | None:
    match = ISO_TS_PATTERN.search(line)
    return match.group(1) if match else None


def _parse_line(line: str) -> Dict[str, Any] | None:
    text = line.strip()
    if not text:
        return None

    event = _base_event()
    event["timestamp"] = _extract_timestamp(text)

    if text.startswith("[HOOK]"):
        secure_match = SECURE_PATTERN.match(text)
        if secure_match:
            event["event_type"] = "sensitive_api"
            event["api"] = "Settings.Secure.getString"
            event["arg"] = secure_match.group("name")
            raw_result = secure_match.group("ret")
            identifier_type = secure_match.group("name").strip().lower()
            if identifier_type in _IDENTIFIER_NAMES:
                event["result"] = _REDACTOR.redact_identifier(
                    raw_result,
                    kind=identifier_type,
                )
                event["identifier_type"] = identifier_type
                event["identifier_present"] = bool(raw_result)
                event["redacted"] = True
                event["raw_retained"] = False
            else:
                event["result"] = raw_result
            return event

        if CLIPBOARD_PATTERN.match(text):
            event["event_type"] = "sensitive_api"
            event["api"] = "ClipboardManager.getPrimaryClip"
            event["arg"] = None
            event["result"] = "called"
            return event

        event["event_type"] = "hook"
        event["result"] = text
        return event

    if text.startswith("[INFO]"):
        event["event_type"] = "info"
        event["source"] = "runner"
        event["result"] = text
        return event

    if text.startswith("[ERROR]"):
        event["event_type"] = "error"
        event["source"] = "runner"
        event["result"] = text
        return event

    event["event_type"] = "raw"
    event["result"] = text
    return event


def _redact_event_text(
    event: Dict[str, Any],
    sensitive_identifiers: dict[str, str] | None,
) -> Dict[str, Any]:
    if not sensitive_identifiers:
        return event
    for key, value in tuple(event.items()):
        if isinstance(value, str):
            event[key] = _REDACTOR.redact_text(
                value,
                sensitive_identifiers,
            )
    return event


def _parse_structured_line(text: str) -> Dict[str, Any] | None:
    """Parse one new-protocol JSONL line without promoting errors to evidence."""

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        return None
    if not isinstance(payload, dict):
        return None
    if payload.get("type") not in {"event", "control"}:
        return None

    run_id = payload.get("run_id")
    session_id = payload.get("session_id")
    if not isinstance(run_id, str) or not isinstance(session_id, str):
        return None
    try:
        model = normalize_frida_payload(
            payload,
            run_id=run_id,
            session_id=session_id,
            redactor=_REDACTOR,
        )
    except FridaEventValidationError:
        return None

    event = model.model_dump(mode="json")
    event["legacy_format"] = False
    event["timing_reliable"] = True
    if event.get("type") == "event":
        event.setdefault("consent_state", "unknown")
    return event


def parse_hook_log(
    log_path: str,
    *,
    sensitive_identifiers: dict[str, str] | None = None,
) -> List[Dict[str, Any]]:
    if not os.path.exists(log_path):
        raise FileNotFoundError(f"hook evidence is missing: {log_path}")

    events: List[Dict[str, Any]] = []
    with open(log_path, "r", encoding="utf-8", errors="strict") as f:
        for line in f:
            stripped = line.strip()
            if stripped.startswith("{"):
                event = _parse_structured_line(stripped)
            else:
                event = _parse_line(line)
            if event is not None:
                events.append(
                    _redact_event_text(event, sensitive_identifiers)
                )
    return events


def write_events_json(events: List[Dict[str, Any]], output_path: str):
    atomic_write_json(output_path, events)


def parse_hook_to_events_json(
    log_path: str,
    output_path: str,
    *,
    sensitive_identifiers: dict[str, str] | None = None,
) -> List[Dict[str, Any]]:
    events = parse_hook_log(
        log_path,
        sensitive_identifiers=sensitive_identifiers,
    )
    write_events_json(events, output_path)
    return events
