"""Dynamic event timeline parsing and findings aggregation."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from app.core.device import DeviceContext
from app.core.status import StepResult, StepStatus
from app.frida.hook_parser import parse_hook_to_events_json
from app.models import DynamicAnalyzeRequest
from app.orchestration.dynamic_collection import DynamicCollectionResult
from app.orchestration.timeline_rules import classify_consent_state
from app.pipelines.common import _step_result
from app.tasks.runtime import report_step


def _build_dynamic_findings(
    events: list[dict],
    *,
    evidence_available: bool = True,
) -> dict:
    secure_calls = 0
    clipboard_calls = 0
    identifier_calls = 0
    identifier_types: set[str] = set()

    for event in events:
        api = event.get("api")
        event_type = event.get("event_type")

        if api == "Settings.Secure.getString":
            secure_calls += 1
            if event.get("identifier_present"):
                identifier_calls += 1
            id_type = event.get("identifier_type")
            if id_type:
                identifier_types.add(id_type)

        if api == "ClipboardManager.getPrimaryClip":
            clipboard_calls += 1

        if event_type == "sensitive_api":
            if event.get("identifier_present"):
                identifier_calls += 1
            id_type = event.get("identifier_type")
            if id_type:
                identifier_types.add(id_type)

    if not evidence_available:
        pre_consent_status = "not_evaluated"
        high_freq_status = "not_evaluated"
    else:
        pre_consent_status = "suspicious" if secure_calls > 0 else "not_detected"
        high_freq_status = (
            "suspicious" if (secure_calls >= 3 or clipboard_calls >= 2) else "not_detected"
        )

    return {
        "rules": [
            {
                "rule_id": "pre_consent_sensitive_access",
                "status": pre_consent_status,
                "secure_calls": secure_calls,
                "evidence_available": evidence_available,
            },
            {
                "rule_id": "high_frequency_sensitive_access",
                "status": high_freq_status,
                "secure_calls": secure_calls,
                "clipboard_calls": clipboard_calls,
                "evidence_available": evidence_available,
            },
        ],
        "summary": {
            "pre_consent_sensitive_access": pre_consent_status,
            "high_frequency_sensitive_access": high_freq_status,
            "secure_calls": secure_calls,
            "clipboard_calls": clipboard_calls,
            "identifier_calls": identifier_calls,
            "identifier_types": sorted(identifier_types),
            "evidence_available": evidence_available,
        },
    }


def _normalize_events(
    source_path: Path,
    output_path: Path,
    *,
    device_context: DeviceContext | None,
    tools: Any = None,
) -> list[dict[str, Any]]:
    parse_fn = (
        getattr(tools, "parse_hook_to_events_json", parse_hook_to_events_json)
        if tools
        else parse_hook_to_events_json
    )
    events = parse_fn(
        str(source_path),
        str(output_path),
        sensitive_identifiers=(
            {"device_serial": device_context.serial} if device_context is not None else None
        ),
    )
    consent_ms: float | int | None = None
    for event in events:
        if event.get("type") == "control" and event.get("event") == "consent_granted":
            consent_ms = event.get("monotonic_ms")
            break
    for event in events:
        if event.get("type") != "event":
            continue
        if event.get("legacy_format") is True or not event.get("timing_reliable"):
            event["consent_state"] = "unknown"
            continue
        event_ms = event.get("monotonic_ms")
        event["consent_state"] = classify_consent_state(
            event_ms,
            consent_ms,
        )
    return events


def _collect_events_stage(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    context: Any,
    environment: Any,
    collection_result: DynamicCollectionResult,
) -> tuple[list[dict[str, Any]], bool]:
    from app.core.clock import utc_now as _utc_now

    frida_session = environment.frida_session
    hook_evidence_available = bool(
        collection_result
        and collection_result.status in {"success", "partial"}
        and frida_session is not None
        and collection_result.outcomes.get("frida_ready") == "success"
    )
    event_started = collection_result.timeline.collection_started_at or _utc_now()
    dynamic_events: list[dict[str, Any]] = []

    report_step("event_validation", "running", "正在提取并校验敏感调用事件")
    if not context.events_raw_path.is_file():
        steps.append(
            _step_result(
                "event_validation",
                StepStatus.SKIPPED,
                event_started,
                required=False,
                warnings=["Frida hook evidence unavailable; network-only collection retained"],
                details={"event_count": 0, "protocol_error_count": 0},
            )
        )
        context.events_raw_path.touch(exist_ok=True)
        return dynamic_events, hook_evidence_available

    try:
        dynamic_events = _normalize_events(
            context.events_raw_path,
            context.events_path,
            device_context=environment.device_context,
            tools=getattr(environment, "tools", None),
        )
        event_status = (
            StepStatus.PARTIAL
            if getattr(frida_session, "protocol_errors", [])
            else StepStatus.SUCCESS
        )
        if not hook_evidence_available:
            event_status = StepStatus.PARTIAL
        steps.append(
            _step_result(
                "event_validation",
                event_status,
                event_started,
                required=False,
                warnings=(
                    list(getattr(frida_session, "protocol_errors", []))
                    if getattr(frida_session, "protocol_errors", [])
                    else (
                        ["Frida hook evidence unavailable; network-only collection retained"]
                        if not hook_evidence_available
                        else []
                    )
                ),
                outputs=[str(context.events_path)],
                details={
                    "event_count": len(dynamic_events),
                    "protocol_error_count": len(getattr(frida_session, "protocol_errors", [])),
                },
            )
        )
    except Exception as exc:
        dynamic_events = []
        hook_evidence_available = False
        from app.core.artifacts import atomic_write_json

        atomic_write_json(context.events_path, [])
        steps.append(
            _step_result(
                "event_validation",
                StepStatus.FAILED,
                event_started,
                required=True,
                error_code="hook_evidence_unavailable",
                error_message=f"hook evidence unavailable: {type(exc).__name__}",
                details={"event_count": 0, "protocol_error_count": 0},
            )
        )
    finally:
        context.events_raw_path.touch(exist_ok=True)
    return dynamic_events, hook_evidence_available


__all__ = [
    "_build_dynamic_findings",
    "_collect_events_stage",
    "_normalize_events",
]
