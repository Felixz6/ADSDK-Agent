from __future__ import annotations

import math
from typing import Any

from app.models import BehaviorTimeline, TimelineEvent


def _finite_number(value: Any) -> float | None:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    number = float(value)
    return number if math.isfinite(number) and number >= 0 else None


def classify_timing(monotonic: Any, consent_monotonic: Any) -> str:
    event_time = _finite_number(monotonic)
    consent_time = _finite_number(consent_monotonic)
    if event_time is None or consent_time is None:
        return "unknown"
    return "pre_consent" if event_time < consent_time else "post_consent"


def _severity(category: str, consent_state: str) -> str:
    if consent_state == "pre_consent" and category in {"identifier", "network", "permission"}:
        return "high"
    if category in {"protocol_error", "failure"}:
        return "medium"
    return "low"


def build_timeline(report: dict[str, Any]) -> BehaviorTimeline:
    raw_timeline = report.get("dynamic_timeline") or {}
    start = _finite_number(raw_timeline.get("collection_started_monotonic_ms"))
    consent = _finite_number(raw_timeline.get("consent_monotonic_ms"))
    events: list[TimelineEvent] = []
    warnings: list[str] = []

    lifecycle_fields = (
        ("session_created", "会话已创建", "session_created_monotonic_ms", "session_created_at"),
        ("hook_ready", "Hook 已就绪", "hook_ready_monotonic_ms", "hook_ready_at"),
        ("collection_started", "采集已开始", "collection_started_monotonic_ms", "collection_started_at"),
        ("app_resumed", "应用已恢复运行", "app_resumed_monotonic_ms", "app_resumed_at"),
        ("consent", "Consent 边界", "consent_monotonic_ms", "consent_at"),
        ("collection_ended", "采集已停止", "collection_ended_monotonic_ms", "collection_ended_at"),
    )
    represented_controls: set[str] = set()
    for event_id, title, monotonic_key, utc_key in lifecycle_fields:
        monotonic = _finite_number(raw_timeline.get(monotonic_key))
        if monotonic is None:
            continue
        represented_controls.add(event_id)
        relative = None
        if start is not None and monotonic >= start:
            relative = int(round(monotonic - start))
        events.append(
            TimelineEvent(
                id=f"control-{event_id}",
                relative_ms=relative,
                timestamp_utc=raw_timeline.get(utc_key),
                source="control",
                category="consent" if event_id == "consent" else "control",
                title=title,
                description="由当前采集会话的单调时钟记录",
                consent_state=classify_timing(monotonic, consent),
                severity="medium",
                evidence_ref="sessions.json#timeline",
            )
        )

    for index, raw in enumerate(report.get("dynamic_events") or []):
        if not isinstance(raw, dict):
            continue
        raw_control = str(raw.get("event") or "")
        if raw.get("type") == "control" and raw_control in represented_controls:
            continue
        monotonic = _finite_number(raw.get("monotonic_ms"))
        state = classify_timing(monotonic, consent)
        category = str(raw.get("category") or raw.get("event_type") or "system")
        source = "control" if raw.get("type") == "control" else "frida"
        relative = None
        if monotonic is not None and start is not None and monotonic >= start:
            relative = int(round(monotonic - start))
        events.append(
            TimelineEvent(
                id=str(raw.get("event_id") or f"frida-{index + 1}"),
                relative_ms=relative,
                timestamp_utc=raw.get("timestamp_utc") or raw.get("timestamp"),
                source=source,
                category=category,
                title=str(raw.get("action") or raw.get("event") or raw.get("api") or "动态事件"),
                description=str(raw.get("api") or raw.get("limitation") or "动态采集事件"),
                consent_state=state,
                severity=_severity(category, state),
                evidence_ref=f"events.raw.jsonl#{index + 1}",
            )
        )

    traffic = report.get("traffic_summary") or {}
    for index, request in enumerate(traffic.get("sample_requests") or []):
        if not isinstance(request, dict):
            continue
        monotonic = _finite_number(request.get("monotonic_ms"))
        state = classify_timing(monotonic, consent)
        relative = None
        if monotonic is not None and start is not None and monotonic >= start:
            relative = int(round(monotonic - start))
        host = request.get("hostname") or "未知主机"
        events.append(
            TimelineEvent(
                id=f"network-{request.get('flow_id') or index + 1}",
                relative_ms=relative,
                timestamp_utc=request.get("timestamp_utc"),
                source="network",
                category="network",
                title=f"{request.get('method', 'HTTP')} {host}",
                description=f"{request.get('scheme', 'http')} 请求（路径已脱敏）",
                consent_state=state,
                severity=_severity("network", state),
                evidence_ref=f"traffic/requests.jsonl#{index + 1}",
            )
        )

    def sort_key(item: TimelineEvent) -> tuple[int, float, str]:
        if item.relative_ms is not None:
            return (0, float(item.relative_ms), item.id)
        return (1, float("inf"), item.timestamp_utc or item.id)

    events.sort(key=sort_key)
    timing_reliable = start is not None and consent is not None
    if not timing_reliable and events:
        warnings.append("时间证据不足，Consent 状态标记为 unknown")
    if traffic.get("collector_outcome") == "collector_failed":
        warnings.append("网络采集失败，时间线仅包含可验证事件")
    if report.get("status") == "failed" or report.get("collection_status") == "failed":
        events.append(
            TimelineEvent(
                id="system-analysis-failed",
                relative_ms=None,
                timestamp_utc=None,
                source="system",
                category="failure",
                title="分析或采集失败",
                description="；".join(str(item) for item in report.get("warnings") or [])
                or "当前任务未形成完整动态证据",
                consent_state="unknown",
                severity="medium",
                evidence_ref="report.json#warnings",
            )
        )
        events.sort(key=sort_key)

    return BehaviorTimeline(
        start_monotonic=start,
        consent_monotonic=consent,
        timing_reliable=timing_reliable,
        warnings=warnings,
        events=events,
    )
