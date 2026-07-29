"""Explain zero-request network collection without overclaiming."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class TrafficDiagnostics(BaseModel):
    schema_version: Literal["traffic-diagnostics-v1"] = "traffic-diagnostics-v1"
    collector_status: str
    proxy_status: Literal["not_applied", "applied", "restored", "restore_failed", "unknown"]
    host_listener: Literal["listening", "not_listening", "unknown"]
    device_reachability: Literal["reachable", "unreachable", "unknown"] = "unknown"
    ca_status: Literal["verified", "unverified", "unknown"] = "unknown"
    tls_failure_observed: bool = False
    pinning_suspected: bool = False
    request_count: int = Field(default=0, ge=0)
    outcome: str
    reason_codes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


def diagnose_traffic(
    *,
    collector_outcome: str,
    request_count: int,
    session_status: dict[str, Any] | None,
    stderr_text: str,
) -> TrafficDiagnostics:
    status = session_status or {}
    proxy_configured = bool(status.get("device_proxy_configured"))
    proxy_restored = status.get("device_proxy_restored")
    if proxy_restored is True:
        proxy_status = "restored"
    elif proxy_restored is False and proxy_configured:
        proxy_status = "restore_failed"
    elif proxy_configured:
        proxy_status = "applied"
    elif collector_outcome == "collector_disabled":
        proxy_status = "not_applied"
    else:
        proxy_status = "unknown"
    listener = (
        "listening"
        if status.get("ready_at")
        else "not_listening"
        if status.get("error_code") in {"mitm_process_exited", "mitm_ready_timeout"}
        else "unknown"
    )
    lowered = stderr_text.casefold()
    tls_failure = any(
        marker in lowered
        for marker in (
            "certificate verify failed",
            "tls handshake failed",
            "ssl error",
            "unknown ca",
        )
    )
    # A suspicion requires TLS failure evidence and an otherwise ready collector.
    pinning = tls_failure and listener == "listening" and proxy_status in {
        "applied",
        "restored",
    }
    reasons: list[str] = []
    if request_count == 0:
        reasons.append("traffic_zero_requests")
    if listener == "not_listening":
        reasons.append("traffic_host_port_not_listening")
    if proxy_status in {"not_applied", "unknown"}:
        reasons.append("traffic_proxy_not_applied")
    if proxy_status == "restore_failed":
        reasons.append("resource_cleanup_failed")
    if tls_failure:
        reasons.append("traffic_tls_failure_observed")
    if pinning:
        reasons.append("traffic_pinning_suspected")
    limitations = []
    if request_count == 0:
        limitations.append("零请求不代表应用没有网络行为")
    if pinning:
        limitations.append("TLS 失败仅支持 Pinning 疑似结论")
    if not pinning:
        limitations.append("现有证据不支持断言存在 SSL Pinning")
    return TrafficDiagnostics(
        collector_status=collector_outcome,
        proxy_status=proxy_status,  # type: ignore[arg-type]
        host_listener=listener,  # type: ignore[arg-type]
        tls_failure_observed=tls_failure,
        pinning_suspected=pinning,
        request_count=request_count,
        outcome=collector_outcome,
        reason_codes=reasons,
        limitations=limitations,
    )
