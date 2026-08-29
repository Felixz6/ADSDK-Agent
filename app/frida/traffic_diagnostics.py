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
    # M7B Phase C visibility facts. All values are deterministic observations
    # (counts / booleans) — never raw socket tables, addresses or payloads, and
    # never transport attributions (an observed UDP:443 endpoint is NOT QUIC).
    proxy_reachable: bool | None = None
    proxy_probe_available: bool = True
    tcp_activity_observed: bool | None = None
    tcp_established_count: int | None = None
    udp_activity_observed: bool | None = None
    udp_port_443_observed: bool | None = None
    target_socket_activity_observed: bool | None = None


def summarize_proc_net(
    *,
    tcp: str | None = None,
    tcp6: str | None = None,
    udp: str | None = None,
    udp6: str | None = None,
) -> dict[str, Any]:
    """Reduce ``/proc/net/{tcp,tcp6,udp,udp6}`` snapshots to facts only.

    The caller labels each table (the file name is the ground truth — no
    content sniffing). Returns counts and booleans: row totals, established
    TCP rows, remote port-443 rows (TCP and UDP separately), and per-uid row
    counts. Raw rows, addresses and uids themselves are deliberately
    discarded — the summary must be safe to persist as-is.
    """

    summary: dict[str, Any] = {
        "tcp_rows": 0,
        "tcp_established": 0,
        "tcp_remote_443": 0,
        "udp_rows": 0,
        "udp_remote_443": 0,
        "uid_socket_rows": {},
    }
    for is_udp, table in (
        (False, tcp),
        (False, tcp6),
        (True, udp),
        (True, udp6),
    ):
        if not table:
            continue
        for line in table.splitlines():
            parts = line.split()
            # Data rows start with "sl:" (e.g. "0:"), headers with "sl".
            if len(parts) < 8 or not parts[0].endswith(":"):
                continue
            local, remote, state = parts[1], parts[2], parts[3]
            uid_text = parts[7].split(":")[0] if ":" in parts[7] else parts[7]
            if not _is_hex(local.split(":")[0]) or not _is_hex(remote.split(":")[0]):
                continue
            if is_udp:
                summary["udp_rows"] += 1
                if remote.upper().endswith(":01BB"):
                    summary["udp_remote_443"] += 1
            else:
                summary["tcp_rows"] += 1
                if state == "01":
                    summary["tcp_established"] += 1
                if remote.upper().endswith(":01BB"):
                    summary["tcp_remote_443"] += 1
            if uid_text.isdigit():
                uid_map: dict[str, int] = summary["uid_socket_rows"]
                uid_map[uid_text] = uid_map.get(uid_text, 0) + 1
    return summary


def _is_hex(field: str) -> bool:
    try:
        int(field, 16)
    except ValueError:
        return False
    return True


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
    # M7B Phase C — deterministic visibility facts from the in-window device
    # network observation (counts/booleans only; see summarize_proc_net).
    observation = (
        status.get("network_observation")
        if isinstance(status.get("network_observation"), dict)
        else {}
    )
    proxy_reachable = status.get("proxy_reachable")
    if proxy_reachable is not None:
        proxy_reachable = bool(proxy_reachable)
    proxy_probe_available = bool(status.get("proxy_probe_available", True))

    target_uid = observation.get("target_uid")
    uid_rows: dict[str, int] = (
        observation.get("uid_socket_rows")
        if isinstance(observation.get("uid_socket_rows"), dict)
        else {}
    )
    target_socket_activity: bool | None = None
    if isinstance(target_uid, int):
        target_socket_activity = uid_rows.get(str(target_uid), 0) > 0

    tcp_activity: bool | None = None
    tcp_established: int | None = None
    udp_activity: bool | None = None
    udp_443: bool | None = None
    if "tcp_rows" in observation:
        tcp_activity = int(observation.get("tcp_rows") or 0) > 0
        tcp_established = int(observation.get("tcp_established") or 0)
    if "udp_rows" in observation:
        udp_activity = int(observation.get("udp_rows") or 0) > 0
        udp_443 = int(observation.get("udp_remote_443") or 0) > 0

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
    # Visibility layering: proxy reachability is a device→proxy transport fact,
    # separate from whether the target actually used the proxy.
    if proxy_status in {"applied", "restored"} and proxy_reachable is False:
        reasons.append("traffic_proxy_unreachable")
    if (
        request_count == 0
        and proxy_status in {"applied", "restored"}
        and proxy_reachable is True
        and listener == "listening"
    ):
        if tcp_activity is False and udp_activity is False:
            # No sockets observed in the window at all: the window saw no
            # traffic to classify, which is NOT evidence of no networking.
            reasons.append("traffic_no_socket_activity_observed")
        elif tcp_activity or udp_activity:
            reasons.append("traffic_socket_activity_without_http_requests")
    if udp_443:
        # Endpoint evidence only. UDP/443 is a non-TCP transport candidate —
        # never claim QUIC/HTTP3 from a port number alone.
        reasons.append("traffic_udp_443_observed")
    limitations = []
    if request_count == 0:
        limitations.append("零请求不代表应用没有网络行为")
    if pinning:
        limitations.append("TLS 失败仅支持 Pinning 疑似结论")
    if not pinning:
        limitations.append("现有证据不支持断言存在 SSL Pinning")
    if request_count == 0 and (tcp_activity or udp_activity):
        limitations.append("观察到 socket 活动，但未被 HTTP 代理采集到；不推断具体传输协议")
    return TrafficDiagnostics(
        collector_status=collector_outcome,
        proxy_status=proxy_status,  # type: ignore[arg-type]
        host_listener=listener,  # type: ignore[arg-type]
        device_reachability=(
            "reachable" if proxy_reachable is True else
            "unreachable" if proxy_reachable is False else
            "unknown"
        ),
        tls_failure_observed=tls_failure,
        pinning_suspected=pinning,
        request_count=request_count,
        outcome=collector_outcome,
        reason_codes=reasons,
        limitations=limitations,
        proxy_reachable=proxy_reachable,
        proxy_probe_available=proxy_probe_available,
        tcp_activity_observed=tcp_activity,
        tcp_established_count=tcp_established,
        udp_activity_observed=udp_activity,
        udp_port_443_observed=udp_443,
        target_socket_activity_observed=target_socket_activity,
    )
