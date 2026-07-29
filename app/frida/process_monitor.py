"""Bounded process-exit and anti-debug suspicion classification."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field


class ProcessExitDiagnostics(BaseModel):
    schema_version: Literal["process-diagnostics-v1"] = "process-diagnostics-v1"
    status: Literal[
        "running",
        "process_crashed",
        "process_killed",
        "process_exited",
        "transport_lost",
        "hook_script_failed",
        "app_self_termination_suspected",
        "anti_debug_suspected",
        "unknown_exit",
    ]
    pid: int | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    hook_ready: bool = False
    hook_event_count: int = Field(default=0, ge=0)
    detached_reason: str | None = None
    most_likely_cause: str
    alternative_explanations: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "low"


def classify_process_exit(
    *,
    pid: int | None,
    duration_ms: int | None,
    hook_ready: bool,
    hook_event_count: int,
    detached_reason: str | None,
    logcat_lines: list[str],
    process_still_running: bool,
) -> ProcessExitDiagnostics:
    """Classify only what the collected signals support."""

    if process_still_running:
        return ProcessExitDiagnostics(
            status="running",
            pid=pid,
            duration_ms=duration_ms,
            hook_ready=hook_ready,
            hook_event_count=hook_event_count,
            detached_reason=detached_reason,
            most_likely_cause="目标进程在观察结束时仍在运行",
            confidence="high",
        )
    text = "\n".join(logcat_lines).casefold()
    evidence: list[str] = []
    if "fatal exception" in text or "fatal signal" in text or "tombstone" in text:
        if "fatal exception" in text:
            evidence.append("Android Runtime FATAL EXCEPTION")
        if "fatal signal" in text:
            evidence.append("native fatal signal")
        if "tombstone" in text:
            evidence.append("tombstone reference")
        return ProcessExitDiagnostics(
            status="process_crashed",
            pid=pid,
            duration_ms=duration_ms,
            hook_ready=hook_ready,
            hook_event_count=hook_event_count,
            detached_reason=detached_reason,
            most_likely_cause="目标应用发生崩溃",
            alternative_explanations=["运行时兼容性问题", "应用自身缺陷"],
            supporting_evidence=evidence,
            confidence="high",
        )
    if "force stopping" in text or "killing " in text or "killed" in text:
        evidence.append("logcat process kill/force-stop signal")
        return ProcessExitDiagnostics(
            status="process_killed",
            pid=pid,
            duration_ms=duration_ms,
            hook_ready=hook_ready,
            hook_event_count=hook_event_count,
            detached_reason=detached_reason,
            most_likely_cause="目标进程被系统或外部操作终止",
            alternative_explanations=["系统资源回收", "用户或测试流程停止应用"],
            supporting_evidence=evidence,
            confidence="medium",
        )
    anti_markers = (
        "tracerpid",
        "ptrace",
        "anti-debug",
        "frida detected",
        "gum-js-loop",
    )
    matched = [marker for marker in anti_markers if marker in text]
    rapid = duration_ms is not None and duration_ms <= 1500
    if matched and rapid:
        return ProcessExitDiagnostics(
            status="anti_debug_suspected",
            pid=pid,
            duration_ms=duration_ms,
            hook_ready=hook_ready,
            hook_event_count=hook_event_count,
            detached_reason=detached_reason,
            most_likely_cause="观察到快速退出与反调试相关日志信号",
            alternative_explanations=["Frida/Android 版本兼容性", "应用启动失败", "应用主动退出"],
            supporting_evidence=[f"logcat marker: {item}" for item in matched],
            confidence="medium",
        )
    if rapid and hook_ready and hook_event_count == 0:
        return ProcessExitDiagnostics(
            status="app_self_termination_suspected",
            pid=pid,
            duration_ms=duration_ms,
            hook_ready=hook_ready,
            hook_event_count=hook_event_count,
            detached_reason=detached_reason,
            most_likely_cause="应用在 Hook 就绪后快速退出",
            alternative_explanations=["主动终止", "兼容性问题", "反调试行为"],
            supporting_evidence=["rapid exit after hook_ready"],
            confidence="low",
        )
    if detached_reason and "connection" in detached_reason.casefold():
        status = "transport_lost"
        cause = "Frida transport 在采集期间断开"
    elif detached_reason and "script" in detached_reason.casefold():
        status = "hook_script_failed"
        cause = "Hook 脚本异常导致会话结束"
    elif detached_reason:
        status = "process_exited"
        cause = "目标进程已退出"
    else:
        status = "unknown_exit"
        cause = "目标进程退出，但现有证据不足以确定原因"
    return ProcessExitDiagnostics(
        status=status,  # type: ignore[arg-type]
        pid=pid,
        duration_ms=duration_ms,
        hook_ready=hook_ready,
        hook_event_count=hook_event_count,
        detached_reason=detached_reason,
        most_likely_cause=cause,
        alternative_explanations=["应用主动退出", "运行时兼容性", "外部终止"],
        confidence="low",
    )
