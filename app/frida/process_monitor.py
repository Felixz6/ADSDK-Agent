"""Bounded process-exit and native-crash classification."""

from __future__ import annotations

import re
from typing import Any, Literal

from pydantic import BaseModel, Field


_FATAL_SIGNAL = re.compile(
    r"Fatal signal\s+(?P<number>\d+)\s+\((?P<signal>SIG[A-Z0-9]+)\),"
    r"\s+code\s+(?P<code_number>-?\d+)\s+\((?P<signal_code>[A-Z0-9_]+)\)"
    r"(?:,\s+fault addr\s+(?P<fault_address>0x[0-9a-fA-F]+))?"
)
_CAUSE = re.compile(r"(?:Cause|Abort message):\s*['\"]?(?P<summary>[^\r\n'\"]+)")
_PROCESS = re.compile(
    r"(?m)^[^\r\n]*>>>\s*(?P<process>[^\r\n<]+?)\s*<<<"
)
_THREAD = re.compile(
    r"(?m)^[^\r\n]*\bname:\s*(?P<thread>[^\r\n>]+?)\s+>>>"
)
_NATIVE_FRAME = re.compile(r"^\s*#\d+\s+pc\s+.+$", re.IGNORECASE)


class ProcessExitDiagnostics(BaseModel):
    schema_version: Literal["process-diagnostics-v2"] = "process-diagnostics-v2"
    status: Literal[
        "running",
        "normal_cleanup",
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
    reason_code: str | None = None
    crash_type: str | None = None
    signal: str | None = None
    signal_code: str | None = None
    fault_address: str | None = None
    process_name: str | None = None
    thread_name: str | None = None
    process_uptime: float | None = Field(default=None, ge=0)
    native_frames: list[str] = Field(default_factory=list)
    suspected_components: list[str] = Field(default_factory=list)
    summary: str | None = None
    alternative_explanations: list[str] = Field(default_factory=list)
    supporting_evidence: list[str] = Field(default_factory=list)
    confidence: Literal["low", "medium", "high"] = "low"
    normal_launch_survived: bool | None = None
    normal_launch_observation_seconds: float | None = Field(default=None, ge=0)
    normal_launch_crash_signature: str | None = None
    correlation_assessment: str | None = None


def _crash_text(crash: dict[str, Any] | None) -> str:
    if not crash:
        return ""
    values: list[str] = []
    for key in ("summary", "report", "description", "message"):
        value = crash.get(key)
        if isinstance(value, str):
            values.append(value)
    return "\n".join(values)


def _native_crash(
    *,
    pid: int | None,
    duration_ms: int | None,
    hook_ready: bool,
    hook_event_count: int,
    detached_reason: str | None,
    lines: list[str],
    normal_launch_survived: bool | None,
    normal_launch_observation_seconds: float | None,
    normal_launch_crash_signature: str | None,
) -> ProcessExitDiagnostics | None:
    joined = "\n".join(lines)
    match = _FATAL_SIGNAL.search(joined)
    if match is None and "sigsegv" not in joined.casefold():
        return None

    signal = match.group("signal") if match else "SIGSEGV"
    signal_code = match.group("signal_code") if match else None
    fault_address = match.group("fault_address") if match else None
    cause_match = _CAUSE.search(joined)
    summary = cause_match.group("summary").strip() if cause_match else None
    if summary is None and "non-executable memory" in joined.casefold():
        summary = "trying to execute non-executable memory"
    process_match = _PROCESS.search(joined)
    thread_match = _THREAD.search(joined)
    native_frames = [
        line.strip()
        for line in lines
        if _NATIVE_FRAME.match(line)
    ]
    folded = joined.casefold()
    components: list[str] = []
    for marker, label in (
        ("libhoudini.so", "libhoudini.so"),
        ("libhp15_x86_64.so", "libhp15_x86_64.so"),
        ("com.tencent.mmkv", "MMKV"),
        ("mmkv.initialize", "MMKV"),
    ):
        if marker in folded and label not in components:
            components.append(label)

    evidence = [f"native fatal signal: {signal}"]
    if signal_code:
        evidence.append(f"signal code: {signal_code}")
    if summary:
        evidence.append(f"cause: {summary}")
    if components:
        evidence.append("components: " + ", ".join(components))

    correlation = None
    if (
        normal_launch_survived is True
        and normal_launch_crash_signature in {None, ""}
        and signal == "SIGSEGV"
    ):
        correlation = "崩溃与 suspended-spawn 路径相关性较高；现有证据不构成单一根因证明。"

    if {"libhoudini.so", "libhp15_x86_64.so", "MMKV"}.intersection(components):
        cause = (
            "应用在 suspended spawn 恢复后发生原生崩溃，崩溃栈涉及 MuMu "
            "Native Bridge 与 MMKV。普通启动和运行中附加均正常，疑似为 "
            "suspended-spawn 与当前模拟器翻译环境的兼容性问题。"
        )
        reason_code = "native_bridge_compatibility_suspected"
    else:
        cause = "目标应用在恢复后的观察窗口内发生原生崩溃"
        reason_code = "native_runtime_crash"

    return ProcessExitDiagnostics(
        status="process_crashed",
        pid=pid,
        duration_ms=duration_ms,
        hook_ready=hook_ready,
        hook_event_count=hook_event_count,
        detached_reason=detached_reason,
        most_likely_cause=cause,
        reason_code=reason_code,
        crash_type="native_sigsegv" if signal == "SIGSEGV" else "native_signal",
        signal=signal,
        signal_code=signal_code,
        fault_address=fault_address,
        process_name=(
            process_match.group("process").strip() if process_match else None
        ),
        thread_name=thread_match.group("thread").strip() if thread_match else None,
        process_uptime=(duration_ms / 1000.0 if duration_ms is not None else None),
        native_frames=native_frames,
        suspected_components=components,
        summary=summary,
        alternative_explanations=[
            "模拟器 Native Bridge 兼容性",
            "应用或原生依赖自身缺陷",
            "Frida 与目标运行时组合问题",
        ],
        supporting_evidence=evidence,
        confidence="high" if match else "medium",
        normal_launch_survived=normal_launch_survived,
        normal_launch_observation_seconds=normal_launch_observation_seconds,
        normal_launch_crash_signature=normal_launch_crash_signature,
        correlation_assessment=correlation,
    )


def classify_process_exit(
    *,
    pid: int | None,
    duration_ms: int | None,
    hook_ready: bool,
    hook_event_count: int,
    detached_reason: str | None,
    logcat_lines: list[str],
    process_still_running: bool,
    crash: dict[str, Any] | None = None,
    normal_launch_survived: bool | None = None,
    normal_launch_observation_seconds: float | None = None,
    normal_launch_crash_signature: str | None = None,
) -> ProcessExitDiagnostics:
    """Classify only signals observed in this owned session."""

    crash_lines = _crash_text(crash).splitlines()
    lines = [*logcat_lines, *crash_lines]
    native = _native_crash(
        pid=pid,
        duration_ms=duration_ms,
        hook_ready=hook_ready,
        hook_event_count=hook_event_count,
        detached_reason=detached_reason,
        lines=lines,
        normal_launch_survived=normal_launch_survived,
        normal_launch_observation_seconds=normal_launch_observation_seconds,
        normal_launch_crash_signature=normal_launch_crash_signature,
    )
    if native is not None:
        return native

    normalized_reason = (detached_reason or "").casefold()
    if normalized_reason == "application-requested" and not crash:
        return ProcessExitDiagnostics(
            status="normal_cleanup",
            pid=pid,
            duration_ms=duration_ms,
            hook_ready=hook_ready,
            hook_event_count=hook_event_count,
            detached_reason=detached_reason,
            most_likely_cause="会话由采集流程主动分离，属于正常清理",
            reason_code="application_requested_detach",
            confidence="high",
        )
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

    text = "\n".join(lines).casefold()
    evidence: list[str] = []
    if "fatal exception" in text or "tombstone" in text:
        if "fatal exception" in text:
            evidence.append("Android Runtime FATAL EXCEPTION")
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
            reason_code="process_crashed",
            alternative_explanations=["运行时兼容性问题", "应用自身缺陷"],
            supporting_evidence=evidence,
            confidence="high",
        )
    if "force stopping" in text or "killing " in text or "killed" in text:
        return ProcessExitDiagnostics(
            status="process_killed",
            pid=pid,
            duration_ms=duration_ms,
            hook_ready=hook_ready,
            hook_event_count=hook_event_count,
            detached_reason=detached_reason,
            most_likely_cause="目标进程被系统或外部操作终止",
            reason_code="process_killed",
            alternative_explanations=["系统资源回收", "用户或测试流程停止应用"],
            supporting_evidence=["logcat process kill/force-stop signal"],
            confidence="medium",
        )
    if detached_reason and "connection" in normalized_reason:
        status = "transport_lost"
        cause = "Frida transport 在采集期间断开"
    elif detached_reason and "script" in normalized_reason:
        status = "hook_script_failed"
        cause = "Hook 脚本异常导致会话结束"
    elif detached_reason:
        status = "process_exited"
        cause = "目标进程已退出"
    else:
        status = "unknown_exit"
        cause = "目标进程退出，现有证据不足以确定原因"
    return ProcessExitDiagnostics(
        status=status,  # type: ignore[arg-type]
        pid=pid,
        duration_ms=duration_ms,
        hook_ready=hook_ready,
        hook_event_count=hook_event_count,
        detached_reason=detached_reason,
        most_likely_cause=cause,
        reason_code=status,
        alternative_explanations=["应用主动退出", "运行时兼容性", "外部终止"],
        confidence="low",
    )
