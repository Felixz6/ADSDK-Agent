"""Deterministic execution-mode selection and explainable evidence grading."""

from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


class DynamicModePolicy(str, Enum):
    STRICT = "strict"
    BALANCED = "balanced"
    ATTACH_ONLY = "attach_only"


class ExecutionMode(str, Enum):
    SPAWN_SUSPENDED = "spawn_suspended"
    SPAWN = "spawn"
    ATTACH_EXISTING = "attach_existing"
    LAUNCH_THEN_ATTACH = "launch_then_attach"
    NONE = "none"


class ExecutionAttempt(BaseModel):
    mode: ExecutionMode
    status: Literal["running", "success", "failed", "skipped"]
    reason_code: str | None = None
    message: str
    phase: str | None = None
    process_result: str | None = None
    post_resume_survival_ms: int | None = Field(default=None, ge=0)
    timestamps: dict[str, Any] = Field(default_factory=dict)
    crash: dict[str, Any] | None = None


class ExecutionModeDecision(BaseModel):
    policy: DynamicModePolicy
    selected_mode: ExecutionMode
    attempts: list[ExecutionAttempt] = Field(default_factory=list)
    fallback_path: list[ExecutionMode] = Field(default_factory=list)
    blocked_reason: str | None = None


class DynamicEvidenceQuality(BaseModel):
    schema_version: Literal["dynamic-evidence-quality-v1"] = (
        "dynamic-evidence-quality-v1"
    )
    level: Literal["A", "B", "C", "D"]
    mode: ExecutionMode
    coverage: list[str]
    limitations: list[str]
    trusted_capabilities: list[str]
    untrusted_capabilities: list[str]
    reason_codes: list[str]


def select_execution_mode(
    policy: DynamicModePolicy,
    *,
    spawn_suspended_ready: bool,
    spawn_ready: bool = False,
    existing_process: bool = False,
    launch_attach_ready: bool = False,
    failure_codes: dict[ExecutionMode, str] | None = None,
) -> ExecutionModeDecision:
    """Select a real mode without hiding failed attempts."""

    failures = failure_codes or {}
    attempts: list[ExecutionAttempt] = []

    def attempt(mode: ExecutionMode, ready: bool) -> bool:
        attempts.append(
            ExecutionAttempt(
                mode=mode,
                status="success" if ready else "failed",
                reason_code=None if ready else failures.get(mode, f"{mode.value}_failed"),
                message=(
                    f"{mode.value} 可用"
                    if ready
                    else f"{mode.value} 不可用，已保留失败证据"
                ),
            )
        )
        return ready

    if policy is DynamicModePolicy.ATTACH_ONLY:
        if attempt(ExecutionMode.ATTACH_EXISTING, existing_process):
            return ExecutionModeDecision(
                policy=policy,
                selected_mode=ExecutionMode.ATTACH_EXISTING,
                attempts=attempts,
            )
        return ExecutionModeDecision(
            policy=policy,
            selected_mode=ExecutionMode.NONE,
            attempts=attempts,
            blocked_reason="package_process_not_found",
        )

    if attempt(ExecutionMode.SPAWN_SUSPENDED, spawn_suspended_ready):
        return ExecutionModeDecision(
            policy=policy,
            selected_mode=ExecutionMode.SPAWN_SUSPENDED,
            attempts=attempts,
        )
    if policy is DynamicModePolicy.STRICT:
        return ExecutionModeDecision(
            policy=policy,
            selected_mode=ExecutionMode.NONE,
            attempts=attempts,
            blocked_reason=attempts[-1].reason_code,
        )

    fallback: list[ExecutionMode] = []
    for mode, ready in (
        (ExecutionMode.SPAWN, spawn_ready),
        (ExecutionMode.ATTACH_EXISTING, existing_process),
        (ExecutionMode.LAUNCH_THEN_ATTACH, launch_attach_ready),
    ):
        fallback.append(mode)
        if attempt(mode, ready):
            return ExecutionModeDecision(
                policy=policy,
                selected_mode=mode,
                attempts=attempts,
                fallback_path=fallback,
            )
    return ExecutionModeDecision(
        policy=policy,
        selected_mode=ExecutionMode.NONE,
        attempts=attempts,
        fallback_path=fallback,
        blocked_reason=attempts[-1].reason_code,
    )


def build_evidence_quality(
    mode: ExecutionMode,
    *,
    transport_trusted: bool,
    hook_ready_trusted: bool,
    event_protocol_trusted: bool,
    consent_boundary_trusted: bool,
    network_evidence: bool,
    reason_codes: list[str] | None = None,
    early_lifecycle_verified: bool = False,
) -> DynamicEvidenceQuality:
    reasons = list(dict.fromkeys(reason_codes or []))
    if (
        mode is ExecutionMode.SPAWN_SUSPENDED
        and transport_trusted
        and hook_ready_trusted
        and event_protocol_trusted
        and consent_boundary_trusted
    ):
        level: Literal["A", "B", "C", "D"] = "A"
    elif (
        mode is ExecutionMode.SPAWN
        and hook_ready_trusted
        and event_protocol_trusted
    ):
        level = "B"
    elif (
        mode is ExecutionMode.LAUNCH_THEN_ATTACH
        and early_lifecycle_verified
        and hook_ready_trusted
        and event_protocol_trusted
    ):
        level = "B"
    elif (
        mode in {ExecutionMode.ATTACH_EXISTING, ExecutionMode.LAUNCH_THEN_ATTACH}
        and event_protocol_trusted
    ):
        level = "C"
    else:
        level = "D"

    coverage = ["静态证据"]
    trusted = ["静态清单与 SDK 证据"]
    limitations: list[str] = []
    untrusted: list[str] = []
    if hook_ready_trusted and event_protocol_trusted:
        coverage.append("Hook 就绪后的运行时事件")
        trusted.append("结构化 Hook 事件协议")
    else:
        limitations.append("缺少可信 Frida 动态事件")
        untrusted.append("进程内 API 行为")
    if network_evidence:
        coverage.append("采集窗口内的网络侧证据")
        trusted.append("网络采集器实际观察结果")
    else:
        limitations.append("网络侧覆盖不可用或未观察到请求")
        untrusted.append("未被观察到的网络行为")
    if mode is not ExecutionMode.SPAWN_SUSPENDED:
        limitations.append("无法证明应用启动阶段行为完整")
        untrusted.append("启动前与早期启动阶段")
    if mode is ExecutionMode.ATTACH_EXISTING:
        limitations.extend(
            [
                "只能分析附加后的行为",
                "无法证明 Consent 前最早阶段完整",
            ]
        )
    if mode is ExecutionMode.LAUNCH_THEN_ATTACH and not early_lifecycle_verified:
        limitations.append("正常启动到 Attach 完成之间存在启动覆盖间隙")
    if not consent_boundary_trusted:
        limitations.append("Consent 前后时间边界不完整")
        untrusted.append("完整 Consent 前覆盖")
    return DynamicEvidenceQuality(
        level=level,
        mode=mode,
        coverage=coverage,
        limitations=list(dict.fromkeys(limitations)),
        trusted_capabilities=list(dict.fromkeys(trusted)),
        untrusted_capabilities=list(dict.fromkeys(untrusted)),
        reason_codes=reasons,
    )
