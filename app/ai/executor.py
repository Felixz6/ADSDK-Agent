"""DAG-based tool execution for AI orchestrated plans."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from app.core.clock import utc_now_iso as _utc_now_iso

from .context_builder import enforce_result_char_limit
from .models import (
    AIOrchestrationRequest,
    AIPlan,
    AIToolTrace,
    AIToolTraceStep,
    PlanStep,
    ToolCompactResult,
    ToolErrorDetail,
)
from .tool_registry import AIToolRegistry, InvalidToolArgumentsError

ToolExecutor = Callable[[str, dict[str, Any]], ToolCompactResult]


class AIPlanExecutor:
    """Execute plan steps sequentially, respecting cancellation and limits."""

    def __init__(
        self,
        *,
        registry: AIToolRegistry,
        cancelled: Callable[[], bool],
        max_tool_calls: int,
        max_tool_result_chars: int = 16000,
    ) -> None:
        self._registry = registry
        self._cancelled = cancelled
        self._max_tool_calls = max_tool_calls
        self._max_tool_result_chars = max_tool_result_chars

    def execute_plan(
        self,
        plan: AIPlan,
        request: AIOrchestrationRequest,
        execute_tool: ToolExecutor,
        trace: AIToolTrace,
        usage: Any,
    ) -> tuple[list[ToolCompactResult], AIToolTrace]:
        results: list[ToolCompactResult] = []
        steps: list[AIToolTraceStep] = []
        executed = 0

        for step in plan.steps:
            if self._cancelled():
                steps.append(
                    AIToolTraceStep(
                        step_id=step.step_id,
                        tool_name=step.tool_name,
                        status="not_run",
                        safe_summary="任务已取消，未启动该工具",
                    )
                )
                continue
            if executed >= self._max_tool_calls:
                steps.append(
                    AIToolTraceStep(
                        step_id=step.step_id,
                        tool_name=step.tool_name,
                        status="not_run",
                        safe_summary="达到工具调用上限，未执行",
                    )
                )
                continue

            started_at = _utc_now_iso()
            result, trace_status, safe_summary = self._execute_step(
                step, request, execute_tool
            )
            if result.status != "not_run":
                executed += 1
            results.append(result)
            steps.append(
                AIToolTraceStep(
                    step_id=step.step_id,
                    tool_name=step.tool_name,
                    started_at=started_at,
                    ended_at=_utc_now_iso(),
                    status=trace_status,
                    safe_summary=safe_summary,
                    artifact_refs=[ref.path for ref in result.artifact_refs],
                    reused=result.reused,
                    confirmation_required=result.confirmation_required,
                    decision_summary=result.decision_summary,
                )
            )
        return results, trace.model_copy(update={"steps": steps})

    def _execute_step(
        self,
        step: PlanStep,
        request: AIOrchestrationRequest,
        execute_tool: ToolExecutor,
    ) -> tuple[ToolCompactResult, str, str]:
        tool_name = step.tool_name
        # Unknown tools are refused before anything runs.
        if not self._registry.has(tool_name):
            result = ToolCompactResult(
                tool_name=tool_name,
                status="failed",
                summary="未注册的工具已被拒绝执行",
                error=ToolErrorDetail(
                    error_code="ai_unknown_tool",
                    safe_message="tool is not in the whitelist",
                    stage="tool_dispatch",
                ),
            )
            return result, "failed", "未注册的工具已被拒绝"

        try:
            arguments = self._registry.validate_arguments(tool_name, step.arguments)
        except InvalidToolArgumentsError as exc:
            result = ToolCompactResult(
                tool_name=tool_name,
                status="failed",
                summary="工具参数未通过校验，已拒绝执行",
                error=ToolErrorDetail(
                    error_code=exc.code,
                    safe_message=exc.detail[:200],
                    stage="tool_dispatch",
                ),
            )
            return result, "failed", "工具参数校验失败"

        # device_state_change requires explicit confirmation.
        if self._registry.requires_confirmation(tool_name):
            confirmed = (
                tool_name in request.confirmed_tools and request.allow_dynamic
            )
            if not confirmed:
                result = ToolCompactResult(
                    tool_name=tool_name,
                    status="blocked_confirmation_required",
                    summary="该工具会改变设备状态，需显式确认后才能执行",
                    confirmation_required=True,
                    limitations=["未获确认，本次未执行设备状态变更类工具"],
                )
                return (
                    result,
                    "blocked_confirmation_required",
                    "需要确认，未执行",
                )

        try:
            raw = execute_tool(tool_name, arguments)
        except Exception as exc:  # tool isolation: never break the task
            result = ToolCompactResult(
                tool_name=tool_name,
                status="failed",
                summary="工具执行异常，已隔离",
                error=ToolErrorDetail(
                    error_code="ai_tool_execution_failed",
                    safe_message=f"{type(exc).__name__}",
                    stage="tool_execution",
                    retryable=False,
                ),
            )
            return result, "failed", "工具执行异常"

        bounded = enforce_result_char_limit(raw, self._max_tool_result_chars)
        return bounded, bounded.status, bounded.summary[:280]


__all__ = ["AIPlanExecutor", "ToolExecutor"]
