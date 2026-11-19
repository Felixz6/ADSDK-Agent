"""Task runner execution for persisted, dynamic, and AI-orchestrated tasks."""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from fastapi import HTTPException
from fastapi.responses import JSONResponse

from app.ai.cache import AIResponseCache
from app.ai.orchestrator import (
    AIOrchestrationRequest,
    AIOrchestrator,
)
from app.ai.settings_service import resolve_effective_ai_settings
from app.ai.tool_registry import AIToolRegistry
from app.api.env import env_check
from app.api.errors import _task_not_found
from app.config import OUTPUT_DIR
from app.container import ai_settings_service, task_service
from app.core.artifacts import atomic_write_json
from app.models import AnalyzeRequest, DynamicAnalyzeRequest
from app.pipelines.common import (
    _ai_cancelled,
    _ai_run_dir,
    _public_ai_section,
    task_service_response_payload,
)
from app.pipelines.full_analysis import _run_m7b_full_analysis_session
from app.services import AITaskService
from app.tasks.models import (
    TaskAIArtifactSummary,
    TaskRecord,
)
from app.tasks.runtime import (
    TaskCancelled,
    report_step,
)


def _get_hook(name: str, fallback: Any) -> Any:
    main = sys.modules.get("app.main")
    if main is not None and hasattr(main, name):
        return getattr(main, name)
    return fallback


def _execute_ai_orchestration(
    *,
    task: TaskRecord,
    payload: dict[str, Any],
    run_dir: Path | None,
    base_report: dict[str, Any],
) -> dict[str, Any]:
    """Build and run the orchestrator, returning the public AI section."""
    step_fn = _get_hook("report_step", report_step)
    step_fn("ai_tool_execution", "running", "正在执行 AI 编排工具")
    scope = str(payload.get("analysis_scope") or "static_only")
    allow_dynamic = bool(payload.get("allow_dynamic"))
    confirmed = frozenset(
        str(item) for item in (payload.get("confirmed_tools") or [])
    )
    ai_settings = _get_hook("ai_settings_service", ai_settings_service)
    effective = resolve_effective_ai_settings(ai_settings.store)
    ai_enabled = bool(effective["enabled"]) and bool(payload.get("ai_enabled", True))

    provider = ai_settings.factory.current() if ai_enabled else None
    orchestrator_cls = _get_hook("AIOrchestrator", AIOrchestrator)
    service_cls = _get_hook("AITaskService", AITaskService)
    orchestrator = orchestrator_cls(
        provider=provider,
        registry=AIToolRegistry(allow_dynamic_tools=bool(effective["allow_dynamic_tools"])),
        enabled=ai_enabled,
        cancelled=_ai_cancelled,
    )
    service = service_cls(
        orchestrator=orchestrator,
        run_dir=run_dir or Path(OUTPUT_DIR),
        static_runner=lambda: base_report,
        dynamic_runner=lambda: base_report,
        environment_probe=lambda: env_check(payload.get("device_id")),
    )
    request = AIOrchestrationRequest(
        objective=str(payload.get("objective") or "分析本次 APK 的隐私风险"),
        analysis_scope=scope,
        task_id=task.id,
        allow_dynamic=allow_dynamic,
        allow_network=bool(payload.get("allow_network")),
        confirmed_tools=confirmed,
        token_budget=int(payload.get("token_budget") or 0) or None,
        report_language=str(payload.get("report_language") or effective["report_language"]),
        run_dir=run_dir,
    )
    step_fn("ai_evidence_digest", "running", "正在构建证据摘要")
    result = service.run(request)
    step_fn(
        "ai_report",
        "success" if result.status in {"completed", "partial"} else "partial",
        f"AI 综合研判：{result.status}",
    )
    return _public_ai_section(result)


def _run_ai_orchestrated_task(
    task: TaskRecord,
    payload: dict[str, Any],
) -> dict[str, Any] | JSONResponse:
    """Run one ``ai_orchestrated`` task."""
    from app.pipelines.dynamic import dynamic_analyze
    from app.pipelines.static import analyze

    dynamic_fn = _get_hook("dynamic_analyze", dynamic_analyze)
    analyze_fn = _get_hook("analyze", analyze)
    step_fn = _get_hook("report_step", report_step)

    scope = str(payload.get("analysis_mode") or payload.get("analysis_scope") or "static_only")
    allow_dynamic = bool(payload.get("allow_dynamic"))
    apk_path = str(payload["apk_path"])

    if scope == "full_analysis":
        return _run_m7b_full_analysis_session(task=task, payload=payload)

    step_fn("ai_planning", "running", "正在准备确定性证据")
    deterministic: dict[str, Any] | JSONResponse
    if allow_dynamic and scope in {"dynamic_only", "full_analysis"}:
        dynamic_request = DynamicAnalyzeRequest.model_validate(
            {
                key: value
                for key, value in payload.items()
                if key in DynamicAnalyzeRequest.model_fields
            }
        )
        deterministic = dynamic_fn(dynamic_request)
    else:
        deterministic = analyze_fn(AnalyzeRequest(apk_path=apk_path))

    base_report = task_service_response_payload(deterministic)
    run_dir = _ai_run_dir(base_report)

    ai_section: dict[str, Any]
    try:
        ai_section = _execute_ai_orchestration(
            task=task,
            payload=payload,
            run_dir=run_dir,
            base_report=base_report,
        )
    except TaskCancelled:
        raise
    except Exception as exc:
        ai_section = {
            "status": "failed",
            "error_code": "ai_orchestration_failed",
            "limitations": [f"AI 编排执行异常：{type(exc).__name__}"],
        }

    base_report["ai_orchestration"] = ai_section
    try:
        if run_dir is not None:
            atomic_write_json(run_dir / "report.json", base_report)
    except Exception:
        base_report.setdefault("limitations", []).append(
            "AI 综合研判未能写入 report.json，确定性证据不受影响"
        )
    if isinstance(deterministic, JSONResponse):
        return JSONResponse(
            status_code=deterministic.status_code,
            content=base_report,
        )
    return base_report


def _run_persisted_task(task: TaskRecord):
    from app.pipelines.dynamic import dynamic_analyze
    from app.pipelines.static import analyze

    analyze_fn = _get_hook("analyze", analyze)
    dynamic_fn = _get_hook("dynamic_analyze", dynamic_analyze)
    ai_orch_fn = _get_hook("_run_ai_orchestrated_task", _run_ai_orchestrated_task)

    payload = dict(task.request_payload)
    if task.task_type == "static":
        return analyze_fn(AnalyzeRequest(apk_path=str(payload["apk_path"])))
    if task.task_type == "dynamic":
        return dynamic_fn(DynamicAnalyzeRequest.model_validate(payload))
    if task.task_type == "ai_orchestrated":
        return ai_orch_fn(task, payload)
    raise ValueError(f"unsupported executable task type: {task.task_type}")


def regenerate_task_ai_report(
    task_id: str,
    use_cache: bool | None = None,
):
    """Re-run only the AI orchestration against existing deterministic artifacts."""
    task_svc = _get_hook("task_service", task_service)
    task = task_svc.get(task_id)
    if task is None:
        raise _task_not_found(task_id)

    if not task.report_json_path:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ai_regenerate_no_report",
                "message": "任务尚无可复用的确定性报告，无法仅重跑 AI 编排",
            },
        )
    run_dir = Path(task.report_json_path).resolve(strict=False).parent
    output_dir = _get_hook("OUTPUT_DIR", OUTPUT_DIR)
    allowed_root = (Path(output_dir).resolve(strict=False) / "runs").resolve(
        strict=False
    )
    if not run_dir.is_relative_to(allowed_root) or not (run_dir / "report.json").is_file():
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ai_regenerate_no_report",
                "message": "任务尚无可复用的确定性报告，无法仅重跑 AI 编排",
            },
        )

    payload = dict(task.request_payload or {})
    try:
        base_report = json.loads(
            (run_dir / "report.json").read_text(encoding="utf-8")
        )
    except Exception:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ai_regenerate_no_report",
                "message": "确定性报告读取失败，无法仅重跑 AI 编排",
            },
        )
    if not isinstance(base_report, dict):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ai_regenerate_no_report",
                "message": "确定性报告格式异常，无法仅重跑 AI 编排",
            },
        )

    scope = str(payload.get("analysis_scope") or "static_only")
    allow_dynamic = bool(payload.get("allow_dynamic"))
    confirmed = frozenset(
        str(item) for item in (payload.get("confirmed_tools") or [])
    )
    ai_settings = _get_hook("ai_settings_service", ai_settings_service)
    effective = resolve_effective_ai_settings(ai_settings.store)
    ai_enabled = bool(effective["enabled"]) and bool(payload.get("ai_enabled", True))

    cache_enabled_default = bool(effective["cache_enabled"])
    cache_enabled = (
        cache_enabled_default if use_cache is None else bool(use_cache)
    )

    provider = ai_settings.factory.current() if ai_enabled else None
    orchestrator_cls = _get_hook("AIOrchestrator", AIOrchestrator)
    service_cls = _get_hook("AITaskService", AITaskService)
    orchestrator = orchestrator_cls(
        provider=provider,
        registry=AIToolRegistry(allow_dynamic_tools=bool(effective["allow_dynamic_tools"])),
        cache=AIResponseCache(enabled=cache_enabled),
        enabled=ai_enabled,
        cancelled=_ai_cancelled,
    )
    service = service_cls(
        orchestrator=orchestrator,
        run_dir=run_dir,
        static_runner=lambda: base_report,
        dynamic_runner=lambda: base_report,
        environment_probe=lambda: env_check(payload.get("device_id")),
    )
    request = AIOrchestrationRequest(
        objective=str(payload.get("objective") or "分析本次 APK 的隐私风险"),
        analysis_scope=scope,
        task_id=task.id,
        allow_dynamic=allow_dynamic,
        allow_network=bool(payload.get("allow_network")),
        confirmed_tools=confirmed,
        token_budget=int(payload.get("token_budget") or 0) or None,
        report_language=str(payload.get("report_language") or effective["report_language"]),
        run_dir=run_dir,
    )
    try:
        result = service.run(request)
        ai_section = _public_ai_section(result)
    except TaskCancelled:
        raise
    except Exception as exc:
        ai_section = {
            "schema_version": "ai-report-v1",
            "status": "failed",
            "error_code": "ai_orchestration_failed",
            "limitations": [f"AI 编排执行异常：{type(exc).__name__}"],
        }

    base_report["ai_orchestration"] = ai_section
    try:
        atomic_write_json(run_dir / "report.json", base_report)
    except Exception:
        base_report.setdefault("limitations", []).append(
            "AI 综合研判重跑未能写入 report.json，确定性证据不受影响"
        )

    return TaskAIArtifactSummary(
        task_id=task_id,
        status=task.status,
        ai_status=str(ai_section.get("status")),
        ai_section=ai_section,
    )


__all__ = [
    "_execute_ai_orchestration",
    "_run_ai_orchestrated_task",
    "_run_persisted_task",
    "regenerate_task_ai_report",
]
