"""AI configuration and orchestration API router."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TYPE_CHECKING, Any

from fastapi import APIRouter, Depends, Query
from fastapi.responses import JSONResponse

from app import config as app_config
from app.ai.settings_service import (
    AISettingsValidationError,
    resolve_effective_ai_settings,
)
from app.api.deps import get_ai_settings_service, get_container, get_task_service
from app.api.errors import task_not_found
from app.pipelines.task_runner import (
    regenerate_task_ai_report as run_regenerate_task_ai_report,
)
from app.tasks.models import (
    AISettingsDeleteKeyResponse,
    AISettingsResponse,
    AISettingsSaveRequest,
    AISettingsTestRequest,
    AISettingsTestResponse,
    AIStatusResponse,
    TaskAIArtifactResponse,
    TaskAIArtifactSummary,
)

if TYPE_CHECKING:
    from app.ai.settings_service import AISettingsService
    from app.container import Container
    from app.services import TaskService

router = APIRouter(tags=["ai"])


@router.get("/ai/status", response_model=AIStatusResponse)
def ai_status(
    probe: bool = Query(default=False),
    ai_settings_service: AISettingsService = Depends(get_ai_settings_service),
):
    """Public AI availability.

    Never returns the API key (or any derivative of it). ``reachable`` is only
    evaluated when ``probe=true`` so a page load never calls the external
    model; otherwise it stays ``null`` ("not probed").
    """
    effective = resolve_effective_ai_settings(ai_settings_service.store)
    configured = bool(effective["configured"])
    reachable: bool | None = None
    last_error_code: str | None = None
    if probe and effective["enabled"] and configured:
        provider = ai_settings_service.factory.current()
        if provider is None:
            last_error_code = "ai_provider_build_failed"
        else:
            try:
                reachable, reason = provider.reachable()
                if not reachable:
                    last_error_code = f"ai_provider_{reason or 'unreachable'}"
            except Exception:
                reachable = False
                last_error_code = "ai_provider_unreachable"
    return AIStatusResponse(
        enabled=bool(effective["enabled"]),
        provider=str(effective["provider"] or ""),
        model=str(effective["model"] or ""),
        configured=configured,
        reachable=reachable,
        last_error_code=last_error_code,
        default_token_budget=int(effective["default_token_budget"]),
        max_rounds=int(effective["max_rounds"]),
        max_tool_calls=int(effective["max_tool_calls"]),
        report_language=str(effective["report_language"]),
        allow_dynamic_tools=bool(effective["allow_dynamic_tools"]),
    )


@router.get("/ai/settings", response_model=AISettingsResponse)
def get_ai_settings(
    ai_settings_service: AISettingsService = Depends(get_ai_settings_service),
):
    """Return the masked effective AI configuration.

    The API key is never present. ``api_key_configured`` is the only key-
    derived boolean. Corrupted local settings degrade to defaults rather than
    500.
    """
    try:
        return ai_settings_service.get_effective_settings()
    except Exception:  # pragma: no cover - defensive, never leaks key
        return JSONResponse(
            status_code=500,
            content={
                "detail": "AI 设置不可用",
                "error_code": "ai_settings_unavailable",
            },
        )


@router.put("/ai/settings", response_model=AISettingsResponse)
def update_ai_settings(
    request: AISettingsSaveRequest,
    ai_settings_service: AISettingsService = Depends(get_ai_settings_service),
):
    """Save editable AI configuration + optional new API key. Body is never logged.

    A missing or empty ``api_key`` field preserves the stored key; deletion
    is a separate authenticated action (DELETE /ai/settings/api-key).
    """
    try:
        payload = request.model_dump(exclude_none=False)
        supplied = {}
        if "api_key" in payload and payload["api_key"] is not None:
            supplied["api_key"] = payload["api_key"]
        for key, value in payload.items():
            if key == "api_key":
                continue
            if value is not None:
                supplied[key] = value
        return ai_settings_service.save_settings(supplied)
    except AISettingsValidationError as exc:
        return JSONResponse(
            status_code=422,
            content={"detail": exc.safe_message, **exc.to_dict()},
        )
    except Exception as exc:  # pragma: no cover - defensive
        return JSONResponse(
            status_code=500,
            content={
                "detail": "AI 设置保存失败",
                "error_code": "ai_settings_save_failed",
                "safe_message": type(exc).__name__,
            },
        )


@router.post("/ai/settings/test", response_model=AISettingsTestResponse)
def test_ai_settings(
    request: AISettingsTestRequest,
    ai_settings_service: AISettingsService = Depends(get_ai_settings_service),
):
    """Test the current or a temporary configuration. Temporary key is not saved.

    The request body (which may carry a temporary ``api_key``) is never logged
    and never persisted. The probe tries ``/models`` first, then a minimal
    chat completion (max_tokens=1) for gateways that do not expose ``/models``.
    """
    try:
        temp = request.model_dump(exclude_none=True)
        return ai_settings_service.test_connection(temp)
    except AISettingsValidationError as exc:
        return JSONResponse(
            status_code=422,
            content={"detail": exc.safe_message, **exc.to_dict()},
        )
    except Exception as exc:  # pragma: no cover - defensive
        return JSONResponse(
            status_code=500,
            content={
                "detail": "测试连接失败",
                "error_code": "ai_settings_test_failed",
                "safe_message": type(exc).__name__,
            },
        )


@router.delete("/ai/settings/api-key", response_model=AISettingsDeleteKeyResponse)
def delete_ai_api_key(
    ai_settings_service: AISettingsService = Depends(get_ai_settings_service),
):
    """Delete the locally-saved API key only. An environment-variable key is untouched."""
    deleted = ai_settings_service.delete_api_key()
    source = ai_settings_service.store.api_key_source()
    return AISettingsDeleteKeyResponse(
        deleted=deleted,
        api_key_source=source,  # type: ignore[arg-type]  # runtime source is one of 'none', 'environment', 'local_store'
        api_key_configured=source != "none",
    )


def _read_task_ai_artifact(
    task_id: str,
    filename: str,
    task_service: TaskService,
) -> TaskAIArtifactResponse:
    task = task_service.get(task_id)
    if task is None:
        raise task_not_found(task_id)
    payload: dict[str, Any] | None = None
    if task.report_json_path:
        candidate = Path(task.report_json_path).resolve(strict=False).parent / filename
        allowed = (Path(app_config.OUTPUT_DIR).resolve(strict=False) / "runs").resolve(strict=False)
        if candidate.is_relative_to(allowed) and candidate.is_file():
            try:
                loaded = json.loads(candidate.read_text(encoding="utf-8"))
            except Exception:
                loaded = None
            if isinstance(loaded, dict):
                payload = loaded
    return TaskAIArtifactResponse(
        task_id=task_id,
        status=task.status,
        available=payload is not None,
        payload=payload,
    )


@router.get("/tasks/{task_id}/ai-plan", response_model=TaskAIArtifactResponse)
def get_task_ai_plan(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
):
    return _read_task_ai_artifact(task_id, "ai-plan.json", task_service)


@router.get("/tasks/{task_id}/ai-report", response_model=TaskAIArtifactResponse)
def get_task_ai_report(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
):
    return _read_task_ai_artifact(task_id, "ai-report.json", task_service)


@router.get(
    "/tasks/{task_id}/ai-runtime-diagnostics",
    response_model=TaskAIArtifactResponse,
)
def get_task_ai_runtime_diagnostics(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
):
    """The ``ai-runtime-diagnostics-v1`` artifact."""
    return _read_task_ai_artifact(task_id, "ai-runtime-diagnostics.json", task_service)


@router.post(
    "/tasks/{task_id}/ai-report/regenerate",
    response_model=TaskAIArtifactSummary,
)
def regenerate_task_ai_report(
    task_id: str,
    container: Container = Depends(get_container),
    use_cache: bool | None = None,
):
    return run_regenerate_task_ai_report(task_id, use_cache=use_cache, container=container)
