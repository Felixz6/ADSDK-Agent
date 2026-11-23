"""Tasks and WebSocket progress API router."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import TYPE_CHECKING

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    Query,
    WebSocket,
    WebSocketDisconnect,
)
from fastapi.responses import FileResponse

from app import config as app_config
from app.api.deps import (
    get_consent_checkpoint_service,
    get_task_repository,
    get_task_service,
)
from app.api.errors import task_not_found
from app.api.middleware import is_websocket_allowed
from app.orchestration.consent_checkpoint import (
    ConsentCheckpointError,
    ConsentCheckpointRequest,
    ConsentCheckpointState,
)
from app.tasks.models import (
    TaskActionResponse,
    TaskCreateRequest,
    TaskListResponse,
    TaskRecord,
    TaskReportResponse,
    TaskSystemStatus,
)

if TYPE_CHECKING:
    from app.orchestration.consent_checkpoint import ConsentCheckpointService
    from app.repositories import TaskRepository
    from app.services import TaskService

router = APIRouter(tags=["tasks"])


@router.post("/tasks", response_model=TaskRecord, status_code=202)
def create_task(
    request: TaskCreateRequest,
    task_service: TaskService = Depends(get_task_service),
):
    return task_service.create(request)


@router.get("/tasks", response_model=TaskListResponse)
def list_tasks(
    status: str | None = Query(default=None),
    task_type: str | None = Query(default=None),
    keyword: str | None = Query(default=None, max_length=256),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort: str = Query(default="-created_at"),
    task_service: TaskService = Depends(get_task_service),
):
    allowed_statuses = {"queued", "running", "completed", "failed", "cancelled"}
    allowed_types = {"static", "dynamic", "comparison", "ai_orchestrated"}
    if status and status not in allowed_statuses:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_status", "message": "任务状态筛选值无效"},
        )
    if task_type and task_type not in allowed_types:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_task_type", "message": "任务类型筛选值无效"},
        )
    return task_service.list(
        status=status,
        task_type=task_type,
        keyword=keyword,
        page=page,
        page_size=page_size,
        sort=sort,
    )


@router.get("/tasks/system/status", response_model=TaskSystemStatus)
def task_system_status(
    task_service: TaskService = Depends(get_task_service),
    task_repository: TaskRepository = Depends(get_task_repository),
):
    running = task_service.list(status="running", page=1, page_size=1).total
    queued = task_service.list(status="queued", page=1, page_size=1).total
    return TaskSystemStatus(
        database_ok=True,
        database_path=str(task_repository.database_path),
        running_tasks=running,
        queued_tasks=queued,
        occupied_devices=task_service.occupied_devices(),
    )


@router.get("/tasks/{task_id}", response_model=TaskRecord)
def get_task(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
):
    task = task_service.get(task_id)
    if task is None:
        raise task_not_found(task_id)
    return task


@router.get("/tasks/{task_id}/report", response_model=TaskReportResponse)
def get_task_report(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
):
    try:
        return task_service.report(task_id)
    except KeyError:
        raise task_not_found(task_id)


@router.post("/tasks/{task_id}/cancel", response_model=TaskActionResponse)
def cancel_task(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
    consent_checkpoint_service: ConsentCheckpointService = Depends(get_consent_checkpoint_service),
):
    try:
        result = task_service.cancel(task_id)
    except KeyError:
        raise task_not_found(task_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "task_not_cancellable", "message": str(exc)},
        )
    consent_checkpoint_service.cancel(task_id=task_id)
    return result


@router.post("/tasks/{task_id}/retry", response_model=TaskActionResponse, status_code=202)
def retry_task(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
):
    try:
        return task_service.retry(task_id)
    except KeyError:
        raise task_not_found(task_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "task_not_retryable", "message": str(exc)},
        )


@router.get(
    "/tasks/{task_id}/consent-checkpoint",
    response_model=ConsentCheckpointState,
)
def get_consent_checkpoint(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
    consent_checkpoint_service: ConsentCheckpointService = Depends(get_consent_checkpoint_service),
):
    if task_service.get(task_id) is None:
        raise task_not_found(task_id)
    state = consent_checkpoint_service.state(task_id)
    if state is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "checkpoint_not_found",
                "message": "该任务当前没有等待中的 Consent 检查点",
            },
        )
    return state


@router.post(
    "/tasks/{task_id}/consent-checkpoint",
    response_model=ConsentCheckpointState,
)
def resolve_consent_checkpoint(
    task_id: str,
    req: ConsentCheckpointRequest,
    task_service: TaskService = Depends(get_task_service),
    consent_checkpoint_service: ConsentCheckpointService = Depends(get_consent_checkpoint_service),
):
    if task_service.get(task_id) is None:
        raise task_not_found(task_id)
    try:
        return consent_checkpoint_service.resolve(
            task_id=task_id,
            action=req.action,
            note=req.note,
        )
    except ConsentCheckpointError as exc:
        status_code = 404 if exc.code == "checkpoint_not_found" else 409
        raise HTTPException(
            status_code=status_code,
            detail={"code": exc.code, "message": exc.message},
        )


@router.delete("/tasks/{task_id}", status_code=204)
def delete_task(
    task_id: str,
    task_service: TaskService = Depends(get_task_service),
):
    try:
        deleted = task_service.delete(task_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "active_task", "message": str(exc)},
        )
    if not deleted:
        raise task_not_found(task_id)
    return None


@router.get("/tasks/{task_id}/artifacts/{artifact_kind}")
def download_task_artifact(
    task_id: str,
    artifact_kind: str,
    task_service: TaskService = Depends(get_task_service),
):
    task = task_service.get(task_id)
    if task is None:
        raise task_not_found(task_id)
    field_map = {
        "json": (task.report_json_path, "application/json", "report.json"),
        "markdown": (task.report_markdown_path, "text/markdown", "report.md"),
        "html": (task.report_html_path, "text/html", "report.html"),
    }
    if artifact_kind not in field_map:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_artifact_kind", "message": "报告格式无效"},
        )
    path_text, media_type, filename = field_map[artifact_kind]
    if not path_text:
        raise HTTPException(
            status_code=404,
            detail={"code": "artifact_not_found", "message": "报告产物尚未生成"},
        )
    path = Path(path_text).resolve(strict=False)
    allowed = (Path(app_config.OUTPUT_DIR).resolve(strict=False) / "runs").resolve(strict=False)
    if not path.is_relative_to(allowed) or not path.is_file():
        raise HTTPException(
            status_code=404,
            detail={"code": "artifact_not_found", "message": "报告产物不存在"},
        )
    return FileResponse(path, media_type=media_type, filename=filename)


@router.websocket("/ws/tasks/{task_id}")
async def task_progress_websocket(
    websocket: WebSocket,
    task_id: str,
    task_svc: TaskService = Depends(get_task_service),
):
    client_host = websocket.client.host if websocket.client else None
    origin = websocket.headers.get("origin")
    if not is_websocket_allowed(client_host, origin):
        await websocket.close(code=1008)
        return
    await websocket.accept()
    loop = asyncio.get_running_loop()
    notify_event = asyncio.Event()
    task_svc.subscribe(task_id, loop, notify_event)
    last_fingerprint: tuple[str, str, int, int] | None = None
    try:
        while True:
            notify_event.clear()
            task = await asyncio.to_thread(task_svc.get, task_id)
            if task is None:
                await websocket.send_json(
                    {"error": {"code": "task_not_found", "message": "任务不存在"}}
                )
                await websocket.close(code=4404)
                return
            fingerprint = (
                task.updated_at,
                task.status,
                task.progress_percent,
                len(task.steps),
            )
            if fingerprint != last_fingerprint:
                await websocket.send_json(task.model_dump(mode="json"))
                last_fingerprint = fingerprint
            if task.status in {"completed", "failed", "cancelled"}:
                await websocket.close(code=1000)
                return
            try:
                await asyncio.wait_for(notify_event.wait(), timeout=5.0)
            except TimeoutError:
                pass
    except WebSocketDisconnect:
        pass
    finally:
        task_svc.unsubscribe(task_id, loop, notify_event)
