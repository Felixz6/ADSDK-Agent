from __future__ import annotations

import json
import threading
from concurrent.futures import Future, ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from uuid import uuid4

from fastapi.responses import JSONResponse

from app.core.redaction import Redactor
from app.repositories.task_repository import TaskRepository, utc_now
from app.tasks.models import (
    TaskActionResponse,
    TaskCreateRequest,
    TaskListResponse,
    TaskRecord,
    TaskReportResponse,
)
from app.tasks.runtime import (
    TaskCancelled,
    TaskExecutionContext,
    bind_task_context,
    request_cancel,
    reset_task_context,
)


TaskRunner = Callable[[TaskRecord], dict[str, Any] | JSONResponse]

_STATIC_PROGRESS = {
    "apk_validation": 8,
    "apk_hash": 14,
    "apk_snapshot": 22,
    "apk_unpack": 48,
    "manifest_parse": 62,
    "sdk_scan": 76,
    "report_write": 96,
}
_DYNAMIC_PROGRESS = {
    **_STATIC_PROGRESS,
    "device_selection": 50,
    "apk_install": 57,
    "frida_spawn": 63,
    "frida_script_load": 68,
    "frida_ready": 72,
    "mitm_start": 75,
    "collection_start": 78,
    "app_resume": 81,
    "consent_boundary": 85,
    "event_validation": 88,
    "resource_cleanup": 91,
    "rule_evaluation": 94,
    "report_write": 97,
}


class TaskService:
    def __init__(
        self,
        repository: TaskRepository,
        *,
        max_workers: int = 3,
    ) -> None:
        self.repository = repository
        self.repository.initialize()
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="adsdk-task",
        )
        self._runner: TaskRunner | None = None
        self._futures: dict[str, Future[None]] = {}
        self._cancel_events: dict[str, threading.Event] = {}
        self._device_locks: dict[str, threading.Lock] = {}
        self._lock = threading.RLock()

    def set_runner(self, runner: TaskRunner) -> None:
        self._runner = runner

    def create(self, request: TaskCreateRequest) -> TaskRecord:
        task_id = str(uuid4())
        payload = request.model_dump(mode="json")
        public_device_id = Redactor().redact_identifier(
            request.device_id,
            kind="device_serial",
        )
        task = self.repository.create_task(
            {
                "id": task_id,
                **payload,
                "device_id": public_device_id,
                "request_payload": payload,
            }
        )
        self.enqueue(task.id)
        return task

    def enqueue(self, task_id: str) -> None:
        if self._runner is None:
            raise RuntimeError("task runner is not configured")
        with self._lock:
            if task_id in self._futures and not self._futures[task_id].done():
                return
            cancel_event = threading.Event()
            self._cancel_events[task_id] = cancel_event
            self._futures[task_id] = self._pool.submit(
                self._execute,
                task_id,
                cancel_event,
            )

    def _execute(self, task_id: str, cancel_event: threading.Event) -> None:
        task = self.repository.get_task(task_id)
        if task is None:
            return
        private_payload = self.repository.get_request_payload(task_id)
        task = task.model_copy(update={"request_payload": private_payload})
        device_lock: threading.Lock | None = None
        if task.task_type == "dynamic":
            key = task.device_id or "__unselected_device__"
            with self._lock:
                device_lock = self._device_locks.setdefault(key, threading.Lock())
            device_lock.acquire()
        token = None
        def release_device() -> None:
            nonlocal device_lock
            if device_lock is not None:
                device_lock.release()
                device_lock = None

        try:
            if cancel_event.is_set():
                raise TaskCancelled()
            self.repository.update_task(
                task_id,
                status="running",
                progress_percent=1,
                current_stage="input_validation",
                started_at=utc_now(),
                error_code=None,
                error_message=None,
            )
            context = TaskExecutionContext(
                task_id=task_id,
                cancel_event=cancel_event,
                progress=lambda key, status, message: self._record_progress(
                    task_id,
                    task.task_type,
                    key,
                    status,
                    message,
                ),
            )
            token = bind_task_context(context)
            assert self._runner is not None
            raw_result = self._runner(task)
            result = self._response_payload(raw_result)
            if cancel_event.is_set():
                raise TaskCancelled()
            failed = result.get("status") == "failed" or result.get("ok") is False
            app_info = result.get("app_info") or {}
            risk = result.get("risk_summary") or {}
            release_device()
            self.repository.update_task(
                task_id,
                status="failed" if failed else "completed",
                progress_percent=100,
                current_stage="failed" if failed else "completed",
                completed_at=utc_now(),
                error_code=result.get("error_code"),
                error_message=result.get("error"),
                apk_snapshot_path=(result.get("apk_snapshot") or {}).get(
                    "snapshot_relative_path"
                ),
                apk_sha256=result.get("apk_sha256"),
                package_name=app_info.get("package_name") or task.package_name,
                app_name=app_info.get("application_label"),
                version_name=app_info.get("version_name"),
                version_code=app_info.get("version_code"),
                report_json_path=result.get("report_json"),
                report_markdown_path=result.get("report_md"),
                report_html_path=result.get("report_html"),
                risk_score=risk.get("score"),
                risk_level=risk.get("level"),
            )
        except TaskCancelled:
            release_device()
            current = self.repository.get_task(task_id, include_steps=False)
            cancelled_at_stage = (
                current.current_stage
                if current and current.current_stage not in {None, "cancelled"}
                else None
            )
            self.repository.update_task(
                task_id,
                status="cancelled",
                current_stage="cancelled",
                cancelled_at_stage=cancelled_at_stage,
                completed_at=utc_now(),
                error_code="task_cancelled",
                error_message="任务已按请求取消，已执行资源清理",
            )
        except Exception as exc:
            release_device()
            self.repository.update_task(
                task_id,
                status="failed",
                current_stage="failed",
                completed_at=utc_now(),
                error_code="task_execution_failed",
                error_message=f"后台任务执行失败: {type(exc).__name__}",
            )
        finally:
            if token is not None:
                reset_task_context(token)
            release_device()
            with self._lock:
                self._cancel_events.pop(task_id, None)

    @staticmethod
    def _response_payload(
        result: dict[str, Any] | JSONResponse,
    ) -> dict[str, Any]:
        if isinstance(result, JSONResponse):
            return json.loads(result.body.decode("utf-8"))
        return dict(result)

    def _record_progress(
        self,
        task_id: str,
        task_type: str,
        step_key: str,
        status: str,
        message: str | None,
    ) -> None:
        progress_map = _DYNAMIC_PROGRESS if task_type == "dynamic" else _STATIC_PROGRESS
        progress = progress_map.get(step_key)
        if progress is None:
            current = self.repository.get_task(task_id, include_steps=False)
            progress = min(95, (current.progress_percent if current else 1) + 1)
        normalized_status = status if status in {
            "success",
            "partial",
            "failed",
            "skipped",
            "running",
        } else "running"
        self.repository.upsert_step(
            task_id,
            step_key=step_key,
            step_name=step_key,
            status=normalized_status,
            progress_percent=progress,
            message=message,
        )
        self.repository.update_task(
            task_id,
            progress_percent=progress,
            current_stage=step_key,
        )

    def get(self, task_id: str) -> TaskRecord | None:
        return self.repository.get_task(task_id)

    def list(self, **filters: Any) -> TaskListResponse:
        return self.repository.list_tasks(**filters)

    def cancel(self, task_id: str) -> TaskActionResponse:
        task = self.repository.get_task(task_id)
        if task is None:
            raise KeyError(task_id)
        if task.status not in {"queued", "running"}:
            raise ValueError("only queued or running tasks may be cancelled")
        with self._lock:
            event = self._cancel_events.get(task_id)
            if event is not None:
                event.set()
        request_cancel(task_id)
        if task.status == "queued":
            task = self.repository.update_task(
                task_id,
                status="cancelled",
                current_stage="cancelled",
                cancelled_at_stage="queued",
                completed_at=utc_now(),
                error_code="task_cancelled",
                error_message="任务在排队阶段取消",
            )
        else:
            task = self.repository.get_task(task_id) or task
        return TaskActionResponse(task=task, message="取消信号已发送")

    def retry(self, task_id: str) -> TaskActionResponse:
        source = self.repository.get_task(task_id)
        if source is None:
            raise KeyError(task_id)
        if source.status not in {"failed", "cancelled", "completed"}:
            raise ValueError("running or queued task cannot be retried")
        request = TaskCreateRequest.model_validate(
            self.repository.get_request_payload(task_id)
        )
        task = self.create(request)
        return TaskActionResponse(task=task, message="已创建重试任务")

    def delete(self, task_id: str) -> bool:
        task = self.repository.get_task(task_id)
        if task is None:
            return False
        if task.status in {"queued", "running"}:
            raise ValueError("active task must be cancelled before deletion")
        return self.repository.delete_task(task_id)

    def report(self, task_id: str) -> TaskReportResponse:
        task = self.repository.get_task(task_id)
        if task is None:
            raise KeyError(task_id)
        payload = None
        if task.report_json_path:
            path = Path(task.report_json_path)
            if path.is_file():
                payload = json.loads(path.read_text(encoding="utf-8"))
        base = f"/tasks/{task_id}/artifacts"
        return TaskReportResponse(
            task_id=task_id,
            status=task.status,
            report=payload,
            json_url=f"{base}/json" if task.report_json_path else None,
            markdown_url=f"{base}/markdown" if task.report_markdown_path else None,
            html_url=f"{base}/html" if task.report_html_path else None,
        )

    def recover(self) -> int:
        return self.repository.recover_interrupted_tasks()

    def shutdown(self) -> None:
        self._pool.shutdown(wait=False, cancel_futures=True)

    def occupied_devices(self) -> list[str]:
        with self._lock:
            return sorted(key for key, lock in self._device_locks.items() if lock.locked())
