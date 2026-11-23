from __future__ import annotations

import asyncio
import builtins
import concurrent.futures
import json
import logging
import shutil
import threading
import time
from collections.abc import Callable
from concurrent.futures import Future, ThreadPoolExecutor
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi.responses import JSONResponse

from app import config as app_config
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
logger = logging.getLogger(__name__)

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
# AI orchestration reuses the deterministic step keys and appends its own
# phases; the deterministic analysis still dominates the progress curve.
_AI_PROGRESS = {
    **_DYNAMIC_PROGRESS,
    "ai_planning": 80,
    "ai_tool_execution": 88,
    "ai_evidence_digest": 92,
    "ai_report": 96,
}


class TaskService:
    def __init__(
        self,
        repository: TaskRepository,
        *,
        max_workers: int = 3,
    ) -> None:
        self.repository = repository
        self._pool = ThreadPoolExecutor(
            max_workers=max_workers,
            thread_name_prefix="adsdk-task",
        )
        self._runner: TaskRunner | None = None
        self._futures: dict[str, Future[None]] = {}
        self._cancel_events: dict[str, threading.Event] = {}
        self._device_locks: dict[str, threading.Lock] = {}
        self._subscribers: dict[str, set[tuple[asyncio.AbstractEventLoop, asyncio.Event]]] = {}
        self._lock = threading.RLock()

    def set_runner(self, runner: TaskRunner) -> None:
        self._runner = runner

    def subscribe(
        self,
        task_id: str,
        loop: asyncio.AbstractEventLoop,
        event: asyncio.Event,
    ) -> None:
        """Register an asyncio waiter notified on task status or step mutations."""
        with self._lock:
            self._subscribers.setdefault(task_id, set()).add((loop, event))

    def unsubscribe(
        self,
        task_id: str,
        loop: asyncio.AbstractEventLoop,
        event: asyncio.Event,
    ) -> None:
        """Remove a previously registered asyncio waiter."""
        with self._lock:
            subscribers = self._subscribers.get(task_id)
            if subscribers is not None:
                subscribers.discard((loop, event))
                if not subscribers:
                    self._subscribers.pop(task_id, None)

    def _notify(self, task_id: str) -> None:
        with self._lock:
            targets = list(self._subscribers.get(task_id, ()))
        self._wake_targets(targets)

    def _notify_all(self) -> None:
        with self._lock:
            targets = [pair for pairs in self._subscribers.values() for pair in pairs]
        self._wake_targets(targets)

    @staticmethod
    def _wake_targets(targets: list[tuple[asyncio.AbstractEventLoop, asyncio.Event]]) -> None:
        for loop, event in targets:
            try:
                if not loop.is_closed():
                    loop.call_soon_threadsafe(event.set)
            except RuntimeError:
                pass

    def shutdown(self, wait: bool = False, *, cancel_timeout: float = 0.0) -> None:
        """Gracefully cancel active tasks, wait briefly for cleanup, and shut down the pool."""
        with self._lock:
            cancel_items = list(self._cancel_events.items())
            active_futures = [future for future in self._futures.values() if not future.done()]
        for task_id, cancel_event in cancel_items:
            cancel_event.set()
            request_cancel(task_id)
        self._notify_all()
        if cancel_timeout > 0 and active_futures:
            concurrent.futures.wait(active_futures, timeout=cancel_timeout)
        self._pool.shutdown(wait=wait, cancel_futures=True)

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
        self._notify(task.id)
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
        # An AI task that is permitted to run device-touching tools must take
        # the same device lease a plain dynamic task takes.
        needs_device = task.task_type == "dynamic" or (
            task.task_type == "ai_orchestrated" and bool(private_payload.get("allow_dynamic"))
        )
        if needs_device:
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
            self._notify(task_id)
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
                apk_snapshot_path=(result.get("apk_snapshot") or {}).get("snapshot_relative_path"),
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
            self._notify(task_id)
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
            self._notify(task_id)
        except Exception as exc:
            logger.exception("后台任务执行失败: task_id=%s task_type=%s", task_id, task.task_type)
            release_device()
            self.repository.update_task(
                task_id,
                status="failed",
                current_stage="failed",
                completed_at=utc_now(),
                error_code="task_execution_failed",
                error_message=f"后台任务执行失败: {type(exc).__name__}",
            )
            self._notify(task_id)
        finally:
            if token is not None:
                reset_task_context(token)
            release_device()
            with self._lock:
                self._cancel_events.pop(task_id, None)
                self._futures.pop(task_id, None)

    @staticmethod
    def _response_payload(
        result: dict[str, Any] | JSONResponse,
    ) -> dict[str, Any]:
        if isinstance(result, JSONResponse):
            return json.loads(bytes(result.body).decode("utf-8"))
        return dict(result)

    def _record_progress(
        self,
        task_id: str,
        task_type: str,
        step_key: str,
        status: str,
        message: str | None,
    ) -> None:
        progress_map = (
            _AI_PROGRESS
            if task_type == "ai_orchestrated"
            else _DYNAMIC_PROGRESS
            if task_type == "dynamic"
            else _STATIC_PROGRESS
        )
        progress = progress_map.get(step_key)
        if progress is None:
            current = self.repository.get_task(task_id, include_steps=False)
            progress = min(95, (current.progress_percent if current else 1) + 1)
        normalized_status = (
            status
            if status
            in {
                "success",
                "partial",
                "failed",
                "skipped",
                "running",
            }
            else "running"
        )
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
        self._notify(task_id)

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
        self._notify(task_id)
        return TaskActionResponse(task=task, message="取消信号已发送")

    def retry(self, task_id: str) -> TaskActionResponse:
        source = self.repository.get_task(task_id)
        if source is None:
            raise KeyError(task_id)
        if source.status not in {"failed", "cancelled", "completed"}:
            raise ValueError("running or queued task cannot be retried")
        request = TaskCreateRequest.model_validate(self.repository.get_request_payload(task_id))
        task = self.create(request)
        return TaskActionResponse(task=task, message="已创建重试任务")

    def delete(self, task_id: str, *, delete_artifacts: bool = True) -> bool:
        task = self.repository.get_task(task_id)
        if task is None:
            return False
        if task.status in {"queued", "running"}:
            raise ValueError("active task must be cancelled before deletion")
        deleted = self.repository.delete_task(task_id)
        if deleted and delete_artifacts:
            self._cleanup_task_artifacts(task)
        return deleted

    def _allowed_runs_dir(self) -> Path:
        return (Path(app_config.OUTPUT_DIR).resolve(strict=False) / "runs").resolve(strict=False)

    def _referenced_run_dirs(self, allowed_runs_dir: Path) -> set[Path]:
        referenced: set[Path] = set()
        for row in self.repository.list_task_name_rows():
            for field in ("report_json_path", "report_markdown_path", "report_html_path"):
                value = row.get(field)
                if not value:
                    continue
                ref_path = Path(str(value)).resolve(strict=False)
                if ref_path.is_relative_to(allowed_runs_dir):
                    rel = ref_path.relative_to(allowed_runs_dir)
                    if rel.parts:
                        referenced.add(allowed_runs_dir / rel.parts[0])
        return referenced

    def _cleanup_task_artifacts(self, task: TaskRecord) -> None:
        allowed_runs_dir = self._allowed_runs_dir()
        candidates: set[Path] = set()
        for path_text in (
            task.report_json_path,
            task.report_markdown_path,
            task.report_html_path,
        ):
            if not path_text:
                continue
            raw_path = Path(path_text)
            if raw_path.parent.is_symlink():
                continue
            resolved_parent = raw_path.resolve(strict=False).parent
            if (
                resolved_parent.parent == allowed_runs_dir
                and resolved_parent != allowed_runs_dir
                and resolved_parent.is_dir()
                and not resolved_parent.is_symlink()
            ):
                candidates.add(resolved_parent)

        if not candidates:
            return
        referenced = self._referenced_run_dirs(allowed_runs_dir)
        for candidate in candidates:
            if candidate in referenced:
                continue
            try:
                shutil.rmtree(candidate)
            except OSError as exc:
                logger.warning(
                    "清理任务产物目录失败: task_id=%s dir=%s err=%s",
                    task.id,
                    candidate,
                    type(exc).__name__,
                )

    def cleanup_orphaned_run_dirs(self, *, min_age_seconds: float = 600.0) -> int:
        """Remove unreferenced run directories older than ``min_age_seconds``."""
        allowed_runs_dir = self._allowed_runs_dir()
        if not allowed_runs_dir.is_dir():
            return 0
        if (
            self.repository.list_tasks(status="running", page=1, page_size=1).total > 0
            or self.repository.list_tasks(status="queued", page=1, page_size=1).total > 0
        ):
            return 0

        referenced = self._referenced_run_dirs(allowed_runs_dir)
        cutoff = time.time() - max(0.0, float(min_age_seconds))
        removed = 0
        try:
            entries = list(allowed_runs_dir.iterdir())
        except OSError:
            return 0

        for entry in entries:
            if not entry.is_dir() or entry.is_symlink() or entry.name.startswith("."):
                continue
            resolved = entry.resolve(strict=False)
            if resolved.parent != allowed_runs_dir or resolved in referenced:
                continue
            try:
                mtime = entry.stat().st_mtime
            except OSError:
                continue
            if mtime > cutoff:
                continue
            try:
                shutil.rmtree(resolved)
                removed += 1
            except OSError as exc:
                logger.warning(
                    "清理孤儿产物目录失败: dir=%s err=%s",
                    resolved,
                    type(exc).__name__,
                )
        return removed

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

    def occupied_devices(self) -> builtins.list[str]:
        with self._lock:
            return sorted(key for key, lock in self._device_locks.items() if lock.locked())
