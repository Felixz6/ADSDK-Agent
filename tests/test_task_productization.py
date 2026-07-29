from __future__ import annotations

import json
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import app.main as main_module
from app.comparisons import ComparisonCreateRequest, ComparisonService
from app.reporting import render_html_report, write_html_report
from app.repositories import TaskRepository
from app.services import TaskService
from app.tasks.models import TaskCreateRequest
from app.tasks.runtime import checkpoint, report_step


def _repository(tmp_path: Path) -> TaskRepository:
    repository = TaskRepository(tmp_path / "state" / "tasks.db")
    repository.initialize()
    return repository


def _create_task(
    repository: TaskRepository,
    *,
    task_id: str = "task-1",
    task_type: str = "static",
    status: str = "queued",
    apk_path: str = "D:/samples/app.apk",
):
    request = {
        "task_type": task_type if task_type != "comparison" else "static",
        "apk_path": apk_path,
        "package_name": None,
        "device_id": "DEVICE" if task_type == "dynamic" else None,
        "enable_traffic": task_type == "dynamic",
        "enable_ui_stimulation": False,
        "consent_after_seconds": 1,
        "pre_consent_seconds": 1,
        "post_consent_seconds": 1,
        "collection_timeout_seconds": 5,
    }
    return repository.create_task(
        {
            "id": task_id,
            "task_type": task_type,
            "status": status,
            "apk_path": apk_path,
            "device_id": request["device_id"],
            "enable_traffic": request["enable_traffic"],
            "request_payload": request,
        }
    )


def _wait_terminal(service: TaskService, task_id: str, timeout: float = 3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        task = service.get(task_id)
        if task and task.status in {"completed", "failed", "cancelled"}:
            return task
        time.sleep(0.01)
    raise AssertionError("task did not reach a terminal state")


def test_sqlite_initialization_and_crud(tmp_path: Path):
    repository = _repository(tmp_path)
    task = _create_task(repository)

    assert repository.database_path.is_file()
    assert task.status == "queued"
    updated = repository.update_task(
        task.id,
        status="running",
        progress_percent=25,
        current_stage="apk_snapshot",
    )
    assert updated.progress_percent == 25
    assert repository.delete_task(task.id) is True
    assert repository.get_task(task.id) is None


def test_repository_step_upsert_list_filter_and_paging(tmp_path: Path):
    repository = _repository(tmp_path)
    first = _create_task(repository, task_id="first", apk_path="D:/samples/alpha.apk")
    _create_task(
        repository,
        task_id="second",
        task_type="dynamic",
        apk_path="D:/samples/beta.apk",
    )
    repository.upsert_step(
        first.id,
        step_key="apk_snapshot",
        step_name="APK snapshot",
        status="success",
        progress_percent=22,
        message=None,
    )

    page = repository.list_tasks(keyword="alpha", page=1, page_size=1)
    dynamic = repository.list_tasks(task_type="dynamic", page=1, page_size=20)
    task = repository.get_task(first.id)

    assert page.total == 1 and page.pages == 1
    assert dynamic.total == 1 and dynamic.items[0].id == "second"
    assert task is not None and task.steps[0].status == "success"


def test_restart_recovery_marks_interrupted_tasks_failed(tmp_path: Path):
    repository = _repository(tmp_path)
    _create_task(repository, task_id="queued")
    running = _create_task(repository, task_id="running")
    repository.update_task(running.id, status="running")

    assert repository.recover_interrupted_tasks() == 2
    assert repository.get_task("queued").error_code == "service_restarted"
    assert repository.get_task("running").status == "failed"


def test_task_service_records_real_progress_and_report_index(tmp_path: Path):
    repository = _repository(tmp_path)
    report_path = tmp_path / "runs" / "report.json"
    markdown_path = report_path.with_suffix(".md")
    html_path = report_path.with_suffix(".html")
    report_path.parent.mkdir()
    payload = {
        "ok": True,
        "status": "success",
        "apk_sha256": "a" * 64,
        "apk_snapshot": {"snapshot_relative_path": "input/app.apk"},
        "app_info": {
            "package_name": "com.example",
            "application_label": "Example",
            "version_name": "1",
            "version_code": "1",
        },
        "risk_summary": {"score": 12, "level": "low"},
        "report_json": str(report_path),
        "report_md": str(markdown_path),
        "report_html": str(html_path),
    }
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    markdown_path.write_text("# report", encoding="utf-8")
    html_path.write_text("<!doctype html>", encoding="utf-8")
    service = TaskService(repository, max_workers=1)

    def runner(_task):
        report_step("apk_snapshot", "success")
        report_step("report_write", "success")
        return payload

    service.set_runner(runner)
    task = service.create(
        TaskCreateRequest(task_type="static", apk_path="D:/samples/app.apk")
    )
    result = _wait_terminal(service, task.id)
    report = service.report(task.id)

    assert result.status == "completed"
    assert result.progress_percent == 100
    assert [step.step_key for step in result.steps] == [
        "apk_snapshot",
        "report_write",
    ]
    assert report.report["app_info"]["package_name"] == "com.example"
    assert report.html_url.endswith("/artifacts/html")
    service.shutdown()


def test_task_service_failure_retry_and_delete(tmp_path: Path):
    repository = _repository(tmp_path)
    service = TaskService(repository, max_workers=1)

    def runner(_task):
        return {
            "ok": False,
            "status": "failed",
            "error_code": "fixture_failed",
            "error": "fixture failure",
        }

    service.set_runner(runner)
    task = service.create(
        TaskCreateRequest(task_type="static", apk_path="D:/samples/app.apk")
    )
    failed = _wait_terminal(service, task.id)
    retried = service.retry(task.id).task
    retried_terminal = _wait_terminal(service, retried.id)

    assert failed.status == "failed"
    assert failed.error_code == "fixture_failed"
    assert retried.id != task.id
    assert retried_terminal.status == "failed"
    assert service.delete(task.id) is True
    service.shutdown()


def test_running_task_cancellation_reaches_safe_point(tmp_path: Path):
    repository = _repository(tmp_path)
    service = TaskService(repository, max_workers=1)
    entered = threading.Event()

    def runner(_task):
        entered.set()
        while True:
            checkpoint()
            time.sleep(0.01)

    service.set_runner(runner)
    task = service.create(
        TaskCreateRequest(
            task_type="dynamic",
            apk_path="D:/samples/app.apk",
            device_id="DEVICE",
        )
    )
    assert entered.wait(1)
    response = service.cancel(task.id)
    cancelled = _wait_terminal(service, task.id)

    assert response.message == "取消信号已发送"
    assert cancelled.status == "cancelled"
    assert cancelled.error_code == "task_cancelled"
    assert service.occupied_devices() == []
    service.shutdown()


def test_html_report_is_printable_and_escapes_untrusted_content(tmp_path: Path):
    report = {
        "schema_version": "1.0",
        "run_id": "run-1",
        "status": "partial",
        "app_info": {
            "package_name": "<script>alert(1)</script>",
            "application_label": "A&B",
            "permissions": ["android.permission.INTERNET"],
        },
        "risk_summary": {"score": 50, "category_scores": []},
        "steps": [],
        "limitations": ["<img src=x onerror=alert(1)>"],
    }

    rendered = render_html_report(report)
    path = write_html_report(report, tmp_path / "report.html")

    assert "<script>alert(1)</script>" not in rendered
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in rendered
    assert "@media print" in rendered
    assert "未获得可信动态证据" in rendered
    assert "这不代表应用不存在对应行为" in rendered
    assert path.read_text(encoding="utf-8") == rendered


def _completed_report_task(
    repository: TaskRepository,
    tmp_path: Path,
    *,
    task_id: str,
    package: str,
    permissions: list[str],
    sdks: list[dict],
    score: int,
):
    report_path = tmp_path / f"{task_id}.json"
    report_path.write_text(
        json.dumps(
            {
                "status": "success",
                "apk_sha256": task_id * 8,
                "apk_snapshot": {"snapshot_size_bytes": 100},
                "app_info": {
                    "package_name": package,
                    "permissions": permissions,
                    "high_attention_permissions": permissions,
                },
                "sdks": sdks,
                "risk_summary": {"score": score, "level": "medium"},
                "dynamic_events": [],
                "traffic_summary": {"top_hosts": []},
            }
        ),
        encoding="utf-8",
    )
    task = _create_task(repository, task_id=task_id, status="completed")
    return repository.update_task(
        task.id,
        status="completed",
        report_json_path=str(report_path),
        completed_at="2026-01-01T00:00:00Z",
    )


def test_comparison_is_deterministic_and_persistent(tmp_path: Path):
    repository = _repository(tmp_path)
    base = _completed_report_task(
        repository,
        tmp_path,
        task_id="base",
        package="com.example",
        permissions=["A"],
        sdks=[{"sdk_name": "SDK-A", "vendor": "V1", "category": "ads"}],
        score=10,
    )
    target = _completed_report_task(
        repository,
        tmp_path,
        task_id="target",
        package="com.example",
        permissions=["A", "B"],
        sdks=[{"sdk_name": "SDK-B", "vendor": "V2", "category": "analytics"}],
        score=22,
    )
    service = ComparisonService(repository)

    result = service.create(
        ComparisonCreateRequest(base_task_id=base.id, target_task_id=target.id)
    )
    loaded = service.get(result.id)

    assert result.schema_version == "comparison-v1"
    assert result.permissions.added == ["B"]
    assert result.sdks.added == ["SDK-B"]
    assert result.risk_score_delta == 12
    assert loaded == result


def test_comparison_validates_inputs_and_cross_app_confirmation(tmp_path: Path):
    repository = _repository(tmp_path)
    base = _completed_report_task(
        repository,
        tmp_path,
        task_id="base",
        package="com.a",
        permissions=[],
        sdks=[],
        score=0,
    )
    target = _completed_report_task(
        repository,
        tmp_path,
        task_id="target",
        package="com.b",
        permissions=[],
        sdks=[],
        score=0,
    )
    service = ComparisonService(repository)

    with pytest.raises(ValueError, match="package names differ"):
        service.create(
            ComparisonCreateRequest(
                base_task_id=base.id,
                target_task_id=target.id,
            )
        )

    result = service.create(
        ComparisonCreateRequest(
            base_task_id=base.id,
            target_task_id=target.id,
            allow_cross_app=True,
        )
    )
    assert result.warnings == ["包名不同，本结果为跨应用对比"]


def test_task_api_create_list_detail_report_and_websocket(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    repository = _repository(tmp_path)
    report_path = tmp_path / "runs" / "task-report.json"
    report_path.parent.mkdir()
    payload = {
        "ok": True,
        "status": "success",
        "report_json": str(report_path),
        "app_info": {"package_name": "com.api"},
    }
    report_path.write_text(json.dumps(payload), encoding="utf-8")
    service = TaskService(repository, max_workers=1)
    service.set_runner(lambda _task: payload)
    monkeypatch.setattr(main_module, "task_service", service)
    monkeypatch.setattr(main_module, "task_repository", repository)

    client = TestClient(main_module.app)
    created_response = client.post(
        "/tasks",
        json={"task_type": "static", "apk_path": "D:/samples/app.apk"},
    )
    assert created_response.status_code == 202
    task_id = created_response.json()["id"]
    _wait_terminal(service, task_id)

    listed = client.get("/tasks", params={"status": "completed"}).json()
    detail = client.get(f"/tasks/{task_id}").json()
    report = client.get(f"/tasks/{task_id}/report").json()
    with client.websocket_connect(f"/ws/tasks/{task_id}") as websocket:
        message = websocket.receive_json()

    assert listed["total"] == 1
    assert detail["steps"] == []
    assert report["report"]["app_info"]["package_name"] == "com.api"
    assert message["status"] == "completed"
    service.shutdown()


def test_task_api_stable_errors_and_delete(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    repository = _repository(tmp_path)
    service = TaskService(repository, max_workers=1)
    service.set_runner(lambda _task: {"ok": False, "status": "failed"})
    monkeypatch.setattr(main_module, "task_service", service)
    monkeypatch.setattr(main_module, "task_repository", repository)
    client = TestClient(main_module.app)

    missing = client.get("/tasks/missing")
    invalid_filter = client.get("/tasks", params={"status": "imaginary"})
    created = client.post(
        "/tasks",
        json={"task_type": "static", "apk_path": "D:/samples/app.apk"},
    ).json()
    _wait_terminal(service, created["id"])
    deleted = client.delete(f"/tasks/{created['id']}")

    assert missing.status_code == 404
    assert missing.json()["detail"]["code"] == "task_not_found"
    assert invalid_filter.status_code == 422
    assert invalid_filter.json()["detail"]["code"] == "invalid_status"
    assert deleted.status_code == 204
    service.shutdown()
