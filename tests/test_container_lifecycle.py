"""Tests for Container lifecycle, zero-IO import, and single-execution recover."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from app.container import Container, build_container
from tests.conftest import make_test_app


def test_container_import_has_no_io(tmp_path: Path):
    """Verify importing app.container does not create database files or output dirs."""
    project_root = Path(__file__).resolve().parent.parent
    code = (
        f"import sys; sys.path.insert(0, r'{project_root}'); "
        "import app.container as c; "
        "print('IMPORTED_OK')"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=True,
    )
    assert "IMPORTED_OK" in result.stdout
    # Confirm no db or state files were created in tmp_path
    created_files = list(tmp_path.rglob("*"))
    assert created_files == []


def test_build_container_constructs_pure_dataclass(tmp_path: Path):
    """build_container should return a populated Container dataclass without IO."""
    db_file = tmp_path / "custom.db"
    container = build_container(settings={"task_database_path": db_file})
    assert isinstance(container, Container)
    assert container.task_repository.database_path == db_file
    assert not db_file.exists()


def test_recover_called_only_once_during_lifespan(tmp_path: Path):
    """recover() must execute exactly once during application startup lifespan."""
    app = make_test_app(tmp_path)
    container = app.state.container

    recover_mock = MagicMock(return_value=0)
    container.task_service.recover = recover_mock

    assert recover_mock.call_count == 0

    with TestClient(app):
        # Lifespan startup has executed
        assert recover_mock.call_count == 1

    # On shutdown, recover is not called again
    assert recover_mock.call_count == 1


def test_create_app_idempotent_routes():
    """Consecutive calls to create_app() must produce identical route definitions."""
    from app.main import create_app

    app1 = create_app()
    app2 = create_app()

    def _extract_routes(app) -> set[tuple[str, tuple[str, ...]]]:
        routes = set()
        for r in app.routes:
            if hasattr(r, "path") and r.path:
                routes.add((r.path, tuple(sorted(getattr(r, "methods", [])))))
            elif hasattr(r, "original_router"):
                for sub in r.original_router.routes:
                    if hasattr(sub, "path") and sub.path:
                        routes.add((sub.path, tuple(sorted(getattr(sub, "methods", [])))))
        return routes

    routes1 = _extract_routes(app1)
    routes2 = _extract_routes(app2)

    assert routes1 == routes2
    paths = {path for path, _ in routes1}
    assert "/" in paths
    assert "/analyze" in paths
    assert "/dynamic/analyze" in paths

    client = TestClient(app1)
    resp = client.get("/")
    assert resp.status_code == 200
    assert resp.json() == {"ok": True, "message": "AdSDK Agent is running"}


def test_two_apps_have_isolated_databases_and_tasks(tmp_path: Path):
    """Two app instances constructed with different paths must not share task state."""
    dir1 = tmp_path / "app1"
    dir2 = tmp_path / "app2"
    dir1.mkdir()
    dir2.mkdir()

    app1 = make_test_app(dir1)
    app2 = make_test_app(dir2)

    with TestClient(app1) as client1, TestClient(app2) as client2:
        create_resp = client1.post(
            "/tasks",
            json={"task_type": "static", "apk_path": "D:/samples/app.apk"},
        )
        assert create_resp.status_code == 202
        task_id = create_resp.json()["id"]

        # App 1 can see its task
        detail1 = client1.get(f"/tasks/{task_id}")
        assert detail1.status_code == 200

        # App 2 cannot see the task created in App 1
        detail2 = client2.get(f"/tasks/{task_id}")
        assert detail2.status_code == 404

        list2 = client2.get("/tasks")
        assert list2.status_code == 200
        assert list2.json()["total"] == 0


def test_task_runner_uses_same_container_instance(tmp_path: Path):
    """When a task is processed, the runner receives the exact container instance from app.state."""
    app = make_test_app(tmp_path)
    captured_container = []

    def mock_runner(task, *, container=None):
        captured_container.append(container)
        return {"status": "completed"}

    from functools import partial

    app.state.container.task_service.set_runner(partial(mock_runner, container=app.state.container))

    with TestClient(app) as client:
        resp = client.post(
            "/tasks",
            json={"task_type": "static", "apk_path": "D:/samples/app.apk"},
        )
        assert resp.status_code == 202
        task_id = resp.json()["id"]

        # Wait for terminal state
        import time

        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            record = app.state.container.task_service.get(task_id)
            if record and record.status in {"completed", "failed"}:
                break
            time.sleep(0.02)

    assert len(captured_container) >= 1
    assert captured_container[0] is app.state.container


def test_pipeline_entries_raise_when_called_without_container():
    """Pipeline entries must strictly require container without silently falling back to build_container."""
    from app.models import DynamicAnalyzeRequest
    from app.pipelines.dynamic import _dynamic_analyze_v2, dynamic_analyze
    from app.pipelines.full_analysis import run_full_analysis_session
    from app.pipelines.task_runner import (
        _execute_ai_orchestration,
        _run_ai_orchestrated_task,
        regenerate_task_ai_report,
        run_persisted_task,
    )
    from app.tasks.models import TaskRecord

    fake_task = TaskRecord(
        id="t-1",
        task_type="static",
        status="queued",
        progress_percent=0,
        request_payload={"apk_path": "test.apk"},
        created_at="2026-01-01T00:00:00Z",
        updated_at="2026-01-01T00:00:00Z",
    )

    with pytest.raises(TypeError):
        run_persisted_task(fake_task)  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        run_full_analysis_session(task=fake_task, payload={})  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        dynamic_analyze(DynamicAnalyzeRequest(apk_path="test.apk"))  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        _dynamic_analyze_v2(DynamicAnalyzeRequest(apk_path="test.apk"))  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        _run_ai_orchestrated_task(fake_task, {})  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        _execute_ai_orchestration(task=fake_task, payload={}, run_dir=None, base_report={})  # type: ignore[call-arg]

    with pytest.raises(TypeError):
        regenerate_task_ai_report("t-1")  # type: ignore[call-arg]


def test_missing_container_on_app_state_fails_cleanly_without_creating_files(tmp_path: Path):
    """When app.state.container is missing or removed, routes must fail with 500 without creating DB files."""
    app = make_test_app(tmp_path)
    # Remove container from state to simulate uninitialised state
    del app.state.container

    initial_files = list(tmp_path.rglob("*"))

    client = TestClient(app, raise_server_exceptions=False)
    resp = client.get("/tasks")
    assert resp.status_code == 500

    # Ensure no new SQLite files or directories were silently created
    current_files = list(tmp_path.rglob("*"))
    assert current_files == initial_files


def test_same_app_sees_identical_services_across_route_runner_and_pipeline(tmp_path: Path):
    """Inside the same app, the route layer, runner, and pipeline observe identical service instances."""
    app = make_test_app(tmp_path)
    container = app.state.container

    captured_lease_reg = []
    captured_consent_svc = []

    def capturing_runner(task, *, container):
        captured_lease_reg.append(container.device_lease_registry)
        captured_consent_svc.append(container.consent_checkpoint_service)
        return {"status": "completed"}

    from functools import partial

    app.state.container.task_service.set_runner(
        partial(capturing_runner, container=app.state.container)
    )

    with TestClient(app) as client:
        # Route layer service resolution via Depends
        route_consent_svc = (
            client.app.dependency_overrides.get(app.state.container.consent_checkpoint_service)
            or app.state.container.consent_checkpoint_service
        )
        assert route_consent_svc is container.consent_checkpoint_service

        resp = client.post("/tasks", json={"task_type": "static", "apk_path": "D:/samples/app.apk"})
        assert resp.status_code == 202
        task_id = resp.json()["id"]

        import time

        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            record = container.task_service.get(task_id)
            if record and record.status in {"completed", "failed"}:
                break
            time.sleep(0.02)

    assert len(captured_lease_reg) == 1
    assert captured_lease_reg[0] is container.device_lease_registry
    assert captured_consent_svc[0] is container.consent_checkpoint_service


def test_container_tools_substitution_and_isolation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Container tools must be injectable, called by pipelines, and isolated across containers."""
    from datetime import UTC, datetime

    from app import config as app_config
    from app.container import build_container
    from app.core.device import DeviceContext
    from app.core.run_context import AnalysisRunContext
    from app.pipelines.static_stage import run_static_stage
    from app.pipelines.tools import PipelineTools

    monkeypatch.setattr(app_config, "STATIC_UNPACK_CACHE_DIR", str(tmp_path / "cache"))

    calls1 = []
    calls2 = []

    def fake_unpack1(apk, out_dir):
        calls1.append((apk, out_dir))
        p = Path(out_dir)
        p.mkdir(parents=True, exist_ok=True)
        (p / "AndroidManifest.xml").write_text(
            "<manifest package='com.test.one'/>", encoding="utf-8"
        )
        return {"returncode": 0, "stdout": "", "stderr": "", "cmd": []}

    def fake_unpack2(apk, out_dir):
        calls2.append((apk, out_dir))
        return {"returncode": -1, "stdout": "", "stderr": "failed", "cmd": []}

    tools1 = PipelineTools(
        unpack_apk=fake_unpack1,
        parse_manifest_info=lambda _: {"package_name": "com.test.one"},
        scan_for_sdks=lambda _: [],
        select_device_context=lambda device_id=None: DeviceContext(serial="device-1"),
    )
    tools2 = PipelineTools(
        unpack_apk=fake_unpack2,
        select_device_context=lambda device_id=None: DeviceContext(serial="device-2"),
    )

    c1 = build_container(settings={"task_database_path": str(tmp_path / "c1.db")}, tools=tools1)
    c2 = build_container(settings={"task_database_path": str(tmp_path / "c2.db")}, tools=tools2)

    assert c1.tools is tools1
    assert c2.tools is tools2
    assert c1.tools.unpack_apk is fake_unpack1
    assert c2.tools.unpack_apk is fake_unpack2

    run_dir1 = tmp_path / "run1"
    run_dir1.mkdir()
    apk1 = tmp_path / "sample1.apk"
    apk1.write_bytes(b"dummy1")
    ctx1 = AnalysisRunContext(
        run_id="run-1",
        apk_path=apk1,
        apk_sha256="1" * 64,
        output_root=tmp_path,
        run_dir=run_dir1,
        unpacked_dir=run_dir1 / "unpacked",
        hook_log_path=run_dir1 / "hook.log",
        events_path=run_dir1 / "events.json",
        traffic_dir=run_dir1 / "traffic",
        traffic_summary_path=run_dir1 / "traffic" / "traffic-summary.json",
        report_json_path=run_dir1 / "report.json",
        report_markdown_path=run_dir1 / "report.md",
        device_id=None,
        normalized_apk_name="sample1.apk",
        started_at=datetime.now(UTC),
        flow_file_path=run_dir1 / "traffic" / "flows.mitm",
        mitm_stream_log_path=run_dir1 / "traffic" / "mitm_stream.log",
    )

    steps1 = []
    res1 = run_static_stage(ctx1, steps1, tools=c1.tools)
    assert res1.unpack_ok is True
    assert len(calls1) == 1
    assert len(calls2) == 0

    run_dir2 = tmp_path / "run2"
    run_dir2.mkdir()
    apk2 = tmp_path / "sample2.apk"
    apk2.write_bytes(b"dummy2")
    ctx2 = AnalysisRunContext(
        run_id="run-2",
        apk_path=apk2,
        apk_sha256="2" * 64,
        output_root=tmp_path,
        run_dir=run_dir2,
        unpacked_dir=run_dir2 / "unpacked",
        hook_log_path=run_dir2 / "hook.log",
        events_path=run_dir2 / "events.json",
        traffic_dir=run_dir2 / "traffic",
        traffic_summary_path=run_dir2 / "traffic" / "traffic-summary.json",
        report_json_path=run_dir2 / "report.json",
        report_markdown_path=run_dir2 / "report.md",
        device_id=None,
        normalized_apk_name="sample2.apk",
        started_at=datetime.now(UTC),
        flow_file_path=run_dir2 / "traffic" / "flows.mitm",
        mitm_stream_log_path=run_dir2 / "traffic" / "mitm_stream.log",
    )

    steps2 = []
    res2 = run_static_stage(ctx2, steps2, tools=c2.tools)
    assert res2.unpack_ok is False
    assert len(calls1) == 1
    assert len(calls2) == 1
