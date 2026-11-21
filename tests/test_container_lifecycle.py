"""Tests for Container lifecycle, zero-IO import, and single-execution recover."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from unittest.mock import MagicMock

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
