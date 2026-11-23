"""Targeted tests for high-priority security, reliability, and disk-lifecycle hardening."""

from __future__ import annotations

import logging
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

import app.config as app_config
import app.main as main_module
from app.api import middleware as middleware_module
from app.api.deps import get_task_repository, get_task_service
from app.core.logging import RedactingFormatter, SecretRedactingFilter, configure_logging
from app.core.static_unpack_cache import evict_static_unpack_cache, prepare_static_unpack
from app.orchestration.consent_checkpoint import ConsentCheckpointService
from app.repositories import TaskRepository
from app.services import TaskService
from app.tasks.models import TaskCreateRequest
from app.tasks.runtime import checkpoint, report_step


def _repo(tmp_path: Path) -> TaskRepository:
    repo = TaskRepository(tmp_path / "state" / "tasks.db")
    repo.initialize()
    return repo


def _wait_terminal(service: TaskService, task_id: str, timeout: float = 3.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        task = service.get(task_id)
        if task is not None and task.status in {"completed", "failed", "cancelled"}:
            return task
        time.sleep(0.01)
    raise AssertionError(f"task {task_id} did not reach terminal state")


# ---------------------------------------------------------------------------
# 1. Config & Redacting Logging
# ---------------------------------------------------------------------------
def test_parse_allowed_origins_handles_separators_slashes_and_defaults():
    assert app_config._parse_allowed_origins(None) == (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    )
    assert app_config._parse_allowed_origins("   ") == (
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    )
    assert app_config._parse_allowed_origins(
        " http://127.0.0.1:4173/ ; http://localhost:5173 , http://127.0.0.1:4173 "
    ) == (
        "http://127.0.0.1:4173",
        "http://localhost:5173",
    )


def test_configure_logging_is_idempotent_and_zero_disk_io(tmp_path: Path):
    project_root = Path(__file__).resolve().parent.parent
    code = (
        f"import sys; sys.path.insert(0, r'{project_root}'); "
        "from app.core.logging import configure_logging; "
        "l1 = configure_logging('DEBUG'); "
        "l2 = configure_logging('INFO'); "
        "assert l1 is l2; "
        "print(len([h for h in l2.handlers if getattr(h, '_adsdk_app_stream_handler', False)]))"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=str(tmp_path),
        capture_output=True,
        text=True,
        check=True,
    )
    assert result.stdout.strip() == "1"
    assert list(tmp_path.rglob("*")) == []


def test_secret_redacting_filter_and_formatter_scrub_messages_and_tracebacks():
    secret = "sk-live-secret-token-987654321"
    record = logging.LogRecord(
        name="app.test",
        level=logging.ERROR,
        pathname=__file__,
        lineno=1,
        msg="request auth=%s key=%s",
        args=(f"Bearer {secret}", secret),
        exc_info=None,
    )
    redacting_filter = SecretRedactingFilter()
    assert redacting_filter.filter(record) is True
    rendered = record.getMessage()
    assert secret not in rendered
    assert "Bearer [REDACTED]" in rendered

    try:
        raise RuntimeError(f"api_key={secret} failed with Bearer {secret}")
    except RuntimeError:
        exc_record = logging.LogRecord(
            name="app.test",
            level=logging.ERROR,
            pathname=__file__,
            lineno=1,
            msg="boom",
            args=(),
            exc_info=sys.exc_info(),
        )
    formatter = RedactingFormatter("%(levelname)s %(message)s")
    formatted = formatter.format(exc_record)
    assert secret not in formatted
    assert "[REDACTED]" in formatted


# ---------------------------------------------------------------------------
# 2. Expanded Local-Only Middleware & WebSocket Origin Guard
# ---------------------------------------------------------------------------
def test_middleware_guards_non_ai_writes_and_respects_allow_remote_writes(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    repo = _repo(tmp_path)
    service = TaskService(repo, max_workers=1)
    service.set_runner(lambda _task: {"ok": True, "status": "success"})
    monkeypatch.setitem(main_module.app.dependency_overrides, get_task_service, lambda: service)
    monkeypatch.setitem(main_module.app.dependency_overrides, get_task_repository, lambda: repo)
    client = TestClient(main_module.app)

    try:
        # Disallowed origin rejected on POST /tasks
        bad_origin = client.post(
            "/tasks",
            json={"task_type": "static", "apk_path": "D:/samples/app.apk"},
            headers={"origin": "http://evil.example"},
        )
        assert bad_origin.status_code == 403
        assert bad_origin.json()["error_code"] == "origin_forbidden"

        # Non-loopback client rejected on POST /tasks and DELETE /tasks/{id}, while GET remains open
        monkeypatch.setattr(middleware_module, "_client_is_loopback", lambda _host: False)
        remote_post = client.post(
            "/tasks",
            json={"task_type": "static", "apk_path": "D:/samples/app.apk"},
        )
        assert remote_post.status_code == 403
        assert remote_post.json()["error_code"] == "remote_client_forbidden"

        remote_delete = client.delete("/tasks/nonexistent")
        assert remote_delete.status_code == 403
        assert remote_delete.json()["error_code"] == "remote_client_forbidden"

        remote_get = client.get("/tasks")
        assert remote_get.status_code == 200

        # ALLOW_REMOTE_WRITES=True relaxes non-AI writes, but /ai/settings* stays strictly local-only
        monkeypatch.setattr(app_config, "ALLOW_REMOTE_WRITES", True)
        allowed_remote_post = client.post(
            "/tasks",
            json={"task_type": "static", "apk_path": "D:/samples/app.apk"},
        )
        assert allowed_remote_post.status_code == 202
        _wait_terminal(service, allowed_remote_post.json()["id"])

        ai_remote_put = client.put("/ai/settings", json={"model": "m1"})
        assert ai_remote_put.status_code == 403
        assert ai_remote_put.json()["error_code"] == "ai_settings_remote_client_forbidden"
    finally:
        service.shutdown()


def test_allowed_origins_env_updates_middleware_and_cors(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setattr(
        app_config,
        "ALLOWED_ORIGINS",
        app_config._parse_allowed_origins("http://127.0.0.1:4173"),
    )
    assert middleware_module.is_origin_allowed("http://127.0.0.1:4173/") is True
    assert middleware_module.is_origin_allowed("http://127.0.0.1:5173") is False

    app = main_module.create_app()
    client = TestClient(app)
    preflight = client.options(
        "/tasks",
        headers={
            "origin": "http://127.0.0.1:4173",
            "access-control-request-method": "POST",
        },
    )
    assert preflight.status_code == 200
    assert preflight.headers.get("access-control-allow-origin") == "http://127.0.0.1:4173"


def test_websocket_rejects_disallowed_origin_and_remote_client(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    repo = _repo(tmp_path)
    service = TaskService(repo, max_workers=1)
    monkeypatch.setitem(main_module.app.dependency_overrides, get_task_service, lambda: service)
    monkeypatch.setitem(main_module.app.dependency_overrides, get_task_repository, lambda: repo)
    client = TestClient(main_module.app)

    try:
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect(
                "/ws/tasks/t-1",
                headers={"origin": "http://evil.example"},
            ):
                pass

        monkeypatch.setattr(middleware_module, "_client_is_loopback", lambda _host: False)
        with pytest.raises(WebSocketDisconnect):
            with client.websocket_connect("/ws/tasks/t-1"):
                pass
    finally:
        service.shutdown()


# ---------------------------------------------------------------------------
# 3. Event-Driven WebSocket Push & TaskService Lifecycle
# ---------------------------------------------------------------------------
def test_websocket_pushes_progress_promptly_and_closes_1000_on_terminal(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    repo = _repo(tmp_path)
    service = TaskService(repo, max_workers=1)
    step_gate = threading.Event()
    finish_gate = threading.Event()

    def runner(_task):
        step_gate.wait(2.0)
        report_step("apk_snapshot", "success")
        finish_gate.wait(2.0)
        return {"ok": True, "status": "success"}

    service.set_runner(runner)
    monkeypatch.setitem(main_module.app.dependency_overrides, get_task_service, lambda: service)
    monkeypatch.setitem(main_module.app.dependency_overrides, get_task_repository, lambda: repo)
    client = TestClient(main_module.app)

    try:
        task_id = client.post(
            "/tasks",
            json={"task_type": "static", "apk_path": "D:/samples/app.apk"},
        ).json()["id"]

        started = time.monotonic()
        with client.websocket_connect(f"/ws/tasks/{task_id}") as ws:
            first = ws.receive_json()
            assert first["id"] == task_id

            step_gate.set()
            seen_snapshot = False
            for _ in range(5):
                msg = ws.receive_json()
                if any(s["step_key"] == "apk_snapshot" for s in msg.get("steps", [])):
                    seen_snapshot = True
                    break
            assert seen_snapshot is True

            finish_gate.set()
            terminal_msg: dict[str, Any] | None = None
            for _ in range(5):
                msg = ws.receive_json()
                if msg.get("status") == "completed":
                    terminal_msg = msg
                    break
            assert terminal_msg is not None
            assert time.monotonic() - started < 2.5

            with pytest.raises(WebSocketDisconnect) as exc_info:
                ws.receive_json()
            assert exc_info.value.code == 1000
    finally:
        step_gate.set()
        finish_gate.set()
        service.shutdown()


def test_task_service_cleans_futures_logs_redacted_traceback_and_graceful_shutdown(
    tmp_path: Path,
    caplog: pytest.LogCaptureFixture,
):
    repo = _repo(tmp_path)
    service = TaskService(repo, max_workers=1)
    secret = "sk-boom-secret-value-12345"

    def failing_runner(_task):
        raise RuntimeError(f"upstream failed with Bearer {secret}")

    service.set_runner(failing_runner)
    configure_logging("INFO")
    with caplog.at_level(logging.ERROR, logger="app.services.task_service"):
        failed_task = service.create(
            TaskCreateRequest(task_type="static", apk_path="D:/samples/app.apk")
        )
        terminal = _wait_terminal(service, failed_task.id)

    assert terminal.status == "failed"
    # Wait briefly for finally block to finish removing future after DB update
    deadline = time.monotonic() + 1.0
    while failed_task.id in service._futures and time.monotonic() < deadline:
        time.sleep(0.01)
    assert failed_task.id not in service._futures
    assert failed_task.id not in service._cancel_events
    assert any(
        "后台任务执行失败" in rec.getMessage() and rec.exc_info is not None
        for rec in caplog.records
    )

    # Graceful shutdown cancels running task + active consent checkpoint and waits for finally
    cleanup_ran = threading.Event()
    entered = threading.Event()
    consent = ConsentCheckpointService(clock=lambda: "2026-11-23T00:00:00Z")
    consent.enter(task_id="consent-task", run_id="run-1")

    def cancellable_runner(_task):
        entered.set()
        try:
            while True:
                checkpoint()
                time.sleep(0.01)
        finally:
            cleanup_ran.set()

    service.set_runner(cancellable_runner)
    running_task = service.create(
        TaskCreateRequest(task_type="dynamic", apk_path="D:/samples/app.apk", device_id="EMU-1")
    )
    assert entered.wait(1.0)
    cancelled_ids = consent.cancel_all()
    assert cancelled_ids == ["consent-task"]
    assert consent.state("consent-task").status == "cancelled"

    service.shutdown(wait=False, cancel_timeout=2.0)
    assert cleanup_ran.is_set() is True
    assert repo.get_task(running_task.id).status == "cancelled"


# ---------------------------------------------------------------------------
# 4. Artifact Cleanup & Static Unpack Cache LRU Eviction
# ---------------------------------------------------------------------------
def test_task_delete_removes_owned_run_dir_and_protects_shared_or_root_dirs(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
):
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path))
    repo = _repo(tmp_path)
    service = TaskService(repo, max_workers=1)

    runs_dir = tmp_path / "runs"
    run1_dir = runs_dir / "run-owned-1"
    run2_dir = runs_dir / "run-shared-2"
    outside_dir = tmp_path / "outside"
    for folder in (run1_dir, run2_dir, outside_dir):
        folder.mkdir(parents=True, exist_ok=True)
        (folder / "report.json").write_text("{}", encoding="utf-8")
    (runs_dir / "report.json").write_text("{}", encoding="utf-8")

    # 1. Task with dedicated runs/<run_id> directory -> deleted
    t1 = repo.create_task(
        {"id": "t1", "task_type": "static", "status": "completed", "apk_path": "a.apk"}
    )
    repo.update_task("t1", report_json_path=str(run1_dir / "report.json"))
    assert service.delete(t1.id) is True
    assert not run1_dir.exists()

    # 2. Task whose report sits directly inside runs/ (no <run_id> subdir) -> runs/ is NOT deleted
    t_root = repo.create_task(
        {"id": "t-root", "task_type": "static", "status": "completed", "apk_path": "a.apk"}
    )
    repo.update_task("t-root", report_json_path=str(runs_dir / "report.json"))
    assert service.delete(t_root.id) is True
    assert runs_dir.is_dir()

    # 3. Path outside OUTPUT_DIR/runs -> untouched
    t_out = repo.create_task(
        {"id": "t-out", "task_type": "static", "status": "completed", "apk_path": "a.apk"}
    )
    repo.update_task("t-out", report_json_path=str(outside_dir / "report.json"))
    assert service.delete(t_out.id) is True
    assert outside_dir.is_dir()

    # 4. Shared run dir referenced by another task -> preserved until last reference removed
    t2a = repo.create_task(
        {"id": "t2a", "task_type": "static", "status": "completed", "apk_path": "a.apk"}
    )
    t2b = repo.create_task(
        {"id": "t2b", "task_type": "static", "status": "completed", "apk_path": "a.apk"}
    )
    repo.update_task("t2a", report_json_path=str(run2_dir / "report.json"))
    repo.update_task("t2b", report_json_path=str(run2_dir / "report.json"))
    assert service.delete(t2a.id) is True
    assert run2_dir.is_dir()
    assert service.delete(t2b.id) is True
    assert not run2_dir.exists()

    # 5. Orphaned directory cleanup respects min_age and active tasks
    orphan_old = runs_dir / "orphan-old"
    orphan_new = runs_dir / "orphan-new"
    orphan_old.mkdir()
    orphan_new.mkdir()
    old_ts = time.time() - 3600
    os.utime(orphan_old, (old_ts, old_ts))

    # Active running task pauses orphan sweep
    repo.create_task(
        {"id": "t-run", "task_type": "static", "status": "running", "apk_path": "a.apk"}
    )
    assert service.cleanup_orphaned_run_dirs(min_age_seconds=600) == 0
    repo.update_task("t-run", status="completed")

    removed = service.cleanup_orphaned_run_dirs(min_age_seconds=600)
    assert removed == 1
    assert not orphan_old.exists()
    assert orphan_new.exists()
    service.shutdown()


def test_static_unpack_cache_lru_eviction_and_disabled_mode(tmp_path: Path):
    apk = tmp_path / "sample.apk"
    apk.write_bytes(b"apk")
    cache_root = tmp_path / "cache"

    def make_unpacker(payload_bytes: int):
        def unpack(_apk: str, output: str):
            target = Path(output)
            target.mkdir(parents=True)
            (target / "AndroidManifest.xml").write_text("<manifest/>", encoding="utf-8")
            (target / "blob.bin").write_bytes(b"x" * payload_bytes)
            return {"returncode": 0, "stdout": "", "stderr": ""}

        return unpack

    # Each entry is ~1000+ bytes; cap at 2500 bytes so at most 2 entries fit
    sha_a = "a" * 64
    sha_b = "b" * 64
    sha_c = "c" * 64

    prepare_static_unpack(
        snapshot_path=apk,
        apk_sha256=sha_a,
        cache_root=cache_root,
        apktool_version="2.11.1",
        unpacker=make_unpacker(1000),
        max_cache_bytes=2500,
    )
    prepare_static_unpack(
        snapshot_path=apk,
        apk_sha256=sha_b,
        cache_root=cache_root,
        apktool_version="2.11.1",
        unpacker=make_unpacker(1000),
        max_cache_bytes=2500,
    )

    # Make sha_a older, then hit sha_a so its metadata.json becomes newer than sha_b
    os.utime(cache_root / sha_a / "metadata.json", (1_000_000, 1_000_000))
    os.utime(cache_root / sha_b / "metadata.json", (2_000_000, 2_000_000))
    hit_a = prepare_static_unpack(
        snapshot_path=apk,
        apk_sha256=sha_a,
        cache_root=cache_root,
        apktool_version="2.11.1",
        unpacker=make_unpacker(1000),
        max_cache_bytes=2500,
    )
    assert hit_a.cache_hit is True
    # Re-pin sha_b older than touched sha_a deterministically
    os.utime(cache_root / sha_b / "metadata.json", (2_000_000, 2_000_000))

    # Build sha_c -> triggers eviction; sha_b (LRU) should be evicted while sha_a & sha_c remain
    built_c = prepare_static_unpack(
        snapshot_path=apk,
        apk_sha256=sha_c,
        cache_root=cache_root,
        apktool_version="2.11.1",
        unpacker=make_unpacker(1000),
        max_cache_bytes=2500,
    )
    assert built_c.cache_hit is False
    assert (cache_root / sha_a).is_dir()
    assert not (cache_root / sha_b).exists()
    assert (cache_root / sha_c).is_dir()

    # Disabled mode (max_bytes=0) evicts nothing
    assert evict_static_unpack_cache(cache_root, max_bytes=0) == []
    assert (cache_root / sha_a).is_dir()
    assert (cache_root / sha_c).is_dir()

    # Preserves freshly built entry even if single entry exceeds max_cache_bytes
    sha_big = "d" * 64
    prepare_static_unpack(
        snapshot_path=apk,
        apk_sha256=sha_big,
        cache_root=cache_root,
        apktool_version="2.11.1",
        unpacker=make_unpacker(5000),
        max_cache_bytes=2500,
    )
    assert (cache_root / sha_big).is_dir()
    assert not (cache_root / sha_a).exists()
    assert not (cache_root / sha_c).exists()
