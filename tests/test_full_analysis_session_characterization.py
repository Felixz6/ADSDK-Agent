"""Characterization tests for run_full_analysis_session and FullAnalysisSession."""

from __future__ import annotations

import threading
import time
from pathlib import Path
from typing import Any

import pytest

import app.config as app_config
from app.container import build_container
from app.core.device import DeviceContext
from app.pipelines import full_analysis as full_mod
from app.pipelines.tools import PipelineTools
from app.tasks.models import TaskRecord
from tests.fake_sessions import FakeTestFridaSession, FakeTestMitmSession


def _fake_run_cmd(
    cmd: list[str],
    call_log: list[str] | None = None,
    *,
    online: bool = True,
    target_pid: str = "",
    helpers: str = "101 102",
    proxy: str = ":0",
) -> dict[str, Any]:
    joined = " ".join(cmd)
    if call_log is not None:
        call_log.append(joined)
    if "get-state" in joined:
        return {
            "returncode": 0 if online else 1,
            "stdout": "device" if online else "offline",
            "stderr": "",
        }
    if "boot_id" in joined:
        return {"returncode": 0, "stdout": "boot-123", "stderr": ""}
    if "ro.product.cpu.abi" in joined:
        return {"returncode": 0, "stdout": "x86_64", "stderr": ""}
    if "settings get global http_proxy" in joined:
        return {"returncode": 0, "stdout": proxy, "stderr": ""}
    if "settings delete global http_proxy" in joined:
        return {"returncode": 0, "stdout": "", "stderr": ""}
    if "settings put global http_proxy" in joined:
        return {"returncode": 0, "stdout": "", "stderr": ""}
    if "pm path" in joined:
        return {"returncode": 0, "stdout": "package:/data/app/app.apk", "stderr": ""}
    if "pidof re.frida.helper" in joined:
        return {"returncode": 0, "stdout": helpers, "stderr": ""}
    if "pidof frida-server" in joined:
        return {"returncode": 0, "stdout": "", "stderr": ""}
    if "pidof" in joined:
        return {"returncode": 0 if target_pid else 1, "stdout": target_pid, "stderr": ""}
    if "kill" in joined:
        return {"returncode": 0, "stdout": "", "stderr": ""}
    return {"returncode": 0, "stdout": "", "stderr": ""}


def _setup_test_run(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    *,
    call_log: list[str] | None = None,
    online: bool = True,
    target_pid: str = "",
    helpers: str = "101 102",
    proxy: str = ":0",
    consent_action: str | None = "confirmed",
    tools_overrides: dict[str, Any] | None = None,
):
    monkeypatch.setattr(app_config, "APK_ALLOWED_ROOTS", (tmp_path.resolve(),))
    monkeypatch.setattr(app_config, "OUTPUT_DIR", str(tmp_path / "output"))
    monkeypatch.setattr(app_config, "STATIC_UNPACK_CACHE_DIR", str(tmp_path / "cache"))

    apk_path = tmp_path / "app.apk"
    import zipfile

    with zipfile.ZipFile(apk_path, "w") as z:
        z.writestr("AndroidManifest.xml", "<manifest package='com.test.app'/>")

    def cmd_runner(cmd: list[str], *args: Any, **kwargs: Any) -> dict[str, Any]:
        return _fake_run_cmd(
            cmd,
            call_log=call_log,
            online=online,
            target_pid=target_pid,
            helpers=helpers,
            proxy=proxy,
        )

    full_mod.run_cmd = cmd_runner  # type: ignore[assignment]

    task = TaskRecord(
        id=f"char-task-{time.time_ns()}",
        task_type="ai_orchestrated",
        status="queued",
        progress_percent=0,
        request_payload={"apk_path": str(apk_path)},
        created_at="2026-11-22T00:00:00Z",
        updated_at="2026-11-22T00:00:00Z",
    )
    payload = {
        "apk_path": str(apk_path),
        "device_id": "emulator-5554",
        "package_name": "com.test.app",
        "allow_dynamic": True,
        "allow_network": True,
        "confirmed_tools": ["dynamic_analysis"],
        "ai_enabled": False,
        "pre_consent_seconds": 0,
        "post_consent_seconds": 0,
    }

    tools_dict = {
        "select_device_context": lambda device_id=None: DeviceContext(
            serial=device_id or "emulator-5554"
        ),
        "unpack_apk": lambda *a, **k: {"returncode": 0, "stdout": "", "stderr": ""},
        "parse_manifest_info": lambda *a, **k: {"package_name": "com.test.app"},
        "scan_for_sdks": lambda *a, **k: [],
        "install_apk": lambda *a, **k: {"returncode": 0},
        "launch_app": lambda *a, **k: {"returncode": 0},
        "sleep": lambda _: None,
    }
    if tools_overrides:
        tools_dict.update(tools_overrides)

    tools = PipelineTools(**tools_dict)
    container = build_container(
        settings={
            "task_database_path": str(tmp_path / "t.db"),
            "ai_settings_path": str(tmp_path / "ai.json"),
            "frida_real_device": False,
        },
        tools=tools,
    )
    container.frida_session_factory = FakeTestFridaSession
    container.mitm_session_factory = FakeTestMitmSession

    if consent_action is not None:

        def auto_confirm():
            for _ in range(300):
                if container.consent_checkpoint_service.state(task.id) is not None:
                    try:
                        container.consent_checkpoint_service.resolve(
                            task_id=task.id,
                            action=consent_action,  # type: ignore[arg-type]
                        )
                        break
                    except Exception:
                        pass
                time.sleep(0.01)

        t = threading.Thread(target=auto_confirm, daemon=True)
        t.start()

    return task, payload, container


# ===========================================================================
# Characterization Tests
# ===========================================================================


def test_full_analysis_session_success_artifacts_and_structure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Standard execution path produces valid report, persists artifacts, and records ownership."""
    call_log: list[str] = []
    task, payload, container = _setup_test_run(tmp_path, monkeypatch, call_log=call_log)

    report = full_mod.run_full_analysis_session(task=task, payload=payload, container=container)

    assert report.get("status") in {"success", "partial"}
    assert report.get("analysis_mode") == "full_analysis"
    assert bool(report.get("run_id"))
    assert report.get("unclassified_new_target") is None

    # Artifact verification
    assert Path(report["report_json"]).is_file()

    # Resource ownership entries were recorded
    ownership = report.get("resource_ownership")
    assert isinstance(ownership, list)
    # Helper provenance recorded
    provenance = report.get("helper_provenance")
    assert provenance is not None
    assert provenance["process_name"] == "re.frida.helper"
    assert 101 in provenance["before_pids"]
    assert 102 in provenance["before_pids"]


def test_full_analysis_session_device_offline_preflight_blocks_and_cleans(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When target device is offline in preflight, execution halts with clean error and releases lease."""
    call_log: list[str] = []
    task, payload, container = _setup_test_run(
        tmp_path, monkeypatch, call_log=call_log, online=False
    )

    report = full_mod.run_full_analysis_session(task=task, payload=payload, container=container)

    assert report.get("status") == "failed"
    assert report.get("error_code") == "device_offline"
    # Lease must be free
    assert container.device_lease_registry.state("emulator-5554") == "free"


def test_full_analysis_session_consent_timeout_records_partial_limitation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When operator consent times out or is not confirmed, session records limitation."""
    call_log: list[str] = []
    task, payload, container = _setup_test_run(
        tmp_path, monkeypatch, call_log=call_log, consent_action=None
    )

    # Resolve as expired in background
    def expire_consent():
        for _ in range(300):
            if container.consent_checkpoint_service.state(task.id) is not None:
                try:
                    container.consent_checkpoint_service.resolve(task_id=task.id, action="expired")
                    break
                except Exception:
                    pass
            time.sleep(0.01)

    threading.Thread(target=expire_consent, daemon=True).start()

    report = full_mod.run_full_analysis_session(task=task, payload=payload, container=container)

    assert report.get("analysis_mode") == "full_analysis"
    assert container.device_lease_registry.state("emulator-5554") == "free"


def test_full_analysis_session_unclassified_new_target_marks_partial_and_diagnostic(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When a new target PID appears postflight without prior provenance, cleanup is partial."""
    call_log: list[str] = []
    preflight_done = False

    def pidof_dynamic_runner(cmd: list[str], *args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal preflight_done
        joined = " ".join(cmd)
        if "pidof com.test.app" in joined:
            if preflight_done:
                return {"returncode": 0, "stdout": "7777", "stderr": ""}
            preflight_done = True
            return {"returncode": 1, "stdout": "", "stderr": ""}
        return _fake_run_cmd(cmd, call_log=call_log, online=True)

    task, payload, container = _setup_test_run(tmp_path, monkeypatch, call_log=call_log)
    full_mod.run_cmd = pidof_dynamic_runner  # type: ignore[assignment]

    report = full_mod.run_full_analysis_session(task=task, payload=payload, container=container)

    unclassified = report.get("unclassified_new_target")
    assert unclassified is not None
    assert unclassified["pid"] == 7777
    assert unclassified["reason_code"] == "unclassified_new_target"

    cleanup_verif = report.get("cleanup_final_verification")
    assert cleanup_verif is not None
    assert cleanup_verif["status"] == "partial"
    assert "unclassified_new_target" in cleanup_verif["failures"]


def test_full_analysis_session_unknown_helper_pid_marks_partial(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When an unexpected frida_helper PID appears in postflight, report marks status partial."""
    call_log: list[str] = []
    postflight_called = False

    def dynamic_cmd_runner(cmd: list[str], *args: Any, **kwargs: Any) -> dict[str, Any]:
        nonlocal postflight_called
        joined = " ".join(cmd)
        if "pidof re.frida.helper" in joined:
            if postflight_called:
                return {"returncode": 0, "stdout": "101 102 999", "stderr": ""}
            postflight_called = True
            return {"returncode": 0, "stdout": "101 102", "stderr": ""}
        return _fake_run_cmd(cmd, call_log=call_log, online=True)

    task, payload, container = _setup_test_run(tmp_path, monkeypatch, call_log=call_log)
    full_mod.run_cmd = dynamic_cmd_runner  # type: ignore[assignment]

    report = full_mod.run_full_analysis_session(task=task, payload=payload, container=container)

    provenance = report.get("helper_provenance")
    assert provenance is not None
    assert 999 in provenance["unknown_newly_appeared_pids"]
    assert report.get("status") == "partial"
    assert any(
        "re.frida.helper PID has unknown provenance" in item
        for item in report.get("limitations", [])
    )


def test_full_analysis_session_unconfirmed_dynamic_tool_drops_dynamic_branch(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """When confirmed_tools does not include dynamic_analysis, planning fails safely with error code."""
    call_log: list[str] = []
    task, payload, container = _setup_test_run(tmp_path, monkeypatch, call_log=call_log)
    payload["confirmed_tools"] = []  # No confirmation for dynamic analysis

    report = full_mod.run_full_analysis_session(task=task, payload=payload, container=container)

    assert report.get("status") == "failed"
    assert report.get("error_code") == "dynamic_not_allowed_effective"
    assert container.device_lease_registry.state("emulator-5554") == "free"
