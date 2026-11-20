"""Ownership-registry effects of the decomposed dynamic execution steps."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from app.core.device import DeviceContext
from app.core.run_context import AnalysisRunContext
from app.orchestration.cleanup_manager import ResourceOwnershipRegistry
from app.pipelines import dynamic as dynamic_module


def _context(tmp_path: Path) -> AnalysisRunContext:
    run_dir = tmp_path / "run"
    traffic_dir = run_dir / "traffic"
    return AnalysisRunContext(
        run_id="run-1",
        apk_path=run_dir / "input" / "app.apk",
        apk_sha256="0" * 64,
        output_root=tmp_path,
        run_dir=run_dir,
        unpacked_dir=run_dir / "unpacked",
        hook_log_path=run_dir / "hook.log",
        events_path=run_dir / "events.json",
        traffic_dir=traffic_dir,
        traffic_summary_path=traffic_dir / "traffic-summary.json",
        report_json_path=run_dir / "report.json",
        report_markdown_path=run_dir / "report.md",
        device_id=None,
        normalized_apk_name="app.apk",
        started_at=datetime.now(UTC),
        flow_file_path=traffic_dir / "flows.mitm",
        mitm_stream_log_path=traffic_dir / "mitm_stream.log",
    )


class _FakeSession:
    def __init__(self, pid: int, mode: str, helper_pid: int | None = None) -> None:
        self.pid = pid
        self.selected_mode = mode
        self.helper_pid = helper_pid


def test_frida_started_spawn_registers_owned_target_and_helper(tmp_path: Path) -> None:
    context = _context(tmp_path)
    device = DeviceContext(serial="emulator-5554")
    registry = ResourceOwnershipRegistry()
    register = dynamic_module._register_owned_target(context, device, "com.example.app", registry)
    _, register_frida_started = dynamic_module._make_collection_callbacks(
        context, device, "com.example.app", registry, register
    )

    register_frida_started(_FakeSession(pid=4242, mode="spawn_suspended", helper_pid=999))

    target = registry.get("app_process", "4242")
    assert target is not None
    assert target.ownership == "owned_by_run"
    assert target.detail["ownership_source"] == "frida_spawn"
    assert target.detail["created_by_run"] is True
    helper = registry.get("frida_helper", "999")
    assert helper is not None
    assert helper.ownership == "owned_by_run"
    assert helper.detail["ownership_source"] == "frida_session_helper_start"


def test_frida_started_attach_registers_external_target(tmp_path: Path) -> None:
    context = _context(tmp_path)
    device = DeviceContext(serial="emulator-5554")
    registry = ResourceOwnershipRegistry()
    register = dynamic_module._register_owned_target(context, device, "com.example.app", registry)
    _, register_frida_started = dynamic_module._make_collection_callbacks(
        context, device, "com.example.app", registry, register
    )

    register_frida_started(_FakeSession(pid=4242, mode="attach_existing"))

    target = registry.get("app_process", "4242")
    assert target is not None
    assert target.ownership == "external"
    assert target.detail["ownership_source"] == "frida_attach_existing"
    assert target.detail["created_by_run"] is False


def test_noop_registrar_never_claims_ownership(tmp_path: Path) -> None:
    context = _context(tmp_path)
    device = DeviceContext(serial="emulator-5554")
    registry = ResourceOwnershipRegistry()
    _, register_frida_started = dynamic_module._make_collection_callbacks(
        context,
        device,
        "com.example.app",
        registry,
        dynamic_module._noop_register_runtime_target,
    )

    register_frida_started(_FakeSession(pid=4242, mode="spawn_suspended", helper_pid=999))

    assert registry.get("app_process", "4242") is None
    # The helper registration is independent of the runtime-target registrar.
    assert registry.get("frida_helper", "999") is not None


def test_launch_target_registers_pid_after_successful_launch(
    tmp_path: Path, monkeypatch: Any
) -> None:
    context = _context(tmp_path)
    device = DeviceContext(serial="emulator-5554")
    registry = ResourceOwnershipRegistry()
    register = dynamic_module._register_owned_target(context, device, "com.example.app", registry)

    monkeypatch.setattr(
        dynamic_module,
        "launch_app",
        lambda package, device_context=None: {"returncode": 0},
    )
    pid_calls = {"count": 0}

    def fake_run_cmd(command: list[str], timeout: int = 10) -> dict[str, Any]:
        pid_calls["count"] += 1
        if pid_calls["count"] == 1:
            return {"returncode": 1, "stdout": ""}
        return {"returncode": 0, "stdout": "4242"}

    monkeypatch.setattr(dynamic_module, "run_cmd", fake_run_cmd)
    monkeypatch.setattr(dynamic_module.time, "sleep", lambda _seconds: None)

    launch = dynamic_module._make_launch_target_for_attach(
        context, device, "com.example.app", register
    )
    payload = launch()

    assert payload["pid"] == 4242
    target = registry.get("app_process", "4242")
    assert target is not None
    assert target.detail["ownership_source"] == "launch_then_attach_pidof"
    assert target.detail["created_by_run"] is True
