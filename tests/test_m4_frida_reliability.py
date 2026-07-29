from __future__ import annotations

import json
import struct
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from app.core.device import DeviceContext
from app.frida.diagnostics import FridaDiagnosticsService
from app.frida.errors import DynamicErrorCode, legacy_error_code
from app.frida.execution_session import PolicyFridaSession
from app.frida.execution_modes import (
    DynamicModePolicy,
    ExecutionMode,
    build_evidence_quality,
    select_execution_mode,
)
from app.frida.models import FridaDiagnosticsRequest
from app.frida.process_monitor import classify_process_exit
from app.frida.server_manager import FridaServerManager
from app.frida.traffic_diagnostics import diagnose_traffic
from app.main import app


class FakeProcess:
    def __init__(self, pid: int, name: str, identifier: str):
        self.pid = pid
        self.name = name
        self.identifier = identifier


class FakeDevice:
    id = "SERIAL"

    def enumerate_processes(self):
        return [FakeProcess(123, "com.example.app", "com.example.app")]


class FakeManager:
    def get_device(self, serial: str, timeout: int):
        assert serial == "SERIAL"
        assert timeout == 10_000
        return FakeDevice()


class FakeFrida:
    __version__ = "17.5.2"

    @staticmethod
    def get_device_manager():
        return FakeManager()


def diagnostic_runner(command, cwd=None, timeout=10):
    del cwd, timeout
    text = " ".join(str(value) for value in command)
    stdout = ""
    returncode = 0
    if "--version" in text:
        stdout = "17.5.2\n"
    elif "get-state" in text:
        stdout = "device\n"
    elif "ro.product.cpu.abi" in text:
        stdout = "x86_64\n"
    elif "ro.build.version.release" in text:
        stdout = "15\n"
    elif "ro.build.version.sdk" in text:
        stdout = "35\n"
    elif "ro.product.manufacturer" in text:
        stdout = "MuMu\n"
    elif "ro.product.model" in text:
        stdout = "Emulator\n"
    elif "getenforce" in text:
        stdout = "Enforcing\n"
    elif text.endswith(" shell id"):
        stdout = "uid=2000(shell)\n"
    elif "su -c id" in text:
        stdout = "uid=0(root)\n"
    elif "df -k" in text:
        stdout = "/data 1048576 10 1048566 1%\n"
    elif "date +%s" in text:
        stdout = "1785312000\n"
    elif "settings get global http_proxy" in text:
        stdout = "null\n"
    elif "ls -l /data/local/tmp/frida-server" in text:
        stdout = "-rwxr-xr-x 1 root root 100 frida-server\n"
    elif "pidof frida-server" in text:
        stdout = "4321\n"
    elif "netstat -lnt" in text:
        stdout = "tcp 0 0 0.0.0.0:27042 LISTEN\n"
    elif "sha256sum" in text:
        stdout = "a" * 64 + "  /data/local/tmp/frida-server\n"
    elif "pm path com.example.app" in text:
        stdout = "package:/data/app/base.apk\n"
    elif "pidof com.example.app" in text:
        stdout = "123\n"
    return {
        "returncode": returncode,
        "stdout": stdout,
        "stderr": "",
        "timed_out": False,
        "cmd": command,
    }


def test_legacy_errors_map_to_precise_codes():
    assert legacy_error_code("frida_server_unavailable") == (
        DynamicErrorCode.FRIDA_SERVER_TRANSPORT_UNREACHABLE.value
    )
    assert legacy_error_code("custom_error") == "custom_error"


def test_diagnostics_are_layered_ready_and_serial_is_private():
    service = FridaDiagnosticsService(
        project_root=Path(__file__).resolve().parents[1],
        server_remote_path="/data/local/tmp/frida-server",
        command_runner=diagnostic_runner,
        module_loader=lambda name: FakeFrida,
        which=lambda name: None,
    )
    result = service.diagnose(
        FridaDiagnosticsRequest(
            device_id="SERIAL",
            package_name="com.example.app",
        )
    )
    payload = result.model_dump(mode="json")
    assert result.schema_version == "frida-diagnostics-v1"
    assert result.overall_status == "ready"
    assert result.recommended_mode == "spawn_suspended"
    assert result.transport.checks["handshake"].status == "pass"
    assert "SERIAL" not in json.dumps(payload)
    assert result.device_ref.startswith("redacted:")


@pytest.mark.parametrize(
    ("state", "code"),
    [
        ("offline", "device_offline"),
        ("unauthorized", "device_unauthorized"),
        ("missing", "device_not_found"),
    ],
)
def test_device_state_is_precisely_classified(state, code):
    def runner(command, cwd=None, timeout=10):
        result = diagnostic_runner(command, cwd, timeout)
        if "get-state" in command:
            result["stdout"] = state if state != "missing" else ""
            result["stderr"] = state if state == "missing" else ""
            result["returncode"] = 1
        return result

    service = FridaDiagnosticsService(
        project_root=Path(__file__).resolve().parents[1],
        server_remote_path="/data/local/tmp/frida-server",
        command_runner=runner,
        module_loader=lambda name: FakeFrida,
    )
    result = service.diagnose(FridaDiagnosticsRequest(device_id="SERIAL"))
    assert result.device.checks["adb_state"].error_code == code
    assert result.overall_status == "blocked"


def test_binding_import_failure_is_not_reported_as_transport_success():
    def loader(name):
        raise ImportError("broken native dependency")

    service = FridaDiagnosticsService(
        project_root=Path(__file__).resolve().parents[1],
        server_remote_path="/data/local/tmp/frida-server",
        command_runner=diagnostic_runner,
        module_loader=loader,
    )
    result = service.diagnose(FridaDiagnosticsRequest(device_id="SERIAL"))
    assert result.host.checks["python_binding"].error_code == "host_frida_import_failed"
    assert result.transport.checks["handshake"].error_code == (
        "frida_server_transport_unreachable"
    )


def test_strict_mode_never_falls_back():
    decision = select_execution_mode(
        DynamicModePolicy.STRICT,
        spawn_suspended_ready=False,
        existing_process=True,
    )
    assert decision.selected_mode is ExecutionMode.NONE
    assert [item.mode for item in decision.attempts] == [
        ExecutionMode.SPAWN_SUSPENDED
    ]


def test_balanced_mode_records_attach_fallback():
    decision = select_execution_mode(
        DynamicModePolicy.BALANCED,
        spawn_suspended_ready=False,
        existing_process=True,
    )
    assert decision.selected_mode is ExecutionMode.ATTACH_EXISTING
    assert decision.fallback_path == [
        ExecutionMode.SPAWN,
        ExecutionMode.ATTACH_EXISTING,
    ]
    assert decision.attempts[0].status == "failed"


def test_policy_session_balanced_can_launch_then_attach():
    calls: list[str] = []

    class ModeError(RuntimeError):
        code = "mode_failed"

    class FakeSession:
        error_code: str | None = None

        def __init__(self, mode: ExecutionMode):
            self.mode = mode

        def start(self):
            calls.append(f"start:{self.mode.value}")
            if self.mode is not ExecutionMode.LAUNCH_THEN_ATTACH:
                self.error_code = "mode_failed"
                raise ModeError("mode failed")
            return self

        def stop(self):
            calls.append(f"stop:{self.mode.value}")
            return True

    session = PolicyFridaSession(
        policy=DynamicModePolicy.BALANCED,
        session_factory=FakeSession,
        launch_target=lambda: calls.append("launch"),
    ).start()

    assert session.selected_mode is ExecutionMode.LAUNCH_THEN_ATTACH
    assert session.fallback_path == ["attach_existing", "launch_then_attach"]
    assert calls == [
        "start:spawn_suspended",
        "stop:spawn_suspended",
        "start:attach_existing",
        "stop:attach_existing",
        "launch",
        "start:launch_then_attach",
    ]


@pytest.mark.parametrize(
    ("mode", "expected"),
    [
        (ExecutionMode.SPAWN_SUSPENDED, "A"),
        (ExecutionMode.SPAWN, "B"),
        (ExecutionMode.ATTACH_EXISTING, "C"),
        (ExecutionMode.NONE, "D"),
    ],
)
def test_evidence_levels_explain_mode_coverage(mode, expected):
    quality = build_evidence_quality(
        mode,
        transport_trusted=mode is not ExecutionMode.NONE,
        hook_ready_trusted=mode is not ExecutionMode.NONE,
        event_protocol_trusted=mode is not ExecutionMode.NONE,
        consent_boundary_trusted=mode is ExecutionMode.SPAWN_SUSPENDED,
        network_evidence=False,
    )
    assert quality.level == expected
    assert quality.coverage
    assert quality.untrusted_capabilities


def test_crash_requires_crash_signal():
    result = classify_process_exit(
        pid=10,
        duration_ms=420,
        hook_ready=True,
        hook_event_count=0,
        detached_reason="process-terminated",
        logcat_lines=["AndroidRuntime: FATAL EXCEPTION: main"],
        process_still_running=False,
    )
    assert result.status == "process_crashed"
    assert result.confidence == "high"


def test_exit_alone_does_not_claim_antidebug():
    result = classify_process_exit(
        pid=10,
        duration_ms=420,
        hook_ready=False,
        hook_event_count=0,
        detached_reason="process-terminated",
        logcat_lines=[],
        process_still_running=False,
    )
    assert result.status != "anti_debug_suspected"
    assert result.confidence == "low"


def test_pinning_requires_tls_and_ready_proxy_evidence():
    zero = diagnose_traffic(
        collector_outcome="collector_success_zero_requests",
        request_count=0,
        session_status={"ready_at": "now", "device_proxy_restored": True},
        stderr_text="",
    )
    assert not zero.pinning_suspected
    assert "零请求不代表应用没有网络行为" in zero.limitations
    tls = diagnose_traffic(
        collector_outcome="collector_success_zero_requests",
        request_count=0,
        session_status={"ready_at": "now", "device_proxy_restored": True},
        stderr_text="TLS handshake failed: certificate verify failed",
    )
    assert tls.tls_failure_observed
    assert tls.pinning_suspected


def make_manager(tmp_path, runner, *, enabled=True, local_path=""):
    return FridaServerManager(
        enabled=enabled,
        local_path=local_path,
        remote_path="/data/local/tmp/frida-server",
        start_timeout_seconds=1,
        handshake_timeout_seconds=1,
        command_runner=runner,
    )


def test_server_management_is_disabled_by_default(tmp_path):
    manager = make_manager(tmp_path, diagnostic_runner, enabled=False)
    result = manager.start(DeviceContext("SERIAL"), confirm=True)
    assert result.status == "not_configured"


def test_server_actions_require_confirmation(tmp_path):
    manager = make_manager(tmp_path, diagnostic_runner)
    result = manager.start(DeviceContext("SERIAL"), confirm=False)
    assert result.error_code == "confirmation_required"


def test_unknown_running_server_is_never_stopped(tmp_path):
    commands = []

    def runner(command, cwd=None, timeout=10):
        commands.append(command)
        return diagnostic_runner(command, cwd, timeout)

    manager = make_manager(tmp_path, runner)
    result = manager.stop(DeviceContext("SERIAL"), confirm=True)
    assert result.status == "not_owned"
    assert not any(" kill " in f" {' '.join(command)} " for command in commands)


def test_local_server_elf_architecture_is_validated(tmp_path):
    binary = tmp_path / "frida-server"
    header = bytearray(20)
    header[:4] = b"\x7fELF"
    header[5] = 1
    header[18:20] = struct.pack("<H", 62)
    binary.write_bytes(bytes(header) + b"\0" * (1024 * 1024))
    manager = make_manager(
        tmp_path,
        diagnostic_runner,
        local_path=str(binary),
    )
    validated = manager.validate_local_binary()
    assert validated.architecture == "x86_64"
    assert len(validated.sha256) == 64


def test_diagnostics_api_rejects_missing_device_id():
    response = TestClient(app).post("/frida/diagnostics", json={})
    assert response.status_code == 422
