from __future__ import annotations

import json
import struct
from datetime import datetime, timezone
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
    assert result.capabilities.transport_available is True
    assert result.capabilities.process_enumeration_available is True
    assert result.capabilities.attach_available is True


def test_successful_handshake_outweighs_hidden_server_process_name():
    def runner(command, cwd=None, timeout=10):
        result = diagnostic_runner(command, cwd, timeout)
        if "pidof" in command and "frida-server" in command:
            result["returncode"] = 1
            result["stdout"] = ""
        return result

    service = FridaDiagnosticsService(
        project_root=Path(__file__).resolve().parents[1],
        server_remote_path="/data/local/tmp/frida-server",
        command_runner=runner,
        module_loader=lambda name: FakeFrida,
        which=lambda name: None,
    )
    result = service.diagnose(
        FridaDiagnosticsRequest(
            device_id="SERIAL",
            package_name="com.example.app",
        )
    )
    assert result.transport.checks["handshake"].status == "pass"
    assert result.server.checks["process"].status == "warning"
    assert result.overall_status == "ready"


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
    assert session.fallback_path == ["launch_then_attach"]
    assert calls == [
        "start:spawn_suspended",
        "stop:spawn_suspended",
        "launch",
        "start:launch_then_attach",
    ]


def test_balanced_falls_back_after_post_resume_native_crash_and_keeps_evidence():
    calls: list[str] = []

    class RuntimeCrash(RuntimeError):
        code = "process_crashed"

    class FakeSession:
        error_code: str | None = None
        error_message: str | None = None
        post_resume_survival_ms: int | None = None
        crash: dict | None = None
        valid_events: list[dict] = []
        valid_messages: list[dict] = []
        control_events: list[dict] = []
        protocol_errors: list[dict] = []
        cleanup_errors: list[str] = []

        def __init__(self, mode: ExecutionMode):
            self.mode = mode
            self.pid = 10 if mode is ExecutionMode.SPAWN_SUSPENDED else 20

        def start(self):
            calls.append(f"start:{self.mode.value}")
            return self

        def wait_ready(self, timeout_seconds=1):
            calls.append(f"ready:{self.mode.value}")
            return True

        def resume(self):
            calls.append(f"resume:{self.mode.value}")
            return True

        def wait_stable(self, timeout_seconds):
            calls.append(f"stable:{self.mode.value}:{timeout_seconds}")
            if self.mode is ExecutionMode.SPAWN_SUSPENDED:
                self.error_code = "process_crashed"
                self.post_resume_survival_ms = 980
                self.crash = {"summary": "trying to execute non-executable memory"}
                raise RuntimeCrash("native crash")
            return True

        def stop(self, *args, **kwargs):
            calls.append(f"stop:{self.mode.value}")
            return True

    launch_requested = datetime(2026, 7, 29, tzinfo=timezone.utc)
    session = PolicyFridaSession(
        policy=DynamicModePolicy.BALANCED,
        session_factory=FakeSession,
        launch_target=lambda: {
            "launch_requested_at": "2026-07-29T00:00:00.000Z",
            "pid_observed_at": "2026-07-29T00:00:00.100Z",
            "_launch_requested_datetime": launch_requested,
        },
    ).start()
    session.wait_ready(timeout_seconds=1)
    session.resume()
    assert session.wait_stable(3) is True

    assert session.selected_mode is ExecutionMode.LAUNCH_THEN_ATTACH
    assert session.environment_capabilities == {
        "transport_available": True,
        "process_enumeration_available": True,
        "attach_available": True,
        "spawn_creation_available": True,
        "spawn_resume_stable": False,
    }
    assert session.attempts[0].status == "failed"
    assert session.attempts[0].phase == "post_resume_stability"
    assert session.attempts[0].reason_code == "spawn_runtime_failed"
    assert session.attempts[0].process_result == "process_crashed"
    assert session.attempts[0].post_resume_survival_ms == 980
    assert session.attempts[0].crash is not None
    assert session.attempts[1].status == "success"
    assert session.attempts[1].phase == "collecting"
    assert session.fallback_path == ["launch_then_attach"]
    assert calls[:5] == [
        "start:spawn_suspended",
        "ready:spawn_suspended",
        "resume:spawn_suspended",
        "stable:spawn_suspended:3",
        "stop:spawn_suspended",
    ]


def test_strict_records_runtime_crash_without_fallback():
    class RuntimeCrash(RuntimeError):
        code = "process_crashed"

    class FakeSession:
        error_code = "process_crashed"
        error_message = "native crash"
        post_resume_survival_ms = 1000
        crash = {"summary": "trying to execute non-executable memory"}
        pid = 10

        def start(self):
            return self

        def wait_ready(self, timeout_seconds=1):
            return True

        def resume(self):
            return True

        def wait_stable(self, timeout_seconds):
            raise RuntimeCrash("native crash")

        def stop(self, *args, **kwargs):
            return True

    session = PolicyFridaSession(
        policy=DynamicModePolicy.STRICT,
        session_factory=lambda mode: FakeSession(),
    ).start()
    session.wait_ready(timeout_seconds=1)
    session.resume()
    with pytest.raises(RuntimeCrash):
        session.wait_stable(3)
    assert session.selected_mode is ExecutionMode.SPAWN_SUSPENDED
    assert session.attempts[0].process_result == "process_crashed"
    assert session.fallback_path == []


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


def test_launch_then_attach_is_c_unless_early_lifecycle_is_verified():
    base = dict(
        transport_trusted=True,
        hook_ready_trusted=True,
        event_protocol_trusted=True,
        consent_boundary_trusted=False,
        network_evidence=False,
    )
    assert build_evidence_quality(
        ExecutionMode.LAUNCH_THEN_ATTACH,
        **base,
    ).level == "C"
    assert build_evidence_quality(
        ExecutionMode.LAUNCH_THEN_ATTACH,
        early_lifecycle_verified=True,
        **base,
    ).level == "B"


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


def test_native_sigsegv_is_structured_and_not_mislabeled_antidebug():
    result = classify_process_exit(
        pid=10,
        duration_ms=1024,
        hook_ready=True,
        hook_event_count=2,
        detached_reason="process-terminated",
        logcat_lines=[
            "Fatal signal 11 (SIGSEGV), code 2 (SEGV_ACCERR), fault addr 0x7f00 in tid 10 (main), pid 10 (com.phoenix.read)",
            "Cause: trying to execute non-executable memory",
            "System.out: Mute.App >>> normal mode: 1002",
            "name: main  >>> com.phoenix.read <<<",
            "#00 pc 000000 /system/lib64/libhoudini.so",
            "#01 pc 000001 /data/system/etc/mumu-configs/shared_libs/libhp15_x86_64.so",
            "com.tencent.mmkv.MMKV.initialize",
        ],
        process_still_running=False,
        normal_launch_survived=True,
        normal_launch_observation_seconds=5,
    )
    assert result.status == "process_crashed"
    assert result.crash_type == "native_sigsegv"
    assert result.signal == "SIGSEGV"
    assert result.signal_code == "SEGV_ACCERR"
    assert result.fault_address == "0x7f00"
    assert result.process_name == "com.phoenix.read"
    assert result.thread_name == "main"
    assert result.summary == "trying to execute non-executable memory"
    assert result.suspected_components == [
        "libhoudini.so",
        "libhp15_x86_64.so",
        "MMKV",
    ]
    assert result.reason_code == "native_bridge_compatibility_suspected"
    assert result.correlation_assessment
    assert result.status != "anti_debug_suspected"


def test_application_requested_detach_is_normal_cleanup():
    result = classify_process_exit(
        pid=10,
        duration_ms=5000,
        hook_ready=True,
        hook_event_count=2,
        detached_reason="application-requested",
        crash=None,
        logcat_lines=[],
        process_still_running=True,
    )
    assert result.status == "normal_cleanup"
    assert result.reason_code == "application_requested_detach"


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


def test_root_started_server_is_verified_alive_and_owned(tmp_path):
    """A su-launched server must be probed under su, not by shell ``kill -0``.

    Regression: the aliveness check used plain adb-shell ``kill -0``, which
    fails with EPERM on the root process it just started, so every successful
    start was misreported as ``frida_server_exited`` and ownership was never
    registered.
    """
    commands = []

    def runner(command, cwd=None, timeout=10):
        commands.append(command)
        text = " ".join(str(value) for value in command)
        if "pidof frida-server" in text:
            return {
                "returncode": 1,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
                "cmd": command,
            }
        if "kill -0 4242" in text:
            return {
                "returncode": 0,
                "stdout": "",
                "stderr": "",
                "timed_out": False,
                "cmd": command,
            }
        if "& echo $!" in text:
            return {
                "returncode": 0,
                "stdout": "4242\n",
                "stderr": "",
                "timed_out": False,
                "cmd": command,
            }
        return diagnostic_runner(command, cwd, timeout)

    manager = make_manager(tmp_path, runner)
    result = manager.start(DeviceContext("SERIAL"), confirm=True)
    assert result.status == "success"
    assert result.owned is True
    assert result.pid == 4242
    alive_checks = [
        command
        for command in commands
        if "kill -0 4242" in " ".join(str(value) for value in command)
    ]
    assert alive_checks, "aliveness must be probed after start"
    assert any("su" in command for command in alive_checks), (
        "aliveness probe must run under the same su context as the start"
    )

    stopped = manager.stop(DeviceContext("SERIAL"), confirm=True)
    assert stopped.status == "success"
    assert stopped.pid == 4242


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


@pytest.mark.parametrize(
    ("failing_method", "expected_phase", "expected_code"),
    [
        ("wait_ready", "hook_ready", "process_crashed"),
        ("resume", "resumed", "app_resume_failed"),
    ],
)
def test_policy_session_finalizes_attempt_when_pre_stability_phase_fails(
    failing_method,
    expected_phase,
    expected_code,
):
    class PhaseFailureSession:
        error_code = None
        crash = {"signal": "SIGSEGV"}

        def start(self):
            return True

        def wait_ready(self, timeout_seconds=1):
            if failing_method == "wait_ready":
                self.error_code = "process_crashed"
                raise RuntimeError("process ended before hook_ready")
            return True

        def resume(self):
            if failing_method == "resume":
                self.error_code = "app_resume_failed"
                raise RuntimeError("resume failed")
            return True

        def stop(self, *args, **kwargs):
            return True

    session = PolicyFridaSession(
        policy=DynamicModePolicy.STRICT,
        session_factory=lambda mode: PhaseFailureSession(),
    ).start()

    with pytest.raises(RuntimeError):
        session.wait_ready(timeout_seconds=1)
        session.resume()

    attempt = session.attempts[0]
    assert attempt.status == "failed"
    assert attempt.phase == expected_phase
    assert attempt.reason_code == expected_code
    assert attempt.crash == {"signal": "SIGSEGV"}


def test_balanced_fallback_must_also_pass_stability_window():
    class RuntimeSession:
        error_code = None
        post_resume_survival_ms = 10
        crash = None

        def __init__(self, mode):
            self.mode = mode

        def start(self):
            return True

        def wait_ready(self, timeout_seconds=1):
            return True

        def resume(self):
            return True

        def wait_stable(self, timeout_seconds):
            if self.mode is ExecutionMode.SPAWN_SUSPENDED:
                self.error_code = "process_crashed"
                raise RuntimeError("native crash")
            return False

        def stop(self, *args, **kwargs):
            return True

    session = PolicyFridaSession(
        policy=DynamicModePolicy.BALANCED,
        session_factory=RuntimeSession,
        launch_target=lambda: {},
    ).start()
    session.wait_ready(timeout_seconds=1)
    session.resume()

    with pytest.raises(RuntimeError, match="launch_then_attach_runtime_failed"):
        session.wait_stable(3)

    assert [attempt.status for attempt in session.attempts] == [
        "failed",
        "failed",
    ]
    assert session.attempts[-1].reason_code == "launch_then_attach_failed"
