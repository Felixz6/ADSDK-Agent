import threading
from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from app.core.device import DeviceContext
from app.tools.frida_session import (
    FridaSession,
    FridaSessionError,
    FridaSessionState,
)


class FakeClock:
    def __init__(self) -> None:
        self.wall = datetime(2026, 1, 1, tzinfo=timezone.utc)
        self.monotonic_value = 10.0

    def utc_now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.monotonic_value

    def advance(self, seconds: float) -> None:
        self.monotonic_value += seconds


class FakeScript:
    def __init__(
        self,
        calls: list[tuple],
        *,
        load_error: Exception | None = None,
        unload_gate: threading.Event | None = None,
    ) -> None:
        self.calls = calls
        self.load_error = load_error
        self.unload_gate = unload_gate
        self.message_callback = None

    def on(self, event: str, callback) -> None:
        self.calls.append(("script.on", event))
        assert event == "message"
        self.message_callback = callback

    def load(self) -> None:
        self.calls.append(("script.load",))
        if self.load_error is not None:
            raise self.load_error

    def unload(self) -> None:
        self.calls.append(("script.unload",))
        if self.unload_gate is not None:
            self.unload_gate.wait()

    def emit(self, payload: dict) -> None:
        assert self.message_callback is not None
        self.message_callback({"type": "send", "payload": payload}, None)


class FakeAttachedSession:
    def __init__(self, calls: list[tuple], script: FakeScript) -> None:
        self.calls = calls
        self.script = script
        self.detached_callback = None

    def on(self, event: str, callback) -> None:
        self.calls.append(("session.on", event))
        assert event == "detached"
        self.detached_callback = callback

    def create_script(self, source: str) -> FakeScript:
        self.calls.append(("session.create_script",))
        assert "__ADSDK_CONTEXT__" in source
        return self.script

    def detach(self) -> None:
        self.calls.append(("session.detach",))


class FakeDevice:
    def __init__(
        self,
        serial: str,
        calls: list[tuple],
        script: FakeScript,
        *,
        spawn_error: Exception | None = None,
        attach_error: Exception | None = None,
    ) -> None:
        self.id = serial
        self.calls = calls
        self.script = script
        self.spawn_error = spawn_error
        self.attach_error = attach_error
        self.attached = FakeAttachedSession(calls, script)

    def spawn(self, argv: list[str]) -> int:
        self.calls.append(("device.spawn", tuple(argv)))
        if self.spawn_error is not None:
            raise self.spawn_error
        return 4242

    def enumerate_processes(self):
        self.calls.append(("device.enumerate_processes",))
        return [SimpleNamespace(pid=4242, name="应用标签", identifier=None)]

    def attach(self, pid: int) -> FakeAttachedSession:
        self.calls.append(("device.attach", pid))
        if self.attach_error is not None:
            raise self.attach_error
        return self.attached

    def resume(self, pid: int) -> None:
        self.calls.append(("device.resume", pid))

    def kill(self, pid: int) -> None:
        self.calls.append(("device.kill", pid))


class FakeAdapter:
    def __init__(self, device: FakeDevice, calls: list[tuple]) -> None:
        self.device = device
        self.calls = calls

    def get_device(self, serial: str, timeout_seconds: float):
        self.calls.append(("adapter.get_device", serial, timeout_seconds))
        return self.device


def _make_session(
    tmp_path,
    *,
    serial: str = "SERIAL-EXACT-2",
    load_error: Exception | None = None,
    spawn_error: Exception | None = None,
    attach_error: Exception | None = None,
    unload_gate: threading.Event | None = None,
    execution_mode: str = "spawn_suspended",
    command_runner=None,
):
    calls: list[tuple] = []
    script_path = tmp_path / "sensitive_apis.js"
    script_path.write_text("Java.perform(function () {});", encoding="utf-8")
    script = FakeScript(
        calls,
        load_error=load_error,
        unload_gate=unload_gate,
    )
    device = FakeDevice(
        serial,
        calls,
        script,
        spawn_error=spawn_error,
        attach_error=attach_error,
    )
    adapter = FakeAdapter(device, calls)
    kwargs = {}
    if command_runner is not None:
        kwargs["command_runner"] = command_runner
    session = FridaSession(
        run_id="run-frida-1",
        device=DeviceContext(serial),
        package_name="com.example.target",
        script_path=script_path,
        event_log_path=tmp_path / "events.raw.jsonl",
        adapter=adapter,
        clock=FakeClock(),
        execution_mode=execution_mode,
        **kwargs,
    )
    return session, script, calls


def _hook_ready_payload(session: FridaSession, **overrides) -> dict:
    payload = {
        "protocol_version": "1.0",
        "schema_version": "1.0",
        "type": "control",
        "event": "hook_ready",
        "event_id": "ready-event-1",
        "run_id": session.run_id,
        "session_id": session.session_id,
        "timestamp_utc": "2026-01-01T00:00:00.000Z",
        "monotonic_ms": 1234.5,
        "pid": 4242,
        "installed_hooks": ["android_id", "clipboard"],
        "failed_hooks": [],
        "metadata": {},
    }
    payload.update(overrides)
    return payload


def test_spawn_load_ready_resume_and_stop_are_ordered_and_device_bound(tmp_path):
    session, script, calls = _make_session(tmp_path)

    session.start()

    assert session.state is FridaSessionState.WAITING_READY
    assert not any(call[0] == "device.resume" for call in calls)
    assert calls[0][:2] == ("adapter.get_device", "SERIAL-EXACT-2")
    assert ("device.spawn", ("com.example.target",)) in calls
    assert calls.index(("script.load",)) > calls.index(("device.spawn", ("com.example.target",)))

    script.emit(_hook_ready_payload(session))
    ready = session.wait_ready(timeout_seconds=0.05)
    assert ready.event == "hook_ready"
    assert session.state is FridaSessionState.READY

    session.resume()
    assert session.state is FridaSessionState.COLLECTING
    assert calls.index(("device.resume", 4242)) > calls.index(("script.load",))

    assert session.stop(timeout_seconds=0.1) is True
    assert session.stop(timeout_seconds=0.1) is True
    assert session.state is FridaSessionState.STOPPED
    assert calls.count(("script.unload",)) == 1
    assert calls.count(("session.detach",)) == 1


def test_ready_timeout_never_resumes_and_preserves_error_code(tmp_path):
    session, _script, calls = _make_session(tmp_path)
    session.start()

    with pytest.raises(FridaSessionError) as captured:
        session.wait_ready(timeout_seconds=0.001)

    assert captured.value.code == "hook_ready_timeout"
    assert session.error_code == "hook_ready_timeout"
    assert session.state is FridaSessionState.FAILED
    assert not any(call[0] == "device.resume" for call in calls)
    assert ("device.kill", 4242) in calls


def test_mismatched_ready_session_is_protocol_error_not_ready(tmp_path):
    session, script, _calls = _make_session(tmp_path)
    session.start()
    script.emit(
        _hook_ready_payload(
            session,
            session_id="another-session",
        )
    )

    with pytest.raises(FridaSessionError) as captured:
        session.wait_ready(timeout_seconds=0.001)

    assert captured.value.code == "hook_ready_timeout"
    assert session.protocol_errors
    assert session.protocol_errors[0]["code"] == "session_mismatch"


def test_partial_hook_install_is_ready_but_exposed(tmp_path):
    session, script, _calls = _make_session(tmp_path)
    session.start()
    script.emit(
        _hook_ready_payload(
            session,
            installed_hooks=["android_id"],
            failed_hooks=["clipboard"],
        )
    )

    session.wait_ready(timeout_seconds=0.05)

    assert session.failed_hooks == ["clipboard"]
    assert session.state is FridaSessionState.READY


def test_deferred_java_hook_status_replaces_bootstrap_pending_state(tmp_path):
    session, script, _calls = _make_session(tmp_path)
    session.start()
    script.emit(
        _hook_ready_payload(
            session,
            installed_hooks=[],
            failed_hooks=["java_runtime_pending"],
        )
    )
    session.wait_ready(timeout_seconds=0.05)

    script.emit(
        _hook_ready_payload(
            session,
            event="hook_status",
            event_id="hook-status-event-1",
            installed_hooks=["android_id", "clipboard"],
            failed_hooks=[],
        )
    )

    assert session.installed_hooks == ["android_id", "clipboard"]
    assert session.failed_hooks == []
    assert session.control_events[-1]["event"] == "hook_status"


def test_collection_and_consent_controls_share_device_monotonic_stream(tmp_path):
    session, script, _calls = _make_session(tmp_path)
    session.start()
    script.emit(_hook_ready_payload(session, monotonic_ms=5000.0))
    session.wait_ready(timeout_seconds=0.05)

    collection_start = session.resume()
    collection_control = session.emit_collection_started()
    assert collection_control.event == "collection_started"
    assert collection_control.monotonic_ms == 5000.0
    assert collection_start == session.timeline.collection_started_at

    session.clock.advance(2.0)
    script.emit(
        {
            "protocol_version": "1.0",
            "schema_version": "1.0",
            "type": "event",
            "event_id": "before-consent",
            "run_id": session.run_id,
            "session_id": session.session_id,
            "timestamp_utc": "2026-01-01T00:00:02.000Z",
            "monotonic_ms": 6500.0,
            "pid": 4242,
            "process_name": "com.example.target",
            "thread_id": 1,
            "category": "identifier_access",
            "action": "android_id_read",
            "api": "Settings.Secure.getString",
            "identifier_type": "android_id",
            "identifier_present": True,
            "value_token": "redacted:fixture",
            "raw_retained": False,
            "stack": [],
            "metadata": {},
        }
    )
    consent = session.emit_consent()
    assert consent.monotonic_ms == 7000.0

    events_json = tmp_path / "events.json"
    session.write_events_json(events_json)
    assert '"consent_state": "pre_consent"' in events_json.read_text(
        encoding="utf-8"
    )


@pytest.mark.parametrize(
    ("failure_kind", "expected_code"),
    [
        ("spawn", "frida_spawn_failed"),
        ("load", "hook_load_failed"),
    ],
)
def test_start_failure_maps_to_specific_error(tmp_path, failure_kind, expected_code):
    session, _script, _calls = _make_session(
        tmp_path,
        spawn_error=RuntimeError("opaque spawn diagnostic")
        if failure_kind == "spawn"
        else None,
        load_error=RuntimeError("opaque load diagnostic")
        if failure_kind == "load"
        else None,
    )

    with pytest.raises(FridaSessionError) as captured:
        session.start()

    assert captured.value.code == expected_code
    assert session.error_code == expected_code
    assert session.state is FridaSessionState.FAILED


@pytest.mark.parametrize(
    ("error", "expected_code"),
    [
        (
            RuntimeError("need Gadget to attach on jailed Android"),
            "frida_server_unavailable",
        ),
        (
            RuntimeError("incompatible frida version protocol mismatch"),
            "frida_version_mismatch",
        ),
    ],
)
def test_spawn_runtime_failures_are_precisely_classified(
    tmp_path,
    error,
    expected_code,
):
    session, _script, _calls = _make_session(tmp_path, spawn_error=error)

    with pytest.raises(FridaSessionError) as captured:
        session.start()

    assert captured.value.code == expected_code


def test_attach_failure_is_distinct_from_hook_load_failure(tmp_path):
    session, _script, _calls = _make_session(
        tmp_path,
        attach_error=RuntimeError("attach denied"),
    )

    with pytest.raises(FridaSessionError) as captured:
        session.start()

    assert captured.value.code == "frida_attach_failed"
    assert session.error_code == "frida_attach_failed"
    assert session.state is FridaSessionState.FAILED


def test_attach_existing_resolves_package_pid_when_frida_name_is_app_label(tmp_path):
    session, _script, calls = _make_session(
        tmp_path,
        execution_mode="attach_existing",
        command_runner=lambda command, timeout: {
            "returncode": 0,
            "stdout": "4242\n",
            "stderr": "",
            "cmd": command,
            "timed_out": False,
        },
    )

    session.start()

    assert session.pid == 4242
    assert ("device.enumerate_processes",) in calls
    assert ("device.attach", 4242) in calls


def test_spawn_stability_window_passes_without_detach(tmp_path):
    session, script, _calls = _make_session(tmp_path)
    session.start()
    script.emit(_hook_ready_payload(session))
    session.wait_ready(timeout_seconds=0.05)
    session.resume()

    assert session.wait_stable(0.001) is True
    assert session.post_resume_survival_ms == 1


def test_native_detach_inside_stability_window_is_process_crash(tmp_path):
    session, script, _calls = _make_session(tmp_path)
    session.start()
    script.emit(_hook_ready_payload(session))
    session.wait_ready(timeout_seconds=0.05)
    session.resume()
    session.clock.advance(1.0)
    session._on_detached(
        "process-terminated",
        {
            "summary": "trying to execute non-executable memory",
            "report": "SIGSEGV SEGV_ACCERR libhoudini.so",
        },
    )

    with pytest.raises(FridaSessionError) as captured:
        session.wait_stable(3)
    assert captured.value.code == "process_crashed"
    assert session.detached_reason == "process-terminated"
    assert session.crash is not None
    assert session.post_resume_survival_ms == 1000


def test_attach_only_cleanup_detaches_without_killing_running_target(tmp_path):
    session, script, calls = _make_session(
        tmp_path,
        execution_mode="attach_existing",
        command_runner=lambda command, timeout: {
            "returncode": 0,
            "stdout": "4242\n",
            "stderr": "",
            "cmd": command,
            "timed_out": False,
        },
    )
    session.start()
    script.emit(_hook_ready_payload(session))
    session.wait_ready(timeout_seconds=0.05)
    session.resume()
    assert session.wait_stable(0.001) is True
    assert session.stop(timeout_seconds=0.1) is True
    assert ("session.detach",) in calls
    assert ("device.kill", 4242) not in calls


def test_application_requested_detach_does_not_mark_session_failed(tmp_path):
    session, script, _calls = _make_session(
        tmp_path,
        execution_mode="attach_existing",
        command_runner=lambda command, timeout: {
            "returncode": 0,
            "stdout": "4242\n",
            "stderr": "",
            "cmd": command,
            "timed_out": False,
        },
    )
    session.start()
    script.emit(_hook_ready_payload(session))
    session.wait_ready(timeout_seconds=0.05)
    session.resume()
    session._on_detached("application-requested", None)

    assert session.error_code is None
    assert session.detached_reason == "application-requested"
    assert session.crash is None


def test_stop_timeout_is_bounded_and_attempts_owned_pid_termination(tmp_path):
    gate = threading.Event()
    session, _script, calls = _make_session(tmp_path, unload_gate=gate)
    session.start()

    assert session.stop(timeout_seconds=0.001) is False
    assert session.error_code == "frida_stop_timeout"
    assert session.state is FridaSessionState.FAILED
    assert ("device.kill", 4242) in calls

    gate.set()
