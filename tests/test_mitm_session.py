from __future__ import annotations

import json
import os
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from app.core.device import DeviceContext
from app.tools import mitm_session as mitm_session_module
from app.tools.mitm_session import (
    MitmSession,
    MitmSessionState,
    PortAllocationError,
    PortPool,
)


class FakeClock:
    def __init__(self) -> None:
        self.value = 100.0

    def monotonic(self) -> float:
        return self.value

    def sleep(self, seconds: float) -> None:
        self.value += seconds


class FakeProcess:
    _next_pid = 4100

    def __init__(
        self,
        *,
        returncode: int | None = None,
        wait_times_out: bool = False,
    ) -> None:
        type(self)._next_pid += 1
        self.pid = type(self)._next_pid
        self.returncode = returncode
        self.wait_times_out = wait_times_out
        self.terminate_calls = 0
        self.kill_calls = 0
        self.wait_calls = 0

    def poll(self) -> int | None:
        return self.returncode

    def terminate(self) -> None:
        self.terminate_calls += 1

    def kill(self) -> None:
        self.kill_calls += 1
        self.returncode = -9

    def wait(self, timeout: float | None = None) -> int:
        self.wait_calls += 1
        if self.wait_times_out and self.kill_calls == 0:
            raise subprocess.TimeoutExpired("mitmdump", timeout)
        if self.returncode is None:
            self.returncode = 0
        return self.returncode


class FakeProcessFactory:
    def __init__(self, process: FakeProcess | None = None) -> None:
        self.process = process or FakeProcess()
        self.calls: list[tuple[list[str], dict[str, Any]]] = []

    def __call__(self, command: list[str], **kwargs: Any) -> FakeProcess:
        self.calls.append((command, kwargs))
        return self.process


class FakeTreeTerminator:
    def __init__(self) -> None:
        self.calls: list[tuple[FakeProcess, bool, float]] = []

    def __call__(
        self,
        process: FakeProcess,
        *,
        force: bool,
        timeout: float,
    ) -> None:
        self.calls.append((process, force, timeout))
        if force:
            process.kill()
        else:
            process.terminate()


def _session(
    tmp_path: Path,
    *,
    run_id: str = "run-a",
    port_pool: PortPool | None = None,
    factory: FakeProcessFactory | None = None,
    clock: FakeClock | None = None,
    tree_terminator: FakeTreeTerminator | None = None,
) -> tuple[MitmSession, FakeProcessFactory, FakeClock]:
    selected_factory = factory or FakeProcessFactory()
    selected_clock = clock or FakeClock()
    session = MitmSession(
        run_id=run_id,
        device=DeviceContext("emulator-5554"),
        traffic_dir=tmp_path / run_id / "traffic",
        port_pool=port_pool or PortPool(
            [18080, 18081],
            availability_probe=lambda _host, _port: True,
        ),
        process_factory=selected_factory,
        process_tree_terminator=tree_terminator or FakeTreeTerminator(),
        monotonic=selected_clock.monotonic,
        sleep=selected_clock.sleep,
    )
    return session, selected_factory, selected_clock


def _append(
    path: Path,
    payload: dict[str, Any],
) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(json.dumps(payload, ensure_ascii=False) + "\n")


def _ready_payload(session: MitmSession, **changes: Any) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "protocol_version": "1.0",
        "schema_version": "1.0",
        "type": "control",
        "event": "mitm_ready",
        "run_id": session.run_id,
        "session_id": session.session_id,
        "timestamp_utc": "2026-07-24T00:00:00.000Z",
    }
    payload.update(changes)
    return payload


def test_start_wait_ready_and_stop_are_session_owned(tmp_path: Path) -> None:
    session, factory, _clock = _session(tmp_path)

    assert session.start() is True
    assert session.state is MitmSessionState.STARTING
    assert session.listen_port == 18080
    assert session.jsonl_path == tmp_path / "run-a" / "traffic" / "requests.jsonl"
    assert session.stderr_path.parent == session.traffic_dir

    command, kwargs = factory.calls[0]
    assert "--listen-port" in command
    assert str(session.listen_port) in command
    assert session.run_id in " ".join(command)
    assert session.session_id in " ".join(command)
    assert kwargs["stdout"] == subprocess.DEVNULL
    if os.name == "nt":
        assert kwargs["creationflags"] == subprocess.CREATE_NEW_PROCESS_GROUP

    _append(session.jsonl_path, _ready_payload(session))
    assert session.wait_ready(timeout=1.0) is True
    assert session.state is MitmSessionState.READY
    assert session.ready_at is not None

    assert session.stop(timeout=1.0) is True
    assert session.state is MitmSessionState.STOPPED
    assert factory.process.terminate_calls == 1
    assert session.stop(timeout=1.0) is True
    assert factory.process.terminate_calls == 1


def test_two_sessions_use_separate_ports_files_and_processes(tmp_path: Path) -> None:
    pool = PortPool(
        [18080, 18081],
        availability_probe=lambda _host, _port: True,
    )
    a, factory_a, _ = _session(tmp_path, run_id="run-a", port_pool=pool)
    b, factory_b, _ = _session(tmp_path, run_id="run-b", port_pool=pool)

    assert a.start() is True
    assert b.start() is True
    assert a.session_id != b.session_id
    assert a.listen_port == 18080
    assert b.listen_port == 18081
    assert a.jsonl_path != b.jsonl_path

    assert b.stop() is True
    assert factory_b.process.terminate_calls == 1
    assert factory_a.process.terminate_calls == 0
    assert a.process is factory_a.process
    assert a.process.poll() is None

    assert a.stop() is True
    assert factory_a.process.terminate_calls == 1


def test_same_requested_port_is_resource_busy_without_reuse(tmp_path: Path) -> None:
    pool = PortPool(
        [18080],
        availability_probe=lambda _host, _port: True,
    )
    a, _factory_a, _ = _session(tmp_path, run_id="run-a", port_pool=pool)
    b_factory = FakeProcessFactory()
    b, _factory_b, _ = _session(
        tmp_path,
        run_id="run-b",
        port_pool=pool,
        factory=b_factory,
    )
    a.listen_port = 18080
    b.listen_port = 18080

    assert a.start() is True
    assert b.start() is False
    assert b.error_code == "mitm_resource_busy"
    assert b_factory.calls == []
    assert a.process is not None and a.process.poll() is None
    a.stop()


def test_port_pool_serializes_competing_threads() -> None:
    pool = PortPool(
        [18080],
        availability_probe=lambda _host, _port: True,
    )
    barrier = threading.Barrier(2)

    def acquire(owner_id: str) -> tuple[str, int | str]:
        barrier.wait()
        try:
            port = pool.acquire(
                owner_id=owner_id,
                host="127.0.0.1",
                requested_port=18080,
            )
            return ("acquired", port)
        except PortAllocationError as exc:
            return ("error", exc.code)

    with ThreadPoolExecutor(max_workers=2) as executor:
        results = list(executor.map(acquire, ("session-a", "session-b")))

    assert sorted(kind for kind, _value in results) == [
        "acquired",
        "error",
    ]
    assert ("error", "mitm_resource_busy") in results


def test_unknown_port_occupant_is_not_adopted_or_stopped(tmp_path: Path) -> None:
    factory = FakeProcessFactory()
    pool = PortPool(
        [18080],
        availability_probe=lambda _host, _port: False,
    )
    session, _factory, _ = _session(
        tmp_path,
        port_pool=pool,
        factory=factory,
    )

    assert session.start() is False
    assert session.error_code == "mitm_port_in_use"
    assert factory.calls == []
    assert session.process is None
    assert session.stop() is True


def test_traffic_directory_must_belong_to_current_run(tmp_path: Path) -> None:
    with pytest.raises(
        ValueError,
        match="current run's traffic directory",
    ):
        MitmSession(
            run_id="run-a",
            device=DeviceContext("emulator-5554"),
            traffic_dir=tmp_path / "run-b" / "traffic",
        )


def test_ready_record_must_match_run_and_session(tmp_path: Path) -> None:
    session, factory, _ = _session(tmp_path)
    assert session.start() is True
    _append(
        session.jsonl_path,
        _ready_payload(session, session_id="foreign-session"),
    )

    assert session.wait_ready(timeout=1.0) is False
    assert session.error_code == "mitm_session_mismatch"
    assert session.state is MitmSessionState.FAILED
    assert factory.process.terminate_calls == 1


def test_malformed_ready_protocol_fails_without_becoming_ready(
    tmp_path: Path,
) -> None:
    session, factory, _ = _session(tmp_path)
    assert session.start() is True
    with session.jsonl_path.open("a", encoding="utf-8") as stream:
        stream.write("{malformed\n")

    assert session.wait_ready(timeout=1.0) is False
    assert session.error_code == "mitm_protocol_error"
    assert session.state is MitmSessionState.FAILED
    assert factory.process.terminate_calls == 1


def test_ready_timeout_uses_fake_monotonic_clock(tmp_path: Path) -> None:
    clock = FakeClock()
    session, factory, _ = _session(tmp_path, clock=clock)
    assert session.start() is True

    assert session.wait_ready(timeout=0.25, poll_interval=0.1) is False
    assert clock.value >= 100.25
    assert session.error_code == "mitm_ready_timeout"
    assert factory.process.terminate_calls == 1


def test_process_exit_before_ready_is_explicit(tmp_path: Path) -> None:
    process = FakeProcess(returncode=23)
    factory = FakeProcessFactory(process)
    session, _factory, _ = _session(tmp_path, factory=factory)
    assert session.start() is True
    assert session._stderr_handle is not None
    session._stderr_handle.write("ModuleNotFoundError: No module named 'app'\n")
    session._stderr_handle.flush()

    assert session.wait_ready(timeout=1.0) is False
    assert session.error_code == "mitm_process_exited"
    assert session.exit_code == 23
    assert session.state is MitmSessionState.FAILED
    status = session.to_status()
    assert status["exit_code"] == 23
    assert "ModuleNotFoundError" in status["stderr_tail"]
    assert status["command"][0] == "mitmdump"
    assert status["addon_path"].endswith("mitm_addon.py")
    assert status["ready_timeout"] == 1.0


def test_device_proxy_is_restored_after_failed_collection(tmp_path: Path) -> None:
    commands: list[list[str]] = []

    def command_runner(command: list[str]) -> dict[str, Any]:
        commands.append(command)
        if command[-4:] == ["settings", "get", "global", "http_proxy"]:
            return {"returncode": 0, "stdout": ":null\n", "stderr": ""}
        return {"returncode": 0, "stdout": "", "stderr": ""}

    factory = FakeProcessFactory()
    clock = FakeClock()
    session = MitmSession(
        run_id="proxy-restore",
        device=DeviceContext("emulator-5554"),
        traffic_dir=tmp_path / "proxy-restore" / "traffic",
        port_pool=PortPool(
            [18080],
            availability_probe=lambda _host, _port: True,
        ),
        process_factory=factory,
        process_tree_terminator=FakeTreeTerminator(),
        monotonic=clock.monotonic,
        sleep=clock.sleep,
        device_proxy_host="10.0.2.2",
        command_runner=command_runner,
    )
    assert session.start() is True
    _append(session.jsonl_path, _ready_payload(session))
    assert session.wait_ready(timeout=1.0) is True
    session.mark_collecting()
    session._set_failure("fixture_failure", "fixture")

    assert session.stop(timeout=1.0) is True
    assert session.device_proxy_restored is True
    assert any(command[-1] == "10.0.2.2:18080" for command in commands)
    assert commands[-1][-1] == ":null"


def test_stop_timeout_kills_only_owned_process_and_is_idempotent(
    tmp_path: Path,
) -> None:
    process = FakeProcess(wait_times_out=True)
    factory = FakeProcessFactory(process)
    session, _factory, _ = _session(tmp_path, factory=factory)
    assert session.start() is True

    assert session.stop(timeout=0.01) is False
    assert session.error_code == "mitm_stop_timeout"
    assert process.terminate_calls == 1
    assert process.kill_calls == 1
    assert process.wait_calls == 2
    assert session.state is MitmSessionState.FAILED

    assert session.stop(timeout=0.01) is False
    assert process.terminate_calls == 1
    assert process.kill_calls == 1


def test_stop_uses_injected_process_tree_terminator_then_waits(
    tmp_path: Path,
) -> None:
    process = FakeProcess()
    factory = FakeProcessFactory(process)
    terminator = FakeTreeTerminator()
    session, _factory, _ = _session(
        tmp_path,
        factory=factory,
        tree_terminator=terminator,
    )
    assert session.start() is True

    assert session.stop(timeout=0.75) is True
    assert terminator.calls == [(process, False, 0.75)]
    assert process.wait_calls == 1
    assert process.returncode == 0


@pytest.mark.skipif(os.name != "nt", reason="Windows process-tree contract")
def test_default_windows_tree_terminator_uses_taskkill_without_shell(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    process = FakeProcess()
    calls: list[tuple[list[str], dict[str, Any]]] = []

    def fake_run(
        command: list[str],
        **kwargs: Any,
    ) -> SimpleNamespace:
        calls.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(
        mitm_session_module.subprocess,
        "run",
        fake_run,
    )
    mitm_session_module.terminate_process_tree(
        process,  # type: ignore[arg-type]
        force=True,
        timeout=0.5,
    )

    command, kwargs = calls[0]
    assert command == [
        "taskkill",
        "/PID",
        str(process.pid),
        "/T",
        "/F",
    ]
    assert kwargs["shell"] is False
    assert kwargs["timeout"] == 0.5
