"""Fake-only integration regressions for the stage 2C dynamic API.

These tests deliberately exercise the HTTP entry point rather than just the
session coordinator.  Every external process boundary is replaced with a
small in-memory fake, so the suite neither needs nor probes ADB, Frida, or
mitmproxy.
"""

from __future__ import annotations

import json
import uuid
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from fastapi.testclient import TestClient

from app import main as main_module
from app.core.device import DeviceContext
from app.tools.dynamic_collection import (
    run_dynamic_collection as real_run_dynamic_collection,
)
from app.tools.traffic_events import (
    TrafficCollectionOutcome,
    TrafficCollectionResult,
)


# Keep the fixture value out of assertion introspection.  A leak failure only
# reports artifact names, never the sensitive value itself.
_RAW_ANDROID_ID = "stage2c-android-id-9f4b19a73d2e4c88"
_SAFE_VALUE_TOKEN = "redacted:test-token"


class _EventEnvelope(dict[str, Any]):
    """Tiny Pydantic-like return value used by the fake control methods."""

    def model_dump(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        del args, kwargs
        return dict(self)

    def model_dump_json(self, *args: Any, **kwargs: Any) -> str:
        del args, kwargs
        return json.dumps(self, ensure_ascii=False)

    def __getattr__(self, name: str) -> Any:
        try:
            return self[name]
        except KeyError as exc:
            raise AttributeError(name) from exc


@dataclass
class _Scenario:
    calls: list[str] = field(default_factory=list)
    tool_apk_paths: list[Path] = field(default_factory=list)
    frida_instances: list["_FakeFridaSession"] = field(default_factory=list)
    mitm_instances: list["_FakeMitmSession"] = field(default_factory=list)
    collection_configs: list[Any] = field(default_factory=list)
    mitm_failure: str | None = None
    frida_failure: str | None = None


def _argument(
    args: tuple[Any, ...],
    kwargs: dict[str, Any],
    names: tuple[str, ...],
    name: str,
    default: Any = None,
) -> Any:
    if name in kwargs:
        return kwargs[name]
    try:
        return args[names.index(name)]
    except (ValueError, IndexError):
        return default


class _FakeFridaSession:
    _POSITIONAL = (
        "run_id",
        "device",
        "package_name",
        "script_path",
        "event_log_path",
    )

    def __init__(
        self,
        scenario: _Scenario,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self._scenario = scenario
        self.run_id = str(
            _argument(args, kwargs, self._POSITIONAL, "run_id", "")
        )
        self.device = _argument(
            args,
            kwargs,
            self._POSITIONAL,
            "device",
            DeviceContext(serial="fixture-device"),
        )
        self.package_name = str(
            _argument(
                args,
                kwargs,
                self._POSITIONAL,
                "package_name",
                "com.example.fixture",
            )
        )
        self.script_path = Path(
            _argument(
                args,
                kwargs,
                self._POSITIONAL,
                "script_path",
                "sensitive_apis.js",
            )
        )
        self.event_log_path = Path(
            _argument(
                args,
                kwargs,
                self._POSITIONAL,
                "event_log_path",
                Path.cwd() / "events.raw.jsonl",
            )
        )
        self.protocol_error_path = Path(
            kwargs.get(
                "protocol_error_path",
                self.event_log_path.with_name(
                    "frida.protocol-errors.jsonl"
                ),
            )
        )
        self.session_id = str(
            kwargs.get("session_id") or uuid.uuid4()
        )
        self.state = SimpleNamespace(value="created")
        self.error_code: str | None = None
        self.error_message: str | None = None
        self.pid: int | None = None
        self.installed_hooks = ["android_id"]
        self.failed_hooks: list[str] = []
        self.valid_events: list[dict[str, Any]] = []
        self.control_events: list[dict[str, Any]] = []
        self.valid_messages: list[dict[str, Any]] = []
        self.protocol_errors: list[dict[str, Any]] = []
        self.protocol_degraded = False
        self.cleanup_errors: list[str] = []
        self.timestamps: dict[str, Any] = {}
        self.started = False
        self.ready = False
        self.resumed = False
        self.stopped = False

        self.event_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.event_log_path.touch()
        self.protocol_error_path.touch()
        scenario.frida_instances.append(self)

    def _append(self, payload: dict[str, Any]) -> _EventEnvelope:
        envelope = _EventEnvelope(payload)
        with self.event_log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
        self.valid_messages.append(dict(payload))
        if payload.get("type") == "event":
            self.valid_events.append(dict(payload))
        else:
            self.control_events.append(dict(payload))
        return envelope

    def _control(self, event: str, **extra: Any) -> _EventEnvelope:
        return self._append(
            {
                "protocol_version": "1.0",
                "schema_version": "1.0",
                "type": "control",
                "event": event,
                "event_id": str(uuid.uuid4()),
                "run_id": self.run_id,
                "session_id": self.session_id,
                "timestamp_utc": "2026-07-24T00:00:00.000Z",
                "monotonic_ms": 1000.0,
                "pid": self.pid or 1234,
                "metadata": {},
                **extra,
            }
        )

    def start(self) -> bool:
        self._scenario.calls.append("frida.start")
        self.started = True
        self.pid = 1234
        if self._scenario.frida_failure == "start":
            self.error_code = "frida_spawn_failed"
            self.error_message = "fixture Frida spawn failed"
            self.state = SimpleNamespace(value="failed")
            return False
        self.state = SimpleNamespace(value="waiting_ready")
        return True

    def wait_ready(
        self,
        timeout: float | None = None,
        timeout_seconds: float | None = None,
    ) -> _EventEnvelope | bool:
        del timeout, timeout_seconds
        self._scenario.calls.append("frida.wait_ready")
        if self._scenario.frida_failure == "ready":
            self.error_code = "frida_ready_timeout"
            self.error_message = "fixture Hook-ready timeout"
            self.state = SimpleNamespace(value="failed")
            return False
        self.ready = True
        self.state = SimpleNamespace(value="ready")
        ready = self._control(
            "hook_ready",
            installed_hooks=["android_id"],
            failed_hooks=[],
        )
        self._append(
            {
                "protocol_version": "1.0",
                "schema_version": "1.0",
                "type": "event",
                "event_id": str(uuid.uuid4()),
                "run_id": self.run_id,
                "session_id": self.session_id,
                "timestamp_utc": "2026-07-24T00:00:00.100Z",
                "monotonic_ms": 1100.0,
                "pid": 1234,
                "process_name": self.package_name,
                "thread_id": 1,
                "thread_name": "main",
                "category": "identifier_access",
                "action": "android_id_read",
                "api": "Settings.Secure.getString",
                "identifier_type": "android_id",
                "identifier_present": True,
                "value_token": _SAFE_VALUE_TOKEN,
                "raw_retained": False,
                "stack": [],
                "metadata": {},
            }
        )
        return ready

    def emit_collection_started(
        self,
        *args: Any,
        **kwargs: Any,
    ) -> _EventEnvelope:
        del args, kwargs
        for item in reversed(self.control_events):
            if item.get("event") == "collection_started":
                return _EventEnvelope(item)
        if not self.ready:
            raise AssertionError(
                "collection_started was emitted before Hook-ready"
            )
        self._scenario.calls.append("frida.emit_collection_started")
        return self._control("collection_started")

    def emit_consent(
        self,
        *args: Any,
        source: str = "configured_delay",
        **kwargs: Any,
    ) -> _EventEnvelope:
        del args, kwargs
        if not self.resumed:
            raise AssertionError("consent was emitted before App resume")
        self._scenario.calls.append("frida.emit_consent")
        return self._control("consent_granted", source=source)

    def emit_control_event(
        self,
        event: dict[str, Any],
    ) -> _EventEnvelope:
        name = str(event.get("event") or "unknown")
        if name == "collection_started":
            return self.emit_collection_started()
        if name == "consent_granted":
            return self.emit_consent(
                source=str(event.get("source") or "configured_delay")
            )
        return self._append(dict(event))

    record_control_event = emit_control_event
    append_control_event = emit_control_event

    def resume(self) -> bool:
        if not self.ready:
            raise AssertionError("resume was attempted before Hook-ready")
        self._scenario.calls.append("frida.resume")
        self.resumed = True
        self.state = SimpleNamespace(value="collecting")
        self.emit_collection_started()
        return True

    def stop(
        self,
        timeout: float | None = None,
        timeout_seconds: float | None = None,
    ) -> bool:
        del timeout, timeout_seconds
        if not self.stopped:
            self._scenario.calls.append("frida.stop")
            self.stopped = True
            if self.state.value != "failed":
                self.state = SimpleNamespace(value="stopped")
        return True

    def to_status(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "session_id": self.session_id,
            "state": self.state.value,
            "error_code": self.error_code,
            "error": self.error_message,
            "event_log_path": str(self.event_log_path),
        }

    def write_events_json(self, output_path: str | Path) -> Path:
        destination = Path(output_path)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(
            json.dumps(self.valid_messages, ensure_ascii=False),
            encoding="utf-8",
        )
        return destination


class _FakeMitmSession:
    _POSITIONAL = ("run_id", "device", "traffic_dir")

    def __init__(
        self,
        scenario: _Scenario,
        *args: Any,
        **kwargs: Any,
    ) -> None:
        self._scenario = scenario
        self.run_id = str(
            _argument(args, kwargs, self._POSITIONAL, "run_id", "")
        )
        self.device = _argument(
            args,
            kwargs,
            self._POSITIONAL,
            "device",
            DeviceContext(serial="fixture-device"),
        )
        self.traffic_dir = Path(
            _argument(
                args,
                kwargs,
                self._POSITIONAL,
                "traffic_dir",
                Path.cwd() / "traffic",
            )
        )
        self.session_id = str(
            kwargs.get("session_id") or uuid.uuid4()
        )
        self.listen_host = str(kwargs.get("listen_host") or "127.0.0.1")
        self.listen_port = int(kwargs.get("listen_port") or 8080)
        self.flow_path = self.traffic_dir / "flows.mitm"
        self.jsonl_path = self.traffic_dir / "requests.jsonl"
        self.stderr_path = self.traffic_dir / "mitm.stderr.log"
        self.state = SimpleNamespace(value="created")
        self.error_code: str | None = None
        self.error_message: str | None = None
        self.started = False
        self.ready = False
        self.stopped = False

        self.traffic_dir.mkdir(parents=True, exist_ok=True)
        self.flow_path.touch()
        self.jsonl_path.touch()
        self.stderr_path.touch()
        scenario.mitm_instances.append(self)

    def start(self) -> bool:
        self._scenario.calls.append("mitm.start")
        self.started = True
        if self._scenario.mitm_failure == "start":
            self.error_code = "mitm_start_failed"
            self.error_message = "fixture mitm start failed"
            self.state = SimpleNamespace(value="failed")
            return False
        self.state = SimpleNamespace(value="starting")
        return True

    def wait_ready(
        self,
        timeout: float | None = None,
        timeout_seconds: float | None = None,
        poll_interval: float | None = None,
    ) -> bool:
        del timeout, timeout_seconds, poll_interval
        self._scenario.calls.append("mitm.wait_ready")
        if self._scenario.mitm_failure == "ready":
            self.error_code = "mitm_ready_timeout"
            self.error_message = "fixture mitm ready timeout"
            self.state = SimpleNamespace(value="failed")
            return False
        self.ready = True
        self.state = SimpleNamespace(value="ready")
        with self.jsonl_path.open("a", encoding="utf-8") as stream:
            stream.write(
                json.dumps(
                    {
                        "protocol_version": "1.0",
                        "schema_version": "1.0",
                        "type": "control",
                        "event": "mitm_ready",
                        "run_id": self.run_id,
                        "session_id": self.session_id,
                        "timestamp_utc": "2026-07-24T00:00:00.000Z",
                    }
                )
                + "\n"
            )
        return True

    def mark_collecting(self) -> None:
        self._scenario.calls.append("mitm.mark_collecting")
        self.state = SimpleNamespace(value="collecting")

    def stop(
        self,
        timeout: float | None = None,
        timeout_seconds: float | None = None,
    ) -> bool:
        del timeout, timeout_seconds
        if not self.stopped:
            self._scenario.calls.append("mitm.stop")
            self.stopped = True
            if self.state.value != "failed":
                self.state = SimpleNamespace(value="stopped")
        return True

    def validate_traffic(self) -> TrafficCollectionResult:
        return TrafficCollectionResult(
            outcome=TrafficCollectionOutcome.SUCCESS_ZERO_REQUESTS,
            coverage="no_observations",
            process_ready=self.ready,
            addon_ready=self.ready,
            records=[],
            issues=[],
        )

    def to_status(self) -> dict[str, Any]:
        return {
            "ok": self.error_code is None,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "state": self.state.value,
            "port": self.listen_port,
            "traffic_dir": str(self.traffic_dir),
            "flow_file": str(self.flow_path),
            "jsonl_path": str(self.jsonl_path),
            "stderr_path": str(self.stderr_path),
            "error_code": self.error_code,
            "error": self.error_message,
        }


class _LegacyProcess:
    """Only prevents the pre-2C implementation from touching real processes."""

    def __init__(self, scenario: _Scenario) -> None:
        self._scenario = scenario
        self._alive = True

    def poll(self) -> int | None:
        return None if self._alive else 0

    def terminate(self) -> None:
        self._alive = False
        self._scenario.calls.append("legacy.frida.stop")

    def wait(self, timeout: float | None = None) -> int:
        del timeout
        self._alive = False
        return 0

    def kill(self) -> None:
        self._alive = False


@dataclass
class _ApiHarness:
    client: TestClient
    scenario: _Scenario
    source_apk: Path
    output_root: Path
    monkeypatch: pytest.MonkeyPatch

    def post(self, **overrides: Any):
        payload: dict[str, Any] = {
            "apk_path": str(self.source_apk),
            "device_id": "fixture-device",
            "consent_after_seconds": 0,
            "pre_consent_seconds": 0,
            "post_consent_seconds": 0,
            "enable_traffic": True,
            "enable_ui_stimulation": False,
            "collection_timeout_seconds": 30,
        }
        payload.update(overrides)
        return self.client.post("/dynamic/analyze", json=payload)

    def fail_report_write(self) -> None:
        def fail_markdown(report: dict[str, Any], path: str) -> None:
            del report, path
            self.scenario.calls.append("report.write")
            raise OSError("fixture report write failure")

        self.monkeypatch.setattr(
            main_module,
            "write_markdown_report",
            fail_markdown,
        )


def _write_fake_apk(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(path, "w") as archive:
        archive.writestr(
            "AndroidManifest.xml",
            "<manifest package='com.example.stage2c'/>",
        )


@pytest.fixture
def dynamic_api(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> _ApiHarness:
    scenario = _Scenario()
    source_apk = tmp_path / "中文 APK 输入" / "fixture app.apk"
    output_root = tmp_path / "output"
    _write_fake_apk(source_apk)

    monkeypatch.setattr(main_module, "OUTPUT_DIR", str(output_root))
    monkeypatch.setattr(
        main_module,
        "APK_ALLOWED_ROOTS",
        (tmp_path.resolve(),),
    )
    monkeypatch.setattr(
        main_module,
        "select_device_context",
        lambda device_id=None: DeviceContext(
            serial=device_id or "fixture-device"
        ),
    )

    def fake_unpack(apk: str, out_dir: str) -> dict[str, Any]:
        apk_path = Path(apk).resolve()
        scenario.calls.append("tool.apktool")
        scenario.tool_apk_paths.append(apk_path)
        destination = Path(out_dir)
        destination.mkdir(parents=True, exist_ok=True)
        (destination / "AndroidManifest.xml").write_text(
            "<manifest package='com.example.stage2c'/>",
            encoding="utf-8",
        )
        return {
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "cmd": ["apktool", str(apk_path)],
        }

    def fake_install(
        apk: str,
        device_context: DeviceContext | None = None,
    ) -> dict[str, Any]:
        assert device_context is not None
        apk_path = Path(apk).resolve()
        scenario.calls.append("tool.adb_install")
        scenario.tool_apk_paths.append(apk_path)
        return {
            "returncode": 0,
            "stdout": "",
            "stderr": "",
            "cmd": device_context.adb_command("install", str(apk_path)),
        }

    def fake_ui_stimulation(
        package_name: str,
        device_context: DeviceContext | None = None,
    ) -> dict[str, Any]:
        del package_name, device_context
        scenario.calls.append("ui.stimulate")
        return {"returncode": 0, "stdout": "", "stderr": "", "cmd": []}

    monkeypatch.setattr(main_module, "unpack_apk", fake_unpack)
    monkeypatch.setattr(main_module, "install_apk", fake_install)
    monkeypatch.setattr(main_module, "launch_app", fake_ui_stimulation)
    monkeypatch.setattr(
        main_module,
        "parse_manifest_info",
        lambda _: {
            "package_name": "com.example.stage2c",
            "version_name": "1.0",
            "version_code": "1",
            "application_label": "Stage2C",
        },
    )
    monkeypatch.setattr(main_module, "scan_for_sdks", lambda _: [])

    class BoundFakeFridaSession(_FakeFridaSession):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(scenario, *args, **kwargs)

    class BoundFakeMitmSession(_FakeMitmSession):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(scenario, *args, **kwargs)

    monkeypatch.setattr(
        main_module,
        "FridaSession",
        BoundFakeFridaSession,
        raising=False,
    )
    monkeypatch.setattr(
        main_module,
        "MitmSession",
        BoundFakeMitmSession,
        raising=False,
    )

    def recording_collection(*args: Any, **kwargs: Any):
        if kwargs:
            scenario.collection_configs.append(kwargs["config"])
        else:
            raise AssertionError(
                "run_dynamic_collection must use its keyword-only contract"
            )
        return real_run_dynamic_collection(*args, **kwargs)

    monkeypatch.setattr(
        main_module,
        "run_dynamic_collection",
        recording_collection,
        raising=False,
    )

    # Legacy entry points are faked too.  This keeps the initial red-light run
    # deterministic while making any continued use of those entry points
    # visible in assertions.
    def legacy_start_mitm(run_dir: str) -> dict[str, Any]:
        scenario.calls.append("legacy.mitm.start")
        traffic_dir = Path(run_dir) / "traffic"
        traffic_dir.mkdir(parents=True, exist_ok=True)
        stream_log = traffic_dir / "mitm_stream.log"
        stream_log.touch()
        ok = scenario.mitm_failure is None
        return {
            "ok": ok,
            "error": None if ok else "fixture mitm failure",
            "traffic_dir": str(traffic_dir),
            "stream_log": str(stream_log),
            "flow_file": str(traffic_dir / "flows.mitm"),
        }

    def legacy_stop_mitm() -> dict[str, Any]:
        scenario.calls.append("legacy.mitm.stop")
        return {"ok": True, "error": None}

    def legacy_spawn(
        package_name: str,
        script_path: str,
        log_path: str,
        device_context: DeviceContext | None = None,
    ) -> dict[str, Any]:
        del package_name, script_path, device_context
        scenario.calls.append("legacy.frida.spawn")
        if scenario.frida_failure is not None:
            return {
                "ok": False,
                "error": "fixture Frida failure",
                "process": None,
                "log_file": None,
            }
        with Path(log_path).open("a", encoding="utf-8") as stream:
            stream.write(
                "[HOOK] Settings.Secure.getString "
                f"name=android_id ret={_RAW_ANDROID_ID}\n"
            )
        return {
            "ok": True,
            "error": None,
            "process": _LegacyProcess(scenario),
            "log_file": None,
        }

    monkeypatch.setattr(main_module, "start_mitm", legacy_start_mitm)
    monkeypatch.setattr(main_module, "stop_mitm", legacy_stop_mitm)
    monkeypatch.setattr(main_module, "spawn_and_inject", legacy_spawn)

    def legacy_traffic_summary(
        traffic_text_path: str,
        output_path: str,
    ) -> dict[str, Any]:
        del traffic_text_path
        summary = {
            "schema_version": "1.0",
            "status": "success",
            "evaluation_status": "not_evaluated",
            "coverage": "no_observations",
            "collector_outcome": "collector_success_zero_requests",
            "warnings": [],
            "total_requests": 0,
            "top_hosts": [],
            "sample_requests": [],
        }
        Path(output_path).write_text(
            json.dumps(summary),
            encoding="utf-8",
        )
        return summary

    monkeypatch.setattr(
        main_module,
        "parse_traffic_to_summary_json",
        legacy_traffic_summary,
    )
    monkeypatch.setattr(
        main_module,
        "evaluate_timeline_rules",
        lambda **kwargs: {
            "summary": {},
            "rules": [],
            "window": {
                "consent_time": kwargs.get("consent_time"),
                "pre_consent_seconds": kwargs.get(
                    "pre_consent_seconds"
                ),
                "post_consent_seconds": kwargs.get(
                    "post_consent_seconds"
                ),
            },
        },
    )

    return _ApiHarness(
        client=TestClient(main_module.app),
        scenario=scenario,
        source_apk=source_apk,
        output_root=output_root,
        monkeypatch=monkeypatch,
    )


def _step(body: dict[str, Any], name: str) -> dict[str, Any]:
    matches = [
        item
        for item in body.get("steps", [])
        if item.get("name") == name
    ]
    assert len(matches) == 1, f"missing or duplicate step: {name}"
    return matches[0]


def _assert_is_within(path: Path, root: Path) -> None:
    path.resolve().relative_to(root.resolve())


def test_external_tools_only_receive_run_snapshot(
    dynamic_api: _ApiHarness,
) -> None:
    response = dynamic_api.post()
    assert response.status_code == 200
    body = response.json()
    run_dir = Path(body["output_dir"]).resolve()
    expected_snapshot = run_dir / "input" / "app.apk"

    assert len(dynamic_api.scenario.tool_apk_paths) >= 2
    assert all(
        path == expected_snapshot
        for path in dynamic_api.scenario.tool_apk_paths
    )
    assert expected_snapshot != dynamic_api.source_apk.resolve()
    assert expected_snapshot.read_bytes() == dynamic_api.source_apk.read_bytes()


def test_mitm_failure_does_not_start_frida(
    dynamic_api: _ApiHarness,
) -> None:
    dynamic_api.scenario.mitm_failure = "start"
    response = dynamic_api.post()
    assert response.status_code != 422
    body = response.json()

    assert dynamic_api.scenario.mitm_instances
    assert "mitm.start" in dynamic_api.scenario.calls
    assert "frida.start" not in dynamic_api.scenario.calls
    assert "legacy.frida.spawn" not in dynamic_api.scenario.calls
    assert _step(body, "mitm_start")["status"] == "failed"


def test_frida_failure_cleans_the_started_mitm_session(
    dynamic_api: _ApiHarness,
) -> None:
    dynamic_api.scenario.frida_failure = "start"
    response = dynamic_api.post()
    assert response.status_code != 422
    body = response.json()

    assert dynamic_api.scenario.frida_instances
    assert dynamic_api.scenario.mitm_instances
    assert dynamic_api.scenario.mitm_instances[0].stopped is True
    assert dynamic_api.scenario.frida_instances[0].stopped is True
    assert dynamic_api.scenario.calls.index("frida.start") < (
        dynamic_api.scenario.calls.index("frida.stop")
    )
    assert dynamic_api.scenario.calls.index("frida.stop") < (
        dynamic_api.scenario.calls.index("mitm.stop")
    )
    assert _step(body, "frida_spawn")["status"] == "failed"
    assert _step(body, "mitm_stop")["status"] in {"success", "partial"}


def test_app_is_never_resumed_before_valid_hook_ready(
    dynamic_api: _ApiHarness,
) -> None:
    response = dynamic_api.post()
    assert response.status_code == 200

    calls = dynamic_api.scenario.calls
    assert dynamic_api.scenario.frida_instances
    assert calls.index("frida.start") < calls.index("frida.wait_ready")
    assert calls.index("frida.wait_ready") < calls.index("frida.resume")
    assert "legacy.frida.spawn" not in calls
    assert dynamic_api.scenario.frida_instances[0].ready is True
    assert dynamic_api.scenario.frida_instances[0].resumed is True


def test_report_failure_occurs_only_after_both_sessions_stop(
    dynamic_api: _ApiHarness,
) -> None:
    dynamic_api.fail_report_write()
    response = dynamic_api.post()
    assert response.status_code == 500

    calls = dynamic_api.scenario.calls
    assert dynamic_api.scenario.frida_instances[0].stopped is True
    assert dynamic_api.scenario.mitm_instances[0].stopped is True
    assert calls.index("frida.stop") < calls.index("report.write")
    assert calls.index("mitm.stop") < calls.index("report.write")
    assert response.json()["status"] == "failed"


def test_every_formal_artifact_and_session_belongs_to_current_run(
    dynamic_api: _ApiHarness,
) -> None:
    response = dynamic_api.post()
    assert response.status_code == 200
    body = response.json()
    run_dir = Path(body["output_dir"]).resolve()

    assert run_dir.name == body["run_id"]
    assert run_dir.parent == (
        dynamic_api.output_root.resolve() / "runs"
    )
    assert len(dynamic_api.scenario.frida_instances) == 1
    assert len(dynamic_api.scenario.mitm_instances) == 1
    assert dynamic_api.scenario.frida_instances[0].run_id == body["run_id"]
    assert dynamic_api.scenario.mitm_instances[0].run_id == body["run_id"]
    _assert_is_within(
        dynamic_api.scenario.frida_instances[0].event_log_path,
        run_dir,
    )
    _assert_is_within(
        dynamic_api.scenario.mitm_instances[0].traffic_dir,
        run_dir,
    )

    artifact_paths = {
        item["name"]: Path(item["path"]).resolve()
        for item in body["artifacts"]
    }
    for path in artifact_paths.values():
        _assert_is_within(path, run_dir)

    expected_relative_paths = {
        "input/app.apk",
        "hook.log",
        "events.raw.jsonl",
        "events.json",
        "traffic/requests.jsonl",
        "traffic/mitm.stderr.log",
        "traffic_summary.json",
        "sessions.json",
        "report.json",
        "report.md",
    }
    missing = [
        relative
        for relative in sorted(expected_relative_paths)
        if not (run_dir / relative).is_file()
    ]
    assert missing == []


def test_raw_identifier_is_absent_from_response_and_formal_artifacts(
    dynamic_api: _ApiHarness,
) -> None:
    response = dynamic_api.post()
    assert response.status_code == 200
    body = response.json()
    run_dir = Path(body["output_dir"]).resolve()
    raw_bytes = _RAW_ANDROID_ID.encode("utf-8")

    leaked_locations: list[str] = []
    if raw_bytes in response.content:
        leaked_locations.append("api_response")
    for path in run_dir.rglob("*"):
        if path.is_file() and raw_bytes in path.read_bytes():
            leaked_locations.append(path.relative_to(run_dir).as_posix())
    if leaked_locations:
        pytest.fail(
            "sensitive fixture leaked into formal outputs: "
            + ", ".join(sorted(leaked_locations)),
            pytrace=False,
        )


def test_new_request_controls_are_forwarded_to_collection_lifecycle(
    dynamic_api: _ApiHarness,
) -> None:
    response = dynamic_api.post(
        enable_traffic=False,
        enable_ui_stimulation=True,
        collection_timeout_seconds=17,
    )
    assert response.status_code == 200
    assert len(dynamic_api.scenario.collection_configs) == 1
    config = dynamic_api.scenario.collection_configs[0]

    assert config.enable_traffic is False
    assert config.enable_ui_stimulation is True
    assert config.collection_timeout_seconds == 17
    assert all(
        not call.startswith("mitm.")
        for call in dynamic_api.scenario.calls
    )
    assert "legacy.mitm.start" not in dynamic_api.scenario.calls
    assert dynamic_api.scenario.calls.index("frida.resume") < (
        dynamic_api.scenario.calls.index("ui.stimulate")
    )


@pytest.mark.parametrize("timeout", [0, 86_401])
def test_collection_timeout_request_range_is_validated(
    dynamic_api: _ApiHarness,
    timeout: int,
) -> None:
    response = dynamic_api.post(collection_timeout_seconds=timeout)
    assert response.status_code == 422
    assert dynamic_api.scenario.calls == []
