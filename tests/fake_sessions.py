"""Reusable fake Frida and MITM sessions for integration tests."""

from __future__ import annotations

import uuid
from pathlib import Path
from types import SimpleNamespace
from typing import Any

from app.core.device import DeviceContext
from app.frida import ExecutionMode
from app.traffic.traffic_events import (
    TrafficCollectionOutcome,
    TrafficCollectionResult,
)


class FakeTestFridaSession:
    is_real: bool = False

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.run_id = kwargs.get("run_id", "test-run")
        self.device = kwargs.get("device", DeviceContext(serial="emulator-5554"))
        self.package_name = kwargs.get("package_name", "com.example.demo")
        self.event_log_path = Path(kwargs.get("event_log_path", Path.cwd() / "events.raw.jsonl"))
        self.event_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.event_log_path.touch()
        self.protocol_error_path = Path(
            kwargs.get(
                "protocol_error_path",
                self.event_log_path.with_name("frida.protocol-errors.jsonl"),
            )
        )
        self.protocol_error_path.touch()
        self.session_id = str(kwargs.get("session_id") or uuid.uuid4())
        self.state = SimpleNamespace(value="created")
        self.error_code: str | None = None
        self.error_message: str | None = None
        self.pid = 1001
        self.installed_hooks = ["android_id"]
        self.failed_hooks: list[str] = []
        self.valid_events: list[dict[str, Any]] = []
        self.control_events: list[dict[str, Any]] = []
        self.valid_messages: list[dict[str, Any]] = []
        self.protocol_errors: list[dict[str, Any]] = []
        self.cleanup_errors: list[str] = []
        self.selected_mode = ExecutionMode.ATTACH_EXISTING
        self.attempts: list[Any] = []
        self.fallback_path: list[str] = []
        self.launch_timing: dict[str, Any] = {}
        self.environment_capabilities: dict[str, Any] = {}

    def start(self) -> bool:
        self.state = SimpleNamespace(value="waiting_ready")
        return True

    def wait_ready(self, timeout: float | None = None) -> bool:
        self.state = SimpleNamespace(value="ready")
        return True

    def resume(self) -> bool:
        self.state = SimpleNamespace(value="collecting")
        return True

    def stop(self, timeout: float | None = None) -> bool:
        self.state = SimpleNamespace(value="stopped")
        return True

    def emit_consent(self, *args: Any, **kwargs: Any) -> None:
        pass

    def emit_control_event(self, *args: Any, **kwargs: Any) -> None:
        pass

    def to_status(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "session_id": self.session_id,
            "state": self.state.value,
            "error_code": self.error_code,
            "error": self.error_message,
        }


class FakeTestMitmSession:
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.run_id = kwargs.get("run_id", "test-run")
        self.traffic_dir = Path(kwargs.get("traffic_dir", Path.cwd() / "traffic"))
        self.traffic_dir.mkdir(parents=True, exist_ok=True)
        self.jsonl_path = self.traffic_dir / "requests.jsonl"
        self.jsonl_path.touch()
        self.stderr_path = self.traffic_dir / "mitm.stderr.log"
        self.stderr_path.touch()
        self.flow_file = self.traffic_dir / "flows.mitm"
        self.flow_file.touch()
        self.session_id = str(kwargs.get("session_id") or uuid.uuid4())
        self.state = SimpleNamespace(value="created")
        self.error_code: str | None = None
        self.error_message: str | None = None
        self.listen_port = 8080

    def start(self) -> bool:
        self.state = SimpleNamespace(value="starting")
        return True

    def wait_ready(self, timeout: float | None = None) -> bool:
        self.state = SimpleNamespace(value="ready")
        return True

    def mark_collecting(self) -> None:
        self.state = SimpleNamespace(value="collecting")

    def stop(self, timeout: float | None = None) -> bool:
        self.state = SimpleNamespace(value="stopped")
        return True

    def validate_traffic(self) -> Any:
        return TrafficCollectionResult(
            outcome=TrafficCollectionOutcome.COLLECTOR_SUCCESS_ZERO_REQUESTS,
            coverage="no_observations",
            process_ready=True,
            addon_ready=True,
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
            "error_code": self.error_code,
            "error": self.error_message,
        }
