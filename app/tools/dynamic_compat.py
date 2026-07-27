"""Compatibility adapters for historical in-process test fixtures.

Production dynamic collection uses :class:`FridaSession` and
:class:`MitmSession`.  These adapters exist only so older callers that inject
the former runner functions can still exercise the API while historical
``hook.log`` input remains a read-only compatibility format.
"""

from __future__ import annotations

import json
import time
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable
from uuid import uuid4

from app.core.device import DeviceContext


class LegacyFridaAdapter:
    def __init__(
        self,
        *,
        run_id: str,
        device: DeviceContext,
        package_name: str,
        script_path: Path,
        transport_path: Path,
        spawn: Callable[..., dict[str, Any]],
        launch: Callable[..., dict[str, Any]],
    ) -> None:
        self.run_id = run_id
        self.device = device
        self.package_name = package_name
        self.script_path = Path(script_path)
        self.event_log_path = Path(transport_path)
        self.event_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.event_log_path.touch()
        self.session_id = str(uuid4())
        self.state = SimpleNamespace(value="created")
        self.error_code: str | None = None
        self.error_message: str | None = None
        self.pid: int | None = None
        self.installed_hooks = ["legacy_reader"]
        self.failed_hooks: list[str] = []
        self.valid_events: list[dict[str, Any]] = []
        self.control_events: list[dict[str, Any]] = []
        self.protocol_errors: list[dict[str, Any]] = []
        self.protocol_degraded = False
        self.cleanup_errors: list[str] = []
        self.timestamps: dict[str, Any] = {}
        self._spawn = spawn
        self._launch = launch
        self._process: Any = None
        self._log_file: Any = None
        self._ready = False

    def start(self) -> bool:
        result = self._spawn(
            self.package_name,
            str(self.script_path),
            str(self.event_log_path),
            device_context=self.device,
        )
        if not result.get("ok"):
            self.error_code = "frida_spawn_failed"
            self.error_message = "legacy injected collector failed"
            self.state = SimpleNamespace(value="failed")
            return False
        self._process = result.get("process")
        self._log_file = result.get("log_file")
        self.pid = getattr(self._process, "pid", None) or 1
        self.state = SimpleNamespace(value="waiting_ready")
        return True

    def wait_ready(self, timeout: float | None = None) -> bool:
        del timeout
        self._ready = True
        self.state = SimpleNamespace(value="ready")
        return True

    def emit_collection_started(self) -> dict[str, Any]:
        return self._control("collection_started")

    def emit_consent(self, *, source: str = "configured_delay") -> dict[str, Any]:
        return self._control("consent_granted", source=source)

    def emit_control_event(self, event: dict[str, Any]) -> dict[str, Any]:
        if event.get("event") == "consent_granted":
            return self.emit_consent(
                source=str(event.get("source") or "configured_delay")
            )
        return self.emit_collection_started()

    def _control(self, event: str, **extra: Any) -> dict[str, Any]:
        payload = {
            "protocol_version": "1.0",
            "schema_version": "1.0",
            "type": "control",
            "event": event,
            "event_id": str(uuid4()),
            "run_id": self.run_id,
            "session_id": self.session_id,
            "timestamp_utc": datetime.now(timezone.utc)
            .isoformat(timespec="milliseconds")
            .replace("+00:00", "Z"),
            "monotonic_ms": time.monotonic() * 1000.0,
            "pid": self.pid or 1,
            "metadata": {},
            **extra,
        }
        self.control_events.append(payload)
        with self.event_log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(payload, ensure_ascii=False) + "\n")
        return payload

    def resume(self) -> bool:
        if not self._ready:
            raise RuntimeError("legacy adapter resume before ready")
        result = self._launch(
            self.package_name,
            device_context=self.device,
        )
        if result.get("returncode") != 0:
            self.error_code = "app_resume_failed"
            self.error_message = "legacy UI launch failed"
            self.state = SimpleNamespace(value="failed")
            raise RuntimeError(self.error_message)
        self.state = SimpleNamespace(value="collecting")
        return True

    def stop(self, timeout: float | None = None) -> bool:
        timeout = 3.0 if timeout is None else timeout
        try:
            if self._process is not None and self._process.poll() is None:
                self._process.terminate()
                try:
                    self._process.wait(timeout=timeout)
                except Exception:
                    self._process.kill()
                    self._process.wait(timeout=timeout)
            if self._log_file is not None and not self._log_file.closed:
                self._log_file.close()
        except Exception:
            self.error_code = "frida_stop_timeout"
            self.error_message = "legacy collector cleanup failed"
            self.state = SimpleNamespace(value="failed")
            return False
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
        }


class LegacyMitmAdapter:
    def __init__(
        self,
        *,
        run_id: str,
        device: DeviceContext,
        traffic_dir: Path,
        start: Callable[..., dict[str, Any]],
        stop: Callable[..., dict[str, Any]],
    ) -> None:
        self.run_id = run_id
        self.device = device
        self.traffic_dir = Path(traffic_dir)
        self.session_id = str(uuid4())
        self.state = SimpleNamespace(value="created")
        self.error_code: str | None = None
        self.error_message: str | None = None
        self.listen_port = 8080
        self.flow_path = self.traffic_dir / "flows.mitm"
        self.jsonl_path = self.traffic_dir / "requests.jsonl"
        self.stderr_path = self.traffic_dir / "mitm.stderr.log"
        self._start = start
        self._stop = stop
        self._state: dict[str, Any] = {}

    def start(self) -> bool:
        self._state = self._start(str(self.traffic_dir.parent))
        self.jsonl_path.touch(exist_ok=True)
        self.stderr_path.touch(exist_ok=True)
        if not self._state.get("ok"):
            self.error_code = "mitm_start_failed"
            self.error_message = "legacy mitm collector failed"
            self.state = SimpleNamespace(value="failed")
            return False
        self.state = SimpleNamespace(value="starting")
        return True

    def wait_ready(self, timeout: float | None = None) -> bool:
        del timeout
        if self.state.value == "failed":
            return False
        self.state = SimpleNamespace(value="ready")
        return True

    def mark_collecting(self) -> None:
        self.state = SimpleNamespace(value="collecting")

    def stop(self, timeout: float | None = None) -> bool:
        del timeout
        result = self._stop()
        if not result.get("ok"):
            self.error_code = "mitm_stop_timeout"
            self.error_message = "legacy mitm cleanup failed"
            self.state = SimpleNamespace(value="failed")
            return False
        if self.state.value != "failed":
            self.state = SimpleNamespace(value="stopped")
        return True

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

