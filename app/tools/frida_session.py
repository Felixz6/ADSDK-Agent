"""Run-bound Frida Python-API session with an explicit ready handshake."""

from __future__ import annotations

import importlib
import json
import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Protocol

from app.core.device import DeviceContext
from app.core.redaction import Redactor

from .utils import run_cmd
from .frida_events import (
    FridaControlEvent,
    FridaEventValidationError,
    FridaStructuredEvent,
    StructuredEventWriter,
    safe_message_type,
    unwrap_frida_message,
)
from .timeline_rules import (
    DynamicTimeline,
    EvidenceTimestamp,
    SystemTimelineClock,
    TimelineClock,
)


class FridaSessionState(str, Enum):
    CREATED = "created"
    STARTING = "starting"
    WAITING_READY = "waiting_ready"
    READY = "ready"
    COLLECTING = "collecting"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class FridaSessionError(RuntimeError):
    """Lifecycle failure with a stable, report-safe error code."""

    def __init__(self, code: str, message: str):
        self.code = code
        super().__init__(f"{code}: {message}")


def _classify_frida_exception(exc: BaseException, fallback: str) -> str:
    text = str(exc).casefold()
    if any(
        marker in text
        for marker in (
            "need gadget",
            "frida gadget",
            "server is not running",
            "unable to connect to remote frida-server",
            "connection refused",
            "connection closed",
        )
    ):
        return "frida_server_unavailable"
    if "version" in text and any(
        marker in text
        for marker in ("mismatch", "incompatible", "different", "protocol")
    ):
        return "frida_version_mismatch"
    if any(
        marker in text
        for marker in (
            "device not found",
            "unable to find device",
            "device is gone",
            "no such device",
        )
    ):
        return "frida_device_not_found"
    return fallback


class FridaAdapter(Protocol):
    def get_device(self, serial: str, timeout_seconds: float) -> Any: ...


class PythonFridaAdapter:
    """Lazy adapter around the optional ``frida`` Python package."""

    def get_device(self, serial: str, timeout_seconds: float) -> Any:
        frida = importlib.import_module("frida")
        manager = frida.get_device_manager()
        timeout_ms = max(0, int(timeout_seconds * 1000))
        return manager.get_device(serial, timeout=timeout_ms)


def _safe_datetime(value: str) -> datetime:
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    parsed = datetime.fromisoformat(text)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


@dataclass
class FridaSession:
    """Own one target process, script, event stream, and timing baseline."""

    run_id: str
    device: DeviceContext
    package_name: str
    script_path: Path
    event_log_path: Path
    adapter: FridaAdapter = field(default_factory=PythonFridaAdapter, repr=False)
    clock: TimelineClock = field(default_factory=SystemTimelineClock, repr=False)
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    protocol_error_path: Path | None = None
    device_timeout_seconds: float = 5.0
    stop_timeout_seconds: float = 3.0
    protocol_error_threshold: int = 10
    execution_mode: str = "spawn_suspended"
    command_runner: Callable[..., dict[str, Any]] = field(
        default=run_cmd,
        repr=False,
    )

    state: FridaSessionState = field(
        default=FridaSessionState.CREATED,
        init=False,
    )
    started_at: datetime | None = field(default=None, init=False)
    ready_at: datetime | None = field(default=None, init=False)
    stopped_at: datetime | None = field(default=None, init=False)
    error_code: str | None = field(default=None, init=False)
    error_message: str | None = field(default=None, init=False)
    pid: int | None = field(default=None, init=False)
    installed_hooks: list[str] = field(default_factory=list, init=False)
    failed_hooks: list[str] = field(default_factory=list, init=False)
    exit_code: int | None = field(default=None, init=False)
    stderr: str | None = field(default=None, init=False)

    def __post_init__(self) -> None:
        self.run_id = self.run_id.strip()
        self.package_name = self.package_name.strip()
        self.session_id = self.session_id.strip()
        if not self.run_id:
            raise ValueError("run_id must not be empty")
        if not self.session_id:
            raise ValueError("session_id must not be empty")
        if not self.package_name:
            raise ValueError("package_name must not be empty")
        if self.protocol_error_threshold < 1:
            raise ValueError("protocol_error_threshold must be positive")
        if self.execution_mode not in {"spawn_suspended", "attach_existing"}:
            raise ValueError("unsupported Frida execution mode")

        self.script_path = Path(self.script_path)
        self.event_log_path = Path(self.event_log_path)
        self.event_log_path.parent.mkdir(parents=True, exist_ok=True)
        self.event_log_path.touch(exist_ok=True)
        if self.protocol_error_path is None:
            self.protocol_error_path = self.event_log_path.with_name(
                "frida.protocol-errors.jsonl"
            )
        else:
            self.protocol_error_path = Path(self.protocol_error_path)

        self.timeline = DynamicTimeline(clock=self.clock)
        self._redactor = Redactor()
        self._writer = StructuredEventWriter(
            self.event_log_path,
            run_id=self.run_id,
            session_id=self.session_id,
            protocol_error_path=self.protocol_error_path,
            redactor=self._redactor,
        )
        self._device_handle: Any | None = None
        self._attached_session: Any | None = None
        self._script: Any | None = None
        self._ready_control: FridaControlEvent | None = None
        self._device_ready_monotonic_ms: float | None = None
        self._host_ready_monotonic_ms: float | None = None
        self._resumed = False
        self._ready_signal = threading.Event()
        self._collection_signal = threading.Event()
        self._consent_signal = threading.Event()
        self._stop_complete = threading.Event()
        self._lock = threading.RLock()
        self._stop_attempted = False
        self._cleanup_errors: list[str] = []

    @property
    def valid_events(self) -> list[dict[str, Any]]:
        return list(self._writer.valid_events)

    @property
    def control_events(self) -> list[dict[str, Any]]:
        return list(self._writer.control_events)

    @property
    def valid_messages(self) -> list[dict[str, Any]]:
        return list(self._writer.valid_messages)

    @property
    def protocol_errors(self) -> list[dict[str, Any]]:
        return list(self._writer.protocol_errors)

    @property
    def timestamps(self) -> dict[str, Any]:
        return self.timeline.to_dict()

    @property
    def cleanup_errors(self) -> list[str]:
        return list(self._cleanup_errors)

    @property
    def protocol_degraded(self) -> bool:
        return len(self._writer.protocol_errors) >= self.protocol_error_threshold

    def _set_failure(self, code: str, message: str) -> None:
        with self._lock:
            if self.error_code is None:
                self.error_code = code
                self.error_message = message
            self.state = FridaSessionState.FAILED

    def _raise_failure(self, code: str, message: str) -> None:
        self._set_failure(code, message)
        raise FridaSessionError(code, message)

    def _record_protocol_error(
        self,
        code: str,
        *,
        message_type: str | None = None,
    ) -> None:
        self._writer.record_protocol_error(
            code,
            message_type=message_type,
        )
        if self.protocol_degraded and self.error_code is None:
            self.error_code = "frida_protocol_error"
            self.error_message = "Frida protocol error threshold reached"
            if self.state is FridaSessionState.WAITING_READY:
                self.state = FridaSessionState.FAILED
                self._ready_signal.set()

    def _script_source(self) -> str:
        if not self.script_path.is_file():
            self._raise_failure(
                "hook_load_failed",
                "Frida script is missing",
            )
        try:
            source = self.script_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            self._set_failure(
                "hook_load_failed",
                "Frida script could not be read",
            )
            raise FridaSessionError(
                "hook_load_failed",
                "Frida script could not be read",
            ) from exc

        context = json.dumps(
            {
                "protocol_version": "1.0",
                "schema_version": "1.0",
                "run_id": self.run_id,
                "session_id": self.session_id,
                "process_name": self.package_name,
            },
            ensure_ascii=False,
            separators=(",", ":"),
        )
        return (
            f"globalThis.__ADSDK_CONTEXT__ = Object.freeze({context});\n"
            + source
        )

    def spawn(self) -> int:
        """Select the exact DeviceContext serial and spawn the app suspended."""

        with self._lock:
            if self.pid is not None:
                return self.pid
            if self.state is not FridaSessionState.CREATED:
                raise FridaSessionError(
                    "frida_spawn_failed",
                    "Frida session is not in created state",
                )
            self.state = FridaSessionState.STARTING
            self.started_at = self.clock.utc_now()

        try:
            handle = self.adapter.get_device(
                self.device.serial,
                self.device_timeout_seconds,
            )
        except ModuleNotFoundError as exc:
            self._set_failure(
                "frida_not_found",
                "Frida Python package is not installed",
            )
            raise FridaSessionError(
                "frida_not_found",
                "Frida Python package is not installed",
            ) from exc
        except Exception as exc:
            code = _classify_frida_exception(
                exc,
                "frida_device_not_found",
            )
            self._set_failure(
                code,
                "The selected Frida device is unavailable",
            )
            raise FridaSessionError(
                code,
                "The selected Frida device is unavailable",
            ) from exc

        selected_serial = getattr(handle, "id", None)
        if selected_serial != self.device.serial:
            self._raise_failure(
                "frida_device_not_found",
                "Frida returned a different device than DeviceContext",
            )
        self._device_handle = handle

        try:
            if self.execution_mode == "attach_existing":
                processes = handle.enumerate_processes()
                process = next(
                    (
                        item
                        for item in processes
                        if str(getattr(item, "identifier", "") or "") == self.package_name
                        or str(getattr(item, "name", "") or "") == self.package_name
                    ),
                    None,
                )
                if process is None:
                    pid_result = self.command_runner(
                        self.device.adb_command(
                            "shell", "pidof", self.package_name
                        ),
                        timeout=max(1, int(self.device_timeout_seconds)),
                    )
                    pid_text = str(pid_result.get("stdout") or "").strip()
                    first_pid = pid_text.split()[0] if pid_text else ""
                    adb_pid = int(first_pid) if first_pid.isdigit() else None
                    process = next(
                        (
                            item
                            for item in processes
                            if getattr(item, "pid", None) == adb_pid
                        ),
                        None,
                    )
                if process is None:
                    self._raise_failure(
                        "package_process_not_found",
                        "Target package process is not running",
                    )
                pid = getattr(process, "pid", None)
            else:
                pid = handle.spawn([self.package_name])
        except FridaSessionError:
            raise
        except Exception as exc:
            fallback = (
                "frida_attach_failed"
                if self.execution_mode == "attach_existing"
                else "frida_spawn_failed"
            )
            code = _classify_frida_exception(exc, fallback)
            self._set_failure(
                code,
                (
                    "Frida could not enumerate the target process"
                    if self.execution_mode == "attach_existing"
                    else "Frida could not spawn the target package"
                ),
            )
            raise FridaSessionError(
                code,
                self.error_message or "Frida process selection failed",
            ) from exc
        if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
            self._raise_failure(
                "frida_spawn_failed",
                "Frida returned an invalid spawned process id",
            )
        self.pid = pid
        return pid

    def load(self) -> None:
        """Attach to the still-suspended PID and load the hook script."""

        with self._lock:
            if self.state is FridaSessionState.WAITING_READY:
                return
            if self.state is not FridaSessionState.STARTING or self.pid is None:
                raise FridaSessionError(
                "hook_load_failed",
                "Frida spawn must complete before script load",
            )

        source = self._script_source()
        try:
            attached = self._device_handle.attach(self.pid)
        except Exception as exc:
            code = _classify_frida_exception(exc, "frida_attach_failed")
            self._set_failure(code, "Frida could not attach to the spawned process")
            raise FridaSessionError(
                code,
                "Frida could not attach to the spawned process",
            ) from exc
        try:
            if hasattr(attached, "on"):
                attached.on("detached", self._on_detached)
            script = attached.create_script(source)
            script.on("message", self._on_message)
            self._attached_session = attached
            self._script = script
            script.load()
        except FridaSessionError:
            raise
        except Exception as exc:
            self._set_failure(
                "hook_load_failed",
                "Frida hook script could not be loaded",
            )
            raise FridaSessionError(
                "hook_load_failed",
                "Frida hook script could not be loaded",
            ) from exc

        with self._lock:
            # A fake/fast script may emit ready synchronously from load().
            if self._ready_control is None:
                self.state = FridaSessionState.WAITING_READY
            else:
                self.state = FridaSessionState.READY

    def start(self) -> "FridaSession":
        """Spawn suspended and load hooks; readiness remains a separate gate."""

        if self.state in {
            FridaSessionState.WAITING_READY,
            FridaSessionState.READY,
            FridaSessionState.COLLECTING,
        }:
            return self
        try:
            self.spawn()
            self.load()
            return self
        except FridaSessionError:
            self.stop(timeout_seconds=self.stop_timeout_seconds)
            raise

    def _on_detached(self, *_args: Any, **_kwargs: Any) -> None:
        with self._lock:
            if self.state in {
                FridaSessionState.STOPPING,
                FridaSessionState.STOPPED,
            }:
                return
            self.exit_code = getattr(
                self._attached_session,
                "returncode",
                None,
            )
            self.stderr = None
            self._set_failure(
                (
                    "app_exited_after_resume"
                    if self._resumed
                    else "frida_process_exited"
                ),
                (
                    "Target app exited after resume"
                    if self._resumed
                    else "Frida session detached before collection completed"
                ),
            )
            self._ready_signal.set()

    def _on_message(self, message: Any, _data: Any) -> None:
        message_type = (
            safe_message_type(message.get("type"))
            if isinstance(message, dict)
            else None
        )
        try:
            model = unwrap_frida_message(
                message,
                run_id=self.run_id,
                session_id=self.session_id,
                redactor=self._redactor,
            )
        except FridaEventValidationError as exc:
            self._record_protocol_error(
                exc.code,
                message_type=message_type,
            )
            return

        if self.pid is not None and model.pid not in {0, self.pid}:
            self._record_protocol_error(
                "pid_mismatch",
                message_type=model.type,
            )
            return

        if isinstance(model, FridaStructuredEvent):
            if self._ready_control is None:
                self._record_protocol_error(
                    "event_before_ready",
                    message_type=model.type,
                )
                return
            self._writer.append(model)
            return

        if model.event == "hook_ready":
            with self._lock:
                if self.state not in {
                    FridaSessionState.STARTING,
                    FridaSessionState.WAITING_READY,
                }:
                    self._record_protocol_error(
                        "unexpected_hook_ready",
                        message_type=model.type,
                    )
                    return
                self._writer.append(model)
                self._ready_control = model
                self._device_ready_monotonic_ms = model.monotonic_ms
                ready_mark = self.timeline.mark_hook_ready()
                self._host_ready_monotonic_ms = ready_mark.monotonic_ms
                self.ready_at = _safe_datetime(model.timestamp_utc)
                self.installed_hooks = list(model.installed_hooks)
                self.failed_hooks = list(model.failed_hooks)
                self.state = FridaSessionState.READY
                self._ready_signal.set()
            return

        if model.event == "consent_granted":
            if self._existing_control("consent_granted") is not None:
                self._record_protocol_error(
                    "duplicate_consent_control",
                    message_type=model.type,
                )
                self._consent_signal.set()
                return
            self._writer.append(model)
            if self.timeline.collection_started_at is not None:
                self.timeline.mark_consent()
            self._consent_signal.set()
            return

        if model.event == "collection_started":
            if self._existing_control("collection_started") is not None:
                self._record_protocol_error(
                    "duplicate_collection_control",
                    message_type=model.type,
                )
                self._collection_signal.set()
                return
            self._writer.append(model)
            if self.timeline.collection_started_at is None:
                self.timeline.mark_collection_started()
            self._collection_signal.set()
            return

        self._writer.append(model)

    def wait_ready(
        self,
        timeout_seconds: float | None = None,
        *,
        timeout: float | None = None,
    ) -> FridaControlEvent:
        if timeout is not None:
            if timeout_seconds is not None:
                raise ValueError("provide only one ready timeout")
            timeout_seconds = timeout
        if timeout_seconds is None:
            timeout_seconds = 15.0
        if timeout_seconds < 0:
            raise ValueError("timeout_seconds must be non-negative")
        if self._ready_control is not None:
            return self._ready_control
        if self.state not in {
            FridaSessionState.STARTING,
            FridaSessionState.WAITING_READY,
        }:
            code = self.error_code or "frida_process_exited"
            raise FridaSessionError(
                code,
                self.error_message or "Frida session is not waiting for ready",
            )

        signaled = self._ready_signal.wait(timeout_seconds)
        if signaled and self._ready_control is not None:
            return self._ready_control
        if self.error_code is not None:
            raise FridaSessionError(
                self.error_code,
                self.error_message or "Frida readiness failed",
            )

        self._set_failure(
            "hook_ready_timeout",
            "Hook-ready message was not received before the deadline",
        )
        self.stop(timeout_seconds=self.stop_timeout_seconds)
        raise FridaSessionError(
            "hook_ready_timeout",
            "Hook-ready message was not received before the deadline",
        )

    def resume(self) -> EvidenceTimestamp:
        """Resume only after a validated hook_ready control message."""

        with self._lock:
            if self.state is FridaSessionState.COLLECTING:
                assert self.timeline.collection_started_at is not None
                return self.timeline.collection_started_at
            if (
                self.state is not FridaSessionState.READY
                or self._ready_control is None
                or self.pid is None
            ):
                raise FridaSessionError(
                    "frida_protocol_error",
                    "App resume is forbidden before hook_ready",
                )

        # Publish the collection baseline while the spawned app is still
        # suspended.  This makes the ordering provable:
        # hook_ready -> collection_started -> resume.
        collection_start = self.emit_collection_started()

        if self.execution_mode == "spawn_suspended":
            try:
                self._device_handle.resume(self.pid)
            except Exception as exc:
                self._set_failure(
                    "frida_process_exited",
                    "Frida could not resume the spawned app",
                )
                raise FridaSessionError(
                    "frida_process_exited",
                    "Frida could not resume the spawned app",
                ) from exc

        with self._lock:
            self._resumed = True
            self.timeline.mark_app_resumed()
            self.state = FridaSessionState.COLLECTING
        assert self.timeline.collection_started_at is not None
        return self.timeline.collection_started_at

    def _estimated_device_monotonic_ms(self) -> float:
        if (
            self._device_ready_monotonic_ms is None
            or self._host_ready_monotonic_ms is None
        ):
            raise FridaSessionError(
                "frida_protocol_error",
                "Device monotonic baseline is unavailable",
            )
        host_now_ms = float(self.clock.monotonic()) * 1000.0
        return (
            self._device_ready_monotonic_ms
            + host_now_ms
            - self._host_ready_monotonic_ms
        )

    def _existing_control(self, event: str) -> FridaControlEvent | None:
        for item in reversed(self._writer.control_events):
            if item.get("event") == event:
                return FridaControlEvent.model_validate(item)
        return None

    def emit_collection_started(self) -> FridaControlEvent:
        """Persist the collection baseline in the same device-time stream."""

        existing = self._existing_control("collection_started")
        if existing is not None:
            return existing
        if (
            self.state
            not in {
                FridaSessionState.READY,
                FridaSessionState.COLLECTING,
            }
            or self.pid is None
        ):
            raise FridaSessionError(
                "frida_protocol_error",
                "Collection-start control requires hook_ready",
            )

        mark = (
            self.timeline.collection_started_at
            or self.timeline.mark_collection_started()
        )

        exports = getattr(self._script, "exports_sync", None)
        if exports is not None:
            method = getattr(exports, "emit_collection_started", None)
            if method is None:
                method = getattr(exports, "emitCollectionStarted", None)
            if callable(method):
                try:
                    method("frida_session")
                    if self._collection_signal.wait(0.25):
                        existing = self._existing_control("collection_started")
                        if existing is not None:
                            return existing
                except Exception:
                    pass

        payload = {
            "protocol_version": "1.0",
            "schema_version": "1.0",
            "type": "control",
            "event": "collection_started",
            "event_id": str(uuid.uuid4()),
            "run_id": self.run_id,
            "session_id": self.session_id,
            "timestamp_utc": mark.to_dict()["timestamp_utc"],
            "monotonic_ms": self._estimated_device_monotonic_ms(),
            "pid": self.pid,
            "source": "frida_session",
            "metadata": {
                "monotonic_source": "hook_ready_offset",
            },
        }
        model = self._writer.append(payload)
        assert isinstance(model, FridaControlEvent)
        return model

    def emit_consent(
        self,
        *,
        source: str = "configured_delay",
    ) -> FridaControlEvent:
        """Emit the one consent boundary in the device-monotonic event stream."""

        if self.state is not FridaSessionState.COLLECTING or self.pid is None:
            raise FridaSessionError(
                "frida_protocol_error",
                "Consent requires an active collection",
            )
        existing = self._existing_control("consent_granted")
        if existing is not None:
            return existing

        # If the script exposes an RPC control method, it stamps the event on
        # the device.  The fallback maps the ready device timestamp through
        # host monotonic elapsed time and remains immune to wall-clock jumps.
        rpc_emitted = False
        exports = getattr(self._script, "exports_sync", None)
        if exports is not None:
            method = getattr(exports, "emit_consent", None)
            if method is None:
                method = getattr(exports, "emitConsent", None)
            if callable(method):
                try:
                    method(source)
                    rpc_emitted = self._consent_signal.wait(0.25)
                except Exception:
                    rpc_emitted = False

        if rpc_emitted:
            existing = self._existing_control("consent_granted")
            if existing is not None:
                return existing

        mark = self.timeline.mark_consent()
        payload = {
            "protocol_version": "1.0",
            "schema_version": "1.0",
            "type": "control",
            "event": "consent_granted",
            "event_id": str(uuid.uuid4()),
            "run_id": self.run_id,
            "session_id": self.session_id,
            "timestamp_utc": mark.to_dict()["timestamp_utc"],
            "monotonic_ms": self._estimated_device_monotonic_ms(),
            "pid": self.pid,
            "source": source,
            "metadata": {
                "monotonic_source": "hook_ready_offset",
            },
        }
        model = self._writer.append(payload)
        assert isinstance(model, FridaControlEvent)
        self._consent_signal.set()
        return model

    def emit_control_event(
        self,
        event: dict[str, Any],
    ) -> FridaControlEvent:
        """Route coordinator controls through the session time authority."""

        name = event.get("event")
        if name == "collection_started":
            return self.emit_collection_started()
        if name == "consent_granted":
            source = event.get("source")
            return self.emit_consent(
                source=(
                    source.strip()
                    if isinstance(source, str) and source.strip()
                    else "configured_delay"
                )
            )
        raise FridaSessionError(
            "frida_protocol_error",
            "Unsupported lifecycle control event",
        )

    record_control_event = emit_control_event
    append_control_event = emit_control_event

    def write_events_json(self, output_path: str | Path) -> Path:
        """Publish validated messages as the compatibility JSON array."""

        return self._writer.write_events_json(output_path)

    def to_status(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "session_id": self.session_id,
            "state": self.state.value,
            "package_name": self.package_name,
            "device": self.device.to_public_dict(),
            "pid": self.pid,
            "error_code": self.error_code,
            "error": self.error_message,
            "event_log_path": self.event_log_path.name,
            "valid_event_count": len(self._writer.valid_events),
            "protocol_error_count": len(self._writer.protocol_errors),
            "installed_hooks": list(self.installed_hooks),
            "failed_hooks": list(self.failed_hooks),
            "timestamps": self.timestamps,
        }

    def _cleanup_owned_resources(self) -> None:
        errors: list[str] = []
        if self._script is not None:
            try:
                self._script.unload()
            except Exception:
                errors.append("script_unload_failed")
        if self._attached_session is not None:
            try:
                self._attached_session.detach()
            except Exception:
                errors.append("session_detach_failed")
        if not self._resumed and self.pid is not None and self._device_handle is not None:
            try:
                self._device_handle.kill(self.pid)
            except Exception:
                errors.append("suspended_process_kill_failed")
        with self._lock:
            self._cleanup_errors.extend(errors)
            self._stop_complete.set()

    def _emergency_kill(self) -> None:
        if self.pid is None or self._device_handle is None:
            return
        try:
            self._device_handle.kill(self.pid)
        except Exception:
            self._cleanup_errors.append("emergency_process_kill_failed")

    def stop(
        self,
        timeout_seconds: float | None = None,
        *,
        timeout: float | None = None,
    ) -> bool:
        """Stop only this session's resources; repeated calls are idempotent."""

        if timeout is not None:
            if timeout_seconds is not None:
                raise ValueError("provide only one stop timeout")
            timeout_seconds = timeout
        timeout = self.stop_timeout_seconds if timeout_seconds is None else timeout_seconds
        if timeout < 0:
            raise ValueError("timeout_seconds must be non-negative")

        wait_for_existing = False
        with self._lock:
            if self.state is FridaSessionState.STOPPED:
                return True
            if self._stop_attempted:
                wait_for_existing = True
                primary_error_code = self.error_code
                primary_error_message = self.error_message
            else:
                self._stop_attempted = True
                primary_error_code = self.error_code
                primary_error_message = self.error_message
                self.state = FridaSessionState.STOPPING

        if wait_for_existing:
            completed = self._stop_complete.wait(timeout)
            return completed and self.error_code != "frida_stop_timeout"

        worker = threading.Thread(
            target=self._cleanup_owned_resources,
            name=f"frida-stop-{self.session_id[:8]}",
            daemon=True,
        )
        worker.start()
        completed = self._stop_complete.wait(timeout)
        self.stopped_at = self.clock.utc_now()
        if self.timeline.collection_ended_at is None:
            self.timeline.mark_collection_ended()

        if not completed:
            self._emergency_kill()
            self.error_code = "frida_stop_timeout"
            self.error_message = "Frida session cleanup exceeded its deadline"
            self.state = FridaSessionState.FAILED
            return False

        if self._cleanup_errors:
            if primary_error_code is None:
                self.error_code = "frida_protocol_error"
                self.error_message = "Frida cleanup completed with errors"
            else:
                self.error_code = primary_error_code
                self.error_message = primary_error_message
            self.state = FridaSessionState.FAILED
            return False

        if primary_error_code is not None:
            self.error_code = primary_error_code
            self.error_message = primary_error_message
            self.state = FridaSessionState.FAILED
        else:
            self.state = FridaSessionState.STOPPED
        return True
