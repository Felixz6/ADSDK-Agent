"""Owned mitmproxy collection sessions and a process-local port lease pool.

The lease pool is protected across threads in one Python worker.  OS-level
availability probing prevents a worker from adopting or terminating an
unknown listener.  Deployments with multiple Uvicorn workers still need an
external lease service or a distinct configured port range per worker; a
foreign worker is treated as an unknown port occupant and is never taken over.
"""

from __future__ import annotations

import os
import signal
import socket
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Callable, Iterable, TextIO

from app.config import DEFAULT_MITM_PORT
from app.core.device import DeviceContext
from app.tools.utils import run_cmd
from app.tools.traffic_events import (
    TrafficCollectionResult,
    load_traffic_jsonl,
    validate_traffic_jsonl,
)

ProcessFactory = Callable[..., subprocess.Popen[str]]
PortAvailabilityProbe = Callable[[str, int], bool]
ProcessTreeTerminator = Callable[..., None]
CommandRunner = Callable[[list[str]], dict[str, Any]]


class MitmSessionState(str, Enum):
    CREATED = "created"
    STARTING = "starting"
    READY = "ready"
    COLLECTING = "collecting"
    STOPPING = "stopping"
    STOPPED = "stopped"
    FAILED = "failed"


class PortAllocationError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class MitmSessionError(RuntimeError):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


def _port_is_available(host: str, port: int) -> bool:
    """Probe availability by binding; never connect to or signal an occupant."""

    try:
        addresses = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
            flags=socket.AI_PASSIVE,
        )
    except OSError:
        return False
    for family, socktype, protocol, _canonical, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as probe:
                if family == socket.AF_INET6:
                    try:
                        probe.setsockopt(
                            socket.IPPROTO_IPV6,
                            socket.IPV6_V6ONLY,
                            1,
                        )
                    except OSError:
                        pass
                probe.bind(address)
                return True
        except OSError:
            continue
    return False


class PortPool:
    """Thread-safe process-local ownership registry for configured ports."""

    def __init__(
        self,
        ports: Iterable[int],
        *,
        availability_probe: PortAvailabilityProbe = _port_is_available,
    ) -> None:
        normalized = tuple(dict.fromkeys(int(port) for port in ports))
        if not normalized:
            raise ValueError("port pool must not be empty")
        if any(port < 1 or port > 65535 for port in normalized):
            raise ValueError("port pool values must be between 1 and 65535")
        self.ports = normalized
        self._availability_probe = availability_probe
        self._leases: dict[tuple[str, int], str] = {}
        self._lock = threading.RLock()

    def acquire(
        self,
        *,
        owner_id: str,
        host: str,
        requested_port: int | None = None,
    ) -> int:
        candidates = (
            (requested_port,)
            if requested_port is not None
            else self.ports
        )
        if requested_port is not None and requested_port not in self.ports:
            raise PortAllocationError(
                "mitm_port_not_configured",
                "requested mitm port is outside the configured pool",
            )

        occupied_count = 0
        leased_count = 0
        with self._lock:
            for port in candidates:
                key = (host, port)
                current_owner = self._leases.get(key)
                if current_owner is not None:
                    if current_owner == owner_id:
                        return port
                    leased_count += 1
                    continue
                if not self._availability_probe(host, port):
                    occupied_count += 1
                    continue
                self._leases[key] = owner_id
                return port

        if requested_port is not None and leased_count:
            raise PortAllocationError(
                "mitm_resource_busy",
                "requested mitm port is leased by another session",
            )
        if requested_port is not None and occupied_count:
            raise PortAllocationError(
                "mitm_port_in_use",
                "requested mitm port has an unknown occupant",
            )
        if occupied_count and not leased_count and len(candidates) == 1:
            raise PortAllocationError(
                "mitm_port_in_use",
                "configured mitm port has an unknown occupant",
            )
        raise PortAllocationError(
            "mitm_no_available_port",
            "no configured mitm port is available",
        )

    def release(self, *, owner_id: str, host: str, port: int) -> bool:
        """Release only an exact owner match."""

        key = (host, port)
        with self._lock:
            if self._leases.get(key) != owner_id:
                return False
            del self._leases[key]
            return True

    def owner(self, *, host: str, port: int) -> str | None:
        with self._lock:
            return self._leases.get((host, port))


def _default_port_pool() -> PortPool:
    try:
        start = int(
            os.getenv("MITM_PORT_START", str(DEFAULT_MITM_PORT))
        )
        end = int(os.getenv("MITM_PORT_END", str(start)))
    except ValueError:
        start = DEFAULT_MITM_PORT
        end = DEFAULT_MITM_PORT
    if end < start:
        start, end = end, start
    return PortPool(range(start, end + 1))


# A global *resource manager* is intentional; no process, file handle, or
# "current session" is stored globally.
DEFAULT_PORT_POOL = _default_port_pool()


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def terminate_process_tree(
    process: subprocess.Popen[str],
    *,
    force: bool,
    timeout: float,
) -> None:
    """Signal the complete owned process tree; the caller still performs wait.

    Windows uses ``taskkill /T /PID`` without a command shell.  POSIX children
    are started in a new session and signalled by process group.  A direct
    Popen signal is retained only as a bounded fallback, and the session always
    calls ``wait()`` afterward.
    """

    if process.poll() is not None:
        return
    if os.name == "nt":
        command = [
            "taskkill",
            "/PID",
            str(process.pid),
            "/T",
        ]
        if force:
            command.append("/F")
        try:
            completed = subprocess.run(
                command,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                shell=False,
                check=False,
                timeout=max(timeout, 0.1),
            )
            if completed.returncode == 0 or process.poll() is not None:
                return
        except (OSError, subprocess.SubprocessError):
            pass
    else:
        selected_signal = signal.SIGKILL if force else signal.SIGTERM
        try:
            process_group = os.getpgid(process.pid)
            os.killpg(process_group, selected_signal)
            return
        except (OSError, AttributeError):
            pass

    if force:
        process.kill()
    else:
        process.terminate()


def _validate_owner_identifier(value: str, name: str) -> str:
    normalized = value.strip()
    if not normalized:
        raise ValueError(f"{name} must not be empty")
    if len(normalized) > 256:
        raise ValueError(f"{name} is too long")
    if any(
        character in normalized
        for character in ("\x00", "\r", "\n", "/", "\\")
    ):
        raise ValueError(f"{name} contains control characters")
    return normalized


@dataclass
class MitmSession:
    """One run-owned mitmdump process and its complete artifact boundary."""

    run_id: str
    device: DeviceContext
    traffic_dir: Path
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    listen_host: str = "127.0.0.1"
    listen_port: int | None = None
    port_pool: PortPool = field(
        default_factory=lambda: DEFAULT_PORT_POOL,
        repr=False,
    )
    process_factory: ProcessFactory = field(
        default=subprocess.Popen,
        repr=False,
    )
    process_tree_terminator: ProcessTreeTerminator = field(
        default=terminate_process_tree,
        repr=False,
    )
    monotonic: Callable[[], float] = field(
        default=time.monotonic,
        repr=False,
    )
    sleep: Callable[[float], None] = field(
        default=time.sleep,
        repr=False,
    )
    utc_now: Callable[[], datetime] = field(
        default=_utc_now,
        repr=False,
    )
    stop_timeout: float = 3.0
    addon_path: Path | None = None
    device_proxy_host: str | None = None
    command_runner: CommandRunner = field(default=run_cmd, repr=False)

    process: subprocess.Popen[str] | None = field(
        default=None,
        init=False,
        repr=False,
    )
    state: MitmSessionState = field(
        default=MitmSessionState.CREATED,
        init=False,
    )
    started_at: datetime | None = field(default=None, init=False)
    ready_at: datetime | None = field(default=None, init=False)
    stopped_at: datetime | None = field(default=None, init=False)
    exit_code: int | None = field(default=None, init=False)
    error_code: str | None = field(default=None, init=False)
    error_message: str | None = field(default=None, init=False)
    ready_timeout: float | None = field(default=None, init=False)
    original_device_proxy: str | None = field(default=None, init=False)
    device_proxy_configured: bool = field(default=False, init=False)
    device_proxy_restored: bool | None = field(default=None, init=False)
    flow_path: Path = field(init=False)
    jsonl_path: Path = field(init=False)
    stderr_path: Path = field(init=False)

    _stderr_handle: TextIO | None = field(
        default=None,
        init=False,
        repr=False,
    )
    _lease_acquired: bool = field(
        default=False,
        init=False,
        repr=False,
    )
    _stop_completed: bool = field(
        default=False,
        init=False,
        repr=False,
    )
    _stop_result: bool = field(
        default=True,
        init=False,
        repr=False,
    )
    _was_ready: bool = field(
        default=False,
        init=False,
        repr=False,
    )
    _lock: threading.RLock = field(
        default_factory=threading.RLock,
        init=False,
        repr=False,
    )

    def __post_init__(self) -> None:
        self.run_id = _validate_owner_identifier(self.run_id, "run_id")
        self.session_id = _validate_owner_identifier(
            self.session_id,
            "session_id",
        )
        if not isinstance(self.device, DeviceContext):
            raise TypeError("device must be DeviceContext")
        self.listen_host = self.listen_host.strip()
        if not self.listen_host:
            raise ValueError("listen_host must not be empty")
        if self.listen_port is not None and not 1 <= self.listen_port <= 65535:
            raise ValueError("listen_port must be between 1 and 65535")
        if self.stop_timeout <= 0:
            raise ValueError("stop_timeout must be positive")
        if self.device_proxy_host is not None:
            self.device_proxy_host = self.device_proxy_host.strip()
            if not self.device_proxy_host:
                self.device_proxy_host = None
            elif any(
                character in self.device_proxy_host
                for character in ("\x00", "\r", "\n", ":", "@", "/")
            ):
                raise ValueError("device_proxy_host is invalid")

        self.traffic_dir = Path(self.traffic_dir).resolve(strict=False)
        if (
            self.traffic_dir.name != "traffic"
            or self.traffic_dir.parent.name != self.run_id
        ):
            raise ValueError(
                "traffic_dir must be the current run's traffic directory"
            )
        self.flow_path = self.traffic_dir / "flows.mitm"
        self.jsonl_path = self.traffic_dir / "requests.jsonl"
        self.stderr_path = self.traffic_dir / "mitm.stderr.log"
        if self.addon_path is None:
            self.addon_path = (
                Path(__file__).resolve().parents[1]
                / "analyzers"
                / "traffic"
                / "mitm_addon.py"
            )
        else:
            self.addon_path = Path(self.addon_path).resolve(strict=False)
        self._assert_owned_paths()

    def _assert_owned_paths(self) -> None:
        root = self.traffic_dir.resolve(strict=False)
        for candidate in (
            self.flow_path,
            self.jsonl_path,
            self.stderr_path,
        ):
            resolved = candidate.resolve(strict=False)
            try:
                resolved.relative_to(root)
            except ValueError as exc:
                raise ValueError(
                    "mitm artifact path is outside the session traffic directory"
                ) from exc

    def _set_failure(self, code: str, message: str) -> None:
        self.error_code = code
        self.error_message = message
        self.state = MitmSessionState.FAILED

    def _command(self) -> list[str]:
        assert self.listen_port is not None
        assert self.addon_path is not None
        return [
            "mitmdump",
            "--quiet",
            "--listen-host",
            self.listen_host,
            "--listen-port",
            str(self.listen_port),
            "-w",
            str(self.flow_path),
            "-s",
            str(self.addon_path),
            "--set",
            f"adsdk_run_id={self.run_id}",
            "--set",
            f"adsdk_session_id={self.session_id}",
            "--set",
            f"adsdk_jsonl_path={self.jsonl_path}",
        ]

    def start(self) -> bool:
        """Allocate a port and spawn only this session's process."""

        with self._lock:
            if self.state in {
                MitmSessionState.STARTING,
                MitmSessionState.READY,
                MitmSessionState.COLLECTING,
            }:
                return True
            if self.state is not MitmSessionState.CREATED:
                return False
            self.state = MitmSessionState.STARTING
            try:
                self.listen_port = self.port_pool.acquire(
                    owner_id=self.session_id,
                    host=self.listen_host,
                    requested_port=self.listen_port,
                )
                self._lease_acquired = True
            except PortAllocationError as exc:
                self._set_failure(exc.code, str(exc))
                return False

            try:
                self._assert_owned_paths()
                if self.addon_path is None or not self.addon_path.is_file():
                    raise FileNotFoundError("mitm addon was not found")
                self.traffic_dir.mkdir(parents=True, exist_ok=True)
                for artifact in (
                    self.flow_path,
                    self.jsonl_path,
                    self.stderr_path,
                ):
                    if artifact.exists():
                        raise FileExistsError(
                            "owned mitm artifact already exists"
                        )
                self.jsonl_path.touch(exist_ok=False)
                self._stderr_handle = self.stderr_path.open(
                    "x",
                    encoding="utf-8",
                    newline="\n",
                )
                project_root = Path(__file__).resolve().parents[2]
                process_options: dict[str, Any] = {
                    "stdout": subprocess.DEVNULL,
                    "stderr": self._stderr_handle,
                    "text": True,
                    "shell": False,
                    "cwd": str(project_root),
                    "env": {
                        **os.environ,
                        "PYTHONPATH": os.pathsep.join(
                            value
                            for value in (
                                str(project_root),
                                os.environ.get("PYTHONPATH", ""),
                            )
                            if value
                        ),
                    },
                }
                if os.name == "nt":
                    process_options["creationflags"] = getattr(
                        subprocess,
                        "CREATE_NEW_PROCESS_GROUP",
                        0,
                    )
                else:
                    process_options["start_new_session"] = True
                self.process = self.process_factory(
                    self._command(),
                    **process_options,
                )
                self.started_at = self.utc_now()
                return True
            except FileNotFoundError:
                self._set_failure(
                    "mitm_not_found",
                    "mitmdump executable or addon was not found",
                )
            except FileExistsError:
                self._set_failure(
                    "mitm_artifact_conflict",
                    "mitm session artifacts already exist",
                )
            except Exception:
                self._set_failure(
                    "mitm_start_failed",
                    "mitmdump process could not be started",
                )
            self._cleanup_resources()
            return False

    def _cleanup_resources(self) -> None:
        if self._stderr_handle is not None:
            try:
                self._stderr_handle.flush()
                self._stderr_handle.close()
            except OSError:
                pass
            self._stderr_handle = None
        if self._lease_acquired and self.listen_port is not None:
            self.port_pool.release(
                owner_id=self.session_id,
                host=self.listen_host,
                port=self.listen_port,
            )
            self._lease_acquired = False

    def _stop_owned_process(
        self,
        *,
        timeout: float,
        preserve_failure: bool,
    ) -> bool:
        if self._stop_completed:
            return self._stop_result

        process = self.process
        timed_out = False
        stop_failed = False
        if process is not None:
            try:
                return_code = process.poll()
            except Exception:
                return_code = None
                stop_failed = True
            if return_code is None:
                try:
                    self.process_tree_terminator(
                        process,
                        force=False,
                        timeout=timeout,
                    )
                except Exception:
                    try:
                        process.terminate()
                    except Exception:
                        stop_failed = True
                try:
                    return_code = process.wait(timeout=timeout)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    try:
                        self.process_tree_terminator(
                            process,
                            force=True,
                            timeout=timeout,
                        )
                    except Exception:
                        try:
                            process.kill()
                        except Exception:
                            stop_failed = True
                    try:
                        return_code = process.wait(timeout=timeout)
                    except subprocess.TimeoutExpired:
                        try:
                            return_code = process.poll()
                        except Exception:
                            return_code = None
                        stop_failed = True
                    except Exception:
                        stop_failed = True
                except Exception:
                    stop_failed = True
            self.exit_code = return_code

        self._cleanup_resources()
        self.stopped_at = self.utc_now()
        self._stop_completed = True
        if timed_out:
            self._stop_result = False
            self._set_failure(
                "mitm_stop_timeout",
                "owned mitmdump process exceeded the stop timeout",
            )
        elif stop_failed:
            self._stop_result = False
            self._set_failure(
                "mitm_stop_failed",
                "owned mitmdump process could not be stopped cleanly",
            )
        elif preserve_failure:
            # The session remains failed, while cleanup itself succeeded.
            self._stop_result = True
            self.state = MitmSessionState.FAILED
        else:
            self._stop_result = True
            self.state = MitmSessionState.STOPPED
        return self._stop_result

    def _fail_and_cleanup(self, code: str, message: str) -> bool:
        self._set_failure(code, message)
        self._stop_owned_process(
            timeout=self.stop_timeout,
            preserve_failure=True,
        )
        # A cleanup timeout is a secondary failure; retain the primary ready
        # or protocol error as requested by the pipeline contract.
        if self.error_code in {"mitm_stop_timeout", "mitm_stop_failed"}:
            self.error_code = code
            self.error_message = message
            self.state = MitmSessionState.FAILED
        return False

    def wait_ready(
        self,
        *,
        timeout: float,
        poll_interval: float = 0.05,
    ) -> bool:
        """Wait for a matching addon control record, not a listening socket."""

        if timeout <= 0:
            raise ValueError("timeout must be positive")
        if poll_interval <= 0:
            raise ValueError("poll_interval must be positive")
        self.ready_timeout = timeout
        deadline = self.monotonic() + timeout

        while True:
            with self._lock:
                if self.state is not MitmSessionState.STARTING:
                    return self.state in {
                        MitmSessionState.READY,
                        MitmSessionState.COLLECTING,
                    }
                process = self.process
                if process is None:
                    return self._fail_and_cleanup(
                        "mitm_start_failed",
                        "mitmdump process ownership was lost",
                    )
                return_code = process.poll()
                if return_code is not None:
                    self.exit_code = return_code
                    stderr_tail = self._stderr_tail()
                    return self._fail_and_cleanup(
                        "mitm_process_exited",
                        "mitmdump exited before addon ready"
                        + (f": {stderr_tail}" if stderr_tail else ""),
                    )

                self._assert_owned_paths()
                read_result = load_traffic_jsonl(
                    self.jsonl_path,
                    run_id=self.run_id,
                    session_id=self.session_id,
                )
                if read_result.ready_seen:
                    self.ready_at = self.utc_now()
                    self._was_ready = True
                    self.state = MitmSessionState.READY
                    return True
                if read_result.issues:
                    mismatch = next(
                        (
                            issue
                            for issue in read_result.issues
                            if issue.code
                            in {
                                "traffic_run_mismatch",
                                "traffic_session_mismatch",
                            }
                        ),
                        None,
                    )
                    if mismatch is not None:
                        return self._fail_and_cleanup(
                            "mitm_session_mismatch",
                            "mitm ready record ownership does not match",
                        )
                    return self._fail_and_cleanup(
                        "mitm_protocol_error",
                        "mitm ready control record is malformed",
                    )
                now = self.monotonic()
                if now >= deadline:
                    return self._fail_and_cleanup(
                        "mitm_ready_timeout",
                        "mitm addon ready record was not observed before timeout",
                    )
            remaining = max(0.0, deadline - self.monotonic())
            self.sleep(min(poll_interval, remaining))

    def mark_collecting(self) -> None:
        with self._lock:
            if self.state is not MitmSessionState.READY:
                raise RuntimeError("mitm session is not ready")
            if self.device_proxy_host is not None:
                self._configure_device_proxy()
            self.state = MitmSessionState.COLLECTING

    def _stderr_tail(self, *, max_lines: int = 20, max_chars: int = 2000) -> str:
        try:
            if self._stderr_handle is not None:
                self._stderr_handle.flush()
            text = self.stderr_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return ""
        lines = [line.strip() for line in text.splitlines() if line.strip()]
        return "\n".join(lines[-max_lines:])[-max_chars:]

    def _configure_device_proxy(self) -> None:
        if self.device_proxy_configured:
            return
        assert self.listen_port is not None
        current = self.command_runner(
            self.device.adb_command(
                "shell", "settings", "get", "global", "http_proxy"
            )
        )
        if current.get("returncode") != 0:
            self._set_failure(
                "device_proxy_read_failed",
                "device proxy value could not be read",
            )
            raise MitmSessionError(
                "device_proxy_read_failed",
                "device proxy value could not be read",
            )
        self.original_device_proxy = str(current.get("stdout") or "").strip()
        target = f"{self.device_proxy_host}:{self.listen_port}"
        updated = self.command_runner(
            self.device.adb_command(
                "shell", "settings", "put", "global", "http_proxy", target
            )
        )
        if updated.get("returncode") != 0:
            self._set_failure(
                "device_proxy_config_failed",
                "device proxy could not be configured",
            )
            raise MitmSessionError(
                "device_proxy_config_failed",
                "device proxy could not be configured",
            )
        self.device_proxy_configured = True
        self.device_proxy_restored = False

    def _restore_device_proxy(self) -> bool:
        if not self.device_proxy_configured:
            return True
        original = self.original_device_proxy
        if original and original.casefold() != "null":
            command = self.device.adb_command(
                "shell", "settings", "put", "global", "http_proxy", original
            )
        else:
            command = self.device.adb_command(
                "shell", "settings", "delete", "global", "http_proxy"
            )
        result = self.command_runner(command)
        restored = result.get("returncode") == 0
        self.device_proxy_restored = restored
        if restored:
            self.device_proxy_configured = False
        return restored

    def stop(self, *, timeout: float | None = None) -> bool:
        """Idempotently stop only the process stored on this object."""

        selected_timeout = self.stop_timeout if timeout is None else timeout
        if selected_timeout <= 0:
            raise ValueError("timeout must be positive")
        with self._lock:
            if self._stop_completed:
                return self._stop_result
            preserve_failure = self.state is MitmSessionState.FAILED
            if not preserve_failure:
                self.state = MitmSessionState.STOPPING
            restored = self._restore_device_proxy()
            stopped = self._stop_owned_process(
                timeout=selected_timeout,
                preserve_failure=preserve_failure,
            )
            if not restored:
                self._stop_result = False
                if not preserve_failure:
                    self._set_failure(
                        "proxy_restore_failed",
                        "device proxy could not be restored",
                    )
            return stopped and restored

    def validate_traffic(self) -> TrafficCollectionResult:
        return validate_traffic_jsonl(
            self.jsonl_path,
            run_id=self.run_id,
            session_id=self.session_id,
            process_ready=self._was_ready,
        )

    def to_status(self) -> dict[str, Any]:
        process = self.process
        return {
            "ok": self.state
            in {
                MitmSessionState.READY,
                MitmSessionState.COLLECTING,
                MitmSessionState.STOPPED,
            }
            and self.error_code is None,
            "run_id": self.run_id,
            "session_id": self.session_id,
            "device": self.device.to_public_dict(),
            "state": self.state.value,
            "pid": process.pid if process is not None else None,
            "port": self.listen_port,
            "listen_host": self.listen_host,
            "listen_port": self.listen_port,
            "addon_path": str(self.addon_path) if self.addon_path else None,
            "command": self._command() if self.listen_port is not None else None,
            "ready_timeout": self.ready_timeout,
            "stderr_tail": self._stderr_tail(),
            "device_proxy_host": self.device_proxy_host,
            "device_proxy_configured": self.device_proxy_configured,
            "device_proxy_restored": self.device_proxy_restored,
            "traffic_dir": str(self.traffic_dir),
            "flow_file": str(self.flow_path),
            "jsonl_path": str(self.jsonl_path),
            "stderr_path": str(self.stderr_path),
            "started_at": (
                self.started_at.isoformat()
                if self.started_at is not None
                else None
            ),
            "ready_at": (
                self.ready_at.isoformat()
                if self.ready_at is not None
                else None
            ),
            "stopped_at": (
                self.stopped_at.isoformat()
                if self.stopped_at is not None
                else None
            ),
            "exit_code": self.exit_code,
            "error_code": self.error_code,
            "error": self.error_message,
        }
