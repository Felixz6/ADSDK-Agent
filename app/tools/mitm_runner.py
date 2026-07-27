"""Compatibility-facing helpers around explicit :class:`MitmSession` objects.

This module has no global process, output handle, last-state singleton, or
implicit current owner.  A caller must retain and pass the session it created.
"""

from __future__ import annotations

import os
import socket
from pathlib import Path
from typing import Any

from app.config import DEFAULT_MITM_PORT
from app.core.device import DeviceContext
from app.tools.mitm_session import MitmSession, MitmSessionState, PortPool


def check_port_listening(
    port: int = DEFAULT_MITM_PORT,
    host: str = "127.0.0.1",
    timeout: float = 0.5,
) -> bool:
    """Environment diagnostic only; listening never establishes ownership."""

    try:
        addresses = socket.getaddrinfo(
            host,
            port,
            type=socket.SOCK_STREAM,
        )
    except OSError:
        return False
    for family, socktype, protocol, _canonical, address in addresses:
        try:
            with socket.socket(family, socktype, protocol) as sock:
                sock.settimeout(timeout)
                if sock.connect_ex(address) == 0:
                    return True
        except OSError:
            continue
    return False


def _check_dir_writable(path: str | os.PathLike[str]) -> bool:
    directory = Path(path)
    try:
        directory.mkdir(parents=True, exist_ok=True)
        probe = directory / ".write_probe"
        with probe.open("x", encoding="utf-8") as stream:
            stream.write("ok")
            stream.flush()
            os.fsync(stream.fileno())
        probe.unlink()
        return True
    except Exception:
        try:
            probe.unlink(missing_ok=True)
        except (OSError, UnboundLocalError):
            pass
        return False


def create_mitm_session(
    *,
    run_id: str,
    device: DeviceContext,
    run_dir: str | os.PathLike[str] | None = None,
    traffic_dir: str | os.PathLike[str] | None = None,
    listen_host: str = "127.0.0.1",
    listen_port: int | None = None,
    port_pool: PortPool | None = None,
    **session_options: Any,
) -> MitmSession:
    """Create, but do not start, one explicitly owned collection session."""

    if (run_dir is None) == (traffic_dir is None):
        raise ValueError("provide exactly one of run_dir or traffic_dir")
    selected_traffic_dir = (
        Path(traffic_dir)
        if traffic_dir is not None
        else Path(run_dir) / "traffic"  # type: ignore[arg-type]
    )
    values: dict[str, Any] = {
        "run_id": run_id,
        "device": device,
        "traffic_dir": selected_traffic_dir,
        "listen_host": listen_host,
        "listen_port": listen_port,
        **session_options,
    }
    if port_pool is not None:
        values["port_pool"] = port_pool
    return MitmSession(**values)


def start_mitm(session: MitmSession) -> dict[str, Any]:
    if not isinstance(session, MitmSession):
        return {
            "ok": False,
            "error_code": "mitm_session_required",
            "error": "start_mitm requires an owned MitmSession",
        }
    started = session.start()
    result = session.to_status()
    result["ok"] = started
    return result


def wait_mitm_ready(
    session: MitmSession,
    *,
    timeout: float,
) -> dict[str, Any]:
    if not isinstance(session, MitmSession):
        return {
            "ok": False,
            "error_code": "mitm_session_required",
            "error": "wait_mitm_ready requires an owned MitmSession",
        }
    ready = session.wait_ready(timeout=timeout)
    result = session.to_status()
    result["ok"] = ready
    return result


def stop_mitm(
    session: MitmSession | None = None,
    *,
    timeout: float | None = None,
) -> dict[str, Any]:
    """Stop an explicit owner; a missing owner is a protected no-op error."""

    if not isinstance(session, MitmSession):
        return {
            "ok": False,
            "error_code": "mitm_session_required",
            "error": "stop_mitm requires an owned MitmSession",
        }
    stopped_cleanly = session.stop(timeout=timeout)
    result = session.to_status()
    result["ok"] = stopped_cleanly
    return result


def get_mitm_status(
    session: MitmSession | None = None,
    *,
    port: int = DEFAULT_MITM_PORT,
    host: str = "127.0.0.1",
) -> dict[str, Any]:
    """Return status without treating an arbitrary listener as this task."""

    if session is None:
        return {
            "has_last_session": False,
            "running": False,
            "owned_by_session": False,
            "pid": None,
            "port": port,
            "port_listening": check_port_listening(
                port=port,
                host=host,
            ),
            "traffic_dir": None,
            "traffic_dir_exists": False,
            "traffic_dir_writable": False,
            "flow_file": None,
            "flow_file_exists": False,
            "flow_file_size": 0,
            "jsonl_path": None,
            "jsonl_exists": False,
            "jsonl_size": 0,
            "stream_log": None,
            "stream_log_exists": False,
            "stream_log_size": 0,
            "last_error": None,
            "error_code": None,
            "started_at": None,
            "ready_at": None,
            "stopped_at": None,
        }

    process = session.process
    running = process is not None and process.poll() is None
    flow_exists = session.flow_path.is_file()
    jsonl_exists = session.jsonl_path.is_file()
    stderr_exists = session.stderr_path.is_file()
    status = session.to_status()
    return {
        "has_last_session": True,
        "running": running,
        "owned_by_session": True,
        "pid": process.pid if process is not None else None,
        "run_id": session.run_id,
        "session_id": session.session_id,
        "state": session.state.value,
        "port": session.listen_port,
        "port_listening": (
            check_port_listening(
                port=session.listen_port,
                host=session.listen_host,
            )
            if session.listen_port is not None
            else False
        ),
        "traffic_dir": str(session.traffic_dir),
        "traffic_dir_exists": session.traffic_dir.is_dir(),
        "traffic_dir_writable": _check_dir_writable(
            session.traffic_dir
        ),
        "flow_file": str(session.flow_path),
        "flow_file_exists": flow_exists,
        "flow_file_size": (
            session.flow_path.stat().st_size if flow_exists else 0
        ),
        "jsonl_path": str(session.jsonl_path),
        "jsonl_exists": jsonl_exists,
        "jsonl_size": (
            session.jsonl_path.stat().st_size if jsonl_exists else 0
        ),
        # Compatibility alias.  New collection does not parse this file.
        "stream_log": str(session.stderr_path),
        "stream_log_exists": stderr_exists,
        "stream_log_size": (
            session.stderr_path.stat().st_size if stderr_exists else 0
        ),
        "last_error": status["error"],
        "error_code": session.error_code,
        "started_at": status["started_at"],
        "ready_at": status["ready_at"],
        "stopped_at": status["stopped_at"],
    }


__all__ = [
    "MitmSession",
    "MitmSessionState",
    "PortPool",
    "check_port_listening",
    "create_mitm_session",
    "get_mitm_status",
    "start_mitm",
    "stop_mitm",
    "wait_mitm_ready",
]
