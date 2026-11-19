"""Device and host process inspection and cleanup operations."""

from __future__ import annotations

import os
import sys
from typing import Any

from app.tools.utils import run_cmd


def _get_hook(name: str, fallback: Any) -> Any:
    main = sys.modules.get("app.main")
    if main is not None and hasattr(main, name):
        return getattr(main, name)
    return fallback


def adb_cleanup_action(device: str, args: list[str]) -> bool:
    cmd_fn = _get_hook("run_cmd", run_cmd)
    return cmd_fn(["adb", "-s", device, *args]).get("returncode") == 0


_adb_cleanup_action = adb_cleanup_action


def stop_owned_host_pid(pid: int) -> bool:
    if pid <= 0:
        return False
    cmd_fn = _get_hook("run_cmd", run_cmd)
    if os.name == "nt":
        return cmd_fn(["taskkill", "/PID", str(pid)]).get("returncode") == 0
    try:
        os.kill(pid, 15)
    except OSError:
        return False
    return True


_stop_owned_host_pid = stop_owned_host_pid


def read_device_proxy(device: str) -> str | None:
    cmd_fn = _get_hook("run_cmd", run_cmd)
    result = cmd_fn(
        ["adb", "-s", device, "shell", "settings", "get", "global", "http_proxy"]
    )
    if result.get("returncode") != 0:
        return None
    value = str(result.get("stdout") or "").strip()
    return "" if value in {"", ":0", ":null", "null"} else value


_read_device_proxy = read_device_proxy


def device_process_command(device: str, pid: int) -> str | None:
    if not device or pid <= 0:
        return None
    cmd_fn = _get_hook("run_cmd", run_cmd)
    result = cmd_fn(
        ["adb", "-s", device, "shell", "cat", f"/proc/{pid}/cmdline"]
    )
    if result.get("returncode") != 0:
        return None
    return str(result.get("stdout") or "").replace("\x00", " ").strip() or None


_device_process_command = device_process_command


def device_package_pids(device: str, package_name: str) -> list[int] | None:
    """Return every live package PID; ``None`` means the probe itself failed."""
    if not device or not package_name:
        return None
    cmd_fn = _get_hook("run_cmd", run_cmd)
    result = cmd_fn(
        ["adb", "-s", device, "shell", "pidof", package_name]
    )
    stdout = str(result.get("stdout") or "").strip()
    stderr = str(result.get("stderr") or "").strip()
    if result.get("returncode") != 0 and stderr:
        return None
    return [
        int(value)
        for value in stdout.split()
        if value.isdigit() and int(value) > 0
    ]


_device_package_pids = device_package_pids


def host_process_command(pid: int) -> str | None:
    if pid <= 0:
        return None
    cmd_fn = _get_hook("run_cmd", run_cmd)
    if os.name == "nt":
        command = (
            "$p=Get-CimInstance Win32_Process -Filter 'ProcessId = "
            f"{pid}' -ErrorAction SilentlyContinue; if ($p) {{ $p.CommandLine }}"
        )
        result = cmd_fn(["powershell.exe", "-NoProfile", "-Command", command])
    else:
        result = cmd_fn(["cat", f"/proc/{pid}/cmdline"])
    if result.get("returncode") != 0:
        return None
    return str(result.get("stdout") or "").replace("\x00", " ").strip() or None


_host_process_command = host_process_command


__all__ = [
    "_adb_cleanup_action",
    "_device_package_pids",
    "_device_process_command",
    "_host_process_command",
    "_read_device_proxy",
    "_stop_owned_host_pid",
    "adb_cleanup_action",
    "device_package_pids",
    "device_process_command",
    "host_process_command",
    "read_device_proxy",
    "stop_owned_host_pid",
]
