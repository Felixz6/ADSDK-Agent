import os
import subprocess
from typing import Any, Dict

from app.core.device import DeviceContext

from .log_writer import append_log
from .utils import ensure_dir, now_iso


def spawn_and_inject(
    package_name: str,
    script_path: str,
    log_path: str,
    device_context: DeviceContext | None = None,
) -> Dict[str, Any]:
    """Historical entry point retained for injected compatibility fixtures.

    Real collection must use ``FridaSession`` so the target is spawned
    suspended and cannot resume before a validated Hook-ready message.
    """

    del package_name, script_path, device_context
    ensure_dir(os.path.dirname(log_path))
    error = "legacy Frida attach entry point is disabled; use FridaSession"
    append_log(log_path, f"[ERROR] {now_iso()} frida_legacy_attach_disabled")
    return {
        "ok": False,
        "error": error,
        "error_code": "frida_legacy_attach_disabled",
        "process": None,
        "log_file": None,
        "cmd": [],
    }


def check_frida_connection(device_id: str | None = None) -> Dict[str, Any]:
    cmd = ["frida-ps", "-U"]
    if device_id:
        cmd = ["frida-ps", "-D", device_id]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            shell=False,
            timeout=10,
        )
        return {
            "ok": result.returncode == 0,
            "returncode": result.returncode,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "cmd": cmd,
        }
    except Exception as e:
        return {
            "ok": False,
            "returncode": -1,
            "stdout": "",
            "stderr": str(e),
            "cmd": cmd,
        }
