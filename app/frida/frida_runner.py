import subprocess
from typing import Any

from app.core.device import DeviceContext
from app.tools.utils import run_cmd


def check_frida_connection(device_id: str | None = None) -> dict[str, Any]:
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


def check_frida_device_runtime(device_id: str | None) -> dict[str, Any]:
    """Probe device ABI and an already-running frida-server without mutation."""

    if not device_id:
        return {
            "status": "device_not_selected",
            "server_running": False,
            "abi": None,
            "mode_hint": "select an exact device",
        }
    device = DeviceContext(serial=device_id)
    process_result = run_cmd(device.adb_command("shell", "ps", "-A"))
    abi_result = run_cmd(device.adb_command("shell", "getprop", "ro.product.cpu.abi"))
    process_names = []
    if process_result.get("returncode") == 0:
        process_names = [
            line.casefold() for line in str(process_result.get("stdout") or "").splitlines()
        ]
    server_running = any("frida-server" in line for line in process_names)
    abi = str(abi_result.get("stdout") or "").strip() if abi_result.get("returncode") == 0 else None
    return {
        "status": "server_available" if server_running else "server_not_observed",
        "server_running": server_running,
        "abi": abi or None,
        "mode_hint": (
            "exact-device frida-server transport"
            if server_running
            else "spawn requires a compatible running frida-server or Gadget"
        ),
    }
