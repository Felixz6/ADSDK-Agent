from app.core.device import DeviceContext

from .utils import run_cmd


def adb_devices():
    return run_cmd(["adb", "devices"])


class DeviceSelectionError(RuntimeError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def install_apk(apk_path: str, device_context: DeviceContext | None = None):
    cmd = (
        device_context.adb_command("install", "-r", apk_path)
        if device_context
        else ["adb", "install", "-r", apk_path]
    )
    return run_cmd(cmd)


def launch_app(package_name: str, device_context: DeviceContext | None = None):
    cmd = (
        device_context.adb_command("shell", "monkey", "-p", package_name, "1")
        if device_context
        else ["adb", "shell", "monkey", "-p", package_name, "1"]
    )
    return run_cmd(cmd)


def current_focus():
    # shell=False 下不能用 "|" / "findstr" 串管道——它们会被当作 adb 的字面参数。
    # 直接 dump 全量 window 状态,在 Python 侧过滤 mCurrentFocus,跨设备 shell 更稳。
    result = run_cmd(["adb", "shell", "dumpsys", "window"])
    if result["returncode"] != 0:
        return result
    lines = [
        line for line in result["stdout"].splitlines()
        if "mCurrentFocus" in line
    ]
    result["stdout"] = "\n".join(lines)
    return result


def adb_version():
    return run_cmd(["adb", "version"])


def parse_adb_devices_output(text: str) -> list[dict]:
    devices = []
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or line.startswith("List of devices attached"):
            continue
        if "\t" in line:
            serial, status = line.split("\t", 1)
            devices.append({"device_id": serial.strip(), "status": status.strip()})
    return devices


def check_adb_available() -> dict:
    result = adb_version()
    ok = result["returncode"] == 0
    return {
        "ok": ok,
        "stdout": result["stdout"],
        "stderr": result["stderr"],
        "cmd": result["cmd"],
    }


def check_device_online(device_id: str | None = None) -> dict:
    result = adb_devices()
    devices = parse_adb_devices_output(result.get("stdout", ""))
    online_devices = [d for d in devices if d.get("status") == "device"]

    if device_id:
        target = next((d for d in devices if d.get("device_id") == device_id), None)
        return {
            "ok": target is not None and target.get("status") == "device",
            "device_id": device_id,
            "target": target,
            "devices": devices,
            "online_count": len(online_devices),
        }

    return {
        "ok": len(online_devices) > 0,
        "device_id": None,
        "target": online_devices[0] if online_devices else None,
        "devices": devices,
        "online_count": len(online_devices),
    }


def select_device_context(device_id: str | None = None) -> DeviceContext:
    result = adb_devices()
    if result.get("returncode") != 0:
        raise DeviceSelectionError(
            "adb_devices_failed",
            result.get("stderr") or "adb devices failed",
        )

    devices = parse_adb_devices_output(result.get("stdout", ""))
    online = [item for item in devices if item.get("status") == "device"]

    if device_id:
        target = next(
            (item for item in online if item.get("device_id") == device_id),
            None,
        )
        if target is None:
            raise DeviceSelectionError(
                "device_not_online",
                "requested device is missing, offline, or unauthorized",
            )
        return DeviceContext(serial=device_id)

    if not online:
        raise DeviceSelectionError("no_online_device", "no online ADB device found")
    if len(online) > 1:
        raise DeviceSelectionError(
            "multiple_devices",
            "multiple online devices found; device_id is required",
        )
    return DeviceContext(serial=str(online[0]["device_id"]))
