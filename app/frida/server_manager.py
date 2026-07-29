"""Explicit, locally sourced and ownership-safe frida-server lifecycle."""

from __future__ import annotations

import hashlib
import os
import struct
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from app.core.device import DeviceContext
from app.tools.utils import run_cmd

from .errors import DynamicErrorCode
from .models import FridaServerActionResponse


class CommandRunner(Protocol):
    def __call__(
        self, command: list[str], cwd: str | None = None, timeout: int = 10
    ) -> dict[str, Any]: ...


@dataclass(frozen=True, slots=True)
class LocalServerBinary:
    path: Path
    size: int
    sha256: str
    architecture: str
    version: str | None


@dataclass(slots=True)
class OwnedServer:
    device_ref: str
    pid: int
    remote_path: str
    binary_sha256: str | None


class FridaServerManager:
    """Track only processes this manager started; never adopt unknown servers."""

    _ELF_MACHINE = {
        3: "x86",
        40: "armeabi-v7a",
        62: "x86_64",
        183: "arm64-v8a",
    }

    def __init__(
        self,
        *,
        enabled: bool,
        local_path: str,
        remote_path: str,
        start_timeout_seconds: float,
        handshake_timeout_seconds: float,
        command_runner: CommandRunner = run_cmd,
    ) -> None:
        self.enabled = enabled
        self.local_path = local_path
        self.remote_path = remote_path
        self.start_timeout_seconds = start_timeout_seconds
        self.handshake_timeout_seconds = handshake_timeout_seconds
        self.command_runner = command_runner
        self._owned: dict[str, OwnedServer] = {}
        self._lock = threading.RLock()

    def _run(self, command: list[str], *, timeout: float | None = None) -> dict[str, Any]:
        selected = max(1, int(timeout or self.start_timeout_seconds))
        try:
            return self.command_runner(command, timeout=selected)
        except TypeError:
            return self.command_runner(command)  # type: ignore[call-arg]

    @staticmethod
    def _response(
        action: str,
        device: DeviceContext,
        *,
        status: str,
        message: str,
        error_code: str | None = None,
        owned: bool = False,
        pid: int | None = None,
        details: dict[str, Any] | None = None,
    ) -> FridaServerActionResponse:
        return FridaServerActionResponse(
            action=action,  # type: ignore[arg-type]
            status=status,  # type: ignore[arg-type]
            error_code=error_code,
            message=message,
            device_ref=device.public_serial,
            owned=owned,
            pid=pid,
            details=details or {},
        )

    def _guard(
        self, action: str, device: DeviceContext, *, confirm: bool
    ) -> FridaServerActionResponse | None:
        if not self.enabled:
            return self._response(
                action,
                device,
                status="not_configured",
                message="自动管理未启用",
            )
        if not confirm:
            return self._response(
                action,
                device,
                status="blocked",
                error_code="confirmation_required",
                message="该操作需要明确确认",
            )
        return None

    def validate_local_binary(self) -> LocalServerBinary:
        path = Path(self.local_path).expanduser().resolve(strict=False)
        if not self.local_path or not path.is_file():
            raise ValueError(DynamicErrorCode.FRIDA_SERVER_BINARY_MISSING.value)
        if path.is_symlink():
            raise ValueError("frida_server_symlink_not_allowed")
        size = path.stat().st_size
        if not 1024 * 1024 <= size <= 256 * 1024 * 1024:
            raise ValueError("frida_server_size_invalid")
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            header = handle.read(20)
            digest.update(header)
            for chunk in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(chunk)
        if header[:4] != b"\x7fELF":
            raise ValueError("frida_server_not_elf")
        endian = "<" if header[5] == 1 else ">"
        machine = struct.unpack(f"{endian}H", header[18:20])[0]
        architecture = self._ELF_MACHINE.get(machine)
        if architecture is None:
            raise ValueError(DynamicErrorCode.FRIDA_SERVER_ABI_MISMATCH.value)
        version_result = self._run([str(path), "--version"], timeout=10)
        version = (
            str(version_result.get("stdout") or "").strip()
            if version_result.get("returncode") == 0
            else None
        )
        return LocalServerBinary(
            path=path,
            size=size,
            sha256=digest.hexdigest(),
            architecture=architecture,
            version=version,
        )

    def status(self, device: DeviceContext) -> FridaServerActionResponse:
        result = self._run(device.adb_command("shell", "pidof", "frida-server"))
        pids = [
            int(value)
            for value in str(result.get("stdout") or "").split()
            if value.isdigit()
        ]
        owned = self._owned.get(device.public_serial)
        owned_alive = bool(owned and owned.pid in pids)
        return self._response(
            "status",
            device,
            status="success" if pids else "failed",
            message="frida-server 正在运行" if pids else "未观察到 frida-server 进程",
            owned=owned_alive,
            pid=owned.pid if owned_alive else (pids[0] if pids else None),
            details={
                "process_count": len(pids),
                "ownership": "platform" if owned_alive else ("external" if pids else "none"),
            },
        )

    def deploy(
        self, device: DeviceContext, *, confirm: bool
    ) -> FridaServerActionResponse:
        guarded = self._guard("deploy", device, confirm=confirm)
        if guarded:
            return guarded
        try:
            binary = self.validate_local_binary()
        except ValueError as exc:
            code = str(exc)
            return self._response(
                "deploy",
                device,
                status="failed",
                error_code=code,
                message="本地 frida-server 校验失败",
            )
        abi_result = self._run(
            device.adb_command("shell", "getprop", "ro.product.cpu.abi")
        )
        abi = str(abi_result.get("stdout") or "").strip()
        if abi != binary.architecture:
            return self._response(
                "deploy",
                device,
                status="failed",
                error_code=DynamicErrorCode.FRIDA_SERVER_ABI_MISMATCH.value,
                message="本地服务文件架构与设备 ABI 不匹配",
                details={"device_abi": abi, "binary_architecture": binary.architecture},
            )
        existing = self._run(device.adb_command("shell", "test", "-e", self.remote_path))
        if existing.get("returncode") == 0:
            return self._response(
                "deploy",
                device,
                status="blocked",
                error_code="frida_server_existing_file_unowned",
                message="远端目标文件已存在，未覆盖未知来源文件",
            )
        temporary = f"{self.remote_path}.upload-{binary.sha256[:12]}"
        pushed = self._run(
            device.adb_command("push", str(binary.path), temporary),
            timeout=max(30, self.start_timeout_seconds),
        )
        if pushed.get("returncode") != 0:
            return self._response(
                "deploy",
                device,
                status="failed",
                error_code="frida_server_deploy_failed",
                message="服务文件上传失败",
            )
        remote_size = self._run(
            device.adb_command("shell", "stat", "-c", "%s", temporary)
        )
        if str(remote_size.get("stdout") or "").strip() != str(binary.size):
            self._run(device.adb_command("shell", "rm", "-f", temporary))
            return self._response(
                "deploy",
                device,
                status="failed",
                error_code="frida_server_upload_verification_failed",
                message="上传后的文件大小校验失败",
            )
        chmod = self._run(device.adb_command("shell", "chmod", "755", temporary))
        moved = self._run(device.adb_command("shell", "mv", temporary, self.remote_path))
        if chmod.get("returncode") != 0 or moved.get("returncode") != 0:
            self._run(device.adb_command("shell", "rm", "-f", temporary))
            return self._response(
                "deploy",
                device,
                status="failed",
                error_code="frida_server_deploy_finalize_failed",
                message="服务文件权限设置或原子替换失败",
            )
        return self._response(
            "deploy",
            device,
            status="success",
            message="已部署经过校验的本地 frida-server",
            details={
                "sha256": binary.sha256,
                "size": binary.size,
                "architecture": binary.architecture,
                "version": binary.version,
            },
        )

    def start(
        self, device: DeviceContext, *, confirm: bool
    ) -> FridaServerActionResponse:
        guarded = self._guard("start", device, confirm=confirm)
        if guarded:
            return guarded
        current = self.status(device)
        if current.pid is not None:
            return self._response(
                "start",
                device,
                status="blocked",
                error_code=DynamicErrorCode.FRIDA_SERVER_PORT_CONFLICT.value,
                message="已存在 frida-server 进程，未接管或终止",
                pid=current.pid,
                owned=current.owned,
            )
        exists = self._run(device.adb_command("shell", "test", "-x", self.remote_path))
        if exists.get("returncode") != 0:
            return self._response(
                "start",
                device,
                status="failed",
                error_code=DynamicErrorCode.FRIDA_SERVER_NOT_EXECUTABLE.value,
                message="已配置的设备端服务文件不存在或不可执行",
            )
        command = (
            f"{self.remote_path} >/data/local/tmp/adsdk-frida-server.log 2>&1 "
            "& echo $!"
        )
        started = self._run(
            device.adb_command("shell", "su", "-c", command),
            timeout=self.start_timeout_seconds,
        )
        pid_text = str(started.get("stdout") or "").strip().splitlines()
        pid = next((int(line) for line in reversed(pid_text) if line.strip().isdigit()), None)
        if started.get("timed_out"):
            code = DynamicErrorCode.FRIDA_SERVER_START_TIMEOUT.value
        else:
            code = DynamicErrorCode.FRIDA_SERVER_START_DENIED.value
        if started.get("returncode") != 0 or pid is None:
            return self._response(
                "start",
                device,
                status="failed",
                error_code=code,
                message="frida-server 启动失败",
            )
        alive = self._run(device.adb_command("shell", "kill", "-0", str(pid)))
        if alive.get("returncode") != 0:
            return self._response(
                "start",
                device,
                status="failed",
                error_code=DynamicErrorCode.FRIDA_SERVER_EXITED.value,
                message="frida-server 启动后快速退出",
                pid=pid,
            )
        with self._lock:
            self._owned[device.public_serial] = OwnedServer(
                device_ref=device.public_serial,
                pid=pid,
                remote_path=self.remote_path,
                binary_sha256=None,
            )
        return self._response(
            "start",
            device,
            status="success",
            message="frida-server 已启动并登记平台所有权",
            owned=True,
            pid=pid,
        )

    def stop(
        self, device: DeviceContext, *, confirm: bool
    ) -> FridaServerActionResponse:
        guarded = self._guard("stop", device, confirm=confirm)
        if guarded:
            return guarded
        with self._lock:
            owned = self._owned.get(device.public_serial)
        if owned is None:
            return self._response(
                "stop",
                device,
                status="not_owned",
                message="当前服务并非由平台启动，未执行停止",
            )
        stopped = self._run(
            device.adb_command("shell", "su", "-c", f"kill {owned.pid}")
        )
        if stopped.get("returncode") != 0:
            return self._response(
                "stop",
                device,
                status="failed",
                error_code=DynamicErrorCode.RESOURCE_CLEANUP_FAILED.value,
                message="平台拥有的 frida-server 停止失败",
                owned=True,
                pid=owned.pid,
            )
        with self._lock:
            self._owned.pop(device.public_serial, None)
        return self._response(
            "stop",
            device,
            status="success",
            message="已停止平台拥有的 frida-server",
            pid=owned.pid,
        )
