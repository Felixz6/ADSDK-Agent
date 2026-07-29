"""Read-only, exact-device Frida environment diagnostics."""

from __future__ import annotations

import importlib
import platform
import shutil
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Protocol

from app.core.device import DeviceContext
from app.tools.utils import run_cmd

from .errors import DynamicErrorCode
from .models import (
    DiagnosticCheck,
    DiagnosticIssue,
    DiagnosticSection,
    FridaEnvironmentCapabilities,
    FridaDiagnosticsRequest,
    FridaDiagnosticsResponse,
)


class CommandRunner(Protocol):
    def __call__(
        self, command: list[str], cwd: str | None = None, timeout: int = 10
    ) -> dict[str, Any]: ...


def _utc_text() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z"
    )


def _major(version: str | None) -> str | None:
    if not version:
        return None
    head = version.strip().split(".", 1)[0]
    return head if head.isdigit() else None


class FridaDiagnosticsService:
    """Layered diagnostics with no deployment, start, stop or download side effects."""

    def __init__(
        self,
        *,
        project_root: Path,
        server_remote_path: str,
        management_enabled: bool = False,
        command_runner: CommandRunner = run_cmd,
        module_loader: Callable[[str], Any] = importlib.import_module,
        which: Callable[[str], str | None] = shutil.which,
        monotonic: Callable[[], float] = time.monotonic,
    ) -> None:
        self.project_root = Path(project_root).resolve()
        self.server_remote_path = server_remote_path
        self.management_enabled = management_enabled
        self.command_runner = command_runner
        self.module_loader = module_loader
        self.which = which
        self.monotonic = monotonic

    def _run(self, command: list[str], *, timeout: int = 10) -> dict[str, Any]:
        try:
            return self.command_runner(command, timeout=timeout)
        except TypeError:
            return self.command_runner(command)  # type: ignore[call-arg]

    @staticmethod
    def _check(
        *,
        status: str,
        message: str,
        detected: Any = None,
        expected: Any = None,
        error_code: str | None = None,
        remediation: str | None = None,
        evidence: dict[str, Any] | None = None,
    ) -> DiagnosticCheck:
        return DiagnosticCheck(
            status=status,  # type: ignore[arg-type]
            detected_value=detected,
            expected_value=expected,
            error_code=error_code,
            message=message,
            remediation=remediation,
            evidence=evidence or {},
        )

    @staticmethod
    def _section(checks: dict[str, DiagnosticCheck]) -> DiagnosticSection:
        statuses = {check.status for check in checks.values()}
        if "error" in statuses:
            status = "error"
        elif statuses & {"warning", "unknown"}:
            status = "warning"
        elif statuses == {"not_configured"}:
            status = "not_configured"
        else:
            status = "pass"
        return DiagnosticSection(status=status, checks=checks)  # type: ignore[arg-type]

    def _host(self) -> tuple[DiagnosticSection, str | None, list[DiagnosticIssue]]:
        checks: dict[str, DiagnosticCheck] = {}
        issues: list[DiagnosticIssue] = []
        expected_python = (self.project_root / ".venv" / "Scripts" / "python.exe").resolve()
        executable = Path(sys.executable).resolve()
        in_project_venv = executable == expected_python
        checks["python_executable"] = self._check(
            status="pass" if in_project_venv else "error",
            detected=str(executable),
            expected=str(expected_python),
            error_code=None if in_project_venv else DynamicErrorCode.HOST_FRIDA_MISSING.value,
            message="正在使用项目虚拟环境" if in_project_venv else "当前 Python 不是项目 .venv",
            remediation="使用 .venv\\Scripts\\python.exe 启动后端",
        )
        checks["host_architecture"] = self._check(
            status="pass",
            detected=platform.machine(),
            expected="host architecture detected",
            message="已识别主机架构",
        )
        checks["subprocess"] = self._check(
            status="pass",
            detected="shell=false",
            expected="shell=false with bounded timeout",
            message="子进程采用参数列表和超时控制",
        )

        binding_version: str | None = None
        frida_module: Any = None
        try:
            frida_module = self.module_loader("frida")
            binding_version = str(getattr(frida_module, "__version__", "") or "") or None
            checks["python_binding"] = self._check(
                status="pass" if binding_version else "warning",
                detected=binding_version,
                expected="importable project .venv binding",
                error_code=(
                    None
                    if binding_version
                    else DynamicErrorCode.HOST_FRIDA_VERSION_UNKNOWN.value
                ),
                message="Frida Python 组件可导入",
            )
        except ModuleNotFoundError:
            checks["python_binding"] = self._check(
                status="error",
                error_code=DynamicErrorCode.HOST_FRIDA_MISSING.value,
                message="项目虚拟环境未安装 Frida Python 组件",
                remediation="在项目 .venv 中安装与设备端匹配的 Frida 版本",
            )
        except Exception as exc:
            checks["python_binding"] = self._check(
                status="error",
                error_code=DynamicErrorCode.HOST_FRIDA_IMPORT_FAILED.value,
                message=f"Frida Python 组件导入失败: {type(exc).__name__}",
                remediation="检查项目 .venv 的 Frida 安装与本机运行库",
            )

        scripts = self.project_root / ".venv" / "Scripts"
        versions: dict[str, str | None] = {}
        for name, filename in (("frida_cli", "frida.exe"), ("frida_ps", "frida-ps.exe")):
            path = scripts / filename
            if not path.is_file():
                checks[name] = self._check(
                    status="error",
                    detected=None,
                    expected=str(path),
                    error_code=DynamicErrorCode.HOST_FRIDA_CLI_MISSING.value,
                    message=f"项目 .venv 中未找到 {filename}",
                    remediation="在项目 .venv 中安装 frida-tools",
                    evidence={"global_candidate_ignored": self.which(filename[:-4])},
                )
                versions[name] = None
                continue
            result = self._run([str(path), "--version"], timeout=10)
            version = (
                str(result.get("stdout") or "").strip()
                if result.get("returncode") == 0
                else None
            )
            versions[name] = version
            checks[name] = self._check(
                status="pass" if version else "warning",
                detected={"path": str(path), "version": version},
                expected="project .venv executable",
                error_code=(
                    None if version else DynamicErrorCode.HOST_FRIDA_VERSION_UNKNOWN.value
                ),
                message=f"{filename} 已检测" if version else f"{filename} 版本读取失败",
                evidence={
                    "returncode": result.get("returncode"),
                    "timed_out": bool(result.get("timed_out")),
                },
            )

        cli_version = versions.get("frida_cli")
        if binding_version and cli_version and _major(binding_version) != _major(cli_version):
            checks["component_compatibility"] = self._check(
                status="error",
                detected={"binding": binding_version, "cli": cli_version},
                expected="matching major versions",
                error_code=DynamicErrorCode.HOST_FRIDA_COMPONENT_MISMATCH.value,
                message="Frida Python 与 CLI 主版本不一致",
                remediation="在项目 .venv 内统一 Frida 组件版本",
            )
        else:
            checks["component_compatibility"] = self._check(
                status="pass" if binding_version and cli_version else "unknown",
                detected={"binding": binding_version, "cli": cli_version},
                expected="matching versions",
                message="主机 Frida 组件版本兼容" if binding_version and cli_version else "主机组件版本尚不完整",
            )
        return self._section(checks), binding_version, issues

    def _device(
        self, request: FridaDiagnosticsRequest, device: DeviceContext
    ) -> tuple[DiagnosticSection, dict[str, Any]]:
        commands: dict[str, tuple[str, ...]] = {
            "state": ("get-state",),
            "abi": ("shell", "getprop", "ro.product.cpu.abi"),
            "android": ("shell", "getprop", "ro.build.version.release"),
            "api_level": ("shell", "getprop", "ro.build.version.sdk"),
            "manufacturer": ("shell", "getprop", "ro.product.manufacturer"),
            "model": ("shell", "getprop", "ro.product.model"),
            "selinux": ("shell", "getenforce"),
            "shell_identity": ("shell", "id"),
            "su_identity": ("shell", "su", "-c", "id"),
            "remote_writable": ("shell", "test", "-w", "/data/local/tmp"),
            "storage": ("shell", "df", "-k", "/data/local/tmp"),
            "device_time": ("shell", "date", "+%s"),
            "proxy": ("shell", "settings", "get", "global", "http_proxy"),
        }
        results = {
            name: self._run(device.adb_command(*args), timeout=10)
            for name, args in commands.items()
        }
        state_result = results["state"]
        state_text = str(state_result.get("stdout") or state_result.get("stderr") or "").strip()
        state_code: str | None = None
        if "unauthorized" in state_text.casefold():
            state_code = DynamicErrorCode.DEVICE_UNAUTHORIZED.value
        elif "offline" in state_text.casefold():
            state_code = DynamicErrorCode.DEVICE_OFFLINE.value
        elif state_result.get("returncode") != 0 or state_text != "device":
            state_code = DynamicErrorCode.DEVICE_NOT_FOUND.value
        checks: dict[str, DiagnosticCheck] = {
            "adb_state": self._check(
                status="pass" if state_code is None else "error",
                detected=state_text or None,
                expected="device",
                error_code=state_code,
                message="指定设备在线" if state_code is None else "指定设备连接状态异常",
                remediation="确认设备在线、ADB 已授权并继续使用同一设备引用",
                evidence={"returncode": state_result.get("returncode")},
            )
        }
        for name in (
            "abi", "android", "api_level", "manufacturer", "model", "selinux",
            "shell_identity", "storage", "device_time", "proxy",
        ):
            result = results[name]
            ok = result.get("returncode") == 0
            checks[name] = self._check(
                status="pass" if ok else "unknown",
                detected=str(result.get("stdout") or "").strip() or None,
                expected="command succeeds",
                error_code=None if ok else DynamicErrorCode.DEVICE_COMMAND_FAILED.value,
                message=f"{name} 已读取" if ok else f"{name} 读取失败",
                evidence={
                    "returncode": result.get("returncode"),
                    "timed_out": bool(result.get("timed_out")),
                },
            )
        su_ok = results["su_identity"].get("returncode") == 0 and "uid=0" in str(
            results["su_identity"].get("stdout") or ""
        )
        checks["su"] = self._check(
            status="pass" if su_ok else "warning",
            detected=str(results["su_identity"].get("stdout") or "").strip() or None,
            expected="uid=0",
            error_code=None if su_ok else DynamicErrorCode.ROOT_UNAVAILABLE.value,
            message="su 可用" if su_ok else "su 不可用或未授予 root",
            remediation="需要管理 frida-server 时授予明确的 root 权限",
        )
        writable = results["remote_writable"].get("returncode") == 0
        checks["remote_directory"] = self._check(
            status="pass" if writable else "warning",
            detected="/data/local/tmp",
            expected="writable",
            error_code=None if writable else DynamicErrorCode.REMOTE_DIRECTORY_UNWRITABLE.value,
            message="远端临时目录可写" if writable else "远端临时目录不可写",
        )
        return self._section(checks), results

    def _server(
        self,
        device: DeviceContext,
        binding_version: str | None,
        device_results: dict[str, Any],
    ) -> tuple[DiagnosticSection, str | None]:
        path = self.server_remote_path
        commands = {
            "file": device.adb_command("shell", "ls", "-l", path),
            "version": device.adb_command("shell", path, "--version"),
            "process": device.adb_command("shell", "pidof", "frida-server"),
            "port": device.adb_command("shell", "sh", "-c", "netstat -lnt 2>/dev/null | grep ':27042 '"),
            "hash": device.adb_command("shell", "sha256sum", path),
        }
        results = {name: self._run(command, timeout=10) for name, command in commands.items()}
        exists = results["file"].get("returncode") == 0
        server_version = (
            str(results["version"].get("stdout") or "").strip()
            if results["version"].get("returncode") == 0
            else None
        )
        file_text = str(results["file"].get("stdout") or "")
        executable = exists and len(file_text) >= 4 and "x" in file_text[:10]
        device_abi = str(device_results["abi"].get("stdout") or "").strip()
        process_text = str(results["process"].get("stdout") or "").strip()
        process_running = (
            results["process"].get("returncode") == 0 and bool(process_text)
        )
        checks: dict[str, DiagnosticCheck] = {
            "configured_path": self._check(
                status="pass",
                detected=path,
                expected="/data/local/tmp/frida-server",
                message="已读取配置的远端服务路径",
            ),
            "binary": self._check(
                status="pass" if exists else "warning",
                detected={"exists": exists, "executable": executable},
                expected="regular executable file",
                error_code=(
                    None if exists else DynamicErrorCode.FRIDA_SERVER_BINARY_MISSING.value
                ),
                message="设备端服务文件存在" if exists else "设备端服务文件缺失",
                remediation="配置本地可信文件后，由用户显式发起部署",
                evidence={
                    "returncode": results["file"].get("returncode"),
                    "sha256": str(results["hash"].get("stdout") or "").split(" ", 1)[0] or None,
                },
            ),
            "executable": self._check(
                status="pass" if executable else ("warning" if exists else "unknown"),
                detected=executable if exists else None,
                expected=True,
                error_code=(
                    DynamicErrorCode.FRIDA_SERVER_NOT_EXECUTABLE.value
                    if exists and not executable
                    else None
                ),
                message="服务文件具有执行权限" if executable else "服务文件执行权限尚未满足",
            ),
            "version": self._check(
                status="pass" if server_version else "unknown",
                detected=server_version,
                expected=binding_version,
                error_code=(
                    DynamicErrorCode.FRIDA_SERVER_VERSION_MISMATCH.value
                    if server_version and binding_version and _major(server_version) != _major(binding_version)
                    else None
                ),
                message="已读取设备端服务版本" if server_version else "设备端服务版本不可读",
            ),
            "abi": self._check(
                status="pass" if device_abi else "unknown",
                detected=device_abi or None,
                expected="server ELF architecture matches device ABI",
                message="设备 ABI 已用于服务兼容性判断" if device_abi else "设备 ABI 不可用",
            ),
            "process": self._check(
                status="pass" if process_running else "warning",
                detected=process_text or None,
                expected="running PID",
                message="已观察到 frida-server 进程" if process_running else "未观察到 frida-server 进程",
            ),
            "listen_port": self._check(
                status="pass" if results["port"].get("returncode") == 0 else "unknown",
                detected="27042" if results["port"].get("returncode") == 0 else None,
                expected="27042 listening",
                message="服务端口正在监听" if results["port"].get("returncode") == 0 else "服务端口监听状态未知",
            ),
        }
        return self._section(checks), server_version

    def _transport(
        self,
        request: FridaDiagnosticsRequest,
        device: DeviceContext,
        binding_version: str | None,
    ) -> DiagnosticSection:
        started = self.monotonic()
        try:
            module = self.module_loader("frida")
            manager = module.get_device_manager()
            target = manager.get_device(device.serial, timeout=10_000)
            processes = target.enumerate_processes()
            elapsed = int((self.monotonic() - started) * 1000)
            return self._section(
                {
                    "handshake": self._check(
                        status="pass",
                        detected={"process_count": len(processes), "duration_ms": elapsed},
                        expected="exact-device Python API handshake",
                        message="Frida Python API 已与指定设备完成握手",
                        evidence={"binding_version": binding_version},
                    )
                }
            )
        except Exception as exc:
            elapsed = int((self.monotonic() - started) * 1000)
            return self._section(
                {
                    "handshake": self._check(
                        status="error",
                        detected={"exception": type(exc).__name__, "duration_ms": elapsed},
                        expected="exact-device Python API handshake",
                        error_code=DynamicErrorCode.FRIDA_SERVER_TRANSPORT_UNREACHABLE.value,
                        message="无法与设备端 Frida 服务建立连接",
                        remediation="检查服务进程、版本、权限与 27042 端口",
                        evidence={"exception_type": type(exc).__name__},
                    )
                }
            )

    def _target(
        self, request: FridaDiagnosticsRequest, device: DeviceContext
    ) -> DiagnosticSection:
        if not request.package_name:
            return DiagnosticSection(
                status="unknown",
                checks={
                    "package": self._check(
                        status="unknown",
                        message="未提供目标包名，跳过目标应用诊断",
                    )
                },
            )
        installed = self._run(
            device.adb_command("shell", "pm", "path", request.package_name), timeout=10
        )
        pid = self._run(
            device.adb_command("shell", "pidof", request.package_name), timeout=10
        )
        pid_text = str(pid.get("stdout") or "").strip()
        process_running = pid.get("returncode") == 0 and bool(pid_text)
        present = installed.get("returncode") == 0 and "package:" in str(
            installed.get("stdout") or ""
        )
        return self._section(
            {
                "package_installed": self._check(
                    status="pass" if present else "error",
                    detected=request.package_name if present else None,
                    expected="installed package",
                    error_code=None if present else DynamicErrorCode.PACKAGE_NOT_INSTALLED.value,
                    message="目标应用已安装" if present else "目标应用未安装",
                ),
                "process": self._check(
                    status="pass" if process_running else "warning",
                    detected=pid_text or None,
                    expected="PID when attach mode is requested",
                    error_code=(
                        None
                        if process_running
                        else DynamicErrorCode.PACKAGE_PROCESS_NOT_FOUND.value
                    ),
                    message="目标进程正在运行" if process_running else "目标进程当前未运行",
                ),
            }
        )

    def diagnose(self, request: FridaDiagnosticsRequest) -> FridaDiagnosticsResponse:
        started = self.monotonic()
        device = DeviceContext(serial=request.device_id)
        host, binding_version, issues = self._host()
        device_section, device_results = self._device(request, device)
        server, server_version = self._server(device, binding_version, device_results)
        transport = self._transport(request, device, binding_version)
        target = self._target(request, device)

        all_checks = [
            *host.checks.values(),
            *device_section.checks.values(),
            *server.checks.values(),
            *transport.checks.values(),
            *target.checks.values(),
        ]
        for check in all_checks:
            if not check.error_code:
                continue
            severity = "blocking" if check.status == "error" else "warning"
            issues.append(
                DiagnosticIssue(
                    code=check.error_code,
                    severity=severity,
                    summary=check.message,
                    detail=check.message,
                    remediation=check.remediation or "查看诊断详情并按层排查",
                    evidence_available=bool(check.evidence),
                )
            )
        blocking = any(issue.severity == "blocking" for issue in issues)
        handshake_ok = transport.checks["handshake"].status == "pass"
        host_ok = host.status == "pass"
        device_ok = device_section.checks["adb_state"].status == "pass"
        server_running = (
            server.checks["process"].status == "pass"
            or server.checks["listen_port"].status == "pass"
            or handshake_ok
        )
        target_installed = target.checks.get("package_installed")
        target_process = target.checks.get("process")
        if handshake_ok and host_ok and device_ok and server_running:
            overall = "ready"
            recommended = "spawn_suspended"
        elif handshake_ok and host_ok and device_ok and not blocking:
            overall = "degraded"
            if target_process and target_process.status == "pass":
                recommended = "attach_existing"
            elif target_installed and target_installed.status == "pass":
                recommended = "launch_then_attach"
            else:
                recommended = "none"
        elif device_ok and not blocking:
            overall = "degraded"
            recommended = "attach_existing" if request.package_name else "none"
        elif blocking:
            overall = "blocked"
            recommended = "none"
        else:
            overall = "error"
            recommended = "none"
        remediations = list(
            dict.fromkeys(issue.remediation for issue in issues if issue.remediation)
        )
        if not self.management_enabled:
            remediations.insert(0, "自动管理未启用；诊断保持只读")
        return FridaDiagnosticsResponse(
            overall_status=overall,  # type: ignore[arg-type]
            recommended_mode=recommended,  # type: ignore[arg-type]
            host=host,
            device=device_section,
            server=server,
            transport=transport,
            target=target,
            issues=issues,
            remediations=remediations,
            checked_at=_utc_text(),
            duration_ms=max(0, int((self.monotonic() - started) * 1000)),
            device_ref=device.public_serial,
            management_enabled=self.management_enabled,
            capabilities=FridaEnvironmentCapabilities(
                transport_available=handshake_ok,
                process_enumeration_available=handshake_ok,
                attach_available=(
                    handshake_ok
                    and target_process is not None
                    and target_process.status == "pass"
                ),
            ),
        )
