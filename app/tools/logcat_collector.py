"""Small, bounded and redacted logcat snapshot for one dynamic task."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol

from app.core.artifacts import atomic_write_json, atomic_write_text
from app.core.device import DeviceContext
from app.tools.utils import run_cmd


class CommandRunner(Protocol):
    def __call__(
        self, command: list[str], cwd: str | None = None, timeout: int = 10
    ) -> dict[str, Any]: ...


class LogcatCollector:
    def __init__(
        self,
        *,
        device: DeviceContext,
        package_name: str,
        output_dir: Path,
        command_runner: CommandRunner = run_cmd,
        max_lines: int = 200,
        max_bytes: int = 64 * 1024,
        timeout_seconds: int = 10,
    ) -> None:
        self.device = device
        self.package_name = package_name
        self.output_dir = Path(output_dir)
        self.command_runner = command_runner
        self.max_lines = max_lines
        self.max_bytes = max_bytes
        self.timeout_seconds = timeout_seconds

    def collect(self, *, pid: int | None) -> dict[str, Any]:
        command = self.device.adb_command("logcat", "-d", "-t", str(self.max_lines * 3))
        try:
            result = self.command_runner(command, timeout=self.timeout_seconds)
        except TypeError:
            result = self.command_runner(command)  # type: ignore[call-arg]
        raw_lines = str(result.get("stdout") or "").splitlines()
        pid_text = str(pid) if pid else None
        selected = [
            line
            for line in raw_lines
            if self.package_name in line
            or (pid_text is not None and pid_text in line)
            or any(
                marker in line
                for marker in (
                    "FATAL EXCEPTION",
                    "Fatal signal",
                    "tombstone",
                    "Force stopping",
                )
            )
        ][-self.max_lines :]
        redacted = [
            self.device.redactor.redact_text(
                line, {"device_serial": self.device.serial}
            )
            or ""
            for line in selected
        ]
        text = "\n".join(redacted)
        encoded = text.encode("utf-8")
        if len(encoded) > self.max_bytes:
            text = encoded[-self.max_bytes :].decode("utf-8", errors="replace")
            redacted = text.splitlines()
        self.output_dir.mkdir(parents=True, exist_ok=True)
        tail_path = self.output_dir / "logcat-tail.txt"
        summary_path = self.output_dir / "logcat-summary.json"
        atomic_write_text(tail_path, text + ("\n" if text else ""))
        summary = {
            "schema_version": "logcat-summary-v1",
            "status": "success" if result.get("returncode") == 0 else "failed",
            "line_count": len(redacted),
            "truncated": len(selected) > len(redacted),
            "max_lines": self.max_lines,
            "max_bytes": self.max_bytes,
            "signals": {
                "java_fatal": any("FATAL EXCEPTION" in line for line in redacted),
                "native_crash": any("Fatal signal" in line for line in redacted),
                "tombstone": any("tombstone" in line.casefold() for line in redacted),
                "force_stop": any("Force stopping" in line for line in redacted),
            },
            "artifact": "dynamic/logcat-tail.txt",
        }
        atomic_write_json(summary_path, summary)
        return {"summary": summary, "lines": redacted}
