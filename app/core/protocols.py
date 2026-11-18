"""Shared structural protocols for injected side effects."""

from __future__ import annotations

from typing import Any, Protocol


class CommandRunner(Protocol):
    """Run a command and return the normalized runner result payload."""

    def __call__(
        self,
        command: list[str],
        cwd: str | None = None,
        timeout: int = 10,
    ) -> dict[str, Any]: ...


class CleanupActionProtocol(Protocol):
    """Device/process cleanup operations shared by orchestration layers."""

    def set_proxy(self, device: str, value: str) -> bool: ...

    def delete_proxy(self, device: str) -> bool: ...

    def kill_pid(self, device: str, pid: int) -> bool: ...

    def stop_mitm_pid(self, pid: int) -> bool: ...

    def stop_frida_session(self, ref: str) -> bool: ...


__all__ = ["CleanupActionProtocol", "CommandRunner"]
