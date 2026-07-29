"""Policy-aware Frida session wrapper with explicit fallback evidence."""

from __future__ import annotations

from typing import Any, Callable

from .execution_modes import DynamicModePolicy, ExecutionAttempt, ExecutionMode


class PolicyFridaSession:
    """Try only modes with real Frida semantics and retain every failed attempt."""

    def __init__(
        self,
        *,
        policy: DynamicModePolicy,
        session_factory: Callable[[ExecutionMode], Any],
        launch_target: Callable[[], None] | None = None,
    ) -> None:
        self.policy = policy
        self.session_factory = session_factory
        self.launch_target = launch_target
        self.active: Any | None = None
        self.attempts: list[ExecutionAttempt] = []
        self.fallback_path: list[str] = []
        self.selected_mode = ExecutionMode.NONE
        self.error_code: str | None = None
        self.error_message: str | None = None

    def _modes(self) -> list[ExecutionMode]:
        if self.policy is DynamicModePolicy.STRICT:
            return [ExecutionMode.SPAWN_SUSPENDED]
        if self.policy is DynamicModePolicy.ATTACH_ONLY:
            return [ExecutionMode.ATTACH_EXISTING]
        # Frida's spawn API is suspended by definition. A separate "spawn"
        # mode would be cosmetic, so balanced uses two real attach variants.
        return [
            ExecutionMode.SPAWN_SUSPENDED,
            ExecutionMode.ATTACH_EXISTING,
            ExecutionMode.LAUNCH_THEN_ATTACH,
        ]

    def start(self) -> "PolicyFridaSession":
        last_error: BaseException | None = None
        for index, mode in enumerate(self._modes()):
            session = self.session_factory(mode)
            try:
                if mode is ExecutionMode.LAUNCH_THEN_ATTACH:
                    if self.launch_target is None:
                        raise RuntimeError("package_launch_failed")
                    self.launch_target()
                session.start()
            except BaseException as exc:
                last_error = exc
                code = str(
                    getattr(session, "error_code", None)
                    or getattr(exc, "code", None)
                    or f"{mode.value}_failed"
                )
                self.attempts.append(
                    ExecutionAttempt(
                        mode=mode,
                        status="failed",
                        reason_code=code,
                        message=f"{mode.value} 失败，已保留诊断证据",
                    )
                )
                try:
                    session.stop()
                except BaseException:
                    pass
                if index + 1 < len(self._modes()):
                    self.fallback_path.append(self._modes()[index + 1].value)
                continue
            self.active = session
            self.selected_mode = mode
            self.attempts.append(
                ExecutionAttempt(
                    mode=mode,
                    status="success",
                    message=f"{mode.value} 已选定",
                )
            )
            return self
        self.error_code = str(getattr(last_error, "code", None) or "spawn_failed")
        self.error_message = str(last_error or "no Frida execution mode is available")
        if last_error is not None:
            raise last_error
        raise RuntimeError(self.error_message)

    def wait_ready(self, *args: Any, **kwargs: Any) -> Any:
        assert self.active is not None
        return self.active.wait_ready(*args, **kwargs)

    def resume(self) -> Any:
        assert self.active is not None
        return self.active.resume()

    def stop(self, *args: Any, **kwargs: Any) -> Any:
        if self.active is None:
            return True
        return self.active.stop(*args, **kwargs)

    def emit_collection_started(self) -> Any:
        assert self.active is not None
        return self.active.emit_collection_started()

    def emit_consent(self, *args: Any, **kwargs: Any) -> Any:
        assert self.active is not None
        return self.active.emit_consent(*args, **kwargs)

    def emit_control_event(self, *args: Any, **kwargs: Any) -> Any:
        assert self.active is not None
        return self.active.emit_control_event(*args, **kwargs)

    def __getattr__(self, name: str) -> Any:
        active = self.__dict__.get("active")
        if active is None:
            raise AttributeError(name)
        return getattr(active, name)
