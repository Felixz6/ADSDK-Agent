"""Policy-aware Frida session wrapper with phase-accurate fallback evidence."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Callable, Mapping

from .execution_modes import DynamicModePolicy, ExecutionAttempt, ExecutionMode


def _utc_text(value: Any) -> str | None:
    if not isinstance(value, datetime):
        return None
    return value.astimezone(timezone.utc).isoformat(timespec="milliseconds").replace(
        "+00:00",
        "Z",
    )


class PolicyFridaSession:
    """Run a real Frida mode and retain phase evidence across fallback."""

    def __init__(
        self,
        *,
        policy: DynamicModePolicy,
        session_factory: Callable[[ExecutionMode], Any],
        launch_target: Callable[[], Mapping[str, Any] | None] | None = None,
    ) -> None:
        self.policy = policy
        self.session_factory = session_factory
        self.launch_target = launch_target
        self.active: Any | None = None
        self.sessions: list[Any] = []
        self.runtime_failure_sessions: list[Any] = []
        self.attempts: list[ExecutionAttempt] = []
        self.fallback_path: list[str] = []
        self.selected_mode = ExecutionMode.NONE
        self.error_code: str | None = None
        self.error_message: str | None = None
        self.launch_timing: dict[str, Any] = {}
        self.environment_capabilities: dict[str, bool | None] = {
            "transport_available": None,
            "process_enumeration_available": None,
            "attach_available": None,
            "spawn_creation_available": None,
            "spawn_resume_stable": None,
        }
        self._ready_args: tuple[Any, ...] = ()
        self._ready_kwargs: dict[str, Any] = {}

    def _modes(self) -> list[ExecutionMode]:
        if self.policy is DynamicModePolicy.STRICT:
            return [ExecutionMode.SPAWN_SUSPENDED]
        if self.policy is DynamicModePolicy.ATTACH_ONLY:
            return [ExecutionMode.ATTACH_EXISTING]
        return [
            ExecutionMode.SPAWN_SUSPENDED,
            ExecutionMode.LAUNCH_THEN_ATTACH,
        ]

    def _attempt_for(self, mode: ExecutionMode) -> ExecutionAttempt:
        for attempt in reversed(self.attempts):
            if attempt.mode is mode and attempt.status == "running":
                return attempt
        raise RuntimeError(f"missing active execution attempt: {mode.value}")

    def _enrich_launch_timing(self, session: Any) -> None:
        if self.selected_mode is not ExecutionMode.LAUNCH_THEN_ATTACH:
            return
        started = getattr(session, "attach_started_at", None)
        completed = getattr(session, "attach_completed_at", None)
        if started is not None:
            self.launch_timing["attach_started_at"] = _utc_text(started)
        if completed is not None:
            self.launch_timing["attach_completed_at"] = _utc_text(completed)
        requested = self.launch_timing.get("_launch_requested_datetime")
        if isinstance(requested, datetime) and isinstance(completed, datetime):
            self.launch_timing["startup_gap_ms"] = max(
                0,
                int((completed - requested).total_seconds() * 1000),
            )
        self.launch_timing.pop("_launch_requested_datetime", None)

    def _activate(self, mode: ExecutionMode) -> Any:
        launch_details: Mapping[str, Any] | None = None
        if mode is ExecutionMode.LAUNCH_THEN_ATTACH:
            if self.launch_target is None:
                raise RuntimeError("package_launch_failed")
            launch_details = self.launch_target()
            if launch_details:
                self.launch_timing.update(dict(launch_details))
        session = self.session_factory(mode)
        self.sessions.append(session)
        session.start()
        self.active = session
        self.selected_mode = mode
        self.error_code = None
        self.error_message = None
        if mode is ExecutionMode.SPAWN_SUSPENDED:
            self.environment_capabilities.update(
                {
                    "transport_available": True,
                    "attach_available": True,
                    "spawn_creation_available": True,
                }
            )
        else:
            self.environment_capabilities.update(
                {
                    "transport_available": True,
                    "process_enumeration_available": True,
                    "attach_available": True,
                }
            )
        self.attempts.append(
            ExecutionAttempt(
                mode=mode,
                status="running",
                phase="hook_loaded",
                message=f"{mode.value} 已完成进程选择、附加与 Hook 加载",
                timestamps=dict(self.launch_timing) if launch_details else {},
            )
        )
        self._enrich_launch_timing(session)
        if launch_details:
            self.attempts[-1].timestamps = dict(self.launch_timing)
        return session

    def start(self) -> "PolicyFridaSession":
        last_error: BaseException | None = None
        modes = self._modes()
        for index, mode in enumerate(modes):
            session: Any | None = None
            try:
                session = self._activate(mode)
            except BaseException as exc:
                if session is None and self.sessions:
                    session = self.sessions[-1]
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
                        phase="start",
                        reason_code=code,
                        message=f"{mode.value} 启动阶段失败，诊断证据已保留",
                    )
                )
                if session is not None:
                    try:
                        session.stop()
                    except BaseException:
                        pass
                if index + 1 < len(modes):
                    self.fallback_path.append(modes[index + 1].value)
                continue
            return self
        self.error_code = str(getattr(last_error, "code", None) or "spawn_failed")
        self.error_message = str(last_error or "no Frida execution mode is available")
        if last_error is not None:
            raise last_error
        raise RuntimeError(self.error_message)

    def wait_ready(self, *args: Any, **kwargs: Any) -> Any:
        assert self.active is not None
        self._ready_args = args
        self._ready_kwargs = dict(kwargs)
        try:
            result = self.active.wait_ready(*args, **kwargs)
        except BaseException as exc:
            attempt = self._attempt_for(self.selected_mode)
            attempt.status = "failed"
            attempt.phase = "hook_ready"
            attempt.reason_code = str(
                getattr(self.active, "error_code", None)
                or getattr(exc, "code", None)
                or "hook_ready_failed"
            )
            attempt.process_result = str(
                getattr(self.active, "error_code", None) or "process_exited"
            )
            attempt.crash = getattr(self.active, "crash", None)
            attempt.message = (
                f"{self.selected_mode.value} 在等待 Hook 就绪时结束"
            )
            self.error_code = attempt.reason_code
            self.error_message = str(exc)
            raise
        attempt = self._attempt_for(self.selected_mode)
        attempt.phase = "hook_ready"
        attempt.message = f"{self.selected_mode.value} Hook 已就绪"
        return result

    def resume(self) -> Any:
        assert self.active is not None
        try:
            result = self.active.resume()
        except BaseException as exc:
            attempt = self._attempt_for(self.selected_mode)
            attempt.status = "failed"
            attempt.phase = "resumed"
            attempt.reason_code = str(
                getattr(self.active, "error_code", None)
                or getattr(exc, "code", None)
                or "app_resume_failed"
            )
            attempt.process_result = str(
                getattr(self.active, "error_code", None) or "process_exited"
            )
            attempt.crash = getattr(self.active, "crash", None)
            attempt.message = f"{self.selected_mode.value} 恢复进程失败"
            self.error_code = attempt.reason_code
            self.error_message = str(exc)
            raise
        attempt = self._attempt_for(self.selected_mode)
        attempt.phase = "resumed"
        attempt.message = f"{self.selected_mode.value} 已恢复，正在等待稳定窗口"
        return result

    def _complete_active_attempt(self) -> None:
        attempt = self._attempt_for(self.selected_mode)
        attempt.status = "success"
        attempt.phase = "collecting"
        attempt.process_result = "running"
        attempt.post_resume_survival_ms = getattr(
            self.active,
            "post_resume_survival_ms",
            None,
        )
        attempt.message = f"{self.selected_mode.value} 已进入稳定采集"

    def _fail_runtime_attempt(self, exc: BaseException) -> None:
        assert self.active is not None
        attempt = self._attempt_for(self.selected_mode)
        attempt.status = "failed"
        attempt.phase = "post_resume_stability"
        attempt.reason_code = "spawn_runtime_failed"
        attempt.process_result = str(
            getattr(self.active, "error_code", None)
            or getattr(exc, "code", None)
            or "process_exited"
        )
        attempt.post_resume_survival_ms = getattr(
            self.active,
            "post_resume_survival_ms",
            None,
        )
        attempt.crash = getattr(self.active, "crash", None)
        attempt.message = (
            "spawn_suspended 已成功完成 resume，目标进程在稳定窗口内结束"
        )
        self.runtime_failure_sessions.append(self.active)
        self.environment_capabilities["spawn_resume_stable"] = False

    def wait_stable(self, timeout_seconds: float) -> bool:
        assert self.active is not None
        waiter = getattr(self.active, "wait_stable", None)
        try:
            if callable(waiter):
                stable = waiter(timeout_seconds)
                if stable is False:
                    raise RuntimeError("spawn_runtime_failed")
            self._complete_active_attempt()
            if self.selected_mode is ExecutionMode.SPAWN_SUSPENDED:
                self.environment_capabilities["spawn_resume_stable"] = True
            return True
        except BaseException as exc:
            failed_mode = self.selected_mode
            self._fail_runtime_attempt(exc)
            if (
                self.policy is not DynamicModePolicy.BALANCED
                or failed_mode is not ExecutionMode.SPAWN_SUSPENDED
            ):
                self.error_code = str(
                    getattr(self.active, "error_code", None)
                    or getattr(exc, "code", None)
                    or "process_exited"
                )
                self.error_message = str(exc)
                raise

            failed = self.active
            try:
                failed.stop()
            finally:
                self.fallback_path.append(ExecutionMode.LAUNCH_THEN_ATTACH.value)

            try:
                self._activate(ExecutionMode.LAUNCH_THEN_ATTACH)
                assert self.active is not None
                self.active.wait_ready(*self._ready_args, **self._ready_kwargs)
                attempt = self._attempt_for(self.selected_mode)
                attempt.phase = "hook_ready"
                self.active.resume()
                attempt.phase = "resumed"
                fallback_waiter = getattr(self.active, "wait_stable", None)
                if callable(fallback_waiter):
                    fallback_stable = fallback_waiter(timeout_seconds)
                    if fallback_stable is False:
                        raise RuntimeError("launch_then_attach_runtime_failed")
                self._complete_active_attempt()
                return True
            except BaseException as fallback_exc:
                attempt = self._attempt_for(ExecutionMode.LAUNCH_THEN_ATTACH)
                attempt.status = "failed"
                attempt.reason_code = str(
                    getattr(self.active, "error_code", None)
                    or getattr(fallback_exc, "code", None)
                    or "launch_then_attach_failed"
                )
                attempt.message = "launch_then_attach 降级尝试失败"
                self.error_code = attempt.reason_code
                self.error_message = str(fallback_exc)
                raise

    def stop(self, *args: Any, **kwargs: Any) -> Any:
        if not self.sessions:
            return True
        ok = True
        for session in reversed(self.sessions):
            try:
                ok = bool(session.stop(*args, **kwargs)) and ok
            except BaseException:
                ok = False
        return ok

    @property
    def valid_events(self) -> list[dict[str, Any]]:
        return [
            item
            for session in self.sessions
            for item in list(getattr(session, "valid_events", []))
        ]

    @property
    def control_events(self) -> list[dict[str, Any]]:
        return [
            item
            for session in self.sessions
            for item in list(getattr(session, "control_events", []))
        ]

    @property
    def valid_messages(self) -> list[dict[str, Any]]:
        return [
            item
            for session in self.sessions
            for item in list(getattr(session, "valid_messages", []))
        ]

    @property
    def protocol_errors(self) -> list[dict[str, Any]]:
        return [
            item
            for session in self.sessions
            for item in list(getattr(session, "protocol_errors", []))
        ]

    @property
    def cleanup_errors(self) -> list[str]:
        return [
            item
            for session in self.sessions
            for item in list(getattr(session, "cleanup_errors", []))
        ]

    def emit_collection_started(self) -> Any:
        assert self.active is not None
        return self.active.emit_collection_started()

    def emit_consent(self, *args: Any, **kwargs: Any) -> Any:
        assert self.active is not None
        return self.active.emit_consent(*args, **kwargs)

    def emit_control_event(self, *args: Any, **kwargs: Any) -> Any:
        assert self.active is not None
        return self.active.emit_control_event(*args, **kwargs)

    def to_status(self) -> dict[str, Any]:
        status = (
            dict(self.active.to_status())
            if self.active is not None and hasattr(self.active, "to_status")
            else {}
        )
        status.update(
            {
                "selected_mode": self.selected_mode.value,
                "attempts": [
                    item.model_dump(mode="json") for item in self.attempts
                ],
                "fallback_path": list(self.fallback_path),
                "environment_capabilities": dict(self.environment_capabilities),
                "launch_timing": dict(self.launch_timing),
            }
        )
        return status

    def __getattr__(self, name: str) -> Any:
        active = self.__dict__.get("active")
        if active is None:
            raise AttributeError(name)
        return getattr(active, name)
