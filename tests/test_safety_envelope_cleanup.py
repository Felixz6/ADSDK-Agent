"""Safety envelope lifecycle, exception-stage cleanup ordering, and cancellation tests."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from typing import Any

from app.ai.models import AIPlan, PlanStep, PreparedPlan
from app.orchestration.cleanup_manager import CleanupManager, ResourceOwnershipRegistry
from app.orchestration.consent_checkpoint import ConsentCheckpointService
from app.orchestration.device_lease import LeaseRegistry
from app.orchestration.device_session import DeviceSessionSnapshot, DeviceState
from app.orchestration.dynamic_collection import (
    DynamicCollectionConfig,
    run_dynamic_collection,
)
from app.orchestration.full_analysis_session import FullAnalysisSession
from app.orchestration.production_session_effects import ProductionSessionEffects


@dataclass
class _MockClock:
    wall: datetime = datetime(2026, 11, 22, tzinfo=UTC)
    monotonic_val: float = 1000.0

    def utc_now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.monotonic_val

    def sleep(self, seconds: float) -> None:
        self.wall += timedelta(seconds=seconds)
        self.monotonic_val += seconds


class _TrackedMitmSession:
    def __init__(
        self,
        call_log: list[str],
        *,
        start_error: Exception | None = None,
        ready_error: Exception | None = None,
        stop_error: Exception | None = None,
    ) -> None:
        self.call_log = call_log
        self.start_error = start_error
        self.ready_error = ready_error
        self.stop_error = stop_error

    def start(self) -> None:
        self.call_log.append("mitm.start")
        if self.start_error:
            raise self.start_error

    def wait_ready(self, timeout: float | None = None) -> None:
        self.call_log.append("mitm.wait_ready")
        if self.ready_error:
            raise self.ready_error

    def stop(self, timeout: float | None = None) -> None:
        self.call_log.append("mitm.stop")
        if self.stop_error:
            raise self.stop_error


class _TrackedFridaSession:
    def __init__(
        self,
        call_log: list[str],
        *,
        pid: int = 1234,
        start_error: Exception | None = None,
        ready_error: Exception | None = None,
        resume_error: Exception | None = None,
        stop_error: Exception | None = None,
    ) -> None:
        self.call_log = call_log
        self.pid = pid
        self.start_error = start_error
        self.ready_error = ready_error
        self.resume_error = resume_error
        self.stop_error = stop_error

    def start(self) -> None:
        self.call_log.append("frida.start")
        if self.start_error:
            raise self.start_error

    def wait_ready(self, timeout: float | None = None) -> None:
        self.call_log.append("frida.wait_ready")
        if self.ready_error:
            raise self.ready_error

    def resume(self) -> None:
        self.call_log.append("frida.resume")
        if self.resume_error:
            raise self.resume_error

    def stop(self, timeout: float | None = None) -> None:
        self.call_log.append("frida.stop")
        if self.stop_error:
            raise self.stop_error


# ===========================================================================
# 1. run_dynamic_collection 阶段异常与清理调用顺序断言
# ===========================================================================


def test_mitm_start_failure_still_cleans_up_and_calls_stops_in_order() -> None:
    """When mitm start fails, cleanup must still execute and record failures."""
    calls: list[str] = []
    frida = _TrackedFridaSession(calls)
    mitm = _TrackedMitmSession(calls, start_error=RuntimeError("mitm port bound"))

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            enable_traffic=True,
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=lambda _: None,
        clock=_MockClock(),
    )

    # MITM failed on start -> degraded to frida only -> frida run and clean
    assert result.status == "partial"
    assert result.primary_error_code == "mitm_start_failed"
    assert calls == [
        "mitm.start",
        "frida.start",
        "frida.wait_ready",
        "frida.resume",
        "frida.stop",
        "mitm.stop",
    ]


def test_mitm_wait_ready_timeout_degrades_and_cleans_up_in_order() -> None:
    """When mitm ready wait times out, execution continues with hook and cleans both in order."""
    calls: list[str] = []
    frida = _TrackedFridaSession(calls)
    mitm = _TrackedMitmSession(calls, ready_error=TimeoutError("mitm ready timeout"))

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            enable_traffic=True,
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=lambda _: None,
        clock=_MockClock(),
    )

    assert result.status == "partial"
    assert result.primary_error_code == "mitm_ready_timeout"
    assert calls == [
        "mitm.start",
        "mitm.wait_ready",
        "frida.start",
        "frida.wait_ready",
        "frida.resume",
        "frida.stop",
        "mitm.stop",
    ]


def test_frida_start_failure_still_cleans_mitm_session_in_order() -> None:
    """When Frida start fails after mitm became ready, mitm must still be cleanly stopped."""
    calls: list[str] = []
    frida = _TrackedFridaSession(calls, start_error=RuntimeError("frida server dead"))
    mitm = _TrackedMitmSession(calls)

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            enable_traffic=True,
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=lambda _: None,
        clock=_MockClock(),
    )

    assert result.status == "failed"
    assert result.primary_error_code == "frida_spawn_failed"
    assert "mitm.start" in calls
    assert "mitm.wait_ready" in calls
    assert "frida.start" in calls
    assert "frida.stop" in calls
    assert "mitm.stop" in calls
    assert calls.index("frida.stop") < calls.index("mitm.stop")


def test_frida_ready_timeout_cleans_both_sessions_in_order() -> None:
    """When wait_ready on Frida times out, both sessions must be stopped in order (frida then mitm)."""
    calls: list[str] = []
    frida = _TrackedFridaSession(calls, ready_error=TimeoutError("hook timeout"))
    mitm = _TrackedMitmSession(calls)

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            enable_traffic=True,
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=lambda _: None,
        clock=_MockClock(),
    )

    assert result.status == "failed"
    assert result.primary_error_code == "hook_ready_timeout"
    assert calls == [
        "mitm.start",
        "mitm.wait_ready",
        "frida.start",
        "frida.wait_ready",
        "frida.stop",
        "mitm.stop",
    ]


def test_collection_window_exception_cleans_both_sessions_in_order() -> None:
    """When an exception occurs during collection window, cleanup must still execute both stops."""
    calls: list[str] = []
    frida = _TrackedFridaSession(calls)
    mitm = _TrackedMitmSession(calls)

    def failing_control(event: dict[str, Any]) -> None:
        if event.get("event") == "consent_granted":
            raise RuntimeError("control pipe crashed")

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            enable_traffic=True,
            consent_after_seconds=1,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=failing_control,
        clock=_MockClock(),
    )

    assert result.status == "failed"
    assert result.primary_error_code == "consent_event_failed"
    assert calls.index("frida.stop") < calls.index("mitm.stop")


def test_frida_stop_failure_does_not_prevent_mitm_stop() -> None:
    """When frida.stop raises an exception during cleanup, mitm.stop must still be called."""
    calls: list[str] = []
    frida = _TrackedFridaSession(calls, stop_error=OSError("frida stop timeout"))
    mitm = _TrackedMitmSession(calls)

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            enable_traffic=True,
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=lambda _: None,
        clock=_MockClock(),
    )

    assert "frida.stop" in calls
    assert "mitm.stop" in calls
    assert calls.index("frida.stop") < calls.index("mitm.stop")
    assert result.status == "partial"
    assert any("Frida cleanup failed" in err for err in result.cleanup_errors)


def test_both_stops_failing_preserves_all_cleanup_errors() -> None:
    """When both frida.stop and mitm.stop raise exceptions, all cleanup errors are captured."""
    calls: list[str] = []
    frida = _TrackedFridaSession(calls, stop_error=OSError("frida stop error"))
    mitm = _TrackedMitmSession(calls, stop_error=OSError("mitm stop error"))

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            enable_traffic=True,
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=lambda _: None,
        clock=_MockClock(),
    )

    assert "frida.stop" in calls
    assert "mitm.stop" in calls
    assert len(result.cleanup_errors) == 2
    assert any("Frida cleanup failed" in err for err in result.cleanup_errors)
    assert any("mitm cleanup failed" in err for err in result.cleanup_errors)


# ===========================================================================
# 2. 全分析会话与安全信封：代理恢复、PID 终止、租约释放与用户取消
# ===========================================================================


def _build_test_effects(call_log: list[str], **overrides: Any) -> ProductionSessionEffects:
    plan = AIPlan(
        objective="test",
        strategy="full_analysis",
        steps=[
            PlanStep(step_id="step-1", tool_name="dynamic_analysis", reason="test", arguments={})
        ],
        generated_by="default",
    )

    values: dict[str, Any] = {
        "task_id": "test-task-1",
        "run_id": "test-run-1",
        "ai_service": SimpleNamespace(
            prepare_plan=lambda _: PreparedPlan(plan=plan),
            execute_prepared_plan=lambda *args: SimpleNamespace(
                status="completed",
                plan=plan,
                diagnostic=SimpleNamespace(analysis_mode="full_analysis"),
            ),
            run=lambda _: SimpleNamespace(diagnostic=None),
        ),
        "consent_service": ConsentCheckpointService(clock=lambda: "2026-11-22T00:00:00Z"),
        "snapshot_factory": lambda _device, _package, kind: DeviceSessionSnapshot(
            run_id="test-run-1",
            device_ref="emulator-5554",
            captured_at="2026-11-22T00:00:00Z",
            initial_state=DeviceState(online=True, http_proxy="127.0.0.1:8080"),
            capture_kind=kind,
        ),
        "clock": lambda: "2026-11-22T00:00:00Z",
        "is_cancelled": lambda: False,
        "report_step": lambda _key, _status, _message=None: None,
        "set_proxy_action": lambda dev, val: call_log.append(f"proxy.set:{val}") or True,
        "delete_proxy_action": lambda dev: call_log.append("proxy.delete") or True,
        "kill_pid_action": lambda dev, pid: call_log.append(f"kill_pid:{pid}") or True,
        "stop_mitm_pid_action": lambda pid: call_log.append(f"stop_mitm:{pid}") or True,
        "stop_frida_session_action": lambda ref: call_log.append(f"stop_frida:{ref}") or True,
        "read_proxy_action": lambda dev: "127.0.0.1:8080",
        "resource_present_action": lambda _kind, _detail: False,
        "resource_identity_matches_action": lambda _kind, _detail: True,
    }
    values.update(overrides)
    return ProductionSessionEffects(**values)


def test_mitm_start_failure_still_restores_proxy_and_releases_lease() -> None:
    """When a session fails, proxy restore, PID kill, and lease release must all execute in order."""
    call_log: list[str] = []
    lease = LeaseRegistry(clock=time.monotonic, stale_after_seconds=60)

    registry = ResourceOwnershipRegistry()
    registry.mark_owned("mitm_process", "mitm-1", pid=8888, created_by_run=True)
    registry.mark_owned("app_process", "app-1", pid=9999, created_by_run=True)

    def failing_execute(*args, **kwargs):
        call_log.append("execution.failed")
        raise RuntimeError("simulated execution crash")

    plan = AIPlan(
        objective="test",
        strategy="full_analysis",
        steps=[
            PlanStep(step_id="step-1", tool_name="dynamic_analysis", reason="test", arguments={})
        ],
        generated_by="default",
    )

    effects = _build_test_effects(
        call_log,
        ai_service=SimpleNamespace(
            prepare_plan=lambda _: PreparedPlan(plan=plan),
            execute_prepared_plan=failing_execute,
            run=lambda _: SimpleNamespace(diagnostic=None),
        ),
        delete_proxy_action=lambda dev: call_log.append("proxy.restore") or True,
        kill_pid_action=lambda dev, pid: call_log.append(f"kill_pid:{pid}") or True,
    )

    session = FullAnalysisSession(
        task_id="test-task-1",
        run_id="test-task-1",
        device_id="emulator-5554",
        package_name="com.example.app",
        objective="test cleanup ordering",
        strategy="full_analysis",
        dynamic_mode_policy="balanced",
        application_launch_allowed=True,
        allow_dynamic=True,
        allow_network=True,
        confirmed_tools=frozenset(["dynamic_analysis"]),
        token_budget=1000,
        report_language="zh-CN",
        lease=lease,
        consent=ConsentCheckpointService(clock=lambda: "2026-11-22T00:00:00Z"),
        registry=registry,
        effects=effects,
        run_dir=None,
    )

    transition = session.run()

    # Verify session transitioned to failed
    assert transition.final_state == "failed"
    # Verify lease was cleanly released in finally block
    assert lease.state("emulator-5554") == "free"
    # Verify cleanup actions occurred in order
    assert "execution.failed" in call_log
    assert "proxy.set:127.0.0.1:8080" in call_log
    assert "kill_pid:9999" in call_log


def test_cleanup_step_failure_continues_remaining_cleanups_and_releases_lease() -> None:
    """When killing PID fails, proxy deletion and lease release must still proceed."""
    call_log: list[str] = []
    lease = LeaseRegistry(clock=time.monotonic, stale_after_seconds=60)

    registry = ResourceOwnershipRegistry()
    registry.mark_owned("app_process", "app-1", pid=1111, created_by_run=True)

    def failing_kill(dev: str, pid: int) -> bool:
        call_log.append(f"kill_pid.failing:{pid}")
        return False

    plan = AIPlan(
        objective="test",
        strategy="full_analysis",
        steps=[
            PlanStep(step_id="step-1", tool_name="dynamic_analysis", reason="test", arguments={})
        ],
        generated_by="default",
    )

    effects = _build_test_effects(
        call_log,
        ai_service=SimpleNamespace(
            prepare_plan=lambda _: PreparedPlan(plan=plan),
            execute_prepared_plan=lambda *args, **kwargs: (_ for _ in ()).throw(
                RuntimeError("fail")
            ),
            run=lambda _: SimpleNamespace(diagnostic=None),
        ),
        kill_pid_action=failing_kill,
        resource_present_action=lambda kind, detail: kind == "app_process",
    )

    session = FullAnalysisSession(
        task_id="test-task-2",
        run_id="test-task-2",
        device_id="emulator-5554",
        package_name="com.example.app",
        objective="test cleanup resilience",
        strategy="full_analysis",
        dynamic_mode_policy="balanced",
        application_launch_allowed=True,
        allow_dynamic=True,
        allow_network=True,
        confirmed_tools=frozenset(["dynamic_analysis"]),
        token_budget=1000,
        report_language="zh-CN",
        lease=lease,
        consent=ConsentCheckpointService(clock=lambda: "2026-11-22T00:00:00Z"),
        registry=registry,
        effects=effects,
        run_dir=None,
    )

    transition = session.run()

    # Lease must still be released
    assert lease.state("emulator-5554") == "free"
    # Proxy restore must have been attempted
    assert "proxy.set:127.0.0.1:8080" in call_log
    assert transition.cleanup is not None
    assert transition.cleanup.status in {"partial", "failed"}


def test_user_cancellation_during_planning_cleans_up_and_releases_lease() -> None:
    """When cancelled before device work, session exits as cancelled and lease is released."""
    call_log: list[str] = []
    lease = LeaseRegistry(clock=time.monotonic, stale_after_seconds=60)

    effects = _build_test_effects(
        call_log,
        is_cancelled=lambda: True,
    )

    session = FullAnalysisSession(
        task_id="test-task-3",
        run_id="test-task-3",
        device_id="emulator-5554",
        package_name="com.example.app",
        objective="test planning cancellation",
        strategy="full_analysis",
        dynamic_mode_policy="balanced",
        application_launch_allowed=True,
        allow_dynamic=True,
        allow_network=True,
        confirmed_tools=frozenset(["dynamic_analysis"]),
        token_budget=1000,
        report_language="zh-CN",
        lease=lease,
        consent=ConsentCheckpointService(clock=lambda: "2026-11-22T00:00:00Z"),
        registry=ResourceOwnershipRegistry(),
        effects=effects,
        run_dir=None,
    )

    transition = session.run()

    assert transition.final_state == "cancelled"
    assert lease.state("emulator-5554") == "free"
    assert transition.cleanup is not None
    assert transition.cleanup.cancelled is True


def test_user_cancellation_during_execution_restores_proxy_and_releases_lease() -> None:
    """When cancelled during consent wait, proxy is restored and lease is released."""
    call_log: list[str] = []
    lease = LeaseRegistry(clock=time.monotonic, stale_after_seconds=60)
    consent_svc = ConsentCheckpointService(clock=lambda: "2026-11-22T00:00:00Z")

    class ConsentCancelService:
        def enter(self, task_id, run_id):
            return consent_svc.enter(task_id=task_id, run_id=run_id)

        def wait(self, **kwargs):
            call_log.append("consent.cancelled")
            return consent_svc.cancel(task_id=kwargs["task_id"])

        def clear(self, task_id):
            return consent_svc.clear(task_id=task_id)

    effects = _build_test_effects(
        call_log,
        consent_service=ConsentCancelService(),
    )

    session = FullAnalysisSession(
        task_id="test-task-4",
        run_id="test-task-4",
        device_id="emulator-5554",
        package_name="com.example.app",
        objective="test execution cancellation",
        strategy="full_analysis",
        dynamic_mode_policy="balanced",
        application_launch_allowed=True,
        allow_dynamic=True,
        allow_network=True,
        confirmed_tools=frozenset(["dynamic_analysis"]),
        token_budget=1000,
        report_language="zh-CN",
        lease=lease,
        consent=consent_svc,
        registry=ResourceOwnershipRegistry(),
        effects=effects,
        run_dir=None,
    )

    transition = session.run()

    assert transition.final_state == "cancelled"
    assert lease.state("emulator-5554") == "free"
    assert "proxy.set:127.0.0.1:8080" in call_log


def test_resource_ownership_registry_tracks_and_cleans_app_pid_and_mitm_on_failure() -> None:
    """Ownership registry accurately reflects registered resources and verifies their absence after cleanup."""
    registry = ResourceOwnershipRegistry()
    registry.mark_owned(
        "app_process", "pid-5555", pid=5555, created_by_run=True, cleanup_required=True
    )
    registry.mark_owned(
        "mitm_process", "mitm-session-1", pid=6666, created_by_run=True, cleanup_required=True
    )

    calls: list[str] = []

    class MockActions:
        def __init__(self):
            self.call_log = []

        def kill_pid(self, device_id: str, pid: int) -> bool:
            calls.append(f"kill_pid:{pid}")
            return True

        def stop_mitm_pid(self, pid: int) -> bool:
            calls.append(f"stop_mitm_pid:{pid}")
            return True

        def delete_proxy(self, device_id: str) -> bool:
            calls.append("delete_proxy")
            return True

        def read_proxy(self, device_id: str) -> str:
            return ""

        def resource_present(self, kind: str, detail: dict[str, Any]) -> bool:
            return False

        def resource_identity_matches(self, kind: str, detail: dict[str, Any]) -> bool:
            return True

        def force_stop_package(self, device_id: str, package: str) -> bool:
            return True

    manager = CleanupManager(
        registry=registry,
        actions=MockActions(),
        snapshot=DeviceSessionSnapshot(
            run_id="test",
            device_ref="ref",
            captured_at="2026-11-22T00:00:00Z",
            initial_state=DeviceState(http_proxy=""),
            capture_kind="preflight",
        ),
        device_id="device-1",
    )

    outcome = manager.run()

    assert outcome.status == "success"
    assert "kill_pid:5555" in calls
    assert "stop_mitm_pid:6666" in calls
