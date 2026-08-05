from __future__ import annotations

from types import SimpleNamespace
from typing import Any

from app.orchestration.cleanup_manager import CleanupManager, ResourceOwnershipRegistry
from app.orchestration.device_session import DeviceSessionSnapshot, DeviceState
from app.orchestration.production_session_effects import ProductionSessionEffects


class _AIService:
    def __init__(self) -> None:
        self.calls: list[tuple[Any, ...]] = []

    def prepare_plan(self, request: Any) -> str:
        self.calls.append(("prepare", request))
        return "prepared"

    def execute_prepared_plan(
        self, prepared: Any, request: Any, effective_plan: Any, decision: Any
    ) -> Any:
        self.calls.append(
            ("execute", prepared, request, effective_plan, decision)
        )
        return SimpleNamespace(diagnostic=SimpleNamespace())

    def run(self, request: Any) -> Any:
        self.calls.append(("run", request))
        return SimpleNamespace(diagnostic=None)


class _Consent:
    def enter(self, *, task_id: str, run_id: str) -> Any:
        return SimpleNamespace(task_id=task_id, run_id=run_id, status="pending")

    def wait(self, *, task_id: str, is_cancelled: Any) -> Any:
        return SimpleNamespace(task_id=task_id, status="cancelled" if is_cancelled() else "resolved")


def _effects(**overrides: Any) -> ProductionSessionEffects:
    values: dict[str, Any] = {
        "task_id": "task-1",
        "run_id": "run-1",
        "ai_service": _AIService(),
        "consent_service": _Consent(),
        "snapshot_factory": lambda _device, _package, kind: DeviceSessionSnapshot(
            run_id="run-1",
            device_ref="masked",
            captured_at="2026-08-05T00:00:00Z",
            initial_state=DeviceState(http_proxy=""),
            capture_kind=kind,
        ),
        "clock": lambda: "2026-08-05T00:00:00Z",
        "is_cancelled": lambda: False,
        "report_step": lambda _key, _status, _message=None: None,
        "set_proxy_action": lambda _device, _value: True,
        "delete_proxy_action": lambda _device: True,
        "kill_pid_action": lambda _device, _pid: True,
        "stop_mitm_pid_action": lambda _pid: True,
        "stop_frida_session_action": lambda _ref: True,
        "read_proxy_action": lambda _device: "",
        "resource_present_action": lambda _kind, _detail: False,
        "resource_identity_matches_action": lambda _kind, _detail: True,
    }
    values.update(overrides)
    return ProductionSessionEffects(**values)


def test_production_effects_propagates_only_effective_strategy() -> None:
    ai_service = _AIService()
    effects = _effects(ai_service=ai_service)
    request = SimpleNamespace(analysis_mode="full_analysis", analysis_scope="full_analysis")
    decision = SimpleNamespace(effective_strategy="balanced")

    result = effects.execute_prepared_orchestration(
        "prepared", request, "effective-plan", decision
    )

    assert ai_service.calls == [
        ("execute", "prepared", request, "effective-plan", decision)
    ]
    assert result.diagnostic.analysis_mode == "full_analysis"
    assert result.diagnostic.orchestration_entrypoint == "tasks_ai_orchestrated"
    assert result.diagnostic.session_engine == "FullAnalysisSession"
    assert result.diagnostic.execution_pipeline_version == "m7b"


def test_production_effects_cleanup_verifies_residual_and_retries_once() -> None:
    present = iter([True, False])
    kills: list[tuple[str, int]] = []
    effects = _effects(
        kill_pid_action=lambda device, pid: kills.append((device, pid)) or True,
        resource_present_action=lambda _kind, _detail: next(present),
    )
    registry = ResourceOwnershipRegistry()
    registry.mark_owned(
        "frida_helper",
        "helper-123",
        pid=123,
        device_id="DEVICE",
        expected_command_token="frida-helper",
    )
    snapshot = DeviceSessionSnapshot(
        run_id="run-1",
        device_ref="masked",
        captured_at="2026-08-05T00:00:00Z",
        initial_state=DeviceState(http_proxy=""),
    )

    outcome = CleanupManager(
        registry=registry,
        actions=effects,
        snapshot=snapshot,
        device_id="DEVICE",
    ).run()

    diagnostic = next(
        item for item in outcome.diagnostics if item.resource_type == "frida_helper"
    )
    assert kills == [("DEVICE", 123), ("DEVICE", 123)]
    assert diagnostic.retry_attempted is True
    assert diagnostic.verification_result == "verified"
    assert diagnostic.final_status == "success"
    assert outcome.status == "success"
