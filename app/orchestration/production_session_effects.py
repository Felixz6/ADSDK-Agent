"""Production adapter for the M7B :class:`FullAnalysisSession` effect seam.

The adapter contains no analysis implementation.  It binds one task-local set
of injected production services to the state machine and keeps the effective
dynamic strategy inside the two-phase orchestration boundary.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable

from app.ai.models import AIPlan
from app.ai.orchestrator import AIOrchestrationRequest, AIOrchestrationResult, PreparedPlan
from app.orchestration.consent_checkpoint import (
    ConsentCheckpointService,
    ConsentCheckpointState,
)
from app.orchestration.device_session import DeviceSessionSnapshot
from app.orchestration.dynamic_strategy import DynamicStrategyDecision
if TYPE_CHECKING:
    from app.services.ai_task_service import AITaskService


SnapshotFactory = Callable[[str | None, str | None, str], DeviceSessionSnapshot]
BoolDeviceValue = Callable[[str, str], bool]
BoolDevicePid = Callable[[str, int], bool]
ResourceProbe = Callable[[str, dict[str, Any]], bool | None]


@dataclass(slots=True)
class ProductionSessionEffects:
    """Task-scoped implementation of ``SessionEffects``.

    Every dependency is captured when the task begins.  In particular the
    supplied ``AITaskService`` owns the provider/config snapshot for this run.
    """

    task_id: str
    run_id: str
    ai_service: "AITaskService"
    consent_service: ConsentCheckpointService
    snapshot_factory: SnapshotFactory
    clock: Callable[[], str]
    is_cancelled: Callable[[], bool]
    report_step: Callable[[str, str, str | None], None]
    set_proxy_action: BoolDeviceValue
    delete_proxy_action: Callable[[str], bool]
    kill_pid_action: BoolDevicePid
    stop_mitm_pid_action: Callable[[int], bool]
    stop_frida_session_action: Callable[[str], bool]
    read_proxy_action: Callable[[str], str | None]
    resource_present_action: ResourceProbe
    resource_identity_matches_action: Callable[[str, dict[str, Any]], bool]
    plan_observer: Callable[[AIPlan, str], None] | None = None
    last_result: AIOrchestrationResult | None = field(default=None, init=False)
    last_executor_strategy_receipt: dict[str, str] | None = field(
        default=None, init=False
    )

    def capture_snapshot(
        self, device_id: str | None, package_name: str | None
    ) -> DeviceSessionSnapshot:
        return self.snapshot_factory(device_id, package_name, "read_only")

    def capture_fresh_snapshot(
        self, device_id: str | None, package_name: str | None
    ) -> DeviceSessionSnapshot:
        return self.snapshot_factory(device_id, package_name, "pre_state_change")

    def run_orchestration(
        self, request: AIOrchestrationRequest
    ) -> AIOrchestrationResult:
        self.last_result = self.ai_service.run(request)
        return self.last_result

    def prepare_orchestration(self, request: AIOrchestrationRequest) -> PreparedPlan:
        return self.ai_service.prepare_plan(request)

    def execute_prepared_orchestration(
        self,
        prepared: PreparedPlan,
        request: AIOrchestrationRequest,
        effective_plan: AIPlan,
        strategy_decision: DynamicStrategyDecision,
    ) -> AIOrchestrationResult:
        self.last_result = self.ai_service.execute_prepared_plan(
            prepared, request, effective_plan, strategy_decision
        )
        if self.last_result.diagnostic is not None:
            self.last_result.diagnostic.analysis_mode = (
                request.analysis_mode or request.analysis_scope
            )
            self.last_result.diagnostic.orchestration_entrypoint = (
                "tasks_ai_orchestrated"
            )
            self.last_result.diagnostic.session_engine = "FullAnalysisSession"
            self.last_result.diagnostic.execution_pipeline_version = "m7b"
        receipt = getattr(self.ai_service, "executor_strategy_receipt", None)
        self.last_executor_strategy_receipt = (
            dict(receipt) if isinstance(receipt, dict) else None
        )
        return self.last_result

    def enter_consent(self, task_id: str, run_id: str) -> ConsentCheckpointState:
        return self.consent_service.enter(task_id=task_id, run_id=run_id)

    def wait_consent(self, task_id: str) -> ConsentCheckpointState:
        return self.consent_service.wait(
            task_id=task_id,
            is_cancelled=self.is_cancelled,
        )

    def notify_plan_built(self, plan: AIPlan, path: str) -> None:
        if self.plan_observer is not None:
            self.plan_observer(plan, path)

    def set_proxy(self, device: str, value: str) -> bool:
        return bool(self.set_proxy_action(device, value))

    def delete_proxy(self, device: str) -> bool:
        return bool(self.delete_proxy_action(device))

    def kill_pid(self, device: str, pid: int) -> bool:
        return bool(self.kill_pid_action(device, pid))

    def stop_mitm_pid(self, pid: int) -> bool:
        return bool(self.stop_mitm_pid_action(pid))

    def stop_frida_session(self, ref: str) -> bool:
        return bool(self.stop_frida_session_action(ref))

    def read_proxy(self, device: str) -> str | None:
        """Read the effective proxy for post-cleanup semantic verification."""
        return self.read_proxy_action(device)

    def resource_present(
        self, kind: str, detail: dict[str, Any]
    ) -> bool | None:
        """Probe the exact PID/port recorded in the task ownership ledger."""
        return self.resource_present_action(kind, detail)

    def resource_identity_matches(
        self, kind: str, detail: dict[str, Any]
    ) -> bool:
        """Guard cleanup against PID reuse or an ownership identity change."""
        return bool(self.resource_identity_matches_action(kind, detail))


__all__ = ["ProductionSessionEffects"]
