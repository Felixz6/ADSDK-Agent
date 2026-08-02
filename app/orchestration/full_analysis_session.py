"""``FullAnalysisSession`` — the M7A state machine and the constrained-plan
validator that wraps the existing deterministic tools and the M6A/M6C AI
orchestrator.

This module owns *no* facts and *no* detection logic. It owns:

* a fixed, auditable state machine (Section 18 step sequence),
* a constrained plan validator (whitelist / DAG / risk / confirmation /
  device-capability) with at most one structured repair, else the
  deterministic default — :func:`build_full_analysis_plan` is a standalone,
  orchestrator-independent path used in tests and as an explicit guard; at
  runtime the AI orchestrator's own ``run`` already enforces the same
  constraints (constrained DAG, confirmation gate, ≤1 repair, deterministic
  fallback, per-stage token caps). The session records *which* build path
  produced the executed plan,
* a try/finally executor that always runs cleanup and restores device state,
* post-run cleanup verification and a structured acceptance record.

Every external effect (ADB, Frida, mitm, AI model call, clock, sleep) is
injected. Tests use fakes and never touch a real device, ADB, Frida,
mitmproxy, or DeepSeek.

Security invariants enforced here (and inherited from the layers it wraps):

* The AI never generates or executes Shell / ADB / Frida / SQL / Python; only
  registered tool names + validated arguments are ever passed on.
* The consent checkpoint is never auto-confirmed and never timed-out to
  confirmed; only the operator may confirm.
* External frida-server is never stopped; app data is never cleared; the
  device is never rebooted; other apps are never modified.
* The full device serial, API key, full prompt, full model response, and
  reasoning_content text never enter any artifact this module emits.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable, Literal, Protocol

from pydantic import BaseModel, ConfigDict, Field

from app.ai.models import (
    AIPlan,
    AIReport,
    AISynthesisStatus,
    EvidenceDigest,
    PlanStep,
)
from app.ai.orchestrator import (
    AIOrchestrationRequest,
    AIOrchestrationResult,
)

from .cleanup_manager import (
    CleanupActions,
    CleanupManager,
    CleanupOutcome,
    ResourceOwnershipRegistry,
)
from .consent_checkpoint import (
    ConsentCheckpointService,
    ConsentCheckpointState,
)
from .device_lease import LeaseAcquireError, LeaseRegistry
from .device_session import (
    DeviceSessionSnapshot,
    DeviceState,
)

# ---------------------------------------------------------------------------
# State machine (Section 18). The steps are the canonical full-analysis
# lifecycle; failure/cancel must still transit to cleanup.
# ---------------------------------------------------------------------------
SessionState = Literal[
    "queued",
    "preflight",
    "planning",
    "awaiting_confirmation",
    "preparing_device",
    "static_analysis",
    "starting_capture",
    "dynamic_pre_consent",
    "awaiting_consent_action",
    "dynamic_post_consent",
    "stopping_capture",
    "correlating",
    "privacy_findings",
    "deterministic_report",
    "ai_synthesis",
    "cleanup",
    "completed",
    "failed",
    "cancelled",
]

# Tools that change device state and so require explicit confirmation
# (mirrors tool_registry requires_confirmation=True). The AI may never wrap
# these without confirmation; validation below rejects it explicitly.
_DEVICE_STATE_TOOLS: frozenset[str] = frozenset({"dynamic_analysis"})

# The fixed DAG the AI may only select from / take subsets of (Section 8).
# Each step maps to a whitelisted tool. The AI cannot add tools, change the
# confirmation gate, or skip cleanup. ``ai_synthesis`` is the orchestrator's
# final model call, not a tool the model calls — listed for trace completeness.
_FULL_DAG_ORDER: tuple[str, ...] = (
    "environment_check",
    "static_analysis",
    "dynamic_analysis",
    "traffic_analysis",
    "evidence_correlation",
    "privacy_findings",
    "deterministic_report",
    "ai_synthesis",
)

# Allowable per-strategy step subsets (tool names only; ai_synthesis excluded).
_STRATEGY_STEPS: dict[str, frozenset[str]] = {
    "static_only": frozenset(
        {"environment_check", "static_analysis", "privacy_findings",
         "deterministic_report"}
    ),
    "dynamic_only": frozenset(
        {"environment_check", "dynamic_analysis", "traffic_analysis",
         "evidence_correlation", "privacy_findings", "deterministic_report"}
    ),
    "full_analysis": frozenset(
        {step for step in _FULL_DAG_ORDER if step != "ai_synthesis"}
    ),
    "report_only": frozenset(
        {"deterministic_report", "privacy_findings"}
    ),
}


def _utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


# ---------------------------------------------------------------------------
# Transition record + light state machine.
# ---------------------------------------------------------------------------
class SessionEvent(BaseModel):
    """One state transition in the session trace (secret-free)."""

    model_config = ConfigDict(extra="forbid")

    from_state: SessionState
    to_state: SessionState
    at: str
    reason: str = Field(default="", max_length=240)
    error_code: str | None = None


class SessionTransition(BaseModel):
    """The structured outcome of one session run (acceptance-relevant)."""

    model_config = ConfigDict(extra="forbid")

    run_id: str
    task_id: str
    device_ref: str
    started_at: str
    ended_at: str | None = None
    initial_state: DeviceState = Field(default_factory=DeviceState)
    final_state: SessionState
    events: list[SessionEvent] = Field(default_factory=list)
    snapshot: DeviceSessionSnapshot | None = None
    plan_built_by: Literal["ai", "default", "repaired"] = "default"
    orchestration_status: AISynthesisStatus = "partial"
    cleanup: CleanupOutcome | None = None
    consent: ConsentCheckpointState | None = None
    lease_released: bool = False
    failures: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Constrained plan validator + default builder (Section 8).
#
# This is the standalone, orchestrator-independent guarded path. At runtime the
# M6A AI orchestrator's own ``run`` already enforces the constrained DAG, the
# confirmation gate, ≤1 structured repair, deterministic fallback, and
# per-stage token caps — but having the same guards here lets tests assert the
# constraint algebra directly and lets the session record the build path.
# ---------------------------------------------------------------------------
class PlanValidationError(ValueError):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code
        self.message = message


def _validate_plan(
    plan: AIPlan,
    *,
    strategy: str,
    allow_dynamic: bool,
    allow_network: bool,
    confirmed_tools: frozenset[str],
) -> None:
    """Whitelist / DAG / risk / confirmation / device-capability validation."""
    allowed_names = _STRATEGY_STEPS.get(strategy)
    if allowed_names is None:
        raise PlanValidationError(
            "unknown_strategy", f"unknown strategy {strategy}"
        )
    if len(plan.steps) > 6:
        raise PlanValidationError("plan_too_long", "plan exceeds 6 steps")
    seen: set[str] = set()
    for step in plan.steps:
        if step.tool_name not in allowed_names:
            raise PlanValidationError(
                "tool_not_in_dag",
                f"{step.tool_name} is not in the {strategy} DAG",
            )
        if step.tool_name in seen:
            raise PlanValidationError(
                "duplicate_step", f"{step.tool_name} appears more than once"
            )
        seen.add(step.tool_name)
        if not isinstance(step.arguments, dict):
            raise PlanValidationError(
                "bad_arguments", f"{step.tool_name} arguments must be a dict"
            )
    for step in plan.steps:
        if step.tool_name in _DEVICE_STATE_TOOLS:
            if not allow_dynamic:
                raise PlanValidationError(
                    "dynamic_not_allowed",
                    "dynamic_analysis requested but allow_dynamic is false",
                )
            if step.tool_name not in confirmed_tools:
                raise PlanValidationError(
                    "confirmation_required",
                    "dynamic_analysis requires explicit user confirmation",
                )
    if "traffic_analysis" in seen and "dynamic_analysis" not in seen:
        if not allow_network:
            raise PlanValidationError(
                "traffic_without_dynamic",
                "traffic_analysis requires dynamic_analysis or allow_network",
            )


def build_default_plan(
    *,
    objective: str,
    strategy: str,
    allow_dynamic: bool,
    confirmed_tools: frozenset[str],
) -> AIPlan:
    """Build the deterministic default plan (never AI).

    The default plan is the maximal DAG subset the configuration permits. It
    is the fallback whenever the model declines, fails, or proposes an
    invalid plan that cannot be repaired.
    """
    allowed = _STRATEGY_STEPS.get(strategy, frozenset())
    order = [step for step in _FULL_DAG_ORDER if step in allowed]
    # A device-changing strategy that the operator never confirmed means the
    # dynamic-collection step (and the steps that depend on its output —
    # traffic_analysis and evidence_correlation) cannot run. We drop the whole
    # dynamic branch rather than leaving dangling dependency steps.
    dynamic_confirmed = allow_dynamic and "dynamic_analysis" in confirmed_tools
    drops_for_no_dynamic = {
        "dynamic_analysis",
        "traffic_analysis",
        "evidence_correlation",
    } if not dynamic_confirmed else set()
    # ``AIPlan`` caps ``steps`` at 6, but the full_analysis DAG enumerates 7
    # tools. Trim to the fixed priority order (mirrors the orchestrator's own
    # ``prioritize_steps``) so the default plan always fits the schema — the
    # read-only ``traffic_analysis`` is the first to drop when only one step
    # must go, since its summary is already present in the deterministic report.
    try:
        from app.ai.tool_registry import prioritize_steps
    except ImportError:  # pragma: no cover - registry always importable
        prioritize_steps = lambda names, limit: names[:limit]  # type: ignore
    trimmed_order = prioritize_steps(
        [s for s in order if s not in drops_for_no_dynamic], 6
    )
    steps: list[PlanStep] = []
    for index, tool_name in enumerate(trimmed_order):
        requires = tool_name in _DEVICE_STATE_TOOLS
        depends = [steps[-1].step_id] if steps else []
        steps.append(
            PlanStep(
                step_id=f"default-{index + 1}",
                tool_name=tool_name,
                reason="deterministic default DAG step",
                arguments={},
                depends_on=depends,
                requires_confirmation=requires,
            )
        )
    return AIPlan(
        objective=objective[:600],
        strategy=strategy,  # type: ignore[arg-type]
        steps=steps,
        expected_outputs=[],
        stop_conditions=[],
        limitations=["deterministic default fallback; no AI plan applied"],
        generated_by="default",
    )


def build_full_analysis_plan(
    *,
    objective: str,
    strategy: str,
    allow_dynamic: bool,
    allow_network: bool,
    confirmed_tools: frozenset[str],
    ai_plan: AIPlan | None,
    repaired_plan: AIPlan | None = None,
) -> tuple[AIPlan, Literal["ai", "default", "repaired"]]:
    """Validate an AI-proposed plan against the constrained DAG.

    A standalone guard path: callers pass the AI's proposed plan (and an
    optional single repair). If the proposal passes validation it is used
    (``ai``); if a repair passes, the repair is used (``repaired``);
    otherwise the deterministic default is used (``default``). The returned
    plan is always a valid constrained DAG plan.
    """
    def _try(plan: AIPlan) -> bool:
        try:
            _validate_plan(
                plan,
                strategy=strategy,
                allow_dynamic=allow_dynamic,
                allow_network=allow_network,
                confirmed_tools=confirmed_tools,
            )
            return True
        except PlanValidationError:
            return False

    if ai_plan is not None and _try(ai_plan):
        return ai_plan, "ai"
    if repaired_plan is not None and _try(repaired_plan):
        return repaired_plan, "repaired"
    return (
        build_default_plan(
            objective=objective,
            strategy=strategy,
            allow_dynamic=allow_dynamic,
            confirmed_tools=confirmed_tools,
        ),
        "default",
    )


# ---------------------------------------------------------------------------
# Injectable effects.
# ---------------------------------------------------------------------------
class SessionEffects(Protocol):
    """The session's external-effect surface, all injected for tests."""

    clock: Callable[[], str]
    is_cancelled: Callable[[], bool]
    report_step: Callable[[str, str, str | None], None]

    def capture_snapshot(
        self, device_id: str | None, package_name: str | None
    ) -> DeviceSessionSnapshot: ...

    def run_orchestration(
        self, request: AIOrchestrationRequest
    ) -> AIOrchestrationResult: ...

    def enter_consent(self, task_id: str, run_id: str) -> ConsentCheckpointState: ...

    def wait_consent(self, task_id: str) -> ConsentCheckpointState: ...

    def notify_plan_built(self, plan: AIPlan, path: Literal["ai", "default", "repaired"]) -> None: ...

    # CleanupActions surface (set_proxy / delete_proxy / kill_pid / stop_mitm_pid /
    # stop_frida_session), all injected.
    def set_proxy(self, device: str, value: str) -> bool: ...
    def delete_proxy(self, device: str) -> bool: ...
    def kill_pid(self, device: str, pid: int) -> bool: ...
    def stop_mitm_pid(self, pid: int) -> bool: ...
    def stop_frida_session(self, ref: str) -> bool: ...


# ---------------------------------------------------------------------------
# Acceptance record (Section 25).
# ---------------------------------------------------------------------------
class FullAnalysisAcceptance(BaseModel):
    """The structured acceptance record for one full-analysis run.

    Secret-free: no API key, full serial, full prompt/response, cookies,
    bodies, or reasoning_content. Real Evidence IDs are sourced from the
    digest.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["m7a-acceptance-v1"] = "m7a-acceptance-v1"
    run_id: str
    task_id: str
    device_ref: str
    started_at: str
    ended_at: str | None = None
    final_state: SessionState
    plan_build_path: Literal["ai", "default", "repaired"] = "default"
    orchestration_status: AISynthesisStatus = "partial"
    token_usage: dict[str, Any] = Field(default_factory=dict)
    evidence_ids: list[str] = Field(default_factory=list)
    key_findings: list[dict[str, Any]] = Field(default_factory=list)
    cleanup_outcome: dict[str, Any] = Field(default_factory=dict)
    consent_outcome: dict[str, Any] = Field(default_factory=dict)
    limitations: list[str] = Field(default_factory=list)
    event_count: int = 0
    lease_released: bool = False


# ---------------------------------------------------------------------------
# The session.
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class FullAnalysisSession:
    """Drives one full-analysis run on a single device.

    Constructed with all injected effects; run via :meth:`run`. Ties together
    the lease, snapshot, ownership registry, consent service, AI orchestrator,
    and cleanup manager into the auditable state machine.
    """

    task_id: str
    run_id: str
    device_id: str | None
    package_name: str | None
    objective: str
    strategy: Literal[
        "static_only", "dynamic_only", "full_analysis", "report_only"
    ]
    allow_dynamic: bool
    allow_network: bool
    confirmed_tools: frozenset[str]
    token_budget: int
    report_language: str
    lease: LeaseRegistry
    consent: ConsentCheckpointService
    registry: ResourceOwnershipRegistry
    effects: "SessionEffects"
    run_dir: Any = None
    # Internal trace.
    _state: SessionState = "queued"
    _events: list[SessionEvent] = field(default_factory=list)
    _started_at: str = ""
    _snapshot: DeviceSessionSnapshot | None = None
    _plan: AIPlan | None = None
    _plan_build_path: Literal["ai", "default", "repaired"] = "default"
    _orch_result: AIOrchestrationResult | None = None
    _cleanup_outcome: CleanupOutcome | None = None
    _consent_state: ConsentCheckpointState | None = None
    _lease_released: bool = False
    _plan_uses_dynamic: bool = False

    # -- state machine -------------------------------------------------
    def _now(self) -> str:
        return self.effects.clock()

    def _transit(
        self,
        to: SessionState,
        reason: str = "",
        error_code: str | None = None,
    ) -> None:
        event = SessionEvent(
            from_state=self._state,
            to_state=to,
            at=self._now(),
            reason=reason[:240],
            error_code=error_code,
        )
        self._events.append(event)
        self._state = to
        stage_key = to if to not in {"failed", "cancelled"} else "cleanup"
        try:
            self.effects.report_step(stage_key, "running", reason or None)
        except BaseException:
            pass

    def _cancelled(self) -> bool:
        try:
            return bool(self.effects.is_cancelled())
        except BaseException:
            return False

    # -- public entry point -------------------------------------------
    def run(self) -> SessionTransition:
        """Run the session to completion.

        Structured so cleanup and finalisation happen exactly once, *after*
        every exit path — including an early terminal state (lease busy,
        cancellation, consent cancelled) and an unexpected exception. The
        body signals an early terminal state by returning it; it never
        finalises the transition itself.
        """
        self._started_at = self._now()
        self._transit("preflight", "capturing read-only snapshot")
        outcome_failures: list[str] = []
        terminal: SessionState | None = None
        try:
            terminal = self._run_body(outcome_failures)
        except BaseException as exc:  # never let cleanup be skipped
            outcome_failures.append(f"session_error: {type(exc).__name__}")
            terminal = "failed"
        finally:
            if self._state != "cleanup":
                self._transit("cleanup", "always run cleanup")
            self._release_lease()
            self._run_cleanup()
            self._finalize_consent_clear()

        final_state: SessionState
        if terminal is not None:
            final_state = terminal
        elif self._cancelled():
            final_state = "cancelled"
        elif outcome_failures and self._orch_result is None:
            final_state = "failed"
        else:
            final_state = "completed"
        self._transit(final_state, "session finished")
        return self._finalize(outcome_failures)

    def _run_body(self, outcome_failures: list[str]) -> SessionState | None:
        """The session flow. Returns an early terminal state, or ``None`` to
        let :meth:`run` decide the final state. Never runs cleanup itself."""
        # Phase preflight: capture snapshot (read-only).
        self._snapshot = self.effects.capture_snapshot(
            self.device_id, self.package_name
        )
        self._transit("planning", "constrained plan selection")
        request = AIOrchestrationRequest(
            objective=self.objective,
            analysis_scope=self.strategy,
            task_id=self.task_id,
            allow_dynamic=self.allow_dynamic,
            allow_network=self.allow_network,
            confirmed_tools=self.confirmed_tools,
            token_budget=self.token_budget,
            report_language=self.report_language,
            run_dir=self.run_dir,
        )

        # Device-changing strategies take a lease and require the explicit
        # confirmation gate (the Phase C confirmation word lives outside this
        # module — the session only enforces that the gate was passed).
        if self._needs_device():
            self._transit(
                "awaiting_confirmation",
                "device-state changes require explicit confirmation",
            )
            device_key = (
                self._snapshot.device_ref if self._snapshot else "__no_device__"
            )
            try:
                self.lease.acquire(
                    device_key=device_key,
                    run_id=self.run_id,
                    task_id=self.task_id,
                )
            except LeaseAcquireError as exc:
                outcome_failures.append(f"lease_acquire_failed: {exc.code}")
                self._transit(
                    "failed", "lease unavailable", error_code=exc.code
                )
                return "failed"
            if self._cancelled():
                self._transit("cancelled", "cancelled before device work")
                return "cancelled"

        # Execute the plan via the AI orchestrator (which enforces the
        # constrained DAG, confirmation gate, <=1 repair, fallback, and
        # per-stage caps internally).
        self._transit("preparing_device", "executing deterministic steps")
        try:
            self._orch_result = self.effects.run_orchestration(request)
            if self._orch_result is not None:
                self._plan = self._orch_result.plan
                self._plan_build_path = (
                    "ai"
                    if self._orch_result.plan.generated_by == "ai"
                    else "default"
                )
                self._plan_uses_dynamic = any(
                    step.tool_name in _DEVICE_STATE_TOOLS
                    for step in self._orch_result.plan.steps
                )
                try:
                    self.effects.notify_plan_built(
                        self._orch_result.plan, self._plan_build_path
                    )
                except BaseException:
                    pass
        except BaseException as exc:  # defensive: never leak stacks
            outcome_failures.append(
                f"orchestration_failed: {type(exc).__name__}"
            )
            self._orch_result = None

        if self._orch_result is not None and self._needs_consent():
            self._transit("dynamic_pre_consent", "awaiting manual consent")
            self._consent_state = self.effects.enter_consent(
                self.task_id, self.run_id
            )
            self._transit(
                "awaiting_consent_action", "operator consent required"
            )
            self._consent_state = self.effects.wait_consent(self.task_id)
            if (
                self._consent_state is not None
                and self._consent_state.status == "cancelled"
            ):
                self._transit("cancelled", "consent cancelled by operator")
                return "cancelled"
            self._transit("dynamic_post_consent", "consent resolved")

        self._transit("ai_synthesis", "AI final report composed")
        return None

    # -- helpers -------------------------------------------------------
    def _needs_device(self) -> bool:
        return self.allow_dynamic or self.strategy in {
            "dynamic_only",
            "full_analysis",
        }

    def _needs_consent(self) -> bool:
        return self._plan_uses_dynamic

    def _release_lease(self) -> None:
        if not self._snapshot:
            return
        device_key = self._snapshot.device_ref
        try:
            ok = self.lease.release(device_key=device_key, run_id=self.run_id)
            self._lease_released = bool(ok)
        except BaseException:
            self._lease_released = False

    def _run_cleanup(self) -> None:
        if self._snapshot is None:
            self._cleanup_outcome = CleanupOutcome(
                ran=False, evidence_retained=True
            )
            return
        try:
            manager = CleanupManager(
                registry=self.registry,
                actions=self.effects,  # type: ignore[arg-type]
                snapshot=self._snapshot,
                device_id=self.device_id,
            )
            self._cleanup_outcome = manager.run(cancelled=self._cancelled())
        except BaseException:
            self._cleanup_outcome = CleanupOutcome(
                ran=True, evidence_retained=True, failures=["cleanup exception"]
            )

    def _finalize_consent_clear(self) -> None:
        try:
            self.consent.clear(self.task_id)
        except BaseException:
            pass

    def _finalize(self, failures: list[str]) -> SessionTransition:
        return SessionTransition(
            run_id=self.run_id,
            task_id=self.task_id,
            device_ref=(
                self._snapshot.device_ref
                if self._snapshot
                else "__no_device__"
            ),
            started_at=self._started_at,
            ended_at=self._now(),
            initial_state=(
                self._snapshot.initial_state
                if self._snapshot
                else DeviceState()
            ),
            final_state=self._state,
            events=list(self._events),
            snapshot=self._snapshot,
            plan_built_by=self._plan_build_path,
            orchestration_status=(
                self._orch_result.status if self._orch_result else "failed"
            ),
            cleanup=self._cleanup_outcome,
            consent=self._consent_state,
            lease_released=self._lease_released,
            failures=failures,
        )


# ---------------------------------------------------------------------------
# Convenience entry points used by app/main.py.
# ---------------------------------------------------------------------------
def execute_full_analysis_plan(
    *, session: "FullAnalysisSession"
) -> SessionTransition:
    """Run one session end-to-end and return its structured transition."""
    return session.run()


def verify_cleanup(outcome: CleanupOutcome | None) -> dict[str, Any]:
    """Post-run cleanup verification (Section 20 per-failure expectations)."""
    if outcome is None:
        return {"ok": False, "reason": "no cleanup outcome"}
    return {
        "ok": outcome.ok,
        "proxy_restore_attempted": outcome.proxy_restore_attempted,
        "proxy_restore_failed": outcome.proxy_restore_failed,
        "external_frida_touched": outcome.external_frida_touched,
        "evidence_retained": outcome.evidence_retained,
        "failures": list(outcome.failures),
        "step_count": len(outcome.steps),
    }


def build_full_analysis_acceptance(
    *,
    transition: SessionTransition,
    result: AIOrchestrationResult | None,
) -> FullAnalysisAcceptance:
    """Compose the structured acceptance record (Section 25, 24 fields)."""
    evidence_ids: list[str] = []
    key_findings: list[dict[str, Any]] = []
    token_usage: dict[str, Any] = {}
    orch_status: AISynthesisStatus = "partial"
    if result is not None:
        orch_status = result.status
        token_usage = result.usage.model_dump(mode="json")
        evidence_ids = sorted(result.digest.known_evidence_ids)
        key_findings = [
            f.model_dump(mode="json") for f in result.report.key_findings
        ]
    limitations: list[str] = []
    if transition.cleanup is not None and transition.cleanup.proxy_restore_failed:
        limitations.append(
            "device proxy restore failed; manual restore may be required"
        )
    if (
        transition.consent is not None
        and transition.consent.status == "not_found"
    ):
        limitations.append(
            "consent UI was not reached; dynamic evidence is partial"
        )
    if result is not None and result.status == "budget_exhausted":
        limitations.append(
            "AI token budget exhausted; deterministic report retained"
        )
    return FullAnalysisAcceptance(
        run_id=transition.run_id,
        task_id=transition.task_id,
        device_ref=transition.device_ref,
        started_at=transition.started_at,
        ended_at=transition.ended_at,
        final_state=transition.final_state,
        plan_build_path=transition.plan_built_by,
        orchestration_status=orch_status,
        token_usage=token_usage,
        evidence_ids=evidence_ids,
        key_findings=key_findings,
        cleanup_outcome=(
            transition.cleanup.model_dump(mode="json")
            if transition.cleanup
            else {}
        ),
        consent_outcome=(
            transition.consent.model_dump(mode="json")
            if transition.consent
            else {}
        ),
        limitations=limitations,
        event_count=len(transition.events),
        lease_released=transition.lease_released,
    )


__all__ = [
    "FullAnalysisAcceptance",
    "FullAnalysisSession",
    "PlanValidationError",
    "SessionEffects",
    "SessionEvent",
    "SessionState",
    "SessionTransition",
    "build_default_plan",
    "build_full_analysis_acceptance",
    "build_full_analysis_plan",
    "execute_full_analysis_plan",
    "verify_cleanup",
]
