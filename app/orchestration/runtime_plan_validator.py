"""Runtime semantic plan validator (Section 十一).

`:func:`validate_plan_against_runtime_state` runs *after* the schema /
whitelist / DAG layers (:mod:`app.ai.plan_validator`) and *before* any
device-state-changing tool is ever executed. It checks the plan against the
**live** facts the preflight and lease layers observed — the things a JSON
schema cannot know:

* whether the device is still online and on the same boot as the snapshot,
* whether the target package is installed / its PID was observed,
* whether a frida-server is available for a dynamic plan,
* whether the lease for this device is free and reclaimable,
* whether the consent gate the plan implies is consistent with the consent
  checkpoint's state, and with the dynamic-strategy normalization decision,
* whether the plan touches the network while network capture is disabled,
* whether the effective (strategy-normalized) plan still matches the steps
  the model chose.

It deliberately performs **no** ADB / Frida / mitm call of its own — every
fact it reasons over was already captured by the read-only preflight and is
handed in. This keeps the module pure and fully unit-testable in Phase A
(no device).

Output is a stable, secret-free :class:`RuntimePlanValidationIssue` list plus
a single bounded fail verdict, so the orchestrator can decide "block +
deterministic fallback", "block + cleanup (device left the run's world)", or
"proceed". The original plan text never appears; only codes + bounded paths.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping

from app.ai.models import AIPlan

from .consent_checkpoint import ConsentCheckpointState
from .device_lease import DeviceLease
from .device_session import DeviceSessionSnapshot
from .full_analysis_session import _DEVICE_STATE_TOOLS

# ---------------------------------------------------------------------------
# Stable error codes — runtime layer (Section 十一). One stable code per
# check; never reused across stages so acceptance metrics can count them.
# ---------------------------------------------------------------------------
RT_DEVICE_OFFLINE = "device_offline"
RT_DEVICE_REBOOTED = "device_rebooted_since_snapshot"
RT_DEVICE_DISCONNECTED = "device_disconnected"
RT_PACKAGE_NOT_INSTALLED = "package_not_installed"
RT_PACKAGE_NOT_RUNNING = "package_not_running"
RT_FOREGROUND_NOT_TARGET = "foreground_not_target"
RT_TARGET_PID_NOT_FOUND = "target_process_not_found"
RT_FRIDA_NOT_READY = "frida_server_not_ready"
RT_FRIDA_OWNED_ELSEWHERE = "frida_server_owned_elsewhere"
RT_NATIVE_BRIDGE_RISK = "native_bridge_anti_debug_risk"
RT_LEASE_BUSY = "lease_busy"
RT_LEASE_STALE_BLOCKED = "lease_stale_blocked"
RT_LEASE_HELD_BY_OTHER = "lease_held_by_other_run"
RT_CONSENT_GATE_MISMATCH = "consent_gate_mismatch"
RT_CONSENT_ALREADY_RESOLVED = "consent_already_resolved"
RT_DYNAMIC_NOT_ALLOWED_EFFECTIVE = "dynamic_not_allowed_effective"
RT_NETWORK_NOT_ALLOWED = "network_capture_not_allowed"
RT_TRAFFIC_REQUIRES_DYNAMIC = "traffic_requires_dynamic"
RT_STRATEGY_CONFLICT = "strategy_conflict_with_steps"
RT_SCOPE_DRIFT = "effective_strategy_scope_drift"
RT_PLAN_TOO_LONG_RUNTIME = "plan_too_long_runtime"
RT_DYNAMIC_TOOL_AFTER_CONSENT = "dynamic_tool_after_consent_order"
RT_REPORT_ONLY_WITH_DYNAMIC = "report_only_plan_has_dynamic_tool"
RT_STATIC_PLAN_TOUCHES_DEVICE = "static_plan_touches_device"
RT_MISSING_PREFLIGHT = "missing_preflight"
RT_LEASE_REQUIRED_BUT_NONE = "lease_required_but_none"
RT_UNKNOWN_RUNTIME_STATE = "unknown_runtime_state"

STAGE_RUNTIME = "runtime"


@dataclass(slots=True)
class RuntimePlanValidationIssue:
    """One runtime-semantic finding (secret-free)."""

    code: str
    stage: str = STAGE_RUNTIME
    json_path: str | None = None
    tool_name: str | None = None
    expected: str | None = None
    received_type: str | None = None
    # Whether the run must halt + run cleanup (device left the run's world),
    # vs. just fall back deterministically.
    fatal: bool = False


@dataclass(slots=True)
class RuntimeCapabilities:
    """Read-only runtime facts the runtime layer reasons over.

    All fields are *observables* the preflight already captured; the runtime
    validator does not re-probe. ``None`` means "could not observe"; the
    validator treats that as a soft insufficiency, never a hard failure, so a
    MuMu emu quirk on a single probe cannot block an otherwise valid plan.
    """

    device_online: bool
    boot_id: str | None
    package_installed: bool | None
    # PIDs of the target app observed at preflight time.
    target_pids: list[int] = field(default_factory=list)
    foreground_package: str | None = None
    frida_server_present: bool | None = None
    frida_server_owned: bool = False
    native_bridge_detected: bool = False
    http_proxy: str | None = None


@dataclass(slots=True)
class RuntimePlanValidationResult:
    """Outcome of :func:`validate_plan_against_runtime_state`."""

    ok: bool
    issues: list[RuntimePlanValidationIssue] = field(default_factory=list)

    @property
    def fatal(self) -> RuntimePlanValidationIssue | None:
        for issue in self.issues:
            if issue.fatal:
                return issue
        return None

    @property
    def first_code(self) -> str | None:
        return self.issues[0].code if self.issues else None


def _capabilities_from_snapshot(
    snapshot: DeviceSessionSnapshot, package_name: str | None
) -> RuntimeCapabilities:
    """Project a ``device-session-v1`` snapshot into runtime capabilities.

    Centralised so callers and tests build the same fact bundle the validator
    reasons over; the snapshot stays the source of truth on disk."""

    state = snapshot.initial_state
    return RuntimeCapabilities(
        device_online=bool(state.online),
        boot_id=state.boot_id,
        package_installed=state.package_installed,
        target_pids=[],  # PIDs are only meaningful in a fresh preflight snapshot
        foreground_package=state.foreground_package,
        frida_server_present=state.frida_server_present,
        frida_server_owned=bool(state.frida_server_owned),
        native_bridge_detected=any(
            "Native Bridge" in note for note in snapshot.environment_notes
        ),
        http_proxy=state.http_proxy,
    )


def validate_plan_against_runtime_state(
    plan: AIPlan,
    *,
    preflight: DeviceSessionSnapshot | None,
    capabilities: RuntimeCapabilities | None,
    confirmation: ConsentCheckpointState | None,
    lease_state: DeviceLease | None,
    requested_strategy: str,
    effective_strategy: str,
    allow_dynamic: bool,
    allow_network: bool,
    confirmed_tools: frozenset[str] | set[str],
    package_name: str | None = None,
    max_steps: int = 6,
    application_launch_allowed: bool = False,
) -> RuntimePlanValidationResult:
    """Run the runtime-semantic checks (≥17).

    Returns a result object; never raises. A ``fatal`` issue means the device
    has left the run's world (offline / rebooted / disconnected / lease gone
    bad) and the caller must block **and** run cleanup. A non-fatal issue
    means the plan cannot run as proposed but the device is still usable; the
    caller falls back to the deterministic plan.
    """

    issues: list[RuntimePlanValidationIssue] = []
    confirmed_tools = frozenset(confirmed_tools)

    # --- preflight presence (1) ---
    if preflight is None:
        issues.append(RuntimePlanValidationIssue(
            code=RT_MISSING_PREFLIGHT, json_path="/steps"
        ))
        return RuntimePlanValidationResult(ok=False, issues=issues)

    caps = capabilities or _capabilities_from_snapshot(preflight, package_name)

    # --- device online (2) ---
    if not caps.device_online:
        issues.append(RuntimePlanValidationIssue(
            code=RT_DEVICE_OFFLINE, json_path="/steps", fatal=True
        ))

    # --- device same boot (3) ---
    snap_boot = preflight.initial_state.boot_id
    if snap_boot and caps.boot_id and snap_boot != caps.boot_id:
        issues.append(RuntimePlanValidationIssue(
            code=RT_DEVICE_REBOOTED, json_path="/steps", fatal=True
        ))

    # The preflight was captured as read-only; if the device is offline now
    # the run is gone, not merely degraded.
    if caps.device_online is False and preflight.initial_state.online:
        issues.append(RuntimePlanValidationIssue(
            code=RT_DEVICE_DISCONNECTED, json_path="/steps", fatal=True
        ))

    # --- package installed (4) ---
    has_dynamic = any(step.tool_name in _DEVICE_STATE_TOOLS for step in plan.steps)
    if package_name is not None:
        if caps.package_installed is False:
            issues.append(RuntimePlanValidationIssue(
                code=RT_PACKAGE_NOT_INSTALLED, json_path="/steps"
            ))

    # --- target process running, when a dynamic plan touches it (5) ---
    if has_dynamic:
        if not caps.target_pids:
            issues.append(RuntimePlanValidationIssue(
                code=RT_TARGET_PID_NOT_FOUND, json_path="/steps",
                expected="target_process_running", received_type="no_pid"
            ))

    # --- foreground is the target (6) (soft: emu focus can lag) ---
    if has_dynamic and package_name is not None and caps.foreground_package and caps.foreground_package != package_name:
        issues.append(RuntimePlanValidationIssue(
            code=RT_FOREGROUND_NOT_TARGET, json_path="/steps",
            tool_name=caps.foreground_package if not caps.foreground_package.startswith("__") else None
        ))

    # --- frida readiness (7) ---
    if has_dynamic and caps.frida_server_present is False:
        issues.append(RuntimePlanValidationIssue(
            code=RT_FRIDA_NOT_READY, json_path="/steps",
            expected="frida_server_present"
        ))

    # --- frida owned elsewhere (8) ---
    if has_dynamic and caps.frida_server_present and not caps.frida_server_owned:
        issues.append(RuntimePlanValidationIssue(
            code=RT_FRIDA_OWNED_ELSEWHERE, json_path="/steps"
        ))

    # --- Native-bridge-as-anti-debug risk (9) (soft, recorded not blocking) ---
    if has_dynamic and caps.native_bridge_detected:
        issues.append(RuntimePlanValidationIssue(
            code=RT_NATIVE_BRIDGE_RISK, json_path="/steps"
        ))

    # --- lease availability (10/11/12) ---
    if has_dynamic or requested_strategy in {"dynamic_only", "full_analysis"}:
        if lease_state is None:
            issues.append(RuntimePlanValidationIssue(
                code=RT_LEASE_REQUIRED_BUT_NONE, json_path="/steps"
            ))
        else:
            ls = lease_state.state
            if ls == "held" and lease_state.owner_run_id is not None:
                # Owner is never persisted to artifacts, so this branch is
                # information-only — the lease layer gates the actual acquire.
                issues.append(RuntimePlanValidationIssue(
                    code=RT_LEASE_HELD_BY_OTHER, json_path="/steps"
                ))
            elif ls == "stale":
                issues.append(RuntimePlanValidationIssue(
                    code=RT_LEASE_STALE_BLOCKED, json_path="/steps"
                ))

    # --- consent gate consistency (13/14) ---
    if has_dynamic:
        if confirmation is None:
            issues.append(RuntimePlanValidationIssue(
                code=RT_CONSENT_GATE_MISMATCH, json_path="/steps",
                expected="awaiting_consent_action"
            ))
        elif confirmation.status == "awaiting":
            # Correct: dynamic plan with a checkpoint awaiting the operator.
            pass
        elif confirmation.status in {"confirmed", "not_found", "skipped"}:
            issues.append(RuntimePlanValidationIssue(
                code=RT_CONSENT_ALREADY_RESOLVED, json_path="/steps"
            ))
        elif confirmation.status == "cancelled":
            issues.append(RuntimePlanValidationIssue(
                code=RT_CONSENT_GATE_MISMATCH, json_path="/steps",
                expected="awaiting_consent_action", fatal=True
            ))
        elif confirmation.status == "expired":
            issues.append(RuntimePlanValidationIssue(
                code=RT_CONSENT_GATE_MISMATCH, json_path="/steps"
            ))
    else:
        # A non-dynamic plan must NOT have an awaiting checkpoint dragging
        # the run into a consent wait it will never resolve.
        if confirmation is not None and confirmation.status == "awaiting":
            issues.append(RuntimePlanValidationIssue(
                code=RT_CONSENT_GATE_MISMATCH, json_path="/steps",
                expected="no_awaiting_consent_for_static_plan"
            ))

    # --- effective-strategy dynamic gate (15) ---
    effective_has_dynamic = (
        effective_strategy in {"dynamic_only", "full_analysis"}
        and allow_dynamic
        and "dynamic_analysis" in confirmed_tools
    )
    if has_dynamic and not effective_has_dynamic:
        issues.append(RuntimePlanValidationIssue(
            code=RT_DYNAMIC_NOT_ALLOWED_EFFECTIVE, json_path="/steps",
            expected="allow_dynamic_and_confirmed"
        ))

    # --- network capture gate (16) ---
    has_traffic = any(step.tool_name == "traffic_analysis" for step in plan.steps)
    if has_traffic and not allow_network and not has_dynamic:
        issues.append(RuntimePlanValidationIssue(
            code=RT_NETWORK_NOT_ALLOWED, json_path="/steps",
            expected="allow_network_or_dynamic_analysis"
        ))
    if has_traffic and not has_dynamic and not allow_network:
        issues.append(RuntimePlanValidationIssue(
            code=RT_TRAFFIC_REQUIRES_DYNAMIC, json_path="/steps"
        ))

    # --- requested/effective strategy conflict with steps (17) ---
    if requested_strategy != effective_strategy and not _steps_fit_strategy(
        plan, effective_strategy
    ):
        issues.append(RuntimePlanValidationIssue(
            code=RT_SCOPE_DRIFT, json_path="/steps",
            expected=effective_strategy,
            received_type=requested_strategy
        ))
    if effective_strategy == "static_only" and has_dynamic:
        issues.append(RuntimePlanValidationIssue(
            code=RT_STATIC_PLAN_TOUCHES_DEVICE, json_path="/steps"
        ))
    if effective_strategy == "report_only" and has_dynamic:
        issues.append(RuntimePlanValidationIssue(
            code=RT_REPORT_ONLY_WITH_DYNAMIC, json_path="/steps"
        ))
    if requested_strategy not in {
        "static_only", "dynamic_only", "full_analysis", "report_only"
    }:
        issues.append(RuntimePlanValidationIssue(
            code=RT_UNKNOWN_RUNTIME_STATE, json_path="/steps"
        ))

    # --- plan length at runtime (18) (mirrors schema cap, kept distinct so
    # the runtime layer can report it independently of the schema layer) ---
    if len(plan.steps) > max_steps:
        issues.append(RuntimePlanValidationIssue(
            code=RT_PLAN_TOO_LONG_RUNTIME, json_path="/steps",
            received_type=str(len(plan.steps))
        ))

    # --- dynamic-tool-only-after-consent ordering (19) ---
    if has_dynamic and confirmation is not None:
        if confirmation.status not in {"awaiting", "confirmed"}:
            issues.append(RuntimePlanValidationIssue(
                code=RT_DYNAMIC_TOOL_AFTER_CONSENT, json_path="/steps"
            ))

    # --- strategy/steps fundamental conflict (20) ---
    if effective_strategy != requested_strategy and has_dynamic and not allow_dynamic:
        issues.append(RuntimePlanValidationIssue(
            code=RT_STRATEGY_CONFLICT, json_path="/steps",
            expected=requested_strategy, received_type=effective_strategy
        ))

    ok = not issues
    return RuntimePlanValidationResult(ok=ok, issues=issues)


def _steps_fit_strategy(plan: AIPlan, strategy: str) -> bool:
    """Whether the plan's tool set is a subset of the strategy's allowed DAG.

    Mirrors :mod:`full_analysis_session._STRATEGY_STEPS` without importing the
    private dict, so the runtime layer can be reasoned about in isolation."""

    allowed: dict[str, frozenset[str]] = {
        "static_only": frozenset(
            {"environment_check", "static_analysis", "privacy_findings",
             "deterministic_report"}
        ),
        "dynamic_only": frozenset(
            {"environment_check", "dynamic_analysis", "traffic_analysis",
             "evidence_correlation", "privacy_findings", "deterministic_report"}
        ),
        "full_analysis": frozenset(
            {"environment_check", "static_analysis", "dynamic_analysis",
             "traffic_analysis", "evidence_correlation", "privacy_findings",
             "deterministic_report"}
        ),
        "report_only": frozenset({"deterministic_report", "privacy_findings"}),
    }
    bag = allowed.get(strategy, frozenset())
    return all(step.tool_name in bag for step in plan.steps)


__all__ = [
    "RT_CONSENT_ALREADY_RESOLVED",
    "RT_CONSENT_GATE_MISMATCH",
    "RT_DEVICE_DISCONNECTED",
    "RT_DEVICE_OFFLINE",
    "RT_DEVICE_REBOOTED",
    "RT_DYNAMIC_NOT_ALLOWED_EFFECTIVE",
    "RT_DYNAMIC_TOOL_AFTER_CONSENT",
    "RT_FOREGROUND_NOT_TARGET",
    "RT_FRIDA_NOT_READY",
    "RT_FRIDA_OWNED_ELSEWHERE",
    "RT_LEASE_BUSY",
    "RT_LEASE_HELD_BY_OTHER",
    "RT_LEASE_REQUIRED_BUT_NONE",
    "RT_LEASE_STALE_BLOCKED",
    "RT_MISSING_PREFLIGHT",
    "RT_NATIVE_BRIDGE_RISK",
    "RT_NETWORK_NOT_ALLOWED",
    "RT_PACKAGE_NOT_INSTALLED",
    "RT_PACKAGE_NOT_RUNNING",
    "RT_PLAN_TOO_LONG_RUNTIME",
    "RT_REPORT_ONLY_WITH_DYNAMIC",
    "RT_SCOPE_DRIFT",
    "RT_STATIC_PLAN_TOUCHES_DEVICE",
    "RT_STRATEGY_CONFLICT",
    "RT_TARGET_PID_NOT_FOUND",
    "RT_TRAFFIC_REQUIRES_DYNAMIC",
    "RT_UNKNOWN_RUNTIME_STATE",
    "RuntimeCapabilities",
    "RuntimePlanValidationIssue",
    "RuntimePlanValidationResult",
    "STAGE_RUNTIME",
    "validate_plan_against_runtime_state",
]
