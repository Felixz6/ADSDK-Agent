"""Dynamic report derivation, process diagnostics, and summary assembly."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.config import SCHEMA_VERSION
from app.core.artifacts import atomic_write_json
from app.core.clock import utc_now as _utc_now
from app.core.run_context import AnalysisRunContext
from app.core.status import StepResult, StepStatus
from app.frida import ExecutionMode, build_evidence_quality
from app.frida.logcat_collector import LogcatCollector
from app.frida.process_monitor import classify_process_exit
from app.models import DynamicAnalyzeRequest
from app.orchestration.dynamic_collection import DynamicCollectionResult
from app.orchestration.timeline_rules import evaluate_timeline_rules
from app.pipelines.common import (
    StaticStageResult,
    _base_report,
    _step_result,
)
from app.pipelines.dynamic._shared import (
    _traffic_failure_summary,
    _traffic_summary_from_result,
)
from app.pipelines.dynamic.collection import (
    _session_status,
    _TrafficOutcome,
)
from app.pipelines.dynamic.sessions import (
    _DynamicEnvironment,
    _is_real_frida_factory,
)
from app.pipelines.dynamic.timeline import _build_dynamic_findings
from app.tools.utils import run_cmd


@dataclass(slots=True)
class _ExecutionOutcome:
    timeline_payload: dict[str, Any]
    consent_time: Any
    execution_decision: dict[str, Any]
    executor_strategy_receipt: dict[str, Any]
    environment_capabilities: dict[str, Any]
    evidence_quality: Any
    task_result: dict[str, Any]
    sessions_payload: dict[str, Any]


def _process_diagnostics_stage(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    context: AnalysisRunContext,
    environment: _DynamicEnvironment,
    collection_result: DynamicCollectionResult,
    traffic: _TrafficOutcome,
    dynamic_events: list[dict[str, Any]],
    hook_evidence_available: bool,
) -> dict[str, Any] | None:
    """Classify process exit/crash evidence when the real Frida path ran."""
    device_context = environment.device_context
    frida_session = environment.frida_session
    package_name = environment.package_name
    process_diagnostics_payload: dict[str, Any] | None = None
    dynamic_diagnostics_dir = context.run_dir / "dynamic"
    dynamic_diagnostics_dir.mkdir(parents=True, exist_ok=True)
    if (
        device_context is not None
        and frida_session is not None
        and _is_real_frida_factory(getattr(environment, "frida_session_factory", None))
    ):
        runtime_failure_sessions = list(getattr(frida_session, "runtime_failure_sessions", []))
        diagnostic_session = (
            runtime_failure_sessions[-1] if runtime_failure_sessions else frida_session
        )
        logcat_factory = getattr(environment.tools, "logcat_collector_factory", LogcatCollector)
        logcat = logcat_factory(
            device=device_context,
            package_name=package_name,
            output_dir=dynamic_diagnostics_dir,
        ).collect(pid=getattr(diagnostic_session, "pid", None))
        run_cmd_fn = getattr(environment.tools, "run_cmd", run_cmd)
        pid_result = run_cmd_fn(
            device_context.adb_command("shell", "pidof", package_name),
            timeout=10,
        )
        pid_text = str(pid_result.get("stdout") or "").strip()
        observed_pid = getattr(diagnostic_session, "pid", None)
        if observed_pid is None and pid_text:
            first_pid = pid_text.split()[0]
            observed_pid = int(first_pid) if first_pid.isdigit() else None
        timeline_for_process = collection_result.timeline.to_dict()
        start_ms = timeline_for_process.get("app_resumed_monotonic_ms")
        end_ms = timeline_for_process.get("collection_ended_monotonic_ms")
        duration_ms = getattr(
            diagnostic_session,
            "post_resume_survival_ms",
            None,
        )
        if duration_ms is None:
            duration_ms = (
                max(0, int(float(end_ms) - float(start_ms)))
                if start_ms is not None and end_ms is not None
                else None
            )
        process_diagnostics = classify_process_exit(
            pid=observed_pid,
            duration_ms=duration_ms,
            hook_ready=hook_evidence_available,
            hook_event_count=len(dynamic_events),
            detached_reason=getattr(
                diagnostic_session,
                "detached_reason",
                getattr(diagnostic_session, "error_code", None),
            ),
            logcat_lines=list(logcat["lines"]),
            process_still_running=(
                not runtime_failure_sessions
                and pid_result.get("returncode") == 0
                and bool(pid_text)
            ),
            crash=getattr(diagnostic_session, "crash", None),
        )
        process_diagnostics_payload = process_diagnostics.model_dump(mode="json")
        process_diagnostics_payload["final_process_result"] = (
            "running"
            if pid_result.get("returncode") == 0 and bool(pid_text)
            else process_diagnostics.status
        )
        atomic_write_json(
            dynamic_diagnostics_dir / "process-diagnostics.json",
            process_diagnostics_payload,
        )
        steps.append(
            _step_result(
                "process_monitoring",
                (
                    StepStatus.SUCCESS
                    if process_diagnostics.status == "running"
                    else StepStatus.PARTIAL
                ),
                _utc_now(),
                required=False,
                warnings=(
                    ["进程退出分类不等同于确定存在反调试"]
                    if process_diagnostics.status != "running"
                    else []
                ),
                details={
                    "status": process_diagnostics.status,
                    "confidence": process_diagnostics.confidence,
                },
            )
        )
    else:
        steps.append(
            _step_result(
                "process_monitoring",
                StepStatus.SKIPPED,
                _utc_now(),
                required=False,
                warnings=["当前兼容会话未启用 M4 进程诊断"],
            )
        )
    return process_diagnostics_payload


def _derive_execution_state(
    req: DynamicAnalyzeRequest,
    environment: _DynamicEnvironment,
    collection_result: DynamicCollectionResult,
    process_diagnostics_payload: dict[str, Any] | None,
) -> tuple[
    dict[str, Any],
    Any,
    ExecutionMode,
    list[Any],
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
]:
    """Derive timeline, execution decision, and capability state."""
    frida_session = environment.frida_session
    timeline_payload = collection_result.timeline.to_dict()
    consent_time = timeline_payload.get("consent_at")
    selected_mode = (
        getattr(frida_session, "selected_mode", ExecutionMode.SPAWN_SUSPENDED)
        if frida_session is not None
        else ExecutionMode.NONE
    )
    if isinstance(selected_mode, str):
        selected_mode = ExecutionMode(selected_mode)
    execution_attempts = list(getattr(frida_session, "attempts", []))
    if process_diagnostics_payload is not None:
        for attempt in execution_attempts:
            if getattr(attempt, "process_result", None) == "process_crashed":
                attempt.crash = dict(process_diagnostics_payload)
                break
    environment_capabilities = dict(getattr(frida_session, "environment_capabilities", {}))
    diagnostic_capabilities = (environment.frida_diagnostic_payload or {}).get("capabilities") or {}
    for key, value in diagnostic_capabilities.items():
        if environment_capabilities.get(key) is None:
            environment_capabilities[key] = value
    execution_decision = {
        "policy": req.dynamic_mode_policy,
        "selected_mode": selected_mode.value,
        "attempts": [
            item.model_dump(mode="json") if hasattr(item, "model_dump") else dict(item)
            for item in execution_attempts
        ],
        "fallback_path": list(getattr(frida_session, "fallback_path", [])),
        "launch_timing": dict(getattr(frida_session, "launch_timing", {})),
    }
    executor_strategy_receipt = {
        "executor_received_strategy": req.dynamic_mode_policy,
        "executor_execution_strategy": selected_mode.value,
        "executor_provenance_source": "app.pipelines.dynamic.execution_decision",
    }
    return (
        timeline_payload,
        consent_time,
        selected_mode,
        execution_attempts,
        environment_capabilities,
        execution_decision,
        executor_strategy_receipt,
    )


def _derive_task_result(
    selected_mode: ExecutionMode,
    execution_attempts: list[Any],
    process_diagnostics_payload: dict[str, Any] | None,
) -> dict[str, Any]:
    """Summarize each execution phase as observed from the session attempts."""
    crashed_attempt = next(
        (
            attempt
            for attempt in execution_attempts
            if getattr(attempt, "process_result", None) == "process_crashed"
        ),
        None,
    )
    return {
        "execution_mode": selected_mode.value,
        "spawn": (
            "success"
            if any(
                item.mode is ExecutionMode.SPAWN_SUSPENDED
                and item.phase in {"resumed", "post_resume_stability", "collecting"}
                for item in execution_attempts
            )
            else "not_observed"
        ),
        "attach": (
            "success"
            if any(
                item.phase
                in {"hook_loaded", "hook_ready", "resumed", "collecting", "post_resume_stability"}
                for item in execution_attempts
            )
            else "not_observed"
        ),
        "hook_load": (
            "success"
            if any(
                item.phase
                in {"hook_loaded", "hook_ready", "resumed", "collecting", "post_resume_stability"}
                for item in execution_attempts
            )
            else "not_observed"
        ),
        "resume": (
            "success"
            if any(
                item.phase in {"resumed", "post_resume_stability", "collecting"}
                for item in execution_attempts
            )
            else "not_observed"
        ),
        "process_result": (
            "process_crashed"
            if crashed_attempt is not None
            else (process_diagnostics_payload or {}).get("status")
        ),
        "crash_type": (process_diagnostics_payload or {}).get("crash_type"),
        "crash_signal": (process_diagnostics_payload or {}).get("signal"),
        "crash_code": (process_diagnostics_payload or {}).get("signal_code"),
        "crash_summary": (process_diagnostics_payload or {}).get("summary"),
    }


def _append_attempt_steps(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    execution_attempts: list[Any],
) -> None:
    """Record one step per execution attempt."""
    for attempt in execution_attempts:
        step_name = (
            "spawn_suspended_attempt"
            if attempt.mode is ExecutionMode.SPAWN_SUSPENDED
            else "attach_attempt"
            if attempt.mode is ExecutionMode.ATTACH_EXISTING
            else f"{attempt.mode.value}_attempt"
        )
        steps.append(
            _step_result(
                step_name,
                {
                    "success": StepStatus.SUCCESS,
                    "failed": StepStatus.FAILED,
                    "skipped": StepStatus.SKIPPED,
                }.get(attempt.status, StepStatus.PARTIAL),
                _utc_now(),
                required=(
                    req.dynamic_mode_policy == "strict"
                    and attempt.mode is ExecutionMode.SPAWN_SUSPENDED
                ),
                error_code=attempt.reason_code,
                error_message=(attempt.message if attempt.status == "failed" else None),
                details={"mode": attempt.mode.value},
            )
        )


def _append_execution_summary_steps(
    steps: list[StepResult],
    selected_mode: ExecutionMode,
    collection_result: DynamicCollectionResult,
    execution_decision: dict[str, Any],
    evidence_quality: Any,
) -> None:
    """Record mode selection, cleanup, and evidence evaluation steps."""
    steps.extend(
        [
            _step_result(
                "execution_mode_selection",
                (
                    StepStatus.SUCCESS
                    if selected_mode is not ExecutionMode.NONE
                    else StepStatus.FAILED
                ),
                _utc_now(),
                required=True,
                error_code=(
                    collection_result.primary_error_code
                    if selected_mode is ExecutionMode.NONE
                    else None
                ),
                error_message=(
                    "没有可用的动态执行模式" if selected_mode is ExecutionMode.NONE else None
                ),
                details=execution_decision,
            ),
            _step_result(
                "resource_cleanup",
                (StepStatus.PARTIAL if collection_result.cleanup_errors else StepStatus.SUCCESS),
                _utc_now(),
                required=True,
                warnings=list(collection_result.cleanup_errors),
            ),
            _step_result(
                "evidence_evaluation",
                StepStatus.SUCCESS,
                _utc_now(),
                required=True,
                details={
                    "level": evidence_quality.level,
                    "mode": evidence_quality.mode.value,
                    "limitations": evidence_quality.limitations,
                },
            ),
        ]
    )


def _build_sessions_payload(
    context: AnalysisRunContext,
    environment: _DynamicEnvironment,
    collection_result: DynamicCollectionResult,
    traffic: _TrafficOutcome,
    timeline_payload: dict[str, Any],
    execution_decision: dict[str, Any],
    environment_capabilities: dict[str, Any],
    task_result: dict[str, Any],
    evidence_quality: Any,
) -> dict[str, Any]:
    """Build and persist the collector-sessions artefact."""
    frida_session = environment.frida_session
    sessions_payload = {
        "schema_version": SCHEMA_VERSION,
        "run_id": context.run_id,
        "device": (
            environment.device_context.to_public_dict()
            if environment.device_context is not None
            else None
        ),
        "frida": (
            _session_status(frida_session, environment.device_context)
            if frida_session is not None and environment.device_context is not None
            else None
        ),
        "mitm": (traffic.mitm_public_status),
        "timeline": timeline_payload,
        "collection_status": collection_result.status,
        "cleanup_errors": list(collection_result.cleanup_errors),
        "execution": execution_decision,
        "environment_capabilities": environment_capabilities,
        "task_result": task_result,
        "evidence_quality": evidence_quality.model_dump(mode="json"),
    }
    atomic_write_json(context.sessions_path, sessions_payload)
    return sessions_payload


def _build_execution_outcome(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    context: AnalysisRunContext,
    environment: _DynamicEnvironment,
    collection_result: DynamicCollectionResult,
    traffic: _TrafficOutcome,
    process_diagnostics_payload: dict[str, Any] | None,
    hook_evidence_available: bool,
) -> _ExecutionOutcome:
    """Derive execution/timeline artefacts and append the remaining report steps."""
    frida_session = environment.frida_session
    (
        timeline_payload,
        consent_time,
        selected_mode,
        execution_attempts,
        environment_capabilities,
        execution_decision,
        executor_strategy_receipt,
    ) = _derive_execution_state(req, environment, collection_result, process_diagnostics_payload)
    evidence_quality = build_evidence_quality(
        selected_mode,
        transport_trusted=hook_evidence_available,
        hook_ready_trusted=hook_evidence_available,
        event_protocol_trusted=hook_evidence_available
        and not bool(getattr(frida_session, "protocol_errors", [])),
        consent_boundary_trusted=hook_evidence_available
        and (req.consent_after_seconds is None or consent_time is not None),
        network_evidence=traffic.network_evidence_available,
        early_lifecycle_verified=False,
        reason_codes=[
            code
            for code in (
                collection_result.primary_error_code,
                *[getattr(item, "reason_code", None) for item in execution_attempts],
            )
            if code
        ],
    )
    task_result = _derive_task_result(
        selected_mode, execution_attempts, process_diagnostics_payload
    )
    _append_attempt_steps(req, steps, execution_attempts)
    _append_execution_summary_steps(
        steps, selected_mode, collection_result, execution_decision, evidence_quality
    )
    sessions_payload = _build_sessions_payload(
        context,
        environment,
        collection_result,
        traffic,
        timeline_payload,
        execution_decision,
        environment_capabilities,
        task_result,
        evidence_quality,
    )
    return _ExecutionOutcome(
        timeline_payload=timeline_payload,
        consent_time=consent_time,
        execution_decision=execution_decision,
        executor_strategy_receipt=executor_strategy_receipt,
        environment_capabilities=environment_capabilities,
        evidence_quality=evidence_quality,
        task_result=task_result,
        sessions_payload=sessions_payload,
    )


def _assemble_dynamic_report(
    req: DynamicAnalyzeRequest,
    context: AnalysisRunContext,
    steps: list[StepResult],
    environment: _DynamicEnvironment,
    static_stage: StaticStageResult,
    collection_result: DynamicCollectionResult,
    dynamic_events: list[dict[str, Any]],
    traffic: _TrafficOutcome,
    execution: _ExecutionOutcome,
    process_diagnostics_payload: dict[str, Any] | None,
    hook_evidence_available: bool,
) -> dict[str, Any]:
    """Assemble the dynamic report body before correlation and publication."""
    dynamic_findings = _build_dynamic_findings(
        dynamic_events,
        evidence_available=hook_evidence_available,
    )
    evaluate_timeline_fn = getattr(
        environment.tools, "evaluate_timeline_rules", evaluate_timeline_rules
    )
    strict_dynamic_findings = evaluate_timeline_fn(
        events_json_path=str(context.events_path),
        consent_time=execution.consent_time,
        pre_consent_seconds=req.pre_consent_seconds,
        post_consent_seconds=req.post_consent_seconds,
        evidence_available=hook_evidence_available,
    )
    report = _base_report(
        context,
        app_info=static_stage.app_info,
        sdk_hits=static_stage.sdk_hits,
    )
    report.update(
        {
            "hook_log": str(context.hook_log_path),
            "events_raw_jsonl": str(context.events_raw_path),
            "events_json": str(context.events_path),
            "consent_time": execution.consent_time,
            "traffic_dir": str(context.traffic_dir),
            "traffic_jsonl": str(context.traffic_jsonl_path),
            "traffic_summary_json": str(context.traffic_summary_path),
            "sessions_json": str(context.sessions_path),
            "dynamic_events": dynamic_events,
            "dynamic_findings": dynamic_findings,
            "strict_dynamic_findings": strict_dynamic_findings,
            "traffic_summary": traffic.traffic_summary,
            "traffic_coverage": traffic.traffic_summary.get("coverage"),
            "pre_consent_seconds": req.pre_consent_seconds,
            "post_consent_seconds": req.post_consent_seconds,
            "enable_traffic": req.enable_traffic,
            "enable_ui_stimulation": req.enable_ui_stimulation,
            "collection_timeout_seconds": req.collection_timeout_seconds,
            "collection_status": collection_result.status,
            "dynamic_validation_level": execution.evidence_quality.level,
            "dynamic_execution": execution.execution_decision,
            "executor_strategy_receipt": execution.executor_strategy_receipt,
            "environment_capabilities": execution.environment_capabilities,
            "dynamic_task_result": execution.task_result,
            "dynamic_evidence_quality": execution.evidence_quality.model_dump(mode="json"),
            "frida_diagnostics": environment.frida_diagnostic_payload,
            "process_diagnostics": process_diagnostics_payload,
            "traffic_diagnostics": (
                traffic.traffic_diagnostics.model_dump(mode="json")
                if traffic.traffic_diagnostics is not None
                else None
            ),
            "dynamic_timeline": execution.timeline_payload,
            "collector_sessions": execution.sessions_payload,
            "manifest_evidence": static_stage.manifest_evidence,
            "device": (
                environment.device_context.to_public_dict()
                if environment.device_context is not None
                else None
            ),
            "limitations": [
                "SSL pinning can reduce traffic visibility",
                "the in-process mitm port pool is limited to one Uvicorn worker",
                "event-request correlation expresses temporal proximity, not causality",
                *(
                    [
                        "Manifest evidence unavailable; Manifest-dependent conclusions were not evaluated"
                    ]
                    if static_stage.manifest_evidence["status"] != "evaluated"
                    else []
                ),
            ],
        }
    )
    return report


__all__ = [
    "_ExecutionOutcome",
    "_append_attempt_steps",
    "_append_execution_summary_steps",
    "_assemble_dynamic_report",
    "_build_execution_outcome",
    "_build_sessions_payload",
    "_derive_execution_state",
    "_derive_task_result",
    "_process_diagnostics_stage",
    "_traffic_failure_summary",
    "_traffic_summary_from_result",
]
