"""Dynamic analysis pipeline implementation."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from fastapi.responses import JSONResponse

from app.config import (
    FRIDA_READY_TIMEOUT_SECONDS,
    FRIDA_SPAWN_STABILITY_SECONDS,
    FRIDA_STOP_TIMEOUT_SECONDS,
    MITM_DEVICE_PROXY_HOST,
    MITM_LISTEN_HOST,
    MITM_READY_TIMEOUT_SECONDS,
    MITM_STOP_TIMEOUT_SECONDS,
    SCHEMA_VERSION,
)
from app.container import Container
from app.core.artifacts import atomic_write_json, atomic_write_text
from app.core.clock import utc_now as _utc_now
from app.core.device import DeviceContext
from app.core.run_context import AnalysisRunContext
from app.core.status import StepResult, StepStatus
from app.frida import (
    DynamicModePolicy,
    ExecutionMode,
    FridaDiagnosticsRequest,
    PolicyFridaSession,
    build_evidence_quality,
)
from app.frida.frida_session import FridaSession, FridaSessionError
from app.frida.hook_parser import parse_hook_to_events_json
from app.frida.logcat_collector import LogcatCollector
from app.frida.process_monitor import classify_process_exit
from app.frida.traffic_diagnostics import diagnose_traffic
from app.models import DynamicAnalyzeRequest
from app.orchestration.cleanup_manager import ResourceOwnershipRegistry
from app.orchestration.dynamic_collection import (
    DynamicCollectionConfig,
    DynamicCollectionResult,
    run_dynamic_collection,
)
from app.orchestration.timeline_rules import classify_consent_state, evaluate_timeline_rules
from app.pipelines.common import (
    StaticStageResult,
    _base_report,
    _build_and_write_evidence_correlation,
    _build_and_write_privacy_findings,
    _finalize_report,
    _has_trusted_consent_boundary,
    _prepare_run,
    _redact_device_diagnostic,
    _step_result,
    resolve_frida_hook_script,
    run_static_stage,
)
from app.tasks.runtime import register_cleanup, report_step
from app.tools.adb_runner import (
    DeviceSelectionError,
    install_apk,
    launch_app,
    select_device_context,
)
from app.tools.utils import now_iso, run_cmd
from app.traffic.traffic_events import (
    TrafficCollectionOutcome,
    TrafficCollectionResult,
)
from app.traffic.traffic_parser import (
    write_traffic_summary,
)


def _build_dynamic_findings(
    events: list[dict],
    *,
    evidence_available: bool = True,
) -> dict:
    secure_calls = 0
    android_id_calls = 0
    clipboard_calls = 0

    for event in events:
        api = event.get("api")
        arg = event.get("arg")

        if api == "Settings.Secure.getString":
            secure_calls += 1
            if arg == "android_id" or event.get("identifier_type") == "android_id":
                android_id_calls += 1
        elif api == "ClipboardManager.getPrimaryClip":
            clipboard_calls += 1

    if not evidence_available:
        pre_consent_evaluation = "not_evaluated"
        high_frequency_evaluation = "not_evaluated"
    else:
        pre_consent_evaluation = "matched" if secure_calls > 0 else "not_matched"
        high_frequency_evaluation = (
            "matched" if android_id_calls > 3 or clipboard_calls > 1 else "not_matched"
        )

    def legacy_status(value: str) -> str:
        if value == "matched":
            return "suspicious"
        if value == "not_matched":
            return "not_detected"
        return value

    pre_consent_status = legacy_status(pre_consent_evaluation)
    high_frequency_status = legacy_status(high_frequency_evaluation)

    return {
        "rules": [
            {
                "rule_id": "pre_consent_sensitive_access",
                "status": pre_consent_evaluation,
                "legacy_status": pre_consent_status,
                "secure_getstring_count": secure_calls,
                "android_id_count": android_id_calls,
            },
            {
                "rule_id": "high_frequency_sensitive_access",
                "status": high_frequency_evaluation,
                "legacy_status": high_frequency_status,
                "android_id_count": android_id_calls,
                "clipboard_count": clipboard_calls,
                "android_id_threshold": 3,
                "clipboard_threshold": 1,
            },
        ],
        "summary": {
            "pre_consent_sensitive_access": pre_consent_status,
            "high_frequency_sensitive_access": high_frequency_status,
        },
        "evaluation_summary": {
            "pre_consent_sensitive_access": pre_consent_evaluation,
            "high_frequency_sensitive_access": high_frequency_evaluation,
        },
    }


def _state_value(session: Any) -> str:
    state = getattr(session, "state", "created")
    return str(getattr(state, "value", state))


def _emit_frida_control(session: Any, event: dict[str, Any]) -> Any:
    name = event.get("event")
    if name == "collection_started":
        method = getattr(session, "emit_collection_started", None)
        if callable(method):
            return method()
    if name == "consent_granted":
        method = getattr(session, "emit_consent", None)
        if callable(method):
            return method(source=str(event.get("source") or "configured_delay"))
    method = getattr(session, "emit_control_event", None)
    if callable(method):
        return method(event)
    raise RuntimeError("Frida session has no structured control writer")


def _normalize_events(
    source_path: Path,
    output_path: Path,
    *,
    device_context: DeviceContext | None,
) -> list[dict[str, Any]]:
    events = parse_hook_to_events_json(
        str(source_path),
        str(output_path),
        sensitive_identifiers=(
            {"device_serial": device_context.serial} if device_context is not None else None
        ),
    )
    consent_ms: float | int | None = None
    for event in events:
        if event.get("type") == "control" and event.get("event") == "consent_granted":
            consent_ms = event.get("monotonic_ms")
            break
    for event in events:
        if event.get("type") != "event":
            continue
        if event.get("legacy_format") is True or not event.get(
            "timing_reliable",
            True,
        ):
            event["consent_state"] = "unknown"
        else:
            event["consent_state"] = classify_consent_state(
                event.get("monotonic_ms"),
                consent_ms,
            )
    atomic_write_json(output_path, events)
    return events


def _traffic_summary_from_result(
    result: TrafficCollectionResult,
) -> dict[str, Any]:
    hosts = Counter(record.hostname for record in result.records)
    failed = result.outcome is TrafficCollectionOutcome.COLLECTOR_FAILED
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "failed" if failed else "success",
        "evaluation_status": "not_evaluated" if failed else "not_matched",
        "coverage": result.coverage,
        "collector_outcome": result.outcome.value,
        "warnings": (
            ["traffic collector did not produce trustworthy evidence"]
            if failed
            else (
                ["collector succeeded; no HTTP requests were observed"]
                if result.valid_request_count == 0
                else []
            )
        ),
        "total_requests": result.valid_request_count,
        "top_hosts": [{"host": host, "count": count} for host, count in hosts.most_common(20)],
        "sample_requests": [record.model_dump(mode="json") for record in result.records[:50]],
        "validation": result.to_dict(),
    }


def _session_status(session: Any, device: DeviceContext) -> dict[str, Any]:
    method = getattr(session, "to_status", None)
    value = method() if callable(method) else {}
    safe = {
        "run_id": value.get("run_id", getattr(session, "run_id", None)),
        "session_id": value.get(
            "session_id",
            getattr(session, "session_id", None),
        ),
        "state": value.get("state", _state_value(session)),
        "device": device.to_public_dict(),
        "pid": value.get("pid", getattr(session, "pid", None)),
        "port": value.get("port", getattr(session, "listen_port", None)),
        "error_code": value.get(
            "error_code",
            getattr(session, "error_code", None),
        ),
        "error": _redact_device_diagnostic(
            value.get("error", getattr(session, "error_message", None)),
            device,
        ),
    }
    command = value.get("command")
    if isinstance(command, list):
        safe["command"] = [_redact_device_diagnostic(argument, device) for argument in command]
    for name in (
        "listen_host",
        "listen_port",
        "addon_path",
        "ready_timeout",
        "stderr_tail",
        "exit_code",
        "device_proxy_host",
        "device_proxy_configured",
        "device_proxy_restored",
        "proxy_reachable",
        "proxy_probe_available",
        "network_observation",
        "started_at",
        "ready_at",
        "stopped_at",
    ):
        if value.get(name) is not None:
            item = value[name]
            safe[name] = _redact_device_diagnostic(item, device) if isinstance(item, str) else item
    for name in (
        "traffic_dir",
        "flow_file",
        "jsonl_path",
        "stderr_path",
        "event_log_path",
    ):
        if value.get(name) is not None:
            safe[name] = value[name]
    return safe


def _append_collection_steps(
    steps: list[StepResult],
    result: DynamicCollectionResult,
    *,
    enable_traffic: bool,
    consent_configured: bool,
    frida_session: Any,
) -> None:
    names = (
        "mitm_start",
        "mitm_ready",
        "frida_spawn",
        "frida_script_load",
        "frida_ready",
        "app_resume",
        "dynamic_collection",
        "consent_event",
        "frida_stop",
        "mitm_stop",
    )
    required = {
        "frida_spawn",
        "frida_script_load",
        "frida_ready",
        "app_resume",
        "dynamic_collection",
    }
    network_only = bool(
        enable_traffic
        and result.outcomes.get("mitm_ready") == "success"
        and result.outcomes.get("frida_ready") != "success"
        and result.outcomes.get("app_resume") == "success"
    )
    if network_only:
        required.difference_update({"frida_spawn", "frida_script_load", "frida_ready"})
    for name in names:
        status_text = result.outcomes.get(name)
        if status_text is None:
            if name.startswith("mitm_") and not enable_traffic:
                status_text = "skipped"
            elif name == "consent_event" and not consent_configured:
                status_text = "skipped"
            else:
                status_text = "skipped"
        status = StepStatus(status_text)
        error_code = None
        error_message = None
        if status is StepStatus.FAILED:
            error_code = result.primary_error_code or f"{name}_failed"
            error_message = result.primary_error or f"{name} failed"
        details: dict[str, Any] = {}
        if name == "frida_ready":
            details = {
                "installed_hooks": list(getattr(frida_session, "installed_hooks", [])),
                "failed_hooks": list(getattr(frida_session, "failed_hooks", [])),
            }
            if status is StepStatus.SUCCESS and details["failed_hooks"]:
                status = StepStatus.PARTIAL
        steps.append(
            _step_result(
                name,
                status,
                _utc_now(),
                required=name in required,
                error_code=error_code,
                error_message=error_message,
                warnings=(
                    list(result.cleanup_errors) if name in {"frida_stop", "mitm_stop"} else []
                ),
                details=details,
            )
        )


@dataclass(slots=True)
class _DynamicEnvironment:
    context: AnalysisRunContext
    device_context: DeviceContext | None
    device_failure: bool
    install_ok: bool
    package_name: str
    frida_session: Any
    mitm_session: Any
    frida_diagnostic_payload: dict[str, Any] | None
    stimulate_ui: Any
    register_frida_started: Any
    frida_session_factory: Any = None


@dataclass(slots=True)
class _TrafficOutcome:
    traffic_summary: dict[str, Any]
    correlation_requests: list[dict[str, Any]]
    network_evidence_available: bool
    traffic_diagnostics: Any
    mitm_public_status: dict[str, Any] | None


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


def _install_and_select_device(
    req: DynamicAnalyzeRequest,
    context: AnalysisRunContext,
    steps: list[StepResult],
    static_stage: StaticStageResult,
) -> tuple[AnalysisRunContext, DeviceContext | None, bool, bool, str]:
    """Select the target device and install the APK when the policy requires it."""
    unpack_ok = static_stage.unpack_ok
    package_name = static_stage.package_name or ""

    device_context: DeviceContext | None = None
    device_failure = False
    started = _utc_now()
    if unpack_ok and package_name:
        try:
            device_context = select_device_context(req.device_id)
            context = replace(context, device_id=device_context.serial)
            steps.append(
                _step_result(
                    "device_selection",
                    StepStatus.SUCCESS,
                    started,
                    required=True,
                    details={"device": device_context.to_public_dict()},
                )
            )
        except DeviceSelectionError as exc:
            device_failure = True
            steps.append(
                _step_result(
                    "device_selection",
                    StepStatus.FAILED,
                    started,
                    required=True,
                    error_code=exc.code,
                    error_message=exc.message,
                )
            )
    else:
        steps.append(
            _step_result(
                "device_selection",
                StepStatus.SKIPPED,
                started,
                required=True,
                warnings=["runtime package or unpacked APK is unavailable"],
            )
        )

    install_ok = False
    started = _utc_now()
    if (
        device_context is not None
        and req.dynamic_mode_policy == DynamicModePolicy.ATTACH_ONLY.value
    ):
        install_ok = True
        steps.append(
            _step_result(
                "apk_install",
                StepStatus.SKIPPED,
                started,
                required=False,
                warnings=["attach_only 保留当前目标进程，本次任务跳过 APK 重新安装"],
            )
        )
    elif device_context is not None:
        try:
            install_result = install_apk(
                str(context.apk_path),
                device_context=device_context,
            )
        except Exception as exc:
            install_result = {
                "returncode": -1,
                "stderr": f"ADB install failed: {type(exc).__name__}",
            }
        install_ok = install_result.get("returncode") == 0
        steps.append(
            _step_result(
                "apk_install",
                StepStatus.SUCCESS if install_ok else StepStatus.FAILED,
                started,
                required=True,
                error_code=None if install_ok else "apk_install_failed",
                error_message=(
                    None
                    if install_ok
                    else _redact_device_diagnostic(
                        install_result.get("stderr")
                        or install_result.get("stdout")
                        or "ADB install failed",
                        device_context,
                    )
                ),
            )
        )
    else:
        steps.append(
            _step_result(
                "apk_install",
                StepStatus.SKIPPED,
                started,
                required=True,
            )
        )

    atomic_write_text(
        context.hook_log_path,
        f"[INFO] {now_iso()} structured dynamic collection prepared\n",
    )
    return context, device_context, device_failure, install_ok, package_name


def _noop_register_runtime_target(pid: int, *, ownership_source: str, created_by_run: bool) -> None:
    # Compatibility collectors never manufacture Android target ownership from
    # a host-side helper process.
    del pid, ownership_source, created_by_run


def _is_real_frida_factory(factory: Any) -> bool:
    if factory is None:
        return True
    if getattr(factory, "_is_real_frida", False):
        return True
    if factory is FridaSession:
        return True
    name = getattr(factory, "__name__", "")
    return name in ("FridaSession", "default_frida_session_factory")


def _report_frida_diagnostics(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    device_context: DeviceContext,
    package_name: str,
    diagnostics_service: Any = None,
) -> dict[str, Any]:
    """Run the layered Frida diagnostics and record its step."""
    report_step("frida_diagnostics", "running", "正在执行 Frida 分层诊断")
    if diagnostics_service is None:
        from app.config import (
            FRIDA_SERVER_MANAGEMENT_ENABLED,
            FRIDA_SERVER_REMOTE_PATH,
        )
        from app.frida import FridaDiagnosticsService

        diagnostics_service = FridaDiagnosticsService(
            project_root=Path(__file__).resolve().parent.parent.parent,
            server_remote_path=FRIDA_SERVER_REMOTE_PATH,
            management_enabled=FRIDA_SERVER_MANAGEMENT_ENABLED,
        )
    diagnostic_result = diagnostics_service.diagnose(
        FridaDiagnosticsRequest(
            device_id=device_context.serial,
            package_name=package_name,
        )
    )
    frida_diagnostic_payload = diagnostic_result.model_dump(mode="json")
    diagnostic_status = (
        StepStatus.SUCCESS
        if diagnostic_result.overall_status == "ready"
        else StepStatus.PARTIAL
        if diagnostic_result.overall_status == "degraded"
        else StepStatus.FAILED
    )
    steps.append(
        _step_result(
            "frida_diagnostics",
            diagnostic_status,
            _utc_now(),
            required=req.dynamic_mode_policy == "strict",
            error_code=(
                diagnostic_result.issues[0].code
                if diagnostic_status is StepStatus.FAILED and diagnostic_result.issues
                else None
            ),
            error_message=(
                diagnostic_result.issues[0].summary
                if diagnostic_status is StepStatus.FAILED and diagnostic_result.issues
                else None
            ),
            details={
                "overall_status": diagnostic_result.overall_status,
                "recommended_mode": diagnostic_result.recommended_mode,
                "device_ref": diagnostic_result.device_ref,
            },
        )
    )
    return frida_diagnostic_payload


def _make_launch_target_for_attach(
    context: AnalysisRunContext,
    device_context: DeviceContext,
    package_name: str,
    register_runtime_target: Any,
) -> Any:
    """Launch the target and resolve the exact PID for attach-then-verify."""

    def launch_target_for_attach() -> dict[str, Any]:
        launch_requested = _utc_now()
        launch_result = launch_app(
            package_name,
            device_context=device_context,
        )
        if launch_result.get("returncode") != 0:
            raise FridaSessionError(
                "package_launch_failed",
                "Target package launch command failed",
            )
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline:
            pid_result = run_cmd(
                device_context.adb_command("shell", "pidof", package_name),
                timeout=3,
            )
            if pid_result.get("returncode") == 0 and str(pid_result.get("stdout") or "").strip():
                pid_observed = _utc_now()
                pid_text = str(pid_result.get("stdout") or "").strip().split()[0]
                pid = int(pid_text) if pid_text.isdigit() else 0
                if pid <= 0:
                    continue
                # Atomic production boundary: the launch command succeeded and
                # the exact resulting PID is known.
                register_runtime_target(
                    pid,
                    ownership_source="launch_then_attach_pidof",
                    created_by_run=True,
                )
                return {
                    "launch_requested_at": launch_requested.isoformat(
                        timespec="milliseconds"
                    ).replace("+00:00", "Z"),
                    "pid_observed_at": pid_observed.isoformat(timespec="milliseconds").replace(
                        "+00:00", "Z"
                    ),
                    "_launch_requested_datetime": launch_requested,
                    "pid": pid,
                }
            time.sleep(0.25)
        raise FridaSessionError(
            "package_process_not_found",
            "Target package did not expose a process after launch",
        )

    return launch_target_for_attach


def _build_real_frida_session(
    req: DynamicAnalyzeRequest,
    context: AnalysisRunContext,
    steps: list[StepResult],
    device_context: DeviceContext,
    package_name: str,
    script_path: Path,
    ownership_registry: ResourceOwnershipRegistry | None,
    register_runtime_target: Any,
    frida_session_factory: Any = None,
    diagnostics_service: Any = None,
) -> tuple[Any, dict[str, Any] | None, Any]:
    """Build the real Frida session (policy or single-mode) and its diagnostics."""
    factory = frida_session_factory or FridaSession
    is_real_frida = _is_real_frida_factory(factory)
    frida_session: Any = None
    frida_diagnostic_payload: dict[str, Any] | None = None
    if is_real_frida:
        frida_diagnostic_payload = _report_frida_diagnostics(
            req, steps, device_context, package_name, diagnostics_service=diagnostics_service
        )
        # Mirrors the original late binding: only the diagnostics branch
        # replaces the no-op registrar with the ownership-tracking one.
        register_runtime_target = _register_owned_target(
            context, device_context, package_name, ownership_registry
        )

        def make_frida_session(mode: ExecutionMode) -> FridaSession:
            return factory(
                run_id=context.run_id,
                device=device_context,
                package_name=package_name,
                script_path=script_path,
                event_log_path=context.events_raw_path,
                protocol_error_path=(context.run_dir / "frida.protocol-errors.jsonl"),
                stop_timeout_seconds=FRIDA_STOP_TIMEOUT_SECONDS,
                execution_mode=(
                    ExecutionMode.ATTACH_EXISTING.value
                    if mode is ExecutionMode.LAUNCH_THEN_ATTACH
                    else mode.value
                ),
            )

        frida_session = PolicyFridaSession(
            policy=DynamicModePolicy(req.dynamic_mode_policy),
            session_factory=make_frida_session,
            launch_target=_make_launch_target_for_attach(
                context,
                device_context,
                package_name,
                register_runtime_target,
            ),
        )
    else:
        frida_session = factory(
            run_id=context.run_id,
            device=device_context,
            package_name=package_name,
            script_path=script_path,
            event_log_path=context.events_raw_path,
            protocol_error_path=(context.run_dir / "frida.protocol-errors.jsonl"),
            stop_timeout_seconds=FRIDA_STOP_TIMEOUT_SECONDS,
        )
    return frida_session, frida_diagnostic_payload, register_runtime_target


def _make_collection_callbacks(
    context: AnalysisRunContext,
    device_context: DeviceContext,
    package_name: str,
    ownership_registry: ResourceOwnershipRegistry | None,
    register_runtime_target: Any,
) -> tuple[Any, Any]:
    """Create the UI-stimulation and Frida-started ownership callbacks."""

    def stimulate_ui() -> None:
        result = launch_app(
            package_name,
            device_context=device_context,
        )
        if result.get("returncode") != 0:
            raise RuntimeError("UI stimulation failed")

    def register_frida_started(session: Any) -> None:
        pid = getattr(session, "pid", None)
        if not isinstance(pid, int) or pid <= 0:
            return
        selected = getattr(session, "selected_mode", None)
        mode = getattr(selected, "value", selected)
        register_runtime_target(
            pid,
            ownership_source=(
                "frida_spawn"
                if mode == ExecutionMode.SPAWN_SUSPENDED.value
                else "frida_attach_existing"
            ),
            created_by_run=mode == ExecutionMode.SPAWN_SUSPENDED.value,
        )
        helper_pid = getattr(session, "helper_pid", None)
        if ownership_registry is not None and isinstance(helper_pid, int) and helper_pid > 0:
            ownership_registry.mark_owned(
                "frida_helper",
                str(helper_pid),
                pid=helper_pid,
                device_id=device_context.serial,
                expected_command_token="re.frida.helper",
                preexisting=False,
                created_by_run=True,
                cleanup_required=True,
                verification_required=True,
                ownership_source="frida_session_helper_start",
                registered_at_stage="helper_pid_available",
                run_id=context.run_id,
            )

    return stimulate_ui, register_frida_started


def _register_owned_target(
    context: AnalysisRunContext,
    device_context: DeviceContext,
    package_name: str,
    ownership_registry: ResourceOwnershipRegistry | None,
) -> Any:
    """Return the runtime-target registrar for the real Frida path."""

    def register_runtime_target(
        pid: int,
        *,
        ownership_source: str,
        created_by_run: bool,
    ) -> None:
        if ownership_registry is None or pid <= 0:
            return
        detail = {
            "pid": pid,
            "device_id": device_context.serial,
            "expected_command_token": package_name,
            "preexisting": not created_by_run,
            "created_by_run": created_by_run,
            "cleanup_required": created_by_run,
            "verification_required": created_by_run,
            "ownership_source": ownership_source,
            "registered_at_stage": "target_pid_available",
            "run_id": context.run_id,
        }
        if created_by_run:
            ownership_registry.mark_owned("app_process", str(pid), **detail)
        else:
            ownership_registry.mark_external("app_process", str(pid), **detail)

    return register_runtime_target


def _build_dynamic_sessions(
    req: DynamicAnalyzeRequest,
    context: AnalysisRunContext,
    steps: list[StepResult],
    device_context: DeviceContext | None,
    package_name: str,
    *,
    ownership_registry: ResourceOwnershipRegistry | None,
    frida_session_factory: Any = None,
    mitm_session_factory: Any = None,
    diagnostics_service: Any = None,
) -> tuple[
    Any,
    Any,
    dict[str, Any] | None,
    Any,
    Any,
]:
    """Create the Frida/MITM session objects and their collection callbacks."""
    if device_context is None:
        return None, None, None, None, None

    script_path = resolve_frida_hook_script()
    frida_session, frida_diagnostic_payload, register_runtime_target = _build_real_frida_session(
        req,
        context,
        steps,
        device_context,
        package_name,
        script_path,
        ownership_registry,
        _noop_register_runtime_target,
        frida_session_factory=frida_session_factory,
        diagnostics_service=diagnostics_service,
    )
    mitm_session: Any = None
    if req.enable_traffic:
        from app.traffic.mitm_session import MitmSession

        mitm_factory = mitm_session_factory or MitmSession
        mitm_session = mitm_factory(
            run_id=context.run_id,
            device=device_context,
            traffic_dir=context.traffic_dir,
            listen_host=MITM_LISTEN_HOST,
            device_proxy_host=MITM_DEVICE_PROXY_HOST,
            stop_timeout=MITM_STOP_TIMEOUT_SECONDS,
            package_name=package_name,
        )

    register_cleanup(frida_session.stop)
    if mitm_session is not None:
        register_cleanup(mitm_session.stop)

    stimulate_ui, register_frida_started = _make_collection_callbacks(
        context,
        device_context,
        package_name,
        ownership_registry,
        register_runtime_target,
    )
    return (
        frida_session,
        mitm_session,
        frida_diagnostic_payload,
        stimulate_ui,
        register_frida_started,
    )


def _run_collection_stage(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    context: AnalysisRunContext,
    environment: _DynamicEnvironment,
) -> DynamicCollectionResult:
    """Run the collection lifecycle (including its cleanup) or record prerequisites failure."""
    frida_session = environment.frida_session
    mitm_session = environment.mitm_session

    if environment.install_ok and environment.device_context is not None:
        collection_result = run_dynamic_collection(
            frida_session=frida_session,
            mitm_session=mitm_session,
            config=DynamicCollectionConfig(
                consent_after_seconds=req.consent_after_seconds,
                pre_consent_seconds=req.pre_consent_seconds,
                post_consent_seconds=req.post_consent_seconds,
                collection_timeout_seconds=req.collection_timeout_seconds,
                frida_ready_timeout_seconds=FRIDA_READY_TIMEOUT_SECONDS,
                frida_spawn_stability_seconds=FRIDA_SPAWN_STABILITY_SECONDS,
                frida_stop_timeout_seconds=FRIDA_STOP_TIMEOUT_SECONDS,
                mitm_ready_timeout_seconds=MITM_READY_TIMEOUT_SECONDS,
                mitm_stop_timeout_seconds=MITM_STOP_TIMEOUT_SECONDS,
                enable_traffic=req.enable_traffic,
                enable_ui_stimulation=req.enable_ui_stimulation,
            ),
            emit_control_event=lambda event: _emit_frida_control(
                frida_session,
                event,
            ),
            stimulate_ui=environment.stimulate_ui,
            on_frida_started=environment.register_frida_started,
            resume_without_frida=environment.stimulate_ui,
        )
        _append_collection_steps(
            steps,
            collection_result,
            enable_traffic=req.enable_traffic,
            consent_configured=req.consent_after_seconds is not None,
            frida_session=frida_session,
        )
        return collection_result

    collection_result = DynamicCollectionResult(
        status="failed",
        timeline=__import__(
            "app.orchestration.dynamic_collection",
            fromlist=["DynamicTimeline"],
        ).DynamicTimeline(
            session_created_at=_utc_now(),
            session_created_monotonic_ms=time.monotonic() * 1000.0,
        ),
        primary_error_code="dynamic_prerequisite_failed",
        primary_error="dynamic prerequisites failed",
    )
    for name in (
        "mitm_start",
        "mitm_ready",
        "frida_spawn",
        "frida_script_load",
        "frida_ready",
        "app_resume",
        "dynamic_collection",
        "consent_event",
        "frida_stop",
        "mitm_stop",
    ):
        steps.append(
            _step_result(
                name,
                StepStatus.SKIPPED,
                _utc_now(),
                required=name
                in {
                    "frida_spawn",
                    "frida_script_load",
                    "frida_ready",
                    "app_resume",
                    "dynamic_collection",
                },
            )
        )
    return collection_result


def _collect_events_stage(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    context: AnalysisRunContext,
    environment: _DynamicEnvironment,
    collection_result: DynamicCollectionResult,
) -> tuple[list[dict[str, Any]], bool]:
    """Normalize hook events and report their validation step."""
    frida_session = environment.frida_session
    hook_evidence_available = bool(
        collection_result
        and collection_result.status in {"success", "partial"}
        and frida_session is not None
        and collection_result.outcomes.get("frida_ready") == "success"
    )
    network_collector_available = bool(
        req.enable_traffic
        and collection_result
        and collection_result.status in {"success", "partial"}
        and collection_result.outcomes.get("mitm_ready") == "success"
    )
    dynamic_events: list[dict[str, Any]] = []
    event_started = _utc_now()
    if not hook_evidence_available and network_collector_available:
        atomic_write_json(context.events_path, [])
        steps.append(
            _step_result(
                "event_validation",
                StepStatus.SKIPPED,
                event_started,
                required=False,
                warnings=["Frida hook evidence unavailable; network-only collection retained"],
                details={"event_count": 0, "protocol_error_count": 0},
            )
        )
        context.events_raw_path.touch(exist_ok=True)
        return dynamic_events, hook_evidence_available

    try:
        dynamic_events = _normalize_events(
            context.events_raw_path,
            context.events_path,
            device_context=environment.device_context,
        )
        event_status = (
            StepStatus.PARTIAL
            if getattr(frida_session, "protocol_errors", [])
            else StepStatus.SUCCESS
        )
        if not hook_evidence_available:
            raise RuntimeError("Frida collector did not become trustworthy")
        steps.append(
            _step_result(
                "event_validation",
                event_status,
                event_started,
                required=True,
                outputs=[str(context.events_path)],
                details={
                    "event_count": len(dynamic_events),
                    "protocol_error_count": len(getattr(frida_session, "protocol_errors", [])),
                },
            )
        )
    except Exception as exc:
        dynamic_events = []
        hook_evidence_available = False
        atomic_write_json(context.events_path, [])
        steps.append(
            _step_result(
                "event_validation",
                StepStatus.FAILED,
                event_started,
                required=True,
                error_code="hook_evidence_unavailable",
                error_message=(f"hook evidence unavailable: {type(exc).__name__}"),
            )
        )
    finally:
        context.events_raw_path.touch(exist_ok=True)
    return dynamic_events, hook_evidence_available


def _traffic_failure_summary(message: str) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "status": "failed",
        "evaluation_status": "not_evaluated",
        "coverage": "unavailable",
        "collector_outcome": "collector_failed",
        "warnings": [message],
        "total_requests": 0,
        "top_hosts": [],
        "sample_requests": [],
    }


def _collect_disabled_traffic(
    steps: list[StepResult],
    context: AnalysisRunContext,
    traffic_started: Any,
) -> dict[str, Any]:
    traffic_summary = {
        "schema_version": SCHEMA_VERSION,
        "status": "skipped",
        "evaluation_status": "not_evaluated",
        "coverage": "unavailable",
        "collector_outcome": "collector_disabled",
        "warnings": ["traffic collection was explicitly disabled"],
        "total_requests": 0,
        "top_hosts": [],
        "sample_requests": [],
    }
    context.traffic_jsonl_path.touch(exist_ok=True)
    context.mitm_stderr_path.touch(exist_ok=True)
    steps.append(
        _step_result(
            "traffic_validation",
            StepStatus.SKIPPED,
            traffic_started,
            required=False,
        )
    )
    return traffic_summary


def _collect_session_traffic(
    steps: list[StepResult],
    mitm_session: Any,
    traffic_started: Any,
) -> tuple[dict[str, Any], list[dict[str, Any]]]:
    try:
        traffic_result = mitm_session.validate_traffic()
        traffic_summary = _traffic_summary_from_result(traffic_result)
        correlation_requests = [record.model_dump(mode="json") for record in traffic_result.records]
        traffic_status = (
            StepStatus.FAILED
            if traffic_result.outcome is TrafficCollectionOutcome.COLLECTOR_FAILED
            else StepStatus.SUCCESS
        )
        steps.append(
            _step_result(
                "traffic_validation",
                traffic_status,
                traffic_started,
                required=False,
                error_code=(
                    "traffic_collector_failed" if traffic_status is StepStatus.FAILED else None
                ),
                error_message=(
                    "traffic collector evidence is unavailable"
                    if traffic_status is StepStatus.FAILED
                    else None
                ),
                details=traffic_result.to_dict(),
            )
        )
        return traffic_summary, correlation_requests
    except Exception as exc:
        traffic_summary = _traffic_failure_summary(
            f"traffic validation failed: {type(exc).__name__}"
        )
        steps.append(
            _step_result(
                "traffic_validation",
                StepStatus.FAILED,
                traffic_started,
                required=False,
                error_code="traffic_evidence_unavailable",
                error_message=traffic_summary["warnings"][0],
            )
        )
        return traffic_summary, []


def _record_traffic_diagnostics(
    steps: list[StepResult],
    context: AnalysisRunContext,
    traffic_summary: dict[str, Any],
    mitm_public_status: dict[str, Any] | None,
) -> Any:
    try:
        mitm_stderr_text = context.mitm_stderr_path.read_text(encoding="utf-8", errors="replace")[
            -64 * 1024 :
        ]
    except OSError:
        mitm_stderr_text = ""
    traffic_diagnostics = diagnose_traffic(
        collector_outcome=str(traffic_summary.get("collector_outcome") or "collector_failed"),
        request_count=int(traffic_summary.get("total_requests") or 0),
        session_status=mitm_public_status,
        stderr_text=mitm_stderr_text,
    )
    dynamic_diagnostics_dir = context.run_dir / "dynamic"
    dynamic_diagnostics_dir.mkdir(parents=True, exist_ok=True)
    atomic_write_json(
        dynamic_diagnostics_dir / "traffic-diagnostics.json",
        traffic_diagnostics.model_dump(mode="json"),
    )
    steps.append(
        _step_result(
            "network_diagnostics",
            (StepStatus.PARTIAL if traffic_diagnostics.reason_codes else StepStatus.SUCCESS),
            _utc_now(),
            required=False,
            warnings=list(traffic_diagnostics.limitations),
            details={
                "outcome": traffic_diagnostics.outcome,
                "proxy_status": traffic_diagnostics.proxy_status,
                "pinning_suspected": traffic_diagnostics.pinning_suspected,
            },
        )
    )
    return traffic_diagnostics


def _collect_traffic_stage(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    context: AnalysisRunContext,
    environment: _DynamicEnvironment,
) -> _TrafficOutcome:
    """Validate traffic evidence, write the summary, and diagnose the collector."""
    mitm_session = environment.mitm_session
    correlation_requests: list[dict[str, Any]] = []
    traffic_started = _utc_now()
    if not req.enable_traffic:
        traffic_summary = _collect_disabled_traffic(steps, context, traffic_started)
    else:
        traffic_summary, correlation_requests = _collect_session_traffic(
            steps, mitm_session, traffic_started
        )
    write_traffic_summary(traffic_summary, str(context.traffic_summary_path))
    if not correlation_requests:
        correlation_requests = [
            dict(item)
            for item in traffic_summary.get("sample_requests") or []
            if isinstance(item, dict)
        ]
    mitm_public_status = (
        _session_status(mitm_session, environment.device_context)
        if mitm_session is not None and environment.device_context is not None
        else None
    )
    traffic_diagnostics = _record_traffic_diagnostics(
        steps, context, traffic_summary, mitm_public_status
    )
    network_evidence_available = traffic_summary.get("collector_outcome") in {
        "collector_success_zero_requests",
        "collector_success_requests_observed",
    }
    return _TrafficOutcome(
        traffic_summary=traffic_summary,
        correlation_requests=correlation_requests,
        network_evidence_available=network_evidence_available,
        traffic_diagnostics=traffic_diagnostics,
        mitm_public_status=mitm_public_status,
    )


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
        logcat = LogcatCollector(
            device=device_context,
            package_name=package_name,
            output_dir=dynamic_diagnostics_dir,
        ).collect(pid=getattr(diagnostic_session, "pid", None))
        pid_result = run_cmd(
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
    # This is emitted at the executor that selected the real Frida branch,
    # rather than inferred later by the orchestration/session layer.
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
    strict_dynamic_findings = evaluate_timeline_rules(
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
            "traffic_diagnostics": traffic.traffic_diagnostics.model_dump(mode="json"),
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


def _dynamic_analyze_v2(
    req: DynamicAnalyzeRequest,
    *,
    container: Container,
    ownership_registry: ResourceOwnershipRegistry | None = None,
    frida_session_factory: Any = None,
    mitm_session_factory: Any = None,
    diagnostics_service: Any = None,
):
    if frida_session_factory is None:
        frida_session_factory = getattr(container, "frida_session_factory", None)
    if mitm_session_factory is None:
        mitm_session_factory = getattr(container, "mitm_session_factory", None)
    if diagnostics_service is None:
        diagnostics_service = getattr(container, "frida_diagnostics_service", None)

    context, steps, failure_response = _prepare_run(
        req.apk_path,
        device_id=req.device_id,
    )
    if failure_response is not None:
        return failure_response
    assert context is not None

    static_stage = run_static_stage(
        context,
        steps,
        package_name_input=req.package_name,
    )
    context, device_context, device_failure, install_ok, package_name = _install_and_select_device(
        req, context, steps, static_stage
    )
    (
        frida_session,
        mitm_session,
        frida_diagnostic_payload,
        stimulate_ui,
        register_frida_started,
    ) = _build_dynamic_sessions(
        req,
        context,
        steps,
        device_context,
        package_name,
        ownership_registry=ownership_registry,
        frida_session_factory=frida_session_factory,
        mitm_session_factory=mitm_session_factory,
        diagnostics_service=diagnostics_service,
    )
    environment = _DynamicEnvironment(
        context=context,
        device_context=device_context,
        device_failure=device_failure,
        install_ok=install_ok,
        package_name=package_name,
        frida_session=frida_session,
        mitm_session=mitm_session,
        frida_diagnostic_payload=frida_diagnostic_payload,
        stimulate_ui=stimulate_ui,
        register_frida_started=register_frida_started,
        frida_session_factory=frida_session_factory,
    )

    collection_result = _run_collection_stage(req, steps, context, environment)
    dynamic_events, hook_evidence_available = _collect_events_stage(
        req, steps, context, environment, collection_result
    )
    traffic = _collect_traffic_stage(req, steps, context, environment)
    process_diagnostics_payload = _process_diagnostics_stage(
        req,
        steps,
        context,
        environment,
        collection_result,
        traffic,
        dynamic_events,
        hook_evidence_available,
    )
    execution = _build_execution_outcome(
        req,
        steps,
        context,
        environment,
        collection_result,
        traffic,
        process_diagnostics_payload,
        hook_evidence_available,
    )
    report = _assemble_dynamic_report(
        req,
        context,
        steps,
        environment,
        static_stage,
        collection_result,
        dynamic_events,
        traffic,
        execution,
        process_diagnostics_payload,
        hook_evidence_available,
    )

    consent_timestamp_utc = None
    raw_consent = execution.timeline_payload.get("consent_at")
    if isinstance(raw_consent, dict):
        value = raw_consent.get("timestamp_utc")
        consent_timestamp_utc = str(value) if value else None
    elif isinstance(raw_consent, str):
        consent_timestamp_utc = raw_consent
    report["evidence_correlation"] = _build_and_write_evidence_correlation(
        context=context,
        dynamic_events=dynamic_events,
        network_requests=traffic.correlation_requests,
        consent_timestamp_utc=consent_timestamp_utc,
    )
    consent_boundary_available = _has_trusted_consent_boundary(execution.timeline_payload)
    report["privacy_findings"] = _build_and_write_privacy_findings(
        context=context,
        dynamic_events=dynamic_events,
        network_requests=traffic.correlation_requests,
        correlation=report["evidence_correlation"],
        manifest_evidence=static_stage.manifest_evidence,
        dynamic_evidence_available=hook_evidence_available,
        network_evidence_available=traffic.network_evidence_available,
        consent_boundary_available=consent_boundary_available,
        dynamic_evidence_grade=execution.evidence_quality.level,
        consent_timestamp_utc=consent_timestamp_utc,
    )
    report, report_error = _finalize_report(report, context, steps)
    if report_error is not None or report.get("status") == "failed":
        return JSONResponse(status_code=500, content=report)
    if device_failure:
        return JSONResponse(status_code=409, content=report)
    return report


def dynamic_analyze(
    req: DynamicAnalyzeRequest,
    *,
    container: Container,
    frida_session_factory: Any = None,
    mitm_session_factory: Any = None,
    diagnostics_service: Any = None,
):
    return _dynamic_analyze_v2(
        req,
        container=container,
        frida_session_factory=frida_session_factory,
        mitm_session_factory=mitm_session_factory,
        diagnostics_service=diagnostics_service,
    )


__all__ = [
    "_append_collection_steps",
    "_build_dynamic_findings",
    "_dynamic_analyze_v2",
    "_emit_frida_control",
    "_normalize_events",
    "_session_status",
    "_state_value",
    "_traffic_summary_from_result",
    "dynamic_analyze",
]
