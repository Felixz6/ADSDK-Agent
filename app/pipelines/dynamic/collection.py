"""Dynamic collection stage: execution window countdown, session callbacks, traffic capture."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from app.config import (
    FRIDA_READY_TIMEOUT_SECONDS,
    FRIDA_SPAWN_STABILITY_SECONDS,
    FRIDA_STOP_TIMEOUT_SECONDS,
    MITM_READY_TIMEOUT_SECONDS,
    MITM_STOP_TIMEOUT_SECONDS,
)
from app.core.clock import utc_now as _utc_now
from app.core.device import DeviceContext
from app.core.status import StepResult, StepStatus
from app.frida.traffic_diagnostics import diagnose_traffic
from app.models import DynamicAnalyzeRequest
from app.orchestration.dynamic_collection import (
    DynamicCollectionConfig,
    DynamicCollectionResult,
    DynamicTimeline,
    run_dynamic_collection,
)
from app.pipelines.common import (
    _redact_device_diagnostic,
    _step_result,
)
from app.pipelines.dynamic._shared import (
    _traffic_failure_summary,
    _traffic_summary_from_result,
)
from app.traffic.traffic_events import (
    TrafficCollectionOutcome,
)
from app.traffic.traffic_parser import write_traffic_summary


@dataclass(slots=True)
class _TrafficOutcome:
    traffic_summary: dict[str, Any]
    correlation_requests: list[dict[str, Any]]
    network_evidence_available: bool
    traffic_diagnostics: Any
    mitm_public_status: dict[str, Any] | None


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


def _run_collection_stage(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    context: Any,
    environment: Any,
) -> DynamicCollectionResult:
    """Run the collection lifecycle (including its cleanup) or record prerequisites failure."""
    import time

    frida_session = environment.frida_session
    mitm_session = environment.mitm_session

    if environment.install_ok and environment.device_context is not None:
        run_fn = getattr(environment.tools, "run_dynamic_collection", run_dynamic_collection)
        collection_result = run_fn(
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
        timeline=DynamicTimeline(
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


def _collect_disabled_traffic(
    steps: list[StepResult],
    context: Any,
    traffic_started: Any,
) -> dict[str, Any]:
    from app.config import SCHEMA_VERSION

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
        traffic_summary = _traffic_failure_summary(exc)
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
    context: Any,
    traffic_summary: dict[str, Any],
    mitm_public_status: dict[str, Any] | None,
) -> Any:
    from app.core.artifacts import atomic_write_json

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
    context: Any,
    environment: Any,
) -> _TrafficOutcome:
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


__all__ = [
    "_TrafficOutcome",
    "_append_collection_steps",
    "_collect_disabled_traffic",
    "_collect_session_traffic",
    "_collect_traffic_stage",
    "_emit_frida_control",
    "_record_traffic_diagnostics",
    "_run_collection_stage",
    "_session_status",
    "_state_value",
]
