"""Dynamic analysis pipeline package."""

from __future__ import annotations

import time
from typing import Any

from fastapi.responses import JSONResponse

from app.container import Container
from app.frida.hook_parser import parse_hook_to_events_json
from app.frida.logcat_collector import LogcatCollector
from app.models import DynamicAnalyzeRequest
from app.orchestration.cleanup_manager import ResourceOwnershipRegistry
from app.orchestration.dynamic_collection import (
    DynamicCollectionConfig,
    DynamicCollectionResult,
    run_dynamic_collection,
)
from app.orchestration.timeline_rules import evaluate_timeline_rules
from app.pipelines.common import (
    _build_and_write_evidence_correlation,
    _build_and_write_privacy_findings,
    _finalize_report,
    _has_trusted_consent_boundary,
    _prepare_run,
    run_static_stage,
)
from app.pipelines.dynamic.collection import (
    _append_collection_steps,
    _collect_traffic_stage,
    _emit_frida_control,
    _run_collection_stage,
    _session_status,
    _state_value,
)
from app.pipelines.dynamic.report import (
    _assemble_dynamic_report,
    _build_execution_outcome,
    _process_diagnostics_stage,
    _traffic_summary_from_result,
)
from app.pipelines.dynamic.sessions import (
    _build_dynamic_sessions,
    _DynamicEnvironment,
    _install_and_select_device,
    _make_collection_callbacks,
    _make_launch_target_for_attach,
    _noop_register_runtime_target,
    _register_owned_target,
)
from app.pipelines.dynamic.timeline import (
    _build_dynamic_findings,
    _collect_events_stage,
    _normalize_events,
)
from app.tools.adb_runner import (
    DeviceSelectionError,
    install_apk,
    launch_app,
    select_device_context,
)
from app.tools.utils import run_cmd


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
        container=container,
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
    "DeviceSelectionError",
    "DynamicCollectionConfig",
    "DynamicCollectionResult",
    "LogcatCollector",
    "_append_collection_steps",
    "_build_dynamic_findings",
    "_dynamic_analyze_v2",
    "_emit_frida_control",
    "_make_collection_callbacks",
    "_make_launch_target_for_attach",
    "_noop_register_runtime_target",
    "_normalize_events",
    "_register_owned_target",
    "_session_status",
    "_state_value",
    "_traffic_summary_from_result",
    "dynamic_analyze",
    "evaluate_timeline_rules",
    "install_apk",
    "launch_app",
    "parse_hook_to_events_json",
    "run_cmd",
    "run_dynamic_collection",
    "select_device_context",
    "time",
]
