import asyncio
import os
import time
from collections import Counter
from dataclasses import replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi import FastAPI, HTTPException, Query, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse, JSONResponse

from app.config import (
    ALLOW_UNC_APK_PATHS,
    APK_ALLOWED_ROOTS,
    APK_MAX_SIZE_BYTES,
    DEFAULT_MITM_PORT,
    FRIDA_READY_TIMEOUT_SECONDS,
    FRIDA_STOP_TIMEOUT_SECONDS,
    MITM_LISTEN_HOST,
    MITM_DEVICE_PROXY_HOST,
    MITM_READY_TIMEOUT_SECONDS,
    MITM_STOP_TIMEOUT_SECONDS,
    OUTPUT_DIR,
    REDACTION_HMAC_KEY,
    SCHEMA_VERSION,
    STATIC_UNPACK_CACHE_DIR,
    TASK_DATABASE_PATH,
)
from app.core.artifacts import atomic_write_json, atomic_write_text
from app.core.device import DeviceContext
from app.core.apk_snapshot import ApkSnapshotError, create_apk_snapshot
from app.core.paths import ApkPathValidationError, ApkPathValidator, sha256_file
from app.core.redaction import Redactor
from app.core.run_context import AnalysisRunContext, create_analysis_run_context
from app.core.static_unpack_cache import (
    StaticUnpackCacheError,
    prepare_static_unpack,
)
from app.core.status import (
    StepResult,
    StepStatus,
    derive_overall_status,
    make_step_result,
)
from app.analyzers.compliance_insight import generate_compliance_insight
from app.analyzers.risk_scoring import calculate_risk_summary
from app.analyzers.sdk_intelligence import correlate_sdk_evidence
from app.analyzers.timeline_builder import build_timeline
from app.models import AnalyzeRequest, AnalyzeResponse, DynamicAnalyzeRequest
from app.comparisons import (
    ComparisonCreateRequest,
    ComparisonResult,
    ComparisonService,
)
from app.reporting import write_html_report
from app.repositories import TaskRepository
from app.services import TaskService
from app.services.application_name_service import (
    repair_historical_application_names,
)
from app.tasks.models import (
    TaskActionResponse,
    TaskCreateRequest,
    TaskListResponse,
    TaskRecord,
    TaskReportResponse,
    TaskSystemStatus,
)
from app.tasks.runtime import (
    current_task_id,
    register_cleanup,
    report_step,
)
from app.tools.adb_runner import (
    DeviceSelectionError,
    check_adb_available,
    check_device_online,
    install_apk,
    launch_app,
    select_device_context,
)
from app.tools.apk_unpack import unpack_apk
from app.tools.frida_runner import (
    check_frida_connection,
    check_frida_device_runtime,
    spawn_and_inject,
)
from app.tools.frida_session import FridaSession
from app.tools.dynamic_collection import (
    DynamicCollectionConfig,
    DynamicCollectionResult,
    run_dynamic_collection,
)
from app.tools.dynamic_compat import LegacyFridaAdapter, LegacyMitmAdapter
from app.tools.env_checks import (
    check_apk_allowed_roots,
    check_apktool,
    check_frida_python_package,
    check_redaction_hmac_key,
)
from app.tools.hook_parser import parse_hook_to_events_json
from app.tools.log_writer import append_log
from app.tools.manifest_parser import parse_manifest_info
from app.tools.mitm_runner import check_port_listening, get_mitm_status, start_mitm, stop_mitm
from app.tools.mitm_session import MitmSession
from app.tools.report_writer import write_json_report, write_markdown_report
from app.tools.sdk_fingerprint import scan_for_sdks
from app.tools.timeline_rules import evaluate_timeline_rules
from app.tools.timeline_rules import classify_consent_state
from app.tools.traffic_events import (
    TrafficCollectionOutcome,
    TrafficCollectionResult,
)
from app.tools.traffic_parser import (
    parse_traffic_text,
    parse_traffic_to_summary_json,
    write_traffic_summary,
)
from app.tools.utils import ensure_dir, now_iso

app = FastAPI(title="AdSDK Agent", version="0.1.0")

# 跨域传输配置(CORS):仅放行本端开发常用来源,不改动任何接口契约/响应结构。
# web/ 前端默认从 http://127.0.0.1:5173 访问本服务,Vite 代理为另一条路径;
# 此中间件保证浏览器对绝对地址的跨域请求也能得到正确的 CORS 头。
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    ],
    allow_credentials=False,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Content-Type"],
)

_ORIGINAL_FRIDA_SESSION_CLASS = FridaSession
_ORIGINAL_MITM_SESSION_CLASS = MitmSession
_ORIGINAL_SPAWN_AND_INJECT = spawn_and_inject
_ORIGINAL_START_MITM = start_mitm

_CRITICAL_STEPS = {
    "apk_validation",
    "apk_hash",
    "apk_snapshot",
    "apk_unpack",
    "report_write",
}


@app.get("/")
def root():
    return {"ok": True, "message": "AdSDK Agent is running"}


def _check_output_writable() -> dict:
    ensure_dir(OUTPUT_DIR)
    probe_file = os.path.join(OUTPUT_DIR, ".write_probe")
    try:
        with open(probe_file, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe_file)
        return {"ok": True, "path": OUTPUT_DIR, "error": None}
    except Exception as e:
        return {"ok": False, "path": OUTPUT_DIR, "error": str(e)}


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
            if (
                arg == "android_id"
                or event.get("identifier_type") == "android_id"
            ):
                android_id_calls += 1
        elif api == "ClipboardManager.getPrimaryClip":
            clipboard_calls += 1

    if not evidence_available:
        pre_consent_evaluation = "not_evaluated"
        high_frequency_evaluation = "not_evaluated"
    else:
        pre_consent_evaluation = "matched" if secure_calls > 0 else "not_matched"
        high_frequency_evaluation = (
            "matched"
            if android_id_calls > 3 or clipboard_calls > 1
            else "not_matched"
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


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _step_result(
    name: str,
    status: StepStatus,
    started_at: datetime,
    *,
    required: bool | None = None,
    warnings: list[str] | None = None,
    error_code: str | None = None,
    error_message: str | None = None,
    outputs: list[str] | None = None,
    details: dict[str, Any] | None = None,
) -> StepResult:
    ended_at = _utc_now()
    result = make_step_result(
        name,
        status,
        required=(name in _CRITICAL_STEPS if required is None else required),
        started_at=started_at,
        ended_at=ended_at,
        warnings=warnings or [],
        error_code=error_code,
        error_message=error_message,
        outputs=outputs or [],
        details=details or {},
    )
    report_step(
        name,
        status.value,
        error_message or (warnings[0] if warnings else None),
    )
    return result


def _steps_payload(steps: list[StepResult]) -> list[dict[str, Any]]:
    return [step.model_dump(mode="json") for step in steps]


def _collect_warnings(steps: list[StepResult]) -> list[str]:
    warnings: list[str] = []
    for step in steps:
        warnings.extend(step.warnings)
        if step.error_message:
            warnings.append(f"{step.name}: {step.error_message}")
    return list(dict.fromkeys(warnings))


def _overall_status(steps: list[StepResult]) -> str:
    return derive_overall_status(steps).value


def _redact_device_diagnostic(
    value: Any,
    device_context: DeviceContext | None,
) -> str | None:
    if value is None:
        return None
    text = str(value)
    if device_context is None:
        return text
    return (
        device_context.redactor.redact_text(
            text,
            {"device_serial": device_context.serial},
        )
        or ""
    )


def _device_serials(
    device_info: dict[str, Any],
    requested_device_id: str | None,
) -> list[str]:
    serials: list[str] = []
    if requested_device_id:
        serials.append(requested_device_id)
    target = device_info.get("target")
    if isinstance(target, dict) and target.get("device_id"):
        serials.append(str(target["device_id"]))
    for item in device_info.get("devices") or []:
        if isinstance(item, dict) and item.get("device_id"):
            serials.append(str(item["device_id"]))
    return list(dict.fromkeys(serials))


def _redact_known_device_serials(
    value: Any,
    serials: list[str],
) -> Any:
    redactor = Redactor(secret=REDACTION_HMAC_KEY)

    def redact_text(text: str) -> str:
        result = text
        for serial in sorted(serials, key=len, reverse=True):
            token = redactor.redact_identifier(
                serial,
                kind="device_serial",
            )
            if token is not None:
                result = result.replace(serial, token)
        return result

    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, list):
        return [
            _redact_known_device_serials(item, serials)
            for item in value
        ]
    if isinstance(value, tuple):
        return [
            _redact_known_device_serials(item, serials)
            for item in value
        ]
    if isinstance(value, dict):
        return {
            key: _redact_known_device_serials(item, serials)
            for key, item in value.items()
        }
    return value


def _validation_failure_response(
    *,
    run_id: str,
    apk_path: str,
    analysis_started_at: datetime,
    steps: list[StepResult],
    error_code: str,
    error_message: str,
    status_code: int,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content={
            "ok": False,
            "schema_version": SCHEMA_VERSION,
            "run_id": run_id,
            "apk_path": apk_path,
            "analysis_started_at": analysis_started_at.isoformat().replace(
                "+00:00",
                "Z",
            ),
            "status": "failed",
            "steps": _steps_payload(steps),
            "warnings": _collect_warnings(steps),
            "error": error_message,
            "error_code": error_code,
        },
    )


def _safe_apk_input_display(value: Any) -> str:
    try:
        name = Path(str(value)).name
    except (TypeError, ValueError, OSError):
        name = ""
    return name or "app.apk"


def _prepare_run(
    apk_path_input: str,
    *,
    device_id: str | None,
) -> tuple[AnalysisRunContext | None, list[StepResult], JSONResponse | None]:
    run_id = current_task_id() or str(uuid4())
    analysis_started_at = _utc_now()
    steps: list[StepResult] = []

    validation_started = _utc_now()
    validator = ApkPathValidator(
        allowed_roots=APK_ALLOWED_ROOTS,
        max_size_bytes=APK_MAX_SIZE_BYTES,
        allow_unc=ALLOW_UNC_APK_PATHS,
    )
    try:
        validated_apk = validator.validate(apk_path_input)
    except ApkPathValidationError as exc:
        steps.append(
            _step_result(
                "apk_validation",
                StepStatus.FAILED,
                validation_started,
                error_code=exc.code,
                error_message=exc.message,
            )
        )
        return (
            None,
            steps,
            _validation_failure_response(
                run_id=run_id,
                apk_path=_safe_apk_input_display(apk_path_input),
                analysis_started_at=analysis_started_at,
                steps=steps,
                error_code=exc.code,
                error_message=exc.message,
                status_code=422,
            ),
        )

    steps.append(
        _step_result(
            "apk_validation",
            StepStatus.SUCCESS,
            validation_started,
            outputs=[validated_apk.name],
            details={"source_path_display": validated_apk.name},
        )
    )

    hash_started = _utc_now()
    try:
        apk_sha256 = sha256_file(validated_apk)
    except (OSError, ValueError) as exc:
        message = f"APK SHA-256 calculation failed: {type(exc).__name__}"
        steps.append(
            _step_result(
                "apk_hash",
                StepStatus.FAILED,
                hash_started,
                error_code="apk_hash_failed",
                error_message=message,
            )
        )
        return (
            None,
            steps,
            _validation_failure_response(
                run_id=run_id,
                apk_path=validated_apk.name,
                analysis_started_at=analysis_started_at,
                steps=steps,
                error_code="apk_hash_failed",
                error_message=message,
                status_code=500,
            ),
        )

    steps.append(
        _step_result(
            "apk_hash",
            StepStatus.SUCCESS,
            hash_started,
            details={"sha256": apk_sha256},
        )
    )

    try:
        context = create_analysis_run_context(
            validated_apk,
            OUTPUT_DIR,
            apk_sha256=apk_sha256,
            run_id=run_id,
            device_id=device_id,
            started_at=analysis_started_at,
        )
    except (OSError, ValueError) as exc:
        message = f"run directory creation failed: {type(exc).__name__}"
        steps.append(
            _step_result(
                "run_context",
                StepStatus.FAILED,
                _utc_now(),
                required=True,
                error_code="run_context_failed",
                error_message=message,
            )
        )
        return (
            None,
            steps,
            _validation_failure_response(
                run_id=run_id,
                apk_path=validated_apk.name,
                analysis_started_at=analysis_started_at,
                steps=steps,
                error_code="run_context_failed",
                error_message=message,
                status_code=500,
            ),
        )

    snapshot_started = _utc_now()
    try:
        snapshot = create_apk_snapshot(
            validated_apk,
            context.run_dir,
            expected_sha256=apk_sha256,
            max_size_bytes=APK_MAX_SIZE_BYTES,
        )
    except ApkSnapshotError as exc:
        steps.append(
            _step_result(
                "apk_snapshot",
                StepStatus.FAILED,
                snapshot_started,
                required=True,
                error_code=exc.code,
                error_message=exc.message,
                details={
                    "source_path_display": validated_apk.name,
                    "snapshot_relative_path": "input/app.apk",
                    "snapshot_status": "failed",
                },
            )
        )
        return (
            None,
            steps,
            _validation_failure_response(
                run_id=run_id,
                apk_path=validated_apk.name,
                analysis_started_at=analysis_started_at,
                steps=steps,
                error_code=exc.code,
                error_message=exc.message,
                status_code=500,
            ),
        )

    context = replace(
        context,
        apk_path=snapshot.path,
        source_apk_path=validated_apk,
        source_apk_display=snapshot.source_display,
        apk_snapshot_relative_path=snapshot.relative_path,
        apk_snapshot_size_bytes=snapshot.size_bytes,
    )
    steps.append(
        _step_result(
            "apk_snapshot",
            StepStatus.SUCCESS,
            snapshot_started,
            required=True,
            outputs=[snapshot.relative_path],
            details=snapshot.to_report_dict(),
        )
    )
    return context, steps, None


def _artifact_entries(context: AnalysisRunContext) -> list[dict[str, Any]]:
    paths = {
        "apk_snapshot": context.apk_path,
        "hook_log": context.hook_log_path,
        "events_raw": context.events_raw_path,
        "events": context.events_path,
        "traffic_requests": context.traffic_jsonl_path,
        "mitm_stderr": context.mitm_stderr_path,
        "traffic_summary": context.traffic_summary_path,
        "sessions": context.sessions_path,
        "report_json": context.report_json_path,
        "report_markdown": context.report_markdown_path,
        "report_html": context.report_html_path,
    }
    return [
        {
            "name": name,
            "path": str(path),
            "schema_version": SCHEMA_VERSION,
        }
        for name, path in paths.items()
    ]


def _base_report(
    context: AnalysisRunContext,
    *,
    app_info: dict[str, Any] | None,
    sdk_hits: list[dict[str, Any]],
) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": context.run_id,
        "apk_path": context.source_apk_display or context.apk_path.name,
        "apk_sha256": context.apk_sha256,
        "apk_snapshot": {
            "source_path_display": (
                context.source_apk_display or context.apk_path.name
            ),
            "snapshot_relative_path": (
                context.apk_snapshot_relative_path or "input/app.apk"
            ),
            "snapshot_sha256": context.apk_sha256,
            "snapshot_size_bytes": context.apk_snapshot_size_bytes,
            "snapshot_status": "success",
        },
        "normalized_apk_name": context.normalized_apk_name,
        "analysis_started_at": context.started_at.isoformat().replace(
            "+00:00",
            "Z",
        ),
        "app_info": app_info,
        "sdk_count": len(sdk_hits),
        "sdks": sdk_hits,
        "output_dir": str(context.run_dir),
        "report_json": str(context.report_json_path),
        "report_md": str(context.report_markdown_path),
        "report_html": str(context.report_html_path),
        "artifacts": _artifact_entries(context),
    }


def _finalize_report(
    report: dict[str, Any],
    context: AnalysisRunContext,
    steps: list[StepResult],
) -> tuple[dict[str, Any], Exception | None]:
    # Enrichment is deterministic and local.  It runs immediately before
    # publishing so JSON, Markdown and the API response share one data model.
    report["sdks"] = correlate_sdk_evidence(
        list(report.get("sdks") or []),
        report,
    )
    report["sdk_count"] = len(report["sdks"])
    risk_started = time.perf_counter()
    risk_summary = calculate_risk_summary(report)
    risk_duration_ms = max(
        0,
        int((time.perf_counter() - risk_started) * 1000),
    )
    report["risk_summary"] = risk_summary.model_dump()
    report["timeline"] = build_timeline(report).model_dump()
    report["compliance_insight"] = generate_compliance_insight(
        risk_summary,
        limitations=[str(item) for item in report.get("limitations") or []],
    ).model_dump()
    report_started = _utc_now()
    report_write_started = time.perf_counter()
    candidate_status = _overall_status([*steps, StepStatus.SUCCESS])
    report.update(
        {
            "status": candidate_status,
            "ok": candidate_status != "failed",
            "steps": _steps_payload(steps),
            "warnings": _collect_warnings(steps),
        }
    )
    step_durations = {
        step.name: step.duration_ms or 0
        for step in steps
    }
    report["diagnostics"] = {
        "snapshot_duration_ms": step_durations.get("apk_snapshot", 0),
        "apktool_duration_ms": step_durations.get("apk_unpack", 0),
        "manifest_duration_ms": step_durations.get("manifest_parse", 0),
        "sdk_scan_duration_ms": step_durations.get("sdk_scan", 0),
        "risk_scoring_duration_ms": risk_duration_ms,
        "report_write_duration_ms": 0,
        "total_duration_ms": max(
            0,
            int((_utc_now() - context.started_at).total_seconds() * 1000),
        ),
    }

    try:
        # Publish human-readable artifacts first and JSON last so report.json is the final
        # machine-readable completion marker for a run.
        write_html_report(report, context.report_html_path)
        write_markdown_report(report, str(context.report_markdown_path))
        report_write_duration_ms = max(
            0,
            int((time.perf_counter() - report_write_started) * 1000),
        )
        successful_write = _step_result(
            "report_write",
            StepStatus.SUCCESS,
            report_started,
            outputs=[
                str(context.report_json_path),
                str(context.report_markdown_path),
                str(context.report_html_path),
            ],
        )
        candidate_steps = [*steps, successful_write]
        report.update(
            {
                "status": _overall_status(candidate_steps),
                "ok": _overall_status(candidate_steps) != "failed",
                "steps": _steps_payload(candidate_steps),
                "warnings": _collect_warnings(candidate_steps),
            }
        )
        report["diagnostics"]["report_write_duration_ms"] = (
            report_write_duration_ms
        )
        report["diagnostics"]["total_duration_ms"] = max(
            0,
            int((_utc_now() - context.started_at).total_seconds() * 1000),
        )
        write_json_report(report, str(context.report_json_path))
    except Exception as exc:
        failed_write = _step_result(
            "report_write",
            StepStatus.FAILED,
            report_started,
            error_code="report_write_failed",
            error_message=f"report write failed: {type(exc).__name__}",
        )
        failed_steps = [*steps, failed_write]
        report.update(
            {
                "status": "failed",
                "ok": False,
                "steps": _steps_payload(failed_steps),
                "warnings": _collect_warnings(failed_steps),
                "error": failed_write.error_message,
            }
        )
        return report, exc

    return report, None


@app.get("/env/check")
def env_check(device_id: str | None = None):
    adb_info = check_adb_available()
    device_info = check_device_online(device_id=device_id)
    frida_info = check_frida_connection(device_id=device_id)
    frida_runtime_info = check_frida_device_runtime(device_id)
    mitm_listen_port = DEFAULT_MITM_PORT
    mitm_8080_listening = check_port_listening(port=mitm_listen_port)
    output_info = _check_output_writable()
    serials = _device_serials(device_info, device_id)

    apktool_info = check_apktool()
    frida_python_info = check_frida_python_package()
    redaction_info = check_redaction_hmac_key()
    allowed_roots_info = check_apk_allowed_roots()

    checks = {
        "adb_available": adb_info.get("ok", False),
        "device_online": device_info.get("ok", False),
        "frida_connectable": frida_info.get("ok", False),
        "frida_server_running": frida_runtime_info.get(
            "server_running",
            False,
        ),
        "frida_python_available": frida_python_info.get(
            "frida_python_available", False
        ),
        "apktool_available": apktool_info.get("apktool_available", False),
        "mitm_8080_listening": mitm_8080_listening,
        "output_writable": output_info.get("ok", False),
        "redaction_hmac_key_secure": redaction_info.get(
            "redaction_hmac_key_security_status"
        ) == "secure",
        "apk_allowed_roots_configured": allowed_roots_info.get(
            "apk_allowed_roots_configured", False
        ),
    }

    # apktool_info / frida_python_info may carry private helper keys (_cmd,
    # _python_executable) that are not part of the public contract; strip them
    # before exposing to the client / logs.
    def _public(obj: dict[str, Any]) -> dict[str, Any]:
        return {k: v for k, v in obj.items() if not k.startswith("_")}

    return {
        "ok": all(checks.values()),
        "device_id": _redact_known_device_serials(device_id, serials),
        "checks": checks,
        "details": {
            "adb": _redact_known_device_serials(adb_info, serials),
            "device": _redact_known_device_serials(
                device_info,
                serials,
            ),
            "frida": _redact_known_device_serials(frida_info, serials),
            "frida_runtime": frida_runtime_info,
            "mitm": {"port": mitm_listen_port, "listening": mitm_8080_listening},
            "output": output_info,
            "apktool": _public(apktool_info),
            "frida_python": _public(frida_python_info),
            "redaction_hmac_key": redaction_info,
            "apk_allowed_roots": allowed_roots_info["apk_allowed_roots"],
        },
    }


@app.get("/traffic/check")
def traffic_check(device_id: str):
    device_info = check_device_online(device_id=device_id)
    mitm_status = get_mitm_status(port=DEFAULT_MITM_PORT)
    stream_log = mitm_status.get("stream_log")
    records = parse_traffic_text(stream_log) if stream_log else []
    flow_file_size = mitm_status.get("flow_file_size", 0)

    # A listening port or non-empty flow file does not prove ownership or a
    # valid observation.  This compatibility endpoint only reports success
    # for an explicitly owned session with parsed observations.
    captured_ok = bool(records) and bool(
        mitm_status.get("owned_by_session")
    )
    reasons = []

    if not device_info.get("ok"):
        reasons.append("Device is offline or unauthorized (adb state is not 'device').")
    if not mitm_status.get("has_last_session"):
        reasons.append("No recent mitm session found.")
    if not mitm_status.get("traffic_dir_exists"):
        reasons.append("traffic directory is missing; capture may not have started or path is inaccessible.")
    if not mitm_status.get("traffic_dir_writable"):
        reasons.append("traffic directory is not writable; cannot persist capture files.")
    if not mitm_status.get("port_listening"):
        reasons.append("mitmproxy is not listening on port 8080.")
    if mitm_status.get("stream_log_exists") and mitm_status.get("stream_log_size", 0) == 0:
        reasons.append("mitm stream log is empty; proxy may not be hit or HTTPS decryption failed.")
    if not captured_ok:
        reasons.append("No requests detected in latest capture; verify proxy/IP/certificate/SSL pinning.")

    serials = _device_serials(device_info, device_id)
    response = {
        "ok": captured_ok,
        "device_id": device_id,
        "captured_success": captured_ok,
        "captured_request_count": len(records),
        "flow_file_size": flow_file_size,
        "possible_reasons": reasons,
        "mitm_status": mitm_status,
        "sample_requests": records[:10],
    }
    return _redact_known_device_serials(response, serials)


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    context, steps, failure_response = _prepare_run(
        req.apk_path,
        device_id=None,
    )
    if failure_response is not None:
        return failure_response
    assert context is not None

    app_info: dict[str, Any] | None = None
    sdk_hits: list[dict[str, Any]] = []
    analysis_dir = context.unpacked_dir

    unpack_started = _utc_now()
    try:
        apktool_info = check_apktool()
        apktool_version = str(
            apktool_info.get("apktool_version") or "unknown"
        )
        configured_cache_root = os.environ.get(
            "STATIC_UNPACK_CACHE_DIR",
            "",
        ).strip()
        cache_root = Path(
            configured_cache_root
            or str(context.output_root / "cache" / "static-unpack")
        )
        cache_result = prepare_static_unpack(
            snapshot_path=context.apk_path,
            apk_sha256=context.apk_sha256,
            cache_root=cache_root,
            apktool_version=apktool_version,
            unpacker=unpack_apk,
        )
        analysis_dir = cache_result.unpacked_dir
        unpack_result = {
            "returncode": 0,
            "stderr": "",
            "stdout": "",
            "cache_hit": cache_result.cache_hit,
            "cache_key": cache_result.cache_key,
            "apktool_version": cache_result.apktool_version,
            "cache_format_version": cache_result.cache_format_version,
        }
    except StaticUnpackCacheError as exc:
        unpack_result = {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "error_code": exc.code,
            **exc.result,
        }
    except Exception as exc:
        unpack_result = {
            "returncode": -1,
            "stdout": "",
            "stderr": f"apktool execution failed: {type(exc).__name__}",
            "error_code": "analysis_failed",
        }
    if unpack_result.get("returncode") == 0:
        steps.append(
            _step_result(
                "apk_unpack",
                StepStatus.SUCCESS,
                unpack_started,
                outputs=[str(analysis_dir)],
                details={
                    "cache_hit": bool(unpack_result.get("cache_hit")),
                    "cache_key": unpack_result.get("cache_key"),
                    "apktool_version": unpack_result.get("apktool_version"),
                    "cache_format_version": unpack_result.get(
                        "cache_format_version"
                    ),
                },
            )
        )
    else:
        steps.append(
            _step_result(
                "apk_unpack",
                StepStatus.FAILED,
                unpack_started,
                error_code=unpack_result.get("error_code")
                or "apk_unpack_failed",
                error_message=(
                    unpack_result.get("stderr")
                    or unpack_result.get("stdout")
                    or "apktool failed"
                ),
            )
        )

    if steps[-1].status is StepStatus.SUCCESS:
        manifest_started = _utc_now()
        try:
            app_info = parse_manifest_info(
                str(analysis_dir),
                apk_filename=context.source_apk_display,
            )
            steps.append(
                _step_result(
                    "manifest_parse",
                    StepStatus.SUCCESS,
                    manifest_started,
                    required=False,
                    outputs=[
                        str(analysis_dir / "AndroidManifest.xml")
                    ],
                )
            )
        except Exception as exc:
            steps.append(
                _step_result(
                    "manifest_parse",
                    StepStatus.FAILED,
                    manifest_started,
                    required=False,
                    error_code="manifest_parse_failed",
                    error_message=f"manifest parse failed: {type(exc).__name__}",
                )
            )

        sdk_started = _utc_now()
        try:
            sdk_hits = scan_for_sdks(str(analysis_dir))
            steps.append(
                _step_result(
                    "sdk_scan",
                    StepStatus.SUCCESS,
                    sdk_started,
                    required=False,
                    details={"sdk_count": len(sdk_hits)},
                )
            )
        except Exception as exc:
            sdk_hits = []
            steps.append(
                _step_result(
                    "sdk_scan",
                    StepStatus.FAILED,
                    sdk_started,
                    required=False,
                    error_code="sdk_scan_failed",
                    error_message=f"SDK scan failed: {type(exc).__name__}",
                )
            )
    else:
        now = _utc_now()
        steps.extend(
            [
                _step_result(
                    "manifest_parse",
                    StepStatus.SKIPPED,
                    now,
                    required=False,
                    warnings=["manifest parse skipped because APK unpack failed"],
                ),
                _step_result(
                    "sdk_scan",
                    StepStatus.SKIPPED,
                    now,
                    required=False,
                    warnings=["SDK scan skipped because APK unpack failed"],
                ),
            ]
        )

    report = _base_report(
        context,
        app_info=app_info,
        sdk_hits=sdk_hits,
    )
    report, report_error = _finalize_report(report, context, steps)
    if report_error is not None or report.get("status") == "failed":
        return JSONResponse(status_code=500, content=report)
    return report


def _state_value(session: Any) -> str:
    state = getattr(session, "state", "created")
    return str(getattr(state, "value", state))


def _legacy_fixture_mode() -> bool:
    return (
        FridaSession is _ORIGINAL_FRIDA_SESSION_CLASS
        and MitmSession is _ORIGINAL_MITM_SESSION_CLASS
        and (
            spawn_and_inject is not _ORIGINAL_SPAWN_AND_INJECT
            or start_mitm is not _ORIGINAL_START_MITM
        )
    )


def _emit_frida_control(session: Any, event: dict[str, Any]) -> Any:
    name = event.get("event")
    if name == "collection_started":
        method = getattr(session, "emit_collection_started", None)
        if callable(method):
            return method()
    if name == "consent_granted":
        method = getattr(session, "emit_consent", None)
        if callable(method):
            return method(
                source=str(event.get("source") or "configured_delay")
            )
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
            {"device_serial": device_context.serial}
            if device_context is not None
            else None
        ),
    )
    consent_ms: float | int | None = None
    for event in events:
        if (
            event.get("type") == "control"
            and event.get("event") == "consent_granted"
        ):
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
        "top_hosts": [
            {"host": host, "count": count}
            for host, count in hosts.most_common(20)
        ],
        "sample_requests": [
            record.model_dump(mode="json") for record in result.records[:50]
        ],
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
        safe["command"] = [
            _redact_device_diagnostic(argument, device) for argument in command
        ]
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
        "started_at",
        "ready_at",
        "stopped_at",
    ):
        if value.get(name) is not None:
            item = value[name]
            safe[name] = (
                _redact_device_diagnostic(item, device)
                if isinstance(item, str)
                else item
            )
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
        required.difference_update(
            {"frida_spawn", "frida_script_load", "frida_ready"}
        )
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
                "installed_hooks": list(
                    getattr(frida_session, "installed_hooks", [])
                ),
                "failed_hooks": list(
                    getattr(frida_session, "failed_hooks", [])
                ),
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
                    list(result.cleanup_errors)
                    if name in {"frida_stop", "mitm_stop"}
                    else []
                ),
                details=details,
            )
        )


def _dynamic_analyze_v2(req: DynamicAnalyzeRequest):
    context, steps, failure_response = _prepare_run(
        req.apk_path,
        device_id=req.device_id,
    )
    if failure_response is not None:
        return failure_response
    assert context is not None

    app_info: dict[str, Any] | None = None
    sdk_hits: list[dict[str, Any]] = []
    analysis_dir = context.unpacked_dir
    unpack_started = _utc_now()
    try:
        apktool_info = check_apktool()
        apktool_version = str(
            apktool_info.get("apktool_version") or "unknown"
        )
        configured_cache_root = os.environ.get(
            "STATIC_UNPACK_CACHE_DIR",
            "",
        ).strip()
        cache_root = Path(
            configured_cache_root
            or str(context.output_root / "cache" / "static-unpack")
        )
        cache_result = prepare_static_unpack(
            snapshot_path=context.apk_path,
            apk_sha256=context.apk_sha256,
            cache_root=cache_root,
            apktool_version=apktool_version,
            unpacker=unpack_apk,
        )
        analysis_dir = cache_result.unpacked_dir
        unpack_result = {
            "returncode": 0,
            "stderr": "",
            "stdout": "",
            "cache_hit": cache_result.cache_hit,
            "cache_key": cache_result.cache_key,
            "apktool_version": cache_result.apktool_version,
            "cache_format_version": cache_result.cache_format_version,
        }
    except StaticUnpackCacheError as exc:
        unpack_result = {
            "returncode": -1,
            "stdout": "",
            "stderr": str(exc),
            "error_code": exc.code,
            **exc.result,
        }
    except Exception as exc:
        unpack_result = {
            "returncode": -1,
            "stderr": f"apktool execution failed: {type(exc).__name__}",
            "error_code": "analysis_failed",
        }
    unpack_ok = unpack_result.get("returncode") == 0
    steps.append(
        _step_result(
            "apk_unpack",
            StepStatus.SUCCESS if unpack_ok else StepStatus.FAILED,
            unpack_started,
            error_code=None
            if unpack_ok
            else unpack_result.get("error_code") or "apk_unpack_failed",
            error_message=(
                None
                if unpack_ok
                else str(
                    unpack_result.get("stderr")
                    or unpack_result.get("stdout")
                    or "apktool failed"
                )
            ),
            outputs=[str(analysis_dir)] if unpack_ok else [],
            details=(
                {
                    "cache_hit": bool(unpack_result.get("cache_hit")),
                    "cache_key": unpack_result.get("cache_key"),
                    "apktool_version": unpack_result.get("apktool_version"),
                    "cache_format_version": unpack_result.get(
                        "cache_format_version"
                    ),
                }
                if unpack_ok
                else {}
            ),
        )
    )

    if unpack_ok:
        started = _utc_now()
        try:
            app_info = parse_manifest_info(
                str(analysis_dir),
                apk_filename=context.source_apk_display,
            )
            steps.append(
                _step_result(
                    "manifest_parse",
                    StepStatus.SUCCESS,
                    started,
                    required=False,
                )
            )
        except Exception as exc:
            steps.append(
                _step_result(
                    "manifest_parse",
                    StepStatus.FAILED,
                    started,
                    required=False,
                    error_code="manifest_parse_failed",
                    error_message=f"manifest parse failed: {type(exc).__name__}",
                )
            )
        started = _utc_now()
        try:
            sdk_hits = scan_for_sdks(str(analysis_dir))
            steps.append(
                _step_result(
                    "sdk_scan",
                    StepStatus.SUCCESS,
                    started,
                    required=False,
                    details={"sdk_count": len(sdk_hits)},
                )
            )
        except Exception as exc:
            steps.append(
                _step_result(
                    "sdk_scan",
                    StepStatus.FAILED,
                    started,
                    required=False,
                    error_code="sdk_scan_failed",
                    error_message=f"SDK scan failed: {type(exc).__name__}",
                )
            )
    else:
        for name in ("manifest_parse", "sdk_scan"):
            steps.append(
                _step_result(
                    name,
                    StepStatus.SKIPPED,
                    _utc_now(),
                    required=False,
                    warnings=["skipped because APK unpack failed"],
                )
            )

    package_name = (req.package_name or "").strip()
    if not package_name and app_info:
        package_name = str(app_info.get("package_name") or "").strip()

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
    if device_context is not None:
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
    frida_session: Any = None
    mitm_session: Any = None
    collection_result: DynamicCollectionResult | None = None
    dynamic_events: list[dict[str, Any]] = []
    traffic_summary: dict[str, Any]
    legacy_mode = _legacy_fixture_mode()
    transport_path = (
        context.run_dir / ".legacy-hook.transport"
        if legacy_mode
        else context.events_raw_path
    )

    if install_ok and device_context is not None:
        script_path = (
            Path(__file__).resolve().parent
            / "frida_hooks"
            / "sensitive_apis.js"
        )
        if legacy_mode:
            frida_session = LegacyFridaAdapter(
                run_id=context.run_id,
                device=device_context,
                package_name=package_name,
                script_path=script_path,
                transport_path=transport_path,
                spawn=spawn_and_inject,
                launch=launch_app,
            )
            if req.enable_traffic:
                mitm_session = LegacyMitmAdapter(
                    run_id=context.run_id,
                    device=device_context,
                    traffic_dir=context.traffic_dir,
                    start=start_mitm,
                    stop=stop_mitm,
                )
        else:
            frida_session = FridaSession(
                run_id=context.run_id,
                device=device_context,
                package_name=package_name,
                script_path=script_path,
                event_log_path=context.events_raw_path,
                protocol_error_path=(
                    context.run_dir / "frida.protocol-errors.jsonl"
                ),
                stop_timeout_seconds=FRIDA_STOP_TIMEOUT_SECONDS,
            )
            if req.enable_traffic:
                mitm_session = MitmSession(
                    run_id=context.run_id,
                    device=device_context,
                    traffic_dir=context.traffic_dir,
                    listen_host=MITM_LISTEN_HOST,
                    device_proxy_host=MITM_DEVICE_PROXY_HOST,
                    stop_timeout=MITM_STOP_TIMEOUT_SECONDS,
                )

        register_cleanup(frida_session.stop)
        if mitm_session is not None:
            register_cleanup(mitm_session.stop)

        def stimulate_ui() -> None:
            result = launch_app(
                package_name,
                device_context=device_context,
            )
            if result.get("returncode") != 0:
                raise RuntimeError("UI stimulation failed")

        collection_result = run_dynamic_collection(
            frida_session=frida_session,
            mitm_session=mitm_session,
            config=DynamicCollectionConfig(
                consent_after_seconds=req.consent_after_seconds,
                pre_consent_seconds=req.pre_consent_seconds,
                post_consent_seconds=req.post_consent_seconds,
                collection_timeout_seconds=req.collection_timeout_seconds,
                frida_ready_timeout_seconds=FRIDA_READY_TIMEOUT_SECONDS,
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
            stimulate_ui=stimulate_ui,
            resume_without_frida=stimulate_ui,
        )
        _append_collection_steps(
            steps,
            collection_result,
            enable_traffic=req.enable_traffic,
            consent_configured=req.consent_after_seconds is not None,
            frida_session=frida_session,
        )
    else:
        collection_result = DynamicCollectionResult(
            status="failed",
            timeline=__import__(
                "app.tools.dynamic_collection",
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
    event_started = _utc_now()
    if not hook_evidence_available and network_collector_available:
        dynamic_events = []
        atomic_write_json(context.events_path, [])
        steps.append(
            _step_result(
                "event_validation",
                StepStatus.SKIPPED,
                event_started,
                required=False,
                warnings=[
                    "Frida hook evidence unavailable; network-only collection retained"
                ],
                details={"event_count": 0, "protocol_error_count": 0},
            )
        )
        context.events_raw_path.touch(exist_ok=True)
    else:
        try:
            dynamic_events = _normalize_events(
                transport_path,
                context.events_path,
                device_context=device_context,
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
                        "protocol_error_count": len(
                            getattr(frida_session, "protocol_errors", [])
                        ),
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
                    error_message=(
                        f"hook evidence unavailable: {type(exc).__name__}"
                    ),
                )
            )
        finally:
            if legacy_mode:
                transport_path.unlink(missing_ok=True)
            context.events_raw_path.touch(exist_ok=True)

    traffic_started = _utc_now()
    if not req.enable_traffic:
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
    elif legacy_mode:
        try:
            stream = getattr(mitm_session, "_state", {}).get(
                "stream_log",
                str(context.mitm_stream_log_path),
            )
            traffic_summary = parse_traffic_to_summary_json(
                traffic_text_path=stream,
                output_path=str(context.traffic_summary_path),
            )
            traffic_status = (
                StepStatus.SUCCESS
                if traffic_summary.get("status") == "success"
                else StepStatus.PARTIAL
            )
            steps.append(
                _step_result(
                    "traffic_validation",
                    traffic_status,
                    traffic_started,
                    required=False,
                )
            )
        except Exception as exc:
            traffic_summary = {
                "schema_version": SCHEMA_VERSION,
                "status": "failed",
                "evaluation_status": "not_evaluated",
                "coverage": "unavailable",
                "collector_outcome": "collector_failed",
                "warnings": [
                    f"traffic evidence unavailable: {type(exc).__name__}"
                ],
                "total_requests": 0,
                "top_hosts": [],
                "sample_requests": [],
            }
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
    else:
        try:
            traffic_result = mitm_session.validate_traffic()
            traffic_summary = _traffic_summary_from_result(traffic_result)
            traffic_status = (
                StepStatus.FAILED
                if traffic_result.outcome
                is TrafficCollectionOutcome.COLLECTOR_FAILED
                else StepStatus.SUCCESS
            )
            steps.append(
                _step_result(
                    "traffic_validation",
                    traffic_status,
                    traffic_started,
                    required=False,
                    error_code=(
                        "traffic_collector_failed"
                        if traffic_status is StepStatus.FAILED
                        else None
                    ),
                    error_message=(
                        "traffic collector evidence is unavailable"
                        if traffic_status is StepStatus.FAILED
                        else None
                    ),
                    details=traffic_result.to_dict(),
                )
            )
        except Exception as exc:
            traffic_summary = {
                "schema_version": SCHEMA_VERSION,
                "status": "failed",
                "evaluation_status": "not_evaluated",
                "coverage": "unavailable",
                "collector_outcome": "collector_failed",
                "warnings": [f"traffic validation failed: {type(exc).__name__}"],
                "total_requests": 0,
                "top_hosts": [],
                "sample_requests": [],
            }
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
    write_traffic_summary(traffic_summary, str(context.traffic_summary_path))
    network_evidence_available = traffic_summary.get("collector_outcome") in {
        "collector_success_zero_requests",
        "collector_success_requests_observed",
    }
    dynamic_validation_level = (
        "A"
        if hook_evidence_available and network_evidence_available
        else "B"
        if hook_evidence_available or network_evidence_available
        else "C"
    )

    sessions_payload = {
        "schema_version": SCHEMA_VERSION,
        "run_id": context.run_id,
        "device": (
            device_context.to_public_dict()
            if device_context is not None
            else None
        ),
        "frida": (
            _session_status(frida_session, device_context)
            if frida_session is not None and device_context is not None
            else None
        ),
        "mitm": (
            _session_status(mitm_session, device_context)
            if mitm_session is not None and device_context is not None
            else None
        ),
        "timeline": collection_result.timeline.to_dict(),
        "collection_status": collection_result.status,
        "cleanup_errors": list(collection_result.cleanup_errors),
    }
    atomic_write_json(context.sessions_path, sessions_payload)

    consent_time = collection_result.timeline.to_dict().get("consent_at")
    dynamic_findings = _build_dynamic_findings(
        dynamic_events,
        evidence_available=hook_evidence_available,
    )
    strict_dynamic_findings = evaluate_timeline_rules(
        events_json_path=str(context.events_path),
        consent_time=consent_time,
        pre_consent_seconds=req.pre_consent_seconds,
        post_consent_seconds=req.post_consent_seconds,
        evidence_available=hook_evidence_available,
    )
    report = _base_report(
        context,
        app_info=app_info,
        sdk_hits=sdk_hits,
    )
    report.update(
        {
            "hook_log": str(context.hook_log_path),
            "events_raw_jsonl": str(context.events_raw_path),
            "events_json": str(context.events_path),
            "consent_time": consent_time,
            "traffic_dir": str(context.traffic_dir),
            "traffic_jsonl": str(context.traffic_jsonl_path),
            "traffic_summary_json": str(context.traffic_summary_path),
            "sessions_json": str(context.sessions_path),
            "dynamic_events": dynamic_events,
            "dynamic_findings": dynamic_findings,
            "strict_dynamic_findings": strict_dynamic_findings,
            "traffic_summary": traffic_summary,
            "traffic_coverage": traffic_summary.get("coverage"),
            "pre_consent_seconds": req.pre_consent_seconds,
            "post_consent_seconds": req.post_consent_seconds,
            "enable_traffic": req.enable_traffic,
            "enable_ui_stimulation": req.enable_ui_stimulation,
            "collection_timeout_seconds": req.collection_timeout_seconds,
            "collection_status": collection_result.status,
            "dynamic_validation_level": dynamic_validation_level,
            "dynamic_timeline": collection_result.timeline.to_dict(),
            "collector_sessions": sessions_payload,
            "device": (
                device_context.to_public_dict()
                if device_context is not None
                else None
            ),
            "limitations": [
                "SSL pinning can reduce traffic visibility",
                "the in-process mitm port pool is limited to one Uvicorn worker",
                "dynamic events and network requests are not fully correlated",
            ],
        }
    )
    report, report_error = _finalize_report(report, context, steps)
    if report_error is not None or report.get("status") == "failed":
        return JSONResponse(status_code=500, content=report)
    if device_failure:
        return JSONResponse(status_code=409, content=report)
    return report


@app.post("/dynamic/analyze", response_model=AnalyzeResponse)
def dynamic_analyze(req: DynamicAnalyzeRequest):
    return _dynamic_analyze_v2(req)


task_repository = TaskRepository(TASK_DATABASE_PATH)
task_service = TaskService(task_repository)
repair_historical_application_names(
    task_repository,
    static_unpack_cache_dir=STATIC_UNPACK_CACHE_DIR,
)
comparison_service = ComparisonService(task_repository)
task_service.recover()


def _run_persisted_task(task: TaskRecord):
    payload = dict(task.request_payload)
    if task.task_type == "static":
        return analyze(AnalyzeRequest(apk_path=str(payload["apk_path"])))
    if task.task_type == "dynamic":
        return dynamic_analyze(DynamicAnalyzeRequest.model_validate(payload))
    raise ValueError(f"unsupported executable task type: {task.task_type}")


task_service.set_runner(_run_persisted_task)


def _task_not_found(task_id: str) -> HTTPException:
    return HTTPException(
        status_code=404,
        detail={"code": "task_not_found", "message": f"任务 {task_id} 不存在"},
    )


@app.post("/tasks", response_model=TaskRecord, status_code=202)
def create_task(request: TaskCreateRequest):
    return task_service.create(request)


@app.get("/tasks", response_model=TaskListResponse)
def list_tasks(
    status: str | None = Query(default=None),
    task_type: str | None = Query(default=None),
    keyword: str | None = Query(default=None, max_length=256),
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    sort: str = Query(default="-created_at"),
):
    allowed_statuses = {"queued", "running", "completed", "failed", "cancelled"}
    allowed_types = {"static", "dynamic", "comparison"}
    if status and status not in allowed_statuses:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_status", "message": "任务状态筛选值无效"},
        )
    if task_type and task_type not in allowed_types:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_task_type", "message": "任务类型筛选值无效"},
        )
    return task_service.list(
        status=status,
        task_type=task_type,
        keyword=keyword,
        page=page,
        page_size=page_size,
        sort=sort,
    )


@app.get("/tasks/system/status", response_model=TaskSystemStatus)
def task_system_status():
    running = task_service.list(status="running", page=1, page_size=1).total
    queued = task_service.list(status="queued", page=1, page_size=1).total
    return TaskSystemStatus(
        database_ok=True,
        database_path=str(task_repository.database_path),
        running_tasks=running,
        queued_tasks=queued,
        occupied_devices=task_service.occupied_devices(),
    )


@app.get("/tasks/{task_id}", response_model=TaskRecord)
def get_task(task_id: str):
    task = task_service.get(task_id)
    if task is None:
        raise _task_not_found(task_id)
    return task


@app.get("/tasks/{task_id}/report", response_model=TaskReportResponse)
def get_task_report(task_id: str):
    try:
        return task_service.report(task_id)
    except KeyError:
        raise _task_not_found(task_id)


@app.post("/tasks/{task_id}/cancel", response_model=TaskActionResponse)
def cancel_task(task_id: str):
    try:
        return task_service.cancel(task_id)
    except KeyError:
        raise _task_not_found(task_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "task_not_cancellable", "message": str(exc)},
        )


@app.post("/tasks/{task_id}/retry", response_model=TaskActionResponse, status_code=202)
def retry_task(task_id: str):
    try:
        return task_service.retry(task_id)
    except KeyError:
        raise _task_not_found(task_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "task_not_retryable", "message": str(exc)},
        )


@app.delete("/tasks/{task_id}", status_code=204)
def delete_task(task_id: str):
    try:
        deleted = task_service.delete(task_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "active_task", "message": str(exc)},
        )
    if not deleted:
        raise _task_not_found(task_id)
    return None


@app.get("/tasks/{task_id}/artifacts/{artifact_kind}")
def download_task_artifact(task_id: str, artifact_kind: str):
    task = task_service.get(task_id)
    if task is None:
        raise _task_not_found(task_id)
    field_map = {
        "json": (task.report_json_path, "application/json", "report.json"),
        "markdown": (task.report_markdown_path, "text/markdown", "report.md"),
        "html": (task.report_html_path, "text/html", "report.html"),
    }
    if artifact_kind not in field_map:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_artifact_kind", "message": "报告格式无效"},
        )
    path_text, media_type, filename = field_map[artifact_kind]
    if not path_text:
        raise HTTPException(
            status_code=404,
            detail={"code": "artifact_not_found", "message": "报告产物尚未生成"},
        )
    path = Path(path_text).resolve(strict=False)
    allowed = (Path(OUTPUT_DIR).resolve(strict=False) / "runs").resolve(strict=False)
    if not path.is_relative_to(allowed) or not path.is_file():
        raise HTTPException(
            status_code=404,
            detail={"code": "artifact_not_found", "message": "报告产物不存在"},
        )
    return FileResponse(path, media_type=media_type, filename=filename)


@app.websocket("/ws/tasks/{task_id}")
async def task_progress_websocket(websocket: WebSocket, task_id: str):
    await websocket.accept()
    last_updated: str | None = None
    try:
        while True:
            task = task_service.get(task_id)
            if task is None:
                await websocket.send_json(
                    {"error": {"code": "task_not_found", "message": "任务不存在"}}
                )
                await websocket.close(code=4404)
                return
            if task.updated_at != last_updated:
                await websocket.send_json(task.model_dump(mode="json"))
                last_updated = task.updated_at
            if task.status in {"completed", "failed", "cancelled"}:
                await websocket.close(code=1000)
                return
            await asyncio.sleep(0.5)
    except WebSocketDisconnect:
        return


@app.post("/comparisons", response_model=ComparisonResult, status_code=201)
def create_comparison(request: ComparisonCreateRequest):
    try:
        return comparison_service.create(request)
    except KeyError:
        raise HTTPException(
            status_code=404,
            detail={"code": "comparison_input_not_found", "message": "对比任务不存在"},
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail={"code": "invalid_comparison", "message": str(exc)},
        )


@app.get("/comparisons", response_model=list[ComparisonResult])
def list_comparisons(limit: int = 20):
    return comparison_service.list(limit=max(1, min(limit, 100)))


@app.get("/comparisons/{comparison_id}", response_model=ComparisonResult)
def get_comparison(comparison_id: str):
    result = comparison_service.get(comparison_id)
    if result is None:
        raise HTTPException(
            status_code=404,
            detail={"code": "comparison_not_found", "message": "对比结果不存在"},
        )
    return result
