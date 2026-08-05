import asyncio
import json
import math
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
    AI_CACHE_ENABLED,
    AI_MAX_ROUNDS,
    AI_MAX_TOOL_CALLS,
    AI_REPORT_LANGUAGE,
    ALLOW_UNC_APK_PATHS,
    APK_ALLOWED_ROOTS,
    APK_MAX_SIZE_BYTES,
    DEFAULT_MITM_PORT,
    EVIDENCE_CORRELATION_WINDOW_MS,
    FRIDA_READY_TIMEOUT_SECONDS,
    FRIDA_SPAWN_STABILITY_SECONDS,
    FRIDA_STOP_TIMEOUT_SECONDS,
    FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS,
    FRIDA_SERVER_LOCAL_PATH,
    FRIDA_SERVER_MANAGEMENT_ENABLED,
    FRIDA_SERVER_REMOTE_PATH,
    FRIDA_SERVER_START_TIMEOUT_SECONDS,
    MITM_LISTEN_HOST,
    MITM_DEVICE_PROXY_HOST,
    MITM_READY_TIMEOUT_SECONDS,
    MITM_STOP_TIMEOUT_SECONDS,
    M7A_CONSENT_WAIT_SECONDS,
    M7A_LEASE_STALE_SECONDS,
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
from app.analyzers.evidence_correlation import (
    EvidenceCorrelationConfig,
    build_error_correlation,
    build_evidence_correlations,
)
from app.analyzers.privacy_findings import (
    build_error_privacy_findings,
    build_privacy_findings,
)
from app.analyzers.risk_scoring import calculate_risk_summary
from app.analyzers.sdk_intelligence import correlate_sdk_evidence
from app.analyzers.timeline_builder import build_timeline
from app.ai.orchestrator import (
    AIOrchestrationRequest,
    AIOrchestrationResult,
    AIOrchestrator,
)
from app.ai.settings_service import (
    AISettingsService,
    AISettingsValidationError,
    resolve_effective_ai_settings,
)
from app.ai.settings_store import AISettingsStore
from app.ai.cache import AIResponseCache
from app.ai.tool_registry import AIToolRegistry
from app.models import AnalyzeRequest, AnalyzeResponse, DynamicAnalyzeRequest
from app.frida import (
    DynamicModePolicy,
    ExecutionMode,
    FridaDiagnosticsRequest,
    FridaDiagnosticsService,
    FridaServerActionRequest,
    FridaServerManager,
    PolicyFridaSession,
    build_evidence_quality,
)
from app.frida.process_monitor import classify_process_exit
from app.frida.traffic_diagnostics import diagnose_traffic
from app.comparisons import (
    ComparisonCreateRequest,
    ComparisonResult,
    ComparisonService,
)
from app.reporting import write_html_report
from app.repositories import TaskRepository
from app.repositories.task_repository import utc_now as task_utc_now
from app.orchestration.consent_checkpoint import (
    ConsentAction,
    ConsentCheckpointError,
    ConsentCheckpointRequest,
    ConsentCheckpointService,
    ConsentCheckpointState,
)
from app.orchestration.device_lease import LeaseRegistry
from app.services import AITaskService, TaskService
from app.services.application_name_service import (
    repair_historical_application_names,
)
from app.tasks.models import (
    AIStatusResponse,
    AISettingsDeleteKeyResponse,
    AISettingsResponse,
    AISettingsSaveRequest,
    AISettingsTestRequest,
    AISettingsTestResponse,
    TaskActionResponse,
    TaskAIArtifactResponse,
    TaskAIArtifactSummary,
    TaskCreateRequest,
    TaskListResponse,
    TaskRecord,
    TaskReportResponse,
    TaskSystemStatus,
)
from app.tasks.runtime import (
    TaskCancelled,
    checkpoint,
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
from app.tools.frida_session import FridaSession, FridaSessionError
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
from app.tools.logcat_collector import LogcatCollector
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
from app.tools.utils import ensure_dir, now_iso, run_cmd

app = FastAPI(title="AdSDK Agent", version="0.1.0")
frida_diagnostics_service = FridaDiagnosticsService(
    project_root=Path(__file__).resolve().parent.parent,
    server_remote_path=FRIDA_SERVER_REMOTE_PATH,
    management_enabled=FRIDA_SERVER_MANAGEMENT_ENABLED,
)
frida_server_manager = FridaServerManager(
    enabled=FRIDA_SERVER_MANAGEMENT_ENABLED,
    local_path=FRIDA_SERVER_LOCAL_PATH,
    remote_path=FRIDA_SERVER_REMOTE_PATH,
    start_timeout_seconds=FRIDA_SERVER_START_TIMEOUT_SECONDS,
    handshake_timeout_seconds=FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS,
)


def _parse_manifest_application(
    unpack_dir: str,
    *,
    apk_filename: str,
) -> dict:
    """Pass the display filename while retaining compatibility with injected parsers."""

    try:
        return parse_manifest_info(unpack_dir, apk_filename=apk_filename)
    except TypeError as exc:
        if "apk_filename" not in str(exc):
            raise
        return parse_manifest_info(unpack_dir)


def _manifest_application_fallback(
    package_name: str | None = None,
) -> dict[str, Any]:
    """Return explicit unknowns without inventing Manifest-derived evidence."""

    normalized_package = str(package_name or "").strip() or None
    return {
        "package_name": normalized_package,
        "version_name": None,
        "version_code": None,
        "application_label": None,
        "permissions": [],
        "declared_permissions": [],
        "custom_permissions": [],
        "component_permissions": [],
        "sensitive_permissions": [],
        "high_attention_permissions": [],
    }

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
    # PUT is required by the M6B AI settings endpoint; without it the browser
    # preflight fails and the Settings form can never save.
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Accept", "Content-Type"],
)

# ---------------------------------------------------------------------------
# M6B — local-only write protection for sensitive AI-config endpoints.
#
# The AI settings write surface (PUT/POST /ai/settings*) may persist an API
# key. It must only be writable from the host. A Starlette middleware (runs
# before route handlers, after CORS preflight handling) rejects any sensitive
# request that is not loopback AND, when an Origin header is present, not one
# of the configured frontend origins. A request with no Origin (local CLI /
# curl) is allowed so long as the client is loopback.
# ---------------------------------------------------------------------------
# Frontend origins allowed to mutate AI settings. Mirrors the CORS list so the
# shipped Vite dev server and any explicit override both work.
_AI_SETTINGS_ALLOWED_ORIGINS = frozenset(
    {
        "http://127.0.0.1:5173",
        "http://localhost:5173",
    }
)
_AI_SETTINGS_PATHS = frozenset(
    {
        "/ai/settings",
        "/ai/settings/test",
        "/ai/settings/api-key",
    }
)
_AI_SETTINGS_WRITE_METHODS = frozenset({"PUT", "POST", "DELETE"})


def _client_is_loopback(client_host: str | None) -> bool:
    if not client_host:
        return False
    host = client_host.split("%", 1)[0]
    if host in {"127.0.0.1", "::1", "localhost"}:
        return True
    # IPv4-mapped IPv6 loopback.
    if host in {"::ffff:127.0.0.1", "::ffff:7f00:1"}:
        return True
    # Starlette's ASGI ``TestClient`` advertises ``testclient`` as the remote
    # host. It runs in-process over a fake transport — there is no real
    # network socket behind it — so it cannot be a *remote* attacker. Treat it
    # as loopback so the test suite can exercise these endpoints; it does not
    # weaken production (real sockets never report this host).
    if host == "testclient":
        return True
    return False


def _origin_allowed_for_ai_settings(origin: str | None) -> bool:
    # No Origin header -> local CLI / curl; permitted (still requires loopback).
    if origin is None or origin == "":
        return True
    return origin in _AI_SETTINGS_ALLOWED_ORIGINS


# We use a light middleware registered right after CORS. It also strips any
# request that tries to mutate via GET query params (defense-in-depth: GET is
# not a write method, but we explicitly refuse query-param-driven config on
# these paths in the route layer too).
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request as StarletteRequest


class _AILocalOnlyMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        method = request.method.upper()
        # Normalize path (strip query) for matching.
        path = request.url.path
        if path in _AI_SETTINGS_PATHS and method in _AI_SETTINGS_WRITE_METHODS:
            client_host = request.client.host if request.client else None
            if not _client_is_loopback(client_host):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "AI 配置写接口仅允许本机访问",
                        "error_code": "ai_settings_remote_client_forbidden",
                    },
                )
            origin = request.headers.get("origin")
            if not _origin_allowed_for_ai_settings(origin):
                return JSONResponse(
                    status_code=403,
                    content={
                        "detail": "非法 Origin",
                        "error_code": "ai_settings_origin_forbidden",
                    },
                )
        return await call_next(request)


app.add_middleware(_AILocalOnlyMiddleware)

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
        "correlations": context.correlations_path,
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


def _build_and_write_evidence_correlation(
    *,
    context: AnalysisRunContext,
    dynamic_events: list[dict[str, Any]],
    network_requests: list[dict[str, Any]],
    consent_timestamp_utc: str | None,
) -> dict[str, Any]:
    """Keep correlation failures isolated from the primary report pipeline."""

    try:
        correlation = build_evidence_correlations(
            dynamic_events,
            network_requests,
            config=EvidenceCorrelationConfig(
                window_ms=EVIDENCE_CORRELATION_WINDOW_MS,
            ),
            consent_timestamp_utc=consent_timestamp_utc,
        )
    except Exception:
        correlation = build_error_correlation(
            window_ms=EVIDENCE_CORRELATION_WINDOW_MS,
            dynamic_event_count=len(dynamic_events),
            network_request_count=len(network_requests),
        )
    payload = correlation.model_dump(mode="json")
    try:
        atomic_write_json(context.correlations_path, payload)
    except Exception:
        payload["status"] = "error"
        payload.setdefault("limitations", []).append(
            "correlations.json 写入失败，主报告仍基于原始证据生成"
        )
    return payload


def _has_trusted_consent_boundary(timeline_payload: dict[str, Any]) -> bool:
    """A Consent boundary is trustworthy only with a finite monotonic mark."""

    consent_at = timeline_payload.get("consent_at")
    if not isinstance(consent_at, dict):
        return False
    monotonic = consent_at.get("monotonic_ms")
    if isinstance(monotonic, bool) or not isinstance(monotonic, (int, float)):
        return False
    return math.isfinite(float(monotonic)) and float(monotonic) >= 0


def _network_consent_states(
    network_requests: list[dict[str, Any]],
    consent_timestamp_utc: str | None,
) -> dict[str, str]:
    """Classify request consent stage from UTC evidence already in the record."""

    consent_dt = _parse_utc(consent_timestamp_utc)
    if consent_dt is None:
        return {}
    states: dict[str, str] = {}
    for index, record in enumerate(network_requests):
        if not isinstance(record, dict):
            continue
        request_id = str(
            record.get("request_id")
            or record.get("flow_id")
            or f"request-{index + 1}"
        )
        observed = _parse_utc(record.get("timestamp_utc") or record.get("timestamp"))
        if observed is None:
            continue
        states[request_id] = (
            "pre_consent" if observed < consent_dt else "post_consent"
        )
    return states


def _parse_utc(value: Any) -> datetime | None:
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _build_and_write_privacy_findings(
    *,
    context: AnalysisRunContext,
    dynamic_events: list[dict[str, Any]],
    network_requests: list[dict[str, Any]],
    correlation: dict[str, Any] | None,
    manifest_evidence: dict[str, Any] | None,
    dynamic_evidence_available: bool,
    network_evidence_available: bool,
    consent_boundary_available: bool,
    dynamic_evidence_grade: str | None,
    consent_timestamp_utc: str | None = None,
) -> dict[str, Any]:
    """Keep privacy-findings failures isolated from the primary report pipeline."""

    try:
        findings = build_privacy_findings(
            dynamic_events=dynamic_events,
            network_requests=network_requests,
            correlation=correlation,
            manifest_evidence=manifest_evidence,
            dynamic_evidence_available=dynamic_evidence_available,
            network_evidence_available=network_evidence_available,
            consent_boundary_available=consent_boundary_available,
            dynamic_evidence_grade=dynamic_evidence_grade,
            request_consent_states=_network_consent_states(
                network_requests,
                consent_timestamp_utc,
            ),
        )
    except Exception as exc:
        findings = build_error_privacy_findings(reason=type(exc).__name__)
    payload = findings.model_dump(mode="json")
    try:
        atomic_write_json(context.privacy_findings_path, payload)
    except Exception:
        payload["status"] = "error"
        payload.setdefault("limitations", []).append(
            "privacy-findings.json 写入失败，主报告仍基于原始证据生成"
        )
    return payload


@app.get("/env/check")
def env_check(device_id: str | None = None):
    resolved_device_id = device_id
    if device_id:
        try:
            resolved_device_id = select_device_context(device_id).serial
        except DeviceSelectionError:
            # Preserve the existing diagnostic response shape for stale or
            # invalid references instead of turning this compatibility route
            # into an exception.
            resolved_device_id = device_id
    adb_info = check_adb_available()
    device_info = check_device_online(device_id=resolved_device_id)
    frida_info = check_frida_connection(device_id=resolved_device_id)
    frida_runtime_info = check_frida_device_runtime(resolved_device_id)
    mitm_listen_port = DEFAULT_MITM_PORT
    mitm_8080_listening = check_port_listening(port=mitm_listen_port)
    output_info = _check_output_writable()
    serials = _device_serials(device_info, resolved_device_id)

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
        "device_id": _redact_known_device_serials(resolved_device_id, serials),
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
    try:
        resolved_device_id = select_device_context(device_id).serial
    except DeviceSelectionError:
        resolved_device_id = device_id
    device_info = check_device_online(device_id=resolved_device_id)
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

    serials = _device_serials(device_info, resolved_device_id)
    response = {
        "ok": captured_ok,
        "device_id": resolved_device_id,
        "captured_success": captured_ok,
        "captured_request_count": len(records),
        "flow_file_size": flow_file_size,
        "possible_reasons": reasons,
        "mitm_status": mitm_status,
        "sample_requests": records[:10],
    }
    return _redact_known_device_serials(response, serials)


@app.post("/frida/diagnostics")
def frida_diagnostics(request: FridaDiagnosticsRequest):
    """Run a read-only, exact-device diagnostic pass."""

    device = select_device_context(request.device_id)
    return frida_diagnostics_service.diagnose(
        request.model_copy(update={"device_id": device.serial})
    )


@app.get("/frida/status")
def frida_server_status(device_id: str = Query(min_length=1, max_length=256)):
    return frida_server_manager.status(select_device_context(device_id))


@app.post("/frida/server/deploy")
def deploy_frida_server(request: FridaServerActionRequest):
    return frida_server_manager.deploy(
        select_device_context(request.device_id),
        confirm=request.confirm,
    )


@app.post("/frida/server/start")
def start_frida_server(request: FridaServerActionRequest):
    return frida_server_manager.start(
        select_device_context(request.device_id),
        confirm=request.confirm,
    )


@app.post("/frida/server/stop")
def stop_frida_server(request: FridaServerActionRequest):
    return frida_server_manager.stop(
        select_device_context(request.device_id),
        confirm=request.confirm,
    )


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze(req: AnalyzeRequest):
    context, steps, failure_response = _prepare_run(
        req.apk_path,
        device_id=None,
    )
    if failure_response is not None:
        return failure_response
    assert context is not None

    app_info = _manifest_application_fallback()
    manifest_evidence: dict[str, Any] = {
        "status": "not_evaluated",
        "error_code": None,
        "message": "Manifest evidence has not been evaluated",
    }
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
            parsed_app_info = _parse_manifest_application(
                str(analysis_dir),
                apk_filename=context.source_apk_display,
            )
            app_info = {
                **_manifest_application_fallback(),
                **parsed_app_info,
            }
            manifest_evidence = {
                "status": "evaluated",
                "error_code": None,
                "message": None,
            }
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
            manifest_evidence = {
                "status": "not_evaluated",
                "error_code": "manifest_parse_failed",
                "message": f"manifest parse failed: {type(exc).__name__}",
            }
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
    report["manifest_evidence"] = manifest_evidence
    if manifest_evidence["status"] != "evaluated":
        report.setdefault("limitations", []).append(
            "Manifest evidence unavailable; Manifest-dependent conclusions were not evaluated"
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

    app_info = _manifest_application_fallback(req.package_name)
    manifest_evidence: dict[str, Any] = {
        "status": "not_evaluated",
        "error_code": None,
        "message": "Manifest evidence has not been evaluated",
    }
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
            parsed_app_info = _parse_manifest_application(
                str(analysis_dir),
                apk_filename=context.source_apk_display,
            )
            app_info = {
                **_manifest_application_fallback(req.package_name),
                **parsed_app_info,
            }
            if not app_info.get("package_name"):
                app_info["package_name"] = (
                    str(req.package_name or "").strip() or None
                )
            manifest_evidence = {
                "status": "evaluated",
                "error_code": None,
                "message": None,
            }
            steps.append(
                _step_result(
                    "manifest_parse",
                    StepStatus.SUCCESS,
                    started,
                    required=False,
                )
            )
        except Exception as exc:
            manifest_evidence = {
                "status": "not_evaluated",
                "error_code": "manifest_parse_failed",
                "message": f"manifest parse failed: {type(exc).__name__}",
            }
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
                warnings=[
                    "attach_only 保留当前目标进程，本次任务跳过 APK 重新安装"
                ],
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
    frida_session: Any = None
    mitm_session: Any = None
    collection_result: DynamicCollectionResult | None = None
    dynamic_events: list[dict[str, Any]] = []
    correlation_requests: list[dict[str, Any]] = []
    traffic_summary: dict[str, Any]
    legacy_mode = _legacy_fixture_mode()
    transport_path = (
        context.run_dir / ".legacy-hook.transport"
        if legacy_mode
        else context.events_raw_path
    )
    frida_diagnostic_payload: dict[str, Any] | None = None

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
            if FridaSession is _ORIGINAL_FRIDA_SESSION_CLASS:
                report_step("frida_diagnostics", "running", "正在执行 Frida 分层诊断")
                diagnostic_result = frida_diagnostics_service.diagnose(
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
                            if diagnostic_status is StepStatus.FAILED
                            and diagnostic_result.issues
                            else None
                        ),
                        error_message=(
                            diagnostic_result.issues[0].summary
                            if diagnostic_status is StepStatus.FAILED
                            and diagnostic_result.issues
                            else None
                        ),
                        details={
                            "overall_status": diagnostic_result.overall_status,
                            "recommended_mode": diagnostic_result.recommended_mode,
                            "device_ref": diagnostic_result.device_ref,
                        },
                    )
                )

                def make_frida_session(mode: ExecutionMode) -> FridaSession:
                    return FridaSession(
                        run_id=context.run_id,
                        device=device_context,
                        package_name=package_name,
                        script_path=script_path,
                        event_log_path=context.events_raw_path,
                        protocol_error_path=(
                            context.run_dir / "frida.protocol-errors.jsonl"
                        ),
                        stop_timeout_seconds=FRIDA_STOP_TIMEOUT_SECONDS,
                        execution_mode=(
                            ExecutionMode.ATTACH_EXISTING.value
                            if mode is ExecutionMode.LAUNCH_THEN_ATTACH
                            else mode.value
                        ),
                    )

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
                            device_context.adb_command(
                                "shell", "pidof", package_name
                            ),
                            timeout=3,
                        )
                        if (
                            pid_result.get("returncode") == 0
                            and str(pid_result.get("stdout") or "").strip()
                        ):
                            pid_observed = _utc_now()
                            return {
                                "launch_requested_at": launch_requested.isoformat(
                                    timespec="milliseconds"
                                ).replace("+00:00", "Z"),
                                "pid_observed_at": pid_observed.isoformat(
                                    timespec="milliseconds"
                                ).replace("+00:00", "Z"),
                                "_launch_requested_datetime": launch_requested,
                            }
                        time.sleep(0.25)
                    raise FridaSessionError(
                        "package_process_not_found",
                        "Target package did not expose a process after launch",
                    )

                frida_session = PolicyFridaSession(
                    policy=DynamicModePolicy(req.dynamic_mode_policy),
                    session_factory=make_frida_session,
                    launch_target=launch_target_for_attach,
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
            correlation_requests = [
                record.model_dump(mode="json")
                for record in traffic_result.records
            ]
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
    if not correlation_requests:
        correlation_requests = [
            dict(item)
            for item in traffic_summary.get("sample_requests") or []
            if isinstance(item, dict)
        ]
    mitm_public_status = (
        _session_status(mitm_session, device_context)
        if mitm_session is not None and device_context is not None
        else None
    )
    try:
        mitm_stderr_text = context.mitm_stderr_path.read_text(
            encoding="utf-8", errors="replace"
        )[-64 * 1024 :]
    except OSError:
        mitm_stderr_text = ""
    traffic_diagnostics = diagnose_traffic(
        collector_outcome=str(
            traffic_summary.get("collector_outcome") or "collector_failed"
        ),
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
            (
                StepStatus.PARTIAL
                if traffic_diagnostics.reason_codes
                else StepStatus.SUCCESS
            ),
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

    process_diagnostics_payload: dict[str, Any] | None = None
    if (
        device_context is not None
        and FridaSession is _ORIGINAL_FRIDA_SESSION_CLASS
        and frida_session is not None
    ):
        runtime_failure_sessions = list(
            getattr(frida_session, "runtime_failure_sessions", [])
        )
        diagnostic_session = (
            runtime_failure_sessions[-1]
            if runtime_failure_sessions
            else frida_session
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
    network_evidence_available = traffic_summary.get("collector_outcome") in {
        "collector_success_zero_requests",
        "collector_success_requests_observed",
    }
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
    environment_capabilities = dict(
        getattr(frida_session, "environment_capabilities", {})
    )
    diagnostic_capabilities = (
        (frida_diagnostic_payload or {}).get("capabilities") or {}
    )
    for key, value in diagnostic_capabilities.items():
        if environment_capabilities.get(key) is None:
            environment_capabilities[key] = value
    execution_decision = {
        "policy": req.dynamic_mode_policy,
        "selected_mode": selected_mode.value,
        "attempts": [
            item.model_dump(mode="json")
            if hasattr(item, "model_dump")
            else dict(item)
            for item in execution_attempts
        ],
        "fallback_path": list(getattr(frida_session, "fallback_path", [])),
        "launch_timing": dict(getattr(frida_session, "launch_timing", {})),
    }
    evidence_quality = build_evidence_quality(
        selected_mode,
        transport_trusted=hook_evidence_available,
        hook_ready_trusted=hook_evidence_available,
        event_protocol_trusted=hook_evidence_available
        and not bool(getattr(frida_session, "protocol_errors", [])),
        consent_boundary_trusted=hook_evidence_available
        and (req.consent_after_seconds is None or consent_time is not None),
        network_evidence=network_evidence_available,
        early_lifecycle_verified=False,
        reason_codes=[
            code
            for code in (
                collection_result.primary_error_code,
                *[
                    getattr(item, "reason_code", None)
                    for item in execution_attempts
                ],
            )
            if code
        ],
    )
    dynamic_validation_level = evidence_quality.level
    crashed_attempt = next(
        (
            attempt
            for attempt in execution_attempts
            if getattr(attempt, "process_result", None) == "process_crashed"
        ),
        None,
    )
    task_result = {
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
                error_message=(
                    attempt.message if attempt.status == "failed" else None
                ),
                details={"mode": attempt.mode.value},
            )
        )
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
                    "没有可用的动态执行模式"
                    if selected_mode is ExecutionMode.NONE
                    else None
                ),
                details=execution_decision,
            ),
            _step_result(
                "resource_cleanup",
                (
                    StepStatus.PARTIAL
                    if collection_result.cleanup_errors
                    else StepStatus.SUCCESS
                ),
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
            mitm_public_status
        ),
        "timeline": timeline_payload,
        "collection_status": collection_result.status,
        "cleanup_errors": list(collection_result.cleanup_errors),
        "execution": execution_decision,
        "environment_capabilities": environment_capabilities,
        "task_result": task_result,
        "evidence_quality": evidence_quality.model_dump(mode="json"),
    }
    atomic_write_json(context.sessions_path, sessions_payload)

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
            "dynamic_execution": execution_decision,
            "environment_capabilities": environment_capabilities,
            "dynamic_task_result": task_result,
            "dynamic_evidence_quality": evidence_quality.model_dump(mode="json"),
            "frida_diagnostics": frida_diagnostic_payload,
            "process_diagnostics": process_diagnostics_payload,
            "traffic_diagnostics": traffic_diagnostics.model_dump(mode="json"),
            "dynamic_timeline": timeline_payload,
            "collector_sessions": sessions_payload,
            "manifest_evidence": manifest_evidence,
            "device": (
                device_context.to_public_dict()
                if device_context is not None
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
                    if manifest_evidence["status"] != "evaluated"
                    else []
                ),
            ],
        }
    )
    consent_timestamp_utc = None
    raw_consent = timeline_payload.get("consent_at")
    if isinstance(raw_consent, dict):
        value = raw_consent.get("timestamp_utc")
        consent_timestamp_utc = str(value) if value else None
    elif isinstance(raw_consent, str):
        consent_timestamp_utc = raw_consent
    report["evidence_correlation"] = _build_and_write_evidence_correlation(
        context=context,
        dynamic_events=dynamic_events,
        network_requests=correlation_requests,
        consent_timestamp_utc=consent_timestamp_utc,
    )
    consent_boundary_available = _has_trusted_consent_boundary(timeline_payload)
    report["privacy_findings"] = _build_and_write_privacy_findings(
        context=context,
        dynamic_events=dynamic_events,
        network_requests=correlation_requests,
        correlation=report["evidence_correlation"],
        manifest_evidence=manifest_evidence,
        dynamic_evidence_available=hook_evidence_available,
        network_evidence_available=network_evidence_available,
        consent_boundary_available=consent_boundary_available,
        dynamic_evidence_grade=dynamic_validation_level,
        consent_timestamp_utc=consent_timestamp_utc,
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

# M6B — single AI settings service + provider factory for the process.
# ``ai_settings_store`` owns the public JSON + DPAPI secret file; the service
# validates/persists and returns masked responses; the factory hot-swaps the
# in-process provider on save (new tasks pick up new config, running tasks keep
# their snapshot). All three are plain module attributes so tests can patch them
# (mirroring the ``task_service``/``task_repository`` seam).
ai_settings_store = AISettingsStore()
ai_settings_service = AISettingsService(ai_settings_store)

# M7A — process-wide consent checkpoint registry and reclaimable device lease.
# The checkpoint is the authority for ``awaiting_consent_action``: only a human
# operator resolves it (confirmed / not_found / skipped). The AI can never
# auto-confirm it and no timer ever flips it to confirmed — a watchdog may only
# *cancel*, which exits the wait and proceeds to cleanup.
consent_checkpoint_service = ConsentCheckpointService(clock=task_utc_now)
device_lease_registry = LeaseRegistry(
    clock=time.monotonic,
    stale_after_seconds=M7A_LEASE_STALE_SECONDS,
)


def _run_persisted_task(task: TaskRecord):
    payload = dict(task.request_payload)
    if task.task_type == "static":
        return analyze(AnalyzeRequest(apk_path=str(payload["apk_path"])))
    if task.task_type == "dynamic":
        return dynamic_analyze(DynamicAnalyzeRequest.model_validate(payload))
    if task.task_type == "ai_orchestrated":
        return _run_ai_orchestrated_task(task, payload)
    raise ValueError(f"unsupported executable task type: {task.task_type}")


def _run_ai_orchestrated_task(
    task: TaskRecord,
    payload: dict[str, Any],
) -> dict[str, Any] | JSONResponse:
    """Run one ``ai_orchestrated`` task.

    The deterministic analysis runs first and owns the task's success/failure
    semantics. AI orchestration then layers scheduling and narration on top:
    an AI failure degrades the AI section only and never fails the task.
    """

    scope = str(payload.get("analysis_scope") or "static_only")
    allow_dynamic = bool(payload.get("allow_dynamic"))
    apk_path = str(payload["apk_path"])

    # 1. Deterministic analysis via the existing entry points. This is the
    #    same code path the plain static / dynamic task types use.
    report_step("ai_planning", "running", "正在准备确定性证据")
    deterministic: dict[str, Any] | JSONResponse
    if allow_dynamic and scope in {"dynamic_only", "full_analysis"}:
        dynamic_request = DynamicAnalyzeRequest.model_validate(
            {
                key: value
                for key, value in payload.items()
                if key in DynamicAnalyzeRequest.model_fields
            }
        )
        deterministic = dynamic_analyze(dynamic_request)
    else:
        deterministic = analyze(AnalyzeRequest(apk_path=apk_path))

    base_report = task_service_response_payload(deterministic)
    run_dir = _ai_run_dir(base_report)

    # 2. AI orchestration. Every failure inside this block degrades the AI
    #    section only; the deterministic report above is already published.
    ai_section: dict[str, Any]
    try:
        ai_section = _execute_ai_orchestration(
            task=task,
            payload=payload,
            run_dir=run_dir,
            base_report=base_report,
        )
    except TaskCancelled:
        raise
    except Exception as exc:
        ai_section = {
            "status": "failed",
            "error_code": "ai_orchestration_failed",
            "limitations": [f"AI 编排执行异常：{type(exc).__name__}"],
        }

    base_report["ai_orchestration"] = ai_section
    # Re-publish report.json so the AI section is part of the persisted
    # artifact, without touching any deterministic field.
    try:
        if run_dir is not None:
            atomic_write_json(run_dir / "report.json", base_report)
    except Exception:
        base_report.setdefault("limitations", []).append(
            "AI 综合研判未能写入 report.json，确定性证据不受影响"
        )
    if isinstance(deterministic, JSONResponse):
        return JSONResponse(
            status_code=deterministic.status_code,
            content=base_report,
        )
    return base_report


def task_service_response_payload(
    result: dict[str, Any] | JSONResponse,
) -> dict[str, Any]:
    """Normalise a runner result to a plain dict without losing failure state."""

    if isinstance(result, JSONResponse):
        return json.loads(result.body.decode("utf-8"))
    return dict(result)


def _ai_run_dir(report: dict[str, Any]) -> Path | None:
    raw = report.get("output_dir")
    if not raw:
        return None
    candidate = Path(str(raw))
    return candidate if candidate.is_dir() else None


def _execute_ai_orchestration(
    *,
    task: TaskRecord,
    payload: dict[str, Any],
    run_dir: Path | None,
    base_report: dict[str, Any],
) -> dict[str, Any]:
    """Build and run the orchestrator, returning the public AI section."""

    report_step("ai_tool_execution", "running", "正在执行 AI 编排工具")
    scope = str(payload.get("analysis_scope") or "static_only")
    allow_dynamic = bool(payload.get("allow_dynamic"))
    confirmed = frozenset(
        str(item) for item in (payload.get("confirmed_tools") or [])
    )
    effective = resolve_effective_ai_settings(ai_settings_service.store)
    ai_enabled = bool(effective["enabled"]) and bool(payload.get("ai_enabled", True))

    # Every new task captures the provider built from the same live effective
    # settings as /ai/settings and /ai/status.  It never falls back to the
    # import-time env-only builder, which could select stale empty settings.
    provider = ai_settings_service.factory.current() if ai_enabled else None
    orchestrator = AIOrchestrator(
        provider=provider,
        registry=AIToolRegistry(allow_dynamic_tools=bool(effective["allow_dynamic_tools"])),
        enabled=ai_enabled,
        cancelled=_ai_cancelled,
    )
    service = AITaskService(
        orchestrator=orchestrator,
        run_dir=run_dir or Path(OUTPUT_DIR),
        static_runner=lambda: base_report,
        dynamic_runner=lambda: base_report,
        environment_probe=lambda: env_check(payload.get("device_id")),
    )
    request = AIOrchestrationRequest(
        objective=str(payload.get("objective") or "分析本次 APK 的隐私风险"),
        analysis_scope=scope,
        task_id=task.id,
        allow_dynamic=allow_dynamic,
        allow_network=bool(payload.get("allow_network")),
        confirmed_tools=confirmed,
        token_budget=int(payload.get("token_budget") or 0) or None,
        report_language=str(payload.get("report_language") or effective["report_language"]),
        run_dir=run_dir,
    )
    report_step("ai_evidence_digest", "running", "正在构建证据摘要")
    result = service.run(request)
    report_step(
        "ai_report",
        "success" if result.status in {"completed", "partial"} else "partial",
        f"AI 综合研判：{result.status}",
    )
    return _public_ai_section(result)


def _ai_cancelled() -> bool:
    """Cancellation probe for the orchestrator (never raises)."""

    try:
        checkpoint()
    except TaskCancelled:
        return True
    return False


def _public_ai_section(result: AIOrchestrationResult) -> dict[str, Any]:
    """The AI section embedded in report.json / the API response.

    Contains no API key, no raw model request/response, and no reasoning text.
    """

    return {
        "schema_version": "ai-report-v1",
        "status": result.status,
        "plan": result.plan.model_dump(mode="json"),
        "report": result.report.model_dump(mode="json"),
        "usage": result.usage.model_dump(mode="json"),
        "trace": result.trace.model_dump(mode="json"),
        "evidence_digest_hash": result.digest.digest_hash,
        "error_code": result.error_code,
        "unavailable_reason": result.unavailable_reason,
        # M6C — observable runtime diagnostics (per-round token provenance,
        # classified errors, latency/cache/retry status). No API key, no prompt
        # or response text, no reasoning_content content — only a presence bool.
        "diagnostic": result.diagnostic_payload(),
    }


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
    allowed_types = {"static", "dynamic", "comparison", "ai_orchestrated"}
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


@app.get("/ai/status", response_model=AIStatusResponse)
def ai_status(probe: bool = Query(default=False)):
    """Public AI availability.

    Never returns the API key (or any derivative of it). ``reachable`` is only
    evaluated when ``probe=true`` so a page load never calls the external
    model; otherwise it stays ``null`` ("not probed").
    """

    effective = resolve_effective_ai_settings(ai_settings_service.store)
    configured = bool(effective["configured"])
    reachable: bool | None = None
    last_error_code: str | None = None
    if probe and effective["enabled"] and configured:
        provider = ai_settings_service.factory.current()
        if provider is None:
            last_error_code = "ai_provider_build_failed"
        else:
            try:
                reachable, reason = provider.reachable()
                if not reachable:
                    last_error_code = f"ai_provider_{reason or 'unreachable'}"
            except Exception:
                reachable = False
                last_error_code = "ai_provider_unreachable"
    return AIStatusResponse(
        enabled=bool(effective["enabled"]),
        provider=str(effective["provider"] or ""),
        model=str(effective["model"] or ""),
        configured=configured,
        reachable=reachable,
        last_error_code=last_error_code,
        default_token_budget=int(effective["default_token_budget"]),
        max_rounds=int(effective["max_rounds"]),
        max_tool_calls=int(effective["max_tool_calls"]),
        report_language=str(effective["report_language"]),
        allow_dynamic_tools=bool(effective["allow_dynamic_tools"]),
    )


# ===========================================================================
# M6B — secure frontend AI configuration center.
#
# All four endpoints below:
#   * never return the API key (only ``api_key_configured`` + ``api_key_source``)
#   * never log request bodies (the write endpoints are blocked by
#     ``_AILocalOnlyMiddleware`` for non-loopback / unknown origins)
#   * never persist the key to the frontend-visible JSON; it lives in the
#     DPAPI ``ai-secret.bin`` file via ``AISettingsStore.set_api_key``.
# ===========================================================================


@app.get("/ai/settings", response_model=AISettingsResponse)
def get_ai_settings():
    """Return the masked effective AI configuration.

    The API key is never present. ``api_key_configured`` is the only key-
    derived boolean. Corrupted local settings degrade to defaults rather than
    500.
    """

    try:
        return ai_settings_service.get_effective_settings()
    except Exception:  # pragma: no cover - defensive, never leaks key
        # Best-effort structured degradation; the layered store already
        # swallows corruption, so reaching here is unexpected.
        return JSONResponse(
            status_code=500,
            content={
                "detail": "AI 设置不可用",
                "error_code": "ai_settings_unavailable",
            },
        )


@app.put("/ai/settings", response_model=AISettingsResponse)
def update_ai_settings(request: AISettingsSaveRequest):
    """Save editable AI configuration + optional new API key. Body is never logged.

    A missing or empty ``api_key`` field preserves the stored key; deletion
    is a separate authenticated action (DELETE /ai/settings/api-key).
    """

    try:
        payload = request.model_dump(exclude_none=False)
        # ``model_dump`` keeps ``None`` for omitted fields; we drop them so the
        # service only sees supplied keys. ``api_key`` must pass through even
        # when it is an empty string ("" == preserve), so handle separately.
        supplied = {}
        if "api_key" in payload and payload["api_key"] is not None:
            supplied["api_key"] = payload["api_key"]
        for key, value in payload.items():
            if key == "api_key":
                continue
            if value is not None:
                supplied[key] = value
        return ai_settings_service.save_settings(supplied)
    except AISettingsValidationError as exc:
        return JSONResponse(
            status_code=422,
            content={"detail": exc.safe_message, **exc.to_dict()},
        )
    except Exception as exc:  # pragma: no cover - defensive
        # Never leak the key via an unexpected exception's repr/args. Surface
        # only a type name.
        return JSONResponse(
            status_code=500,
            content={
                "detail": "AI 设置保存失败",
                "error_code": "ai_settings_save_failed",
                "safe_message": type(exc).__name__,
            },
        )


@app.post("/ai/settings/test", response_model=AISettingsTestResponse)
def test_ai_settings(request: AISettingsTestRequest):
    """Test the current or a temporary configuration. Temporary key is not saved.

    The request body (which may carry a temporary ``api_key``) is never logged
    and never persisted. The probe tries ``/models`` first, then a minimal
    chat completion (max_tokens=1) for gateways that do not expose ``/models``.
    """

    try:
        temp = request.model_dump(exclude_none=True)
        return ai_settings_service.test_connection(temp)
    except AISettingsValidationError as exc:
        return JSONResponse(
            status_code=422,
            content={"detail": exc.safe_message, **exc.to_dict()},
        )
    except Exception as exc:  # pragma: no cover - defensive
        return JSONResponse(
            status_code=500,
            content={
                "detail": "测试连接失败",
                "error_code": "ai_settings_test_failed",
                "safe_message": type(exc).__name__,
            },
        )


@app.delete("/ai/settings/api-key", response_model=AISettingsDeleteKeyResponse)
def delete_ai_api_key():
    """Delete the locally-saved API key only. An environment-variable key is untouched."""

    deleted = ai_settings_service.delete_api_key()
    source = ai_settings_service.store.api_key_source()
    # After deleting a local key, if an env key exists it remains the source.
    return AISettingsDeleteKeyResponse(
        deleted=deleted,
        api_key_source=source,
        api_key_configured=source != "none",
    )


def _read_task_ai_artifact(task_id: str, filename: str) -> TaskAIArtifactResponse:
    task = task_service.get(task_id)
    if task is None:
        raise _task_not_found(task_id)
    payload: dict[str, Any] | None = None
    if task.report_json_path:
        candidate = Path(task.report_json_path).resolve(strict=False).parent / filename
        allowed = (Path(OUTPUT_DIR).resolve(strict=False) / "runs").resolve(
            strict=False
        )
        if candidate.is_relative_to(allowed) and candidate.is_file():
            try:
                loaded = json.loads(candidate.read_text(encoding="utf-8"))
            except Exception:
                loaded = None
            if isinstance(loaded, dict):
                payload = loaded
    return TaskAIArtifactResponse(
        task_id=task_id,
        status=task.status,
        available=payload is not None,
        payload=payload,
    )


@app.get("/tasks/{task_id}/ai-plan", response_model=TaskAIArtifactResponse)
def get_task_ai_plan(task_id: str):
    return _read_task_ai_artifact(task_id, "ai-plan.json")


@app.get("/tasks/{task_id}/ai-report", response_model=TaskAIArtifactResponse)
def get_task_ai_report(task_id: str):
    return _read_task_ai_artifact(task_id, "ai-report.json")


@app.get(
    "/tasks/{task_id}/ai-runtime-diagnostics",
    response_model=TaskAIArtifactResponse,
)
def get_task_ai_runtime_diagnostics(task_id: str):
    """The ``ai-runtime-diagnostics-v1`` artifact.

    Observable runtime facts only (per-round token provenance, classified
    errors, latency, retry/cache status). No API key, no prompt or response
    text, no reasoning_content content — the artifact simply never carries it.
    """

    return _read_task_ai_artifact(task_id, "ai-runtime-diagnostics.json")


@app.post(
    "/tasks/{task_id}/ai-report/regenerate",
    response_model=TaskAIArtifactSummary,
)
def regenerate_task_ai_report(
    task_id: str,
    use_cache: bool | None = None,
):
    """Re-run only the AI orchestration against the task's *existing* deterministic
    artifacts. Never re-runs static / dynamic / traffic analysis (must-complete:
    the deterministic evidence on disk is the source of truth).

    ``use_cache`` overrides the configured cache for this regeneration:

    * ``None``  -> honour the saved effective cache setting (default behaviour).
    * ``True``  -> force the response cache on (a cache hit avoids a real model
      call entirely — zero tokens). Used for the cache-acceptance scenario.
    * ``False`` -> force the response cache off (always a real model call).

    The API key, full prompts, full model responses, and reasoning_content
    content are never written or returned. The body carries no secrets, so it
    is read from the query string; no key is echoed in the summary.
    """

    task = task_service.get(task_id)
    if task is None:
        raise _task_not_found(task_id)

    # Resolve the persisted run directory from the deterministic report path.
    if not task.report_json_path:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ai_regenerate_no_report",
                "message": "任务尚无可复用的确定性报告，无法仅重跑 AI 编排",
            },
        )
    run_dir = Path(task.report_json_path).resolve(strict=False).parent
    allowed_root = (Path(OUTPUT_DIR).resolve(strict=False) / "runs").resolve(
        strict=False
    )
    if not run_dir.is_relative_to(allowed_root) or not (run_dir / "report.json").is_file():
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ai_regenerate_no_report",
                "message": "任务尚无可复用的确定性报告，无法仅重跑 AI 编排",
            },
        )

    payload = dict(task.request_payload or {})
    try:
        base_report = json.loads(
            (run_dir / "report.json").read_text(encoding="utf-8")
        )
    except Exception:
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ai_regenerate_no_report",
                "message": "确定性报告读取失败，无法仅重跑 AI 编排",
            },
        )
    if not isinstance(base_report, dict):
        raise HTTPException(
            status_code=409,
            detail={
                "code": "ai_regenerate_no_report",
                "message": "确定性报告格式异常，无法仅重跑 AI 编排",
            },
        )

    scope = str(payload.get("analysis_scope") or "static_only")
    allow_dynamic = bool(payload.get("allow_dynamic"))
    confirmed = frozenset(
        str(item) for item in (payload.get("confirmed_tools") or [])
    )
    effective = resolve_effective_ai_settings(ai_settings_service.store)
    ai_enabled = bool(effective["enabled"]) and bool(payload.get("ai_enabled", True))

    # Regeneration uses the same effective snapshot as new tasks and status.
    cache_enabled_default = bool(effective["cache_enabled"])
    cache_enabled = (
        cache_enabled_default if use_cache is None else bool(use_cache)
    )

    provider = ai_settings_service.factory.current() if ai_enabled else None
    orchestrator = AIOrchestrator(
        provider=provider,
        registry=AIToolRegistry(allow_dynamic_tools=bool(effective["allow_dynamic_tools"])),
        cache=AIResponseCache(enabled=cache_enabled),
        enabled=ai_enabled,
        cancelled=_ai_cancelled,
    )
    service = AITaskService(
        orchestrator=orchestrator,
        run_dir=run_dir,
        static_runner=lambda: base_report,
        dynamic_runner=lambda: base_report,
        environment_probe=lambda: env_check(payload.get("device_id")),
    )
    request = AIOrchestrationRequest(
        objective=str(payload.get("objective") or "分析本次 APK 的隐私风险"),
        analysis_scope=scope,
        task_id=task.id,
        allow_dynamic=allow_dynamic,
        allow_network=bool(payload.get("allow_network")),
        confirmed_tools=confirmed,
        token_budget=int(payload.get("token_budget") or 0) or None,
        report_language=str(payload.get("report_language") or effective["report_language"]),
        run_dir=run_dir,
    )
    try:
        result = service.run(request)
        ai_section = _public_ai_section(result)
    except TaskCancelled:
        raise
    except Exception as exc:
        ai_section = {
            "schema_version": "ai-report-v1",
            "status": "failed",
            "error_code": "ai_orchestration_failed",
            "limitations": [f"AI 编排执行异常：{type(exc).__name__}"],
        }

    # Re-publish report.json so the regenerated AI section replaces the prior
    # one without touching any deterministic field.
    base_report["ai_orchestration"] = ai_section
    try:
        atomic_write_json(run_dir / "report.json", base_report)
    except Exception:
        base_report.setdefault("limitations", []).append(
            "AI 综合研判重跑未能写入 report.json，确定性证据不受影响"
        )

    return TaskAIArtifactSummary(
        task_id=task_id,
        status=task.status,
        ai_status=str(ai_section.get("status")),
        ai_section=ai_section,
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
        result = task_service.cancel(task_id)
    except KeyError:
        raise _task_not_found(task_id)
    except ValueError as exc:
        raise HTTPException(
            status_code=409,
            detail={"code": "task_not_cancellable", "message": str(exc)},
        )
    # M7A — a task waiting on the manual consent checkpoint must exit that wait
    # on cancel so cleanup runs. Cancelling never confirms consent.
    consent_checkpoint_service.cancel(task_id=task_id)
    return result


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


@app.get(
    "/tasks/{task_id}/consent-checkpoint",
    response_model=ConsentCheckpointState,
)
def get_consent_checkpoint(task_id: str):
    """Read the current consent checkpoint for a task.

    Returns 404 when the task has no checkpoint awaiting (either it never
    reached ``awaiting_consent_action`` or the checkpoint was already cleared
    by cleanup). The payload carries no UI text, no cookies, no bodies.
    """
    if task_service.get(task_id) is None:
        raise _task_not_found(task_id)
    state = consent_checkpoint_service.state(task_id)
    if state is None:
        raise HTTPException(
            status_code=404,
            detail={
                "code": "checkpoint_not_found",
                "message": "该任务当前没有等待中的 Consent 检查点",
            },
        )
    return state


@app.post(
    "/tasks/{task_id}/consent-checkpoint",
    response_model=ConsentCheckpointState,
)
def resolve_consent_checkpoint(task_id: str, req: ConsentCheckpointRequest):
    """Resolve the manual consent checkpoint for a running full-analysis task.

    Only a human operator reaches this route. The action is one of
    ``confirmed`` / ``not_found`` / ``skipped`` — the AI never calls it and no
    timer ever produces ``confirmed``. The call is idempotent for a repeat of
    the same action and state-gated: resolving a task that is not awaiting
    consent returns 409, and a different action after resolution returns 409.
    """
    if task_service.get(task_id) is None:
        raise _task_not_found(task_id)
    try:
        return consent_checkpoint_service.resolve(
            task_id=task_id,
            action=req.action,
            note=req.note,
        )
    except ConsentCheckpointError as exc:
        status_code = 404 if exc.code == "checkpoint_not_found" else 409
        raise HTTPException(
            status_code=status_code,
            detail={"code": exc.code, "message": exc.message},
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
