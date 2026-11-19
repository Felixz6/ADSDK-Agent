"""AdSDK Agent FastAPI application entry point."""

from __future__ import annotations

import time
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

from app.ai.orchestrator import AIOrchestrator
from app.ai.settings_service import resolve_effective_ai_settings
from app.analyzers.evidence_correlation import build_evidence_correlations
from app.analyzers.privacy_findings import build_privacy_findings
from app.api.errors import _task_not_found, task_not_found

# ---------------------------------------------------------------------------
# Re-exported config constants (used by routes and tests via main.X)
# ---------------------------------------------------------------------------
from app.config import (
    ALLOW_UNC_APK_PATHS,
    APK_ALLOWED_ROOTS,
    APK_MAX_SIZE_BYTES,
    DEFAULT_MITM_PORT,  # noqa: F401  # re-export for monkeypatch，阶段 3 移除
    EVIDENCE_CORRELATION_WINDOW_MS,
    FRIDA_READY_TIMEOUT_SECONDS,
    FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS,
    FRIDA_SERVER_LOCAL_PATH,
    FRIDA_SERVER_MANAGEMENT_ENABLED,
    FRIDA_SERVER_REMOTE_PATH,
    FRIDA_SERVER_START_TIMEOUT_SECONDS,
    FRIDA_SPAWN_STABILITY_SECONDS,
    FRIDA_STOP_TIMEOUT_SECONDS,
    M7A_CONSENT_WAIT_SECONDS,
    M7A_LEASE_STALE_SECONDS,
    MITM_DEVICE_PROXY_HOST,
    MITM_LISTEN_HOST,
    MITM_READY_TIMEOUT_SECONDS,
    MITM_STOP_TIMEOUT_SECONDS,
    OUTPUT_DIR,
    REDACTION_HMAC_KEY,
    SCHEMA_VERSION,
    STATIC_UNPACK_CACHE_DIR,
    TASK_DATABASE_PATH,
)

# ---------------------------------------------------------------------------
# Container and core services
# ---------------------------------------------------------------------------
from app.container import (
    ai_settings_service,
    ai_settings_store,
    comparison_service,
    consent_checkpoint_service,
    device_lease_registry,
    frida_diagnostics_service,
    frida_server_manager,
    task_repository,
    task_service,
)
from app.core.artifacts import atomic_write_json

# ---------------------------------------------------------------------------
# Re-exported tool & runner functions for tests / compatibility
# ---------------------------------------------------------------------------
from app.core.clock import parse_utc as _parse_utc, utc_now as _utc_now
from app.core.device import DeviceContext
from app.core.redaction import (
    _device_serials,
    _redact_known_device_serials,
    extract_device_serials,
    redact_known_device_serials,
)
from app.models import AnalyzeRequest, AnalyzeResponse, DynamicAnalyzeRequest
from app.orchestration.device_ops import (
    _adb_cleanup_action,
    _device_package_pids,
    _device_process_command,
    _host_process_command,
    _read_device_proxy,
    _stop_owned_host_pid,
)
from app.orchestration.full_analysis_session import FullAnalysisSession
from app.orchestration.production_session_effects import ProductionSessionEffects

# ---------------------------------------------------------------------------
# Re-exported pipeline implementations
# ---------------------------------------------------------------------------
from app.pipelines.common import (
    _CRITICAL_STEPS,
    _ai_cancelled,
    _ai_run_dir,
    _artifact_entries,
    _base_report,
    _build_and_write_evidence_correlation,
    _build_and_write_privacy_findings,
    _check_output_writable,
    _collect_warnings,
    _finalize_report,
    _has_trusted_consent_boundary,
    _manifest_application_fallback,
    _network_consent_states,
    _overall_status,
    _parse_manifest_application,
    _prepare_run,
    _public_ai_section,
    _redact_device_diagnostic,
    _safe_apk_input_display,
    _step_result,
    _steps_payload,
    _validation_failure_response,
    resolve_frida_hook_script,
    task_service_response_payload,
)
from app.pipelines.dynamic import (
    _append_collection_steps,
    _build_dynamic_findings,
    _dynamic_analyze_v2,
    _emit_frida_control,
    _legacy_fixture_mode,
    _normalize_events,
    _session_status,
    _state_value,
    _traffic_summary_from_result,
    dynamic_analyze,
)
from app.pipelines.full_analysis import (
    _capture_m7b_device_snapshot,
    _m7b_resource_identity_matches,
    _m7b_resource_present,
    _m7b_target_pid,
    _register_m7b_owned_resources,
    _run_m7b_full_analysis_session,
)
from app.pipelines.static import analyze
from app.pipelines.task_runner import (
    _execute_ai_orchestration,
    _run_ai_orchestrated_task,
    _run_persisted_task,
    regenerate_task_ai_report,
)
from app.services import AITaskService
from app.tasks.runtime import report_step
from app.tools.adb_runner import (  # noqa: F401  # re-export for monkeypatch，阶段 3 移除
    DeviceSelectionError,
    check_adb_available,
    check_device_online,
    install_apk,
    launch_app,
    select_device_context,
)
from app.tools.apk_unpack import unpack_apk
from app.tools.dynamic_collection import run_dynamic_collection
from app.tools.env_checks import (  # noqa: F401  # re-export for monkeypatch，阶段 3 移除
    check_apk_allowed_roots,
    check_apktool,
    check_frida_python_package,
    check_redaction_hmac_key,
)
from app.tools.frida_runner import (  # noqa: F401  # re-export for monkeypatch，阶段 3 移除
    check_frida_connection,
    check_frida_device_runtime,
    spawn_and_inject,
)
from app.tools.frida_session import FridaSession, FridaSessionError
from app.tools.hook_parser import parse_hook_to_events_json
from app.tools.manifest_parser import parse_manifest_info
from app.tools.mitm_runner import (
    check_port_listening,
    get_mitm_status,  # noqa: F401  # re-export for monkeypatch，阶段 3 移除
    start_mitm,
    stop_mitm,
)
from app.tools.mitm_session import MitmSession
from app.tools.report_writer import write_markdown_report
from app.tools.sdk_fingerprint import scan_for_sdks
from app.tools.timeline_rules import evaluate_timeline_rules
from app.tools.traffic_parser import (
    parse_traffic_text,  # noqa: F401  # re-export for monkeypatch，阶段 3 移除
    parse_traffic_to_summary_json,
)
from app.tools.utils import run_cmd

# Original references for legacy fixture detection
_ORIGINAL_FRIDA_SESSION_CLASS = FridaSession
_ORIGINAL_MITM_SESSION_CLASS = MitmSession
_ORIGINAL_SPAWN_AND_INJECT = spawn_and_inject
_ORIGINAL_START_MITM = start_mitm

# Wire runner to task service
task_service.set_runner(_run_persisted_task)


# ---------------------------------------------------------------------------
# Local-only write protection middleware for AI settings
# ---------------------------------------------------------------------------
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
    return client_host in {"127.0.0.1", "::1", "localhost", "testclient"}


def _origin_allowed_for_ai_settings(origin: str | None) -> bool:
    if not origin:
        return True
    return origin in _AI_SETTINGS_ALLOWED_ORIGINS


class _AILocalOnlyMiddleware(BaseHTTPMiddleware):
    """Enforces host-only writes on sensitive AI settings endpoints."""

    async def dispatch(self, request: Request, call_next) -> Response:
        path = request.url.path
        method = request.method.upper()

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


# ---------------------------------------------------------------------------
# Application lifespan & factory
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    task_repository.initialize()
    task_service.recover()
    yield
    task_service.shutdown()


def create_app() -> FastAPI:
    app_instance = FastAPI(title="AdSDK Agent", version="0.2.0", lifespan=lifespan)
    app_instance.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://127.0.0.1:5173",
            "http://localhost:5173",
        ],
        allow_credentials=False,
        allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
        allow_headers=["Accept", "Content-Type"],
    )
    app_instance.add_middleware(_AILocalOnlyMiddleware)

    from app.api.ai import router as ai_router
    from app.api.comparisons import router as comparisons_router
    from app.api.env import router as env_router
    from app.api.tasks import router as tasks_router

    app_instance.include_router(env_router)
    app_instance.include_router(tasks_router)
    app_instance.include_router(ai_router)
    app_instance.include_router(comparisons_router)

    return app_instance


app = create_app()


@app.get("/")
def root():
    return {"ok": True, "message": "AdSDK Agent is running"}


@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_endpoint(req: AnalyzeRequest):
    return analyze(req)


@app.post("/dynamic/analyze", response_model=AnalyzeResponse)
def dynamic_analyze_endpoint(req: DynamicAnalyzeRequest):
    return dynamic_analyze(req)


__all__ = [
    "AIOrchestrator",
    "AITaskService",
    "ALLOW_UNC_APK_PATHS",
    "APK_ALLOWED_ROOTS",
    "APK_MAX_SIZE_BYTES",
    "DEFAULT_MITM_PORT",
    "DeviceContext",
    "DeviceSelectionError",
    "EVIDENCE_CORRELATION_WINDOW_MS",
    "FRIDA_READY_TIMEOUT_SECONDS",
    "FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS",
    "FRIDA_SERVER_LOCAL_PATH",
    "FRIDA_SERVER_MANAGEMENT_ENABLED",
    "FRIDA_SERVER_REMOTE_PATH",
    "FRIDA_SERVER_START_TIMEOUT_SECONDS",
    "FRIDA_SPAWN_STABILITY_SECONDS",
    "FRIDA_STOP_TIMEOUT_SECONDS",
    "FridaSession",
    "FridaSessionError",
    "FullAnalysisSession",
    "M7A_CONSENT_WAIT_SECONDS",
    "M7A_LEASE_STALE_SECONDS",
    "MITM_DEVICE_PROXY_HOST",
    "MITM_LISTEN_HOST",
    "MITM_READY_TIMEOUT_SECONDS",
    "MITM_STOP_TIMEOUT_SECONDS",
    "MitmSession",
    "OUTPUT_DIR",
    "ProductionSessionEffects",
    "REDACTION_HMAC_KEY",
    "SCHEMA_VERSION",
    "STATIC_UNPACK_CACHE_DIR",
    "TASK_DATABASE_PATH",
    "_CRITICAL_STEPS",
    "_ORIGINAL_FRIDA_SESSION_CLASS",
    "_ORIGINAL_MITM_SESSION_CLASS",
    "_ORIGINAL_SPAWN_AND_INJECT",
    "_ORIGINAL_START_MITM",
    "_adb_cleanup_action",
    "_ai_cancelled",
    "_ai_run_dir",
    "_append_collection_steps",
    "_artifact_entries",
    "_base_report",
    "_build_and_write_evidence_correlation",
    "_build_and_write_privacy_findings",
    "_build_dynamic_findings",
    "_capture_m7b_device_snapshot",
    "_check_output_writable",
    "_collect_warnings",
    "_device_package_pids",
    "_device_process_command",
    "_device_serials",
    "_dynamic_analyze_v2",
    "_emit_frida_control",
    "_execute_ai_orchestration",
    "_finalize_report",
    "_has_trusted_consent_boundary",
    "_host_process_command",
    "_legacy_fixture_mode",
    "_m7b_resource_identity_matches",
    "_m7b_resource_present",
    "_m7b_target_pid",
    "_manifest_application_fallback",
    "_network_consent_states",
    "_normalize_events",
    "_overall_status",
    "_parse_manifest_application",
    "_parse_utc",
    "_prepare_run",
    "_public_ai_section",
    "_read_device_proxy",
    "_redact_device_diagnostic",
    "_redact_known_device_serials",
    "_register_m7b_owned_resources",
    "_run_ai_orchestrated_task",
    "_run_m7b_full_analysis_session",
    "_run_persisted_task",
    "_safe_apk_input_display",
    "_session_status",
    "_state_value",
    "_step_result",
    "_steps_payload",
    "_stop_owned_host_pid",
    "_task_not_found",
    "_traffic_summary_from_result",
    "_utc_now",
    "_validation_failure_response",
    "ai_settings_service",
    "ai_settings_store",
    "analyze",
    "app",
    "atomic_write_json",
    "build_evidence_correlations",
    "build_privacy_findings",
    "check_adb_available",
    "check_apk_allowed_roots",
    "check_apktool",
    "check_device_online",
    "check_frida_connection",
    "check_frida_device_runtime",
    "check_frida_python_package",
    "check_port_listening",
    "check_redaction_hmac_key",
    "comparison_service",
    "consent_checkpoint_service",
    "create_app",
    "device_lease_registry",
    "dynamic_analyze",
    "evaluate_timeline_rules",
    "extract_device_serials",
    "frida_diagnostics_service",
    "frida_server_manager",
    "get_mitm_status",
    "install_apk",
    "launch_app",
    "lifespan",
    "parse_hook_to_events_json",
    "parse_manifest_info",
    "parse_traffic_text",
    "parse_traffic_to_summary_json",
    "redact_known_device_serials",
    "regenerate_task_ai_report",
    "report_step",
    "resolve_effective_ai_settings",
    "resolve_frida_hook_script",
    "root",
    "run_cmd",
    "run_dynamic_collection",
    "scan_for_sdks",
    "select_device_context",
    "spawn_and_inject",
    "start_mitm",
    "stop_mitm",
    "task_not_found",
    "task_repository",
    "task_service",
    "task_service_response_payload",
    "time",
    "unpack_apk",
    "write_markdown_report",
]
