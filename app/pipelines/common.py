"""Common data helpers, step reporting, and artifact finalization for analysis pipelines."""

from __future__ import annotations

import json
import math
import os
import sys
import time
from dataclasses import dataclass, replace
from datetime import datetime
from pathlib import Path
from typing import Any
from uuid import uuid4

from fastapi.responses import JSONResponse

from app.ai.orchestrator import AIOrchestrationResult
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
from app.config import (
    ALLOW_UNC_APK_PATHS,
    APK_ALLOWED_ROOTS,
    APK_MAX_SIZE_BYTES,
    EVIDENCE_CORRELATION_WINDOW_MS,
    OUTPUT_DIR,
    SCHEMA_VERSION,
    STATIC_UNPACK_CACHE_DIR,
)
from app.core.apk_snapshot import ApkSnapshotError, create_apk_snapshot
from app.core.artifacts import atomic_write_json
from app.core.clock import parse_utc as _parse_utc, utc_now as _utc_now
from app.core.device import DeviceContext
from app.core.paths import ApkPathValidationError, ApkPathValidator, sha256_file
from app.core.redaction import (
    _device_serials,
    _redact_known_device_serials,
)
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
from app.reporting import write_html_report
from app.tasks.runtime import TaskCancelled, checkpoint, current_task_id, report_step
from app.tools.apk_unpack import unpack_apk
from app.tools.env_checks import check_apktool
from app.tools.manifest_parser import parse_manifest_info
from app.tools.report_writer import write_json_report, write_markdown_report
from app.tools.sdk_fingerprint import scan_for_sdks
from app.tools.utils import ensure_dir

_CRITICAL_STEPS = {
    "apk_validation",
    "apk_hash",
    "apk_snapshot",
    "apk_unpack",
    "report_write",
}


def _get_hook(name: str, fallback: Any) -> Any:
    main = sys.modules.get("app.main")
    if main is not None and hasattr(main, name):
        return getattr(main, name)
    return fallback


def resolve_frida_hook_script(hooks_dir: Path | None = None) -> Path:
    """Pick the hook agent source injected into target processes."""
    directory = hooks_dir or (
        Path(__file__).resolve().parent.parent / "frida_hooks"
    )
    bundled = directory / "agent.compiled.js"
    if bundled.is_file():
        return bundled
    return directory / "sensitive_apis.js"


def _check_output_writable() -> dict[str, Any]:
    output_dir = _get_hook("OUTPUT_DIR", OUTPUT_DIR)
    ensure_dir(output_dir)
    probe_file = os.path.join(output_dir, ".write_probe")
    try:
        with open(probe_file, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe_file)
        return {"ok": True, "path": output_dir, "error": None}
    except Exception as e:
        return {"ok": False, "path": output_dir, "error": str(e)}


def _parse_manifest_application(
    unpack_dir: str,
    *,
    apk_filename: str,
) -> dict[str, Any]:
    """Pass the display filename while retaining compatibility with injected parsers."""
    parser = _get_hook("parse_manifest_info", parse_manifest_info)
    try:
        return parser(unpack_dir, apk_filename=apk_filename)
    except TypeError as exc:
        if "apk_filename" not in str(exc):
            raise
        return parser(unpack_dir)


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


@dataclass(slots=True)
class StaticStageResult:
    analysis_dir: Path
    app_info: dict[str, Any]
    manifest_evidence: dict[str, Any]
    sdk_hits: list[dict[str, Any]]
    unpack_ok: bool
    package_name: str | None = None


def run_static_stage(
    context: AnalysisRunContext,
    steps: list[StepResult],
    *,
    package_name_input: str | None = None,
) -> StaticStageResult:
    """Execute the common static analysis stage: unpack, manifest parse, SDK scan."""
    app_info = _manifest_application_fallback(package_name_input)
    manifest_evidence: dict[str, Any] = {
        "status": "not_evaluated",
        "error_code": None,
        "message": "Manifest evidence has not been evaluated",
    }
    sdk_hits: list[dict[str, Any]] = []
    analysis_dir = context.unpacked_dir

    unpack_started = _utc_now()
    try:
        apktool_info = _get_hook("check_apktool", check_apktool)()
        apktool_version = str(
            apktool_info.get("apktool_version") or "unknown"
        )
        cache_root = Path(STATIC_UNPACK_CACHE_DIR)
        unpacker_fn = _get_hook("unpack_apk", unpack_apk)
        cache_result = prepare_static_unpack(
            snapshot_path=context.apk_path,
            apk_sha256=context.apk_sha256,
            cache_root=cache_root,
            apktool_version=apktool_version,
            unpacker=unpacker_fn,
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
        manifest_started = _utc_now()
        try:
            parsed_app_info = _parse_manifest_application(
                str(analysis_dir),
                apk_filename=context.source_apk_display,
            )
            app_info = {
                **_manifest_application_fallback(package_name_input),
                **parsed_app_info,
            }
            if not app_info.get("package_name") and package_name_input:
                app_info["package_name"] = (
                    str(package_name_input or "").strip() or None
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
                    manifest_started,
                    required=False,
                    outputs=[str(analysis_dir / "AndroidManifest.xml")],
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
            scan_fn = _get_hook("scan_for_sdks", scan_for_sdks)
            sdk_hits = scan_fn(str(analysis_dir))
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

    resolved_package_name = str(package_name_input or "").strip()
    if not resolved_package_name and app_info:
        resolved_package_name = str(app_info.get("package_name") or "").strip()

    return StaticStageResult(
        analysis_dir=analysis_dir,
        app_info=app_info,
        manifest_evidence=manifest_evidence,
        sdk_hits=sdk_hits,
        unpack_ok=unpack_ok,
        package_name=resolved_package_name or None,
    )


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
        allowed_roots=_get_hook("APK_ALLOWED_ROOTS", APK_ALLOWED_ROOTS),
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
            _get_hook("OUTPUT_DIR", OUTPUT_DIR),
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
        write_html_report(report, context.report_html_path)
        _get_hook("write_markdown_report", write_markdown_report)(
            report, str(context.report_markdown_path)
        )
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
    builder = _get_hook(
        "build_evidence_correlations", build_evidence_correlations
    )
    writer = _get_hook("atomic_write_json", atomic_write_json)
    try:
        correlation = builder(
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
        writer(context.correlations_path, payload)
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
    builder = _get_hook(
        "build_privacy_findings", build_privacy_findings
    )
    writer = _get_hook("atomic_write_json", atomic_write_json)
    try:
        findings = builder(
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
        writer(context.privacy_findings_path, payload)
    except Exception:
        payload["status"] = "error"
        payload.setdefault("limitations", []).append(
            "privacy-findings.json 写入失败，主报告仍基于原始证据生成"
        )
    return payload


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


def _ai_cancelled() -> bool:
    """Cancellation probe for the orchestrator (never raises)."""
    try:
        checkpoint()
    except TaskCancelled:
        return True
    return False


def _public_ai_section(result: AIOrchestrationResult) -> dict[str, Any]:
    """The AI section embedded in report.json / the API response."""
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
        "diagnostic": result.diagnostic_payload(),
    }


__all__ = [
    "_CRITICAL_STEPS",
    "_ai_cancelled",
    "_ai_run_dir",
    "_artifact_entries",
    "_base_report",
    "_build_and_write_evidence_correlation",
    "_build_and_write_privacy_findings",
    "_check_output_writable",
    "_collect_warnings",
    "_device_serials",
    "_finalize_report",
    "_has_trusted_consent_boundary",
    "_manifest_application_fallback",
    "_network_consent_states",
    "_overall_status",
    "_parse_manifest_application",
    "_prepare_run",
    "_public_ai_section",
    "_redact_device_diagnostic",
    "_redact_known_device_serials",
    "_safe_apk_input_display",
    "_step_result",
    "_steps_payload",
    "_validation_failure_response",
    "resolve_frida_hook_script",
    "run_static_stage",
    "StaticStageResult",
    "task_service_response_payload",
]
