"""Static analysis pipeline stage: APK unpack, manifest parse, SDK detection."""

from __future__ import annotations

import os
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from app import config as app_config
from app.core.apk_unpack import unpack_apk
from app.core.clock import utc_now as _utc_now
from app.core.env_checks import check_apktool
from app.core.manifest_parser import parse_manifest_info
from app.core.run_context import AnalysisRunContext
from app.core.sdk_fingerprint import scan_for_sdks
from app.core.static_unpack_cache import (
    StaticUnpackCacheError,
    prepare_static_unpack,
)
from app.core.status import StepResult, StepStatus, make_step_result
from app.tools.utils import ensure_dir

_CRITICAL_STEPS = {
    "apk_validation",
    "apk_hash",
    "apk_snapshot",
    "apk_unpack",
    "report_write",
}


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
    return make_step_result(
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


def _check_output_writable() -> dict[str, Any]:
    output_dir = app_config.OUTPUT_DIR
    ensure_dir(output_dir)
    probe_file = os.path.join(output_dir, ".write_probe")
    try:
        with open(probe_file, "w", encoding="utf-8") as f:
            f.write("ok")
        os.remove(probe_file)
        return {"ok": True, "path": output_dir, "error": None}
    except Exception as e:
        return {"ok": False, "path": output_dir, "error": str(e)}


def _resolve_tool(name: str, default: Any) -> Any:
    import sys

    common_mod = sys.modules.get("app.pipelines.common")
    if common_mod is not None and hasattr(common_mod, name):
        return getattr(common_mod, name)
    return default


def _parse_manifest_application(
    unpack_dir: str,
    *,
    apk_filename: str,
) -> dict[str, Any]:
    """Pass the display filename while retaining compatibility with injected parsers."""
    parser = _resolve_tool("parse_manifest_info", parse_manifest_info)
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
        apktool_info = check_apktool()
        apktool_version = str(apktool_info.get("apktool_version") or "unknown")
        cache_root = Path(app_config.STATIC_UNPACK_CACHE_DIR)
        unpacker_fn = _resolve_tool("unpack_apk", unpack_apk)
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
    err_code = unpack_result.get("error_code")
    steps.append(
        _step_result(
            "apk_unpack",
            StepStatus.SUCCESS if unpack_ok else StepStatus.FAILED,
            unpack_started,
            error_code=None if unpack_ok else (str(err_code) if err_code else "apk_unpack_failed"),
            error_message=(
                None
                if unpack_ok
                else str(
                    unpack_result.get("stderr") or unpack_result.get("stdout") or "apktool failed"
                )
            ),
            outputs=[str(analysis_dir)] if unpack_ok else [],
            details=(
                {
                    "cache_hit": bool(unpack_result.get("cache_hit")),
                    "cache_key": unpack_result.get("cache_key"),
                    "apktool_version": unpack_result.get("apktool_version"),
                    "cache_format_version": unpack_result.get("cache_format_version"),
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
                apk_filename=str(context.source_apk_display or ""),
            )
            app_info = {
                **_manifest_application_fallback(package_name_input),
                **parsed_app_info,
            }
            if not app_info.get("package_name") and package_name_input:
                app_info["package_name"] = str(package_name_input or "").strip() or None
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
            scan_fn = _resolve_tool("scan_for_sdks", scan_for_sdks)
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


__all__ = [
    "StaticStageResult",
    "_check_output_writable",
    "_manifest_application_fallback",
    "_parse_manifest_application",
    "run_static_stage",
]
