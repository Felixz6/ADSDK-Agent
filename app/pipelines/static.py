"""Static analysis pipeline implementation."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

from fastapi.responses import JSONResponse

from app.config import STATIC_UNPACK_CACHE_DIR
from app.core.clock import utc_now as _utc_now
from app.core.static_unpack_cache import (
    StaticUnpackCacheError,
    prepare_static_unpack,
)
from app.core.status import StepStatus
from app.models import AnalyzeRequest
from app.pipelines.common import (
    _base_report,
    _finalize_report,
    _manifest_application_fallback,
    _parse_manifest_application,
    _prepare_run,
    _step_result,
)
from app.tools.apk_unpack import unpack_apk
from app.tools.env_checks import check_apktool
from app.tools.sdk_fingerprint import scan_for_sdks


def _get_hook(name: str, fallback: Any) -> Any:
    main = sys.modules.get("app.main")
    if main is not None and hasattr(main, name):
        return getattr(main, name)
    return fallback


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
        cache_root = Path(STATIC_UNPACK_CACHE_DIR)
        cache_result = prepare_static_unpack(
            snapshot_path=context.apk_path,
            apk_sha256=context.apk_sha256,
            cache_root=cache_root,
            apktool_version=apktool_version,
            unpacker=_get_hook("unpack_apk", unpack_apk),
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
            sdk_hits = _get_hook("scan_for_sdks", scan_for_sdks)(str(analysis_dir))
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


__all__ = ["analyze"]
