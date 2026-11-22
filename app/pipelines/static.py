"""Static analysis pipeline implementation."""

from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi.responses import JSONResponse

from app.models import AnalyzeRequest
from app.pipelines.common import (
    _base_report,
    _finalize_report,
    _prepare_run,
    run_static_stage,
)
from app.pipelines.tools import PipelineTools

if TYPE_CHECKING:
    from app.container import Container


def analyze(req: AnalyzeRequest, *, container: Container | None = None):
    tools = container.tools if container is not None else PipelineTools()
    context, steps, failure_response = _prepare_run(
        req.apk_path,
        device_id=None,
    )
    if failure_response is not None:
        return failure_response
    assert context is not None

    static_stage = run_static_stage(context, steps, tools=tools)

    report = _base_report(
        context,
        app_info=static_stage.app_info,
        sdk_hits=static_stage.sdk_hits,
    )
    report["manifest_evidence"] = static_stage.manifest_evidence
    if static_stage.manifest_evidence["status"] != "evaluated":
        report.setdefault("limitations", []).append(
            "Manifest evidence unavailable; Manifest-dependent conclusions were not evaluated"
        )
    report, report_error = _finalize_report(report, context, steps, tools=tools)
    if report_error is not None or report.get("status") == "failed":
        return JSONResponse(status_code=500, content=report)
    return report


__all__ = ["analyze"]
