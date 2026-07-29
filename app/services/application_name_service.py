from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from app.core.application_names import (
    is_android_resource_reference,
    resolve_application_label,
    stable_application_name,
)
from app.reporting import write_html_report
from app.repositories.task_repository import TaskRepository
from app.tools.report_writer import write_json_report, write_markdown_report


def repair_historical_application_names(
    repository: TaskRepository,
    *,
    static_unpack_cache_dir: str | Path,
) -> int:
    """Repair legacy task/report labels and comparison titles in place."""

    cache_root = Path(static_unpack_cache_dir)
    repaired = 0
    for row in repository.list_task_name_rows():
        if row["task_type"] == "comparison":
            continue
        report = _read_report(row.get("report_json_path"))
        app_info = report.get("app_info") if report else None
        app_info = app_info if isinstance(app_info, dict) else {}
        raw_label = app_info.get("application_label") or row.get("app_name")
        unpacked_dir = (
            cache_root / str(row["apk_sha256"]).lower() / "unpacked"
            if row.get("apk_sha256")
            else None
        )
        resolved = (
            resolve_application_label(unpacked_dir, raw_label)
            if unpacked_dir and unpacked_dir.is_dir()
            else None
        )
        if not resolved and raw_label and not is_android_resource_reference(raw_label):
            resolved = str(raw_label)
        display_name = stable_application_name(
            resolved,
            apk_filename=Path(row["apk_path"]).name if row.get("apk_path") else None,
            package_name=row.get("package_name") or app_info.get("package_name"),
        )

        if row.get("app_name") != display_name:
            repository.update_task(row["id"], app_name=display_name)
            repaired += 1
        if report and app_info.get("application_label") != display_name:
            app_info["application_label"] = display_name
            app_info["resolved_app_name"] = display_name
            report["app_info"] = app_info
            _rewrite_report_artifacts(row, report)
            repaired += 1

    for row in repository.list_comparison_rows():
        result = json.loads(row["result_json"])
        base_task = repository.get_task(row["base_task_id"], include_steps=False)
        target_task = repository.get_task(row["target_task_id"], include_steps=False)
        if base_task is None or target_task is None:
            continue
        base_name = stable_application_name(
            base_task.app_name,
            apk_filename=Path(base_task.apk_path).name if base_task.apk_path else None,
            package_name=base_task.package_name,
        )
        target_name = stable_application_name(
            target_task.app_name,
            apk_filename=Path(target_task.apk_path).name if target_task.apk_path else None,
            package_name=target_task.package_name,
        )
        base_summary = result.setdefault("base_summary", {})
        target_summary = result.setdefault("target_summary", {})
        changed = False
        if base_summary.get("app_name") != base_name:
            base_summary["app_name"] = base_name
            changed = True
        if target_summary.get("app_name") != target_name:
            target_summary["app_name"] = target_name
            changed = True
        if not result.get("created_at"):
            result["created_at"] = row["created_at"]
            changed = True
        if changed:
            repository.update_comparison_result(row["id"], result)
            repaired += 1

        comparison_title = f"{base_name} · 版本对比"
        comparison_task = repository.get_task(row["task_id"], include_steps=False)
        if comparison_task and (
            comparison_task.app_name != comparison_title
            or comparison_task.package_name != base_task.package_name
        ):
            repository.update_task(
                row["task_id"],
                app_name=comparison_title,
                package_name=base_task.package_name,
            )
            repaired += 1
    return repaired


def _read_report(path_text: str | None) -> dict[str, Any] | None:
    if not path_text:
        return None
    path = Path(path_text)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return None
    return payload if isinstance(payload, dict) else None


def _rewrite_report_artifacts(
    row: dict[str, Any],
    report: dict[str, Any],
) -> None:
    if row.get("report_json_path"):
        write_json_report(report, row["report_json_path"])
    if row.get("report_markdown_path"):
        write_markdown_report(report, row["report_markdown_path"])
    if row.get("report_html_path"):
        write_html_report(report, row["report_html_path"])
