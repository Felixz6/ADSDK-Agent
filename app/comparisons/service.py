from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable
from uuid import uuid4

from app.comparisons.models import (
    ComparisonCreateRequest,
    ComparisonResult,
    DifferenceSet,
)
from app.repositories.task_repository import TaskRepository, utc_now


def _strings(values: Iterable[Any]) -> set[str]:
    return {str(value) for value in values if value is not None and str(value)}


def _diff(base: Iterable[Any], target: Iterable[Any], *, unavailable: bool = False) -> DifferenceSet:
    left = _strings(base)
    right = _strings(target)
    return DifferenceSet(
        added=sorted(right - left),
        removed=sorted(left - right),
        unchanged=sorted(left & right),
        unavailable=unavailable,
    )


def _rules(report: dict[str, Any]) -> list[str]:
    output: list[str] = []
    for key in ("dynamic_findings", "strict_dynamic_findings"):
        for rule in (report.get(key) or {}).get("rules") or []:
            output.append(f"{rule.get('rule_id')}={rule.get('status')}")
    return output


def _domains(report: dict[str, Any]) -> list[str]:
    return [
        item.get("host")
        for item in (report.get("traffic_summary") or {}).get("top_hosts") or []
        if item.get("host")
    ]


def _behaviors(report: dict[str, Any]) -> list[str]:
    return [
        f"{item.get('api') or item.get('title')}@{item.get('consent_state', 'unknown')}"
        for item in report.get("dynamic_events") or []
    ]


class ComparisonService:
    def __init__(self, repository: TaskRepository) -> None:
        self.repository = repository

    def create(self, request: ComparisonCreateRequest) -> ComparisonResult:
        if request.base_task_id == request.target_task_id:
            raise ValueError("base and target tasks must differ")
        base_task = self.repository.get_task(request.base_task_id)
        target_task = self.repository.get_task(request.target_task_id)
        if base_task is None or target_task is None:
            raise KeyError("comparison input task not found")
        for task in (base_task, target_task):
            if task.status != "completed" or not task.report_json_path:
                raise ValueError("comparison requires completed tasks with static reports")
        base_report = self._read_report(base_task.report_json_path)
        target_report = self._read_report(target_task.report_json_path)
        base_app = base_report.get("app_info") or {}
        target_app = target_report.get("app_info") or {}
        base_package = base_app.get("package_name")
        target_package = target_app.get("package_name")
        warnings: list[str] = []
        if base_package != target_package:
            if not request.allow_cross_app:
                raise ValueError("package names differ; set allow_cross_app to confirm")
            warnings.append("包名不同，本结果为跨应用对比")

        base_sdks = base_report.get("sdks") or []
        target_sdks = target_report.get("sdks") or []
        base_risk = (base_report.get("risk_summary") or {}).get("score")
        target_risk = (target_report.get("risk_summary") or {}).get("score")
        dynamic_available = bool(
            base_report.get("dynamic_events") is not None
            and target_report.get("dynamic_events") is not None
        )
        comparison_id = str(uuid4())
        task_id = str(uuid4())
        permissions = _diff(
            base_app.get("permissions") or [],
            target_app.get("permissions") or [],
        )
        sdks = _diff(
            (item.get("sdk_name") or item.get("package") for item in base_sdks),
            (item.get("sdk_name") or item.get("package") for item in target_sdks),
        )
        domains = _diff(
            _domains(base_report),
            _domains(target_report),
            unavailable=not dynamic_available,
        )
        delta = (
            int(target_risk) - int(base_risk)
            if isinstance(base_risk, int) and isinstance(target_risk, int)
            else None
        )
        highlights: list[str] = []
        if permissions.added:
            highlights.append(f"新增 {len(permissions.added)} 项权限")
        if sdks.added:
            highlights.append(f"新增 {len(sdks.added)} 个 SDK")
        if domains.removed:
            highlights.append(f"移除 {len(domains.removed)} 个域名")
        if delta is not None and delta:
            highlights.append(f"风险评分{'上升' if delta > 0 else '下降'} {abs(delta)} 分")
        if not highlights:
            highlights.append("未发现可确认的关键变化")

        result = ComparisonResult(
            id=comparison_id,
            task_id=task_id,
            base_task_id=base_task.id,
            target_task_id=target_task.id,
            base_summary=self._summary(base_report),
            target_summary=self._summary(target_report),
            risk_score_delta=delta,
            permissions=permissions,
            high_risk_permissions=_diff(
                base_app.get("high_attention_permissions") or [],
                target_app.get("high_attention_permissions") or [],
            ),
            sdks=sdks,
            sdk_vendors=_diff(
                (item.get("vendor") for item in base_sdks),
                (item.get("vendor") for item in target_sdks),
            ),
            sdk_categories=_diff(
                (item.get("category") for item in base_sdks),
                (item.get("category") for item in target_sdks),
            ),
            rules=_diff(_rules(base_report), _rules(target_report)),
            domains=domains,
            dynamic_behaviors=_diff(
                _behaviors(base_report),
                _behaviors(target_report),
                unavailable=not dynamic_available,
            ),
            evidence_complete=dynamic_available,
            highlights=highlights,
            warnings=warnings,
        )
        self.repository.create_task(
            {
                "id": task_id,
                "task_type": "comparison",
                "status": "completed",
                "apk_path": None,
                "progress_percent": 100,
                "request_payload": request.model_dump(mode="json"),
                "created_at": utc_now(),
            }
        )
        self.repository.update_task(
            task_id,
            progress_percent=100,
            current_stage="completed",
            completed_at=utc_now(),
        )
        self.repository.create_comparison(
            comparison_id=comparison_id,
            task_id=task_id,
            base_task_id=base_task.id,
            target_task_id=target_task.id,
            result=result.model_dump(mode="json"),
        )
        return result

    def get(self, comparison_id: str) -> ComparisonResult | None:
        payload = self.repository.get_comparison(comparison_id)
        return ComparisonResult.model_validate(payload) if payload else None

    @staticmethod
    def _read_report(path_text: str) -> dict[str, Any]:
        path = Path(path_text)
        if not path.is_file():
            raise ValueError("report artifact is missing")
        return json.loads(path.read_text(encoding="utf-8"))

    @staticmethod
    def _summary(report: dict[str, Any]) -> dict[str, Any]:
        app = report.get("app_info") or {}
        risk = report.get("risk_summary") or {}
        snapshot = report.get("apk_snapshot") or {}
        return {
            "app_name": app.get("application_label"),
            "package_name": app.get("package_name"),
            "version_name": app.get("version_name"),
            "version_code": app.get("version_code"),
            "apk_sha256": report.get("apk_sha256"),
            "file_size": snapshot.get("snapshot_size_bytes"),
            "risk_score": risk.get("score"),
            "risk_level": risk.get("level"),
            "status": report.get("status"),
        }
