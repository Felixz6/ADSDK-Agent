"""Task-level AI orchestration service (M6A).

This module is the seam between the AI orchestrator and the *existing*
deterministic pipeline. It owns:

* the tool executor — each whitelisted tool either reuses a valid artifact the
  deterministic pipeline already wrote, or delegates to the existing runner;
* artifact reuse detection (``reused=True`` + ``artifact_ref``, no re-run);
* the deterministic evidence digest assembly from on-disk artifacts;
* the four AI artifacts written into the run directory.

No analysis logic is re-implemented here. ``static_analysis`` and
``dynamic_analysis`` call the same entry points the ordinary ``static`` /
``dynamic`` task types use; every other tool is a bounded artifact reader.
"""

from __future__ import annotations

from pathlib import Path
import threading
from typing import Any, Callable, Mapping
from uuid import uuid4

from app.core.artifacts import atomic_write_json

from app.ai.context_builder import (
    AIContextBuilder,
    make_artifact_refs,
    make_evidence_refs,
    read_json_artifact,
    read_json_list_artifact,
)
from app.ai.models import (
    EvidenceDigestArtifactRef,
    ToolCompactResult,
    ToolErrorDetail,
)
from app.ai.orchestrator import (
    AIOrchestrationRequest,
    AIOrchestrationResult,
    AIOrchestrator,
    write_ai_artifacts,
)
from app.ai.orchestrator import PreparedPlan
from app.ai.models import AIPlan
from app.orchestration.dynamic_strategy import DynamicStrategyDecision

# A deterministic runner produces the full report dict for the run.
DeterministicRunner = Callable[[], Mapping[str, Any]]


class RunArtifacts:
    """Resolves and reads the artifacts one run directory may contain."""

    def __init__(self, run_dir: Path | str) -> None:
        self.run_dir = Path(run_dir)

    @property
    def report_json(self) -> Path:
        return self.run_dir / "report.json"

    @property
    def correlations(self) -> Path:
        return self.run_dir / "correlations.json"

    @property
    def privacy_findings(self) -> Path:
        return self.run_dir / "privacy-findings.json"

    @property
    def traffic_summary(self) -> Path:
        return self.run_dir / "traffic_summary.json"

    @property
    def events(self) -> Path:
        return self.run_dir / "events.json"

    @property
    def report_markdown(self) -> Path:
        return self.run_dir / "report.md"

    @property
    def report_html(self) -> Path:
        return self.run_dir / "report.html"

    def paths(self) -> dict[str, Path]:
        return {
            "report_json": self.report_json,
            "correlations": self.correlations,
            "privacy_findings": self.privacy_findings,
            "traffic_summary": self.traffic_summary,
            "events": self.events,
        }

    def digest_refs(self) -> list[EvidenceDigestArtifactRef]:
        return [
            EvidenceDigestArtifactRef(
                name=name,
                artifact_kind=name,
                path=str(path),
                exists=path.is_file(),
            )
            for name, path in self.paths().items()
        ]


class RunScopedExecution:
    """One run-owned deterministic execution, shared by every consumer.

    This is deliberately supplied by the production session rather than held
    in a process-global map: its lifetime is the task/run and it also shares an
    in-flight failure with later consumers.
    """

    def __init__(
        self,
        runner: Callable[[str], Mapping[str, Any]],
        *,
        task_id: str = "",
        run_context_path: Path | str | None = None,
        diagnostics_path: Path | str | None = None,
    ) -> None:
        self._runner = runner
        self._condition = threading.Condition()
        self._running = False
        self._completed = False
        self._result: dict[str, Any] | None = None
        self._error: BaseException | None = None
        self._task_id = task_id
        self._run_context_path = str(run_context_path or "")
        self._diagnostics_path = Path(diagnostics_path) if diagnostics_path else None
        self._events: list[dict[str, Any]] = []
        self._sequence = 0

    def _record(self, **event: Any) -> None:
        self._sequence += 1
        payload = {
            "claim_sequence": self._sequence,
            "run_id": self._task_id,
            "task_id": self._task_id,
            "execution_scope_id": self._task_id,
            "single_flight_key": self._task_id,
            "run_context_path": self._run_context_path,
            **event,
        }
        self._events.append(payload)
        if self._diagnostics_path is not None:
            atomic_write_json(self._diagnostics_path, {
                "schema_version": "run-context-claims-v1",
                "events": self._events,
            })

    def request(self, strategy: str, *, caller_role: str, service_instance_token: str) -> dict[str, Any]:
        with self._condition:
            if self._running:
                self._record(phase="unified_execution", caller_role=caller_role,
                    operation="reuse_existing_execution", single_flight_role="waiter",
                    service_instance_token=service_instance_token, result="waiting")
                while self._running:
                    self._condition.wait()
                if self._error is not None:
                    self._record(phase="unified_execution", caller_role=caller_role,
                        operation="reuse_same_failure", single_flight_role="reuser",
                        service_instance_token=service_instance_token, result="failure",
                        exception_type=type(self._error).__name__)
                    raise self._error
                assert self._result is not None
                self._record(phase="unified_execution", caller_role=caller_role,
                    operation="reuse_existing_execution", single_flight_role="reuser",
                    service_instance_token=service_instance_token, result="success")
                return dict(self._result)
            if self._completed:
                if self._error is not None:
                    self._record(phase="unified_execution", caller_role=caller_role,
                        operation="reuse_same_failure", single_flight_role="reuser",
                        service_instance_token=service_instance_token, result="failure",
                        exception_type=type(self._error).__name__)
                    raise self._error
                assert self._result is not None
                self._record(phase="unified_execution", caller_role=caller_role,
                    operation="reuse_existing_execution", single_flight_role="reuser",
                    service_instance_token=service_instance_token, result="success")
                return dict(self._result)
            self._running = True
            self._record(phase="run_context", caller_role=caller_role, operation="create",
                single_flight_role="owner", service_instance_token=service_instance_token,
                result="started")
        try:
            result = dict(self._runner(strategy))
        except BaseException as exc:
            with self._condition:
                self._error = exc
                self._completed = True
                self._running = False
                self._record(phase="run_context", caller_role=caller_role, operation="create",
                    single_flight_role="owner", service_instance_token=service_instance_token,
                    result="failure", exception_type=type(exc).__name__,
                    path_existed=Path(self._run_context_path).exists() if self._run_context_path else None)
                self._condition.notify_all()
            raise
        with self._condition:
            self._result = result
            self._completed = True
            self._running = False
            self._record(phase="run_context", caller_role=caller_role, operation="create",
                single_flight_role="owner", service_instance_token=service_instance_token,
                result="success")
            self._condition.notify_all()
        return dict(result)

    def __call__(self, strategy: str) -> dict[str, Any]:
        return self.request(strategy, caller_role="execution_owner", service_instance_token="direct")


class AITaskService:
    """Runs one ``ai_orchestrated`` task end to end."""

    def __init__(
        self,
        *,
        orchestrator: AIOrchestrator,
        run_dir: Path | str,
        static_runner: DeterministicRunner | None = None,
        dynamic_runner: DeterministicRunner | None = None,
        dynamic_runner_with_strategy: Callable[[str], Mapping[str, Any]] | None = None,
        unified_runner_with_strategy: Callable[[str], Mapping[str, Any]] | None = None,
        environment_probe: Callable[[], Mapping[str, Any]] | None = None,
        context_builder: AIContextBuilder | None = None,
    ) -> None:
        self._orchestrator = orchestrator
        self._artifacts = RunArtifacts(run_dir)
        self._static_runner = static_runner
        self._dynamic_runner = dynamic_runner
        self._dynamic_runner_with_strategy = dynamic_runner_with_strategy
        self._unified_runner_with_strategy = unified_runner_with_strategy
        self._effective_dynamic_strategy: str | None = None
        # Recorded where the production tool boundary actually dispatches the
        # resolved policy, rather than inferred by FullAnalysisSession.
        self._executor_strategy_receipt: dict[str, str] | None = None
        self._environment_probe = environment_probe
        self._context = context_builder or AIContextBuilder()
        self._environment: dict[str, Any] | None = None
        # Cache of the report produced in-process so a later tool in the same
        # plan does not re-run an expensive pipeline.
        self._report_cache: dict[str, Any] | None = None
        self._service_instance_token = uuid4().hex[:12]

    # -- public ---------------------------------------------------------
    def run(self, request: AIOrchestrationRequest) -> AIOrchestrationResult:
        result = self._orchestrator.run(
            request,
            execute_tool=self.execute_tool,
            build_digest=lambda results: self.build_digest(request, results),
        )
        write_ai_artifacts(self._artifacts.run_dir, result)
        return result

    def prepare_plan(self, request: AIOrchestrationRequest) -> PreparedPlan:
        """Prepare exactly one plan without dispatching deterministic tools."""
        return self._orchestrator.prepare_plan(request)

    def execute_prepared_plan(
        self,
        prepared: PreparedPlan,
        request: AIOrchestrationRequest,
        effective_plan: AIPlan,
        strategy_decision: DynamicStrategyDecision,
    ) -> AIOrchestrationResult:
        """Execute the externally gated plan using only the effective policy."""
        self._effective_dynamic_strategy = strategy_decision.effective_strategy
        self._executor_strategy_receipt = None
        result = self._orchestrator.execute_prepared_plan(
            prepared,
            request=request,
            execute_tool=self.execute_tool,
            build_digest=lambda results: self.build_digest(request, results),
            effective_plan=effective_plan,
            strategy_decision=strategy_decision,
        )
        write_ai_artifacts(self._artifacts.run_dir, result)
        return result

    @property
    def executor_strategy_receipt(self) -> dict[str, str] | None:
        """Receipt emitted by the tool executor after it selects a branch."""
        return dict(self._executor_strategy_receipt) if self._executor_strategy_receipt else None

    def _run_unified_with_effective_strategy(self, caller_role: str) -> dict[str, Any]:
        if not self._effective_dynamic_strategy:
            raise RuntimeError("effective_dynamic_strategy_missing")
        if self._unified_runner_with_strategy is None:
            raise RuntimeError("unified_runner_missing")
        strategy = self._effective_dynamic_strategy
        runner = self._unified_runner_with_strategy
        request = getattr(runner, "request", None)
        report = dict(request(strategy, caller_role=caller_role, service_instance_token=self._service_instance_token) if callable(request) else runner(strategy))
        receipt = report.get("executor_strategy_receipt")
        if isinstance(receipt, Mapping):
            self._executor_strategy_receipt = {
                "executor_received_strategy": str(receipt.get("executor_received_strategy") or strategy),
                "executor_execution_strategy": str(receipt.get("executor_execution_strategy") or strategy),
                "executor_provenance_source": str(receipt.get("executor_provenance_source") or "unknown"),
            }
        return report

    # -- digest ---------------------------------------------------------
    def build_digest(
        self,
        request: AIOrchestrationRequest,
        _results: list[ToolCompactResult],
    ):
        report = self._load_report()
        return self._context.build(
            task={
                "task_id": request.task_id,
                "task_type": "ai_orchestrated",
                "analysis_scope": request.analysis_scope,
                "objective": request.objective,
                "allow_dynamic": request.allow_dynamic,
                "allow_network": request.allow_network,
                "report_language": request.report_language,
            },
            report=report,
            correlation=self._load_correlation(report),
            privacy_findings=self._load_privacy_findings(report),
            traffic_summary=read_json_artifact(self._artifacts.traffic_summary),
            environment=self._environment,
            artifact_refs=self._artifacts.digest_refs(),
        )

    # -- tool executor --------------------------------------------------
    def execute_tool(
        self,
        tool_name: str,
        arguments: Mapping[str, Any],
    ) -> ToolCompactResult:
        handler = {
            "environment_check": self._tool_environment_check,
            "static_analysis": self._tool_static_analysis,
            "dynamic_analysis": self._tool_dynamic_analysis,
            "traffic_analysis": self._tool_traffic_analysis,
            "evidence_correlation": self._tool_evidence_correlation,
            "privacy_findings": self._tool_privacy_findings,
            "deterministic_report": self._tool_deterministic_report,
            "task_status": self._tool_task_status,
            "artifact_summary": self._tool_artifact_summary,
        }.get(tool_name)
        if handler is None:
            return ToolCompactResult(
                tool_name=tool_name,
                status="failed",
                summary="工具未实现",
                error=ToolErrorDetail(
                    error_code="ai_tool_not_implemented",
                    safe_message="tool has no executor",
                    stage="tool_dispatch",
                ),
            )
        return handler(dict(arguments))

    # -- individual tools ------------------------------------------------
    def _tool_environment_check(self, _arguments: dict[str, Any]) -> ToolCompactResult:
        if self._environment_probe is None:
            return ToolCompactResult(
                tool_name="environment_check",
                status="not_run",
                summary="未提供环境自检实现",
                limitations=["环境自检不可用"],
            )
        try:
            payload = dict(self._environment_probe())
        except Exception as exc:
            return ToolCompactResult(
                tool_name="environment_check",
                status="failed",
                summary="环境自检执行异常",
                error=ToolErrorDetail(
                    error_code="ai_environment_check_failed",
                    safe_message=type(exc).__name__,
                    stage="environment_check",
                    retryable=True,
                ),
            )
        self._environment = payload
        checks = payload.get("checks") if isinstance(payload.get("checks"), Mapping) else {}
        passed = sum(1 for value in checks.values() if value)
        return ToolCompactResult(
            tool_name="environment_check",
            status="success" if payload.get("ok") else "partial",
            summary=f"环境自检完成：{passed}/{len(checks)} 项通过",
            metrics={
                "checks_total": len(checks),
                "checks_passed": passed,
                "ok": bool(payload.get("ok")),
            },
            recommended_next_tools=["static_analysis"],
        )

    def _tool_static_analysis(self, arguments: dict[str, Any]) -> ToolCompactResult:
        force = bool(arguments.get("force_rerun"))
        existing = None if force else self._load_report()
        if existing is not None and _static_evidence_valid(existing):
            return ToolCompactResult(
                tool_name="static_analysis",
                status="success",
                summary="复用已有静态分析产物，未重复执行",
                metrics=_static_summary_metrics(existing),
                artifact_refs=make_artifact_refs(
                    {"report_json": self._artifacts.report_json}
                ),
                reused=True,
                decision_summary="existing static artifact reused",
                recommended_next_tools=["privacy_findings"],
            )
        if self._static_runner is None and self._unified_runner_with_strategy is None:
            return ToolCompactResult(
                tool_name="static_analysis",
                status="not_run",
                summary="未提供静态分析实现",
                limitations=["静态分析不可用"],
            )
        try:
            if self._report_cache is not None:
                report = self._report_cache
            elif self._unified_runner_with_strategy is not None:
                report = self._run_unified_with_effective_strategy("static_consumer")
            else:
                assert self._static_runner is not None
                report = dict(self._static_runner())
        except Exception as exc:
            return ToolCompactResult(
                tool_name="static_analysis",
                status="failed",
                summary="静态分析执行异常",
                error=ToolErrorDetail(
                    error_code="ai_static_analysis_failed",
                    safe_message=type(exc).__name__,
                    stage="static_analysis",
                ),
            )
        self._report_cache = report
        status = "success" if report.get("status") != "failed" else "failed"
        return ToolCompactResult(
            tool_name="static_analysis",
            status=status,  # type: ignore[arg-type]
            summary="静态分析完成",
            metrics=_static_summary_metrics(report),
            artifact_refs=make_artifact_refs(
                {"report_json": self._artifacts.report_json}
            ),
            recommended_next_tools=["privacy_findings"],
        )

    def _tool_dynamic_analysis(self, arguments: dict[str, Any]) -> ToolCompactResult:
        force = bool(arguments.get("force_rerun"))
        existing = None if force else self._load_report()
        if existing is not None and existing.get("dynamic_events") is not None:
            return ToolCompactResult(
                tool_name="dynamic_analysis",
                status="success",
                summary="复用已有动态分析产物，未重复采集",
                metrics=_dynamic_summary_metrics(existing),
                artifact_refs=make_artifact_refs(
                    {"report_json": self._artifacts.report_json}
                ),
                reused=True,
                confirmation_required=True,
                decision_summary="existing dynamic artifact reused",
                recommended_next_tools=["traffic_analysis"],
            )
        if (
            self._dynamic_runner is None
            and self._dynamic_runner_with_strategy is None
            and self._unified_runner_with_strategy is None
        ):
            return ToolCompactResult(
                tool_name="dynamic_analysis",
                status="not_run",
                summary="未提供动态分析实现",
                confirmation_required=True,
                limitations=["动态分析不可用"],
            )
        try:
            if self._report_cache is not None:
                report = self._report_cache
            elif self._unified_runner_with_strategy is not None:
                report = self._run_unified_with_effective_strategy("dynamic_consumer")
            elif self._dynamic_runner_with_strategy is not None:
                if not self._effective_dynamic_strategy:
                    raise RuntimeError("effective_dynamic_strategy_missing")
                report = dict(
                    self._dynamic_runner_with_strategy(
                        self._effective_dynamic_strategy
                    )
                )
            else:
                assert self._dynamic_runner is not None
                report = dict(self._dynamic_runner())
        except Exception as exc:
            return ToolCompactResult(
                tool_name="dynamic_analysis",
                status="failed",
                summary="动态分析执行异常",
                confirmation_required=True,
                error=ToolErrorDetail(
                    error_code="ai_dynamic_analysis_failed",
                    safe_message=type(exc).__name__,
                    stage="dynamic_analysis",
                ),
            )
        self._report_cache = report
        return ToolCompactResult(
            tool_name="dynamic_analysis",
            status="success" if report.get("status") != "failed" else "partial",
            summary="动态分析完成",
            metrics=_dynamic_summary_metrics(report),
            artifact_refs=make_artifact_refs(
                {"report_json": self._artifacts.report_json}
            ),
            confirmation_required=True,
            recommended_next_tools=["traffic_analysis", "evidence_correlation"],
        )

    def _tool_traffic_analysis(self, _arguments: dict[str, Any]) -> ToolCompactResult:
        report = self._load_report()
        traffic: Mapping[str, Any] | None = None
        if isinstance(report, Mapping) and isinstance(
            report.get("traffic_summary"), Mapping
        ):
            traffic = report["traffic_summary"]
        else:
            traffic = read_json_artifact(self._artifacts.traffic_summary)
        if traffic is None:
            return ToolCompactResult(
                tool_name="traffic_analysis",
                status="not_run",
                summary="本次没有可用的网络采集结果",
                limitations=["网络证据不可用；零请求不代表不存在外发行为"],
            )
        return ToolCompactResult(
            tool_name="traffic_analysis",
            status="success",
            summary="读取网络观察摘要完成",
            metrics={
                "total_requests": int(traffic.get("total_requests") or 0),
                "status": str(traffic.get("status") or "unknown"),
                "collector_outcome": str(traffic.get("collector_outcome") or ""),
                "coverage": str(traffic.get("coverage") or ""),
            },
            artifact_refs=make_artifact_refs(
                {"traffic_summary": self._artifacts.traffic_summary}
            ),
            reused=True,
            recommended_next_tools=["evidence_correlation"],
        )

    def _tool_evidence_correlation(
        self, _arguments: dict[str, Any]
    ) -> ToolCompactResult:
        correlation = self._load_correlation(self._load_report())
        if correlation is None:
            return ToolCompactResult(
                tool_name="evidence_correlation",
                status="not_run",
                summary="本次没有可用的事件—请求关联结果",
                limitations=["关联类结论未评估"],
            )
        summary = (
            correlation.get("summary")
            if isinstance(correlation.get("summary"), Mapping)
            else {}
        )
        return ToolCompactResult(
            tool_name="evidence_correlation",
            status="success",
            summary="读取 correlation-v1 结果完成",
            metrics={
                "status": str(correlation.get("status") or "unknown"),
                "correlated_pair_count": int(
                    summary.get("correlated_pair_count") or 0
                ),
                "high_confidence_count": int(
                    summary.get("high_confidence_count") or 0
                ),
                "window_ms": int(correlation.get("window_ms") or 0),
            },
            artifact_refs=make_artifact_refs(
                {"correlations": self._artifacts.correlations}
            ),
            reused=True,
            recommended_next_tools=["privacy_findings"],
        )

    def _tool_privacy_findings(self, _arguments: dict[str, Any]) -> ToolCompactResult:
        findings = self._load_privacy_findings(self._load_report())
        if findings is None:
            return ToolCompactResult(
                tool_name="privacy_findings",
                status="not_run",
                summary="本次没有可用的隐私发现结果",
                limitations=["隐私发现未评估；未评估不代表不存在风险"],
            )
        summary = (
            findings.get("summary")
            if isinstance(findings.get("summary"), Mapping)
            else {}
        )
        evidence_ids = [
            str(item.get("finding_id"))
            for item in findings.get("findings") or []
            if isinstance(item, Mapping) and item.get("finding_id")
        ]
        return ToolCompactResult(
            tool_name="privacy_findings",
            status="success",
            summary="读取 privacy-findings-v2 结果完成",
            metrics={
                "status": str(findings.get("status") or "unknown"),
                "finding_count": int(summary.get("finding_count") or 0),
                "suspected_risk_count": int(
                    summary.get("suspected_risk_count") or 0
                ),
                "not_evaluated_rule_count": int(
                    summary.get("not_evaluated_rule_count") or 0
                ),
            },
            evidence_refs=make_evidence_refs(evidence_ids),
            artifact_refs=make_artifact_refs(
                {"privacy_findings": self._artifacts.privacy_findings}
            ),
            reused=True,
            recommended_next_tools=["deterministic_report"],
        )

    def _tool_deterministic_report(
        self, _arguments: dict[str, Any]
    ) -> ToolCompactResult:
        present = {
            name: path
            for name, path in {
                "report_json": self._artifacts.report_json,
                "report_markdown": self._artifacts.report_markdown,
                "report_html": self._artifacts.report_html,
            }.items()
            if path.is_file()
        }
        if not present:
            return ToolCompactResult(
                tool_name="deterministic_report",
                status="not_run",
                summary="确定性报告产物尚未生成",
                limitations=["报告产物缺失"],
            )
        return ToolCompactResult(
            tool_name="deterministic_report",
            status="success",
            summary=f"确定性报告产物已生成（{len(present)} 项）",
            metrics={"artifact_count": len(present)},
            artifact_refs=make_artifact_refs(present),
            reused=True,
        )

    def _tool_task_status(self, _arguments: dict[str, Any]) -> ToolCompactResult:
        available = {
            name: path.is_file() for name, path in self._artifacts.paths().items()
        }
        return ToolCompactResult(
            tool_name="task_status",
            status="success",
            summary="读取任务状态与产物可用性完成",
            metrics={f"has_{name}": value for name, value in available.items()},
            reused=True,
        )

    def _tool_artifact_summary(self, arguments: dict[str, Any]) -> ToolCompactResult:
        kind = str(arguments.get("artifact_kind") or "report_json")
        path = self._artifacts.paths().get(kind)
        if path is None or not path.is_file():
            return ToolCompactResult(
                tool_name="artifact_summary",
                status="not_run",
                summary=f"产物 {kind} 不存在",
                limitations=[f"{kind} 不可用"],
            )
        payload = (
            read_json_list_artifact(path)
            if kind == "events"
            else read_json_artifact(path)
        )
        if payload is None:
            return ToolCompactResult(
                tool_name="artifact_summary",
                status="failed",
                summary=f"产物 {kind} 无法解析",
                error=ToolErrorDetail(
                    error_code="ai_artifact_corrupt",
                    safe_message="artifact is not valid JSON",
                    stage="artifact_summary",
                    retryable=True,
                ),
            )
        metrics: dict[str, Any] = {"artifact_kind": kind}
        if isinstance(payload, list):
            metrics["item_count"] = len(payload)
        else:
            metrics["key_count"] = len(payload)
            if "status" in payload:
                metrics["status"] = str(payload.get("status"))
        return ToolCompactResult(
            tool_name="artifact_summary",
            status="success",
            summary=f"读取产物 {kind} 摘要完成",
            metrics=metrics,
            artifact_refs=make_artifact_refs({kind: path}),
            reused=True,
        )

    # -- artifact loading ------------------------------------------------
    def _load_report(self) -> dict[str, Any] | None:
        if self._report_cache is not None:
            return self._report_cache
        report = read_json_artifact(self._artifacts.report_json)
        if report is not None:
            self._report_cache = report
        return report

    def _load_correlation(
        self, report: Mapping[str, Any] | None
    ) -> dict[str, Any] | None:
        if isinstance(report, Mapping) and isinstance(
            report.get("evidence_correlation"), Mapping
        ):
            return dict(report["evidence_correlation"])
        return read_json_artifact(self._artifacts.correlations)

    def _load_privacy_findings(
        self, report: Mapping[str, Any] | None
    ) -> dict[str, Any] | None:
        if isinstance(report, Mapping) and isinstance(
            report.get("privacy_findings"), Mapping
        ):
            return dict(report["privacy_findings"])
        return read_json_artifact(self._artifacts.privacy_findings)


# ---------------------------------------------------------------------------
# Metric helpers (counts only — never raw evidence).
# ---------------------------------------------------------------------------
def _static_evidence_valid(report: Mapping[str, Any]) -> bool:
    """An artifact counts as reusable only when its static evidence is real."""

    if report.get("status") == "failed":
        return False
    app_info = report.get("app_info")
    return isinstance(app_info, Mapping) and bool(report.get("apk_sha256"))


def _static_summary_metrics(report: Mapping[str, Any]) -> dict[str, Any]:
    app_info = report.get("app_info") if isinstance(report.get("app_info"), Mapping) else {}
    risk = report.get("risk_summary") if isinstance(report.get("risk_summary"), Mapping) else {}
    return {
        "sdk_count": int(report.get("sdk_count") or 0),
        "permission_count": len(app_info.get("permissions") or []),
        "sensitive_permission_count": len(app_info.get("sensitive_permissions") or []),
        "risk_score": risk.get("score"),
        "risk_level": risk.get("level"),
        "status": str(report.get("status") or "unknown"),
    }


def _dynamic_summary_metrics(report: Mapping[str, Any]) -> dict[str, Any]:
    events = report.get("dynamic_events")
    quality = (
        report.get("dynamic_evidence_quality")
        if isinstance(report.get("dynamic_evidence_quality"), Mapping)
        else {}
    )
    return {
        "event_count": len(events) if isinstance(events, list) else 0,
        "collection_status": str(report.get("collection_status") or "unknown"),
        "evidence_grade": quality.get("level"),
    }


__all__ = ["AITaskService", "RunArtifacts"]
