"""Deterministic evidence digest + compact tool results (``evidence-digest-v1``).

Everything in this module is code-generated. The AI never authors a digest and
never sees a full artifact: the builder reads the artifacts the deterministic
pipeline already wrote (report.json, correlations.json, privacy-findings.json,
traffic_summary.json, events.json) and emits only counts, statuses, evidence
identifiers, artifact references, limitations, and bounded already-redacted
summaries.

Prompt-injection defence lives here too. Free text that originated inside the
APK, Manifest, network fields, hook arguments, or application names is
untrusted: it is truncated, control characters are stripped, instruction-like
markers are neutralised, and every such value is tagged with its source so the
system prompt can treat it as evidence rather than instruction.
"""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Mapping, Sequence

from .models import (
    EvidenceDigest,
    EvidenceDigestArtifactRef,
    EvidenceDigestFinding,
    ToolArtifactRef,
    ToolCompactResult,
    ToolEvidenceRef,
)

# Bounds. Every one of these is enforced, not advisory.
MAX_TOP_FINDINGS = 10
MAX_SUMMARY_CHARS = 360
MAX_TITLE_CHARS = 200
MAX_LIST_ITEMS = 12
MAX_EVIDENCE_REFS_PER_FINDING = 8
MAX_HOSTS = 8
MAX_UNTRUSTED_TEXT_CHARS = 240

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")

# Instruction-like markers that must never survive into the prompt as
# something the model could read as a directive. They are replaced with an
# inert token; the surrounding text is still shown as evidence.
_INJECTION_MARKERS = re.compile(
    r"(?i)\b("
    r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|preceding)\s+"
    r"(instruction|instructions|prompt|prompts|rule|rules)"
    r"|disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\s+"
    r"(instruction|instructions|prompt|prompts)"
    r"|system\s*prompt"
    r"|you\s+are\s+now\b"
    r"|忽略(之前|以上|前面)?的?(全部|所有)?指令"
    r"|无视(之前|以上|前面)?的?指令"
    r")"
)

# Command-ish surfaces that must never be echoed verbatim into the prompt.
_COMMAND_MARKERS = re.compile(
    r"(?i)\b(adb\s+shell|adb\s+install|frida\s+-|frida-server|mitmdump|"
    r"mitmproxy|rm\s+-rf|curl\s+http|powershell|cmd\.exe|/bin/sh|/bin/bash)\b"
)

_NEUTRALISED = "[neutralized]"


def sanitize_untrusted_text(
    value: Any,
    *,
    limit: int = MAX_UNTRUSTED_TEXT_CHARS,
) -> str:
    """Make APK/network-derived free text safe to place in a prompt.

    The result is data, never an instruction: control characters are removed,
    instruction-like and command-like markers are neutralised, and the text is
    truncated to *limit* characters.
    """

    if value is None:
        return ""
    text = value if isinstance(value, str) else str(value)
    text = _CONTROL_CHARS.sub(" ", text)
    text = _WHITESPACE.sub(" ", text).strip()
    text = _INJECTION_MARKERS.sub(_NEUTRALISED, text)
    text = _COMMAND_MARKERS.sub(_NEUTRALISED, text)
    if len(text) > limit:
        text = text[: max(0, limit - 3)] + "..."
    return text


def _clean(value: Any, limit: int) -> str:
    """Truncate trusted (already-structured) text without marker rewriting."""

    if value is None:
        return ""
    text = _WHITESPACE.sub(" ", _CONTROL_CHARS.sub(" ", str(value))).strip()
    if len(text) > limit:
        text = text[: max(0, limit - 3)] + "..."
    return text


def _bounded_list(values: Any, *, limit: int = MAX_LIST_ITEMS) -> list[str]:
    if not isinstance(values, (list, tuple)):
        return []
    out: list[str] = []
    for item in values:
        text = _clean(item, MAX_SUMMARY_CHARS)
        if text:
            out.append(text)
        if len(out) >= limit:
            break
    return out


def _int(value: Any, default: int = 0) -> int:
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return int(value)
    return default


def read_json_artifact(path: Path | str | None) -> dict[str, Any] | None:
    """Read a JSON artifact, returning ``None`` for missing / corrupt files.

    A corrupt artifact never raises: the caller treats it as "not available"
    and may re-run the producing tool.
    """

    if path is None:
        return None
    candidate = Path(path)
    if not candidate.is_file():
        return None
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, dict) else None


def read_json_list_artifact(path: Path | str | None) -> list[Any] | None:
    if path is None:
        return None
    candidate = Path(path)
    if not candidate.is_file():
        return None
    try:
        payload = json.loads(candidate.read_text(encoding="utf-8"))
    except Exception:
        return None
    return payload if isinstance(payload, list) else None


# ---------------------------------------------------------------------------
# Section builders — each returns counts/statuses only.
# ---------------------------------------------------------------------------
def build_static_summary(report: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(report, Mapping):
        return {"status": "not_run"}
    app_info = report.get("app_info") if isinstance(report.get("app_info"), Mapping) else {}
    sdks = report.get("sdks") if isinstance(report.get("sdks"), list) else []
    manifest_evidence = (
        report.get("manifest_evidence")
        if isinstance(report.get("manifest_evidence"), Mapping)
        else {}
    )
    risk = report.get("risk_summary") if isinstance(report.get("risk_summary"), Mapping) else {}
    categories: dict[str, int] = {}
    for entry in sdks:
        if isinstance(entry, Mapping):
            category = _clean(entry.get("category"), 40) or "unknown"
            categories[category] = categories.get(category, 0) + 1
    return {
        "status": _clean(report.get("status"), 40) or "unknown",
        # Package name comes from the APK: untrusted, sanitised, source-tagged.
        "package_name": sanitize_untrusted_text(app_info.get("package_name"), limit=180),
        "package_name_source": "apk_manifest_untrusted",
        "application_label": sanitize_untrusted_text(
            app_info.get("application_label"), limit=120
        ),
        "application_label_source": "apk_manifest_untrusted",
        "permission_count": len(app_info.get("permissions") or []),
        "sensitive_permission_count": len(
            app_info.get("sensitive_permissions") or []
        ),
        "high_attention_permission_count": len(
            app_info.get("high_attention_permissions") or []
        ),
        "sdk_count": _int(report.get("sdk_count"), len(sdks)),
        "sdk_categories": categories,
        "manifest_status": _clean(manifest_evidence.get("status"), 40)
        or "not_evaluated",
        "risk_score": risk.get("score") if isinstance(risk.get("score"), int) else None,
        "risk_level": _clean(risk.get("level"), 24) or None,
        "risk_confidence": _clean(risk.get("confidence"), 24) or None,
    }


def build_dynamic_summary(report: Mapping[str, Any] | None) -> dict[str, Any]:
    if not isinstance(report, Mapping):
        return {"status": "not_run"}
    events = report.get("dynamic_events")
    evidence_quality = (
        report.get("dynamic_evidence_quality")
        if isinstance(report.get("dynamic_evidence_quality"), Mapping)
        else {}
    )
    execution = (
        report.get("dynamic_execution")
        if isinstance(report.get("dynamic_execution"), Mapping)
        else {}
    )
    process = (
        report.get("process_diagnostics")
        if isinstance(report.get("process_diagnostics"), Mapping)
        else {}
    )
    event_list = events if isinstance(events, list) else []
    api_counts: dict[str, int] = {}
    pre_consent = 0
    post_consent = 0
    for event in event_list:
        if not isinstance(event, Mapping):
            continue
        api = _clean(event.get("api"), 80) or "unknown"
        api_counts[api] = api_counts.get(api, 0) + 1
        state = _clean(event.get("consent_state"), 24)
        if state == "pre_consent":
            pre_consent += 1
        elif state == "post_consent":
            post_consent += 1
    return {
        "status": _clean(report.get("collection_status"), 40) or "not_run",
        "evidence_available": events is not None,
        "event_count": len(event_list),
        "pre_consent_event_count": pre_consent,
        "post_consent_event_count": post_consent,
        "api_counts": dict(sorted(api_counts.items())[:MAX_LIST_ITEMS]),
        "evidence_grade": _clean(evidence_quality.get("level"), 8)
        or _clean(report.get("dynamic_validation_level"), 8)
        or None,
        "execution_mode": _clean(execution.get("selected_mode"), 40) or None,
        "execution_policy": _clean(execution.get("policy"), 40) or None,
        "process_result": _clean(process.get("status"), 60) or None,
        "limitations": _bounded_list(evidence_quality.get("limitations")),
    }


def build_network_summary(
    report: Mapping[str, Any] | None,
    traffic_summary: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    source: Mapping[str, Any] | None = None
    if isinstance(report, Mapping) and isinstance(report.get("traffic_summary"), Mapping):
        source = report["traffic_summary"]
    elif isinstance(traffic_summary, Mapping):
        source = traffic_summary
    if source is None:
        return {"status": "not_run", "total_requests": 0}
    hosts: list[dict[str, Any]] = []
    for entry in (source.get("top_hosts") or [])[:MAX_HOSTS]:
        if not isinstance(entry, Mapping):
            continue
        hosts.append(
            {
                # Host names come from observed traffic: untrusted input.
                "host": sanitize_untrusted_text(entry.get("host"), limit=120),
                "count": _int(entry.get("count")),
            }
        )
    return {
        "status": _clean(source.get("status"), 40) or "unknown",
        "collector_outcome": _clean(source.get("collector_outcome"), 60) or None,
        "coverage": _clean(source.get("coverage"), 40) or None,
        "total_requests": _int(source.get("total_requests")),
        "top_hosts": hosts,
        "top_hosts_source": "observed_traffic_untrusted",
        "warnings": _bounded_list(source.get("warnings")),
    }


def build_correlation_summary(
    correlation: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(correlation, Mapping):
        return {"status": "not_available", "correlated_pair_count": 0}
    summary = (
        correlation.get("summary")
        if isinstance(correlation.get("summary"), Mapping)
        else {}
    )
    return {
        "status": _clean(correlation.get("status"), 40) or "unknown",
        "window_ms": _int(correlation.get("window_ms")),
        "dynamic_event_count": _int(summary.get("dynamic_event_count")),
        "network_request_count": _int(summary.get("network_request_count")),
        "correlated_pair_count": _int(summary.get("correlated_pair_count")),
        "high_confidence_count": _int(summary.get("high_confidence_count")),
        "medium_confidence_count": _int(summary.get("medium_confidence_count")),
        "low_confidence_count": _int(summary.get("low_confidence_count")),
        "limitations": _bounded_list(correlation.get("limitations")),
    }


def build_privacy_findings_summary(
    findings: Mapping[str, Any] | None,
) -> dict[str, Any]:
    if not isinstance(findings, Mapping):
        return {"status": "not_available", "finding_count": 0}
    summary = (
        findings.get("summary")
        if isinstance(findings.get("summary"), Mapping)
        else {}
    )
    rule_statuses: dict[str, int] = {}
    for rule in findings.get("rule_results") or []:
        if isinstance(rule, Mapping):
            status = _clean(rule.get("status"), 32) or "unknown"
            rule_statuses[status] = rule_statuses.get(status, 0) + 1
    return {
        "status": _clean(findings.get("status"), 40) or "unknown",
        "finding_count": _int(summary.get("finding_count")),
        "confirmed_observation_count": _int(
            summary.get("confirmed_observation_count")
        ),
        "suspected_risk_count": _int(summary.get("suspected_risk_count")),
        "evidence_gap_count": _int(summary.get("evidence_gap_count")),
        "not_evaluated_rule_count": _int(
            summary.get("not_evaluated_rule_count")
        ),
        "rule_status_counts": rule_statuses,
        "limitations": _bounded_list(findings.get("limitations")),
    }


def build_top_findings(
    findings: Mapping[str, Any] | None,
    *,
    limit: int = MAX_TOP_FINDINGS,
) -> list[EvidenceDigestFinding]:
    """Highest-value findings only, each bounded and evidence-referenced."""

    if not isinstance(findings, Mapping):
        return []
    raw = findings.get("findings")
    if not isinstance(raw, list):
        return []
    severity_rank = {"high": 0, "medium": 1, "low": 2, "info": 3}
    type_rank = {"observed": 0, "suspected": 1, "evidence_gap": 2}
    entries = [item for item in raw if isinstance(item, Mapping)]
    entries.sort(
        key=lambda item: (
            severity_rank.get(str(item.get("severity", "info")), 9),
            type_rank.get(str(item.get("finding_type", "")), 9),
            str(item.get("finding_id", "")),
        )
    )
    out: list[EvidenceDigestFinding] = []
    for item in entries[:limit]:
        refs: list[str] = []
        for ref in item.get("evidence_refs") or []:
            if isinstance(ref, Mapping):
                evidence_id = _clean(ref.get("evidence_id"), 120)
                if evidence_id:
                    refs.append(evidence_id)
            if len(refs) >= MAX_EVIDENCE_REFS_PER_FINDING:
                break
        severity = str(item.get("severity", "info"))
        confidence = str(item.get("confidence", "low"))
        out.append(
            EvidenceDigestFinding(
                finding_id=_clean(item.get("finding_id"), 120) or "unknown",
                rule_id=_clean(item.get("rule_id"), 80) or "unknown",
                title=_clean(item.get("title"), MAX_TITLE_CHARS),
                finding_type=_clean(item.get("finding_type"), 40) or "unknown",
                severity=severity if severity in severity_rank else "info",
                confidence=confidence
                if confidence in {"high", "medium", "low"}
                else "low",
                summary=_clean(item.get("summary"), MAX_SUMMARY_CHARS),
                evidence_refs=refs,
                limitations=_bounded_list(item.get("limitations"), limit=4),
            )
        )
    return out


def build_evidence_gaps(
    *,
    static_summary: Mapping[str, Any],
    dynamic_summary: Mapping[str, Any],
    network_summary: Mapping[str, Any],
    correlation_summary: Mapping[str, Any],
    privacy_summary: Mapping[str, Any],
) -> list[str]:
    """Deterministic gap list. Absence of a finding never means "safe"."""

    gaps: list[str] = []
    if static_summary.get("manifest_status") not in {"evaluated"}:
        gaps.append("Manifest 证据不可用，依赖 Manifest 的静态判断未评估")
    if not dynamic_summary.get("evidence_available"):
        gaps.append("本次没有可信的动态事件证据，动态类结论未评估")
    elif dynamic_summary.get("evidence_grade") in {"D", None}:
        gaps.append("动态证据等级不足，动态结论置信度受限")
    if _int(network_summary.get("total_requests")) == 0:
        gaps.append("本次未观察到网络请求；零请求只代表本次采集窗口未观察到")
    if correlation_summary.get("status") in {"not_available", "error", "unknown"}:
        gaps.append("本次没有可用的事件—请求关联结果，关联类结论未评估")
    if _int(privacy_summary.get("not_evaluated_rule_count")) > 0:
        gaps.append(
            "存在未评估的隐私规则；未评估不等同于不存在对应行为"
        )
    return gaps[:MAX_LIST_ITEMS]


# ---------------------------------------------------------------------------
# Digest assembly.
# ---------------------------------------------------------------------------
def compute_digest_hash(digest: EvidenceDigest) -> str:
    payload = digest.model_dump(mode="json", exclude={"digest_hash"})
    text = json.dumps(payload, sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


class AIContextBuilder:
    """Builds the deterministic evidence digest for one run."""

    def __init__(
        self,
        *,
        max_top_findings: int = MAX_TOP_FINDINGS,
        max_summary_chars: int = MAX_SUMMARY_CHARS,
    ) -> None:
        self._max_top_findings = max(1, min(max_top_findings, MAX_TOP_FINDINGS))
        self._max_summary_chars = max(40, max_summary_chars)

    def build(
        self,
        *,
        task: Mapping[str, Any],
        report: Mapping[str, Any] | None = None,
        correlation: Mapping[str, Any] | None = None,
        privacy_findings: Mapping[str, Any] | None = None,
        traffic_summary: Mapping[str, Any] | None = None,
        environment: Mapping[str, Any] | None = None,
        artifact_refs: Sequence[EvidenceDigestArtifactRef] | None = None,
    ) -> EvidenceDigest:
        static_summary = build_static_summary(report)
        dynamic_summary = build_dynamic_summary(report)
        network_summary = build_network_summary(report, traffic_summary)
        correlation_summary = build_correlation_summary(correlation)
        privacy_summary = build_privacy_findings_summary(privacy_findings)
        top_findings = build_top_findings(
            privacy_findings, limit=self._max_top_findings
        )
        digest = EvidenceDigest(
            task=self._task_section(task),
            environment=self._environment_section(environment),
            static_summary=static_summary,
            dynamic_summary=dynamic_summary,
            network_summary=network_summary,
            correlation_summary=correlation_summary,
            privacy_findings_summary=privacy_summary,
            top_findings=top_findings,
            evidence_gaps=build_evidence_gaps(
                static_summary=static_summary,
                dynamic_summary=dynamic_summary,
                network_summary=network_summary,
                correlation_summary=correlation_summary,
                privacy_summary=privacy_summary,
            ),
            artifact_refs=list(artifact_refs or []),
        )
        return digest.model_copy(update={"digest_hash": compute_digest_hash(digest)})

    @staticmethod
    def _task_section(task: Mapping[str, Any]) -> dict[str, Any]:
        return {
            "task_id": _clean(task.get("task_id") or task.get("id"), 64),
            "task_type": _clean(task.get("task_type"), 40) or "ai_orchestrated",
            "analysis_scope": _clean(task.get("analysis_scope"), 40)
            or "static_only",
            # The objective is user-supplied free text: still treated as data.
            "objective": sanitize_untrusted_text(task.get("objective"), limit=400),
            "allow_dynamic": bool(task.get("allow_dynamic")),
            "allow_network": bool(task.get("allow_network")),
            "report_language": _clean(task.get("report_language"), 16) or "zh-CN",
        }

    @staticmethod
    def _environment_section(
        environment: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        if not isinstance(environment, Mapping):
            return {"status": "not_evaluated"}
        checks = (
            environment.get("checks")
            if isinstance(environment.get("checks"), Mapping)
            else {}
        )
        return {
            "status": "evaluated",
            "ok": bool(environment.get("ok")),
            # Only boolean capability flags; never raw serials or paths.
            "checks": {
                _clean(key, 60): bool(value)
                for key, value in list(checks.items())[:MAX_LIST_ITEMS]
            },
        }


# ---------------------------------------------------------------------------
# Compact tool results.
# ---------------------------------------------------------------------------
def enforce_result_char_limit(
    result: ToolCompactResult,
    max_chars: int,
) -> ToolCompactResult:
    """Guarantee a serialised compact result never exceeds *max_chars*.

    Trimming is progressive and lossy-by-design: metrics and refs are dropped
    before the summary, and the result records that truncation happened so the
    model is never told a trimmed view is complete.
    """

    def size(candidate: ToolCompactResult) -> int:
        return len(
            json.dumps(candidate.model_dump(mode="json"), ensure_ascii=False)
        )

    current = result
    if size(current) <= max_chars:
        return current
    current = current.model_copy(
        update={
            "limitations": [
                *current.limitations[:2],
                "工具结果已按字符上限截断",
            ]
        }
    )
    for update in (
        {"metrics": _trim_metrics(current.metrics)},
        {"evidence_refs": current.evidence_refs[:3]},
        {"artifact_refs": current.artifact_refs[:2]},
        {"recommended_next_tools": []},
        {"metrics": {}},
        {"evidence_refs": []},
        {"artifact_refs": []},
    ):
        if size(current) <= max_chars:
            return current
        current = current.model_copy(update=update)
    if size(current) > max_chars:
        overflow = size(current) - max_chars
        trimmed_summary = current.summary[: max(0, len(current.summary) - overflow - 8)]
        current = current.model_copy(
            update={"summary": _clean(trimmed_summary, MAX_SUMMARY_CHARS)}
        )
    return current


def _trim_metrics(metrics: Mapping[str, Any]) -> dict[str, Any]:
    """Keep only scalar metrics; nested structures are what blow up size."""

    return {
        key: value
        for key, value in list(metrics.items())[:MAX_LIST_ITEMS]
        if isinstance(value, (int, float, str, bool)) or value is None
    }


def make_artifact_refs(paths: Mapping[str, Any]) -> list[ToolArtifactRef]:
    refs: list[ToolArtifactRef] = []
    for kind, path in paths.items():
        if not path:
            continue
        refs.append(
            ToolArtifactRef(
                name=_clean(kind, 64),
                artifact_kind=_clean(kind, 64),
                path=str(path),
            )
        )
    return refs


def make_evidence_refs(evidence_ids: Sequence[str]) -> list[ToolEvidenceRef]:
    return [
        ToolEvidenceRef(evidence_id=_clean(value, 120))
        for value in evidence_ids[:MAX_EVIDENCE_REFS_PER_FINDING]
        if _clean(value, 120)
    ]


__all__ = [
    "AIContextBuilder",
    "MAX_TOP_FINDINGS",
    "build_correlation_summary",
    "build_dynamic_summary",
    "build_evidence_gaps",
    "build_network_summary",
    "build_privacy_findings_summary",
    "build_static_summary",
    "build_top_findings",
    "compute_digest_hash",
    "enforce_result_char_limit",
    "make_artifact_refs",
    "make_evidence_refs",
    "read_json_artifact",
    "read_json_list_artifact",
    "sanitize_untrusted_text",
]
