from __future__ import annotations

from collections import defaultdict
from typing import Any, Iterable

from app.models import RiskCategoryScore, RiskSummary, TopRisk


CALCULATION_VERSION = "risk-v1"

# 所有分值集中在此处，便于审阅、版本化和后续校准。
RISK_WEIGHTS: dict[str, dict[str, Any]] = {
    "pre_consent_sensitive_access": {
        "score": 25, "category": "privacy", "severity": "high",
        "title": "用户同意前访问敏感信息",
    },
    "pre_consent_network": {
        "score": 20, "category": "network", "severity": "high",
        "title": "用户同意前发送网络请求",
    },
    "sensitive_permission": {
        "score": 12, "category": "permission", "severity": "medium",
        "title": "声明高关注权限",
    },
    "cleartext_http": {
        "score": 15, "category": "network", "severity": "high",
        "title": "观测到明文 HTTP 通信",
    },
    "high_risk_sdk": {
        "score": 12, "category": "sdk", "severity": "high",
        "title": "识别到高关注 SDK",
    },
    "medium_risk_sdk": {
        "score": 6, "category": "sdk", "severity": "medium",
        "title": "识别到需关注 SDK",
    },
    "protocol_error": {
        "score": 8, "category": "collection", "severity": "medium",
        "title": "动态采集协议出现错误",
    },
}

HIGH_ATTENTION_PERMISSIONS = {
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.CAMERA",
    "android.permission.READ_CONTACTS",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_SMS",
    "android.permission.RECORD_AUDIO",
}

CATEGORY_LABELS = {
    "privacy": "隐私行为",
    "network": "网络通信",
    "permission": "权限",
    "sdk": "SDK",
    "collection": "证据质量",
}


def level_for_score(score: int) -> str:
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"


def _iter_rules(report: dict[str, Any]) -> Iterable[dict[str, Any]]:
    for key in ("dynamic_findings", "strict_dynamic_findings"):
        findings = report.get(key)
        if isinstance(findings, dict):
            for rule in findings.get("rules") or []:
                if isinstance(rule, dict):
                    yield rule


def _rule_signal(rule_id: str) -> str:
    lowered = rule_id.lower()
    if "pre_consent" in lowered and ("network" in lowered or "request" in lowered):
        return "pre_consent_network"
    if "pre_consent" in lowered or "sensitive" in lowered:
        return "pre_consent_sensitive_access"
    if "permission" in lowered:
        return "sensitive_permission"
    if "http" in lowered or "cleartext" in lowered:
        return "cleartext_http"
    return "pre_consent_sensitive_access"


def calculate_risk_summary(report: dict[str, Any]) -> RiskSummary:
    risks: list[TopRisk] = []
    category_totals: dict[str, int] = defaultdict(int)
    evaluated = 0
    unevaluated = 0
    errors = 0

    for rule in _iter_rules(report):
        status = rule.get("status") or rule.get("evaluation_status")
        if status == "matched":
            evaluated += 1
            signal = _rule_signal(str(rule.get("rule_id") or "dynamic_rule"))
            weight = RISK_WEIGHTS[signal]
            evidence = rule.get("evidence_refs") or []
            risks.append(
                TopRisk(
                    id=str(rule.get("rule_id") or signal),
                    title=weight["title"],
                    severity=weight["severity"],
                    score=weight["score"],
                    evidence_refs=[str(item) for item in evidence],
                )
            )
            category_totals[weight["category"]] += weight["score"]
        elif status == "not_matched":
            evaluated += 1
        elif status == "not_evaluated":
            unevaluated += 1
        elif status == "error":
            errors += 1
            unevaluated += 1

    app_info = report.get("app_info") or {}
    declared = app_info.get("declared_permissions")
    if declared is None:
        # Compatibility for reports produced before permission classification.
        declared = app_info.get("permissions") or []
    high_attention = sorted(set(declared) & HIGH_ATTENTION_PERMISSIONS)
    if high_attention:
        weight = RISK_WEIGHTS["sensitive_permission"]
        risks.append(
            TopRisk(
                id="manifest_sensitive_permissions",
                title=weight["title"],
                severity=weight["severity"],
                score=weight["score"],
                evidence_refs=[
                    f"AndroidManifest.xml#{permission}"
                    for permission in high_attention
                ],
            )
        )
        category_totals[weight["category"]] += weight["score"]

    sdks = report.get("sdks") or []
    for sdk in sdks:
        if not isinstance(sdk, dict) or sdk.get("risk_level") not in {
            "medium", "high", "critical"
        }:
            continue
        weight = RISK_WEIGHTS[
            "high_risk_sdk"
            if sdk.get("risk_level") in {"high", "critical"}
            else "medium_risk_sdk"
        ]
        evidence_refs = [
            str(item.get("relative_path"))
            for item in sdk.get("evidence") or []
            if isinstance(item, dict) and item.get("relative_path")
        ]
        risks.append(
            TopRisk(
                id=f"sdk:{sdk.get('id') or sdk.get('package')}",
                title=f"识别到高关注 SDK：{sdk.get('sdk_name')}",
                severity=weight["severity"],
                score=weight["score"],
                evidence_refs=evidence_refs,
            )
        )
        category_totals[weight["category"]] += weight["score"]

    traffic = report.get("traffic_summary") or {}
    for request in traffic.get("sample_requests") or []:
        if isinstance(request, dict) and request.get("scheme") == "http":
            weight = RISK_WEIGHTS["cleartext_http"]
            risks.append(
                TopRisk(
                    id="cleartext_http",
                    title=weight["title"],
                    severity=weight["severity"],
                    score=weight["score"],
                    evidence_refs=[f"traffic/requests.jsonl#{request.get('flow_id', '')}"],
                )
            )
            category_totals[weight["category"]] += weight["score"]
            break

    protocol_events = [
        item
        for item in report.get("dynamic_events") or []
        if isinstance(item, dict)
        and (
            item.get("category") == "protocol_error"
            or item.get("event") == "protocol_error"
        )
    ]
    if protocol_events:
        weight = RISK_WEIGHTS["protocol_error"]
        risks.append(
            TopRisk(
                id="dynamic_protocol_error",
                title=weight["title"],
                severity=weight["severity"],
                score=weight["score"],
                evidence_refs=["frida.protocol-errors.jsonl"],
            )
        )
        category_totals[weight["category"]] += weight["score"]

    confidence_reasons: list[str] = []
    coverage = traffic.get("coverage")
    collection_status = report.get("collection_status")
    if collection_status in {"partial", "failed"}:
        confidence_reasons.append("动态采集不完整")
    if coverage == "unavailable":
        confidence_reasons.append("网络证据不可用")
    if unevaluated:
        confidence_reasons.append(f"{unevaluated} 条规则证据不足")
    if errors:
        confidence_reasons.append(f"{errors} 条规则执行异常")
    limitations = report.get("limitations") or []
    if any("pinning" in str(item).lower() for item in limitations):
        confidence_reasons.append("SSL Pinning 可能降低流量覆盖")
    if report.get("dynamic_events") is None:
        confidence_reasons.append("未执行动态行为采集")

    if errors or collection_status == "failed" or len(confidence_reasons) >= 3:
        confidence = "low"
    elif unevaluated or confidence_reasons:
        confidence = "medium"
    else:
        confidence = "high"

    score = max(0, min(100, sum(item.score for item in risks)))
    categories = [
        RiskCategoryScore(
            category=category,
            label=CATEGORY_LABELS[category],
            score=min(value, 100),
            max_score=100,
        )
        for category, value in sorted(category_totals.items())
    ]
    return RiskSummary(
        score=score,
        level=level_for_score(score),
        confidence=confidence,
        evaluated_rule_count=evaluated,
        unevaluated_rule_count=unevaluated,
        category_scores=categories,
        top_risks=sorted(risks, key=lambda item: item.score, reverse=True)[:5],
        confidence_reasons=confidence_reasons,
        calculation_version=CALCULATION_VERSION,
    )
