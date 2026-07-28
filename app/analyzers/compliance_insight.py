from __future__ import annotations

from app.models import (
    ComplianceFinding,
    ComplianceInsight,
    PriorityAction,
    RiskSummary,
)


RECOMMENDATIONS = {
    "privacy": "将相关 SDK 初始化和敏感信息读取延迟至用户明确同意后，并增加调用门禁。",
    "network": "在同意状态确认前阻断外发请求，并复核明文 HTTP 与传输加密配置。",
    "permission": "按最小权限原则移除非必要权限，并在实际使用时再申请。",
    "sdk": "核对 SDK 配置、初始化时机和数据字段，补充动态证据后再作行为判断。",
    "collection": "修复采集链路并重新执行，以补足可验证证据。",
}


def generate_compliance_insight(
    risk_summary: RiskSummary,
    *,
    limitations: list[str] | None = None,
) -> ComplianceInsight:
    findings: list[ComplianceFinding] = []
    actions: list[PriorityAction] = []
    for risk in risk_summary.top_risks:
        category = risk.id.split(":", 1)[0]
        if "network" in risk.id or "http" in risk.id:
            category = "network"
        elif "sdk" in risk.id:
            category = "sdk"
        elif "permission" in risk.id:
            category = "permission"
        elif "protocol" in risk.id:
            category = "collection"
        else:
            category = "privacy"
        recommendation = RECOMMENDATIONS[category]
        findings.append(
            ComplianceFinding(
                title=risk.title,
                severity=risk.severity,
                summary=f"结构化证据命中该风险信号，风险贡献 {risk.score} 分。",
                recommendation=recommendation,
                evidence_refs=list(risk.evidence_refs),
            )
        )
        priority = (
            "P0"
            if risk.severity in {"critical", "high"}
            else "P1"
            if risk.severity == "medium"
            else "P2"
        )
        actions.append(
            PriorityAction(
                priority=priority,
                action=recommendation,
                reason=f"该项有结构化风险证据，贡献 {risk.score} 分。",
            )
        )

    if findings:
        assessment = (
            f"本次分析风险等级为 {risk_summary.level}，得分 "
            f"{risk_summary.score}/100；结论仅基于当前任务的结构化证据。"
        )
    else:
        assessment = (
            "当前可验证证据未命中已配置风险规则；这不等于证明不存在风险，"
            "仍需结合证据覆盖情况判断。"
        )

    insight_limitations = list(dict.fromkeys(limitations or []))
    insight_limitations.extend(
        item
        for item in risk_summary.confidence_reasons
        if item not in insight_limitations
    )
    return ComplianceInsight(
        overall_assessment=assessment,
        key_findings=findings,
        priority_actions=actions[:5],
        limitations=insight_limitations,
    )
