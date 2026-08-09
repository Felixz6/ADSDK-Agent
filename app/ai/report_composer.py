"""AI report composition + the deterministic Evidence Reference Validator.

The validator is the safety boundary between model narration and published
facts. After the model produces an ``ai-report-v1`` object, this module:

* deletes ``evidence_refs`` that do not exist in the evidence digest;
* downgrades factual conclusions that are left with no evidence reference;
* enforces that counts / statistics quoted in the narrative match the digest;
* caps severity at the level of the corresponding privacy finding;
* caps confidence at the level of the underlying evidence;
* rejects invented domains, permissions, SDKs, and events;
* strips legal / regulatory compliance conclusions.

If validation cannot produce a usable report, the caller falls back to the
deterministic template built here — which is code-generated, never AI-authored.
"""

from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from .context_builder import sanitize_untrusted_text
from .models import (
    AIKeyFinding,
    AIReport,
    AIReportSource,
    AISynthesisStatus,
    AITokenUsage,
    EvidenceDigest,
)


def _int(value: Any, default: int = 0) -> int:
    """Best-effort int coercion (mirrors context_builder._int locally)."""

    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return int(value)
    return default

FIXED_DISCLAIMER = (
    "AI 综合研判基于本次任务中已有的结构化技术证据生成。"
    "AI 不直接读取或验证原始敏感数据，本结果不构成法律合规结论。"
    "未观察到某项行为不代表该行为不会在其他设备、时间、账号或操作路径下发生。"
)

# Section 十六 — stable Evidence-Validator reason codes. The composer appends
# these to ``rejected_claims`` / ``downgraded_findings`` / new ``limitations`` so
# the diagnostics artifact records exactly why a claim was removed or softened.
# Never echoes sensitive content: only the code and (optionally) a bounded
# placeholder marker.
EV_REJECTED_LEGAL = "legal_conclusion"
EV_REJECTED_INVENTED = "invented_entity"
EV_REJECTED_COUNT = "count_mismatch"
EV_DOWNGRADED_NO_REF = "no_evidence_ref"
EV_DOWNGRADED_RANK = "rank_capped"
EV_REJECTED_CONSENT_STATE = "consent_state_inconsistency"
EV_DOWNGRADED_NATIVE_BRIDGE = "native_bridge_anti_debug_risk"
EV_DOWNGRADED_ZERO_REQUESTS = "zero_requests_no_network_inference"
EV_REJECTED_CORRELATION_CAUSATION = "correlation_as_causation"

_SEVERITY_RANK = {"high": 0, "medium": 1, "low": 2, "info": 3}
_CONFIDENCE_RANK = {"high": 0, "medium": 1, "low": 2}

# Commands the model must never be able to recommend as a "next action". The AI
# capability surface is read-only by default and never includes a native shell,
# adb, frida, or mitmproxy invocation; a narrative recommendation naming those
# is treated as an attempt to widen the capability surface and is dropped.
_FORBIDDEN_ACTION_PATTERN = re.compile(
    r"(?i)(^|\s|[（(])("
    r"\b(?:adb|fastboot|shell|sh|bash|cmd|powershell)\b[/:.\s]"
    r"|frida[-_ ]?(?:server|trace|ps|inject|kill)"
    r"|mitm(?:proxy|dump|web)"
    r"|rm\s+-rf"
    r"|\bsu\b\s+-c"
    r"|\bpip\s+install"
    r"|execute\s+shell"
    r"|run\s+command"
    r")"
)


def _is_forbidden_action(text: str) -> bool:
    """True if a recommended action names a shell/adb/frida/mitm command."""

    return bool(_FORBIDDEN_ACTION_PATTERN.search(text or ""))

# Legal / regulatory conclusion markers. The AI may describe technical risk;
# it may never assert legality, compliance status, or violation of a statute.
_LEGAL_MARKERS = re.compile(
    r"(?i)("
    r"违法|违规|不合规|合规结论|触犯|违反了?(《[^》]{1,40}》|[A-Z]{2,10}(?:\s*法)?)"
    r"|承担法律责任|构成侵权|应当处罚|监管处罚"
    r"|violat(?:es|ed|ion)\s+(?:the\s+)?(?:GDPR|CCPA|PIPL|COPPA|law|regulation)"
    r"|is\s+(?:il)?legal\b|non-?compliant\b|breach(?:es)?\s+the\s+law"
    r")"
)

_NUMBER_PATTERN = re.compile(r"\d+")


class EvidenceValidationOutcome:
    """Result of validating one AI report against the digest.

    ``report_source`` is the provenance tag the composer stamps on the returned
    report (Section 十六): ``deterministic_fallback`` until a caller explicitly
    passes a model-authored report through ``validate``; the orchestrator flips
    it to ``ai_validated`` / ``ai_repaired`` depending on the path that reached
    validation.
    """

    def __init__(
        self,
        report: AIReport,
        *,
        removed_refs: list[str],
        downgraded_findings: list[str],
        rejected_claims: list[str],
        usable: bool,
        report_source: AIReportSource = "deterministic_fallback",
    ) -> None:
        self.report = report
        self.removed_refs = removed_refs
        self.downgraded_findings = downgraded_findings
        self.rejected_claims = rejected_claims
        self.usable = usable
        self.report_source = report_source


class AIReportComposer:
    """Validates and finalises AI reports; owns the deterministic fallback."""

    def __init__(self, *, disclaimer: str = FIXED_DISCLAIMER) -> None:
        self._disclaimer = disclaimer

    # -- validation ------------------------------------------------------
    def validate(
        self,
        report: AIReport,
        digest: EvidenceDigest,
        *,
        report_source: AIReportSource = "ai_validated",
    ) -> EvidenceValidationOutcome:
        known_ids = set(digest.known_evidence_ids)
        removed_refs: list[str] = []
        downgraded: list[str] = []
        rejected: list[str] = []

        severity_cap = _digest_severity_cap(digest)
        confidence_cap = _digest_confidence_cap(digest)
        allowed_terms = _allowed_terms(digest)

        # Section 十六 — precompute the digest facts the four new checks read.
        consent_state = _consent_state(digest)
        native_bridge = _native_bridge_flag(digest)
        total_requests = _int(digest.network_summary.get("total_requests"))
        correlated_pairs = _int(
            digest.correlation_summary.get("correlated_pair_count")
        )

        validated_findings: list[AIKeyFinding] = []
        for finding in report.key_findings:
            kept_refs = [ref for ref in finding.evidence_refs if ref in known_ids]
            dropped = [ref for ref in finding.evidence_refs if ref not in known_ids]
            removed_refs.extend(dropped)

            summary = sanitize_untrusted_text(finding.summary, limit=600)
            title = sanitize_untrusted_text(finding.title, limit=200)

            # Legal conclusions are never publishable.
            if _LEGAL_MARKERS.search(summary) or _LEGAL_MARKERS.search(title):
                rejected.append(f"legal_conclusion:{title[:60]}")
                continue

            # Invented entities (domains / permissions / SDKs) are rejected.
            invented = _invented_entities(f"{title} {summary}", allowed_terms)
            if invented:
                rejected.append(f"invented_entity:{invented[0][:60]}")
                continue

            # Numbers must not contradict the digest.
            if _contradicts_counts(summary, digest):
                rejected.append(f"count_mismatch:{title[:60]}")
                continue

            # --- Section 十六: the four new Evidence-Validator checks --------
            # Each only narrows a claim; none of them echo sensitive content.
            # (1) consent-state consistency: a finding that narrates post-consent
            # activity while the digest recorded no post-consent events (or vice
            # versa) is dropped — the consent gate is a deterministic fact.
            if _violates_consent_state(summary, consent_state):
                rejected.append(f"consent_state_inconsistency:{title[:60]}")
                continue
            # (2) Native-bridge-as-anti-debug: a finding that downplays a process
            # crash / anti-debug observation on a Native Bridge device is
            # downgraded (not removed) so the risk is still narrated, honestly.
            # (3) zero-requests-as-no-network: claiming a network finding from a
            # run with zero observed requests is unsupported; downgrade + mark.
            # (4) correlation-as-causation: a finding that asserts causation from
            # a (low-confidence) correlation pair is downgraded.
            downgrade_native = native_bridge and _downplays_process_risk(summary)
            downgrade_zero_net = (
                total_requests == 0 and _asserts_network_finding(summary)
            )
            downgrade_causation = (
                correlated_pairs > 0 and _asserts_causation_from_correlation(summary)
            )

            severity = _cap_rank(finding.severity, severity_cap, _SEVERITY_RANK)
            confidence = _cap_rank(
                finding.confidence, confidence_cap, _CONFIDENCE_RANK
            )
            if severity != finding.severity or confidence != finding.confidence:
                downgraded.append(title[:80])

            # A factual finding with no surviving evidence reference is
            # downgraded to the lowest confidence and marked as unverified.
            if not kept_refs:
                confidence = "low"
                if severity in {"high", "medium"}:
                    severity = "low"
                downgraded.append(title[:80])
                summary = _mark_unsupported(summary)

            if downgrade_native:
                confidence = "low"
                summary = _append_limitation_marker(
                    summary, "（Native Bridge 反调试/崩溃风险未在叙述中体现，已降级）"
                )
                downgraded.append(f"native_bridge_anti_debug_risk:{title[:60]}")
            if downgrade_zero_net:
                confidence = "low"
                summary = _append_limitation_marker(
                    summary, "（本次零网络请求，网络类结论无证据支撑）"
                )
                downgraded.append(f"zero_requests_no_network_inference:{title[:60]}")
            if downgrade_causation:
                confidence = "low"
                summary = _append_limitation_marker(
                    summary, "（关联不等于因果，因果性结论已降级）"
                )
                downgraded.append(f"correlation_as_causation:{title[:60]}")

            validated_findings.append(
                AIKeyFinding(
                    title=title,
                    severity=severity,
                    confidence=confidence,
                    summary=summary,
                    evidence_refs=kept_refs,
                )
            )

        top_level_refs = [ref for ref in report.evidence_refs if ref in known_ids]
        removed_refs.extend(
            [ref for ref in report.evidence_refs if ref not in known_ids]
        )

        summary_text = sanitize_untrusted_text(report.executive_summary, limit=2400)
        if _LEGAL_MARKERS.search(summary_text):
            summary_text = _LEGAL_MARKERS.sub("[已移除法律结论]", summary_text)
            rejected.append("legal_conclusion:executive_summary")
        if _contradicts_counts(summary_text, digest):
            rejected.append("count_mismatch:executive_summary")
            summary_text = _deterministic_executive_summary(digest)
        # Section 十六 — the four checks also police the executive summary.
        if _violates_consent_state(summary_text, consent_state):
            rejected.append("consent_state_inconsistency:executive_summary")
            summary_text = _deterministic_executive_summary(digest)
        if native_bridge and _downplays_process_risk(summary_text):
            summary_text = _append_limitation_marker(
                summary_text, "（Native Bridge 反调试/崩溃风险未在叙述中体现，已降级）"
            )
            downgraded.append("native_bridge_anti_debug_risk:executive_summary")
        if total_requests == 0 and _asserts_network_finding(summary_text):
            summary_text = _append_limitation_marker(
                summary_text, "（本次零网络请求，网络类结论无证据支撑）"
            )
            downgraded.append("zero_requests_no_network_inference:executive_summary")
        if correlated_pairs > 0 and _asserts_causation_from_correlation(summary_text):
            summary_text = _append_limitation_marker(
                summary_text, "（关联不等于因果，因果性结论已降级）"
            )
            downgraded.append("correlation_as_causation:executive_summary")

        limitations = _bounded_text_list(report.limitations)
        if removed_refs:
            limitations.append("部分 AI 引用的证据编号不存在，已删除")
        if downgraded:
            limitations.append("部分 AI 结论缺少证据支撑，严重性/置信度已下调")
        if rejected:
            limitations.append("部分 AI 结论未通过证据校验，已移除")

        # Defense-in-depth: filter any recommended action that names a shell,
        # adb, frida, or mitm command — the capability surface is fixed and
        # read-only; the model must never widen it via narration. The check
        # runs against the RAW action text, before sanitize_untrusted_text
        # neutralises command markers (``adb shell`` -> ``[neutralized]``),
        # otherwise a forbidden recommendation would survive detection simply
        # by being rewritten into a neutralised token.
        raw_recommended = list(report.recommended_actions or [])
        forbidden_actions = [
            a for a in raw_recommended if _is_forbidden_action(str(a))
        ]
        kept_raw = [
            a for a in raw_recommended if not _is_forbidden_action(str(a))
        ]
        recommended = _bounded_text_list(kept_raw)
        if forbidden_actions:
            limitations.append("部分 AI 建议动作包含设备命令，已按只读策略移除")

        validated = report.model_copy(
            update={
                "executive_summary": summary_text,
                "key_findings": validated_findings,
                "evidence_gaps": _bounded_text_list(report.evidence_gaps)
                or list(digest.evidence_gaps),
                "risk_priorities": _bounded_text_list(report.risk_priorities),
                "evidence_refs": top_level_refs,
                "limitations": _dedupe(limitations),
                "disclaimer": self._disclaimer,
                "recommended_actions": recommended,
                # Section 十六 — stamp provenance on the persisted report.
                "report_source": report_source,
            }
        )
        usable = bool(validated.executive_summary.strip())
        return EvidenceValidationOutcome(
            validated,
            removed_refs=removed_refs,
            downgraded_findings=downgraded,
            rejected_claims=rejected,
            usable=usable,
            report_source=report_source,
        )

    # -- deterministic fallback -----------------------------------------
    def deterministic_report(
        self,
        digest: EvidenceDigest,
        *,
        status: AISynthesisStatus = "partial",
        usage: AITokenUsage | None = None,
        reason: str | None = None,
    ) -> AIReport:
        """Code-generated report used whenever AI output is unusable.

        Every sentence here is derived from digest counts, so it can never
        contain an unsupported claim.
        """

        limitations = ["本节由确定性模板生成，未使用 AI 叙述"]
        if reason:
            limitations.append(f"降级原因：{reason}")
        limitations.extend(list(digest.evidence_gaps)[:4])

        findings = [
            AIKeyFinding(
                title=item.title or item.rule_id,
                severity=item.severity,
                confidence=item.confidence,
                summary=item.summary,
                evidence_refs=list(item.evidence_refs),
            )
            for item in digest.top_findings[:5]
        ]
        return AIReport(
            status=status,
            report_source="deterministic_fallback",
            executive_summary=_deterministic_executive_summary(digest),
            key_findings=findings,
            evidence_gaps=list(digest.evidence_gaps),
            risk_priorities=_deterministic_risk_priorities(digest),
            recommended_actions=_deterministic_actions(digest),
            evidence_refs=[item.finding_id for item in digest.top_findings[:5]],
            limitations=_dedupe(limitations),
            disclaimer=self._disclaimer,
            usage=(usage.model_dump(mode="json") if usage else {}),
        )

    def disabled_report(self, reason: str = "AI 功能未启用") -> AIReport:
        return AIReport(
            status="disabled",
            report_source="deterministic_fallback",
            executive_summary="",
            limitations=[reason],
            disclaimer=self._disclaimer,
        )


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------
def _cap_rank(value: str, cap: str | None, ranks: Mapping[str, int]) -> str:
    if cap is None or value not in ranks or cap not in ranks:
        return value
    return value if ranks[value] >= ranks[cap] else cap


# Section 十六 — the four new checks operate on already-sanitised narration.
# Markers that reveal the four anti-patterns: a model that (1) narrates consent
# transitions the digest did not record, (2) downplays a process crash /
# anti-debug event on a Native Bridge device, (3) asserts a network finding
# from a zero-request run, or (4) turns a correlation into causation.
_CONSENT_POST_PATTERN = re.compile(
    r"同意后|用户同意之后|consent[_\s-]?after|post[_\s-]?consent"
)
_CONSENT_PRE_PATTERN = re.compile(
    r"同意前|未经用户同意|consent[_\s-]?before|pre[_\s-]?consent|without\s+consent"
)
_PROCESS_CRASH_DOWNPLAY = re.compile(
    r"(?i)(无崩溃|未崩溃|进程\s*未\s*退出|无\s*反调试|未触发反调试|no\s+crash|"
    r"did\s+not\s+crash|no\s+anti-?debug|stable\s+execution)"
)
_NETWORK_FINDING_PATTERN = re.compile(
    r"网络(行为|请求|通信|活动)|network\s+(request|behavior|traffic|activity)"
)
_CAUSATION_PATTERN = re.compile(
    r"(?i)(导致|引发|诱发|\bcaused\b|\bleads?\s+to\b|\bresults?\s+in\b|\btriggers?\b)"
)


def _consent_state(digest: EvidenceDigest) -> str:
    """Deterministic consent state derived from the digest's event counts.

    Returns ``no_dynamic``, ``pre_only``, ``post_only``, or ``both``. The
    validator never trusts the model's narration of consent — it reads the
    counts the deterministic pipeline already recorded.
    """

    dynamic = digest.dynamic_summary or {}
    pre = _int(dynamic.get("pre_consent_event_count"))
    post = _int(dynamic.get("post_consent_event_count"))
    if pre == 0 and post == 0:
        return "no_dynamic"
    if pre > 0 and post == 0:
        return "pre_only"
    if pre == 0 and post > 0:
        return "post_only"
    return "both"


def _native_bridge_flag(digest: EvidenceDigest) -> bool:
    """Read the deterministic Native Bridge flag the digest's environment block
    carries (set by ``context_builder._environment_section``). Defaults to
    ``False`` so a digest built before the flag existed cannot spuriously fire.
    """

    env = digest.environment or {}
    flag = env.get("native_bridge_detected")
    return bool(flag) if isinstance(flag, bool) else False


def _violates_consent_state(text: str, consent_state: str) -> bool:
    """A finding that narrates a consent transition the digest did not record.

    ``post_only`` and ``both`` seen, no pre-consent events but text mentions
    pre-consent activity => violated. Reciprocally, claiming post-consent
    activity when none was recorded => violated.
    """

    if not text:
        return False
    has_post = bool(_CONSENT_POST_PATTERN.search(text))
    has_pre = bool(_CONSENT_PRE_PATTERN.search(text))
    if consent_state == "no_dynamic":
        return has_pre or has_post
    if consent_state == "pre_only":
        return has_post
    if consent_state == "post_only":
        return has_pre
    # both recorded -> narration may reference either; no violation
    return False


def _downplays_process_risk(text: str) -> bool:
    """Narration that asserts no crash / no anti-debug on a device whose digest
    flagged a Native Bridge process-exit risk."""

    return bool(_PROCESS_CRASH_DOWNPLAY.search(text or ""))


def _asserts_network_finding(text: str) -> bool:
    """A paragraph that frames zero-observed-requests as a network finding."""

    return bool(_NETWORK_FINDING_PATTERN.search(text or ""))


def _asserts_causation_from_correlation(text: str) -> bool:
    """Narration that turns an observed correlation into a causal claim."""
    return bool(_CAUSATION_PATTERN.search(text or ""))


def _append_limitation_marker(summary: str, marker: str) -> str:
    """Append a determinant limitation marker without duplicating it."""

    if not summary:
        return marker
    if marker in summary:
        return summary
    return summary + marker


def _digest_severity_cap(digest: EvidenceDigest) -> str | None:
    """The AI may never exceed the highest severity the rules produced."""

    if not digest.top_findings:
        return "info"
    return min(
        (item.severity for item in digest.top_findings),
        key=lambda value: _SEVERITY_RANK.get(value, 9),
    )


def _digest_confidence_cap(digest: EvidenceDigest) -> str | None:
    if not digest.top_findings:
        return "low"
    return min(
        (item.confidence for item in digest.top_findings),
        key=lambda value: _CONFIDENCE_RANK.get(value, 9),
    )


def _allowed_terms(digest: EvidenceDigest) -> set[str]:
    """Domains / SDK categories / package names that actually appear."""

    terms: set[str] = set()
    network = digest.network_summary or {}
    for entry in network.get("top_hosts") or []:
        if isinstance(entry, Mapping):
            host = str(entry.get("host") or "").strip().lower()
            if host:
                terms.add(host)
    static = digest.static_summary or {}
    package = str(static.get("package_name") or "").strip().lower()
    if package:
        terms.add(package)
    for category in (static.get("sdk_categories") or {}):
        terms.add(str(category).strip().lower())
    for finding in digest.top_findings:
        terms.add(finding.rule_id.lower())
    return terms


_DOMAIN_PATTERN = re.compile(
    r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"(?:com|net|org|cn|io|co|info|biz|app|dev|xyz|top|site)\b",
    re.IGNORECASE,
)
_PERMISSION_PATTERN = re.compile(r"\bandroid\.permission\.[A-Z_]{3,}\b")


def _invented_entities(text: str, allowed: set[str]) -> list[str]:
    """Domains / permissions named by the AI that the digest never contained."""

    invented: list[str] = []
    for match in _DOMAIN_PATTERN.findall(text or ""):
        host = match.strip().lower()
        if host and not any(host == term or host in term or term in host for term in allowed):
            invented.append(host)
    # Permissions are only quotable when the digest actually carried counts.
    for match in _PERMISSION_PATTERN.findall(text or ""):
        if match.lower() not in allowed:
            invented.append(match)
    return invented


def _contradicts_counts(text: str, digest: EvidenceDigest) -> bool:
    """Reject narration whose quoted counts disagree with the digest.

    Only checks numbers adjacent to the count nouns the digest owns, so
    ordinary prose numbers are not policed.
    """

    if not text:
        return False
    checks: list[tuple[re.Pattern[str], int]] = [
        (
            re.compile(r"(\d+)\s*(?:个|条)?\s*(?:网络)?请求"),
            int(digest.network_summary.get("total_requests") or 0),
        ),
        (
            re.compile(r"(\d+)\s*(?:个|条)?\s*(?:动态)?事件"),
            int(digest.dynamic_summary.get("event_count") or 0),
        ),
        (
            re.compile(r"(\d+)\s*个?\s*SDK"),
            int(digest.static_summary.get("sdk_count") or 0),
        ),
        (
            re.compile(r"(\d+)\s*(?:个|条)?\s*(?:隐私)?发现"),
            int(digest.privacy_findings_summary.get("finding_count") or 0),
        ),
    ]
    for pattern, expected in checks:
        for raw in pattern.findall(text):
            try:
                quoted = int(raw)
            except ValueError:
                continue
            if quoted != expected:
                return True
    return False


def _mark_unsupported(summary: str) -> str:
    marker = "（该表述缺少直接证据引用，已降级为提示）"
    return summary + marker if marker not in summary else summary


def _bounded_text_list(values: Sequence[Any], *, limit: int = 10) -> list[str]:
    out: list[str] = []
    for value in values or []:
        text = sanitize_untrusted_text(value, limit=300)
        if not text:
            continue
        if _LEGAL_MARKERS.search(text):
            text = _LEGAL_MARKERS.sub("[已移除法律结论]", text)
        out.append(text)
        if len(out) >= limit:
            break
    return out


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(value for value in values if value))


def _deterministic_executive_summary(digest: EvidenceDigest) -> str:
    static = digest.static_summary or {}
    dynamic = digest.dynamic_summary or {}
    network = digest.network_summary or {}
    privacy = digest.privacy_findings_summary or {}
    parts = [
        f"本次分析识别到 {int(static.get('sdk_count') or 0)} 个 SDK、"
        f"{int(static.get('permission_count') or 0)} 项声明权限。",
        f"动态观察记录 {int(dynamic.get('event_count') or 0)} 条事件，"
        f"网络侧观察 {int(network.get('total_requests') or 0)} 个请求。",
        f"确定性隐私规则形成 {int(privacy.get('finding_count') or 0)} 条发现，"
        f"其中未评估规则 {int(privacy.get('not_evaluated_rule_count') or 0)} 条。",
        "未评估仅表示证据不足，不代表不存在对应行为。",
    ]
    return "".join(parts)


def _deterministic_risk_priorities(digest: EvidenceDigest) -> list[str]:
    priorities: list[str] = []
    for finding in digest.top_findings[:5]:
        if finding.severity in {"high", "medium"}:
            priorities.append(
                f"[{finding.severity}] {finding.title or finding.rule_id}"
            )
    if not priorities:
        priorities.append("本次证据未形成高于低severity的风险提示")
    return priorities


def _deterministic_actions(digest: EvidenceDigest) -> list[str]:
    actions: list[str] = []
    if not (digest.dynamic_summary or {}).get("evidence_available"):
        actions.append("补充一次可信动态采集，以评估同意前后的实际行为")
    if int((digest.network_summary or {}).get("total_requests") or 0) == 0:
        actions.append("检查代理与证书配置后重新采集网络证据")
    if int((digest.privacy_findings_summary or {}).get("not_evaluated_rule_count") or 0) > 0:
        actions.append("补齐未评估规则所需证据后重新评估")
    if not actions:
        actions.append("结合业务场景人工复核本次发现")
    return actions


__all__ = [
    "AIReportComposer",
    "EvidenceValidationOutcome",
    "FIXED_DISCLAIMER",
]
