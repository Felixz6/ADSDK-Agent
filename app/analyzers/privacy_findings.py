"""M5B explainable privacy findings engine (``privacy-findings-v2``).

Converts existing static / dynamic / network / Consent-timeline / correlation-v1
evidence into deterministic, traceable, explainable privacy findings.

Findings are risk prompts formed from the current observation window. They are
never legal compliance conclusions: the engine must never state that an app is
illegal, non-compliant, or that it uploaded personal data. Observed technical
facts (``observed``) stay separated from inference based on temporal proximity
(``suspected``) and from missing coverage (``evidence_gap``). A rule that cannot
be evaluated reports ``not_evaluated``; absence of findings never means "safe".

Every public builder is pure: inputs are copied into narrow Pydantic models and
are never modified, ordering and identifiers are stable, no network access or
real device is required, and no raw sensitive content (Cookie / Authorization /
Token / request body / response body / full query value / device serial /
Android ID / IMEI / OAID / advertising ID / user input / unredacted device path)
is ever copied into a finding.
"""

from __future__ import annotations

import hashlib
from typing import Any, Literal, Mapping, Sequence

from pydantic import AliasChoices, BaseModel, ConfigDict, Field

SCHEMA_VERSION = "privacy-findings-v2"

FINDINGS_DISCLAIMER = (
    "本结果是基于当前观察窗口和技术证据形成的风险提示，不构成法律合规结论。"
    "未观察到某项行为不代表该行为不会在其他设备、时间、账号或操作路径下发生。"
)

MAX_EVIDENCE_REFS = 20
"""Upper bound of evidence references kept per finding (truncation is reported)."""

SENSITIVE_APIS: frozenset[str] = frozenset(
    {
        "Settings.Secure.getString",
        "ClipboardManager.getPrimaryClip",
    }
)

FindingsStatus = Literal[
    "evaluated",
    "partially_evaluated",
    "not_evaluated",
    "no_observations",
    "error",
]
FindingSeverity = Literal["high", "medium", "low", "info"]
FindingConfidence = Literal["high", "medium", "low"]
FindingType = Literal["observed", "suspected", "evidence_gap"]
ConsentState = Literal["pre_consent", "post_consent", "unknown"]
EvidenceType = Literal[
    "manifest",
    "dynamic_event",
    "network_request",
    "correlation",
    "timeline",
    "diagnostic",
]
RuleStatus = Literal["matched", "not_matched", "not_evaluated", "error"]
DynamicEvidenceGrade = Literal["A", "B", "C", "D"]

RULE_IDS: tuple[str, ...] = (
    "PF-PRECONSENT-SENSITIVE-EVENT",
    "PF-PRECONSENT-NETWORK",
    "PF-PRECONSENT-CORRELATED-ACTIVITY",
    "PF-CONSENT-STATE-UNKNOWN",
    "PF-DYNAMIC-EVIDENCE-GAP",
    "PF-NETWORK-EVIDENCE-GAP",
    "PF-POSTCONSENT-OBSERVATION",
)

SUPPORTED_REASON_CODES: frozenset[str] = frozenset(
    {
        "pre_consent_sensitive_api_observed",
        "pre_consent_network_request_observed",
        "post_consent_observation_only",
        "temporal_proximity_only",
        "no_causality_established",
        "consent_boundary_missing",
        "consent_state_unknown",
        "dynamic_evidence_unavailable",
        "dynamic_evidence_grade_insufficient",
        "network_evidence_unavailable",
        "correlation_not_available",
        "correlation_confidence_capped",
        "utc_time_fallback",
        "manifest_evidence_unavailable",
        "observation_window_limited",
        "no_matching_observation",
        "rule_execution_error",
        "evidence_refs_truncated",
    }
)

REASON_CODE_EXPLANATIONS: dict[str, str] = {
    "pre_consent_sensitive_api_observed": "在 Consent 之前观察到敏感 API 调用记录。",
    "pre_consent_network_request_observed": "在 Consent 之前观察到网络请求记录。",
    "post_consent_observation_only": "相关观察仅出现在 Consent 之后。",
    "temporal_proximity_only": "仅存在时间接近关系，未建立因果关系。",
    "no_causality_established": "证据不支持“事件触发了请求”这一结论。",
    "consent_boundary_missing": "缺少可信的 Consent 时间边界。",
    "consent_state_unknown": "部分观察的 Consent 阶段无法判定。",
    "dynamic_evidence_unavailable": "本次没有可信的动态事件证据。",
    "dynamic_evidence_grade_insufficient": "动态证据等级不足以形成确定性动态结论。",
    "network_evidence_unavailable": "本次没有可信的网络侧证据。",
    "correlation_not_available": "本次没有可用的事件—请求关联结果。",
    "correlation_confidence_capped": "关联置信度限制了本发现的置信度上限。",
    "utc_time_fallback": "时间对齐依赖墙钟时间，置信度上限为低。",
    "manifest_evidence_unavailable": "Manifest 证据不可用，相关静态判断未评估。",
    "observation_window_limited": "结论仅覆盖本次采集窗口。",
    "no_matching_observation": "在可评估证据中没有匹配到该规则的观察。",
    "rule_execution_error": "该规则执行异常，其他规则不受影响。",
    "evidence_refs_truncated": "证据引用数量过多，仅展示前若干条。",
}


class PrivacyEvidenceRef(BaseModel):
    """A traceable pointer to already-redacted evidence."""

    model_config = ConfigDict(extra="forbid")

    evidence_type: EvidenceType
    evidence_id: str
    artifact: str
    label: str


class PrivacyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    rule_id: str
    title: str
    category: str
    severity: FindingSeverity
    confidence: FindingConfidence
    finding_type: FindingType
    consent_state: ConsentState
    summary: str
    explanation: str
    reason_codes: list[str] = Field(default_factory=list)
    evidence_refs: list[PrivacyEvidenceRef] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class PrivacyRuleResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    rule_id: str
    status: RuleStatus
    reason_codes: list[str] = Field(default_factory=list)
    evidence_refs: list[PrivacyEvidenceRef] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class PrivacyFindingsSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_count: int = Field(ge=0)
    high_severity_count: int = Field(ge=0)
    medium_severity_count: int = Field(ge=0)
    low_severity_count: int = Field(ge=0)
    info_severity_count: int = Field(ge=0)
    confirmed_observation_count: int = Field(ge=0)
    suspected_risk_count: int = Field(ge=0)
    evidence_gap_count: int = Field(ge=0)
    matched_rule_count: int = Field(ge=0)
    not_matched_rule_count: int = Field(ge=0)
    not_evaluated_rule_count: int = Field(ge=0)
    error_rule_count: int = Field(ge=0)


class PrivacyFindings(BaseModel):
    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["privacy-findings-v2"] = SCHEMA_VERSION
    status: FindingsStatus
    disclaimer: str = FINDINGS_DISCLAIMER
    findings: list[PrivacyFinding] = Field(default_factory=list)
    rule_results: list[PrivacyRuleResult] = Field(default_factory=list)
    summary: PrivacyFindingsSummary
    limitations: list[str] = Field(default_factory=list)


class DynamicEventEvidence(BaseModel):
    """Safe dynamic-event projection; raw Hook parameters are excluded."""

    model_config = ConfigDict(extra="ignore")

    event_id: str
    event_type: str = "dynamic_event"
    api: str | None = None
    identifier_type: str | None = None
    category: str | None = None
    consent_state: ConsentState = "unknown"
    timestamp_utc: str | None = Field(
        default=None,
        validation_alias=AliasChoices("timestamp_utc", "timestamp"),
    )
    timing_reliable: bool = True

    @property
    def is_sensitive(self) -> bool:
        return self.api in SENSITIVE_APIS


class NetworkRequestEvidence(BaseModel):
    """Safe request metadata only; bodies, headers and query values are absent."""

    model_config = ConfigDict(extra="ignore")

    request_id: str = Field(validation_alias=AliasChoices("request_id", "flow_id"))
    host: str = Field(
        default="unknown",
        validation_alias=AliasChoices("host", "hostname", "request_host"),
    )
    method: str = Field(
        default="HTTP",
        validation_alias=AliasChoices("method", "request_method"),
    )
    path: str | None = None
    timestamp_utc: str | None = Field(
        default=None,
        validation_alias=AliasChoices("timestamp_utc", "timestamp"),
    )
    consent_state: ConsentState = "unknown"


class CorrelationEvidence(BaseModel):
    """Safe correlation-v1 projection."""

    model_config = ConfigDict(extra="ignore")

    correlation_id: str
    dynamic_event_id: str = ""
    network_request_id: str = ""
    event_type: str = "dynamic_event"
    request_host: str = "unknown"
    request_method: str = "HTTP"
    delta_ms: int = 0
    consent_state: ConsentState = "unknown"
    confidence: FindingConfidence = "low"
    reason_codes: list[str] = Field(default_factory=list)


def safe_path_summary(path: Any) -> str:
    """Reduce a request path to a coarse, non-identifying summary."""

    if not isinstance(path, str) or not path.strip():
        return "/"
    segments = [segment for segment in path.split("?")[0].split("/") if segment]
    if not segments:
        return "/"
    kept = ["".join(segment[:24]) for segment in segments[:2]]
    summary = "/" + "/".join(kept)
    return f"{summary}/…" if len(segments) > 2 else summary


def _normalized_grade(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    grade = value.strip().upper()
    return grade if grade in {"A", "B", "C", "D"} else None


def _dedupe(values: Sequence[str]) -> list[str]:
    return list(dict.fromkeys(values))


def _supported_reasons(values: Sequence[str]) -> list[str]:
    return [code for code in _dedupe(values) if code in SUPPORTED_REASON_CODES]


def build_finding_id(
    *,
    rule_id: str,
    evidence_ids: Sequence[str],
    consent_state: str,
) -> str:
    """Build a stable identifier for one finding.

    The digest covers the schema version, the rule, the sorted evidence
    identifiers and the consent state, so identical evidence always yields an
    identical identifier regardless of input ordering.
    """

    joined = "\0".join(sorted(str(value) for value in evidence_ids))
    digest = hashlib.sha256(
        f"{SCHEMA_VERSION}\0{rule_id}\0{joined}\0{consent_state}".encode("utf-8")
    ).hexdigest()
    return f"pf-{digest[:24]}"


def calculate_finding_confidence(
    *,
    dynamic_grade: str | None = None,
    correlation_confidence: str | None = None,
    utc_time_fallback: bool = False,
    consent_state: str = "unknown",
    base: FindingConfidence = "medium",
) -> FindingConfidence:
    """Derive confidence from evidence quality, never from severity.

    Dynamic grade A supports high confidence, B high-to-medium, C at most
    medium, and D supports no deterministic dynamic conclusion (low). A
    correlation ceiling, a wall-clock (UTC) fallback and an unknown consent
    state each lower the ceiling independently.
    """

    order = {"high": 3, "medium": 2, "low": 1}
    ceiling = order[base]

    grade = _normalized_grade(dynamic_grade)
    if grade == "A":
        ceiling = min(ceiling, order["high"])
    elif grade == "B":
        ceiling = min(ceiling, order["high"])
    elif grade == "C":
        ceiling = min(ceiling, order["medium"])
    elif grade == "D":
        ceiling = min(ceiling, order["low"])

    if isinstance(correlation_confidence, str):
        normalized = correlation_confidence.strip().lower()
        if normalized == "medium":
            ceiling = min(ceiling, order["medium"])
        elif normalized == "low":
            ceiling = min(ceiling, order["low"])

    if utc_time_fallback:
        ceiling = min(ceiling, order["low"])
    if consent_state == "unknown":
        ceiling = min(ceiling, order["low"])

    for name, value in (("high", 3), ("medium", 2), ("low", 1)):
        if value == ceiling:
            return name  # type: ignore[return-value]
    return "low"


def _event_ref(event: DynamicEventEvidence) -> PrivacyEvidenceRef:
    descriptor = event.api or event.category or event.event_type
    return PrivacyEvidenceRef(
        evidence_type="dynamic_event",
        evidence_id=event.event_id,
        artifact="events.json",
        label=f"{event.event_type} · {descriptor}",
    )


def _request_ref(request: NetworkRequestEvidence) -> PrivacyEvidenceRef:
    return PrivacyEvidenceRef(
        evidence_type="network_request",
        evidence_id=request.request_id,
        artifact="traffic/requests.jsonl",
        label=(
            f"{request.method.upper()} {request.host}"
            f"{safe_path_summary(request.path)}"
        ),
    )


def _correlation_ref(item: CorrelationEvidence) -> PrivacyEvidenceRef:
    return PrivacyEvidenceRef(
        evidence_type="correlation",
        evidence_id=item.correlation_id,
        artifact="correlations.json",
        label=(
            f"{item.event_type} 与 {item.request_method.upper()} "
            f"{item.request_host} 时间差 {item.delta_ms} ms"
        ),
    )


def _timeline_ref(evidence_id: str, label: str) -> PrivacyEvidenceRef:
    return PrivacyEvidenceRef(
        evidence_type="timeline",
        evidence_id=evidence_id,
        artifact="sessions.json#timeline",
        label=label,
    )


def _diagnostic_ref(evidence_id: str, label: str) -> PrivacyEvidenceRef:
    return PrivacyEvidenceRef(
        evidence_type="diagnostic",
        evidence_id=evidence_id,
        artifact="report.json",
        label=label,
    )


def build_evidence_refs(
    refs: Sequence[PrivacyEvidenceRef],
) -> tuple[list[PrivacyEvidenceRef], list[str]]:
    """Sort, deduplicate and bound evidence references."""

    unique: dict[tuple[str, str], PrivacyEvidenceRef] = {}
    for ref in refs:
        unique.setdefault((ref.evidence_type, ref.evidence_id), ref)
    ordered = sorted(
        unique.values(),
        key=lambda ref: (ref.evidence_type, ref.evidence_id),
    )
    if len(ordered) <= MAX_EVIDENCE_REFS:
        return ordered, []
    dropped = len(ordered) - MAX_EVIDENCE_REFS
    return (
        ordered[:MAX_EVIDENCE_REFS],
        [f"证据引用超过 {MAX_EVIDENCE_REFS} 条，已省略 {dropped} 条（原始证据仍可查阅）"],
    )


def _make_finding(
    *,
    rule_id: str,
    title: str,
    category: str,
    severity: FindingSeverity,
    confidence: FindingConfidence,
    finding_type: FindingType,
    consent_state: ConsentState,
    summary: str,
    explanation: str,
    reason_codes: Sequence[str],
    refs: Sequence[PrivacyEvidenceRef],
    limitations: Sequence[str] = (),
) -> PrivacyFinding:
    bounded_refs, truncation_limits = build_evidence_refs(refs)
    codes = list(reason_codes)
    if truncation_limits:
        codes.append("evidence_refs_truncated")
    return PrivacyFinding(
        finding_id=build_finding_id(
            rule_id=rule_id,
            evidence_ids=[ref.evidence_id for ref in bounded_refs],
            consent_state=consent_state,
        ),
        rule_id=rule_id,
        title=title,
        category=category,
        severity=severity,
        confidence=confidence,
        finding_type=finding_type,
        consent_state=consent_state,
        summary=summary,
        explanation=explanation,
        reason_codes=_supported_reasons(codes),
        evidence_refs=bounded_refs,
        limitations=_dedupe([*limitations, *truncation_limits]),
    )


class PrivacyRuleContext(BaseModel):
    """Read-only, already-redacted inputs shared by every rule."""

    model_config = ConfigDict(extra="forbid", arbitrary_types_allowed=True)

    events: list[DynamicEventEvidence] = Field(default_factory=list)
    requests: list[NetworkRequestEvidence] = Field(default_factory=list)
    correlations: list[CorrelationEvidence] = Field(default_factory=list)
    correlation_status: str | None = None
    dynamic_evidence_available: bool = False
    network_evidence_available: bool = False
    consent_boundary_available: bool = False
    dynamic_grade: str | None = None
    manifest_status: str | None = None

    @property
    def dynamic_conclusions_allowed(self) -> bool:
        return (
            self.dynamic_evidence_available
            and _normalized_grade(self.dynamic_grade) in {"A", "B", "C"}
        )


def _rule_preconsent_sensitive_event(
    context: PrivacyRuleContext,
) -> tuple[PrivacyRuleResult, list[PrivacyFinding]]:
    rule_id = "PF-PRECONSENT-SENSITIVE-EVENT"
    if not context.dynamic_evidence_available:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_evaluated",
                reason_codes=["dynamic_evidence_unavailable"],
                limitations=["缺少可信动态事件证据，该规则未评估"],
            ),
            [],
        )
    if not context.dynamic_conclusions_allowed:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_evaluated",
                reason_codes=["dynamic_evidence_grade_insufficient"],
                limitations=["动态证据等级为 D，未形成确定性动态结论"],
            ),
            [],
        )
    if not context.consent_boundary_available:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_evaluated",
                reason_codes=["consent_boundary_missing"],
                limitations=["缺少可信 Consent 时间边界，Consent 前后无法判定"],
            ),
            [],
        )

    matched = [
        event
        for event in context.events
        if event.is_sensitive and event.consent_state == "pre_consent"
    ]
    if not matched:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_matched",
                reason_codes=["no_matching_observation", "observation_window_limited"],
                limitations=["未观察到该行为不代表其在其他环境下不会发生"],
            ),
            [],
        )

    refs = [_event_ref(event) for event in matched]
    confidence = calculate_finding_confidence(
        dynamic_grade=context.dynamic_grade,
        consent_state="pre_consent",
        base="high",
    )
    finding = _make_finding(
        rule_id=rule_id,
        title="Consent 前存在敏感 API 调用观察",
        category="privacy_sensitive_access",
        severity="high",
        confidence=confidence,
        finding_type="observed",
        consent_state="pre_consent",
        summary=(
            f"在 Consent 之前观察到 {len(matched)} 条敏感 API 调用记录。"
        ),
        explanation=(
            "本次采集在可信 Consent 边界之前记录到敏感 API 调用。"
            "这是对技术调用行为的观察，不代表这些数据被上传或被用于特定用途，"
            "也不构成法律合规结论。"
        ),
        reason_codes=[
            "pre_consent_sensitive_api_observed",
            "observation_window_limited",
        ],
        refs=refs,
        limitations=[
            "调用发生不等同于数据外发；是否外发需结合网络侧证据判断",
        ],
    )
    return (
        PrivacyRuleResult(
            rule_id=rule_id,
            status="matched",
            reason_codes=finding.reason_codes,
            evidence_refs=finding.evidence_refs,
            limitations=finding.limitations,
        ),
        [finding],
    )


def _rule_preconsent_network(
    context: PrivacyRuleContext,
) -> tuple[PrivacyRuleResult, list[PrivacyFinding]]:
    rule_id = "PF-PRECONSENT-NETWORK"
    if not context.network_evidence_available:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_evaluated",
                reason_codes=["network_evidence_unavailable"],
                limitations=["网络侧证据不可用，该规则未评估"],
            ),
            [],
        )
    if not context.consent_boundary_available:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_evaluated",
                reason_codes=["consent_boundary_missing"],
                limitations=["缺少可信 Consent 时间边界，Consent 前后无法判定"],
            ),
            [],
        )

    matched = [
        request
        for request in context.requests
        if request.consent_state == "pre_consent"
    ]
    if not matched:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_matched",
                reason_codes=["no_matching_observation", "observation_window_limited"],
                limitations=["零请求或无 Consent 前请求不代表应用没有网络行为"],
            ),
            [],
        )

    refs = [_request_ref(request) for request in matched]
    hosts = sorted({request.host for request in matched})
    confidence = calculate_finding_confidence(
        consent_state="pre_consent",
        base="high",
    )
    finding = _make_finding(
        rule_id=rule_id,
        title="Consent 前存在网络请求观察",
        category="privacy_network_activity",
        severity="high",
        confidence=confidence,
        finding_type="observed",
        consent_state="pre_consent",
        summary=(
            f"在 Consent 之前观察到 {len(matched)} 条网络请求，"
            f"涉及 {len(hosts)} 个主机。"
        ),
        explanation=(
            "采集器在可信 Consent 边界之前记录到网络请求元数据（主机、方法、粗粒度路径）。"
            "请求内容未被解析或保存，因此不能据此判断是否传输了个人信息，"
            "也不构成法律合规结论。"
        ),
        reason_codes=[
            "pre_consent_network_request_observed",
            "observation_window_limited",
        ],
        refs=refs,
        limitations=[
            "仅记录请求元数据，不包含请求体、响应体或完整查询参数",
        ],
    )
    return (
        PrivacyRuleResult(
            rule_id=rule_id,
            status="matched",
            reason_codes=finding.reason_codes,
            evidence_refs=finding.evidence_refs,
            limitations=finding.limitations,
        ),
        [finding],
    )


def _rule_preconsent_correlated_activity(
    context: PrivacyRuleContext,
) -> tuple[PrivacyRuleResult, list[PrivacyFinding]]:
    rule_id = "PF-PRECONSENT-CORRELATED-ACTIVITY"
    if context.correlation_status is None or context.correlation_status in {
        "not_evaluated",
        "error",
    }:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_evaluated",
                reason_codes=["correlation_not_available"],
                limitations=["没有可用的事件—请求关联结果，该规则未评估"],
            ),
            [],
        )

    matched = [
        item
        for item in context.correlations
        if item.consent_state == "pre_consent"
    ]
    if not matched:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_matched",
                reason_codes=["no_matching_observation", "temporal_proximity_only"],
                limitations=["未形成 Consent 前的时间接近关系，不代表相关行为未发生"],
            ),
            [],
        )

    order = {"high": 3, "medium": 2, "low": 1}
    best = max(matched, key=lambda item: order.get(item.confidence, 1))
    utc_fallback = any(
        "clock_unreliable" in item.reason_codes or "utc_time_near" in item.reason_codes
        for item in matched
    )
    confidence = calculate_finding_confidence(
        dynamic_grade=context.dynamic_grade,
        correlation_confidence=best.confidence,
        utc_time_fallback=utc_fallback,
        consent_state="pre_consent",
        base="medium",
    )
    reason_codes = [
        "temporal_proximity_only",
        "no_causality_established",
        "correlation_confidence_capped",
        "observation_window_limited",
    ]
    if utc_fallback:
        reason_codes.append("utc_time_fallback")
    finding = _make_finding(
        rule_id=rule_id,
        title="Consent 前动态事件与网络请求时间接近",
        category="privacy_correlated_activity",
        severity="medium",
        confidence=confidence,
        finding_type="suspected",
        consent_state="pre_consent",
        summary=(
            f"在 Consent 之前存在 {len(matched)} 组时间接近的动态事件与网络请求。"
        ),
        explanation=(
            "该结果只表示两类证据在时间上接近，可能相关。"
            "它不证明事件触发了网络请求，也不证明请求中包含个人信息，"
            "更不构成法律合规结论。需要人工结合业务逻辑复核。"
        ),
        reason_codes=reason_codes,
        refs=[_correlation_ref(item) for item in matched],
        limitations=[
            "时间接近不等于因果关系",
            "关联置信度上限由时间证据质量决定",
        ],
    )
    return (
        PrivacyRuleResult(
            rule_id=rule_id,
            status="matched",
            reason_codes=finding.reason_codes,
            evidence_refs=finding.evidence_refs,
            limitations=finding.limitations,
        ),
        [finding],
    )


def _rule_consent_state_unknown(
    context: PrivacyRuleContext,
) -> tuple[PrivacyRuleResult, list[PrivacyFinding]]:
    rule_id = "PF-CONSENT-STATE-UNKNOWN"
    if not context.dynamic_evidence_available and not context.network_evidence_available:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_evaluated",
                reason_codes=[
                    "dynamic_evidence_unavailable",
                    "network_evidence_unavailable",
                ],
                limitations=["没有可判定 Consent 阶段的观察，该规则未评估"],
            ),
            [],
        )

    unknown_events = [
        event for event in context.events if event.consent_state == "unknown"
    ]
    unknown_requests = [
        request for request in context.requests if request.consent_state == "unknown"
    ]
    total = len(unknown_events) + len(unknown_requests)
    if total == 0 and context.consent_boundary_available:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_matched",
                reason_codes=["no_matching_observation"],
            ),
            [],
        )

    refs = [
        *(_event_ref(event) for event in unknown_events),
        *(_request_ref(request) for request in unknown_requests),
    ]
    reason_codes = ["consent_state_unknown", "observation_window_limited"]
    limitations = ["Consent 阶段未知的观察不参与 Consent 前后判定"]
    if not context.consent_boundary_available:
        reason_codes.insert(0, "consent_boundary_missing")
        limitations.append("缺少可信 Consent 时间边界")
        refs.append(
            _timeline_ref("consent_boundary", "Consent 边界缺失或时间不可信")
        )
    finding = _make_finding(
        rule_id=rule_id,
        title="部分观察的 Consent 阶段无法判定",
        category="evidence_coverage",
        severity="info",
        confidence="low",
        finding_type="evidence_gap",
        consent_state="unknown",
        summary=(
            f"有 {total} 条观察缺少可信时间信息，无法归入 Consent 前或 Consent 后。"
        ),
        explanation=(
            "这是证据覆盖度提示，不是风险判定。"
            "这些观察既不能用于支持 Consent 前风险提示，也不能用于证明不存在相关行为。"
        ),
        reason_codes=reason_codes,
        refs=refs,
        limitations=limitations,
    )
    return (
        PrivacyRuleResult(
            rule_id=rule_id,
            status="matched",
            reason_codes=finding.reason_codes,
            evidence_refs=finding.evidence_refs,
            limitations=finding.limitations,
        ),
        [finding],
    )


def _rule_dynamic_evidence_gap(
    context: PrivacyRuleContext,
) -> tuple[PrivacyRuleResult, list[PrivacyFinding]]:
    rule_id = "PF-DYNAMIC-EVIDENCE-GAP"
    grade = _normalized_grade(context.dynamic_grade)
    if context.dynamic_evidence_available and grade in {"A", "B", "C"}:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_matched",
                reason_codes=["no_matching_observation"],
            ),
            [],
        )

    reason_codes = ["observation_window_limited"]
    details: list[str] = []
    if not context.dynamic_evidence_available:
        reason_codes.insert(0, "dynamic_evidence_unavailable")
        details.append("本次没有可信的动态事件证据")
    if grade == "D" or grade is None:
        reason_codes.append("dynamic_evidence_grade_insufficient")
        details.append("动态证据等级不足以形成确定性动态结论")
    finding = _make_finding(
        rule_id=rule_id,
        title="动态证据覆盖不足",
        category="evidence_coverage",
        severity="info",
        confidence="low",
        finding_type="evidence_gap",
        consent_state="unknown",
        summary="；".join(details) or "动态证据覆盖不足。",
        explanation=(
            "依赖动态事件的规则本次未评估。"
            "未评估代表证据不足，不代表相关行为不存在，也不代表应用安全或合规。"
        ),
        reason_codes=reason_codes,
        refs=[
            _diagnostic_ref(
                "dynamic_evidence_quality",
                f"动态证据等级：{grade or '未记录'}",
            )
        ],
        limitations=["未评估不等于安全，需要在可用环境中重新采集"],
    )
    return (
        PrivacyRuleResult(
            rule_id=rule_id,
            status="matched",
            reason_codes=finding.reason_codes,
            evidence_refs=finding.evidence_refs,
            limitations=finding.limitations,
        ),
        [finding],
    )


def _rule_network_evidence_gap(
    context: PrivacyRuleContext,
) -> tuple[PrivacyRuleResult, list[PrivacyFinding]]:
    rule_id = "PF-NETWORK-EVIDENCE-GAP"
    if context.network_evidence_available:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_matched",
                reason_codes=["no_matching_observation"],
            ),
            [],
        )
    finding = _make_finding(
        rule_id=rule_id,
        title="网络侧证据覆盖不足",
        category="evidence_coverage",
        severity="info",
        confidence="low",
        finding_type="evidence_gap",
        consent_state="unknown",
        summary="本次没有可信的网络侧证据，依赖网络证据的规则未评估。",
        explanation=(
            "采集器未成功产出可信网络证据（例如未启用、启动失败或证书限制）。"
            "缺少网络观察不代表应用没有网络行为，也不代表不存在数据外发。"
        ),
        reason_codes=["network_evidence_unavailable", "observation_window_limited"],
        refs=[_diagnostic_ref("traffic_summary", "网络采集结果不可信或不可用")],
        limitations=["零请求不代表应用没有网络行为"],
    )
    return (
        PrivacyRuleResult(
            rule_id=rule_id,
            status="matched",
            reason_codes=finding.reason_codes,
            evidence_refs=finding.evidence_refs,
            limitations=finding.limitations,
        ),
        [finding],
    )


def _rule_postconsent_observation(
    context: PrivacyRuleContext,
) -> tuple[PrivacyRuleResult, list[PrivacyFinding]]:
    rule_id = "PF-POSTCONSENT-OBSERVATION"
    if not context.dynamic_evidence_available and not context.network_evidence_available:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_evaluated",
                reason_codes=[
                    "dynamic_evidence_unavailable",
                    "network_evidence_unavailable",
                ],
                limitations=["没有可信观察，该规则未评估"],
            ),
            [],
        )
    if not context.consent_boundary_available:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_evaluated",
                reason_codes=["consent_boundary_missing"],
                limitations=["缺少可信 Consent 时间边界，Consent 后无法判定"],
            ),
            [],
        )

    events = [
        event
        for event in context.events
        if event.is_sensitive and event.consent_state == "post_consent"
    ]
    requests = [
        request
        for request in context.requests
        if request.consent_state == "post_consent"
    ]
    if not events and not requests:
        return (
            PrivacyRuleResult(
                rule_id=rule_id,
                status="not_matched",
                reason_codes=["no_matching_observation"],
            ),
            [],
        )

    confidence = calculate_finding_confidence(
        dynamic_grade=context.dynamic_grade if events else None,
        consent_state="post_consent",
        base="medium",
    )
    finding = _make_finding(
        rule_id=rule_id,
        title="Consent 后的敏感行为与网络活动观察",
        category="privacy_post_consent_activity",
        severity="low",
        confidence=confidence,
        finding_type="observed",
        consent_state="post_consent",
        summary=(
            f"Consent 之后观察到 {len(events)} 条敏感 API 调用与 "
            f"{len(requests)} 条网络请求。"
        ),
        explanation=(
            "这些观察发生在 Consent 之后，作为行为基线信息记录。"
            "本条目不是风险判定，也不评价这些行为是否在授权范围之内。"
        ),
        reason_codes=["post_consent_observation_only", "observation_window_limited"],
        refs=[
            *(_event_ref(event) for event in events),
            *(_request_ref(request) for request in requests),
        ],
        limitations=["Consent 后行为是否符合授权范围需人工结合隐私政策判断"],
    )
    return (
        PrivacyRuleResult(
            rule_id=rule_id,
            status="matched",
            reason_codes=finding.reason_codes,
            evidence_refs=finding.evidence_refs,
            limitations=finding.limitations,
        ),
        [finding],
    )


_RULES: tuple[
    tuple[str, Any],
    ...,
] = (
    ("PF-PRECONSENT-SENSITIVE-EVENT", _rule_preconsent_sensitive_event),
    ("PF-PRECONSENT-NETWORK", _rule_preconsent_network),
    ("PF-PRECONSENT-CORRELATED-ACTIVITY", _rule_preconsent_correlated_activity),
    ("PF-CONSENT-STATE-UNKNOWN", _rule_consent_state_unknown),
    ("PF-DYNAMIC-EVIDENCE-GAP", _rule_dynamic_evidence_gap),
    ("PF-NETWORK-EVIDENCE-GAP", _rule_network_evidence_gap),
    ("PF-POSTCONSENT-OBSERVATION", _rule_postconsent_observation),
)


def evaluate_privacy_rules(
    context: PrivacyRuleContext,
) -> tuple[list[PrivacyRuleResult], list[PrivacyFinding]]:
    """Evaluate every rule independently with per-rule fault isolation.

    A failing rule is reported as ``status="error"`` with a redacted reason and
    never prevents the remaining rules from being evaluated.
    """

    results: list[PrivacyRuleResult] = []
    findings: list[PrivacyFinding] = []
    for rule_id, rule in _RULES:
        try:
            result, rule_findings = rule(context)
        except Exception as exc:  # per-rule isolation, never a global swallow
            results.append(
                PrivacyRuleResult(
                    rule_id=rule_id,
                    status="error",
                    reason_codes=["rule_execution_error"],
                    limitations=[
                        f"规则执行异常（{type(exc).__name__}），其他规则不受影响"
                    ],
                )
            )
            continue
        results.append(result)
        findings.extend(rule_findings)
    return results, findings


def build_findings_summary(
    findings: Sequence[PrivacyFinding],
    rule_results: Sequence[PrivacyRuleResult],
) -> PrivacyFindingsSummary:
    return PrivacyFindingsSummary(
        finding_count=len(findings),
        high_severity_count=sum(item.severity == "high" for item in findings),
        medium_severity_count=sum(item.severity == "medium" for item in findings),
        low_severity_count=sum(item.severity == "low" for item in findings),
        info_severity_count=sum(item.severity == "info" for item in findings),
        confirmed_observation_count=sum(
            item.finding_type == "observed" for item in findings
        ),
        suspected_risk_count=sum(item.finding_type == "suspected" for item in findings),
        evidence_gap_count=sum(
            item.finding_type == "evidence_gap" for item in findings
        ),
        matched_rule_count=sum(item.status == "matched" for item in rule_results),
        not_matched_rule_count=sum(
            item.status == "not_matched" for item in rule_results
        ),
        not_evaluated_rule_count=sum(
            item.status == "not_evaluated" for item in rule_results
        ),
        error_rule_count=sum(item.status == "error" for item in rule_results),
    )


_SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2, "info": 3}
_TYPE_ORDER = {"observed": 0, "suspected": 1, "evidence_gap": 2}


def _sort_findings(findings: Sequence[PrivacyFinding]) -> list[PrivacyFinding]:
    return sorted(
        findings,
        key=lambda item: (
            _SEVERITY_ORDER.get(item.severity, 9),
            _TYPE_ORDER.get(item.finding_type, 9),
            item.rule_id,
            item.finding_id,
        ),
    )


def _validate_events(
    raw_events: Sequence[Mapping[str, Any]],
) -> list[DynamicEventEvidence]:
    events: list[DynamicEventEvidence] = []
    for index, raw in enumerate(raw_events):
        if not isinstance(raw, Mapping):
            continue
        if raw.get("type") == "control":
            continue
        payload = {
            **raw,
            "event_id": str(raw.get("event_id") or f"event-{index + 1}"),
            "event_type": str(
                raw.get("event_type")
                or raw.get("category")
                or raw.get("action")
                or "dynamic_event"
            ),
        }
        try:
            events.append(DynamicEventEvidence.model_validate(payload))
        except (TypeError, ValueError):
            continue
    return events


def _validate_requests(
    raw_requests: Sequence[Mapping[str, Any]],
    *,
    request_consent_states: Mapping[str, str] | None = None,
) -> list[NetworkRequestEvidence]:
    states = request_consent_states or {}
    requests: list[NetworkRequestEvidence] = []
    for index, raw in enumerate(raw_requests):
        if not isinstance(raw, Mapping):
            continue
        request_id = str(
            raw.get("request_id") or raw.get("flow_id") or f"request-{index + 1}"
        )
        payload = {**raw, "request_id": request_id}
        resolved_state = states.get(request_id)
        if resolved_state in {"pre_consent", "post_consent", "unknown"}:
            payload["consent_state"] = resolved_state
        try:
            requests.append(NetworkRequestEvidence.model_validate(payload))
        except (TypeError, ValueError):
            continue
    return requests


def _validate_correlations(
    correlation: Mapping[str, Any] | None,
) -> tuple[list[CorrelationEvidence], str | None]:
    if not isinstance(correlation, Mapping):
        return [], None
    status = correlation.get("status")
    items: list[CorrelationEvidence] = []
    for index, raw in enumerate(correlation.get("items") or []):
        if not isinstance(raw, Mapping):
            continue
        payload = {
            **raw,
            "correlation_id": str(
                raw.get("correlation_id") or f"correlation-{index + 1}"
            ),
        }
        try:
            items.append(CorrelationEvidence.model_validate(payload))
        except (TypeError, ValueError):
            continue
    return items, str(status) if status is not None else None


def _derive_status(
    rule_results: Sequence[PrivacyRuleResult],
    *,
    has_observations: bool,
) -> FindingsStatus:
    statuses = {item.status for item in rule_results}
    decided = {"matched", "not_matched"} & statuses
    if not decided:
        if statuses == {"error"}:
            return "error"
        return "not_evaluated"
    if not has_observations and not ({"matched"} & statuses):
        return "no_observations"
    if {"not_evaluated", "error"} & statuses:
        return "partially_evaluated"
    return "evaluated"


def build_privacy_findings(
    *,
    dynamic_events: Sequence[Mapping[str, Any]] | None = None,
    network_requests: Sequence[Mapping[str, Any]] | None = None,
    correlation: Mapping[str, Any] | None = None,
    manifest_evidence: Mapping[str, Any] | None = None,
    dynamic_evidence_available: bool = False,
    network_evidence_available: bool = False,
    consent_boundary_available: bool = False,
    dynamic_evidence_grade: str | None = None,
    request_consent_states: Mapping[str, str] | None = None,
) -> PrivacyFindings:
    """Build explainable privacy findings from already-redacted evidence.

    Inputs are read-only. Every rule is evaluated independently, so a missing
    Manifest never blocks dynamic rules and a missing correlation result never
    blocks the independent dynamic and network rules.
    """

    events = _validate_events(dynamic_events or [])
    requests = _validate_requests(
        network_requests or [],
        request_consent_states=request_consent_states,
    )
    correlations, correlation_status = _validate_correlations(correlation)
    manifest_status = None
    if isinstance(manifest_evidence, Mapping):
        raw_status = manifest_evidence.get("status")
        manifest_status = str(raw_status) if raw_status is not None else None

    context = PrivacyRuleContext(
        events=events,
        requests=requests,
        correlations=correlations,
        correlation_status=correlation_status,
        dynamic_evidence_available=dynamic_evidence_available,
        network_evidence_available=network_evidence_available,
        consent_boundary_available=consent_boundary_available,
        dynamic_grade=_normalized_grade(dynamic_evidence_grade),
        manifest_status=manifest_status,
    )
    rule_results, findings = evaluate_privacy_rules(context)
    ordered_findings = _sort_findings(findings)
    ordered_results = sorted(rule_results, key=lambda item: item.rule_id)

    limitations = [FINDINGS_DISCLAIMER]
    if manifest_status is not None and manifest_status != "evaluated":
        limitations.append("Manifest 证据不可用，依赖 Manifest 的静态判断未评估")
    if correlation_status is None:
        limitations.append("本次没有可用的事件—请求关联结果，关联类发现未评估")
    if not events and not requests:
        limitations.append("本次没有可用于隐私发现的动态或网络观察")

    return PrivacyFindings(
        status=_derive_status(
            ordered_results,
            has_observations=bool(events or requests or correlations),
        ),
        findings=ordered_findings,
        rule_results=ordered_results,
        summary=build_findings_summary(ordered_findings, ordered_results),
        limitations=_dedupe(limitations),
    )


def build_error_privacy_findings(
    *,
    reason: str | None = None,
) -> PrivacyFindings:
    """Return a safe degraded result when the engine itself fails."""

    rule_results = [
        PrivacyRuleResult(
            rule_id=rule_id,
            status="error",
            reason_codes=["rule_execution_error"],
            limitations=["隐私发现模块执行异常，主报告仍基于原始证据生成"],
        )
        for rule_id in RULE_IDS
    ]
    limitations = [
        FINDINGS_DISCLAIMER,
        "隐私发现模块执行异常，本次未形成可解释隐私发现",
    ]
    if reason:
        limitations.append(f"异常类型：{reason}")
    return PrivacyFindings(
        status="error",
        findings=[],
        rule_results=rule_results,
        summary=build_findings_summary([], rule_results),
        limitations=_dedupe(limitations),
    )
