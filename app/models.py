from typing import Any, Literal

from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    apk_path: str = Field(..., description="Absolute path to the APK on Windows")


class DynamicAnalyzeRequest(BaseModel):
    apk_path: str = Field(..., description="Absolute path to the APK on Windows")
    package_name: str | None = Field(
        default=None,
        description="Android package name; if empty, parse from AndroidManifest.xml",
    )
    device_id: str | None = Field(
        default=None,
        max_length=256,
        description="ADB/Frida device serial; required when multiple devices are online",
    )
    consent_after_seconds: int | None = Field(
        default=None,
        ge=0,
        le=86400,
        description="Seconds after dynamic capture start when user consent is considered granted",
    )
    pre_consent_seconds: int = Field(
        default=10,
        ge=0,
        le=3600,
        description="Pre-consent analysis window length in seconds",
    )
    post_consent_seconds: int = Field(
        default=10,
        ge=0,
        le=3600,
        description="Post-consent analysis window length in seconds",
    )
    enable_traffic: bool = Field(
        default=True,
        description="Enable the run-owned mitmproxy collection session",
    )
    enable_ui_stimulation: bool = Field(
        default=False,
        description="Run an optional UI action only after Hook-ready and resume",
    )
    collection_timeout_seconds: int = Field(
        default=300,
        ge=1,
        le=86400,
        description="Hard timeout for the active dynamic collection window",
    )
    dynamic_mode_policy: Literal["strict", "balanced", "attach_only"] = Field(
        default="balanced",
        description="Frida execution policy; balanced preserves historical fallback behavior",
    )


class EvidenceRef(BaseModel):
    source_type: str
    relative_path: str
    detector: str
    description: str | None = None


RiskLevel = Literal["low", "medium", "high", "critical"]
RiskConfidence = Literal["low", "medium", "high"]
ConsentState = Literal["pre_consent", "post_consent", "unknown"]


class SDKHit(BaseModel):
    id: str | None = None
    sdk_name: str
    package: str
    vendor: str | None = None
    category: str | None = None
    risk_level: RiskLevel | None = None
    confidence: float = 0.8
    version: str | None = None
    evidence: list[EvidenceRef] = Field(default_factory=list)
    capabilities: list[str] = Field(default_factory=list)
    static_only: bool = True
    dynamic_correlated: bool = False


class AppInfo(BaseModel):
    package_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    application_label: str | None = None
    permissions: list[str] = Field(default_factory=list)
    declared_permissions: list[str] = Field(default_factory=list)
    custom_permissions: list[str] = Field(default_factory=list)
    component_permissions: list[str] = Field(default_factory=list)
    sensitive_permissions: list[str] = Field(default_factory=list)
    high_attention_permissions: list[str] = Field(default_factory=list)


class RiskCategoryScore(BaseModel):
    category: str
    label: str
    score: int = Field(ge=0, le=100)
    max_score: int = Field(ge=0, le=100)


class TopRisk(BaseModel):
    id: str
    title: str
    severity: RiskLevel
    score: int = Field(ge=0, le=100)
    evidence_refs: list[str] = Field(default_factory=list)


class RiskSummary(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    confidence: RiskConfidence
    evaluated_rule_count: int = Field(ge=0)
    unevaluated_rule_count: int = Field(ge=0)
    category_scores: list[RiskCategoryScore] = Field(default_factory=list)
    top_risks: list[TopRisk] = Field(default_factory=list)
    confidence_reasons: list[str] = Field(default_factory=list)
    calculation_version: str = "risk-v1"


class TimelineEvent(BaseModel):
    id: str
    relative_ms: int | None = Field(default=None, ge=0)
    timestamp_utc: str | None = None
    source: Literal["frida", "network", "system", "control"]
    category: str
    title: str
    description: str
    consent_state: ConsentState
    severity: RiskLevel
    evidence_ref: str | None = None


class BehaviorTimeline(BaseModel):
    start_monotonic: float | None = None
    consent_monotonic: float | None = None
    timing_reliable: bool = False
    warnings: list[str] = Field(default_factory=list)
    events: list[TimelineEvent] = Field(default_factory=list)
    timeline_version: str = "timeline-v1"


class ComplianceFinding(BaseModel):
    title: str
    severity: RiskLevel
    summary: str
    recommendation: str
    evidence_refs: list[str] = Field(default_factory=list)


class PriorityAction(BaseModel):
    priority: Literal["P0", "P1", "P2"]
    action: str
    reason: str


class ComplianceInsight(BaseModel):
    overall_assessment: str
    key_findings: list[ComplianceFinding] = Field(default_factory=list)
    priority_actions: list[PriorityAction] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    generator_version: str = "insight-v1"


class AnalysisDiagnostics(BaseModel):
    snapshot_duration_ms: int = Field(default=0, ge=0)
    apktool_duration_ms: int = Field(default=0, ge=0)
    manifest_duration_ms: int = Field(default=0, ge=0)
    sdk_scan_duration_ms: int = Field(default=0, ge=0)
    risk_scoring_duration_ms: int = Field(default=0, ge=0)
    report_write_duration_ms: int = Field(default=0, ge=0)
    total_duration_ms: int = Field(default=0, ge=0)


class AnalyzeResponse(BaseModel):
    ok: bool
    apk_path: str
    schema_version: str = "1.0"
    run_id: str | None = None
    apk_sha256: str | None = None
    apk_snapshot: dict[str, Any] | None = None
    normalized_apk_name: str | None = None
    analysis_started_at: str | None = None
    status: str | None = None
    steps: list[dict[str, Any]] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    device: dict[str, Any] | None = None
    artifacts: list[dict[str, Any]] = Field(default_factory=list)
    app_info: AppInfo | None = None
    sdk_count: int = 0
    sdks: list[SDKHit] = Field(default_factory=list)
    output_dir: str | None = None
    hook_log: str | None = None
    events_json: str | None = None
    events_raw_jsonl: str | None = None
    consent_time: str | None = None
    traffic_dir: str | None = None
    traffic_summary_json: str | None = None
    traffic_jsonl: str | None = None
    sessions_json: str | None = None
    report_json: str | None = None
    report_md: str | None = None
    report_html: str | None = None
    dynamic_events: list[dict[str, Any]] | None = None
    dynamic_findings: dict[str, Any] | None = None
    strict_dynamic_findings: dict[str, Any] | None = None
    traffic_summary: dict[str, Any] | None = None
    pre_consent_seconds: int | None = None
    post_consent_seconds: int | None = None
    enable_traffic: bool | None = None
    enable_ui_stimulation: bool | None = None
    collection_timeout_seconds: int | None = None
    collection_status: str | None = None
    dynamic_validation_level: str | None = None
    dynamic_execution: dict[str, Any] | None = None
    environment_capabilities: dict[str, Any] | None = None
    dynamic_task_result: dict[str, Any] | None = None
    dynamic_evidence_quality: dict[str, Any] | None = None
    frida_diagnostics: dict[str, Any] | None = None
    process_diagnostics: dict[str, Any] | None = None
    traffic_diagnostics: dict[str, Any] | None = None
    traffic_coverage: str | None = None
    dynamic_timeline: dict[str, Any] | None = None
    collector_sessions: dict[str, Any] | None = None
    manifest_evidence: dict[str, Any] | None = None
    evidence_correlation: dict[str, Any] | None = None
    privacy_findings: dict[str, Any] | None = None
    risk_summary: RiskSummary | None = None
    timeline: BehaviorTimeline | None = None
    compliance_insight: ComplianceInsight | None = None
    diagnostics: AnalysisDiagnostics | None = None
    error: str | None = None
    error_code: str | None = None
    limitations: list[str] = Field(default_factory=list)
