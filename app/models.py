from typing import Any, Dict, List, Literal, Optional
from pydantic import BaseModel, Field


class AnalyzeRequest(BaseModel):
    apk_path: str = Field(..., description="Absolute path to the APK on Windows")


class DynamicAnalyzeRequest(BaseModel):
    apk_path: str = Field(..., description="Absolute path to the APK on Windows")
    package_name: Optional[str] = Field(
        default=None,
        description="Android package name; if empty, parse from AndroidManifest.xml",
    )
    device_id: Optional[str] = Field(
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
    description: Optional[str] = None


RiskLevel = Literal["low", "medium", "high", "critical"]
RiskConfidence = Literal["low", "medium", "high"]
ConsentState = Literal["pre_consent", "post_consent", "unknown"]


class SDKHit(BaseModel):
    id: Optional[str] = None
    sdk_name: str
    package: str
    vendor: Optional[str] = None
    category: Optional[str] = None
    risk_level: Optional[RiskLevel] = None
    confidence: float = 0.8
    version: Optional[str] = None
    evidence: List[EvidenceRef] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    static_only: bool = True
    dynamic_correlated: bool = False


class AppInfo(BaseModel):
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    application_label: Optional[str] = None
    permissions: List[str] = Field(default_factory=list)
    declared_permissions: List[str] = Field(default_factory=list)
    custom_permissions: List[str] = Field(default_factory=list)
    component_permissions: List[str] = Field(default_factory=list)
    sensitive_permissions: List[str] = Field(default_factory=list)
    high_attention_permissions: List[str] = Field(default_factory=list)


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
    evidence_refs: List[str] = Field(default_factory=list)


class RiskSummary(BaseModel):
    score: int = Field(ge=0, le=100)
    level: RiskLevel
    confidence: RiskConfidence
    evaluated_rule_count: int = Field(ge=0)
    unevaluated_rule_count: int = Field(ge=0)
    category_scores: List[RiskCategoryScore] = Field(default_factory=list)
    top_risks: List[TopRisk] = Field(default_factory=list)
    confidence_reasons: List[str] = Field(default_factory=list)
    calculation_version: str = "risk-v1"


class TimelineEvent(BaseModel):
    id: str
    relative_ms: Optional[int] = Field(default=None, ge=0)
    timestamp_utc: Optional[str] = None
    source: Literal["frida", "network", "system", "control"]
    category: str
    title: str
    description: str
    consent_state: ConsentState
    severity: RiskLevel
    evidence_ref: Optional[str] = None


class BehaviorTimeline(BaseModel):
    start_monotonic: Optional[float] = None
    consent_monotonic: Optional[float] = None
    timing_reliable: bool = False
    warnings: List[str] = Field(default_factory=list)
    events: List[TimelineEvent] = Field(default_factory=list)
    timeline_version: str = "timeline-v1"


class ComplianceFinding(BaseModel):
    title: str
    severity: RiskLevel
    summary: str
    recommendation: str
    evidence_refs: List[str] = Field(default_factory=list)


class PriorityAction(BaseModel):
    priority: Literal["P0", "P1", "P2"]
    action: str
    reason: str


class ComplianceInsight(BaseModel):
    overall_assessment: str
    key_findings: List[ComplianceFinding] = Field(default_factory=list)
    priority_actions: List[PriorityAction] = Field(default_factory=list)
    limitations: List[str] = Field(default_factory=list)
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
    run_id: Optional[str] = None
    apk_sha256: Optional[str] = None
    apk_snapshot: Optional[Dict[str, Any]] = None
    normalized_apk_name: Optional[str] = None
    analysis_started_at: Optional[str] = None
    status: Optional[str] = None
    steps: List[Dict[str, Any]] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)
    device: Optional[Dict[str, Any]] = None
    artifacts: List[Dict[str, Any]] = Field(default_factory=list)
    app_info: Optional[AppInfo] = None
    sdk_count: int = 0
    sdks: List[SDKHit] = Field(default_factory=list)
    output_dir: Optional[str] = None
    hook_log: Optional[str] = None
    events_json: Optional[str] = None
    events_raw_jsonl: Optional[str] = None
    consent_time: Optional[str] = None
    traffic_dir: Optional[str] = None
    traffic_summary_json: Optional[str] = None
    traffic_jsonl: Optional[str] = None
    sessions_json: Optional[str] = None
    report_json: Optional[str] = None
    report_md: Optional[str] = None
    report_html: Optional[str] = None
    dynamic_events: Optional[List[Dict[str, Any]]] = None
    dynamic_findings: Optional[Dict[str, Any]] = None
    strict_dynamic_findings: Optional[Dict[str, Any]] = None
    traffic_summary: Optional[Dict[str, Any]] = None
    pre_consent_seconds: Optional[int] = None
    post_consent_seconds: Optional[int] = None
    enable_traffic: Optional[bool] = None
    enable_ui_stimulation: Optional[bool] = None
    collection_timeout_seconds: Optional[int] = None
    collection_status: Optional[str] = None
    dynamic_validation_level: Optional[str] = None
    dynamic_execution: Optional[Dict[str, Any]] = None
    environment_capabilities: Optional[Dict[str, Any]] = None
    dynamic_task_result: Optional[Dict[str, Any]] = None
    dynamic_evidence_quality: Optional[Dict[str, Any]] = None
    frida_diagnostics: Optional[Dict[str, Any]] = None
    process_diagnostics: Optional[Dict[str, Any]] = None
    traffic_diagnostics: Optional[Dict[str, Any]] = None
    traffic_coverage: Optional[str] = None
    dynamic_timeline: Optional[Dict[str, Any]] = None
    collector_sessions: Optional[Dict[str, Any]] = None
    risk_summary: Optional[RiskSummary] = None
    timeline: Optional[BehaviorTimeline] = None
    compliance_insight: Optional[ComplianceInsight] = None
    diagnostics: Optional[AnalysisDiagnostics] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)
