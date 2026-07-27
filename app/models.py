from typing import Any, Dict, List, Optional
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


class EvidenceRef(BaseModel):
    source_type: str
    relative_path: str
    detector: str
    description: Optional[str] = None


class SDKHit(BaseModel):
    sdk_name: str
    package: str
    confidence: float = 0.8
    version: Optional[str] = None
    evidence: List[EvidenceRef] = Field(default_factory=list)


class AppInfo(BaseModel):
    package_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    application_label: Optional[str] = None


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
    traffic_coverage: Optional[str] = None
    dynamic_timeline: Optional[Dict[str, Any]] = None
    error: Optional[str] = None
    error_code: Optional[str] = None
    limitations: List[str] = Field(default_factory=list)
