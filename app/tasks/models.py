from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


TaskType = Literal["static", "dynamic", "comparison", "ai_orchestrated"]
TaskStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
TaskStepStatus = Literal["success", "partial", "failed", "skipped", "running"]
AnalysisScope = Literal[
    "static_only", "dynamic_only", "full_analysis", "report_only"
]


class TaskCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_type: Literal["static", "dynamic", "ai_orchestrated"]
    apk_path: str = Field(min_length=1, max_length=32768)
    package_name: str | None = Field(default=None, max_length=512)
    device_id: str | None = Field(default=None, max_length=256)
    enable_traffic: bool = True
    enable_ui_stimulation: bool = False
    consent_after_seconds: int | None = Field(default=None, ge=0, le=86400)
    pre_consent_seconds: int = Field(default=10, ge=0, le=3600)
    post_consent_seconds: int = Field(default=10, ge=0, le=3600)
    collection_timeout_seconds: int = Field(default=300, ge=1, le=86400)
    dynamic_mode_policy: Literal["strict", "balanced", "attach_only"] = "balanced"

    # --- AI orchestration (task_type="ai_orchestrated") --------------------
    # All AI fields are optional so existing static/dynamic submissions keep
    # their exact current shape and behaviour.
    objective: str | None = Field(default=None, max_length=2000)
    analysis_scope: AnalysisScope = "static_only"
    allow_dynamic: bool = False
    allow_network: bool = False
    ai_enabled: bool = True
    # Bounded on both ends: an unlimited budget is never accepted.
    token_budget: int = Field(default=6000, ge=256, le=200_000)
    report_language: str = Field(default="zh-CN", max_length=16)
    # Explicit confirmations for device_state_change tools. Without an entry
    # here the orchestrator refuses to execute the tool.
    confirmed_tools: list[str] = Field(default_factory=list, max_length=8)


class TaskStepRecord(BaseModel):
    id: int
    task_id: str
    step_key: str
    step_name: str
    status: TaskStepStatus
    progress_percent: int = Field(ge=0, le=100)
    message: str | None = None
    started_at: str | None = None
    completed_at: str | None = None
    updated_at: str


class TaskRecord(BaseModel):
    id: str
    task_type: TaskType
    status: TaskStatus
    apk_path: str | None = None
    apk_snapshot_path: str | None = None
    apk_sha256: str | None = None
    package_name: str | None = None
    app_name: str | None = None
    version_name: str | None = None
    version_code: str | None = None
    device_id: str | None = None
    enable_traffic: bool = False
    enable_ui_stimulation: bool = False
    progress_percent: int = Field(ge=0, le=100)
    current_stage: str | None = None
    cancelled_at_stage: str | None = None
    error_code: str | None = None
    error_message: str | None = None
    report_json_path: str | None = None
    report_markdown_path: str | None = None
    report_html_path: str | None = None
    risk_score: int | None = None
    risk_level: str | None = None
    request_payload: dict[str, Any] = Field(default_factory=dict)
    created_at: str
    started_at: str | None = None
    completed_at: str | None = None
    updated_at: str
    steps: list[TaskStepRecord] = Field(default_factory=list)


class TaskListResponse(BaseModel):
    items: list[TaskRecord]
    total: int = Field(ge=0)
    page: int = Field(ge=1)
    page_size: int = Field(ge=1)
    pages: int = Field(ge=0)


class TaskActionResponse(BaseModel):
    task: TaskRecord
    message: str


class TaskReportResponse(BaseModel):
    task_id: str
    status: TaskStatus
    report: dict[str, Any] | None = None
    json_url: str | None = None
    markdown_url: str | None = None
    html_url: str | None = None


class TaskSystemStatus(BaseModel):
    database_ok: bool
    database_path: str
    running_tasks: int
    queued_tasks: int
    occupied_devices: list[str] = Field(default_factory=list)


class AIStatusResponse(BaseModel):
    """Public AI availability. Never exposes the API key or its length."""

    model_config = ConfigDict(extra="forbid")

    enabled: bool
    provider: str
    model: str
    configured: bool
    reachable: bool | None = None
    last_error_code: str | None = None
    default_token_budget: int
    max_rounds: int
    max_tool_calls: int
    report_language: str
    allow_dynamic_tools: bool


class TaskAIArtifactResponse(BaseModel):
    """Wrapper for ai-plan.json / ai-report.json reads."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    status: TaskStatus
    available: bool
    payload: dict[str, Any] | None = None


class TaskAIArtifactSummary(BaseModel):
    """Identifying summary of the regenerated AI section, returned by the
    ``regenerate`` route so the client can immediately poll the artifact
    endpoints. Carries no secrets and no model text."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    status: TaskStatus
    ai_status: str
    ai_section: dict[str, Any]


# ---------------------------------------------------------------------------
# M6B — secure frontend AI configuration center.
#
# Models below describe the /ai/settings* surface. The API key is *never*
# present in any response model. Save requests carry it as an optional write-
# only field; a missing or empty value preserves the stored key (deletion is
# a separate authenticated action).
# ---------------------------------------------------------------------------
AISettingsFieldSource = Literal["default", "environment", "local_store"]
AIKeyType = Literal["none", "environment", "local_store"]


class AISettingsResponse(BaseModel):
    """Masked effective AI settings returned by GET /ai/settings.

    ``api_key_configured`` is the *only* key-derived field; the raw key, its
    length, or any derivative is never included.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: str
    enabled: bool
    provider: str
    base_url: str
    model: str
    api_key_configured: bool
    api_key_source: AIKeyType
    default_token_budget: int
    max_rounds: int
    max_tool_calls: int
    timeout_seconds: int
    max_input_tokens: int
    max_output_tokens: int
    cache_enabled: bool
    cache_ttl_seconds: int
    allow_dynamic_tools: bool
    report_language: str
    field_sources: dict[str, AISettingsFieldSource]
    locked_fields: list[str]


class AISettingsSaveRequest(BaseModel):
    """PUT /ai/settings — editable fields + optional write-only API key.

    ``api_key`` semantics:
      * omitted      -> the stored key is preserved
      * empty string -> the stored key is preserved (NOT a delete)
      * non-empty    -> replace the stored key (DPAPI)
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    provider: str | None = None
    base_url: str | None = None
    model: str | None = None
    # Write-only: never echoed back. Stored via DPAPI, never in the JSON.
    api_key: str | None = None
    default_token_budget: int | None = None
    max_rounds: int | None = None
    max_tool_calls: int | None = None
    timeout_seconds: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    cache_enabled: bool | None = None
    cache_ttl_seconds: int | None = None
    allow_dynamic_tools: bool | None = None
    report_language: str | None = None


class AISettingsTestRequest(BaseModel):
    """POST /ai/settings/test — optional temporary config (never persisted).

    A temporary ``api_key`` lives only in this request's memory: it is not
    written to the store, cache, DB, report, or logs.
    """

    model_config = ConfigDict(extra="forbid")

    enabled: bool | None = None
    provider: str | None = None
    base_url: str | None = None
    model: str | None = None
    api_key: str | None = None
    timeout_seconds: int | None = None


class AISettingsTestResponse(BaseModel):
    """Result of a connection test. No key, no host echo beyond the request."""

    model_config = ConfigDict(extra="forbid")

    status: Literal[
        "reachable",
        "unreachable",
        "invalid_configuration",
        "authentication_failed",
        "timeout",
    ]
    provider: str
    model: str
    latency_ms: int
    safe_message: str
    models_endpoint_supported: bool


class AISettingsDeleteKeyResponse(BaseModel):
    """Result of DELETE /ai/settings/api-key (local key only)."""

    model_config = ConfigDict(extra="forbid")

    deleted: bool
    api_key_source: AIKeyType
    api_key_configured: bool
