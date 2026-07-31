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
