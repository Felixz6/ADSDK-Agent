from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field


TaskType = Literal["static", "dynamic", "comparison"]
TaskStatus = Literal["queued", "running", "completed", "failed", "cancelled"]
TaskStepStatus = Literal["success", "partial", "failed", "skipped", "running"]


class TaskCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    task_type: Literal["static", "dynamic"]
    apk_path: str = Field(min_length=1, max_length=32768)
    package_name: str | None = Field(default=None, max_length=512)
    device_id: str | None = Field(default=None, max_length=256)
    enable_traffic: bool = True
    enable_ui_stimulation: bool = False
    consent_after_seconds: int | None = Field(default=None, ge=0, le=86400)
    pre_consent_seconds: int = Field(default=10, ge=0, le=3600)
    post_consent_seconds: int = Field(default=10, ge=0, le=3600)
    collection_timeout_seconds: int = Field(default=300, ge=1, le=86400)


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
