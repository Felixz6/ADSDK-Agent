"""Typed pipeline and rule-evaluation status models."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Iterable

from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    field_validator,
    model_validator,
)


class StepStatus(str, Enum):
    SUCCESS = "success"
    PARTIAL = "partial"
    FAILED = "failed"
    SKIPPED = "skipped"


class RuleEvaluationStatus(str, Enum):
    MATCHED = "matched"
    NOT_MATCHED = "not_matched"
    NOT_EVALUATED = "not_evaluated"
    ERROR = "error"


class StepResult(BaseModel):
    """Result and diagnostics for one analysis pipeline step."""

    model_config = ConfigDict(extra="forbid", validate_assignment=True)

    schema_version: str = Field(default="1.0", min_length=1)
    name: str = Field(min_length=1)
    status: StepStatus
    required: bool = True
    started_at: datetime | None = None
    ended_at: datetime | None = None
    duration_ms: int | None = Field(default=None, ge=0)
    duration_seconds: float | None = Field(default=None, ge=0)
    outputs: list[str] = Field(default_factory=list)
    output_files: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)
    error_code: str | None = None
    error_message: str | None = None
    error: str | None = None
    details: dict[str, Any] = Field(default_factory=dict)

    @field_validator("name")
    @classmethod
    def _normalize_name(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("step name must not be blank")
        return normalized

    @field_validator("started_at", "ended_at")
    @classmethod
    def _require_timezone(cls, value: datetime | None) -> datetime | None:
        if value is not None and (
            value.tzinfo is None or value.utcoffset() is None
        ):
            raise ValueError("step timestamps must include a timezone")
        return value

    @model_validator(mode="after")
    def _validate_timing(self) -> "StepResult":
        if (
            self.started_at is not None
            and self.ended_at is not None
            and self.ended_at < self.started_at
        ):
            raise ValueError("ended_at must not precede started_at")
        if (
            self.duration_seconds is None
            and self.started_at is not None
            and self.ended_at is not None
        ):
            self.duration_seconds = (
                self.ended_at - self.started_at
            ).total_seconds()
        if self.duration_ms is None and self.duration_seconds is not None:
            self.duration_ms = max(0, int(self.duration_seconds * 1000))
        if not self.outputs and self.output_files:
            self.outputs = list(self.output_files)
        if not self.output_files and self.outputs:
            self.output_files = list(self.outputs)
        if self.error_message is None and self.error is not None:
            self.error_message = self.error
        if self.error is None and self.error_message is not None:
            self.error = self.error_message
        return self


def make_step_result(
    name: str,
    status: StepStatus | str,
    **values: Any,
) -> StepResult:
    """Small compatibility helper for constructing a validated step result."""

    return StepResult(name=name, status=StepStatus(status), **values)


def derive_overall_status(
    steps: Iterable[StepResult | StepStatus | str],
) -> StepStatus:
    """Derive a pipeline status while respecting optional failed steps."""

    normalized: list[tuple[StepStatus, bool]] = []
    for step in steps:
        if isinstance(step, StepResult):
            normalized.append((step.status, step.required))
        else:
            normalized.append((StepStatus(step), True))

    if not normalized:
        return StepStatus.SKIPPED
    if any(
        status is StepStatus.FAILED and required
        for status, required in normalized
    ):
        return StepStatus.FAILED
    if all(status is StepStatus.SKIPPED for status, _ in normalized):
        return StepStatus.SKIPPED
    if any(
        status in {StepStatus.FAILED, StepStatus.PARTIAL}
        for status, _ in normalized
    ):
        return StepStatus.PARTIAL
    if any(
        status is StepStatus.SKIPPED and required
        for status, required in normalized
    ):
        return StepStatus.PARTIAL
    return StepStatus.SUCCESS
