from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ComparisonCreateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    base_task_id: str = Field(min_length=1, max_length=128)
    target_task_id: str = Field(min_length=1, max_length=128)
    allow_cross_app: bool = False


class DifferenceSet(BaseModel):
    added: list[str] = Field(default_factory=list)
    removed: list[str] = Field(default_factory=list)
    unchanged: list[str] = Field(default_factory=list)
    unavailable: bool = False


class ComparisonResult(BaseModel):
    schema_version: str = "comparison-v1"
    id: str
    task_id: str
    base_task_id: str
    target_task_id: str
    base_summary: dict[str, Any]
    target_summary: dict[str, Any]
    risk_score_delta: int | None = None
    permissions: DifferenceSet
    high_risk_permissions: DifferenceSet
    sdks: DifferenceSet
    sdk_vendors: DifferenceSet
    sdk_categories: DifferenceSet
    rules: DifferenceSet
    domains: DifferenceSet
    dynamic_behaviors: DifferenceSet
    evidence_complete: bool
    highlights: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

