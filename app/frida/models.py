"""Pydantic contracts for diagnostics, lifecycle and evidence quality."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


CheckStatus = Literal["pass", "warning", "error", "unknown", "not_configured"]
OverallStatus = Literal["ready", "degraded", "blocked", "error"]
RecommendedMode = Literal[
    "spawn_suspended", "spawn", "attach_existing", "launch_then_attach", "none"
]


class DiagnosticCheck(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: CheckStatus
    detected_value: Any = None
    expected_value: Any = None
    error_code: str | None = None
    message: str
    remediation: str | None = None
    evidence: dict[str, Any] = Field(default_factory=dict)


class DiagnosticIssue(BaseModel):
    model_config = ConfigDict(extra="forbid")

    code: str
    severity: Literal["info", "warning", "error", "blocking"]
    summary: str
    detail: str
    remediation: str
    evidence_available: bool = False


class DiagnosticSection(BaseModel):
    status: CheckStatus = "unknown"
    checks: dict[str, DiagnosticCheck] = Field(default_factory=dict)


class FridaDiagnosticsRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(min_length=1, max_length=256, repr=False)
    package_name: str | None = Field(default=None, max_length=512)

    @field_validator("device_id", "package_name")
    @classmethod
    def reject_control_characters(cls, value: str | None) -> str | None:
        if value is None:
            return None
        normalized = value.strip()
        if any(character in normalized for character in ("\x00", "\r", "\n")):
            raise ValueError("control characters are not allowed")
        return normalized or None


class FridaDiagnosticsResponse(BaseModel):
    schema_version: Literal["frida-diagnostics-v1"] = "frida-diagnostics-v1"
    overall_status: OverallStatus
    recommended_mode: RecommendedMode
    host: DiagnosticSection
    device: DiagnosticSection
    server: DiagnosticSection
    transport: DiagnosticSection
    target: DiagnosticSection
    issues: list[DiagnosticIssue] = Field(default_factory=list)
    remediations: list[str] = Field(default_factory=list)
    checked_at: str
    duration_ms: int = Field(ge=0)
    device_ref: str | None = None
    management_enabled: bool = False


class FridaServerActionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    device_id: str = Field(min_length=1, max_length=256, repr=False)
    confirm: bool = False

    @field_validator("device_id")
    @classmethod
    def validate_device_id(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized or any(c in normalized for c in ("\x00", "\r", "\n")):
            raise ValueError("invalid device_id")
        return normalized


class FridaServerActionResponse(BaseModel):
    schema_version: Literal["frida-server-action-v1"] = "frida-server-action-v1"
    action: Literal["deploy", "start", "stop", "status"]
    status: Literal["success", "failed", "blocked", "not_owned", "not_configured"]
    error_code: str | None = None
    message: str
    device_ref: str
    owned: bool = False
    pid: int | None = None
    details: dict[str, Any] = Field(default_factory=dict)
