"""Pydantic models for the M6A AI orchestration module.

Three versioned schemas are owned here:

* ``ai-plan-v1``         -> the model's execution plan.
* ``evidence-digest-v1`` -> the *deterministic, code-generated* evidence digest
  that grounds every model call (built by ``context_builder``, never by AI).
* ``ai-report-v1``       -> the AI synthesis report.

Plus the compact tool result shape that travels back to the model and the
token-usage accounting record. All models ``forbid`` extra fields so a
malformed / injected model output fails fast and triggers the structured
repair / deterministic fallback path.
"""

from __future__ import annotations

from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field

# ---------------------------------------------------------------------------
# Versioned schema tags.
# ---------------------------------------------------------------------------
AI_PLAN_SCHEMA_VERSION: Literal["ai-plan-v1"] = "ai-plan-v1"
AI_REPORT_SCHEMA_VERSION: Literal["ai-report-v1"] = "ai-report-v1"
EVIDENCE_DIGEST_SCHEMA_VERSION: Literal["evidence-digest-v1"] = (
    "evidence-digest-v1"
)
# M6C — runtime diagnostics artifact. Records observable runtime facts about
# AI execution: per-round token provenance, error classification, latency, cache
# status, retry counts. Contains NO API key, NO full prompt, NO full model
# response, NO reasoning_content text, NO chain-of-thought — only a boolean
# recording whether reasoning_content was present.
AI_RUNTIME_DIAGNOSTICS_SCHEMA_VERSION: Literal["ai-runtime-diagnostics-v1"] = (
    "ai-runtime-diagnostics-v1"
)


def ai_plan_schema_version() -> str:
    return AI_PLAN_SCHEMA_VERSION


def ai_report_schema_version() -> str:
    return AI_REPORT_SCHEMA_VERSION


def evidence_digest_schema_version() -> str:
    return EVIDENCE_DIGEST_SCHEMA_VERSION


def ai_runtime_diagnostics_schema_version() -> str:
    return AI_RUNTIME_DIAGNOSTICS_SCHEMA_VERSION


# ---------------------------------------------------------------------------
# Tool registry primitives.
# ---------------------------------------------------------------------------
ToolRiskLevel = Literal["read_only", "analysis", "device_state_change"]
ToolResultStatus = Literal[
    "success", "partial", "failed", "not_run", "blocked_confirmation_required"
]


class ToolInputSchema(BaseModel):
    """JSON-schema-like description of a tool's accepted arguments.

    Stored as a plain dict so it can be serialised straight into the model
    prompt and validated server-side with a real Pydantic model per tool.
    """

    model_config = ConfigDict(extra="forbid")

    type: Literal["object"] = "object"
    properties: dict[str, dict[str, Any]] = Field(default_factory=dict)
    required: list[str] = Field(default_factory=list)
    additionalProperties: bool = False


class ToolCandidate(BaseModel):
    """A registry entry describing one whitelisted tool offered to the model."""

    model_config = ConfigDict(extra="forbid")

    name: str
    description: str = Field(max_length=512)
    input_schema: ToolInputSchema = Field(default_factory=ToolInputSchema)
    risk_level: ToolRiskLevel
    requires_confirmation: bool = False
    estimated_cost: Literal["low", "medium", "high"] = "low"
    allowed_task_types: list[str] = Field(default_factory=list)

    def to_prompt_dict(self) -> dict[str, Any]:
        """Compact, prompt-safe description (drops server-only metadata)."""

        return {
            "name": self.name,
            "description": self.description,
            "risk_level": self.risk_level,
            "requires_confirmation": self.requires_confirmation,
            "estimated_cost": self.estimated_cost,
            "input_schema": self.input_schema.model_dump(mode="json"),
        }


# ---------------------------------------------------------------------------
# Compact tool result (the only tool output shape that reaches the model).
# ---------------------------------------------------------------------------
class ToolEvidenceRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    evidence_id: str
    evidence_type: str = "diagnostic"


class ToolArtifactRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    artifact_kind: str
    path: str


class ToolErrorDetail(BaseModel):
    """Safe, structured error summary — never carries stacks or bodies."""

    model_config = ConfigDict(extra="forbid")

    error_code: str
    safe_message: str = Field(max_length=512)
    stage: str | None = None
    retryable: bool = False


class ToolCompactResult(BaseModel):
    """The unified, compact result sent back to the model after a tool runs.

    Never contains full report.json, raw hook logs, logcat, requests.jsonl,
    request/response bodies, full Manifest XML, or large exception stacks.
    """

    model_config = ConfigDict(extra="forbid")

    tool_name: str
    status: ToolResultStatus
    summary: str = Field(default="", max_length=1200)
    metrics: dict[str, Any] = Field(default_factory=dict)
    evidence_refs: list[ToolEvidenceRef] = Field(default_factory=list)
    artifact_refs: list[ToolArtifactRef] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    recommended_next_tools: list[str] = Field(default_factory=list)
    error: ToolErrorDetail | None = None
    reused: bool = False
    confirmation_required: bool = False
    decision_summary: str | None = Field(default=None, max_length=240)


# ---------------------------------------------------------------------------
# ai-plan-v1
# ---------------------------------------------------------------------------
PlanStrategy = Literal[
    "static_only", "dynamic_only", "full_analysis", "report_only"
]


class PlanStep(BaseModel):
    model_config = ConfigDict(extra="forbid")

    step_id: str
    tool_name: str
    reason: str = Field(max_length=120)
    arguments: dict[str, Any] = Field(default_factory=dict)
    depends_on: list[str] = Field(default_factory=list)
    requires_confirmation: bool = False


class AIPlan(BaseModel):
    """The validated ``ai-plan-v1`` execution plan."""

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["ai-plan-v1"] = AI_PLAN_SCHEMA_VERSION
    objective: str = Field(max_length=600)
    strategy: PlanStrategy
    steps: list[PlanStep] = Field(default_factory=list, max_length=6)
    expected_outputs: list[str] = Field(default_factory=list)
    stop_conditions: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    generated_by: Literal["ai", "default"] = "default"


# ---------------------------------------------------------------------------
# evidence-digest-v1  (deterministic, code-generated — never AI-generated).
# ---------------------------------------------------------------------------
class EvidenceDigestFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    finding_id: str
    rule_id: str
    title: str = Field(max_length=200)
    finding_type: str
    severity: Literal["high", "medium", "low", "info"] = "info"
    confidence: Literal["high", "medium", "low"] = "low"
    summary: str = Field(default="", max_length=360)
    evidence_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


class EvidenceDigestArtifactRef(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    artifact_kind: str
    path: str
    exists: bool = True


class EvidenceDigest(BaseModel):
    """Deterministic, code-built digest of the run's already-redacted evidence.

    The AI may only reference ``evidence_id`` values that appear here. Every
    free-text field is truncated and treated as data, never instructions.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["evidence-digest-v1"] = (
        EVIDENCE_DIGEST_SCHEMA_VERSION
    )
    task: dict[str, Any] = Field(default_factory=dict)
    environment: dict[str, Any] = Field(default_factory=dict)
    static_summary: dict[str, Any] = Field(default_factory=dict)
    dynamic_summary: dict[str, Any] = Field(default_factory=dict)
    network_summary: dict[str, Any] = Field(default_factory=dict)
    correlation_summary: dict[str, Any] = Field(default_factory=dict)
    privacy_findings_summary: dict[str, Any] = Field(default_factory=dict)
    top_findings: list[EvidenceDigestFinding] = Field(
        default_factory=list, max_length=10
    )
    evidence_gaps: list[str] = Field(default_factory=list)
    artifact_refs: list[EvidenceDigestArtifactRef] = Field(default_factory=list)
    digest_hash: str = Field(default="")

    @property
    def known_evidence_ids(self) -> frozenset[str]:
        ids: set[str] = set()
        for finding in self.top_findings:
            ids.add(finding.finding_id)
            ids.update(finding.evidence_refs)
        for section in (
            self.static_summary,
            self.dynamic_summary,
            self.network_summary,
            self.correlation_summary,
            self.privacy_findings_summary,
            self.environment,
        ):
            ids.update(_collect_evidence_ids(section))
        return frozenset(ids)


def _collect_evidence_ids(node: Any) -> set[str]:
    """Best-effort extraction of ``evidence_id`` values from digest sections."""

    found: set[str] = set()
    if isinstance(node, dict):
        for key, value in node.items():
            if key == "evidence_id" and isinstance(value, str) and value:
                found.add(value)
            else:
                found |= _collect_evidence_ids(value)
    elif isinstance(node, list):
        for item in node:
            found |= _collect_evidence_ids(item)
    return found


# ---------------------------------------------------------------------------
# ai-report-v1
# ---------------------------------------------------------------------------
AISynthesisStatus = Literal[
    "completed", "partial", "failed", "budget_exhausted", "disabled"
]


class AIKeyFinding(BaseModel):
    model_config = ConfigDict(extra="forbid")

    title: str = Field(max_length=200)
    severity: Literal["high", "medium", "low", "info"] = "info"
    confidence: Literal["high", "medium", "low"] = "low"
    summary: str = Field(default="", max_length=600)
    evidence_refs: list[str] = Field(default_factory=list)


class AIReport(BaseModel):
    """The AI synthesis report (``ai-report-v1``).

    Every ``evidence_refs`` value must exist in the evidence digest; the
    report composer validates this and strips / downgrades violations before
    the report is ever persisted or returned.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["ai-report-v1"] = AI_REPORT_SCHEMA_VERSION
    status: AISynthesisStatus = "partial"
    executive_summary: str = Field(default="", max_length=2400)
    key_findings: list[AIKeyFinding] = Field(
        default_factory=list, max_length=10
    )
    evidence_gaps: list[str] = Field(default_factory=list)
    risk_priorities: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    evidence_refs: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    disclaimer: str = ""
    usage: dict[str, Any] = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Token / call budget accounting.
# ---------------------------------------------------------------------------
# Where a token figure came from. ``provider`` is authoritative real tokens
# returned by the upstream API usage block; ``estimated`` is a local estimate
# (e.g. heuristic token count when the provider returned no usage); ``unavailable``
# means no usage could be determined at all. This lets the diagnostics surface
# distinguish real-vs-estimated token accounting.
TokenUsageSource = Literal["provider", "estimated", "unavailable"]

# Which orchestration stage a model round belonged to. Per-stage output-token
# caps and per-round provenance are tracked against this label.
AIRoundType = Literal["plan", "report", "repair"]

# Unified error classification produced by the provider retry/classify layer.
AIErrorCode = Literal[
    "ai_not_configured",
    "ai_provider_timeout",
    "ai_provider_unreachable",
    "ai_provider_authentication_failed",
    "ai_provider_model_not_found",
    "ai_provider_rate_limited",
    "ai_provider_error",
    "ai_provider_invalid_json",
    "ai_provider_invalid_response",
]


class AIPerRoundUsage(BaseModel):
    """Token accounting for a single model round.

    ``usage_source`` distinguishes real provider tokens from a local estimate.
    ``reasoning_content_present`` records *only* whether the model returned a
    reasoning_content field — never the content itself. No prompt text, no
    response text, no reasoning text is ever stored here.
    """

    model_config = ConfigDict(extra="forbid")

    round_index: int = 0
    round_type: AIRoundType
    usage_source: TokenUsageSource = "unavailable"
    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    latency_ms: int = 0
    finish_reason: str | None = None
    reasoning_content_present: bool = False
    retry_count: int = 0
    cache_hit: bool = False


class AITokenUsage(BaseModel):
    """Per-AI-task token accounting. Real usage when the provider returns it,
    otherwise an explicitly-marked estimate."""  # noqa: D200

    model_config = ConfigDict(extra="forbid")

    input_tokens: int = 0
    output_tokens: int = 0
    cached_tokens: int = 0
    estimated_tokens: int = 0
    tool_call_count: int = 0
    model_round_count: int = 0
    latency_ms: int = 0
    cache_hit: bool = False
    budget_exhausted: bool = False
    usage_is_estimate: bool = True
    # M6C — provenance & per-stage visibility.
    usage_source: TokenUsageSource = "unavailable"
    # Aggregate reasoning presence across rounds: True iff any round carried a
    # reasoning_content field. The content is never recorded.
    reasoning_content_present: bool = False
    # Total real-vs-estimated breakdown (subset of input/output_tokens that came
    # from the authoritative provider usage block). ``0`` when unavailable.
    real_tokens: int = 0
    estimated_total_tokens: int = 0
    # Per-round provenance, one entry per model round executed.
    rounds: list[AIPerRoundUsage] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# ai-runtime-diagnostics-v1  (observable runtime facts only; no secrets,
# no model text, no reasoning_content content, no full prompt/response).
# ---------------------------------------------------------------------------
class AIErrorObservation(BaseModel):
    """One classified error that occurred during a model call/retry.

    Flat error vocabulary shared with the provider layer. ``retry_count`` is the
    number of retries consumed for this call before the error was finalized
    (``0`` if the first attempt failed and was not retried). No error body,
    header, or URL is stored — only the classifier label and timing.
    """

    model_config = ConfigDict(extra="forbid")

    code: AIErrorCode
    retryable: bool = False
    attempt: int = 1
    retry_count: int = 0
    stage: AIRoundType | None = None
    http_status: int | None = None
    latency_ms: int = 0
    finalized: bool = True


class AIRuntimeDiagnostic(BaseModel):
    """The ``ai-runtime-diagnostics-v1`` artifact — observable runtime facts.

    Deliberately minimal and secret-free. Includes: per-round token provenance,
    aggregate usage, classified errors, retry/latency summaries, cache status,
    model identity, and the compatibility profile applied. Excludes by design:
    API key, Authorization, full prompt, full model response, reasoning_content
    text (only a presence bool per round), ai-secret.bin contents.
    """

    model_config = ConfigDict(extra="forbid")

    schema_version: Literal["ai-runtime-diagnostics-v1"] = (
        AI_RUNTIME_DIAGNOSTICS_SCHEMA_VERSION
    )
    task_id: str
    model: str = ""
    provider_profile: str = ""
    thinking_mode: str = ""
    enabled: bool = False
    # Aggregate usage (mirrors AITokenUsage totals).
    usage: AITokenUsage = Field(default_factory=AITokenUsage)
    # Per-round provenance.
    rounds: list[AIPerRoundUsage] = Field(default_factory=list)
    # Classified errors encountered (transient retries + finalized failures).
    errors: list[AIErrorObservation] = Field(default_factory=list)
    # Summary counters.
    total_rounds: int = 0
    total_retries: int = 0
    # Cache outcome for this run.
    cache_hit: bool = False
    cache_enabled: bool = False
    # Whether the run degraded to a deterministic fallback (no successful model
    # call synthesized the artifact).
    deterministic_fallback: bool = False
    # Highest severity reached. ``ok`` means a successful model call produced
    # the artifact; ``degraded`` means retries/estimates/imputed values were
    # needed; ``failed`` means no model artifact was produced.
    outcome: Literal["ok", "degraded", "failed", "disabled"] = "ok"
    generated_at: str = ""


# ---------------------------------------------------------------------------
# ai-tool-trace.json record (safe metadata only).
# ---------------------------------------------------------------------------
class AIToolTraceStep(BaseModel):
    """One executed tool's safe trace record. No API key, no full model
    request/response, no chain-of-thought, no raw sensitive identifiers."""

    model_config = ConfigDict(extra="forbid")

    step_id: str
    tool_name: str
    started_at: str | None = None
    ended_at: str | None = None
    status: ToolResultStatus = "not_run"
    safe_summary: str = Field(default="", max_length=600)
    artifact_refs: list[str] = Field(default_factory=list)
    reused: bool = False
    confirmation_required: bool = False
    decision_summary: str | None = Field(default=None, max_length=240)


class AIToolTrace(BaseModel):
    model_config = ConfigDict(extra="forbid")

    trace_id: str = Field(default_factory=lambda: str(uuid4()))
    steps: list[AIToolTraceStep] = Field(default_factory=list)
    model_round_count: int = 0
    cache_hit: bool = False
    budget_exhausted: bool = False
