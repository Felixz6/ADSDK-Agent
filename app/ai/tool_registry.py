"""Whitelisted tool registry for the M6A AI orchestrator.

The model may only ever return a *registered tool name* plus structured
arguments. It can never return Shell commands, Python code, filesystem paths,
SQL, or raw adb / frida / mitmproxy invocations — those surfaces are not
expressible in any tool schema here, and unknown names are rejected before
execution.

Every tool is an adapter over an existing deterministic implementation or over
artifacts that implementation already wrote. No analysis logic is duplicated
in this module.

Risk levels:

* ``read_only``            — safe to run automatically (probes, artifact reads).
* ``analysis``             — safe when the user already submitted a matching
                             task configuration (static / dynamic analysis).
* ``device_state_change``  — always requires explicit confirmation; without it
                             the tool reports ``blocked_confirmation_required``
                             and is never executed.
"""

from __future__ import annotations

from typing import Any, Callable, Mapping

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from .models import (
    ToolCandidate,
    ToolInputSchema,
    ToolRiskLevel,
)

# ---------------------------------------------------------------------------
# Per-tool argument models. Pydantic validates every model-produced argument
# set; extra fields are forbidden so an injected argument cannot smuggle a
# path, command, or flag into an implementation.
# ---------------------------------------------------------------------------


class _NoArguments(BaseModel):
    model_config = ConfigDict(extra="forbid")


class EnvironmentCheckArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # Deliberately no free-form device path: only an opaque reference the
    # orchestrator maps back to the task's own configured device.
    use_task_device: bool = True


class StaticAnalysisArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # The APK is always the task's own validated APK. The model cannot supply
    # an arbitrary path — only ask for a re-run of the existing input.
    force_rerun: bool = False


class DynamicAnalysisArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    force_rerun: bool = False


class TrafficAnalysisArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    force_rerun: bool = False


class EvidenceCorrelationArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    force_rerun: bool = False


class PrivacyFindingsArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    force_rerun: bool = False


class DeterministicReportArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    force_rerun: bool = False


class TaskStatusArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ArtifactSummaryArgs(BaseModel):
    model_config = ConfigDict(extra="forbid")

    # A closed enum, not a path: the model can only name artifact kinds the
    # registry already knows how to summarise.
    artifact_kind: str = Field(default="report_json", max_length=64)


_ARGUMENT_MODELS: dict[str, type[BaseModel]] = {
    "environment_check": EnvironmentCheckArgs,
    "static_analysis": StaticAnalysisArgs,
    "dynamic_analysis": DynamicAnalysisArgs,
    "traffic_analysis": TrafficAnalysisArgs,
    "evidence_correlation": EvidenceCorrelationArgs,
    "privacy_findings": PrivacyFindingsArgs,
    "deterministic_report": DeterministicReportArgs,
    "task_status": TaskStatusArgs,
    "artifact_summary": ArtifactSummaryArgs,
}

ALLOWED_ARTIFACT_KINDS: frozenset[str] = frozenset(
    {
        "report_json",
        "correlations",
        "privacy_findings",
        "traffic_summary",
        "events",
    }
)


def _schema(
    properties: dict[str, dict[str, Any]] | None = None,
    required: list[str] | None = None,
) -> ToolInputSchema:
    return ToolInputSchema(
        properties=properties or {},
        required=required or [],
    )


_FORCE_RERUN_PROPERTY = {
    "force_rerun": {
        "type": "boolean",
        "description": (
            "Re-run even when a valid artifact already exists. Default false; "
            "existing valid artifacts are reused."
        ),
    }
}


# ---------------------------------------------------------------------------
# The registry itself.
# ---------------------------------------------------------------------------
_REGISTRY: dict[str, ToolCandidate] = {
    "environment_check": ToolCandidate(
        name="environment_check",
        description=(
            "Read-only local environment probe (adb / apktool / frida / "
            "mitmproxy availability and output writability). Does not modify "
            "the device."
        ),
        input_schema=_schema(
            {
                "use_task_device": {
                    "type": "boolean",
                    "description": "Probe against the task's configured device.",
                }
            }
        ),
        risk_level="read_only",
        requires_confirmation=False,
        estimated_cost="low",
        allowed_task_types=["static_only", "dynamic_only", "full_analysis"],
    ),
    "static_analysis": ToolCandidate(
        name="static_analysis",
        description=(
            "Run the existing deterministic static pipeline on the task's own "
            "APK (unpack, Manifest/permission parse, SDK fingerprinting) and "
            "return a compact summary."
        ),
        input_schema=_schema(_FORCE_RERUN_PROPERTY),
        risk_level="analysis",
        requires_confirmation=False,
        estimated_cost="medium",
        allowed_task_types=["static_only", "dynamic_only", "full_analysis"],
    ),
    "dynamic_analysis": ToolCandidate(
        name="dynamic_analysis",
        description=(
            "Run the existing deterministic dynamic pipeline (Frida-based "
            "behaviour collection across the Consent boundary) on the task's "
            "configured device. Changes device state and requires explicit "
            "user confirmation."
        ),
        input_schema=_schema(_FORCE_RERUN_PROPERTY),
        risk_level="device_state_change",
        requires_confirmation=True,
        estimated_cost="high",
        allowed_task_types=["dynamic_only", "full_analysis"],
    ),
    "traffic_analysis": ToolCandidate(
        name="traffic_analysis",
        description=(
            "Summarise the network observations already collected for this "
            "run (host counts, coverage, collector outcome). Never returns "
            "request or response bodies."
        ),
        input_schema=_schema(_FORCE_RERUN_PROPERTY),
        risk_level="analysis",
        requires_confirmation=False,
        estimated_cost="low",
        allowed_task_types=["dynamic_only", "full_analysis"],
    ),
    "evidence_correlation": ToolCandidate(
        name="evidence_correlation",
        description=(
            "Read the deterministic correlation-v1 result linking dynamic "
            "events to network requests within the configured time window."
        ),
        input_schema=_schema(_FORCE_RERUN_PROPERTY),
        risk_level="analysis",
        requires_confirmation=False,
        estimated_cost="low",
        allowed_task_types=["dynamic_only", "full_analysis"],
    ),
    "privacy_findings": ToolCandidate(
        name="privacy_findings",
        description=(
            "Read the deterministic privacy-findings-v2 rule results. These "
            "are technical risk prompts, never legal compliance conclusions."
        ),
        input_schema=_schema(_FORCE_RERUN_PROPERTY),
        risk_level="analysis",
        requires_confirmation=False,
        estimated_cost="low",
        allowed_task_types=[
            "static_only",
            "dynamic_only",
            "full_analysis",
            "report_only",
        ],
    ),
    "deterministic_report": ToolCandidate(
        name="deterministic_report",
        description=(
            "Confirm the deterministic JSON / Markdown / HTML report artifacts "
            "for this run and return their reference paths."
        ),
        input_schema=_schema(_FORCE_RERUN_PROPERTY),
        risk_level="analysis",
        requires_confirmation=False,
        estimated_cost="low",
        allowed_task_types=[
            "static_only",
            "dynamic_only",
            "full_analysis",
            "report_only",
        ],
    ),
    "task_status": ToolCandidate(
        name="task_status",
        description=(
            "Return the current task's own status, configuration flags, and "
            "which artifacts already exist."
        ),
        input_schema=_schema(),
        risk_level="read_only",
        requires_confirmation=False,
        estimated_cost="low",
        allowed_task_types=[
            "static_only",
            "dynamic_only",
            "full_analysis",
            "report_only",
        ],
    ),
    "artifact_summary": ToolCandidate(
        name="artifact_summary",
        description=(
            "Return a compact summary of one named artifact kind for this run. "
            "Accepts only known artifact kinds, never a filesystem path."
        ),
        input_schema=_schema(
            {
                "artifact_kind": {
                    "type": "string",
                    "enum": sorted(ALLOWED_ARTIFACT_KINDS),
                    "description": "Which known artifact to summarise.",
                }
            }
        ),
        risk_level="read_only",
        requires_confirmation=False,
        estimated_cost="low",
        allowed_task_types=[
            "static_only",
            "dynamic_only",
            "full_analysis",
            "report_only",
        ],
    ),
}


class UnknownToolError(ValueError):
    """Raised when the model names a tool that is not registered."""

    def __init__(self, tool_name: str) -> None:
        super().__init__(f"unknown tool: {tool_name}")
        self.tool_name = tool_name
        self.code = "ai_unknown_tool"


class InvalidToolArgumentsError(ValueError):
    """Raised when model-supplied arguments fail their Pydantic schema."""

    def __init__(self, tool_name: str, detail: str) -> None:
        super().__init__(f"invalid arguments for {tool_name}: {detail}")
        self.tool_name = tool_name
        self.detail = detail
        self.code = "ai_invalid_tool_arguments"


class AIToolRegistry:
    """Whitelist of tools the orchestrator may execute."""

    def __init__(
        self,
        *,
        allow_dynamic_tools: bool = False,
        registry: Mapping[str, ToolCandidate] | None = None,
    ) -> None:
        self._registry = dict(registry or _REGISTRY)
        self._allow_dynamic_tools = allow_dynamic_tools

    # -- lookup ---------------------------------------------------------
    def has(self, tool_name: str) -> bool:
        return tool_name in self._registry

    def get(self, tool_name: str) -> ToolCandidate:
        try:
            return self._registry[tool_name]
        except KeyError as exc:
            raise UnknownToolError(tool_name) from exc

    def names(self) -> list[str]:
        return sorted(self._registry)

    # -- validation -----------------------------------------------------
    def validate_arguments(
        self,
        tool_name: str,
        arguments: Mapping[str, Any] | None,
    ) -> dict[str, Any]:
        """Validate model-supplied arguments against the tool's schema."""

        self.get(tool_name)  # raises UnknownToolError for unregistered names
        model = _ARGUMENT_MODELS.get(tool_name, _NoArguments)
        try:
            validated = model.model_validate(dict(arguments or {}))
        except ValidationError as exc:
            raise InvalidToolArgumentsError(
                tool_name,
                _first_validation_message(exc),
            ) from exc
        payload = validated.model_dump(mode="json")
        if tool_name == "artifact_summary":
            kind = str(payload.get("artifact_kind") or "")
            if kind not in ALLOWED_ARTIFACT_KINDS:
                raise InvalidToolArgumentsError(
                    tool_name,
                    "artifact_kind must be a known artifact kind",
                )
        return payload

    def requires_confirmation(self, tool_name: str) -> bool:
        candidate = self.get(tool_name)
        return (
            candidate.requires_confirmation
            or candidate.risk_level == "device_state_change"
        )

    def risk_level(self, tool_name: str) -> ToolRiskLevel:
        return self.get(tool_name).risk_level

    # -- candidate routing ---------------------------------------------
    def candidates_for(
        self,
        strategy: str,
        *,
        max_candidates: int = 6,
        allow_dynamic: bool | None = None,
    ) -> list[ToolCandidate]:
        """Deterministic capability router.

        Only the tools relevant to *strategy* are ever offered to the model,
        so a single call never carries the full catalogue. Dynamic /
        device-touching tools are withheld unless dynamic execution is both
        configured and permitted for this task.
        """

        dynamic_allowed = (
            self._allow_dynamic_tools if allow_dynamic is None else allow_dynamic
        )
        ordered = _STRATEGY_TOOLS.get(strategy, _STRATEGY_TOOLS["static_only"])
        selected: list[ToolCandidate] = []
        for name in ordered:
            candidate = self._registry.get(name)
            if candidate is None:
                continue
            if (
                candidate.risk_level == "device_state_change"
                and not dynamic_allowed
            ):
                continue
            selected.append(candidate)
            if len(selected) >= max_candidates:
                break
        return selected

    def prompt_catalogue(
        self,
        strategy: str,
        *,
        max_candidates: int = 6,
        allow_dynamic: bool | None = None,
    ) -> list[dict[str, Any]]:
        return [
            candidate.to_prompt_dict()
            for candidate in self.candidates_for(
                strategy,
                max_candidates=max_candidates,
                allow_dynamic=allow_dynamic,
            )
        ]

    def catalogue_digest(
        self,
        strategy: str,
        *,
        max_candidates: int = 6,
        allow_dynamic: bool | None = None,
    ) -> str:
        """Stable digest of the offered catalogue (part of the cache key)."""

        import hashlib
        import json

        payload = json.dumps(
            self.prompt_catalogue(
                strategy,
                max_candidates=max_candidates,
                allow_dynamic=allow_dynamic,
            ),
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:32]


def _first_validation_message(exc: ValidationError) -> str:
    errors = exc.errors()
    if not errors:
        return "invalid arguments"
    first = errors[0]
    location = ".".join(str(part) for part in first.get("loc", ()))
    message = str(first.get("msg", "invalid"))
    return f"{location}: {message}" if location else message


# Deterministic candidate ordering per strategy (capability router).
_STRATEGY_TOOLS: dict[str, tuple[str, ...]] = {
    "static_only": (
        "environment_check",
        "static_analysis",
        "privacy_findings",
        "deterministic_report",
    ),
    "dynamic_only": (
        "environment_check",
        "dynamic_analysis",
        "traffic_analysis",
        "evidence_correlation",
        "privacy_findings",
        "deterministic_report",
    ),
    "full_analysis": (
        "environment_check",
        "static_analysis",
        "dynamic_analysis",
        "traffic_analysis",
        "evidence_correlation",
        "privacy_findings",
        "deterministic_report",
    ),
    "report_only": (
        "task_status",
        "artifact_summary",
        "privacy_findings",
        "deterministic_report",
    ),
}

# Deterministic default plans (code-generated; never authored by the model).
DEFAULT_PLAN_STEPS: dict[str, tuple[str, ...]] = {
    "static_only": (
        "environment_check",
        "static_analysis",
        "privacy_findings",
        "deterministic_report",
    ),
    "dynamic_only": (
        "environment_check",
        "dynamic_analysis",
        "traffic_analysis",
        "evidence_correlation",
        "privacy_findings",
        "deterministic_report",
    ),
    "full_analysis": (
        "environment_check",
        "static_analysis",
        "dynamic_analysis",
        "traffic_analysis",
        "evidence_correlation",
        "privacy_findings",
        "deterministic_report",
    ),
    "report_only": (
        "task_status",
        "privacy_findings",
        "deterministic_report",
    ),
}

# Priority order used when a plan exceeds the tool-call budget.
TOOL_PRIORITY: tuple[str, ...] = (
    "environment_check",
    "static_analysis",
    "dynamic_analysis",
    "privacy_findings",
    "evidence_correlation",
    "deterministic_report",
)


def prioritize_steps(tool_names: list[str], limit: int) -> list[str]:
    """Trim a step list to *limit* entries using the fixed priority order."""

    if limit <= 0:
        return []
    if len(tool_names) <= limit:
        return list(tool_names)
    ranked = sorted(
        range(len(tool_names)),
        key=lambda index: (
            TOOL_PRIORITY.index(tool_names[index])
            if tool_names[index] in TOOL_PRIORITY
            else len(TOOL_PRIORITY),
            index,
        ),
    )
    keep = sorted(ranked[:limit])
    return [tool_names[index] for index in keep]


__all__ = [
    "ALLOWED_ARTIFACT_KINDS",
    "AIToolRegistry",
    "DEFAULT_PLAN_STEPS",
    "InvalidToolArgumentsError",
    "TOOL_PRIORITY",
    "UnknownToolError",
    "prioritize_steps",
]
