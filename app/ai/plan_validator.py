"""Plan schema validator (Section 八 — ai-plan-validation-v2).

Validates a parsed plan dict against:
1. Schema version (surface-level, before Pydantic).
2. ``AIPlan`` shape via Pydantic v2.
3. Step count (6).
4. Per-step whitelist + argument schema.
5. Duplicate step IDs and duplicate tool signatures.
6. Dependency resolution + acyclicity.

Returns a ``PlanValidationResult``; never raises.
"""
from __future__ import annotations

import json
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Mapping

from pydantic import ValidationError

from .models import AIPlan, PlanStep as _PlanStep, PlanValidationIssue, ToolCandidate, ToolRiskLevel

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MAX_PLAN_STEPS: int = 6
AI_PLAN_SCHEMA_VERSION: str = "ai-plan-v1"

PLAN_CODE_INVALID_PLAN_SHAPE: str = "plan_invalid_shape"
PLAN_CODE_MISSING_SCHEMA_VERSION: str = "missing_schema_version"
PLAN_CODE_UNSUPPORTED_SCHEMA_VERSION: str = "unsupported_schema_version"
PLAN_CODE_MISSING_STEPS: str = "missing_steps"
PLAN_CODE_TOO_MANY_STEPS: str = "too_many_steps"
PLAN_CODE_DUPLICATE_STEP_ID: str = "duplicate_step_id"
PLAN_CODE_INVALID_TOOL_NAME: str = "invalid_tool_name"
PLAN_CODE_TOOL_NOT_ALLOWED_FOR_SCOPE: str = "tool_not_allowed_for_scope"
PLAN_CODE_DYNAMIC_TOOL_NOT_CONFIRMED: str = "dynamic_tool_not_confirmed"
PLAN_CODE_INVALID_ARGUMENTS: str = "invalid_arguments"
PLAN_CODE_DUPLICATE_TOOL_SIGNATURE: str = "duplicate_tool_signature"
PLAN_CODE_UNKNOWN_DEPENDENCY: str = "unknown_dependency"
PLAN_CODE_CIRCULAR_DEPENDENCY: str = "circular_dependency"

STAGE_SCHEMA = "schema"
STAGE_WHITELIST = "whitelist"
STAGE_ARGS = "args"
STAGE_DAG = "dag"

# ---------------------------------------------------------------------------
# Validation result type
# ---------------------------------------------------------------------------
@dataclass(slots=True)
class PlanValidationResult:
    plan: AIPlan | None
    issues: list[PlanValidationIssue]
    fatal_stage: str = STAGE_SCHEMA
    parse_code: str | None = None

    @property
    def ok(self) -> bool:
        return not self.issues

    @property
    def first_code(self) -> str | None:
        return self.issues[0].code if self.issues else None


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------
def validate_plan(
    payload: Mapping[str, Any],
    *,
    registry: Any,
    strategy: str,
    allow_dynamic: bool,
    confirmed_tools: frozenset[str] | set[str] = frozenset(),
) -> PlanValidationResult:
    """Validate a parsed plan dict against schema/whitelist/DAG layers.

    The ``confirmed_tools`` gate is enforced at *execution* time in the
    orchestrator, not here at validation time, preserving HEAD behavior.
    """
    if not isinstance(payload, Mapping):
        return PlanValidationResult(
            plan=None,
            issues=[PlanValidationIssue(code=PLAN_CODE_INVALID_PLAN_SHAPE, stage=STAGE_SCHEMA)],
        )

    issues: list[PlanValidationIssue] = []

    # Schema version (surface-level, before Pydantic)
    raw_sv = payload.get("schema_version")
    if raw_sv is None:
        issues.append(PlanValidationIssue(
            code=PLAN_CODE_MISSING_SCHEMA_VERSION, stage=STAGE_SCHEMA, json_path="/schema_version",
        ))
        return PlanValidationResult(plan=None, issues=issues)
    if raw_sv != AI_PLAN_SCHEMA_VERSION:
        issues.append(PlanValidationIssue(
            code=PLAN_CODE_UNSUPPORTED_SCHEMA_VERSION, stage=STAGE_SCHEMA, json_path="/schema_version",
            received_type=type(raw_sv).__name__,
        ))
        return PlanValidationResult(plan=None, issues=issues)

    # AIPlan shape via Pydantic
    try:
        plan = AIPlan.model_validate(dict(payload))
    except ValidationError as exc:
        detail = exc.errors()[0] if exc.errors() else {}
        issues.append(PlanValidationIssue(
            code=PLAN_CODE_INVALID_PLAN_SHAPE, stage=STAGE_SCHEMA,
            json_path=str(detail.get("loc", (""))),
            received_type=str(detail.get("type", "")),
        ))
        return PlanValidationResult(plan=None, issues=issues)

    # Empty steps
    if not plan.steps:
        issues.append(PlanValidationIssue(
            code=PLAN_CODE_MISSING_STEPS, stage=STAGE_SCHEMA, json_path="/steps",
        ))
        return PlanValidationResult(plan=None, issues=issues)

    # Too many steps
    if len(plan.steps) > MAX_PLAN_STEPS:
        issues.append(PlanValidationIssue(
            code=PLAN_CODE_TOO_MANY_STEPS, stage=STAGE_DAG, json_path="/steps",
            received_type=str(len(plan.steps)),
        ))
        return PlanValidationResult(plan=None, issues=issues)

    # Per-step checks
    seen_ids: set[str] = set()
    seen_signatures: set[tuple[str, str]] = set()

    for index, step in enumerate(plan.steps):
        path = f"/steps/{index}"

        # Duplicate step ID
        if step.step_id in seen_ids:
            issues.append(PlanValidationIssue(
                code=PLAN_CODE_DUPLICATE_STEP_ID, stage=STAGE_DAG,
                json_path=f"{path}/step_id", tool_name=step.step_id,
            ))
            return PlanValidationResult(plan=None, issues=issues)
        seen_ids.add(step.step_id)

        # Tool whitelist
        if not registry.has(step.tool_name):
            issues.append(PlanValidationIssue(
                code=PLAN_CODE_INVALID_TOOL_NAME, stage=STAGE_WHITELIST,
                json_path=f"{path}/tool_name", tool_name=step.tool_name,
            ))
            return PlanValidationResult(plan=None, issues=issues)

        candidate = registry.get(step.tool_name)

        # Scope: tool must be allowed for the requested strategy
        if strategy not in candidate.allowed_task_types:
            issues.append(PlanValidationIssue(
                code=PLAN_CODE_TOOL_NOT_ALLOWED_FOR_SCOPE, stage=STAGE_WHITELIST,
                json_path=f"{path}/tool_name", tool_name=step.tool_name, expected=strategy,
            ))
            return PlanValidationResult(plan=None, issues=issues)

        # Device-touching: must have allow_dynamic=true
        # (confirmed_tools checked at execution time in orchestrator)
        if candidate.risk_level == "device_state_change" and not allow_dynamic:
            issues.append(PlanValidationIssue(
                code=PLAN_CODE_DYNAMIC_TOOL_NOT_CONFIRMED, stage=STAGE_WHITELIST,
                json_path=f"{path}/tool_name", tool_name=step.tool_name, expected="allow_dynamic=true",
            ))
            return PlanValidationResult(plan=None, issues=issues)

        # Argument schema (the tool's own Pydantic model)
        try:
            registry.validate_arguments(step.tool_name, step.arguments)
        except Exception as exc:
            issues.append(PlanValidationIssue(
                code=PLAN_CODE_INVALID_ARGUMENTS, stage=STAGE_ARGS,
                json_path=f"{path}/arguments", tool_name=step.tool_name, expected=str(exc),
            ))
            return PlanValidationResult(plan=None, issues=issues)

        # Duplicate signature (same tool + identical args)
        signature = (step.tool_name, json.dumps(step.arguments, sort_keys=True, ensure_ascii=False))
        if signature in seen_signatures:
            issues.append(PlanValidationIssue(
                code=PLAN_CODE_DUPLICATE_TOOL_SIGNATURE, stage=STAGE_DAG,
                json_path=path, tool_name=step.tool_name,
            ))
            return PlanValidationResult(plan=None, issues=issues)
        seen_signatures.add(signature)

    # Dependency resolution + acyclicity
    for index, step in enumerate(plan.steps):
        for dep in step.depends_on:
            if dep not in seen_ids:
                issues.append(PlanValidationIssue(
                    code=PLAN_CODE_UNKNOWN_DEPENDENCY, stage=STAGE_DAG,
                    json_path=f"/steps/{index}/depends_on", tool_name=dep,
                ))
                return PlanValidationResult(plan=None, issues=issues)

    if _find_cycle(plan.steps) is not None:
        issues.append(PlanValidationIssue(
            code=PLAN_CODE_CIRCULAR_DEPENDENCY, stage=STAGE_DAG, json_path="/steps",
        ))
        return PlanValidationResult(plan=None, issues=issues)

    return PlanValidationResult(plan=plan, issues=[])


# ---------------------------------------------------------------------------
# Cycle detection (Kahn's algorithm - O(V+E))
# ---------------------------------------------------------------------------
def _find_cycle(steps: list[PlanStep]) -> str | None:
    """Return a step_id in a cycle, or None when acyclic."""
    id_set = {s.step_id for s in steps}
    in_degree: dict[str, int] = defaultdict(int)
    children: dict[str, list[str]] = defaultdict(list)
    for s in steps:
        for d in s.depends_on:
            if d in id_set:
                in_degree[d] += 1
                children[s.step_id].append(d)
    queue: list[str] = [sid for sid in id_set if in_degree[sid] == 0]
    visited = 0
    while queue:
        node = queue.pop()
        visited += 1
        for child in children[node]:
            in_degree[child] -= 1
            if in_degree[child] == 0:
                queue.append(child)
    return None if visited == len(id_set) else next(iter(id_set))


__all__ = [
    "MAX_PLAN_STEPS", "AI_PLAN_SCHEMA_VERSION",
    "PLAN_CODE_INVALID_PLAN_SHAPE", "PLAN_CODE_MISSING_SCHEMA_VERSION",
    "PLAN_CODE_UNSUPPORTED_SCHEMA_VERSION", "PLAN_CODE_MISSING_STEPS",
    "PLAN_CODE_TOO_MANY_STEPS", "PLAN_CODE_DUPLICATE_STEP_ID",
    "PLAN_CODE_INVALID_TOOL_NAME", "PLAN_CODE_TOOL_NOT_ALLOWED_FOR_SCOPE",
    "PLAN_CODE_DYNAMIC_TOOL_NOT_CONFIRMED", "PLAN_CODE_INVALID_ARGUMENTS",
    "PLAN_CODE_DUPLICATE_TOOL_SIGNATURE", "PLAN_CODE_UNKNOWN_DEPENDENCY",
    "PLAN_CODE_CIRCULAR_DEPENDENCY",
    "PlanValidationIssue", "PlanValidationResult",
    "validate_plan", "_find_cycle",
]
