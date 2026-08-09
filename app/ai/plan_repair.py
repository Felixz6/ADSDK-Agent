"""Structured single-repair for a rejected AI plan (Section 十, ai-plan-v1).

A failed plan earns *one* repair attempt — never two, never a loop — and the
repair prompt is built from a **safe summary** only:

* the original plan's shape (step_ids / tool_names / counts) — never the
  objective verbatim if it is long, never argument *values*;
* the **single** stable validation code + bounded location that explains why
  the plan was rejected (from :mod:`app.ai.plan_validator`);
* the allowed tool names and the correct field structure;
* the fixed DAG / step budget;
* the residual model/token budget so the repair does not chase a plan that
  can no longer run.

It deliberately does **not** re-send the full planning prompt, the full model
response, any ``reasoning_content``, any tool result, or any log line. The
repair round returns a full corrected ``ai-plan-v1`` object; the caller then
re-validates it through the same schema/whitelist/DAG layers and records
``plan_source="repaired"`` when it passes, or falls back to the deterministic
plan when it does not.

This module owns no I/O and no provider: it only builds the repair contract
string and reports whether one more repair is permitted under the call budget.
The model call itself stays in the orchestrator so token accounting and the
``AI_MAX_ROUNDS`` cap remain in one place.
"""

from __future__ import annotations

from typing import Any, Mapping

from .models import AI_PLAN_SCHEMA_VERSION, AIPlan, PlanStep
from .plan_validator import (
    PlanValidationResult,
    STAGE_DAG,
    STAGE_SCHEMA,
    STAGE_WHITELIST,
    validate_plan,
)
from .tool_registry import AIToolRegistry

# A repaired plan is allowed at most one extra model round over the initial
# plan round. We expose the cap here so callers can decide to skip the repair
# when the residual round budget is already zero instead of inside this module
# (the orchestrator owns the actual round counter).
MAX_PLAN_REPAIRS: int = 1

# Bounded summaries of the rejected plan. Anything above these caps is
# truncated so a pathological plan (very long objective / many steps) cannot
# balloon the repair prompt.
_MAX_SUMMARY_OBJECTIVE_CHARS = 120
_MAX_SUMMARY_STEPS = 6


def build_plan_repair_contract(
    *,
    registry: AIToolRegistry,
    strategy: str,
    allow_dynamic: bool,
    confirmed_tools: frozenset[str] | set[str],
    rejected_plan: Mapping[str, Any] | None,
    validation: PlanValidationResult,
    max_steps: int,
    budget_rounds_remaining: int,
) -> str | None:
    """Build the repair prompt from a safe summary, or ``None`` if no repair
    is available.

    Returns ``None`` when ``budget_rounds_remaining`` is not positive (no model
    round left to spend) so the orchestrator can fall straight to the
    deterministic plan without assembling dead text.

    ``rejected_plan`` is the parsed-but-invalid dict; only its *shape* is
    summarized. ``validation`` carries the stable code + bounded location that
    the repair must address.
    """

    if budget_rounds_remaining <= 0:
        return None

    allowed = sorted(registry.names())
    allowed_line = ", ".join(allowed)

    saw_dynamic = _plan_references_dynamic(rejected_plan, registry)
    schema_line = _correct_field_structure(allow_dynamic=allow_dynamic)

    issue = validation.issues[0] if validation.issues else None
    if issue is not None:
        where = issue.json_path or "/"
        code = issue.code
        stage = issue.stage
        hint = (
            f"stage={stage} code={code} at={where}"
            + (f" expected={issue.expected}" if issue.expected else "")
            + (f" got={issue.received_type}" if issue.received_type else "")
        )
    else:
        hint = f"parse_code={validation.parse_code or 'unknown'}"

    plan_summary = _summarize_rejected_plan(rejected_plan)

    scope_note = _scope_note(strategy, allow_dynamic, confirmed_tools, saw_dynamic)

    return (
        "__ai_phase__:repair_plan\n"
        "The previous ai-plan-v1 object failed structured validation.\n"
        "Return a NEW, complete JSON object conforming to ai-plan-v1. Do not "
        "repeat the failure; address the single issue below.\n"
        f"Schema: {AI_PLAN_SCHEMA_VERSION}\n"
        f"Stable failure: {hint}\n"
        f"Strategy (fixed): {strategy}\n"
        f"allow_dynamic={allow_dynamic}; confirmed_tools={sorted(confirmed_tools)}\n"
        f"{scope_note}"
        "Top-level keys (exact, no others): schema_version, objective, "
        "strategy, steps, expected_outputs, stop_conditions, limitations.\n"
        f"{schema_line}"
        f"Maximum steps: {max_steps}\n"
        "Rules: only tool_name values from the allowed list; no shell, adb, "
        "frida, or mitmproxy commands; no filesystem paths; each reason <= 120 "
        "characters; depends_on references earlier step_ids only; no circular "
        "dependencies; no meaningless repeated tool calls.\n"
        f"Allowed tool names: {allowed_line}\n"
        f"Rejected plan shape (summary only, no argument values): {plan_summary}\n"
        "Return only the JSON object. No prose, no code fences, no reasoning."
    )


def _summarize_rejected_plan(plan: Mapping[str, Any] | None) -> str:
    """Reduce a rejected plan to a shape-only summary.

    Records the step count, the ordered ``step_id`` / ``tool_name`` pairs, and
    a bounded objective fragment. Argument values are deliberately omitted so
    the repair prompt never echoes them.
    """

    if not isinstance(plan, Mapping):
        return "<no parsed object>"
    parts: list[str] = []
    objective = plan.get("objective")
    if isinstance(objective, str) and objective:
        parts.append(f"objective~{objective[:_MAX_SUMMARY_OBJECTIVE_CHARS]!r}")
    steps = plan.get("steps")
    if isinstance(steps, list):
        shown = steps[:_MAX_SUMMARY_STEPS]
        step_pairs = []
        for entry in shown:
            if isinstance(entry, Mapping):
                sid = entry.get("step_id")
                tool = entry.get("tool_name")
                if isinstance(sid, str) and isinstance(tool, str):
                    step_pairs.append(f"{sid}:{tool}")
        parts.append(f"steps={len(steps)} [{', '.join(step_pairs)}]")
    sv = plan.get("schema_version")
    if sv is not None:
        parts.append(f"schema_version={sv!r}")
    return " | ".join(parts) if parts else "<empty>"


def _plan_references_dynamic(
    plan: Mapping[str, Any] | None, registry: AIToolRegistry
) -> bool:
    """Whether the rejected plan already named a device-touching tool."""

    if not isinstance(plan, Mapping):
        return False
    steps = plan.get("steps")
    if not isinstance(steps, list):
        return False
    for entry in steps:
        if isinstance(entry, Mapping):
            tool = entry.get("tool_name")
            if isinstance(tool, str) and registry.has(tool):
                if registry.risk_level(tool) == "device_state_change":
                    return True
    return False


def _scope_note(
    strategy: str,
    allow_dynamic: bool,
    confirmed_tools: frozenset[str] | set[str],
    saw_dynamic: bool,
) -> str:
    if not allow_dynamic:
        if saw_dynamic:
            return (
                "Note: device-state-changing tools are NOT permitted for this "
                "task (allow_dynamic=false). Drop them and use read-only / "
                "analysis tools only.\n"
            )
        return ""
    if not confirmed_tools:
        return (
            "Note: no device-state tool has user confirmation, so none may be "
            "planned.\n"
        )
    return ""


def _correct_field_structure(*, allow_dynamic: bool) -> str:
    return (
        "Each step is an object with keys: step_id (string), tool_name "
        "(one of the allowed names), reason (string <= 120 chars), arguments "
        "(object; only fields the named tool accepts), depends_on (array of "
        "earlier step_ids), requires_confirmation (boolean; set true only for "
        "device-state tools that are both allow_dynamic AND in "
        "confirmed_tools).\n"
    )


def attempt_repair(
    *,
    registry: AIToolRegistry,
    strategy: str,
    allow_dynamic: bool,
    confirmed_tools: frozenset[str] | set[str],
    rejected_payload: Mapping[str, Any] | None,
    previous_validation: PlanValidationResult,
    max_steps: int,
    budget_rounds_remaining: int,
) -> str | None:
    """Thin facade so callers express intent: build the repair contract or
    signal "no repair available". Kept separate from
    :func:`build_plan_repair_contract` so the orchestrator can log the
    ``repair_attempted`` / ``repair_succeeded`` flags around it without the
    prompt builder knowing about diagnostics."""

    return build_plan_repair_contract(
        registry=registry,
        strategy=strategy,
        allow_dynamic=allow_dynamic,
        confirmed_tools=confirmed_tools,
        rejected_plan=rejected_payload,
        validation=previous_validation,
        max_steps=max_steps,
        budget_rounds_remaining=budget_rounds_remaining,
    )


def revalidate_repaired(
    payload: Mapping[str, Any],
    *,
    registry: AIToolRegistry,
    strategy: str,
    allow_dynamic: bool,
    confirmed_tools: frozenset[str] | set[str],
) -> PlanValidationResult:
    """Re-run the schema/whitelist/DAG layers on the repaired payload.

    The repair round's output must pass the *same* validation as the initial
    plan — never trusted outright. Returns the :class:`PlanValidationResult`
    so the caller can record the round and decide ``plan_source``."""

    return validate_plan(
        payload,
        registry=registry,
        strategy=strategy,
        allow_dynamic=allow_dynamic,
        confirmed_tools=confirmed_tools,
    )


def repaired_plan_from(validation: PlanValidationResult) -> AIPlan | None:
    """Return the validated repaired plan, or ``None`` when the repair still
    fails so the orchestrator falls back deterministically."""

    if validation.ok and validation.plan is not None:
        return validation.plan.model_copy(update={"generated_by": "ai"})
    return None


__all__ = [
    "MAX_PLAN_REPAIRS",
    "attempt_repair",
    "build_plan_repair_contract",
    "repaired_plan_from",
    "revalidate_repaired",
]
