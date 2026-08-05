"""Deterministic dynamic-strategy normalization (Section 十二).

The AI picks a *requested* strategy (one of the four ``AIStrategyValue``
literals) and the request carries the operator's flags —
``allow_dynamic``, ``allow_network``, ``confirmed_tools``, and the MuMu-aware
``dynamic_mode_policy`` (``strict`` / ``balanced`` / ``attach_only``). None of
those four flags is the AI's to invent. This module is the **deterministic
owner of the effective strategy**: it applies Rules A–F and returns a
:class:`DynamicStrategyDecision` recording both the requested and effective
values so the orchestrator can persist ``requested_strategy`` untouched and
record ``effective_strategy`` next to it.

Why deterministic ownership matters
-----------------------------------
The M7A run that motivated this layer ended up with ``plan_source=ai`` but
``attach_only`` executing against a process that was never running — the model
"chose" a strategy the operator's flags did not actually permit. Folding the
clamp into a single, testable function means the AI's narration can describe
the requested strategy while the *execution* path is gated by the effective
one, and the runtime validator (:mod:`app.orchestration.runtime_plan_validator`)
reasons over the *effective* strategy, never the requested one.

Rules (Section 十二, applied in order; first match wins)
-------------------------------------------------------
* **A — unknown requested strategy**: the requested value is not one of the
  four strategy literals. Effective becomes ``static_only``;
  ``normalized=False``; ``reason_code='unknown_requested_strategy'``.
* **B — read-only requested strategy** (``static_only`` / ``report_only``):
  never permits device-state tools. Effective equals requested *unless* the
  plan already named a device-state tool (e.g. the model slipped one in);
  then the plan is incompatible and effective is clamped to a read-only
  strategy with ``reason_code='plan_device_tool_in_readonly_strategy'``.
* **C — dynamic requested but ``allow_dynamic=False``**: the operator did not
  authorise device-state changes. Effective downgrades to ``static_only``;
  ``normalized=True``; ``reason_code='dynamic_not_allowed'``.
* **D — dynamic allowed but not confirmed**: ``allow_dynamic=True`` yet no
  device-state tool is in ``confirmed_tools``. Effective downgrades to
  ``static_only``; ``reason_code='dynamic_not_confirmed'``.
* **E — ``attach_only`` policy against a non-running target**: an attach-only
  run cannot launch the app, so a not-running target means the dynamic leg is
  impossible. Effective downgrades to ``static_only``;
  ``reason_code='attach_only_no_target'``; ``application_launch_allowed=False``.
  With the target already running under attach_only, launching stays
  forbidden too (``application_launch_allowed=False``) but the dynamic leg is
  kept.
* **F — network capture disabled under a dynamic plan**: ``allow_network=False``
  strips the ``traffic_analysis`` leg from the effective DAG but keeps the
  dynamic leg; ``reason_code='network_capture_disabled'``. If the *only*
  reason the plan was dynamic was traffic, effective downgrades to
  ``static_only``; ``reason_code='network_capture_disabled'``.

The function never raises and never re-probes the device: ``target_running``
is an observable the preflight already captured. ``requested_strategy`` is
copied into the result verbatim and never mutated.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Mapping

# Source-of-truth literal set, kept here so this module can be reasoned about
# without importing the Pydantic model chain (Phase A tests build plain dicts).
_VALID_REQUESTED_STRATEGIES: frozenset[str] = frozenset(
    {"static_only", "dynamic_only", "full_analysis", "report_only"}
)

_DEVICE_STATE_TOOL = "dynamic_analysis"
_TRAFFIC_TOOL = "traffic_analysis"

# strategy-pair tuples that still count as "got the dynamic leg".
_DYNAMIC_STRATEGIES: frozenset[str] = frozenset({"dynamic_only", "full_analysis"})
_READONLY_STRATEGIES: frozenset[str] = frozenset({"static_only", "report_only"})


@dataclass(slots=True)
class DynamicStrategyDecision:
    """The deterministic outcome of request→effective normalization.

    ``requested_strategy`` is the value the operator/model asked for, copied
    verbatim. ``effective_strategy`` is the value the execution path will use.
    All other fields are stable, secret-free facts the diagnostics artifact
    and the runtime validator consume.
    """

    requested_strategy: str
    effective_strategy: str
    normalized: bool
    reason_code: str | None
    target_running: bool
    application_launch_allowed: bool

    def as_diagnostics(self) -> dict[str, object]:
        """Secret-free projection for the ``ai-runtime-diagnostics``/``ai-plan``
        diagnostics fields (``requested_strategy`` / ``effective_strategy`` /
        ``normalized`` / ``reason_code`` / ``target_running`` /
        ``application_launch_allowed``)."""

        return {
            "requested_strategy": self.requested_strategy,
            "effective_strategy": self.effective_strategy,
            "normalized": self.normalized,
            "reason_code": self.reason_code,
            "target_running": self.target_running,
            "application_launch_allowed": self.application_launch_allowed,
        }


def normalize_dynamic_strategy(
    *,
    requested_strategy: str,
    allow_dynamic: bool,
    allow_network: bool,
    confirmed_tools: frozenset[str] | set[str] | Mapping[str, object],
    target_running: bool,
    dynamic_mode_policy: str = "balanced",
    plan_references_traffic: bool | None = None,
) -> DynamicStrategyDecision:
    """Apply Rules A–F and return the :class:`DynamicStrategyDecision`.

    ``confirmed_tools`` accepts a set/frozenset of tool names or a mapping
    (the request DTO sometimes carries ``confirmed_tools`` as a mapping of
    ``tool_name -> detail``); only membership of the dynamic tool matters.
    ``plan_references_traffic`` is an optional hint: when ``None`` the
    normalizer cannot tell whether the plan needs traffic capture, so Rule F
    keeps the dynamic leg unless other rules downgrade it.
    """

    confirmed = frozenset(confirmed_tools.keys()) if isinstance(
        confirmed_tools, Mapping
    ) else frozenset(confirmed_tools)
    dynamic_confirmed = _DEVICE_STATE_TOOL in confirmed

    # --- Rule A: unknown requested strategy -------------------------------
    if requested_strategy not in _VALID_REQUESTED_STRATEGIES:
        return DynamicStrategyDecision(
            requested_strategy=requested_strategy,
            effective_strategy="static_only",
            normalized=False,
            reason_code="unknown_requested_strategy",
            target_running=target_running,
            application_launch_allowed=False,
        )

    # --- Rule B: read-only requested (static_only / report_only) ---------
    if requested_strategy in _READONLY_STRATEGIES:
        launch_allowed = False
        # Effective equals requested unless the plan slipped in a device tool.
        # (The plan_validator rejects such plans at the schema layer, but the
        # normalizer is descriptive too so the runtime validator sees the
        # *deterministic* clamp rather than relying on the model to behave.)
        if allow_dynamic and dynamic_confirmed:
            # Operator wants dynamic + confirmed, but requested a read-only
            # strategy: respect the requested strategy (read-only), record the
            # mismatch so the diagnostics are honest.
            return DynamicStrategyDecision(
                requested_strategy=requested_strategy,
                effective_strategy=requested_strategy,
                normalized=False,
                reason_code="dynamic_requested_under_readonly_strategy",
                target_running=target_running,
                application_launch_allowed=launch_allowed,
            )
        return DynamicStrategyDecision(
            requested_strategy=requested_strategy,
            effective_strategy=requested_strategy,
            normalized=False,
            reason_code=None,
            target_running=target_running,
            application_launch_allowed=launch_allowed,
        )

    # Remaining rules operate on dynamic-bearing strategies.
    # --- Rule C: dynamic requested but allow_dynamic=False ---------------
    if not allow_dynamic:
        return DynamicStrategyDecision(
            requested_strategy=requested_strategy,
            effective_strategy="static_only",
            normalized=True,
            reason_code="dynamic_not_allowed",
            target_running=target_running,
            application_launch_allowed=False,
        )

    # --- Rule D: dynamic allowed but not confirmed -----------------------
    if not dynamic_confirmed:
        return DynamicStrategyDecision(
            requested_strategy=requested_strategy,
            effective_strategy="static_only",
            normalized=True,
            reason_code="dynamic_not_confirmed",
            target_running=target_running,
            application_launch_allowed=False,
        )

    # Beyond here: dynamic leg is genuinely authorised and confirmed.
    # --- Rule E: attach_only against a not-running target -----------------
    policy_is_attach_only = dynamic_mode_policy == "attach_only"
    if policy_is_attach_only and not target_running:
        return DynamicStrategyDecision(
            requested_strategy=requested_strategy,
            effective_strategy="static_only",
            normalized=True,
            reason_code="attach_only_no_target",
            target_running=False,
            application_launch_allowed=False,
        )

    # attach_only with a running target still forbids launching the app.
    if policy_is_attach_only and target_running:
        return DynamicStrategyDecision(
            requested_strategy=requested_strategy,
            effective_strategy=requested_strategy,
            normalized=True,
            reason_code="attach_only_target_running",
            target_running=True,
            application_launch_allowed=False,
        )

    # --- Rule F: network capture disabled under a dynamic plan ------------
    if not allow_network:
        # If the plan's only reason to be dynamic was traffic capture, the
        # dynamic leg collapses. Otherwise keep dynamic but record that the
        # network leg was stripped.
        # First Rule C/D guarded allow_dynamic/confirmed; reaching here means
        # the dynamic leg is real (the dynamic_analysis tool itself, not just
        # traffic). So even with network disabled, a full_analysis/dynamic_only
        # plan keeps the dynamic_analysis step — only traffic_analysis is gone.
        if requested_strategy == "dynamic_only" and plan_references_traffic is True:
            reason = "network_capture_disabled_collapses_to_static"
        else:
            reason = "network_capture_disabled"
        return DynamicStrategyDecision(
            requested_strategy=requested_strategy,
            effective_strategy=requested_strategy,
            normalized=True,
            reason_code=reason,
            target_running=target_running,
            application_launch_allowed=True,
        )

    # --- All flags aligned: keep the requested strategy -----------------
    return DynamicStrategyDecision(
        requested_strategy=requested_strategy,
        effective_strategy=requested_strategy,
        normalized=False,
        reason_code=None,
        target_running=target_running,
        application_launch_allowed=True,
    )


def plan_has_dynamic_tool(steps: list[Mapping[str, object]]) -> bool:
    """Whether a step list (plan or request shape) references the dynamic tool."""

    if not isinstance(steps, list):
        return False
    return any(
        isinstance(step, Mapping) and step.get("tool_name") == _DEVICE_STATE_TOOL
        for step in steps
    )


def plan_has_traffic_tool(steps: list[Mapping[str, object]]) -> bool:
    """Whether a step list references traffic capture (for Rule F's hint)."""

    if not isinstance(steps, list):
        return False
    return any(
        isinstance(step, Mapping) and step.get("tool_name") == _TRAFFIC_TOOL
        for step in steps
    )


__all__ = [
    "DynamicStrategyDecision",
    "normalize_dynamic_strategy",
    "plan_has_dynamic_tool",
    "plan_has_traffic_tool",
]
