"""In-memory mock AI provider for testing and offline development."""

from __future__ import annotations

import json
from typing import Any

from .base import (
    ProviderCompatibilityProfile,
    ProviderError,
    ProviderResponse,
    ProviderUsage,
    _safe_truncate,
)


class MockAIProvider:
    """Returns deterministic canned structured objects.

    Tests steer it with ``plan`` / ``report`` overrides and an ``error``
    switch so they can drive every orchestrator branch without a network.
    The mock never holds an API key and is always "configured".
    """

    name = "mock"

    def __init__(
        self,
        *,
        plan: dict[str, Any] | None = None,
        report: dict[str, Any] | None = None,
        error: ProviderError | None = None,
        model: str = "mock-1",
        finish_reason: str | None = "stop",
    ) -> None:
        self._plan = plan
        self._report = report
        self._error = error
        self._model = model
        self._finish_reason = finish_reason
        self.call_count = 0
        self.received_system_prompt: str | None = None
        self.received_user_prompt: str | None = None
        self.received_tools: list[dict[str, Any]] | None = None
        self.received_max_input: int | None = None
        # M6C: capture the profile/thinking the orchestrator asked for so tests
        # can assert compat behaviour without touching the network.
        self.received_profile: ProviderCompatibilityProfile | None = None
        self.received_thinking_mode: str | None = None
        self.received_max_output: int | None = None

    @property
    def model(self) -> str:  # type: ignore[override]
        return self._model

    def is_configured(self) -> bool:  # type: ignore[override]
        return True

    def configuration_error(self) -> dict[str, Any] | None:  # type: ignore[override]
        return None

    def call(  # type: ignore[override]
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        tools: list[dict[str, Any]],
        max_input_tokens: int,
        max_output_tokens: int,
        profile: ProviderCompatibilityProfile | None = None,
        thinking_mode: str | None = None,
    ) -> ProviderResponse:
        self.call_count += 1
        self.received_system_prompt = system_prompt
        self.received_user_prompt = user_prompt
        self.received_tools = list(tools)
        self.received_max_input = max_input_tokens
        self.received_max_output = max_output_tokens
        self.received_profile = profile
        self.received_thinking_mode = thinking_mode
        if self._error is not None:
            raise self._error
        # Heuristic: a planning call mentions the plan schema, a reporting call
        # mentions the evidence digest / report schema. Tests may also pin the
        # exact override via an injected marker in the user prompt.
        body, decision = self._choose_body(user_prompt)
        # The mock reports authoritative synthetic usage so downstream
        # provenance logic (real vs estimated) is exercised.
        return ProviderResponse(
            content_json=body,
            content_chars=len(json.dumps(body, ensure_ascii=False)),
            usage=ProviderUsage(
                input_tokens=max(1, len(_safe_truncate(user_prompt, 4096)) // 4),
                output_tokens=max(1, len(json.dumps(body, ensure_ascii=False)) // 4),
                model=self._model,
                usage_source="provider",
            ),
            decision_summary=decision,
            latency_ms=1,
            usage_source="provider",
            finish_reason=self._finish_reason,
            reasoning_content_present=False,
        )

    def _choose_body(
        self, user_prompt: str
    ) -> tuple[dict[str, Any], str | None]:
        marker = "__ai_phase__:"  # tests inject this to pin the phase
        if marker in user_prompt:
            tag = user_prompt.split(marker, 1)[1].split()[0] if marker else ""
        else:
            tag = "plan" if "ai-plan-v1" in user_prompt else "report"
        if tag.startswith("plan"):
            return (self._plan or _default_mock_plan()), "mock plan"
        return (self._report or _default_mock_report()), "mock report"

    def reachable(self) -> tuple[bool, str | None]:  # type: ignore[override]
        return True, None


def _default_mock_plan() -> dict[str, Any]:
    return {
        "schema_version": "ai-plan-v1",
        "objective": "mock static privacy check",
        "strategy": "static_only",
        "steps": [
            {
                "step_id": "s1",
                "tool_name": "static_analysis",
                "reason": "identify SDKs and permissions",
                "arguments": {},
                "depends_on": [],
                "requires_confirmation": False,
            },
            {
                "step_id": "s2",
                "tool_name": "privacy_findings",
                "reason": "evaluate privacy rules",
                "arguments": {},
                "depends_on": ["s1"],
                "requires_confirmation": False,
            },
        ],
        "expected_outputs": ["static_summary", "privacy_findings_summary"],
        "stop_conditions": ["all steps success"],
        "limitations": ["mock plan"],
        "generated_by": "ai",
    }


def _default_mock_report() -> dict[str, Any]:
    return {
        "schema_version": "ai-report-v1",
        "status": "completed",
        "executive_summary": "mock synthesis summary",
        "key_findings": [],
        "evidence_gaps": [],
        "risk_priorities": [],
        "recommended_actions": [],
        "evidence_refs": [],
        "limitations": ["mock report"],
        "disclaimer": "",
        "usage": {},
    }



__all__ = [
    "MockAIProvider",
    "_default_mock_plan",
    "_default_mock_report",
]
