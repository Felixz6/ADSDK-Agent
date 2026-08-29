"""M7B Phase B — AI planner truncation regression tests.

Real-device finding this file pins down: deepseek-v4-flash answered the old
500-token planner prompt with a JSON object that had no ``steps`` key at all
(validation ``missing_schema_version``), and the 300-token repair cap could
never re-emit a full plan. These tests cover the requested A-J matrix without
touching a device or a real provider.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.ai.cache import AIResponseCache
from app.ai.context_builder import AIContextBuilder
from app.ai.models import AIPerRoundUsage
from app.ai.orchestrator import AIOrchestrationRequest, AIOrchestrator
from app.ai.plan_parser import parse_plan_response
from app.ai.plan_repair import build_plan_repair_contract
from app.ai.plan_validator import PlanValidationResult
from app.ai.models import PlanValidationIssue
from app.ai.provider import (
    MockAIProvider,
    ProviderError,
    ProviderResponse,
    ProviderUsage,
    _extract_json_object,
)
from app.ai.secret_store import SecretStore
from app.ai.settings_store import (
    DEFAULT_PLANNER_MAX_OUTPUT_TOKENS,
    DEFAULT_REPAIR_MAX_OUTPUT_TOKENS,
)
from app.ai.tool_registry import AIToolRegistry


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------
def _step(step_id: str, tool: str, **kwargs: Any) -> dict[str, Any]:
    return {
        "step_id": step_id,
        "tool_name": tool,
        "reason": kwargs.pop("reason", "r"),
        "arguments": kwargs.pop("arguments", {}),
        "depends_on": kwargs.pop("depends_on", []),
        "requires_confirmation": kwargs.pop("requires_confirmation", False),
    }


def _plan_payload(steps: list[dict[str, Any]], strategy: str = "static_only") -> dict[str, Any]:
    return {
        "schema_version": "ai-plan-v1",
        "objective": "short objective",
        "strategy": strategy,
        "steps": steps,
        "expected_outputs": [],
        "stop_conditions": [],
        "limitations": [],
    }


_VALID_PLAN = _plan_payload([_step("s1", "static_analysis")])

# The exact real-device failure shape: a balanced JSON object that is NOT a
# plan — six top-level fields, no schema_version, no steps.
_V5_LIKE_RESPONSE: dict[str, Any] = {
    "objective": "short objective",
    "strategy": "static_only",
    "expected_outputs": ["report"],
    "stop_conditions": ["none"],
    "limitations": ["limited window"],
    "notes": "model produced a plan description without steps",
}


class ScriptedProvider:
    """Queued provider: each call pops one scripted response.

    Entries are either :class:`ProviderError` (raised), a ``str`` (raw model
    text, mimicking truncation so the provider-level JSON extraction runs), or
    a ``dict`` (an already-structured body, like MockAIProvider returns).
    """

    name = "scripted"

    def __init__(
        self,
        script: list[Any],
        *,
        finish_reasons: list[str] | None = None,
        reasoning_flags: list[bool] | None = None,
    ) -> None:
        self._script = list(script)
        self._finish_reasons = list(finish_reasons or [])
        self._reasoning = list(reasoning_flags or [])
        self.call_count = 0
        self.received_max_output: list[int] = []
        self.received_prompts: list[str] = []
        self.model = "scripted-1"

    def is_configured(self) -> bool:
        return True

    def reachable(self) -> tuple[bool, str | None]:
        return True, None

    def configuration_error(self) -> dict[str, str] | None:
        return None

    def call(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        tools: list[dict[str, Any]],
        max_input_tokens: int,
        max_output_tokens: int,
        profile: Any = None,
        thinking_mode: Any = None,
    ) -> ProviderResponse:
        self.call_count += 1
        self.received_max_output.append(max_output_tokens)
        self.received_prompts.append(user_prompt)
        if not self._script:
            raise AssertionError("script exhausted")
        item = self._script.pop(0)
        if isinstance(item, ProviderError):
            raise item
        if isinstance(item, str):
            parsed = _extract_json_object(item)
            if parsed is None:
                raise ProviderError(
                    "ai_provider_invalid_json",
                    "AI provider content had no parseable JSON object",
                    retryable=False,
                    stage="provider_call",
                )
            body, chars = parsed, len(item)
        else:
            body, chars = item, len(json.dumps(item, ensure_ascii=False))
        finish = self._finish_reasons.pop(0) if self._finish_reasons else "stop"
        reasoning = self._reasoning.pop(0) if self._reasoning else False
        return ProviderResponse(
            content_json=body,
            content_chars=chars,
            usage=ProviderUsage(
                input_tokens=120,
                output_tokens=40,
                model=self.model,
                usage_source="provider",
            ),
            latency_ms=1,
            usage_source="provider",
            finish_reason=finish,
            reasoning_content_present=reasoning,
        )


def _tool(name: str) -> Any:
    from app.ai.models import ToolCompactResult

    return ToolCompactResult(
        tool_name=name,
        status="success",
        summary="ok",
        result={"ok": True},
        truncated=False,
    )


def _run(orch: AIOrchestrator, request: AIOrchestrationRequest):
    builder = AIContextBuilder()
    return orch.run(
        request,
        execute_tool=lambda name, _args: _tool(name),
        build_digest=lambda _results: builder.build(
            task={"task_id": "t1", "objective": request.objective}
        ),
    )


def _request(**overrides: Any) -> AIOrchestrationRequest:
    params: dict[str, Any] = {"objective": "short objective"}
    params.update(overrides)
    return AIOrchestrationRequest(**params)


def _report_body() -> dict[str, Any]:
    return {
        "schema_version": "ai-report-v1",
        "status": "completed",
        "executive_summary": "two SDKs, no requests",
        "key_findings": [],
        "evidence_gaps": [],
        "risk_priorities": [],
        "recommended_actions": [],
        "evidence_refs": [],
        "limitations": [],
    }


# ---------------------------------------------------------------------------
# A — planner minimal output parses and is accepted.
# ---------------------------------------------------------------------------
def test_a_planner_minimal_output_is_accepted():
    raw = json.dumps(_VALID_PLAN, ensure_ascii=False)
    provider = ScriptedProvider([raw, _report_body()])
    result = _run(AIOrchestrator(provider=provider), _request())

    assert result.plan.generated_by == "ai"
    assert result.diagnostic_payload()["plan_source"] == "ai"
    assert result.status == "completed"


# ---------------------------------------------------------------------------
# B — finish_reason=length with a complete JSON is still accepted locally.
# ---------------------------------------------------------------------------
def test_b_length_finish_reason_with_valid_json_is_accepted():
    provider = ScriptedProvider(
        [_VALID_PLAN, _report_body()],
        finish_reasons=["length", "stop"],
    )
    result = _run(AIOrchestrator(provider=provider), _request())

    assert result.plan.generated_by == "ai"
    assert result.diagnostic_payload()["plan_source"] == "ai"
    assert result.error_code is None
    # The local parse accepted the complete object: no repair was needed.
    assert result.diagnostic_payload()["repair_attempted"] is False
    rounds = result.diagnostic_payload()["rounds"]
    assert rounds[0]["finish_reason"] == "length"
    assert rounds[0]["requested_output_tokens"] > 0
    assert rounds[0]["response_chars"] == len(
        json.dumps(_VALID_PLAN, ensure_ascii=False)
    )


# ---------------------------------------------------------------------------
# C — length + invalid JSON goes to the structured repair round.
# ---------------------------------------------------------------------------
def test_c_truncated_json_goes_to_repair_then_succeeds():
    truncated = json.dumps(_VALID_PLAN, ensure_ascii=False)[:-40]  # cut mid-JSON
    provider = ScriptedProvider([truncated, _VALID_PLAN, _report_body()])
    result = _run(AIOrchestrator(provider=provider), _request())

    assert result.diagnostic_payload()["plan_source"] == "repaired"
    assert result.diagnostic_payload()["repair_attempted"] is True
    assert result.diagnostic_payload()["repair_succeeded"] is True
    assert result.status == "completed"


# ---------------------------------------------------------------------------
# D — repair round succeeds with a smaller output budget.
# ---------------------------------------------------------------------------
def test_d_repair_recovers_within_smaller_cap():
    provider = ScriptedProvider([_V5_LIKE_RESPONSE, _VALID_PLAN, _report_body()])
    orch = AIOrchestrator(
        provider=provider,
        planner_max_output_tokens=500,
        repair_max_output_tokens=500,
    )
    result = _run(orch, _request())

    assert result.diagnostic_payload()["plan_source"] == "repaired"
    # The repair round was capped at the explicitly reduced budget, not at the
    # planner cap (and never below its own stage cap).
    assert provider.received_max_output[1] == 500
    assert result.status == "completed"


# ---------------------------------------------------------------------------
# E — unknown tool is rejected and can never run.
# ---------------------------------------------------------------------------
def test_e_unknown_tool_fails_validation_and_never_executes():
    bad = _plan_payload([_step("s1", "shell")])
    provider = ScriptedProvider([bad, bad, _report_body()])
    result = _run(AIOrchestrator(provider=provider), _request())

    assert result.plan.generated_by == "default"
    assert result.diagnostic_payload()["plan_source"] == "deterministic"
    executed = [item.tool_name for item in result.tool_results]
    assert "shell" not in executed
    assert all(name != "shell" for name in executed)


# ---------------------------------------------------------------------------
# F — the real-device malformed schema (no schema_version, no steps) is
# repaired into a valid plan instead of silently accepted.
# ---------------------------------------------------------------------------
def test_f_v5_malformed_schema_fixture_is_repaired():
    provider = ScriptedProvider([_V5_LIKE_RESPONSE, _VALID_PLAN, _report_body()])
    result = _run(AIOrchestrator(provider=provider), _request())

    assert result.diagnostic_payload()["plan_source"] == "repaired"
    assert result.plan.schema_version == "ai-plan-v1"
    assert result.plan.steps
    diag = result.diagnostic_payload()
    assert diag["validation_error_code"] in {
        "missing_schema_version",
        "missing_steps",
        "plan_invalid_shape",
    }


# ---------------------------------------------------------------------------
# G — reasoning content is never persisted, only its presence flag.
# ---------------------------------------------------------------------------
def test_g_reasoning_content_is_never_persisted():
    secret = "SECRET-REASONING-CHAIN-MUST-NOT-APPEAR"
    provider = ScriptedProvider(
        [_VALID_PLAN, _report_body()],
        reasoning_flags=[True, True],
    )
    result = _run(AIOrchestrator(provider=provider), _request())

    assert result.usage.reasoning_content_present is True
    payload = json.dumps(result.diagnostic_payload(), ensure_ascii=False)
    assert '"reasoning_content_present"' in payload
    assert secret not in payload


# ---------------------------------------------------------------------------
# H — planner output budget is bounded, not unbounded.
# ---------------------------------------------------------------------------
def test_h_planner_output_cap_is_bounded_and_respected():
    provider = ScriptedProvider([_VALID_PLAN, _report_body()])
    orch = AIOrchestrator(provider=provider, planner_max_output_tokens=400)
    _run(orch, _request())
    assert provider.received_max_output[0] == 400

    bounded_request = _request(token_budget=500)
    provider2 = ScriptedProvider([_VALID_PLAN, _report_body()])
    _run(AIOrchestrator(provider=provider2), bounded_request)
    # min(planner cap 800, budget remaining 500) — budget wins.
    assert provider2.received_max_output[0] == 500

    # Defaults: the repair cap must never be smaller than the planner cap.
    assert DEFAULT_REPAIR_MAX_OUTPUT_TOKENS >= DEFAULT_PLANNER_MAX_OUTPUT_TOKENS


# ---------------------------------------------------------------------------
# I — the same digest hits the response cache instead of the model.
# ---------------------------------------------------------------------------
def test_i_same_digest_uses_cache_not_model(tmp_path: Path):
    cache = AIResponseCache(tmp_path / "cache", enabled=True)
    builder = AIContextBuilder()
    digest = builder.build(task={"task_id": "t", "objective": "o"})

    def run_once() -> tuple[MockAIProvider, Any]:
        provider = MockAIProvider()
        orch = AIOrchestrator(provider=provider, enabled=True, cache=cache)
        result = orch.run(
            _request(),
            execute_tool=lambda name, _args: _tool(name),
            build_digest=lambda _r: digest,
        )
        return provider, result

    first_provider, first = run_once()
    second_provider, second = run_once()

    assert first_provider.call_count == 2  # plan + report
    # The digest-keyed report is served from cache; only the planning round is
    # re-billed (planning is task-scoped, not digest-scoped).
    assert second_provider.call_count == 1
    assert second.usage.cache_hit is True


# ---------------------------------------------------------------------------
# J — a fully unavailable provider still produces the deterministic result.
# ---------------------------------------------------------------------------
def test_j_provider_outage_keeps_deterministic_result():
    provider = ScriptedProvider(
        [
            ProviderError(
                "ai_provider_unreachable",
                "provider unreachable",
                retryable=False,
                stage="provider_call",
            )
        ]
    )
    result = _run(AIOrchestrator(provider=provider), _request())

    assert result.plan.generated_by == "default"
    assert result.diagnostic_payload()["plan_source"] == "deterministic"
    assert result.status in {"completed", "partial"}
    assert result.report is not None
    assert [item.tool_name for item in result.tool_results]


# ---------------------------------------------------------------------------
# Parser contract the fixes rely on.
# ---------------------------------------------------------------------------
def test_parser_still_rejects_truncated_json():
    truncated = json.dumps(_VALID_PLAN, ensure_ascii=False)[:-40]
    parsed = parse_plan_response(truncated)
    assert not parsed.ok
    assert parsed.error == "invalid_json"


def test_repair_contract_handles_missing_parsed_object():
    prompt = build_plan_repair_contract(
        registry=AIToolRegistry(),
        strategy="static_only",
        allow_dynamic=False,
        confirmed_tools=frozenset(),
        rejected_plan=None,
        validation=PlanValidationResult(
            plan=None,
            issues=[PlanValidationIssue(code="parse_failed", stage="parse")],
            parse_code="parse_failed",
        ),
        max_steps=6,
        budget_rounds_remaining=1,
    )
    assert prompt is not None
    assert "Return only the JSON object" in prompt
    assert "shortest valid plan" in prompt
