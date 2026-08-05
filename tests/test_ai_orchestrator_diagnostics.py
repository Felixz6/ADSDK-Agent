"""M6C AI runtime-diagnostics and token-provenance tests.

No test here ever reaches a real model, a real device, ADB or Frida: every
scenario is driven through ``MockAIProvider`` (or a subclass) with an
in-process cache. There is no real ``sleep`` anywhere — the orchestrator does
not sleep, and provider-level retry backoff is covered in
``test_ai_provider_compat.py`` with an injected sleep.

Coverage:

* per-stage output-token caps (plan / report / repair) and budget gating,
* per-round ``AIPerRoundUsage`` provenance records,
* real-vs-estimated token accounting kept strictly apart,
* classified provider errors surfaced as ``AIErrorObservation``,
* the ``ok / degraded / failed / disabled`` outcome matrix,
* ``deterministic_fallback`` marking template-generated reports,
* ``reasoning_content`` reduced to a presence boolean and never persisted,
* ``ai-runtime-diagnostics.json`` written as a secret-free 5th artifact.
"""

from __future__ import annotations

import dataclasses
import json
from pathlib import Path
from typing import Any

import pytest

from app.ai.cache import AIResponseCache
from app.ai.context_builder import AIContextBuilder
from app.ai.models import (
    AIErrorObservation,
    AIPerRoundUsage,
    AIRuntimeDiagnostic,
    AITokenUsage,
    ToolCompactResult,
)
from app.ai.orchestrator import (
    _normalize_plan_envelope,
    AIOrchestrationRequest,
    AIOrchestrator,
    write_ai_artifacts,
)
from app.ai.provider import MockAIProvider, ProviderError, ProviderResponse

# A syntactically plausible key shape used ONLY to prove it never reaches an
# artifact. It is not a real credential and is never sent anywhere.
_FAKE_KEY = "sk-test-never-a-real-key-0000000000"


# ---------------------------------------------------------------------------
# Helpers.
# ---------------------------------------------------------------------------
def _no_cache() -> AIResponseCache:
    return AIResponseCache(enabled=False)


def _execute_ok(name: str, _arguments: dict[str, Any]) -> ToolCompactResult:
    return ToolCompactResult(tool_name=name, status="success", summary=name)


def _orchestrator(provider: Any, **kwargs: Any) -> AIOrchestrator:
    kwargs.setdefault("enabled", True)
    kwargs.setdefault("cache", _no_cache())
    return AIOrchestrator(provider=provider, **kwargs)


def _run(orch: AIOrchestrator, request: AIOrchestrationRequest, execute=_execute_ok):
    builder = AIContextBuilder()
    return orch.run(
        request,
        execute_tool=execute,
        build_digest=lambda _results: builder.build(
            task={"task_id": request.task_id or "t1", "objective": request.objective}
        ),
    )


def _request(**kwargs: Any) -> AIOrchestrationRequest:
    kwargs.setdefault("objective", "静态隐私检查")
    kwargs.setdefault("task_id", "t-diag")
    return AIOrchestrationRequest(**kwargs)


class RecordingProvider(MockAIProvider):
    """Captures the ``max_output_tokens`` the orchestrator asked for per call."""

    def __init__(self, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.output_caps: list[int] = []

    def call(self, **kwargs: Any) -> ProviderResponse:  # type: ignore[override]
        self.output_caps.append(kwargs["max_output_tokens"])
        return super().call(**kwargs)


class ReasoningProvider(MockAIProvider):
    """Returns a response flagged as having produced ``reasoning_content``.

    Only the *boolean* is set; the mock never carries reasoning text, matching
    the provider contract that the content is dropped at parse time.
    """

    def call(self, **kwargs: Any) -> ProviderResponse:  # type: ignore[override]
        response = super().call(**kwargs)
        return dataclasses.replace(response, reasoning_content_present=True)


class NoUsageProvider(MockAIProvider):
    """Reports no real token counts, forcing the estimated provenance path."""

    def call(self, **kwargs: Any) -> ProviderResponse:  # type: ignore[override]
        response = super().call(**kwargs)
        return dataclasses.replace(
            response,
            usage=dataclasses.replace(
                response.usage, input_tokens=None, output_tokens=None
            ),
            usage_source="unavailable",
        )


class FailingReportProvider(MockAIProvider):
    """Succeeds at planning, then raises a classified error on the report call."""

    def __init__(self, error: ProviderError, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._report_error = error

    def call(self, **kwargs: Any) -> ProviderResponse:  # type: ignore[override]
        if "ai-plan-v1" not in kwargs.get("user_prompt", ""):
            self.call_count += 1
            raise self._report_error
        return super().call(**kwargs)


# ---------------------------------------------------------------------------
# 1. Per-stage output-token caps.
# ---------------------------------------------------------------------------
class TestStageOutputCaps:
    def test_each_stage_uses_its_own_cap(self):
        orch = _orchestrator(MockAIProvider())

        assert orch._stage_cap("plan") == 500
        assert orch._stage_cap("report") == 1000
        assert orch._stage_cap("repair") == 300

    def test_stage_cap_is_clipped_by_the_global_output_ceiling(self):
        orch = _orchestrator(MockAIProvider(), max_output_tokens=120)

        # No stage may exceed the global ceiling even when its own cap is larger.
        assert orch._stage_cap("plan") == 120
        assert orch._stage_cap("report") == 120
        assert orch._stage_cap("repair") == 120

    def test_stage_cap_never_returns_less_than_one_token(self):
        orch = _orchestrator(MockAIProvider(), max_output_tokens=0)

        assert orch._stage_cap("plan") == 1
        assert orch._stage_cap("report", input_floor=1) == 1

    def test_repair_cap_is_the_tightest_of_the_three(self):
        orch = _orchestrator(MockAIProvider())

        caps = [orch._stage_cap(s) for s in ("plan", "report", "repair")]
        assert min(caps) == orch._stage_cap("repair")

    def test_remaining_cap_equals_stage_cap_without_a_budget(self):
        orch = _orchestrator(MockAIProvider())
        usage = AITokenUsage()

        assert orch._remaining_output_cap("report", _request(), usage) == 1000

    def test_remaining_cap_shrinks_as_the_budget_is_consumed(self):
        orch = _orchestrator(MockAIProvider())
        request = _request(token_budget=800)
        usage = AITokenUsage(input_tokens=300, output_tokens=100)

        # 800 budget - 400 spent = 400 remaining, below the 1000 report cap.
        assert orch._remaining_output_cap("report", request, usage) == 400

    def test_remaining_cap_counts_estimated_tokens_as_spend(self):
        orch = _orchestrator(MockAIProvider())
        request = _request(token_budget=900)
        usage = AITokenUsage(input_tokens=100, output_tokens=100, estimated_tokens=200)

        assert orch._remaining_output_cap("report", request, usage) == 500

    def test_remaining_cap_floors_at_one_when_the_budget_is_used_up(self):
        orch = _orchestrator(MockAIProvider())
        request = _request(token_budget=100)
        usage = AITokenUsage(input_tokens=500)

        # Never returns 0 or a negative cap, which providers reject.
        assert orch._remaining_output_cap("report", request, usage) == 1

    def test_remaining_cap_ignores_a_non_positive_budget(self):
        orch = _orchestrator(MockAIProvider())
        usage = AITokenUsage(input_tokens=10_000)

        assert orch._remaining_output_cap("plan", _request(token_budget=0), usage) == 500

    def test_stage_cap_still_bounds_a_generous_budget(self):
        orch = _orchestrator(MockAIProvider())
        request = _request(token_budget=1_000_000)

        # A huge budget must not lift a stage above its own cap.
        assert orch._remaining_output_cap("plan", request, AITokenUsage()) == 500

    def test_orchestrator_sends_the_stage_cap_to_the_provider(self):
        provider = RecordingProvider()
        _run(_orchestrator(provider), _request())

        # Round 1 is planning (500), round 2 is reporting (1000).
        assert provider.output_caps == [500, 1000]

    def test_provider_caps_respect_a_low_global_ceiling(self):
        provider = RecordingProvider()
        _run(_orchestrator(provider, max_output_tokens=200), _request())

        assert provider.output_caps == [200, 200]

    def test_report_only_skips_planning_and_bills_one_round(self):
        provider = RecordingProvider()
        result = _run(_orchestrator(provider), _request(analysis_scope="report_only"))

        # The report_only tool set is fixed, so there is nothing to plan: the
        # normal path costs exactly one billed call.
        assert provider.call_count == 1
        assert provider.output_caps == [1000]
        assert [r.round_type for r in result.usage.rounds] == ["report"]

    def test_report_only_still_reaches_a_completed_report(self):
        result = _run(_orchestrator(MockAIProvider()), _request(analysis_scope="report_only"))

        # Skipping planning must not degrade the run.
        assert result.status == "completed"
        assert result.diagnostic.outcome == "ok"
        assert result.diagnostic.deterministic_fallback is False


# ---------------------------------------------------------------------------
# 2. Per-round usage records.
# ---------------------------------------------------------------------------
class TestPerRoundUsage:
    def test_each_model_round_produces_one_usage_record(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert len(result.usage.rounds) == 2
        assert all(isinstance(r, AIPerRoundUsage) for r in result.usage.rounds)

    def test_rounds_are_labelled_plan_then_report(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert [r.round_type for r in result.usage.rounds] == ["plan", "report"]

    def test_round_indexes_are_sequential_and_one_based(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert [r.round_index for r in result.usage.rounds] == [1, 2]

    def test_rounds_carry_provider_provenance_when_usage_is_reported(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert all(r.usage_source == "provider" for r in result.usage.rounds)

    def test_rounds_carry_estimated_provenance_without_reported_usage(self):
        result = _run(_orchestrator(NoUsageProvider()), _request())

        assert all(r.usage_source == "estimated" for r in result.usage.rounds)

    def test_round_records_the_provider_finish_reason(self):
        result = _run(_orchestrator(MockAIProvider(finish_reason="length")), _request())

        assert all(r.finish_reason == "length" for r in result.usage.rounds)

    def test_round_token_counts_are_non_negative_integers(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        for record in result.usage.rounds:
            assert record.input_tokens >= 0
            assert record.output_tokens >= 0
            assert isinstance(record.input_tokens, int)

    def test_estimated_rounds_report_zero_real_tokens(self):
        result = _run(_orchestrator(NoUsageProvider()), _request())

        # An estimated round must not present fabricated numbers as real.
        assert all(r.input_tokens == 0 and r.output_tokens == 0
                   for r in result.usage.rounds)

    def test_retry_count_defaults_to_zero_when_unreported(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert all(r.retry_count == 0 for r in result.usage.rounds)

    def test_total_rounds_matches_the_model_round_count(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.diagnostic.total_rounds == result.usage.model_round_count == 2

    def test_a_reused_orchestrator_does_not_leak_rounds_between_runs(self):
        orch = _orchestrator(MockAIProvider())
        _run(orch, _request())
        second = _run(orch, _request())

        # Diagnostics are reset per run, so the second run reports its own 2.
        assert len(second.usage.rounds) == 2
        assert second.diagnostic.total_rounds == 2


# ---------------------------------------------------------------------------
# 3. Real vs estimated token accounting.
# ---------------------------------------------------------------------------
class TestTokenProvenance:
    def test_provider_reported_usage_is_labelled_real(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.usage.usage_source == "provider"
        assert result.usage.usage_is_estimate is False

    def test_real_tokens_accumulate_across_rounds(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        expected = sum(r.input_tokens + r.output_tokens for r in result.usage.rounds)
        assert result.usage.real_tokens == expected > 0

    def test_real_run_records_no_estimated_total(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.usage.estimated_total_tokens == 0

    def test_missing_usage_falls_back_to_a_labelled_estimate(self):
        result = _run(_orchestrator(NoUsageProvider()), _request())

        assert result.usage.usage_source == "estimated"
        assert result.usage.usage_is_estimate is True

    def test_estimated_run_records_no_real_tokens(self):
        result = _run(_orchestrator(NoUsageProvider()), _request())

        # Estimates must never be counted as provider-authoritative numbers.
        assert result.usage.real_tokens == 0
        assert result.usage.estimated_total_tokens > 0

    def test_real_and_estimated_totals_are_kept_in_separate_fields(self):
        real = _run(_orchestrator(MockAIProvider()), _request()).usage
        estimated = _run(_orchestrator(NoUsageProvider()), _request()).usage

        # The two provenances never mix into a single ambiguous total.
        assert (real.real_tokens > 0) and (real.estimated_total_tokens == 0)
        assert (estimated.real_tokens == 0) and (estimated.estimated_total_tokens > 0)

    def test_diagnostic_usage_matches_the_persisted_usage(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.diagnostic.usage.real_tokens == result.usage.real_tokens
        assert result.diagnostic.usage.usage_source == result.usage.usage_source


# ---------------------------------------------------------------------------
# 4. Classified provider errors.
# ---------------------------------------------------------------------------
class TestErrorClassification:
    def _failing(self, code: str, *, retryable: bool, status: int | None):
        return FailingReportProvider(
            ProviderError(code, "safe", retryable=retryable, status_code=status)
        )

    def test_report_stage_failure_is_recorded_as_an_observation(self):
        provider = self._failing("ai_provider_timeout", retryable=True, status=408)
        result = _run(_orchestrator(provider), _request())

        assert len(result.diagnostic.errors) == 1
        assert isinstance(result.diagnostic.errors[0], AIErrorObservation)

    def test_observation_preserves_the_classified_code(self):
        provider = self._failing("ai_provider_rate_limited", retryable=True, status=429)
        result = _run(_orchestrator(provider), _request())

        assert result.diagnostic.errors[0].code == "ai_provider_rate_limited"

    def test_observation_preserves_the_http_status(self):
        provider = self._failing("ai_provider_timeout", retryable=True, status=408)
        result = _run(_orchestrator(provider), _request())

        assert result.diagnostic.errors[0].http_status == 408

    def test_observation_preserves_the_retryable_flag(self):
        provider = self._failing(
            "ai_provider_authentication_failed", retryable=False, status=401
        )
        result = _run(_orchestrator(provider), _request())

        assert result.diagnostic.errors[0].retryable is False

    def test_observation_records_the_failing_stage(self):
        provider = self._failing("ai_provider_timeout", retryable=True, status=408)
        result = _run(_orchestrator(provider), _request())

        assert result.diagnostic.errors[0].stage == "report"

    def test_report_stage_failure_is_marked_finalized(self):
        provider = self._failing("ai_provider_timeout", retryable=True, status=408)
        result = _run(_orchestrator(provider), _request())

        # There is no second report attempt, so the observation is terminal.
        assert result.diagnostic.errors[0].finalized is True

    def test_failure_degrades_to_partial_and_surfaces_the_error_code(self):
        provider = self._failing("ai_provider_unreachable", retryable=True, status=503)
        result = _run(_orchestrator(provider), _request())

        assert result.status == "partial"
        assert result.error_code == "ai_provider_unreachable"

    def test_error_observation_carries_no_message_text(self):
        provider = self._failing("ai_provider_error", retryable=False, status=400)
        result = _run(_orchestrator(provider), _request())

        # Only structured fields are kept; no free-form provider prose.
        dumped = result.diagnostic.errors[0].model_dump()
        assert "safe" not in json.dumps(dumped)
        assert set(dumped) == {
            "code", "retryable", "attempt", "retry_count",
            "stage", "http_status", "latency_ms", "finalized",
        }

    def test_a_successful_run_records_no_errors(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.diagnostic.errors == []

    def test_a_retryable_plan_failure_is_recorded_as_not_finalized(self):
        provider = MockAIProvider(
            error=ProviderError(
                "ai_provider_timeout", "safe", retryable=True, status_code=408
            )
        )
        result = _run(_orchestrator(provider), _request())

        # The first retryable planning attempt is followed by one retry, so it
        # is not the terminal observation.
        assert result.diagnostic.errors[0].finalized is False
        assert result.diagnostic.errors[0].stage == "plan"

    def test_a_non_retryable_plan_failure_is_finalized_immediately(self):
        provider = MockAIProvider(
            error=ProviderError(
                "ai_provider_authentication_failed",
                "safe",
                retryable=False,
                status_code=401,
            )
        )
        result = _run(_orchestrator(provider), _request())

        # No retry is attempted, so the planning observation is terminal.
        plan_errors = [e for e in result.diagnostic.errors if e.stage == "plan"]
        assert len(plan_errors) == 1
        assert plan_errors[0].finalized is True
        assert plan_errors[0].attempt == 1


# ---------------------------------------------------------------------------
# 5. Outcome matrix and deterministic fallback.
# ---------------------------------------------------------------------------
class TestOutcomeMatrix:
    def test_a_completed_run_is_ok(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.status == "completed"
        assert result.diagnostic.outcome == "ok"

    def test_a_partial_run_after_a_model_call_is_degraded(self):
        provider = FailingReportProvider(
            ProviderError("ai_provider_timeout", "safe", retryable=True, status_code=408)
        )
        result = _run(_orchestrator(provider), _request())

        assert result.diagnostic.outcome == "degraded"

    def test_a_disabled_run_is_reported_as_disabled(self):
        orch = AIOrchestrator(provider=MockAIProvider(), enabled=False)
        result = _run(orch, _request())

        assert result.diagnostic.outcome == "disabled"
        assert result.diagnostic.enabled is False

    def test_an_unconfigured_provider_is_reported_as_failed(self):
        class Unconfigured(MockAIProvider):
            def is_configured(self) -> bool:
                return False

        result = _run(_orchestrator(Unconfigured()), _request())

        assert result.unavailable_reason == "not_configured"
        assert result.diagnostic.outcome == "failed"

    def test_budget_exhaustion_is_degraded_not_failed(self):
        result = _run(_orchestrator(MockAIProvider()), _request(token_budget=1))

        assert result.status == "budget_exhausted"
        assert result.diagnostic.outcome == "degraded"

    def test_a_successful_model_report_is_not_a_deterministic_fallback(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.diagnostic.deterministic_fallback is False

    def test_a_template_report_is_marked_as_a_deterministic_fallback(self):
        provider = FailingReportProvider(
            ProviderError("ai_provider_timeout", "safe", retryable=True, status_code=408)
        )
        result = _run(_orchestrator(provider), _request())

        assert result.diagnostic.deterministic_fallback is True

    def test_budget_exhausted_reports_are_deterministic_fallbacks(self):
        # The budget path returns a composer template, so it must say so.
        result = _run(_orchestrator(MockAIProvider()), _request(token_budget=1))

        assert result.diagnostic.deterministic_fallback is True

    def test_a_disabled_run_is_a_deterministic_fallback(self):
        orch = AIOrchestrator(provider=MockAIProvider(), enabled=False)
        result = _run(orch, _request())

        assert result.diagnostic.deterministic_fallback is True

    def test_a_cancelled_run_degrades_without_claiming_success(self):
        orch = _orchestrator(MockAIProvider(), cancelled=lambda: True)
        result = _run(orch, _request())

        assert result.status != "completed"
        assert result.diagnostic.deterministic_fallback is True

    def test_outcome_is_one_of_the_four_declared_values(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.diagnostic.outcome in {"ok", "degraded", "failed", "disabled"}


# ---------------------------------------------------------------------------
# 6. Cache accounting.
# ---------------------------------------------------------------------------
class TestCacheDiagnostics:
    def test_a_cache_miss_then_hit_reports_the_hit(self, tmp_path: Path):
        cache = AIResponseCache(tmp_path / "cache", enabled=True)
        first = _run(_orchestrator(MockAIProvider(), cache=cache), _request())
        provider = MockAIProvider()
        second = _run(_orchestrator(provider, cache=cache), _request())

        assert first.diagnostic.cache_hit is False
        assert second.diagnostic.cache_hit is True

    def test_a_cache_hit_avoids_the_report_model_call(self, tmp_path: Path):
        cache = AIResponseCache(tmp_path / "cache", enabled=True)
        _run(_orchestrator(MockAIProvider(), cache=cache), _request())
        provider = MockAIProvider()
        _run(_orchestrator(provider, cache=cache), _request())

        # Planning still runs; the billed report round is served from cache.
        assert provider.call_count == 1

    def test_cache_enabled_flag_is_reported(self, tmp_path: Path):
        cache = AIResponseCache(tmp_path / "cache", enabled=True)
        result = _run(_orchestrator(MockAIProvider(), cache=cache), _request())

        assert result.diagnostic.cache_enabled is True

    def test_cache_disabled_flag_is_reported(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.diagnostic.cache_enabled is False
        assert result.diagnostic.cache_hit is False


# ---------------------------------------------------------------------------
# 7. reasoning_content is a boolean and nothing more.
# ---------------------------------------------------------------------------
class TestReasoningContentIsolation:
    def test_presence_is_recorded_as_a_boolean_on_each_round(self):
        result = _run(_orchestrator(ReasoningProvider()), _request())

        for record in result.usage.rounds:
            assert record.reasoning_content_present is True
            assert isinstance(record.reasoning_content_present, bool)

    def test_presence_is_aggregated_onto_the_usage_record(self):
        result = _run(_orchestrator(ReasoningProvider()), _request())

        assert result.usage.reasoning_content_present is True

    def test_absence_is_recorded_as_false(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.usage.reasoning_content_present is False
        assert all(r.reasoning_content_present is False for r in result.usage.rounds)

    def test_no_reasoning_field_other_than_the_presence_boolean_is_stored(self):
        result = _run(_orchestrator(ReasoningProvider()), _request())

        payload = result.diagnostic.model_dump(mode="json")
        keys = _all_keys(payload)
        reasoning_keys = {k for k in keys if "reasoning" in k}
        assert reasoning_keys == {"reasoning_content_present"}

    def test_the_diagnostic_payload_carries_no_reasoning_text(self):
        result = _run(_orchestrator(ReasoningProvider()), _request())

        blob = json.dumps(result.diagnostic.model_dump(mode="json"), ensure_ascii=False)
        # Only the boolean field name may appear — never a content string.
        assert "reasoning_content\"" not in blob.replace(
            "reasoning_content_present", ""
        )

    def test_the_report_usage_carries_only_the_presence_boolean(self):
        result = _run(_orchestrator(ReasoningProvider()), _request())

        # The embedded usage may record that reasoning happened, never what it was.
        keys = _all_keys(result.report.usage)
        assert {k for k in keys if "reasoning" in k} == {"reasoning_content_present"}
        assert result.report.usage["reasoning_content_present"] is True


# ---------------------------------------------------------------------------
# 8. The persisted artifact.
# ---------------------------------------------------------------------------
class TestDiagnosticsArtifact:
    def test_diagnostics_are_written_as_a_fifth_artifact(self, tmp_path: Path):
        result = _run(_orchestrator(MockAIProvider()), _request())
        written = write_ai_artifacts(tmp_path, result)

        assert "ai-runtime-diagnostics.json" in written
        assert len(written) == 5

    def test_the_artifact_declares_its_schema_version(self, tmp_path: Path):
        result = _run(_orchestrator(MockAIProvider()), _request())
        write_ai_artifacts(tmp_path, result)

        payload = json.loads(
            (tmp_path / "ai-runtime-diagnostics.json").read_text(encoding="utf-8")
        )
        assert payload["schema_version"] == "ai-runtime-diagnostics-v1"

    def test_the_artifact_round_trips_back_into_the_model(self, tmp_path: Path):
        result = _run(_orchestrator(MockAIProvider()), _request())
        write_ai_artifacts(tmp_path, result)

        payload = json.loads(
            (tmp_path / "ai-runtime-diagnostics.json").read_text(encoding="utf-8")
        )
        assert AIRuntimeDiagnostic.model_validate(payload).outcome == "ok"

    def test_no_artifact_is_written_without_a_diagnostic(self, tmp_path: Path):
        result = _run(_orchestrator(MockAIProvider()), _request())
        stripped = dataclasses.replace(result, diagnostic=None)
        written = write_ai_artifacts(tmp_path, stripped)

        assert "ai-runtime-diagnostics.json" not in written
        assert not (tmp_path / "ai-runtime-diagnostics.json").exists()

    def test_the_artifact_contains_no_api_key(self, tmp_path: Path):
        provider = MockAIProvider()
        # The key is never handed to the orchestrator; assert the artifact is
        # clean regardless.
        object.__setattr__(provider, "_never_read_key", _FAKE_KEY)
        result = _run(_orchestrator(provider), _request())
        write_ai_artifacts(tmp_path, result)

        text = (tmp_path / "ai-runtime-diagnostics.json").read_text(encoding="utf-8")
        assert _FAKE_KEY not in text
        assert "sk-" not in text

    def test_the_artifact_contains_no_prompt_or_response_text(self, tmp_path: Path):
        result = _run(_orchestrator(MockAIProvider()), _request())
        write_ai_artifacts(tmp_path, result)

        text = (tmp_path / "ai-runtime-diagnostics.json").read_text(encoding="utf-8")
        for forbidden in (
            "Authorization",
            "system_prompt",
            "user_prompt",
            "mock synthesis summary",
        ):
            assert forbidden not in text

    def test_the_artifact_holds_only_observable_runtime_fields(self, tmp_path: Path):
        result = _run(_orchestrator(MockAIProvider()), _request())
        write_ai_artifacts(tmp_path, result)

        payload = json.loads(
            (tmp_path / "ai-runtime-diagnostics.json").read_text(encoding="utf-8")
        )
        assert set(payload) == {
            "schema_version", "task_id", "model", "provider_profile",
            "thinking_mode", "enabled", "usage", "rounds", "errors",
            "total_rounds", "total_retries", "cache_hit", "cache_enabled",
            "deterministic_fallback", "outcome", "generated_at",
            # M7B (Section 八/九) — plan-source + dynamic-strategy + report
            # provenance stamped on the runtime artifact. These are observable
            # secret-free fields (codes/labels/booleans), extended alongside the
            # ai-plan-validation-v2 artifact's parallel fields.
            "plan_source", "planning_failed", "deterministic_plan_fallback",
            "requested_strategy", "effective_strategy", "repair_attempted",
            "repair_succeeded", "fallback_used", "validation_error_code",
            "validation_json_path", "normalized", "normalization_reason",
            "target_running", "preflight_changed", "report_source",
        }

    def test_the_artifact_records_the_compat_profile_and_thinking_mode(
        self, tmp_path: Path
    ):
        orch = _orchestrator(
            MockAIProvider(), provider_profile="deepseek", thinking_mode="disabled"
        )
        result = _run(orch, _request())

        assert result.diagnostic.provider_profile == "deepseek"
        assert result.diagnostic.thinking_mode == "disabled"

    def test_the_artifact_records_the_task_id_and_model(self, tmp_path: Path):
        result = _run(_orchestrator(MockAIProvider(model="deepseek-v4-flash")),
                      _request(task_id="t-9"))

        assert result.diagnostic.task_id == "t-9"
        assert result.diagnostic.model == "deepseek-v4-flash"

    def test_generated_at_is_an_iso_utc_timestamp(self):
        result = _run(_orchestrator(MockAIProvider()), _request())

        assert result.diagnostic.generated_at.endswith("Z")

    def test_missing_parent_directories_are_created(self, tmp_path: Path):
        result = _run(_orchestrator(MockAIProvider()), _request())
        nested = tmp_path / "runs" / "t-diag"

        written = write_ai_artifacts(nested, result)
        assert (nested / "ai-runtime-diagnostics.json").exists()
        assert len(written) == 5

    def test_a_write_failure_never_breaks_the_pipeline(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ):
        import app.ai.orchestrator as orchestrator_module

        def boom(*_args: Any, **_kwargs: Any):
            raise OSError("disk full")

        monkeypatch.setattr(orchestrator_module, "atomic_write_json", boom)
        result = _run(_orchestrator(MockAIProvider()), _request())

        # Artifact persistence is best-effort; failures are swallowed, not raised.
        assert write_ai_artifacts(tmp_path, result) == {}


def _all_keys(value: Any) -> set[str]:
    """Every dict key appearing anywhere in a nested JSON-like structure."""
    keys: set[str] = set()
    if isinstance(value, dict):
        for key, child in value.items():
            keys.add(key)
            keys |= _all_keys(child)
    elif isinstance(value, list):
        for child in value:
            keys |= _all_keys(child)
    return keys


def test_m7b_missing_schema_version_is_normalized_without_changing_steps():
    payload = {"objective": "o", "steps": [{"tool_name": "static_analysis", "arguments": {}}]}
    normalized = _normalize_plan_envelope(payload)
    assert normalized.applied is True
    assert normalized.fields == ("schema_version",)
    assert normalized.reason_codes == ("missing_schema_version",)
    assert normalized.payload["schema_version"] == "ai-plan-v1"
    assert normalized.payload["steps"] == payload["steps"]


def test_m7b_envelope_normalizer_does_not_rewrite_invalid_tool_or_arguments():
    payload = {"steps": [{"tool_name": "not_whitelisted", "arguments": {"device": "x"}}]}
    normalized = _normalize_plan_envelope(payload)
    assert normalized.applied is True
    assert normalized.payload["steps"] == payload["steps"]
