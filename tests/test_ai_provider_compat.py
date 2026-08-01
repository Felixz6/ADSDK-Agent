"""M6C backend tests — DeepSeek V4 provider compatibility.

These tests exercise the OpenAI-compatible provider's DeepSeek-specific
compatibility surface WITHOUT touching the network and WITHOUT real sleeps:

* request shape (top-level ``"thinking": {"type": "disabled"}`` injection),
* provider profile detection (auto/explicit/unknown/host-based),
* ``_thinking_disabled_for`` matrix,
* ``_classify_http`` for every status in the unified error vocabulary,
* ``_parse_retry_after`` and ``_retry_delay_seconds`` (Retry-After +
  exponential fallback + ceiling cap),
* robust ``_extract_json_object`` parsing,
* ``_parse_chat_completion`` usage provenance + ``reasoning_content_present``
  boolean-only isolation,
* retry-then-success, non-retryable auth/model errors, retryable
  timeout/unreachable/rate-limited.

All HTTP is driven through ``httpx.MockTransport`` (injected as ``transport``)
and all sleeps through an injectable recorder — no real DeepSeek call, no real
``time.sleep``. No API key material ever leaves the bearer header; we never
assert on the secret value.
"""

from __future__ import annotations

import json

import httpx
import pytest

from app.ai.provider import (
    OpenAICompatibleProvider,
    PROFILE_DEEPSEEK,
    PROFILE_GENERIC_OPENAI,
    ProviderError,
    ProviderResponse,
    _balanced_object_slice,
    _detect_profile,
    _extract_json_object,
    _parse_chat_completion,
    _thinking_disabled_for,
)
# ``_classify_http`` and ``_parse_retry_after``/``_retry_delay_seconds`` are
# bound methods on OpenAICompatibleProvider, exercised via instance calls
# below. ``_balanced_object_slice``/``_extract_json_object``/
# ``_parse_chat_completion`` are module functions.

# A non-secret placeholder key used only to satisfy is_configured(). The
# tests never assert on its value and never print it.
_KEY = "sk-test-never-commit-this-value-12345"
_DEEPSEEK_BASE = "https://api.deepseek.com/v1"
_GENERIC_BASE = "https://api.openai.com/v1"


def _ok(body: dict) -> httpx.Response:
    """A 200 chat-completions response carrying ``body`` as the JSON envelope."""
    return httpx.Response(200, json=body)


def _provider(base_url: str = _DEEPSEEK_BASE, **kw) -> OpenAICompatibleProvider:
    """Build a provider with a test transport + recorded sleep by default."""
    sleeps: list[float] = []
    kw.setdefault("api_key", _KEY)
    kw.setdefault("model", "deepseek-v4-flash")
    kw.setdefault("transport", httpx.MockTransport(lambda req: _ok(_simple_body())))
    kw.setdefault("sleep", lambda s: sleeps.append(s))
    p = OpenAICompatibleProvider(base_url=base_url, **kw)
    # Expose the recorder for tests that assert on sleeps.
    object.__setattr__(p, "_test_sleeps", sleeps)
    return p


def _simple_body() -> dict:
    return {
        "choices": [
            {
                "message": {"content": json.dumps({"ok": 1})},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7},
        "model": "deepseek-v4-flash",
    }


def _capture_payload(handler) -> dict[str, httpx.Request]:
    """Wrap a handler so the raw posted request (payload) is captured."""
    captured: dict[str, httpx.Request] = {"req": None}  # type: ignore

    def _w(req: httpx.Request) -> httpx.Response:
        captured["req"] = req
        return handler(req)

    return captured  # type: ignore


# ---------------------------------------------------------------------------
# 1. DeepSeek V4 request compatibility — top-level thinking-disabled.
# ---------------------------------------------------------------------------
class TestDeepSeekRequestCompat:
    def test_deepseek_default_injects_thinking_disabled_top_level(self):
        """A deepseek-profile call with default thinking sends thinking:disabled."""

        captured: dict[str, httpx.Request] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["req"] = req
            return _ok(_simple_body())

        p = OpenAICompatibleProvider(
            base_url=_DEEPSEEK_BASE,
            api_key=_KEY,
            model="deepseek-v4-flash",
            transport=httpx.MockTransport(handler),
        )
        p.call(system_prompt="s", user_prompt="u", tools=[], max_input_tokens=10, max_output_tokens=10)

        posted = json.loads(captured["req"].content.decode("utf-8"))
        assert posted["thinking"] == {"type": "disabled"}

    def test_thinking_field_present_only_when_thinking_disabled(self):
        """thinking_mode='off' omits the field; 'disabled' (default) keeps it."""

        def make(thinking_mode: str):
            captured: dict[str, httpx.Request] = {}

            def handler(req: httpx.Request) -> httpx.Response:
                captured["req"] = req
                return _ok(_simple_body())

            p = OpenAICompatibleProvider(
                base_url=_DEEPSEEK_BASE,
                api_key=_KEY,
                model="m",
                transport=httpx.MockTransport(handler),
                thinking_mode=thinking_mode,
            )
            p.call(
                system_prompt="s", user_prompt="u", tools=[],
                max_input_tokens=10, max_output_tokens=10,
            )
            return json.loads(captured["req"].content.decode("utf-8"))

        assert "thinking" in make("disabled")
        assert "thinking" not in make("off")

    def test_payload_contains_model_messages_temperature_maxtokens_response_format(self):
        """The base request fields match the OpenAI chat-completions shape."""

        captured: dict[str, httpx.Request] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["req"] = req
            return _ok(_simple_body())

        p = OpenAICompatibleProvider(
            base_url=_DEEPSEEK_BASE, api_key=_KEY, model="deepseek-v4-flash",
            transport=httpx.MockTransport(handler), thinking_mode="off",
        )
        p.call(system_prompt="SYS", user_prompt="USR", tools=[],
               max_input_tokens=10, max_output_tokens=42)

        posted = json.loads(captured["req"].content.decode("utf-8"))
        assert posted["model"] == "deepseek-v4-flash"
        assert posted["messages"] == [
            {"role": "system", "content": "SYS"},
            {"role": "user", "content": "USR"},
        ]
        assert posted["temperature"] == 0.2
        assert posted["max_tokens"] == 42
        assert posted["response_format"] == {"type": "json_object"}

    def test_tools_catalogue_appended_to_user_content(self):
        """A non-empty tools list is attached to the user prompt, not native FC."""

        captured: dict[str, httpx.Request] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["req"] = req
            return _ok(_simple_body())

        p = OpenAICompatibleProvider(
            base_url=_DEEPSEEK_BASE, api_key=_KEY, model="m",
            transport=httpx.MockTransport(handler), thinking_mode="off",
        )
        p.call(system_prompt="s", user_prompt="USR",
               tools=[{"name": "static_analysis"}],
               max_input_tokens=10, max_output_tokens=10)

        posted = json.loads(captured["req"].content.decode("utf-8"))
        assert posted["messages"][1]["content"] == (
            "USR" + "\n\nAvailable tools:\n"
            + json.dumps([{"name": "static_analysis"}])
        )

    def test_chat_url_targets_chat_completions(self):
        """The request goes to ``<base>/chat/completions``."""

        captured: dict[str, httpx.Request] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["req"] = req
            return _ok(_simple_body())

        p = OpenAICompatibleProvider(
            base_url="https://api.deepseek.com/v1/",  # trailing slash
            api_key=_KEY, model="m",
            transport=httpx.MockTransport(handler), thinking_mode="off",
        )
        p.call(system_prompt="s", user_prompt="u", tools=[],
               max_input_tokens=10, max_output_tokens=10)

        assert captured["req"].url.path.rstrip("/") == "/v1/chat/completions"


# ---------------------------------------------------------------------------
# 2. Provider profile detection.
# ---------------------------------------------------------------------------
class TestDetectProfile:
    @pytest.mark.parametrize(
        "base_url, explicit, expected",
        [
            # auto (host-based)
            ("https://api.deepseek.com/v1", None, PROFILE_DEEPSEEK),
            ("https://api.deepseek.com/v1", "auto", PROFILE_DEEPSEEK),
            ("https://API.DEEPSEEK.COM/v1", "auto", PROFILE_DEEPSEEK),
            ("https://api.openai.com/v1", "auto", PROFILE_GENERIC_OPENAI),
            ("https://gateway.example.com/v1", "auto", PROFILE_GENERIC_OPENAI),
            # explicit
            ("https://api.openai.com/v1", "deepseek", PROFILE_DEEPSEEK),
            ("https://api.deepseek.com/v1", "generic_openai", PROFILE_GENERIC_OPENAI),
            ("https://api.deepseek.com/v1", "DEEPSEEK", PROFILE_DEEPSEEK),
            ("https://api.deepseek.com/v1", " GENERIC_OPENAI ", PROFILE_GENERIC_OPENAI),
            ("https://api.deepseek.com/v1", "", PROFILE_DEEPSEEK),
            # unknown explicit -> host-based fallback
            ("https://api.deepseek.com/v1", "bogus", PROFILE_DEEPSEEK),
            ("https://api.openai.com/v1", "bogus", PROFILE_GENERIC_OPENAI),
        ],
    )
    def test_detection_matrix(self, base_url, explicit, expected):
        assert _detect_profile(base_url, explicit) == expected

    def test_provider_profile_property_uses_base_url_and_choice(self):
        p_ds = OpenAICompatibleProvider(
            base_url=_DEEPSEEK_BASE, api_key=_KEY, model="m")
        assert p_ds.profile == PROFILE_DEEPSEEK
        p_gen = OpenAICompatibleProvider(
            base_url=_GENERIC_BASE, api_key=_KEY, model="m",
            provider_profile="auto",
        )
        assert p_gen.profile == PROFILE_GENERIC_OPENAI
        # Explicit override wins over host.
        p_override = OpenAICompatibleProvider(
            base_url=_GENERIC_BASE, api_key=_KEY, model="m",
            provider_profile="deepseek",
        )
        assert p_override.profile == PROFILE_DEEPSEEK

    def test_call_profile_override_resolves_eff_profile(self):
        """Per-call ``profile=`` overrides construction-time resolution."""
        captured: dict[str, httpx.Request] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["req"] = req
            return _ok(_simple_body())

        p = OpenAICompatibleProvider(
            base_url=_GENERIC_BASE, api_key=_KEY, model="m",
            transport=httpx.MockTransport(handler),
            thinking_mode="auto",  # inject only when profile==deepseek
        )
        # Override to deepseek at call time -> the thinking field must appear.
        p.call(system_prompt="s", user_prompt="u", tools=[],
               max_input_tokens=10, max_output_tokens=10, profile="deepseek")
        posted = json.loads(captured["req"].content.decode("utf-8"))
        assert posted["thinking"] == {"type": "disabled"}


# ---------------------------------------------------------------------------
# 3. _thinking_disabled_for matrix.
# ---------------------------------------------------------------------------
class TestThinkingDisabledFor:
    @pytest.mark.parametrize(
        "profile, thinking_mode, expected",
        [
            (PROFILE_DEEPSEEK, "disabled", True),
            (PROFILE_DEEPSEEK, "auto", True),
            (PROFILE_DEEPSEEK, "off", False),
            (PROFILE_DEEPSEEK, "", True),          # empty -> default disabled
            (PROFILE_DEEPSEEK, None, True),       # None -> default disabled
            (PROFILE_DEEPSEEK, "unknown", True),  # unknown -> deterministic
            (PROFILE_DEEPSEEK, "DISABLED", True), # case-insensitive
            (PROFILE_DEEPSEEK, "AUTO", True),
            (PROFILE_DEEPSEEK, "OFF", False),
            (PROFILE_GENERIC_OPENAI, "disabled", True),  # injected (harmless)
            (PROFILE_GENERIC_OPENAI, "auto", False),      # only for deepseek
            (PROFILE_GENERIC_OPENAI, "off", False),
            (PROFILE_GENERIC_OPENAI, "unknown", True),
        ],
    )
    def test_matrix(self, profile, thinking_mode, expected):
        assert _thinking_disabled_for(profile, thinking_mode) is expected


# ---------------------------------------------------------------------------
# 4. _classify_http — unified error vocabulary + retryability + Retry-After.
# ---------------------------------------------------------------------------
def _resp(status: int, *, retry_after: str | None = None) -> httpx.Response:
    headers = {}
    if retry_after is not None:
        headers["Retry-After"] = retry_after
    return httpx.Response(status, json={"error": "x"}, headers=headers)


class TestClassifyHttp:
    def test_2xx_returns_none(self):
        p = _provider()
        assert p._classify_http(httpx.Response(200, json={})) is None
        assert p._classify_http(httpx.Response(204, json={})) is None
        assert p._classify_http(httpx.Response(299, json={})) is None

    @pytest.mark.parametrize("status", [400, 405, 418, 422])
    def test_other_4xx_is_ai_provider_error_non_retryable(self, status):
        p = _provider()
        err = p._classify_http(_resp(status))
        assert err is not None
        assert err.code == "ai_provider_error"
        assert err.retryable is False
        assert err.status_code == status

    @pytest.mark.parametrize("status, code", [(401, "ai_provider_authentication_failed"),
                                              (403, "ai_provider_authentication_failed")])
    def test_auth_fail_non_retryable(self, status, code):
        p = _provider()
        err = p._classify_http(_resp(status))
        assert err.code == code
        assert err.retryable is False
        assert err.status_code == status

    def test_408_timeout_retryable_reads_retry_after(self):
        p = _provider()
        err = p._classify_http(_resp(408, retry_after="2"))
        assert err.code == "ai_provider_timeout"
        assert err.retryable is True
        assert err.status_code == 408
        assert err.retry_after_ms == 2000

    def test_404_model_not_found_non_retryable(self):
        p = _provider()
        err = p._classify_http(_resp(404))
        assert err.code == "ai_provider_model_not_found"
        assert err.retryable is False
        assert err.status_code == 404

    def test_429_rate_limited_retryable_reads_retry_after(self):
        p = _provider()
        err = p._classify_http(_resp(429, retry_after="1.5"))
        assert err.code == "ai_provider_rate_limited"
        assert err.retryable is True
        assert err.status_code == 429
        assert err.retry_after_ms == 1500

    @pytest.mark.parametrize("status", [500, 502, 503, 504, 599])
    def test_5xx_unreachable_retryable(self, status):
        p = _provider()
        err = p._classify_http(_resp(status, retry_after="3"))
        assert err.code == "ai_provider_unreachable"
        assert err.retryable is True
        assert err.status_code == status
        assert err.retry_after_ms == 3000

    def test_retryable_statuses_without_retry_after_have_none_ms(self):
        """No Retry-After header -> retry_after_ms is None (fall back to base)."""

        p = _provider()
        for status in (408, 429, 500):
            err = p._classify_http(_resp(status))
            assert err.retry_after_ms is None

    @pytest.mark.parametrize("status, expected_code", [
        (408, "ai_provider_timeout"),
        (429, "ai_provider_rate_limited"),
        (500, "ai_provider_unreachable"),
        (404, "ai_provider_model_not_found"),
    ])
    def test_status_to_code_complete(self, status, expected_code):
        p = _provider()
        err = p._classify_http(_resp(status))
        assert err.code == expected_code


# ---------------------------------------------------------------------------
# 5. _parse_retry_after.
# ---------------------------------------------------------------------------
class TestParseRetryAfter:
    @pytest.mark.parametrize("value, expected", [
        (None, None),
        ("", None),
        ("   ", None),
        ("0", 0),
        ("30", 30000),
        ("2.5", 2500),
        ("0.001", 1),                 # rounds down to int ms via truncation
        ("  10 ", 10000),             # surrounding whitespace stripped
        ("Wed, 21 Oct 2025 07:28:00 GMT", None),  # HTTP-date ignored -> None
        ("tomorrow", None),           # non-numeric -> None
        ("nan", None),
        ("1e3", 1000000),              # float-form/scientific parsed
    ])
    def test_matrix(self, value, expected):
        assert OpenAICompatibleProvider._parse_retry_after(value) == expected


# ---------------------------------------------------------------------------
# 6. _retry_delay_seconds — Retry-After honour, exponential fallback, cap.
# ---------------------------------------------------------------------------
class TestRetryDelaySeconds:
    def _err(self, retry_after_ms: int | None = None, retryable: bool = True):
        return ProviderError("ai_provider_rate_limited", "x",
                             retryable=retryable, stage="provider_call",
                             retry_after_ms=retry_after_ms)

    def test_honours_retry_after_when_present(self):
        p = _provider(retry_base_delay_ms=100, max_retry_after_seconds=10)
        assert p._retry_delay_seconds(self._err(retry_after_ms=3000), 0) == 3.0
        assert p._retry_delay_seconds(self._err(retry_after_ms=3000), 3) == 3.0

    def test_exponential_fallback_by_attempt(self):
        p = _provider(retry_base_delay_ms=100, max_retry_after_seconds=60)
        assert p._retry_delay_seconds(self._err(retry_after_ms=None), 0) == 0.1
        assert p._retry_delay_seconds(self._err(retry_after_ms=None), 1) == 0.2
        assert p._retry_delay_seconds(self._err(retry_after_ms=None), 2) == 0.4
        assert p._retry_delay_seconds(self._err(retry_after_ms=None), 3) == 0.8

    def test_cap_clips_retry_after_to_ceiling(self):
        """Retry-After above the ceiling is clipped to the cap."""

        p = _provider(retry_base_delay_ms=100, max_retry_after_seconds=2)
        assert p._retry_delay_seconds(self._err(retry_after_ms=9999), 0) == 2.0

    def test_cap_clips_exponential_to_ceiling(self):
        p = _provider(retry_base_delay_ms=1000, max_retry_after_seconds=5)
        # exponential at attempt 4 would be 1.0*16 = 16s without cap.
        assert p._retry_delay_seconds(self._err(retry_after_ms=None), 4) == 5.0

    @pytest.mark.parametrize("ceiling", [None, 0, None])
    def test_no_ceiling_means_uncapped(self, ceiling):
        p = _provider(retry_base_delay_ms=1000,
                      max_retry_after_seconds=ceiling if ceiling is not None else 0)
        # ceiling 0 -> disabled (never min'd), so exponential grows freely.
        assert p._retry_delay_seconds(self._err(retry_after_ms=None), 5) == 32.0

    def test_zero_retry_after_falls_back_to_exponential(self):
        p = _provider(retry_base_delay_ms=200, max_retry_after_seconds=10)
        assert p._retry_delay_seconds(self._err(retry_after_ms=0), 1) == 0.4

    def test_delay_never_negative(self):
        p = _provider(retry_base_delay_ms=0, max_retry_after_seconds=0)
        assert p._retry_delay_seconds(self._err(retry_after_ms=None), 0) == 0.0


# ---------------------------------------------------------------------------
# 7. _balanced_object_slice — brace matching with strings/escapes.
# ---------------------------------------------------------------------------
class TestBalancedObjectSlice:
    def test_exact_object(self):
        assert _balanced_object_slice('{"a":1}', 0) == '{"a":1}'

    def test_skip_strings_with_braces(self):
        text = '{"k": "a}b"}'
        assert _balanced_object_slice(text, 0) == text

    def test_skip_escaped_quotes(self):
        text = '{"k": "a\\"}b"}'
        assert _balanced_object_slice(text, 0) == text

    def test_nested_objects(self):
        text = '{"a": {"b": 2}, "c": 3}'
        assert _balanced_object_slice(text, 0) == text

    def test_unterminated_returns_none(self):
        assert _balanced_object_slice('{"a": 1', 0) is None

    def test_start_at_offset(self):
        text = 'prefix {"a":1} suffix'
        assert _balanced_object_slice(text, text.index("{")) == '{"a":1}'

    def test_nested_brace_in_string_then_close(self):
        text = '{"k": "}" }'
        assert _balanced_object_slice(text, 0) == '{"k": "}" }'


# ---------------------------------------------------------------------------
# 8. _extract_json_object — robust parsing.
# ---------------------------------------------------------------------------
class TestExtractJsonObject:
    def test_empty_returns_none(self):
        assert _extract_json_object("") is None
        assert _extract_json_object("   ") is None

    def test_whole_string_object(self):
        assert _extract_json_object('{"k": 1}') == {"k": 1}

    def test_fenced_json_block(self):
        text = 'Here:\n```json\n{"ok": 2}\n```'
        assert _extract_json_object(text) == {"ok": 2}

    def test_fenced_bare_block(self):
        text = '```\n{"ok": 3}\n```'
        assert _extract_json_object(text) == {"ok": 3}

    def test_prose_prefix_then_object(self):
        text = "Sure, here is the report:\n" + '{"summary": "x"}'
        assert _extract_json_object(text) == {"summary": "x"}

    def test_object_with_trailing_prose(self):
        text = '{"summary": "y"}\nThat is all.'
        assert _extract_json_object(text) == {"summary": "y"}

    def test_prose_on_both_sides(self):
        text = 'Here: {"k": 9} done'
        assert _extract_json_object(text) == {"k": 9}

    def test_first_object_when_multiple(self):
        text = '{"a": 1} {"b": 2}'
        assert _extract_json_object(text) == {"a": 1}

    def test_array_rejected_returns_none(self):
        assert _extract_json_object('[1, 2, 3]') is None

    def test_scalar_rejected_returns_none(self):
        assert _extract_json_object('42') is None
        assert _extract_json_object('true') is None
        assert _extract_json_object('"just a string"') is None

    def test_nested_object_returns_full(self):
        text = '{"a": {"b": {"c": 1}}}'
        assert _extract_json_object(text) == {"a": {"b": {"c": 1}}}

    def test_object_with_braces_inside_strings(self):
        text = '{"k": "{"}'
        # The string literal "{" should be skipped; the object is whole.
        assert _extract_json_object(text) == {"k": "{"}

    def test_garbage_returns_none(self):
        assert _extract_json_object("not json at all") is None

    def test_unterminated_object_returns_none(self):
        assert _extract_json_object('{"k": 1') is None

    def test_brute_force_finds_buried_object(self):
        text = 'noise "}{ junk "extra ' + '{"found": true}' + ' more noise'
        result = _extract_json_object(text)
        assert result == {"found": True}


# ---------------------------------------------------------------------------
# 9. _parse_chat_completion — usage provenance + reasoning isolation + errors.
# ---------------------------------------------------------------------------
class TestParseChatCompletion:
    def _body(self, *, content=None, reasoning=None, usage=None,
              finish_reason="stop", model="deepseek-v4-flash"):
        message = {}
        if content is not None:
            message["content"] = content
        if reasoning is not None:
            message["reasoning_content"] = reasoning
        return {
            "choices": [{"message": message, "finish_reason": finish_reason}],
            "model": model,
            "usage": usage or {},
        }

    def test_usage_source_provider_when_real_tokens_present(self):
        body = self._body(content='{"k":1}',
                         usage={"prompt_tokens": 10, "completion_tokens": 20})
        r = _parse_chat_completion(body, 50)
        assert r.usage_source == "provider"
        assert r.usage.usage_source == "provider"
        assert r.usage.input_tokens == 10
        assert r.usage.output_tokens == 20
        assert r.usage.cached_tokens is None

    def test_usage_source_unavailable_when_no_real_tokens(self):
        body = self._body(content='{"k":1}', usage={})
        r = _parse_chat_completion(body, 50)
        assert r.usage_source == "unavailable"
        assert r.usage.usage_source == "unavailable"
        assert r.usage.input_tokens is None
        assert r.usage.output_tokens is None

    def test_cached_only_still_counts_as_real(self):
        body = self._body(content='{"k":1}',
                         usage={"cached_tokens": 5})
        r = _parse_chat_completion(body, 50)
        assert r.usage_source == "provider"
        assert r.usage.cached_tokens == 5
        assert r.usage.input_tokens is None
        assert r.usage.output_tokens is None

    def test_finish_reason_propagated(self):
        body = self._body(content='{"k":1}', finish_reason="length")
        r = _parse_chat_completion(body, 50)
        assert r.finish_reason == "length"

    def test_cached_tokens_read_from_prompt_tokens_details(self):
        # Generic OpenAI reports the prompt-cache hit count nested here.
        body = self._body(
            content='{"k":1}',
            usage={
                "prompt_tokens": 262,
                "completion_tokens": 40,
                "prompt_tokens_details": {"cached_tokens": 128},
            },
        )
        r = _parse_chat_completion(body, 50)
        assert r.usage.cached_tokens == 128

    def test_cached_tokens_read_from_deepseek_prompt_cache_hit(self):
        # DeepSeek additionally reports it as a flat prompt_cache_hit_tokens.
        body = self._body(
            content='{"k":1}',
            usage={
                "prompt_tokens": 262,
                "completion_tokens": 40,
                "prompt_cache_hit_tokens": 96,
            },
        )
        r = _parse_chat_completion(body, 50)
        assert r.usage.cached_tokens == 96

    def test_flat_cached_tokens_wins_over_nested(self):
        body = self._body(
            content='{"k":1}',
            usage={
                "cached_tokens": 7,
                "prompt_tokens_details": {"cached_tokens": 128},
                "prompt_cache_hit_tokens": 96,
            },
        )
        r = _parse_chat_completion(body, 50)
        assert r.usage.cached_tokens == 7

    def test_absent_cache_fields_report_none_not_zero(self):
        # "unknown" must stay distinguishable from a real zero-hit report.
        body = self._body(
            content='{"k":1}',
            usage={"prompt_tokens": 10, "completion_tokens": 20},
        )
        r = _parse_chat_completion(body, 50)
        assert r.usage.cached_tokens is None

    def test_malformed_cache_details_are_ignored(self):
        body = self._body(
            content='{"k":1}',
            usage={
                "prompt_tokens": 10,
                "prompt_tokens_details": "not-a-dict",
            },
        )
        r = _parse_chat_completion(body, 50)
        assert r.usage.cached_tokens is None

    def test_truncated_json_content_is_rejected(self):
        # A finish_reason=length response often cuts the object mid-string;
        # it must not be accepted as a complete structured answer.
        body = self._body(content='{"a":1,"b":"unterminated',
                          finish_reason="length")
        with pytest.raises(ProviderError) as exc:
            _parse_chat_completion(body, 50)
        assert exc.value.code == "ai_provider_invalid_json"

    def test_finish_reason_none_when_not_string(self):
        body = self._body(content='{"k":1}', finish_reason=None)
        r = _parse_chat_completion(body, 50)
        assert r.finish_reason is None

    def test_content_json_parsed_object_returned(self):
        r = _parse_chat_completion(self._body(content='{"ok": 1}'), 50)
        assert r.content_json == {"ok": 1}

    def test_reasoning_content_present_only_bool_never_content(self):
        """reasoning_content presence recorded as bool; text never in response."""

        body = self._body(content='{"k":1}',
                         reasoning="secret chain-of-thought thoughts")
        r = _parse_chat_completion(body, 50)
        assert r.reasoning_content_present is True
        # No attribute ever leaks the reasoning text.
        import dataclasses
        values = {f.name: getattr(r, f.name) for f in dataclasses.fields(r)}
        assert "secret" not in json.dumps(values, default=str).lower()
        assert r.content_json == {"k": 1}

    def test_reasoning_content_present_false_when_empty_string(self):
        body = self._body(content='{"k":1}', reasoning="   ")
        r = _parse_chat_completion(body, 50)
        assert r.reasoning_content_present is False

    def test_reasoning_content_present_false_when_absent(self):
        body = self._body(content='{"k":1}')
        r = _parse_chat_completion(body, 50)
        assert r.reasoning_content_present is False

    def test_no_choices_raises_invalid_response(self):
        body = {"choices": [], "usage": {}}
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_response"
        assert ei.value.retryable is False

    def test_choices_not_list_raises_invalid_response(self):
        body = {"choices": "x", "usage": {}}
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_response"

    def test_first_choice_not_dict_raises_invalid_response(self):
        body = {"choices": ["notadict"], "usage": {}}
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_response"

    def test_empty_content_raises_invalid_json(self):
        body = self._body(content="")
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_json"

    def test_whitespace_only_content_raises_invalid_json(self):
        body = self._body(content="   \n  ")
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_json"

    def test_reasoning_only_no_content_raises_invalid_response(self):
        """reasoning_content present but no structured payload -> invalid_response."""

        body = self._body(content="", reasoning="only thoughts here")
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_response"

    def test_content_not_a_string_raises_invalid_json(self):
        body = {"choices": [{"message": {"content": {"x": 1}}, "finish_reason": "stop"}]}
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_json"

    def test_unparseable_content_raises_invalid_json(self):
        body = self._body(content="not json at all")
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_json"

    def test_non_object_content_rejected(self):
        body = self._body(content="[1, 2, 3]")
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_json"

    def test_content_is_array_parsed_to_non_object_raises_invalid_json(self):
        body = self._body(content='[1,2]')
        with pytest.raises(ProviderError) as ei:
            _parse_chat_completion(body, 50)
        assert ei.value.code == "ai_provider_invalid_json"

    def test_model_propagated_from_body(self):
        body = self._body(content='{"k":1}', model="other-model")
        r = _parse_chat_completion(body, 50)
        assert r.usage.model == "other-model"

    def test_latency_ms_propagated(self):
        r = _parse_chat_completion(self._body(content='{"k":1}'), 1234)
        assert r.latency_ms == 1234

    def test_not_configured_raises_ai_not_configured(self):
        """A provider without base_url/key/model short-circuits before any HTTP."""

        p = OpenAICompatibleProvider(
            base_url="", api_key="", model="",
            transport=httpx.MockTransport(lambda r: _ok(_simple_body())),
        )
        with pytest.raises(ProviderError) as ei:
            p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert ei.value.code == "ai_not_configured"
        assert ei.value.retryable is False


# ---------------------------------------------------------------------------
# 10. call() retry/error behaviour — retry-then-success, non/retryable errors.
# ---------------------------------------------------------------------------
class TestCallRetryBehaviour:
    def _provider_with_handler(self, handler, *, retries=1, **kw):
        sleeps: list[float] = []
        kw.setdefault("api_key", _KEY)
        kw.setdefault("model", "m")
        kw.setdefault("transport", httpx.MockTransport(handler))
        kw.setdefault("sleep", lambda s: sleeps.append(s))
        p = OpenAICompatibleProvider(base_url=_DEEPSEEK_BASE, request_retries=retries, **kw)
        return p, sleeps

    def test_retry_then_success_on_429(self):
        """429 (retryable) -> sleep -> 200 with a structured payload."""

        calls = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            if calls["n"] == 1:
                return httpx.Response(429, headers={"Retry-After": "1"})
            return _ok(_simple_body())

        p, sleeps = self._provider_with_handler(handler, retries=1)
        r = p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert r.content_json == {"ok": 1}
        assert r.usage_source == "provider"
        assert r.finish_reason == "stop"
        assert r.reasoning_content_present is False
        assert calls["n"] == 2
        assert len(sleeps) == 1  # one backoff between the two attempts

    def test_auth_fail_is_non_retryable_no_sleep(self):
        """401 is non-retryable: raises immediately, sleep never called."""

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(401)

        p, sleeps = self._provider_with_handler(handler, retries=3)
        with pytest.raises(ProviderError) as ei:
            p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert ei.value.code == "ai_provider_authentication_failed"
        assert ei.value.retryable is False
        assert sleeps == []  # SHOULD-NOT-HAPPEN: no backoff before raising

    def test_model_not_found_is_non_retryable(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(404)

        p, sleeps = self._provider_with_handler(handler, retries=3)
        with pytest.raises(ProviderError) as ei:
            p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert ei.value.code == "ai_provider_model_not_found"
        assert sleeps == []

    def test_other_4xx_is_non_retryable(self):
        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(418)

        p, sleeps = self._provider_with_handler(handler, retries=3)
        with pytest.raises(ProviderError) as ei:
            p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert ei.value.code == "ai_provider_error"
        assert ei.value.retryable is False
        assert sleeps == []

    def test_timeout_retryable_then_success(self):
        """408 -> retry -> 200."""

        calls = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(408) if calls["n"] == 1 else _ok(_simple_body())

        p, sleeps = self._provider_with_handler(handler, retries=1)
        r = p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert r.content_json == {"ok": 1}
        assert calls["n"] == 2
        assert len(sleeps) == 1

    def test_5xx_unreachable_retryable_then_success(self):
        calls = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(503, headers={"Retry-After": "0.5"}) if calls["n"] == 1 else _ok(_simple_body())

        p, sleeps = self._provider_with_handler(handler, retries=1)
        r = p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert r.content_json == {"ok": 1}
        assert calls["n"] == 2
        assert len(sleeps) == 1

    def test_retry_after_cap_honoured(self):
        """Retry-After above max_retry_after_seconds is clipped to the cap."""

        sleeps: list[float] = []

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(503, headers={"Retry-After": "999"})

        p = OpenAICompatibleProvider(
            base_url=_DEEPSEEK_BASE, api_key=_KEY, model="m",
            transport=httpx.MockTransport(handler), request_retries=1,
            sleep=lambda s: sleeps.append(s), max_retry_after_seconds=2,
        )
        with pytest.raises(ProviderError) as ei:
            p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert ei.value.code == "ai_provider_unreachable"
        assert sleeps[0] <= 2.0  # backoff clipped to the 2s ceiling

    def test_exhausts_retries_then_raises_last_error(self):
        """All retryable attempts fail -> last classified error raised."""

        calls = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(500, headers={"Retry-After": "0.1"})

        p, sleeps = self._provider_with_handler(handler, retries=2)
        with pytest.raises(ProviderError) as ei:
            p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert ei.value.code == "ai_provider_unreachable"
        assert calls["n"] == 3  # original + 2 retries
        assert len(sleeps) == 2

    def test_zero_retries_raises_on_first_retryable_error(self):
        calls = {"n": 0}

        def handler(req: httpx.Request) -> httpx.Response:
            calls["n"] += 1
            return httpx.Response(429)

        p, sleeps = self._provider_with_handler(handler, retries=0)
        with pytest.raises(ProviderError) as ei:
            p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert ei.value.code == "ai_provider_rate_limited"
        assert calls["n"] == 1
        assert sleeps == []

    def test_invalid_json_envelope_raises_invalid_json_non_retryable(self):
        """A 200 body that is not valid JSON -> ai_provider_invalid_json."""

        def handler(req: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not json", headers={"content-type": "application/json"})

        p, sleeps = self._provider_with_handler(handler, retries=2)
        with pytest.raises(ProviderError) as ei:
            p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert ei.value.code == "ai_provider_invalid_json"
        assert ei.value.retryable is False
        assert sleeps == []

    def test_response_with_reasoning_content_returns_present_bool(self):
        body = {
            "choices": [{
                "message": {"content": '{"x": 1}', "reasoning_content": "secret thoughts"},
                "finish_reason": "stop",
            }],
            "usage": {"prompt_tokens": 3, "completion_tokens": 4},
        }

        p, sleeps = self._provider_with_handler(lambda r: _ok(body), retries=0)
        r = p.call(system_prompt="s", user_prompt="u", tools=[],
                   max_input_tokens=10, max_output_tokens=10)
        assert r.reasoning_content_present is True
        assert r.content_json == {"x": 1}

    def test_generic_openai_profile_with_auto_thinking_omits_thinking(self):
        """generic_openai + thinking_mode=auto -> no thinking field (harmless skip)."""

        captured: dict[str, httpx.Request] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["req"] = req
            return _ok(_simple_body())

        p = OpenAICompatibleProvider(
            base_url=_GENERIC_BASE, api_key=_KEY, model="m",
            transport=httpx.MockTransport(handler), thinking_mode="auto",
        )
        p.call(system_prompt="s", user_prompt="u", tools=[],
               max_input_tokens=10, max_output_tokens=10)
        posted = json.loads(captured["req"].content.decode("utf-8"))
        assert "thinking" not in posted

    def test_bearer_header_present_with_key(self):
        """Authorization uses the bearer scheme; the header is always sent."""

        captured: dict[str, httpx.Request] = {}

        def handler(req: httpx.Request) -> httpx.Response:
            captured["req"] = req
            return _ok(_simple_body())

        p = OpenAICompatibleProvider(
            base_url=_DEEPSEEK_BASE, api_key=_KEY, model="m",
            transport=httpx.MockTransport(handler), thinking_mode="off",
        )
        p.call(system_prompt="s", user_prompt="u", tools=[],
               max_input_tokens=10, max_output_tokens=10)
        assert captured["req"].headers["Authorization"].startswith("Bearer ")
        assert captured["req"].headers["Content-Type"] == "application/json"
