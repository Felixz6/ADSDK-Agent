"""OpenAI-compatible and DeepSeek provider implementation."""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

import httpx

from app.config import (
    AI_API_KEY,
    AI_BASE_URL,
    AI_MAX_RETRY_AFTER_SECONDS,
    AI_MODEL,
    AI_PROVIDER_PROFILE,
    AI_REQUEST_RETRIES,
    AI_RETRY_BASE_DELAY_MS,
    AI_THINKING_MODE,
    AI_TIMEOUT_SECONDS,
)

from .base import (
    ProviderCompatibilityProfile,
    ProviderError,
    ProviderResponse,
    ProviderUsage,
    _cached_tokens_from_usage,
    _detect_profile,
    _extract_json_object,
    _thinking_disabled_for,
)


class OpenAICompatibleProvider:
    """Talks to any OpenAI-compatible ``/chat/completions`` endpoint."""

    def __init__(
        self,
        *,
        base_url: str | None = None,
        api_key: str | None = None,
        model: str | None = None,
        timeout_seconds: float | None = None,
        transport: httpx.BaseTransport | None = None,
        provider_profile: str | None = None,
        thinking_mode: str | None = None,
        request_retries: int | None = None,
        retry_base_delay_ms: int | None = None,
        max_retry_after_seconds: int | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self._base_url = (base_url if base_url is not None else AI_BASE_URL).strip()
        self._api_key = api_key if api_key is not None else AI_API_KEY
        self._model = (model if model is not None else AI_MODEL).strip()
        self._timeout = timeout_seconds if timeout_seconds is not None else AI_TIMEOUT_SECONDS
        # ``transport`` is injected by tests; production builds the client
        # lazily so importing this module never opens a socket.
        self._transport = transport
        # M6C compatibility knobs. ``_profile`` is resolved at construction
        # (from explicit choice or base_url host) and re-resolvable per call
        # when the caller supplies an override. These are non-secret.
        self._profile_choice = (
            provider_profile if provider_profile is not None else AI_PROVIDER_PROFILE
        )
        self._thinking_mode = thinking_mode if thinking_mode is not None else AI_THINKING_MODE
        self._request_retries = (
            request_retries if request_retries is not None else AI_REQUEST_RETRIES
        )
        self._retry_base_delay_ms = (
            retry_base_delay_ms if retry_base_delay_ms is not None else AI_RETRY_BASE_DELAY_MS
        )
        self._max_retry_after_seconds = (
            max_retry_after_seconds
            if max_retry_after_seconds is not None
            else AI_MAX_RETRY_AFTER_SECONDS
        )
        # Injectable sleep so tests never call time.sleep. Defaults to the real
        # one; tests inject a no-op or recorder. Never used when retries == 0.
        self._sleep: Callable[[float], None] = sleep if sleep is not None else time.sleep

    name = "openai_compatible"

    @property
    def model(self) -> str:
        return self._model

    @property
    def profile(self) -> ProviderCompatibilityProfile:
        """The resolved compatibility profile (from construction-time base_url)."""

        return _detect_profile(self._base_url, self._profile_choice)

    def is_configured(self) -> bool:
        return bool(self._base_url and self._api_key and self._model)

    def configuration_error(self) -> dict[str, Any] | None:
        missing = [
            name
            for name, value in (
                ("AI_BASE_URL", self._base_url),
                ("AI_API_KEY", self._api_key),
                ("AI_MODEL", self._model),
            )
            if not value
        ]
        if not missing:
            return None
        return {
            "error_code": "ai_not_configured",
            "safe_message": "AI provider is missing configuration: " + ", ".join(missing),
            "missing": missing,
        }

    def _client(self) -> httpx.Client:
        if self._transport is not None:
            return httpx.Client(transport=self._transport, timeout=self._timeout)
        return httpx.Client(timeout=self._timeout)

    def _make_client(self) -> httpx.Client:
        """Build a fresh client for a single request scope.

        When a transport is injected (tests), we wrap it in a throwaway
        :class:`httpx.Client` so each probe attempt gets its own close-able
        scope (``with`` can only be entered once per instance). When no
        transport is injected, this is identical to :meth:`_client`.
        """

        if self._transport is not None:
            return httpx.Client(transport=self._transport, timeout=self._timeout)
        return httpx.Client(timeout=self._timeout)

    def _chat_url(self) -> str:
        base = self._base_url.rstrip("/")
        return f"{base}/chat/completions"

    def _build_payload(
        self,
        *,
        system_prompt: str,
        user_prompt: str,
        tools: list[dict[str, Any]],
        max_output_tokens: int,
        profile: ProviderCompatibilityProfile,
        thinking_mode: str,
    ) -> dict[str, Any]:
        """Assemble the chat-completions request body.

        DeepSeek compat: when thinking is disabled for this profile/mode we send
        ``"thinking": {"type": "disabled"}`` so the model never emits
        ``reasoning_content`` (keeps responses deterministic and token-cheap).

        This is a raw HTTP call, so the field goes at the TOP LEVEL of the JSON
        body. ``extra_body`` is an OpenAI *SDK* convention: the SDK merges those
        keys into the body before sending, so a literal ``extra_body`` object is
        not part of the wire protocol and every gateway silently ignores it.
        Unknown top-level keys are ignored by generic OpenAI hosts.
        """

        payload: dict[str, Any] = {
            "model": self._model,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            "temperature": 0.2,
            "max_tokens": max_output_tokens,
            "response_format": {"type": "json_object"},
        }
        if tools:
            # We pass the tool catalogue as part of the user prompt rather
            # than native function-calling: the orchestrator wants a single
            # structured plan/report object, not an open tool-call loop.
            payload["messages"][1]["content"] = (
                user_prompt + "\n\nAvailable tools:\n" + json.dumps(tools)
            )
        if _thinking_disabled_for(profile, thinking_mode):
            payload["thinking"] = {"type": "disabled"}
        return payload

    def call(
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
        if not self.is_configured():
            raise ProviderError(
                "ai_not_configured",
                "AI provider is not configured",
                retryable=False,
                stage="provider_call",
            )
        eff_profile = profile if profile is not None else self.profile
        eff_thinking = thinking_mode if thinking_mode is not None else self._thinking_mode
        payload = self._build_payload(
            system_prompt=system_prompt,
            user_prompt=user_prompt,
            tools=tools,
            max_output_tokens=max_output_tokens,
            profile=eff_profile,
            thinking_mode=eff_thinking,
        )
        retries = max(0, int(self._request_retries))
        started = time.perf_counter()
        last_error: ProviderError | None = None
        for attempt in range(retries + 1):
            try:
                with self._make_client() as client:
                    response = client.post(
                        self._chat_url(),
                        json=payload,
                        headers=self._auth_headers(),
                        timeout=self._timeout,
                    )
            except httpx.TimeoutException:
                last_error = ProviderError(
                    "ai_provider_timeout",
                    "AI provider call timed out",
                    retryable=True,
                    stage="provider_call",
                )
            except httpx.HTTPError:
                last_error = ProviderError(
                    "ai_provider_unreachable",
                    "AI provider is unreachable",
                    retryable=True,
                    stage="provider_call",
                )
            else:
                err = self._classify_http(response)
                if err is None:
                    # Success path — parse and return.
                    latency_ms = int((time.perf_counter() - started) * 1000)
                    try:
                        body = response.json()
                    except Exception as exc:
                        raise ProviderError(
                            "ai_provider_invalid_json",
                            "AI provider returned non-JSON envelope",
                            retryable=False,
                            stage="provider_call",
                        ) from exc
                    return _parse_chat_completion(
                        body,
                        latency_ms,
                        profile=eff_profile,
                    )
                last_error = err
            # Retry decision.
            if attempt < retries and last_error is not None and last_error.retryable:
                self._sleep(self._retry_delay_seconds(last_error, attempt))
                continue
            # No more retries (or non-retryable): raise the classified error.
            assert last_error is not None
            raise last_error

        assert last_error is not None
        raise last_error

    def _retry_delay_seconds(self, error: ProviderError, attempt: int) -> float:
        """Compute a deterministic backoff delay.

        Honours the server's ``Retry-After`` (when present and within the
        configured ceiling), else falls back to exponential growth of the base
        delay keyed by attempt (no real randomness — reproducible in tests).
        """

        if error.retry_after_ms is not None and error.retry_after_ms > 0:
            secs = error.retry_after_ms / 1000.0
        else:
            base = max(0, int(self._retry_base_delay_ms)) / 1000.0
            secs = base * (2**attempt)
        ceiling = max(0, int(self._max_retry_after_seconds))
        if ceiling > 0:
            secs = min(secs, float(ceiling))
        return max(0.0, secs)

    @staticmethod
    def _parse_retry_after(value: str | None) -> int | None:
        """Parse a ``Retry-After`` header into milliseconds, or ``None``.

        Supports an integer seconds form (``"30"``). The HTTP-date form is
        intentionally ignored (we never rely on wall-clock for backoff in
        tests); its absence yields ``None`` so we fall back to base delay.
        """

        if not value:
            return None
        raw = value.strip()
        try:
            return int(float(raw) * 1000)
        except ValueError:
            return None

    def _classify_http(self, response: httpx.Response) -> ProviderError | None:
        """Translate an HTTP response into a structured ``ProviderError``.

        Returns ``None`` for 2xx (success). Otherwise maps to the unified
        error vocabulary, sets retryability from status semantics, and parses
        ``Retry-After`` when the status is retryable. Messages never reveal the
        key; the status code is the only server-derived detail kept.
        """

        status = response.status_code
        if status < 400:
            return None
        retry_after_ms = self._parse_retry_after(response.headers.get("Retry-After"))
        if status == 401 or status == 403:
            return ProviderError(
                "ai_provider_authentication_failed",
                f"AI provider rejected credentials (HTTP {status})",
                retryable=False,
                stage="provider_call",
                status_code=status,
            )
        if status == 408:
            return ProviderError(
                "ai_provider_timeout",
                f"AI provider timed out (HTTP {status})",
                retryable=True,
                stage="provider_call",
                status_code=status,
                retry_after_ms=retry_after_ms,
            )
        if status == 404:
            return ProviderError(
                "ai_provider_model_not_found",
                f"AI provider model not found (HTTP {status})",
                retryable=False,
                stage="provider_call",
                status_code=status,
            )
        if status == 429:
            return ProviderError(
                "ai_provider_rate_limited",
                f"AI provider rate limited (HTTP {status})",
                retryable=True,
                stage="provider_call",
                status_code=status,
                retry_after_ms=retry_after_ms,
            )
        if status >= 500:
            return ProviderError(
                "ai_provider_unreachable",
                f"AI provider server error (HTTP {status})",
                retryable=True,
                stage="provider_call",
                status_code=status,
                retry_after_ms=retry_after_ms,
            )
        # Other 4xx: malformed request / unsupported configuration.
        return ProviderError(
            "ai_provider_error",
            f"AI provider rejected request (HTTP {status})",
            retryable=False,
            stage="provider_call",
            status_code=status,
        )

    def _auth_headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    def reachable(self) -> tuple[bool, str | None]:
        if not self.is_configured():
            return False, "not_configured"
        try:
            with self._client() as client:
                # A lightweight models-capability probe; many OpenAI-compatible
                # gateways expose ``/models``. We treat any 2xx as reachable.
                client.get(
                    f"{self._base_url.rstrip('/')}/models",
                    headers=self._auth_headers(),
                    timeout=min(self._timeout, 10.0),
                )
        except httpx.HTTPError:
            return False, "unreachable"
        return True, None

    # ------------------------------------------------------------------
    # Structured reachability probe used by POST /ai/settings/test.
    #
    # Strategy (per M6B): do not depend on ``/models`` alone. Some OpenAI-
    # compatible gateways return 404/405 for ``/models`` while still serving
    # ``/chat/completions``. So:
    #
    #   1. Try ``GET /models`` — a 2xx means reachable.
    #   2. On 404/405 (or any non-2xx that is not an auth failure), fall back
    #      to a minimal chat completion with ``max_tokens=1`` and a fixed
    #      short prompt. No tools, no response_format, no report/cache.
    #   3. 401/403 from either probe → ``authentication_failed``.
    #   4. Any timeout → ``timeout``. Other transport errors → unreachable.
    #
    # The probe names which path it took via ``models_endpoint_supported``.
    # The returned message is safe (no key, no host echo beyond what the
    # caller already supplied).
    # ------------------------------------------------------------------
    _PROBE_PROMPT = "ping"

    def probe_reachable(self, *, timeout_seconds: float | None = None) -> dict[str, Any]:
        """Return a structured reachability dict; never raises, never logs key."""

        if not self.is_configured():
            return {
                "status": "invalid_configuration",
                "provider": self.name,
                "model": self._model,
                "latency_ms": 0,
                "safe_message": "缺少 base_url / api_key / model",
                "models_endpoint_supported": False,
            }
        timeout = float(timeout_seconds if timeout_seconds is not None else self._timeout)
        started = time.perf_counter()

        # Step 1: /models.
        try:
            with self._make_client() as client:
                models_resp = client.get(
                    f"{self._base_url.rstrip('/')}/models",
                    headers=self._auth_headers(),
                    timeout=min(timeout, 10.0),
                )
        except httpx.TimeoutException:
            return self._probe_failure("timeout", "探测超时", started)
        except httpx.HTTPError:
            return self._probe_failure("unreachable", "网关不可达", started)

        if models_resp.status_code in (401, 403):
            return self._probe_failure("authentication_failed", "鉴权失败", started)
        if 200 <= models_resp.status_code < 300:
            return {
                "status": "reachable",
                "provider": self.name,
                "model": self._model,
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "safe_message": "通过 /models 探测成功",
                "models_endpoint_supported": True,
            }

        # Step 2: minimal chat fallback (e.g. /models returned 404/405).
        chat_payload = {
            "model": self._model,
            "messages": [{"role": "user", "content": self._PROBE_PROMPT}],
            "max_tokens": 1,
            "temperature": 0,
        }
        try:
            with self._make_client() as client:
                chat_resp = client.post(
                    self._chat_url(),
                    json=chat_payload,
                    headers=self._auth_headers(),
                    timeout=timeout,
                )
        except httpx.TimeoutException:
            return self._probe_failure(
                "timeout",
                "探测超时（最小聊天探测）",
                started,
                models_supported=False,
            )
        except httpx.HTTPError:
            return self._probe_failure(
                "unreachable",
                "网关不可达（最小聊天探测）",
                started,
                models_supported=False,
            )

        if chat_resp.status_code in (401, 403):
            return self._probe_failure(
                "authentication_failed", "鉴权失败", started, models_supported=False
            )
        if 200 <= chat_resp.status_code < 300:
            return {
                "status": "reachable",
                "provider": self.name,
                "model": self._model,
                "latency_ms": int((time.perf_counter() - started) * 1000),
                "safe_message": "通过最小聊天探测成功（/models 不可用）",
                "models_endpoint_supported": False,
            }
        if chat_resp.status_code >= 400:
            return self._probe_failure(
                "invalid_configuration",
                f"网关返回 HTTP {chat_resp.status_code}",
                started,
                models_supported=False,
            )
        return self._probe_failure("unreachable", "网关响应异常", started, models_supported=False)

    def _probe_failure(
        self,
        status: str,
        safe_message: str,
        started: float,
        *,
        models_supported: bool | None = None,
    ) -> dict[str, Any]:
        return {
            "status": status,
            "provider": self.name,
            "model": self._model,
            "latency_ms": int((time.perf_counter() - started) * 1000),
            "safe_message": safe_message,
            "models_endpoint_supported": bool(models_supported),
        }


def _parse_chat_completion(
    body: dict[str, Any],
    latency_ms: int,
    *,
    profile: ProviderCompatibilityProfile | None = None,
) -> ProviderResponse:
    choices = body.get("choices") or []
    if not choices or not isinstance(choices, list):
        raise ProviderError(
            "ai_provider_invalid_response",
            "AI provider response had no choices",
            retryable=False,
            stage="provider_call",
        )
    first = choices[0]
    if not isinstance(first, dict):
        raise ProviderError(
            "ai_provider_invalid_response",
            "AI provider response choice was malformed",
            retryable=False,
            stage="provider_call",
        )
    message = first.get("message") if isinstance(first.get("message"), dict) else {}
    content = message.get("content") if isinstance(message, dict) else None

    # M6C reasoning isolation: detect a DeepSeek ``reasoning_content`` field
    # and record ONLY its presence as a boolean. The text itself is dropped
    # here and never stored anywhere downstream — not in the response, not in
    # logs, not in the report, not in the cache.
    reasoning_present = False
    if isinstance(message, dict) and "reasoning_content" in message:
        rc = message.get("reasoning_content")
        reasoning_present = isinstance(rc, str) and bool(rc.strip())

    if not isinstance(content, str) or not content.strip():
        # A response that produced only reasoning_content (no payload) is an
        # invalid structured response, not a transport error.
        if reasoning_present:
            raise ProviderError(
                "ai_provider_invalid_response",
                "AI provider returned reasoning_content but no structured content",
                retryable=False,
                stage="provider_call",
            )
        raise ProviderError(
            "ai_provider_invalid_json",
            "AI provider returned empty content",
            retryable=False,
            stage="provider_call",
        )

    parsed = _extract_json_object(content)
    if parsed is None:
        raise ProviderError(
            "ai_provider_invalid_json",
            "AI provider content had no parseable JSON object",
            retryable=False,
            stage="provider_call",
        )
    if not isinstance(parsed, dict):
        raise ProviderError(
            "ai_provider_invalid_json",
            "AI provider content parsed to a non-object JSON value",
            retryable=False,
            stage="provider_call",
        )

    finish_reason = (
        first.get("finish_reason") if isinstance(first.get("finish_reason"), str) else None
    )

    # Usage provenance. A usage block with at least one real token count is
    # authoritative; an empty/absent block is ``unavailable``.
    usage_raw = body.get("usage") if isinstance(body.get("usage"), dict) else {}
    prompt_tokens = usage_raw.get("prompt_tokens") if isinstance(usage_raw, dict) else None
    completion_tokens = usage_raw.get("completion_tokens") if isinstance(usage_raw, dict) else None
    cached_tokens = _cached_tokens_from_usage(usage_raw)
    has_real = any(isinstance(v, int) for v in (prompt_tokens, completion_tokens, cached_tokens))
    if has_real:
        usage_source = "provider"
    else:
        usage_source = "unavailable"
    return ProviderResponse(
        content_json=parsed,
        content_chars=len(content),
        usage=ProviderUsage(
            input_tokens=prompt_tokens if isinstance(prompt_tokens, int) else None,
            output_tokens=completion_tokens if isinstance(completion_tokens, int) else None,
            cached_tokens=cached_tokens if isinstance(cached_tokens, int) else None,
            model=body.get("model"),
            usage_source=usage_source,
        ),
        latency_ms=latency_ms,
        usage_source=usage_source,
        finish_reason=finish_reason,
        reasoning_content_present=reasoning_present,
    )


# ---------------------------------------------------------------------------
# Mock provider — deterministic, used by every automated test.
# ---------------------------------------------------------------------------

__all__ = ["OpenAICompatibleProvider", "_parse_chat_completion"]
