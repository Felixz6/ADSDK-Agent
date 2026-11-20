"""AI model provider adapters and factory."""

from __future__ import annotations

from app.config import (
    AI_MAX_RETRY_AFTER_SECONDS,
    AI_PROVIDER,
    AI_PROVIDER_PROFILE,
    AI_REQUEST_RETRIES,
    AI_RETRY_BASE_DELAY_MS,
    AI_THINKING_MODE,
)

from .base import (
    PROFILE_DEEPSEEK,
    PROFILE_GENERIC_OPENAI,
    AIProvider,
    ProviderCompatibilityProfile,
    ProviderError,
    ProviderResponse,
    ProviderUsage,
    _balanced_object_slice,
    _cached_tokens_from_usage,
    _detect_profile,
    _extract_json_object,
    _safe_truncate,
    _thinking_disabled_for,
    build_system_prompt,
)
from .mock import MockAIProvider, _default_mock_plan, _default_mock_report
from .openai_compatible import OpenAICompatibleProvider, _parse_chat_completion


def build_provider_from_config() -> AIProvider:
    """Construct the configured provider. The mock is selectable for tests."""
    if AI_PROVIDER == "mock":
        return MockAIProvider()
    return OpenAICompatibleProvider(
        provider_profile=AI_PROVIDER_PROFILE,
        thinking_mode=AI_THINKING_MODE,
        request_retries=AI_REQUEST_RETRIES,
        retry_base_delay_ms=AI_RETRY_BASE_DELAY_MS,
        max_retry_after_seconds=AI_MAX_RETRY_AFTER_SECONDS,
    )


__all__ = [
    "AIProvider",
    "MockAIProvider",
    "OpenAICompatibleProvider",
    "PROFILE_DEEPSEEK",
    "PROFILE_GENERIC_OPENAI",
    "ProviderCompatibilityProfile",
    "ProviderError",
    "ProviderResponse",
    "ProviderUsage",
    "build_provider_from_config",
    "build_system_prompt",
    "_balanced_object_slice",
    "_cached_tokens_from_usage",
    "_default_mock_plan",
    "_default_mock_report",
    "_detect_profile",
    "_extract_json_object",
    "_parse_chat_completion",
    "_safe_truncate",
    "_thinking_disabled_for",
]
