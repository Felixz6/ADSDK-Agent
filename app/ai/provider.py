"""Backward-compatible re-export facade for app.ai.providers."""

from __future__ import annotations

from .providers import (
    PROFILE_DEEPSEEK,
    PROFILE_GENERIC_OPENAI,
    AIProvider,
    MockAIProvider,
    OpenAICompatibleProvider,
    ProviderCompatibilityProfile,
    ProviderError,
    ProviderResponse,
    ProviderUsage,
    _balanced_object_slice,
    _detect_profile,
    _extract_json_object,
    _parse_chat_completion,
    _thinking_disabled_for,
    build_provider_from_config,
    build_system_prompt,
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
    "_detect_profile",
    "_extract_json_object",
    "_parse_chat_completion",
    "_thinking_disabled_for",
]
