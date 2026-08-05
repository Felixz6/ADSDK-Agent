"""AISettingsService — validation, persistence orchestration, masked responses.

This is the bridge between the HTTP layer and the two stores
(:class:`AISettingsStore` for the public JSON, :class:`SecretStore` for the
DPAPI key). Responsibilities:

* Validate an incoming save request (ranges, schemes, lengths, no control
  chars) and reject illegal configuration with a structured error.
* Apply environment-variable precedence: env-managed fields are not
  overwritten by a local save and are surfaced as ``locked_fields`` /
  ``field_sources``.
* Build the *masked* effective settings response. The API key is *never*
  returned; only ``api_key_configured`` + ``api_key_source`` leak.
* Drive a thread-safe :class:`AIProviderFactory` so a save hot-swaps the
  in-process provider for *new* tasks while running tasks keep their snapshot.

Security invariants (enforced):

* ``api_key`` never enters the returned response, never enters the
  settings JSON, never enters logs, never enters exceptions. The service
  raises ``AISettingsValidationError`` with a safe message only.
* Empty ``api_key`` (``""``) in a save request does **not** delete the
  stored key — deletion is a separate authenticated action. A missing key
  preserves the existing key.
"""

from __future__ import annotations

import threading
from typing import Any

from app.config import (
    AI_ALLOW_DYNAMIC_TOOLS,
    AI_BASE_URL,
    AI_CACHE_ENABLED,
    AI_CACHE_TTL_SECONDS,
    AI_ENABLED,
    AI_MAX_INPUT_TOKENS,
    AI_MAX_OUTPUT_TOKENS,
    AI_MAX_ROUNDS,
    AI_MAX_TOOL_CALLS,
    AI_MODEL,
    AI_PROVIDER,
    AI_REPORT_LANGUAGE,
    AI_TIMEOUT_SECONDS,
)
from app.ai.provider import AIProvider, MockAIProvider, OpenAICompatibleProvider
from app.ai.secret_store import DPAPIError
from app.ai.settings_store import (
    AISettingsStore,
    DEFAULT_ALLOW_DYNAMIC_TOOLS,
    DEFAULT_CACHE_ENABLED,
    DEFAULT_CACHE_TTL_SECONDS,
    DEFAULT_DEFAULT_TOKEN_BUDGET,
    DEFAULT_MAX_INPUT_TOKENS,
    DEFAULT_MAX_OUTPUT_TOKENS,
    DEFAULT_MAX_ROUNDS,
    DEFAULT_MAX_TOOL_CALLS,
    DEFAULT_PROVIDER,
    DEFAULT_REPORT_LANGUAGE,
    DEFAULT_TIMEOUT_SECONDS,
    LocalSettings,
    SCHEMA_VERSION,
    SettingsCorruptionError,
)

# Public re-exports for the HTTP layer.
__all__ = [
    "AISettingsService",
    "AIProviderFactory",
    "AISettingsValidationError",
    "EffectiveSettings",
    "resolve_effective_ai_settings",
    "SCHEMA_VERSION",
]


class AISettingsValidationError(Exception):
    """Structured validation failure — safe message only, never the key."""

    def __init__(self, code: str, safe_message: str, *, field: str | None = None) -> None:
        super().__init__(safe_message)
        self.code = code
        self.safe_message = safe_message
        self.field = field

    def to_dict(self) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "error_code": self.code,
            "safe_message": self.safe_message,
        }
        if self.field is not None:
            payload["field"] = self.field
        return payload


# ---------------------------------------------------------------------------
# Validation — M6B spec ranges.
# ---------------------------------------------------------------------------
_RANGES = {
    "default_token_budget": (100, 100000),
    "max_rounds": (1, 3),
    "max_tool_calls": (1, 10),
    "timeout_seconds": (5, 300),
    "max_input_tokens": (500, 100000),
    "max_output_tokens": (100, 10000),
    "cache_ttl_seconds": (60, 604800),
}
_ALLOWED_PROVIDERS = {"openai_compatible"}
_ALLOWED_LANGUAGES = {"zh-CN", "en-US"}
_API_KEY_MAX_LENGTH = 4096

_SAVE_FLOAT_FIELDS = {"default_token_budget"} | set(_RANGES)


def _has_control_chars(value: str) -> bool:
    return any(ord(ch) < 0x20 for ch in value)


def _validate_base_url(value: str) -> str:
    v = value.strip()
    if _has_control_chars(v):
        raise AISettingsValidationError(
            "invalid_base_url", "Base URL 含控制字符", field="base_url"
        )
    lowered = v.lower()
    if lowered.startswith("file://") or lowered.startswith("javascript:"):
        raise AISettingsValidationError(
            "invalid_base_url", "Base URL 协议不被允许", field="base_url"
        )
    if not (lowered.startswith("http://") or lowered.startswith("https://")):
        raise AISettingsValidationError(
            "invalid_base_url", "Base URL 必须为 http 或 https", field="base_url"
        )
    return v.rstrip("/")


def _validate_model(value: str) -> str:
    v = value.strip()
    if _has_control_chars(v):
        raise AISettingsValidationError("invalid_model", "Model 含控制字符", field="model")
    if "\n" in v or "\r" in v:
        raise AISettingsValidationError("invalid_model", "Model 不得换行", field="model")
    if not (1 <= len(v) <= 200):
        raise AISettingsValidationError(
            "invalid_model", "Model 长度应在 1–200 之间", field="model"
        )
    return v


def _validate_api_key(value: str) -> str:
    if _has_control_chars(value):
        raise AISettingsValidationError(
            "invalid_api_key", "API Key 含控制字符", field="api_key"
        )
    if "\n" in value or "\r" in value:
        raise AISettingsValidationError(
            "invalid_api_key", "API Key 不得换行", field="api_key"
        )
    if not (1 <= len(value) <= _API_KEY_MAX_LENGTH):
        raise AISettingsValidationError(
            "invalid_api_key", "API Key 长度应在 1–4096 之间", field="api_key"
        )
    return value


def _validate_range(name: str, value: int) -> int:
    low, high = _RANGES[name]
    if not (low <= value <= high):
        raise AISettingsValidationError(
            f"invalid_{name}",
            f"{name} 应在 {low}–{high} 之间",
            field=name,
        )
    return value


def _coerce_env(name: str, raw: str):
    """Convert a raw env string to the field's Python type.

    Out-of-range / unparsable values fall back to ``None`` so a malformed env
    var degrades to the next precedence tier instead of raising at read time.
    ``app.config`` still owns the strict, fail-fast parsing at import.
    """

    bool_fields = {"enabled", "cache_enabled", "allow_dynamic_tools"}
    int_fields = {
        "timeout_seconds",
        "max_rounds",
        "max_tool_calls",
        "max_input_tokens",
        "max_output_tokens",
        "cache_ttl_seconds",
    }
    if name in bool_fields:
        return raw.strip().lower() in {"1", "true", "yes", "on"}
    if name in int_fields:
        try:
            return int(raw.strip())
        except ValueError:
            return None
    value = raw.strip()
    return value or None



# ---------------------------------------------------------------------------
# Effective settings (masked).
# ---------------------------------------------------------------------------
class EffectiveSettings:
    """Container for the masked effective view returned to the frontend."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self.payload = payload

    def to_dict(self) -> dict[str, Any]:
        return dict(self.payload)


# ---------------------------------------------------------------------------
# Provider factory — thread-safe hot reload with snapshot semantics.
# ---------------------------------------------------------------------------
class AIProviderFactory:
    """Process-safe provider cache that swaps on save without a restart.

    ``current()`` returns the latest built provider; running tasks capture the
    returned object and keep using it for their lifetime, so a save mid-task
    cannot change an in-flight analysis. A failed rebuild keeps the old
    provider (best-effort) so an invalid-but-saved config does not break the
    next analysis outright.
    """

    def __init__(self, store: AISettingsStore, *, allow_mock: bool = True) -> None:
        self._store = store
        self._allow_mock = allow_mock
        self._lock = threading.RLock()
        self._provider: AIProvider | None = None
        self._build_error: dict[str, Any] | None = None

    def current(self) -> AIProvider | None:
        with self._lock:
            if self._provider is None:
                self._provider = self._build_locked()
            return self._provider

    def last_build_error(self) -> dict[str, Any] | None:
        with self._lock:
            return dict(self._build_error) if self._build_error else None

    def rebuild(self) -> AIProvider | None:
        """Rebuild from live settings; only transient build errors keep the old one."""

        with self._lock:
            new = self._build_locked()
            if new is not None:
                self._provider = new
            elif self._build_error is None:
                # A complete, successful resolution that has no provider means
                # the effective configuration is now incomplete (for example
                # the local key was deleted).  Do not retain a stale provider.
                self._provider = None
            return self._provider

    def _build_locked(self) -> AIProvider | None:
        try:
            provider = self._build_from_effective()
            self._build_error = None
            return provider
        except DPAPIError as exc:
            self._build_error = {
                "error_code": exc.code,
                "safe_message": exc.safe_message,
            }
            return self._provider  # keep old if any
        except Exception as exc:  # pragma: no cover - defensive
            self._build_error = {
                "error_code": "ai_provider_build_failed",
                "safe_message": type(exc).__name__,
            }
            return self._provider

    def _build_from_effective(self) -> AIProvider | None:
        # Mock is test-only and opt-in; never built from saved settings in prod.
        effective = resolve_effective_ai_settings(self._store)
        provider_name = effective["provider"]
        if provider_name == "mock" and self._allow_mock:
            return MockAIProvider()
        if provider_name != "openai_compatible" and provider_name != "mock":
            return None
        # Even if AI is disabled we can still *build* a provider (so /test
        # works while disabled). Disabling only gates orchestration, not the
        # provider object itself.
        base_url = effective["base_url"] or ""
        model = effective["model"] or ""
        api_key = effective["api_key"] or ""
        timeout = effective["timeout_seconds"] or DEFAULT_TIMEOUT_SECONDS
        if not (base_url and model and api_key):
            # Not enough to build a real provider; return None so callers
            # degrade gracefully without raising.
            return None
        return OpenAICompatibleProvider(
            base_url=base_url,
            api_key=api_key,
            model=model,
            timeout_seconds=float(timeout),
        )

# Fields whose env value is authoritative when present.
_ENV_VALUE_PROVIDER_SET = {
    "enabled",
    "provider",
    "base_url",
    "model",
    "timeout_seconds",
    "max_rounds",
    "max_tool_calls",
    "max_input_tokens",
    "max_output_tokens",
    "cache_enabled",
    "cache_ttl_seconds",
    "allow_dynamic_tools",
    "report_language",
}

_DEFAULT_FIELD_VALUES = {
    "enabled": AI_ENABLED,
    "provider": DEFAULT_PROVIDER,
    "base_url": AI_BASE_URL,
    "model": AI_MODEL,
    "timeout_seconds": AI_TIMEOUT_SECONDS,
    "max_rounds": DEFAULT_MAX_ROUNDS,
    "max_tool_calls": DEFAULT_MAX_TOOL_CALLS,
    "max_input_tokens": DEFAULT_MAX_INPUT_TOKENS,
    "max_output_tokens": DEFAULT_MAX_OUTPUT_TOKENS,
    "cache_enabled": DEFAULT_CACHE_ENABLED,
    "cache_ttl_seconds": DEFAULT_CACHE_TTL_SECONDS,
    "allow_dynamic_tools": DEFAULT_ALLOW_DYNAMIC_TOOLS,
    "report_language": DEFAULT_REPORT_LANGUAGE,
    "default_token_budget": DEFAULT_DEFAULT_TOKEN_BUDGET,
}


def resolve_effective_ai_settings(store: AISettingsStore) -> dict[str, Any]:
    """Resolve the one live AI configuration used by every runtime path.

    The returned mapping is internal-only because it carries the plaintext key
    briefly for provider construction.  Callers returning HTTP payloads must
    use :meth:`AISettingsService.get_effective_settings`, which masks it.
    """

    from app.ai.settings_store import settings_corruption_degradable

    local = settings_corruption_degradable(store)

    def resolve(name: str) -> Any:
        raw_env = store.environment_raw(name)
        env = _coerce_env(name, raw_env) if raw_env is not None else None
        if env is not None:
            return env
        local_value = getattr(local, name, None)
        if local_value is not None:
            return local_value
        return _DEFAULT_FIELD_VALUES.get(name)

    values = {name: resolve(name) for name in _DEFAULT_FIELD_VALUES}
    api_key = store.effective_api_key()
    api_key_source = store.api_key_source()
    values.update(
        api_key=api_key,
        api_key_source=api_key_source,
        api_key_configured=api_key_source != "none",
        configured=(
            values["provider"] == "openai_compatible"
            and bool(values["base_url"])
            and bool(values["model"])
            and bool(api_key)
        ),
        locked_fields=sorted(store.environment_overrides()),
        field_sources={
            name: store.field_source(name)
            for name in AISettingsService._EDITABLE_FIELDS
        },
    )
    return values


# ---------------------------------------------------------------------------
# Service.
# ---------------------------------------------------------------------------
class AISettingsService:
    """Owns validation + masked responses + provider hot reload."""

    # Editable text/bool/scalar fields accepted on PUT in strict mode.
    _EDITABLE_FIELDS = {
        "enabled",
        "provider",
        "base_url",
        "model",
        "default_token_budget",
        "max_rounds",
        "max_tool_calls",
        "timeout_seconds",
        "max_input_tokens",
        "max_output_tokens",
        "cache_enabled",
        "cache_ttl_seconds",
        "allow_dynamic_tools",
        "report_language",
    }

    def __init__(
        self,
        store: AISettingsStore | None = None,
        *,
        factory: AIProviderFactory | None = None,
    ) -> None:
        self._store = store or AISettingsStore()
        self._factory = factory or AIProviderFactory(self._store)

    @property
    def store(self) -> AISettingsStore:
        return self._store

    @property
    def factory(self) -> AIProviderFactory:
        return self._factory

    # -- masked response ----------------------------------------------
    def get_effective_settings(self) -> dict[str, Any]:
        effective = resolve_effective_ai_settings(self._store)
        payload = {
            "schema_version": SCHEMA_VERSION,
            **{name: effective[name] for name in self._EDITABLE_FIELDS},
            "api_key_configured": effective["api_key_configured"],
            "api_key_source": effective["api_key_source"],
            "field_sources": effective["field_sources"],
            "locked_fields": effective["locked_fields"],
        }
        return payload

    # -- save ----------------------------------------------------------
    def save_settings(self, request: dict[str, Any]) -> dict[str, Any]:
        """Validate + persist (key separately). Returns the masked effective view.

        ``api_key`` semantics:
          * missing key  -> keep existing key
          * non-empty    -> replace key (DPAPI)
          * empty string -> keep existing (NOT a delete)
        """

        self._validate_request(request)
        local = self._safe_load_local()
        locked = self._store.environment_overrides()

        # Apply editable, non-locked fields.
        for field_name, value in request.items():
            if field_name == "api_key":
                continue
            if field_name not in self._EDITABLE_FIELDS:
                continue
            if field_name in locked:
                continue  # env wins; ignore local override silently
            setattr(local, field_name, value)

        # API key handling.
        if "api_key" in request:
            supplied = request["api_key"]
            if supplied is None:
                pass  # keep existing
            elif supplied == "":
                pass  # empty is NOT a delete — keep existing
            else:
                _validate_api_key(supplied)
                try:
                    self._store.set_api_key(supplied)
                except DPAPIError as exc:
                    raise AISettingsValidationError(
                        exc.code,
                        exc.safe_message,
                        field="api_key",
                    ) from exc

        self._store.save_settings(local)
        # Hot-reload the in-process provider for *new* tasks.
        self._factory.rebuild()
        return self.get_effective_settings()

    # -- delete key ----------------------------------------------------
    def delete_api_key(self) -> bool:
        """Delete only the locally-stored key. Env key is untouched."""

        deleted = self._store.delete_api_key()
        self._factory.rebuild()
        return deleted

    # -- test connection -----------------------------------------------
    def test_connection(self, request: dict[str, Any] | None = None) -> dict[str, Any]:
        """Probe reachability using either saved settings or supplied temporary ones.

        A temporary test request may carry ``api_key``; it lives only in this
        request's memory, is never saved, never cached, never logged.
        """

        request = request or {}
        # Resolve the same live settings used by status and new tasks, then let
        # explicit one-shot test fields override that snapshot.
        effective = resolve_effective_ai_settings(self._store)
        base_url = request.get("base_url") or effective["base_url"]
        model = request.get("model") or effective["model"]
        provider_name = request.get("provider") or effective["provider"] or DEFAULT_PROVIDER
        timeout = request.get("timeout_seconds") or effective["timeout_seconds"] or DEFAULT_TIMEOUT_SECONDS
        try:
            timeout_f = float(timeout)
        except (TypeError, ValueError):
            timeout_f = float(DEFAULT_TIMEOUT_SECONDS)

        # API key for the test: supplied temporary key wins, else effective key.
        temp_key = request.get("api_key")
        if temp_key:
            _validate_api_key(temp_key)
            api_key = temp_key
        else:
            api_key = effective["api_key"] or ""

        result: dict[str, Any] = {
            "status": "unreachable",
            "provider": provider_name,
            "model": model or "",
            "latency_ms": 0,
            "safe_message": "",
            "models_endpoint_supported": False,
        }

        if provider_name == "mock":
            result.update(status="reachable", safe_message="mock provider", latency_ms=0)
            return result

        if not (base_url and model and api_key):
            result.update(
                status="invalid_configuration",
                safe_message="缺少 base_url / model / api_key",
            )
            return result

        provider = OpenAICompatibleProvider(
            base_url=base_url,
            api_key=api_key,
            model=model,
            timeout_seconds=timeout_f,
        )
        return provider.probe_reachable(timeout_seconds=timeout_f)

    # -- helpers -------------------------------------------------------
    def _validate_request(self, request: dict[str, Any]) -> None:
        if not isinstance(request, dict):
            raise AISettingsValidationError("invalid_request", "请求体必须是 JSON 对象")

        if "enabled" in request and request["enabled"] is not None:
            if not isinstance(request["enabled"], bool):
                raise AISettingsValidationError(
                    "invalid_enabled", "enabled 必须为布尔值", field="enabled"
                )

        if "provider" in request and request["provider"] is not None:
            provider_value = str(request["provider"]).strip()
            if provider_value not in _ALLOWED_PROVIDERS:
                raise AISettingsValidationError(
                    "invalid_provider",
                    "provider 当前只允许 openai_compatible",
                    field="provider",
                )

        if "base_url" in request and request["base_url"] not in (None, ""):
            request["base_url"] = _validate_base_url(str(request["base_url"]))
        elif "base_url" in request and request["base_url"] == "":
            raise AISettingsValidationError(
                "invalid_base_url", "base_url 不得为空", field="base_url"
            )

        if "model" in request and request["model"] not in (None, ""):
            request["model"] = _validate_model(str(request["model"]))
        elif "model" in request and request["model"] == "":
            raise AISettingsValidationError(
                "invalid_model", "model 不得为空", field="model"
            )

        for name, (low, high) in _RANGES.items():
            if name in request and request[name] is not None:
                if not isinstance(request[name], int) or isinstance(request[name], bool):
                    raise AISettingsValidationError(
                        f"invalid_{name}", f"{name} 必须为整数", field=name
                    )
                _validate_range(name, int(request[name]))

        if "cache_enabled" in request and request["cache_enabled"] is not None:
            if not isinstance(request["cache_enabled"], bool):
                raise AISettingsValidationError(
                    "invalid_cache_enabled", "cache_enabled 必须为布尔值", field="cache_enabled"
                )

        if "allow_dynamic_tools" in request and request["allow_dynamic_tools"] is not None:
            if not isinstance(request["allow_dynamic_tools"], bool):
                raise AISettingsValidationError(
                    "invalid_allow_dynamic_tools",
                    "allow_dynamic_tools 必须为布尔值",
                    field="allow_dynamic_tools",
                )

        if "report_language" in request and request["report_language"] is not None:
            lang = str(request["report_language"]).strip()
            if lang not in _ALLOWED_LANGUAGES:
                raise AISettingsValidationError(
                    "invalid_report_language",
                    "report_language 当前只允许 zh-CN、en-US",
                    field="report_language",
                )
            request["report_language"] = lang

        if "api_key" in request and request["api_key"] is not None and request["api_key"] != "":
            _validate_api_key(str(request["api_key"]))

    def _safe_load_local(self) -> LocalSettings:
        from app.ai.settings_store import settings_corruption_degradable

        return settings_corruption_degradable(self._store)
