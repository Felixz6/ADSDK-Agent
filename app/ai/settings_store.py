"""Local AI settings store with environment-variable precedence.

M6B lets the user configure AI from the frontend Settings page. The key
invariant — *the API key is never written to the frontend or returned to it* —
is enforced here:

* Normal editable configuration (provider, base_url, model, budgets, cache,
  language, …) is persisted as plain JSON at ``output/config/ai-settings.json``.
* The API key is persisted **separately** by :class:`SecretStore` under
  ``output/config/ai-secret.bin`` via Windows DPAPI. It never enters the
  settings JSON.
* Effective configuration follows a fixed precedence — environment variable >
  locally-saved value > code default — and each field reports its source so
  the frontend can lock env-managed inputs.
* Corruption degrades structurally: a broken settings JSON is ignored and
  defaults are used; the app still boots.

This module does not import FastAPI or do validation; the
:class:`AISettingsService` layer owns request/response models and validation.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field, fields
from pathlib import Path

from app.ai.secret_store import SecretStore, DPAPIError

# ---------------------------------------------------------------------------
# Schema/version.
# ---------------------------------------------------------------------------
SCHEMA_VERSION = "ai-settings-v1"

# ---------------------------------------------------------------------------
# Code defaults — used when neither env nor local store supplies a field.
# Mirrors app/config.py defaults so behavior is identical when nothing is saved.
# ---------------------------------------------------------------------------
DEFAULT_PROVIDER = "openai_compatible"
DEFAULT_TIMEOUT_SECONDS = 60
DEFAULT_DEFAULT_TOKEN_BUDGET = 6000
DEFAULT_MAX_ROUNDS = 2
DEFAULT_MAX_TOOL_CALLS = 6
DEFAULT_MAX_INPUT_TOKENS = 6000
DEFAULT_MAX_OUTPUT_TOKENS = 1800
DEFAULT_CACHE_ENABLED = True
DEFAULT_CACHE_TTL_SECONDS = 86400
DEFAULT_ALLOW_DYNAMIC_TOOLS = False
DEFAULT_REPORT_LANGUAGE = "zh-CN"

# ---------------------------------------------------------------------------
# Environment-variable bindings. A field that has a non-empty env value is
# "locked" — the frontend must not edit it, and field_source=environment.
# ---------------------------------------------------------------------------
_ENV_BINDINGS = {
    "enabled": "AI_ENABLED",
    "provider": "AI_PROVIDER",
    "base_url": "AI_BASE_URL",
    "model": "AI_MODEL",
}

# Numeric/bool env bindings are only consulted to compute locked_fields /
# field_sources for the editable numeric fields exposed to the frontend. The
# effective numeric values still come from app.config's validating parsers
# (via the service), so these mappings exist purely for source reporting.
_ENV_NUMERIC_BINDINGS = {
    "timeout_seconds": "AI_TIMEOUT_SECONDS",
    "max_rounds": "AI_MAX_ROUNDS",
    "max_tool_calls": "AI_MAX_TOOL_CALLS",
    "max_input_tokens": "AI_MAX_INPUT_TOKENS",
    "max_output_tokens": "AI_MAX_OUTPUT_TOKENS",
    "cache_ttl_seconds": "AI_CACHE_TTL_SECONDS",
    "cache_enabled": "AI_CACHE_ENABLED",
    "allow_dynamic_tools": "AI_ALLOW_DYNAMIC_TOOLS",
    "report_language": "AI_REPORT_LANGUAGE",
}

# Fields the frontend should never receive the effective value of once set
# (only env is acceptable): the API key itself. Its "source" is tracked
# separately as ``api_key_source``.


@dataclass(slots=True)
class LocalSettings:
    """The editable fields persisted to ``ai-settings.json``."""

    enabled: bool | None = None
    provider: str | None = None
    base_url: str | None = None
    model: str | None = None
    default_token_budget: int | None = None
    max_rounds: int | None = None
    max_tool_calls: int | None = None
    timeout_seconds: int | None = None
    max_input_tokens: int | None = None
    max_output_tokens: int | None = None
    cache_enabled: bool | None = None
    cache_ttl_seconds: int | None = None
    allow_dynamic_tools: bool | None = None
    report_language: str | None = None

    def to_dict(self) -> dict[str, object]:
        return {f.name: getattr(self, f.name) for f in fields(self) if getattr(self, f.name) is not None}

    @classmethod
    def from_dict(cls, data: object) -> "LocalSettings":
        if not isinstance(data, dict):
            raise TypeError("settings payload must be a dict")
        known = {f.name for f in fields(cls)}
        # Unknown keys are dropped (forward/backward compat); no exception.
        filtered = {k: v for k, v in data.items() if k in known and v is not None}
        # Coerce bool/str/int loosely but reject obviously wrong types per field.
        return cls(
            enabled=_opt_bool(filtered.get("enabled")),
            provider=_opt_str(filtered.get("provider")),
            base_url=_opt_str(filtered.get("base_url")),
            model=_opt_str(filtered.get("model")),
            default_token_budget=_opt_int(filtered.get("default_token_budget")),
            max_rounds=_opt_int(filtered.get("max_rounds")),
            max_tool_calls=_opt_int(filtered.get("max_tool_calls")),
            timeout_seconds=_opt_int(filtered.get("timeout_seconds")),
            max_input_tokens=_opt_int(filtered.get("max_input_tokens")),
            max_output_tokens=_opt_int(filtered.get("max_output_tokens")),
            cache_enabled=_opt_bool(filtered.get("cache_enabled")),
            cache_ttl_seconds=_opt_int(filtered.get("cache_ttl_seconds")),
            allow_dynamic_tools=_opt_bool(filtered.get("allow_dynamic_tools")),
            report_language=_opt_str(filtered.get("report_language")),
        )


def _opt_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        return bool(value)
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "on"}
    return None


def _opt_str(value: object) -> str | None:
    if value is None:
        return None
    if isinstance(value, str):
        v = value.strip()
        return v or None
    return None


def _opt_int(value: object) -> int | None:
    if value is None:
        return None
    if isinstance(value, bool):  # bool is an int subclass; reject it here
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, float) and value.is_integer():
        return int(value)
    if isinstance(value, str):
        try:
            return int(value.strip())
        except ValueError:
            return None
    return None


class SettingsCorruptionError(Exception):
    """Structural corruption of the settings JSON — degrades to defaults."""


class AISettingsStore:
    """Owns the plain settings JSON and delegates the API key to SecretStore.

    Two physical artifacts:

    * ``ai-settings.json`` — editable, non-secret public configuration.
    * ``ai-secret.bin``   — DPAPI-encrypted API key (SecretStore).

    The store deliberately does *not* perform validation; that is the service
    layer's job. It only persists what the service hands it and reports the
    effective merge of env > local > default for source tracking.
    """

    def __init__(
        self,
        *,
        settings_path: Path | str | None = None,
        secret_store: SecretStore | None = None,
    ) -> None:
        if settings_path is not None:
            self._path = Path(settings_path)
        else:
            from app.config import OUTPUT_DIR

            self._path = Path(OUTPUT_DIR) / "config" / "ai-settings.json"
        self._secrets = secret_store or SecretStore()
        self._env = os.environ  # injectable seam for tests

    @property
    def settings_path(self) -> Path:
        return self._path

    @property
    def secret_store(self) -> SecretStore:
        return self._secrets

    # -- public --------------------------------------------------------
    def load_settings(self) -> LocalSettings:
        """Read the local JSON, tolerating corruption by falling back to empty."""

        if not self._path.is_file():
            return LocalSettings()
        try:
            raw = self._path.read_text(encoding="utf-8")
        except OSError:
            return LocalSettings()
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise SettingsCorruptionError(
                f"ai-settings.json is not valid JSON: {exc.msg}"
            ) from exc
        if not isinstance(parsed, dict):
            raise SettingsCorruptionError("ai-settings.json root is not an object")
        # Older schemas may carry its own schema_version; we only consume the
        # editable fields, unknown keys are tolerated.
        try:
            return LocalSettings.from_dict(parsed)
        except TypeError as exc:
            raise SettingsCorruptionError(str(exc)) from exc

    def save_settings(self, settings: LocalSettings, *, uid: int | None = None) -> None:
        """Atomically write the editable settings. Secret lives separately.

        ``uid`` support is reserved for a future per-user path; on a single-user
        single-process host it is ignored.
        """

        from app.core.artifacts import atomic_write_json

        payload = {
            "schema_version": SCHEMA_VERSION,
            **settings.to_dict(),
        }
        # Never allow the API key field to slip into the public JSON. The field
        # is not part of LocalSettings, but a defensive scrub protects against
        # accidental future additions.
        payload.pop("api_key", None)
        payload.pop("authorization", None)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self._path, payload, indent=2)

    def set_api_key(self, value: str) -> None:
        """Persist a new API key (DPAPI-encrypted). Overwrites prior key."""

        self._secrets.set(value)

    def delete_api_key(self) -> bool:
        """Remove the locally-persisted key. No-op if absent. Env key unaffected."""

        return self._secrets.delete()

    def has_api_key(self) -> bool:
        """True iff a locally-persisted (decryptable) key exists."""

        return self._secrets.has()

    def get_local_api_key(self) -> str | None:
        """Return the locally-persisted key plaintext (callers must not log)."""

        return self._secrets.get()

    # -- effective config + source tracking ---------------------------
    def environment_overrides(self) -> set[str]:
        """Field names whose env var is set and therefore locks that field."""

        locked: set[str] = set()
        for field_name, env_name in {**_ENV_BINDINGS, **_ENV_NUMERIC_BINDINGS}.items():
            raw = self._env.get(env_name)
            if raw is not None and raw.strip() != "":
                locked.add(field_name)
        return locked

    def field_source(self, field_name: str) -> str:
        """``environment`` | ``local_store`` | ``default`` for one editable field."""

        env_name = (
            _ENV_BINDINGS.get(field_name)
            or _ENV_NUMERIC_BINDINGS.get(field_name)
        )
        if env_name:
            raw = self._env.get(env_name)
            if raw is not None and raw.strip() != "":
                return "environment"
        # Corruption must never turn a source query into a 500: an unreadable
        # settings file simply means "no local value".
        try:
            local = self.load_settings()
        except SettingsCorruptionError:
            return "default"
        local_value = getattr(local, field_name, None)
        if local_value is not None:
            return "local_store"
        return "default"

    def environment_raw(self, field_name: str) -> str | None:
        """Raw env string for *field_name*, or ``None`` when unset/blank.

        Reading the live ``os.environ`` (rather than the import-time constants
        in :mod:`app.config`) is what makes environment precedence observable
        without a process restart — and what lets tests set an env var and see
        it take effect.
        """

        env_name = (
            _ENV_BINDINGS.get(field_name)
            or _ENV_NUMERIC_BINDINGS.get(field_name)
        )
        if not env_name:
            return None
        raw = self._env.get(env_name)
        if raw is None or raw.strip() == "":
            return None
        return raw

    def api_key_source(self) -> str:
        """``environment`` if AI_API_KEY env set, else ``local_store`` if a
        decryptable key file exists, else ``none``."""

        env_key = self._env.get("AI_API_KEY")
        if env_key and env_key.strip():
            return "environment"
        if self._secrets.supported() and self.has_api_key():
            return "local_store"
        return "none"

    def effective_api_key(self) -> str | None:
        """Env key wins over local key. Local key is decrypted; env is returned raw."""

        env_key = self._env.get("AI_API_KEY")
        if env_key and env_key.strip():
            return env_key
        return self.get_local_api_key()


def settings_corruption_degradable(
    store: "AISettingsStore",
) -> LocalSettings:
    """Load settings, swallowing corruption into empty defaults.

    Used at boot so a broken JSON never prevents the app from starting.
    """

    try:
        return store.load_settings()
    except (SettingsCorruptionError, OSError, DPAPIError):
        return LocalSettings()


__all__ = [
    "AISettingsStore",
    "LocalSettings",
    "SettingsCorruptionError",
    "SCHEMA_VERSION",
    "DEFAULT_PROVIDER",
    "DEFAULT_REPORT_LANGUAGE",
    "DEFAULT_DEFAULT_TOKEN_BUDGET",
    "DEFAULT_MAX_ROUNDS",
    "DEFAULT_MAX_TOOL_CALLS",
    "DEFAULT_TIMEOUT_SECONDS",
    "DEFAULT_MAX_INPUT_TOKENS",
    "DEFAULT_MAX_OUTPUT_TOKENS",
    "DEFAULT_CACHE_ENABLED",
    "DEFAULT_CACHE_TTL_SECONDS",
    "DEFAULT_ALLOW_DYNAMIC_TOOLS",
    "settings_corruption_degradable",
]
