"""File-backed response cache for the M6A AI orchestrator.

The cache stores **only** parsed model-output JSON objects — never the API
key, never raw model prompts, never chain-of-thought, never request/response
bodies. Cache corruption never breaks an analysis: a corrupt entry is treated
as a miss and rewritten.

The cache key is a stable SHA-256 over the inputs that fully determine the
model output: provider name, model, prompt version, task objective, tool
definition digest, evidence-digest hash, and report language. Same inputs
=> same key => stable reuse.
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any

from app.config import AI_CACHE_TTL_SECONDS
from app.core.artifacts import atomic_write_json


class AIResponseCache:
    """A single-file-per-key JSON cache under ``root``.

    ``root`` defaults to ``output/state/ai-cache``. Each entry is written
    atomically; reads that fail to parse are deleted and treated as misses.
    """

    def __init__(
        self,
        root: Path | str | None = None,
        *,
        enabled: bool = True,
        ttl_seconds: int = AI_CACHE_TTL_SECONDS,
    ) -> None:
        from app.config import OUTPUT_DIR

        self._root = Path(root) if root is not None else Path(OUTPUT_DIR) / "state" / "ai-cache"
        self._enabled = enabled
        self._ttl = max(1, int(ttl_seconds))

    @property
    def enabled(self) -> bool:
        return self._enabled

    @staticmethod
    def make_key(
        *,
        provider: str,
        model: str,
        prompt_version: str,
        objective: str,
        tools_digest: str,
        evidence_digest_hash: str,
        report_language: str,
    ) -> str:
        """Stable cache key across identical inputs."""

        payload = json.dumps(
            {
                "provider": provider,
                "model": model,
                "prompt_version": prompt_version,
                "objective": objective,
                "tools_digest": tools_digest,
                "evidence_digest_hash": evidence_digest_hash,
                "report_language": report_language,
            },
            sort_keys=True,
            ensure_ascii=False,
        )
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()

    def get(self, key: str) -> dict[str, Any] | None:
        if not self._enabled:
            return None
        path = self._path(key)
        if not path.is_file():
            return None
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            self._safe_delete(path)
            return None
        if not isinstance(raw, dict):
            self._safe_delete(path)
            return None
        expires_at = raw.get("_expires_at")
        stored_value = raw.get("value")
        if not isinstance(stored_value, dict) or not isinstance(expires_at, (int, float)):
            self._safe_delete(path)
            return None
        if time.time() > float(expires_at):
            self._safe_delete(path)
            return None
        return stored_value

    def set(self, key: str, value: dict[str, Any]) -> None:
        if not self._enabled or not isinstance(value, dict):
            return
        try:
            self._root.mkdir(parents=True, exist_ok=True)
            atomic_write_json(
                self._path(key),
                {
                    "value": value,
                    "_expires_at": time.time() + self._ttl,
                    "_created_at": time.time(),
                },
                indent=2,
                sort_keys=True,
            )
        except Exception:
            # Cache write failure must never break analysis.
            return

    def expire(self, key: str) -> None:
        self._safe_delete(self._path(key))

    def _path(self, key: str) -> Path:
        safe = "".join(c if c.isalnum() else "" for c in key) or "empty"
        return self._root / f"{safe}.json"

    @staticmethod
    def _safe_delete(path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except Exception:
            pass
