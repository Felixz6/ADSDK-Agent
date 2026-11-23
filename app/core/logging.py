"""Structured application logging with secret redaction."""

from __future__ import annotations

import logging
import re
from collections.abc import Mapping

from app import config as app_config

_ADSDK_HANDLER_MARKER = "_adsdk_app_stream_handler"

_BEARER_RE = re.compile(r"(?i)\bBearer\s+[^\s\"',;]+")
_SK_TOKEN_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_KEY_VALUE_SECRET_RE = re.compile(
    r"(?i)(['\"]?(?:api_key|apikey|authorization|x-api-key|secret_key)['\"]?\s*[:=]\s*)"
    r"(?:\"[^\"]*\"|'[^']*'|[^\s,;}\]]+)"
)


def scrub_secrets(text: str) -> str:
    """Replace credential patterns in log text with ``[REDACTED]``."""
    redacted = _BEARER_RE.sub("Bearer [REDACTED]", text)
    redacted = _SK_TOKEN_RE.sub("[REDACTED]", redacted)
    redacted = _KEY_VALUE_SECRET_RE.sub(r"\1[REDACTED]", redacted)
    return redacted


class SecretRedactingFilter(logging.Filter):
    """Logging filter that scrubs credentials from messages, args, and cached tracebacks."""

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except Exception:
            message = str(record.msg)
        scrubbed = scrub_secrets(message)
        if scrubbed != message:
            record.msg = scrubbed
            record.args = None
        else:
            if isinstance(record.msg, str):
                record.msg = scrub_secrets(record.msg)
            if isinstance(record.args, tuple):
                record.args = tuple(
                    scrub_secrets(arg) if isinstance(arg, str) else arg for arg in record.args
                )
            elif isinstance(record.args, Mapping):
                record.args = {
                    key: scrub_secrets(val) if isinstance(val, str) else val
                    for key, val in record.args.items()
                }
        if isinstance(record.exc_text, str):
            record.exc_text = scrub_secrets(record.exc_text)
        return True


class RedactingFormatter(logging.Formatter):
    """Formatter that scrubs secrets from the complete formatted log line and traceback."""

    def format(self, record: logging.LogRecord) -> str:
        return scrub_secrets(super().format(record))


def _resolve_log_level(level: str | None) -> int:
    raw = (level if level is not None else app_config.LOG_LEVEL).strip().upper()
    resolved = getattr(logging, raw, None)
    return resolved if isinstance(resolved, int) else logging.INFO


def configure_logging(level: str | None = None) -> logging.Logger:
    """Idempotently configure the ``app`` logger using stream-only output (zero disk IO)."""
    app_logger = logging.getLogger("app")
    resolved_level = _resolve_log_level(level)
    app_logger.setLevel(resolved_level)
    app_logger.propagate = True

    existing = next(
        (h for h in app_logger.handlers if getattr(h, _ADSDK_HANDLER_MARKER, False)),
        None,
    )
    if existing is None:
        handler = logging.StreamHandler()
        setattr(handler, _ADSDK_HANDLER_MARKER, True)
        handler.setFormatter(RedactingFormatter("%(asctime)s %(levelname)s [%(name)s] %(message)s"))
        handler.addFilter(SecretRedactingFilter())
        handler.setLevel(resolved_level)
        app_logger.addHandler(handler)
    else:
        existing.setLevel(resolved_level)

    return app_logger


__all__ = [
    "RedactingFormatter",
    "SecretRedactingFilter",
    "configure_logging",
    "scrub_secrets",
]
