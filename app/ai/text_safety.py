"""Text safety and prompt-injection neutralization utilities for AI components."""

from __future__ import annotations

import re
from typing import Any

MAX_UNTRUSTED_TEXT_CHARS = 240

_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_WHITESPACE = re.compile(r"\s+")

# Instruction-like markers that must never survive into the prompt as
# something the model could read as a directive. They are replaced with an
# inert token; the surrounding text is still shown as evidence.
_INJECTION_MARKERS = re.compile(
    r"(?i)\b("
    r"ignore\s+(all\s+|any\s+|the\s+)?(previous|prior|above|preceding)\s+"
    r"(instruction|instructions|prompt|prompts|rule|rules)"
    r"|disregard\s+(all\s+|any\s+|the\s+)?(previous|prior|above)\s+"
    r"(instruction|instructions|prompt|prompts)"
    r"|system\s*prompt"
    r"|you\s+are\s+now\b"
    r"|忽略(之前|以上|前面)?的?(全部|所有)?指令"
    r"|无视(之前|以上|前面)?的?指令"
    r")"
)

# Command-ish surfaces that must never be echoed verbatim into the prompt.
_COMMAND_MARKERS = re.compile(
    r"(?i)\b(adb\s+shell|adb\s+install|frida\s+-|frida-server|mitmdump|"
    r"mitmproxy|rm\s+-rf|curl\s+http|powershell|cmd\.exe|/bin/sh|/bin/bash)\b"
)

_NEUTRALISED = "[neutralized]"


def sanitize_untrusted_text(
    value: Any,
    *,
    limit: int = MAX_UNTRUSTED_TEXT_CHARS,
) -> str:
    """Make APK/network-derived free text safe to place in a prompt.

    The result is data, never an instruction: control characters are removed,
    whitespace is collapsed, directive-like phrases are neutralized, and the
    length is capped.
    """
    if value is None:
        return ""
    text = str(value)
    text = _CONTROL_CHARS.sub("", text)
    text = _WHITESPACE.sub(" ", text).strip()
    text = _INJECTION_MARKERS.sub(_NEUTRALISED, text)
    text = _COMMAND_MARKERS.sub(_NEUTRALISED, text)
    if len(text) > limit:
        return text[: max(0, limit - 3)] + "..."
    return text


def safe_int(value: Any, default: int = 0) -> int:
    """Best-effort integer coercion without boolean promotion."""
    if isinstance(value, bool):
        return default
    if isinstance(value, (int, float)):
        return int(value)
    return default


__all__ = [
    "MAX_UNTRUSTED_TEXT_CHARS",
    "_CONTROL_CHARS",
    "_WHITESPACE",
    "safe_int",
    "sanitize_untrusted_text",
]
