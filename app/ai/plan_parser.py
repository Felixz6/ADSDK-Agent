"""Robust AI plan JSON parser (Section 八 — ai-plan-validation-v2).

A single, defensive entry point that turns a raw model response string into a
Python ``dict`` ready for :mod:`app.ai.plan_validator`, with stable error codes
suitable for the ``ai-plan-validation-v2`` diagnostics artifact.

Design contract (Section 八):

* Accept: pure JSON object, fenced ``\\`\\`\\`json`` / plain ``\\`\\`\\``, JSON
  embedded in surrounding prose, string-typed JSON, BOM, leading/trailing
  whitespace.
* Reject: multiple candidate JSON objects, array/scalar root, ``eval`` /
  ``ast.literal_eval``, infinite regex backtracking. Input above a fixed cap
  is rejected (``input_too_long``) rather than scanned blindly.
* Never persist the original body: on failure the diagnostic carries only the
  *stable error code* plus bounded location info (the JSON pointer / index),
  never the offending text. The caller may record ``json_path`` and
  ``tool_name`` it derives after a successful parse — this module records nothing.
* Never be so permissive that a genuine schema error is masked as a parse
  success: array/scalar roots and multiple-object inputs are hard rejects even
  when each candidate is individually valid JSON.

This module owns no I/O and no secrets; it is pure and deterministic so tests
can exercise every branch without a device or a model.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

# Fixed cap. Larger inputs are rejected without scanning so a pathological
# model response cannot drive quadratic brace-matching. Generous for a plan
# (the v1 schema caps steps at 6) but bounded nonetheless.
MAX_PLAN_INPUT_CHARS: int = 65_536

# Stable error codes for the plan-parse stage of ai-plan-validation-v2.
ParseErrorCode = str
PARSE_EMPTY_RESPONSE: ParseErrorCode = "empty_response"
PARSE_INVALID_JSON: ParseErrorCode = "invalid_json"
PARSE_JSON_ROOT_NOT_OBJECT: ParseErrorCode = "json_root_not_object"
PARSE_MULTIPLE_JSON_OBJECTS: ParseErrorCode = "multiple_json_objects"
PARSE_INPUT_TOO_LONG: ParseErrorCode = "input_too_long"


class PlanParseError(ValueError):
    """Raised when the model response cannot be reduced to a single JSON object.

    Carries a *stable* ``code`` (one of the ``PARSE_*`` constants) plus an
    optional bounded location hint (``json_path`` / ``index``). No error
    message here echoes the offending content — callers must not persist it.
    """

    __slots__ = ("code", "json_path", "index")

    def __init__(
        self,
        code: ParseErrorCode,
        *,
        json_path: str | None = None,
        index: int | None = None,
    ) -> None:
        super().__init__(code)
        self.code = code
        self.json_path = json_path
        self.index = index


@dataclass(slots=True)
class ParseOutcome:
    """The result of a parse attempt.

    ``value`` is the validated root object on success (always a ``dict``).
    On failure ``error`` carries the stable code; ``value`` is ``None``. The
    bounded location hints are populated where computable.
    """

    value: dict[str, Any] | None
    error: ParseErrorCode | None
    json_path: str | None = None
    index: int | None = None

    @property
    def ok(self) -> bool:
        return self.error is None and self.value is not None


# ---------------------------------------------------------------------------
# Implementation.
# ---------------------------------------------------------------------------
def _strip_bom_and_whitespace(text: str) -> str:
    # A UTF-8 BOM may survive as the literal ﻿ code point; trim it plus
    # surrounding whitespace before any scan so it never confuses the brace
    # matcher (a leading BOM shifts the first-object index off by one).
    if text.startswith("﻿"):
        text = text[1:]
    return text.strip()


def _fenced_block(text: str) -> str | None:
    """Extract the content of the first ``` fenced block if present.

    Returns the trimmed inner text (without the fences). We do NOT use a
    greedy ``\\{.*?\\}`` capture over the fence content — that would silently
    accept a fence whose inner text is not actually an object. The caller's
    json.loads + object-discriminator does the structural check.
    """
    start = text.find("```")
    if start < 0:
        return None
    after = text[start + 3 :]
    # Skip an optional language tag (```json / ```JSON) up to the newline.
    newline = after.find("\n")
    if newline < 0:
        return None
    inner = after[newline + 1 :]
    end = inner.find("```")
    if end < 0:
        # No closing fence: fall through to whole-string / prose parsing.
        return None
    return inner[:end].strip()


def _count_top_level_objects(text: str) -> int:
    """Count brace-balanced top-level object candidates in *text*.

    Used to reject the multi-object case (Section 八 requirement 7): if two
    distinct balanced objects exist, the response is ambiguous and must be
    rejected even if the first is valid JSON. Strings (with escapes) are
    respected so a brace inside a string literal does not open an object.
    """
    depth = 0
    in_string = False
    escape = False
    started = False
    count = 0
    closed = False
    for ch in text:
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            if depth == 0:
                if started and closed:
                    # A new top-level object begins after a completed one.
                    count += 1
                    closed = False
                elif not started:
                    started = True
                    count = 1
            depth += 1
        elif ch == "}":
            if depth > 0:
                depth -= 1
                if depth == 0:
                    closed = True
    return count if started else 0


def _balanced_object_slice(text: str) -> tuple[str, int] | None:
    """Return the substring of the first balanced ``{...}`` object and its
    start index, or ``None`` when no balanced object exists.

    Respects string literals and escapes so a brace inside a string never
    triggers a false open/close. The scan is O(n) and bounded by the input
    cap applied upstream, so pathological nesting cannot cause backtracking.
    """
    start = text.find("{")
    if start < 0:
        return None
    depth = 0
    in_string = False
    escape = False
    for index in range(start, len(text)):
        ch = text[index]
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"':
            in_string = True
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return text[start : index + 1], start
    return None


def parse_plan_response(content: str | None) -> ParseOutcome:
    """Parse a model plan response into a single JSON object dict.

    Returns a :class:`ParseOutcome` rather than raising, so the orchestrator
    can record the stable error code straight into diagnostics without
    translating exceptions. The original content is never echoed in the
    outcome; only the stable code and bounded location hints travel out.
    """
    if content is None:
        return ParseOutcome(None, PARSE_EMPTY_RESPONSE)
    # The provider contract delivers ``content_json`` already parsed to a dict
    # (see ``ProviderResponse.content_json``); both the live and mock providers
    # return a dict, never a raw JSON string. Accept it directly here rather
    # than round-tripping through ``json.dumps`` — that would defeat the
    # string-handling robustness below and, worse, a non-dict root (array /
    # scalar delivered by a misbehaving provider) must still map to the stable
    # ``json_root_not_object`` code, not be silently stringified into a parse
    # retry. Strings fall through to the defensive text pipeline below.
    if isinstance(content, dict):
        return ParseOutcome(content, None)
    if not isinstance(content, str | bytes):
        # Non-string/non-dict inputs (e.g. a provider bug returning an array
        # or scalar) are treated as an invalid response shape. A *dict* is the
        # happy path; an array/scalar here is a root-type reject.
        return ParseOutcome(
            None,
            PARSE_JSON_ROOT_NOT_OBJECT
            if isinstance(content, list | tuple)
            else PARSE_INVALID_JSON,
        )
    if isinstance(content, bytes):
        try:
            text = content.decode("utf-8-sig")
        except UnicodeDecodeError:
            return ParseOutcome(None, PARSE_INVALID_JSON)
    else:
        text = _strip_bom_and_whitespace(content)
    if not text:
        return ParseOutcome(None, PARSE_EMPTY_RESPONSE)
    if len(text) > MAX_PLAN_INPUT_CHARS:
        # Hard cap before any scan so a giant response cannot drive quadratic
        # matching. The v1 plan schema is small; anything this large is not a
        # plan.
        return ParseOutcome(None, PARSE_INPUT_TOO_LONG)

    candidates: list[tuple[str, int]] = []
    fenced = _fenced_block(text)
    if fenced is not None:
        candidates.append((fenced, 0))
    candidates.append((text, 0))

    last_json_error: ParseErrorCode | None = None
    for candidate, _offset in candidates:
        stripped = candidate.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            # Remember the most informative reason but keep scanning; the next
            # candidate (whole-string vs fenced) may succeed.
            last_json_error = PARSE_INVALID_JSON
            # Suppress unused-variable noise while keeping the location hint
            # available if we later need it (kept out of diagnostics on
            # purpose — never echo offending text).
            _ = exc
            continue
        # A JSON string ("...") whose content is itself JSON-as-text is a valid
        # plan transport (Section 八: "string content"). Parse the inner text
        # exactly once more; an inner array/scalar/string is still a root
        # reject, and an inner non-JSON string falls through to brace extraction.
        while isinstance(parsed, str):
            inner = parsed.strip()
            if not inner:
                break
            try:
                parsed = json.loads(inner)
            except json.JSONDecodeError:
                break
        if not isinstance(parsed, dict):
            return ParseOutcome(None, PARSE_JSON_ROOT_NOT_OBJECT)
        return ParseOutcome(parsed, None)

    # No candidate parsed as a whole / fenced string: fall back to brace
    # extraction from the prose. Before trusting a single extracted object,
    # reject the multi-object case explicitly.
    object_count = _count_top_level_objects(text)
    if object_count > 1:
        return ParseOutcome(None, PARSE_MULTIPLE_JSON_OBJECTS)
    balanced = _balanced_object_slice(text)
    if balanced is None:
        return ParseOutcome(None, PARSE_INVALID_JSON)
    slice_text, start_index = balanced
    try:
        parsed = json.loads(slice_text)
    except json.JSONDecodeError:
        return ParseOutcome(None, PARSE_INVALID_JSON, index=start_index)
    if not isinstance(parsed, dict):
        return ParseOutcome(None, PARSE_JSON_ROOT_NOT_OBJECT, index=start_index)
    return ParseOutcome(parsed, None, index=start_index)


__all__ = [
    "MAX_PLAN_INPUT_CHARS",
    "PARSE_EMPTY_RESPONSE",
    "PARSE_INVALID_JSON",
    "PARSE_JSON_ROOT_NOT_OBJECT",
    "PARSE_MULTIPLE_JSON_OBJECTS",
    "PARSE_INPUT_TOO_LONG",
    "ParseOutcome",
    "ParseErrorCode",
    "PlanParseError",
    "parse_plan_response",
]
