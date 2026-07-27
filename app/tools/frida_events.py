"""Typed Frida message protocol and durable JSONL event writer.

The Frida transport is treated as an untrusted message boundary.  Payloads are
copied into a strict allow-list, identifiers are pseudonymized before any
serialization, and validation failures are represented by metadata-only error
records that never echo the original payload.
"""

from __future__ import annotations

import json
import math
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal, Mapping

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.config import SCHEMA_VERSION
from app.core.artifacts import atomic_write_json
from app.core.redaction import Redactor

PROTOCOL_VERSION = "1.0"
ConsentState = Literal["pre_consent", "post_consent", "unknown"]

_RAW_IDENTIFIER_KEYS = {
    "raw_value",
    "identifier_value",
    "identifier_raw",
}
_SENSITIVE_METADATA_KEYS = {
    "android_id",
    "advertising_id",
    "authorization",
    "cookie",
    "device_id",
    "gaid",
    "imei",
    "meid",
    "oaid",
    "password",
    "raw_value",
    "result",
    "serial",
    "set-cookie",
    "token",
    "value",
}
_EVENT_FIELDS = {
    "protocol_version",
    "schema_version",
    "type",
    "event_id",
    "run_id",
    "session_id",
    "timestamp_utc",
    "monotonic_ms",
    "pid",
    "process_name",
    "thread_id",
    "thread_name",
    "category",
    "api",
    "action",
    "identifier_type",
    "identifier_present",
    "value_token",
    "raw_retained",
    "stack",
    "metadata",
    "consent_state",
}
_CONTROL_FIELDS = {
    "protocol_version",
    "schema_version",
    "type",
    "event_id",
    "event",
    "run_id",
    "session_id",
    "timestamp_utc",
    "monotonic_ms",
    "pid",
    "source",
    "installed_hooks",
    "failed_hooks",
    "metadata",
}


def _utc_iso(value: Any) -> str:
    """Validate and normalize an aware ISO timestamp to UTC."""

    if not isinstance(value, str) or not value.strip():
        raise ValueError("timestamp_utc must be a non-empty ISO timestamp")
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError as exc:
        raise ValueError("timestamp_utc must be a valid ISO timestamp") from exc
    if parsed.tzinfo is None:
        raise ValueError("timestamp_utc must include a timezone")
    normalized = parsed.astimezone(timezone.utc).isoformat(timespec="milliseconds")
    return normalized.replace("+00:00", "Z")


def utc_now_iso() -> str:
    return (
        datetime.now(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def _metadata_is_safe(value: Any) -> bool:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if str(key).strip().casefold() in _SENSITIVE_METADATA_KEYS:
                return False
            if not _metadata_is_safe(item):
                return False
        return True
    if isinstance(value, (list, tuple)):
        return all(_metadata_is_safe(item) for item in value)
    return value is None or isinstance(value, (str, int, float, bool))


class FridaEventValidationError(ValueError):
    """A safe protocol error that intentionally omits untrusted values."""

    def __init__(self, code: str, message: str = "Frida message validation failed"):
        self.code = code
        super().__init__(message)


class FridaStructuredEvent(BaseModel):
    """Validated dynamic observation."""

    model_config = ConfigDict(extra="forbid", strict=True)

    protocol_version: Literal["1.0"] = PROTOCOL_VERSION
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    type: Literal["event"]
    event_id: str
    run_id: str
    session_id: str
    timestamp_utc: str
    monotonic_ms: float = Field(ge=0)
    pid: int = Field(gt=0)
    process_name: str = Field(min_length=1)
    thread_id: int = Field(ge=0)
    thread_name: str | None = None
    category: str = Field(min_length=1)
    api: str = Field(min_length=1)
    action: str = Field(min_length=1)
    identifier_type: str | None = None
    identifier_present: bool | None = None
    value_token: str | None = None
    raw_retained: Literal[False] = False
    stack: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)
    consent_state: ConsentState = "unknown"

    @field_validator("timestamp_utc")
    @classmethod
    def validate_timestamp(cls, value: Any) -> str:
        return _utc_iso(value)

    @field_validator("monotonic_ms")
    @classmethod
    def validate_monotonic(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("monotonic_ms must be finite")
        return value

    @field_validator(
        "event_id",
        "run_id",
        "session_id",
        "process_name",
        "category",
        "api",
        "action",
    )
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("required text field must not be empty")
        return normalized

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not _metadata_is_safe(value):
            raise ValueError("metadata contains a sensitive raw-value field")
        return value

    @model_validator(mode="after")
    def validate_identifier_shape(self) -> "FridaStructuredEvent":
        is_identifier = (
            self.category == "identifier_access"
            or self.identifier_type is not None
            or self.identifier_present is not None
        )
        if is_identifier:
            if not self.identifier_type:
                raise ValueError("identifier_type is required")
            if self.identifier_present is None:
                raise ValueError("identifier_present is required")
            if self.identifier_present:
                if not self.value_token or not self.value_token.startswith(
                    "redacted:"
                ):
                    raise ValueError("a redacted value_token is required")
            elif self.value_token is not None and not self.value_token.startswith(
                "redacted:"
            ):
                raise ValueError("value_token must be redacted")
        elif self.value_token is not None:
            raise ValueError("value_token is only valid for identifier events")
        return self


class FridaControlEvent(BaseModel):
    """Validated lifecycle control record."""

    model_config = ConfigDict(extra="forbid", strict=True)

    protocol_version: Literal["1.0"] = PROTOCOL_VERSION
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    type: Literal["control"]
    event_id: str
    event: str = Field(min_length=1)
    run_id: str
    session_id: str
    timestamp_utc: str
    monotonic_ms: float = Field(ge=0)
    pid: int = Field(gt=0)
    source: str | None = None
    installed_hooks: list[str] = Field(default_factory=list)
    failed_hooks: list[str] = Field(default_factory=list)
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("timestamp_utc")
    @classmethod
    def validate_timestamp(cls, value: Any) -> str:
        return _utc_iso(value)

    @field_validator("monotonic_ms")
    @classmethod
    def validate_monotonic(cls, value: float) -> float:
        if not math.isfinite(value):
            raise ValueError("monotonic_ms must be finite")
        return value

    @field_validator("event_id", "event", "run_id", "session_id")
    @classmethod
    def validate_non_empty(cls, value: str) -> str:
        normalized = value.strip()
        if not normalized:
            raise ValueError("required text field must not be empty")
        return normalized

    @field_validator("metadata")
    @classmethod
    def validate_metadata(cls, value: dict[str, Any]) -> dict[str, Any]:
        if not _metadata_is_safe(value):
            raise ValueError("metadata contains a sensitive raw-value field")
        return value

    @model_validator(mode="after")
    def validate_control_shape(self) -> "FridaControlEvent":
        if self.event == "hook_ready" and not (
            self.installed_hooks or self.failed_hooks
        ):
            # An empty target set is almost always a script/protocol defect.
            raise ValueError("hook_ready must report attempted hooks")
        if self.event == "consent_granted" and not self.source:
            raise ValueError("consent_granted must include source")
        return self


FridaMessage = FridaStructuredEvent | FridaControlEvent


def safe_message_type(value: Any) -> str | None:
    if value in {"event", "control", "send", "error", "log"}:
        return str(value)
    return "unknown" if value is not None else None


def _safe_copy(payload: Mapping[str, Any], fields: set[str]) -> dict[str, Any]:
    return {name: payload[name] for name in fields if name in payload}


def normalize_frida_payload(
    payload: Mapping[str, Any],
    *,
    run_id: str,
    session_id: str,
    redactor: Redactor | None = None,
) -> FridaMessage:
    """Normalize an untrusted transport payload into a typed record.

    ``raw_value`` is accepted only as an in-memory bridge for adapters that can
    deliver it without stdout/file logging.  It is HMAC-pseudonymized before
    model construction and is never copied into an exception.
    """

    if not isinstance(payload, Mapping):
        raise FridaEventValidationError("payload_not_object")

    message_type = payload.get("type")
    if message_type not in {"event", "control"}:
        raise FridaEventValidationError("unsupported_message_type")

    supplied_run_id = payload.get("run_id")
    supplied_session_id = payload.get("session_id")
    if supplied_run_id not in {None, run_id}:
        raise FridaEventValidationError("run_mismatch")
    if supplied_session_id not in {None, session_id}:
        raise FridaEventValidationError("session_mismatch")

    fields = _EVENT_FIELDS if message_type == "event" else _CONTROL_FIELDS
    unexpected_fields = set(payload) - fields - _RAW_IDENTIFIER_KEYS
    if unexpected_fields:
        raise FridaEventValidationError("unknown_fields")

    raw_identifier: Any = None
    for key in _RAW_IDENTIFIER_KEYS:
        if key in payload:
            raw_identifier = payload.get(key)
            break

    normalized = _safe_copy(payload, fields)
    normalized["type"] = message_type
    normalized["run_id"] = run_id
    normalized["session_id"] = session_id
    normalized.setdefault("protocol_version", PROTOCOL_VERSION)
    normalized.setdefault("schema_version", SCHEMA_VERSION)
    normalized.setdefault("event_id", str(uuid.uuid4()))
    normalized.setdefault("metadata", {})

    if message_type == "event":
        normalized.setdefault("raw_retained", False)
        normalized.setdefault("stack", [])
        normalized.setdefault("consent_state", "unknown")

        identifier_type = normalized.get("identifier_type")
        if raw_identifier is not None:
            if not isinstance(raw_identifier, (str, bytes)):
                raise FridaEventValidationError("invalid_identifier_transport")
            redaction = redactor or Redactor()
            normalized["value_token"] = redaction.redact_identifier(
                raw_identifier,
                kind=str(identifier_type or "identifier"),
            )
            normalized.setdefault(
                "identifier_present",
                bool(
                    raw_identifier.strip()
                    if isinstance(raw_identifier, bytes)
                    else raw_identifier.strip()
                ),
            )
        elif normalized.get("identifier_present") and not normalized.get(
            "value_token"
        ):
            # The default JS collector intentionally withholds the raw value.
            # This explicit token signals presence without pretending that a
            # cross-event stable value comparison was possible.
            normalized["value_token"] = "redacted:withheld-at-source"

    try:
        if message_type == "event":
            return FridaStructuredEvent.model_validate(normalized)
        return FridaControlEvent.model_validate(normalized)
    except Exception:
        raise FridaEventValidationError("validation_error") from None


def unwrap_frida_message(
    message: Mapping[str, Any],
    *,
    run_id: str,
    session_id: str,
    redactor: Redactor | None = None,
) -> FridaMessage:
    """Validate a standard Frida ``script.on('message')`` envelope."""

    if not isinstance(message, Mapping):
        raise FridaEventValidationError("invalid_transport_envelope")
    if message.get("type") != "send":
        raise FridaEventValidationError("transport_error")
    payload = message.get("payload")
    if not isinstance(payload, Mapping):
        raise FridaEventValidationError("payload_not_object")
    return normalize_frida_payload(
        payload,
        run_id=run_id,
        session_id=session_id,
        redactor=redactor,
    )


def normalize_consent_states(
    messages: list[Mapping[str, Any]],
) -> list[dict[str, Any]]:
    """Return canonical event objects classified by one consent control."""

    from .timeline_rules import classify_consent_state

    consent_monotonic_ms: float | int | None = None
    for item in messages:
        if (
            item.get("type") == "control"
            and item.get("event") == "consent_granted"
        ):
            consent_monotonic_ms = item.get("monotonic_ms")
            break

    normalized: list[dict[str, Any]] = []
    for item in messages:
        copy = dict(item)
        if copy.get("type") == "event":
            copy["consent_state"] = classify_consent_state(
                copy.get("monotonic_ms"),
                consent_monotonic_ms,
            )
        normalized.append(copy)
    return normalized


def write_events_json(
    messages: list[Mapping[str, Any]],
    output_path: str | os.PathLike[str],
) -> Path:
    """Atomically publish the compatibility ``events.json`` array."""

    return atomic_write_json(
        output_path,
        normalize_consent_states(messages),
    )


class StructuredEventWriter:
    """Thread-safe, append-only JSONL writer for validated Frida messages."""

    def __init__(
        self,
        path: str | os.PathLike[str],
        *,
        run_id: str,
        session_id: str,
        protocol_error_path: str | os.PathLike[str] | None = None,
        redactor: Redactor | None = None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.run_id = run_id
        self.session_id = session_id
        self.protocol_error_path = (
            Path(protocol_error_path)
            if protocol_error_path is not None
            else self.path.with_name("frida.protocol-errors.jsonl")
        )
        self.protocol_error_path.parent.mkdir(parents=True, exist_ok=True)
        self.redactor = redactor or Redactor()
        self.valid_events: list[dict[str, Any]] = []
        self.control_events: list[dict[str, Any]] = []
        self.valid_messages: list[dict[str, Any]] = []
        self.protocol_errors: list[dict[str, Any]] = []
        self._lock = threading.RLock()

    @staticmethod
    def _write_line(path: Path, payload: Mapping[str, Any]) -> None:
        encoded = json.dumps(
            payload,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        )
        with path.open("a", encoding="utf-8", newline="\n") as stream:
            stream.write(encoded)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())

    def record_protocol_error(
        self,
        code: str,
        *,
        message_type: str | None = None,
    ) -> dict[str, Any]:
        record = {
            "protocol_version": PROTOCOL_VERSION,
            "type": "protocol_error",
            "timestamp_utc": utc_now_iso(),
            "run_id": self.run_id,
            "session_id": self.session_id,
            "code": code,
            "message_type": message_type,
            "raw_retained": False,
        }
        with self._lock:
            self.protocol_errors.append(record)
            self._write_line(self.protocol_error_path, record)
        return record

    def append(
        self,
        payload: Mapping[str, Any] | FridaMessage,
    ) -> FridaMessage | None:
        try:
            model = (
                payload
                if isinstance(payload, (FridaStructuredEvent, FridaControlEvent))
                else normalize_frida_payload(
                    payload,
                    run_id=self.run_id,
                    session_id=self.session_id,
                    redactor=self.redactor,
                )
            )
        except FridaEventValidationError as exc:
            message_type = (
                safe_message_type(payload.get("type"))
                if isinstance(payload, Mapping)
                else None
            )
            self.record_protocol_error(exc.code, message_type=message_type)
            return None

        serialized = model.model_dump(mode="json")
        with self._lock:
            self._write_line(self.path, serialized)
            self.valid_messages.append(serialized)
            if isinstance(model, FridaStructuredEvent):
                self.valid_events.append(serialized)
            else:
                self.control_events.append(serialized)
        return model

    def write_events_json(self, output_path: str | os.PathLike[str]) -> Path:
        with self._lock:
            snapshot = list(self.valid_messages)
        return write_events_json(snapshot, output_path)
