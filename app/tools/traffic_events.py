"""Typed, privacy-preserving mitmproxy JSONL traffic protocol.

The protocol intentionally stores request metadata only.  Query values,
headers, and bodies are accepted by the construction boundary so callers do
not need a second representation, but those values are never placed on the
validated model or written to disk.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any, Literal, Mapping, Sequence
from urllib.parse import unquote, unquote_plus, urlsplit

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator

PROTOCOL_VERSION = "1.0"
SCHEMA_VERSION = "1.0"
MAX_JSONL_LINE_BYTES = 1024 * 1024
MAX_PATH_LENGTH = 512
MAX_QUERY_KEY_LENGTH = 128

_METHOD_PATTERN = re.compile(r"^[A-Z][A-Z0-9_-]{0,31}$")
_UUID_PATTERN = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-"
    r"[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$"
)
_TOKENISH_PATTERN = re.compile(r"^[A-Za-z0-9_-]{16,}$")
_SENSITIVE_PATH_KEYS = {
    "access_token",
    "adid",
    "advertising_id",
    "android_id",
    "api_key",
    "apikey",
    "auth",
    "authorization",
    "cookie",
    "device",
    "device_id",
    "email",
    "idfa",
    "oaid",
    "password",
    "passwd",
    "secret",
    "session",
    "session_id",
    "sid",
    "token",
    "user",
    "user_id",
    "userid",
}


def normalize_timestamp_utc(value: datetime | str | int | float) -> str:
    """Return an aware timestamp as canonical millisecond UTC with ``Z``."""

    parsed: datetime
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        parsed = datetime.fromtimestamp(float(value), tz=timezone.utc)
    elif isinstance(value, str):
        candidate = value.strip()
        if not candidate:
            raise ValueError("timestamp_utc must not be blank")
        if candidate.endswith(("Z", "z")):
            candidate = candidate[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(candidate)
        except ValueError as exc:
            raise ValueError("timestamp_utc must be ISO-8601") from exc
    else:
        raise TypeError("timestamp_utc must be datetime, ISO-8601, or epoch")

    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("timestamp_utc must include a timezone")
    return (
        parsed.astimezone(timezone.utc)
        .isoformat(timespec="milliseconds")
        .replace("+00:00", "Z")
    )


def normalize_hostname(hostname: str) -> str:
    """Normalize DNS, IPv4, and IPv6 hosts without retaining URL credentials."""

    value = hostname.strip()
    if value.startswith("[") and value.endswith("]"):
        value = value[1:-1]
    value = value.rstrip(".")
    if not value:
        raise ValueError("hostname must not be blank")
    if any(character in value for character in ("\x00", "\r", "\n", "/", "@")):
        raise ValueError("hostname contains invalid characters")

    try:
        return ipaddress.ip_address(value).compressed.casefold()
    except ValueError:
        pass

    labels = value.split(".")
    if any(not label for label in labels):
        raise ValueError("hostname contains an empty label")
    try:
        normalized = ".".join(
            label.encode("idna").decode("ascii").casefold()
            for label in labels
        )
    except UnicodeError as exc:
        raise ValueError("hostname is not valid IDNA") from exc
    if len(normalized) > 253:
        raise ValueError("hostname is too long")
    return normalized


def _looks_sensitive_segment(segment: str) -> bool:
    lowered = segment.casefold()
    if not segment:
        return False
    if "@" in segment:
        return True
    if _UUID_PATTERN.fullmatch(segment):
        return True
    if segment.count(".") >= 2 and len(segment) >= 20:
        return True
    if segment.isdecimal() and len(segment) >= 7:
        return True
    if _TOKENISH_PATTERN.fullmatch(segment):
        has_alpha = any(character.isalpha() for character in segment)
        has_digit = any(character.isdigit() for character in segment)
        return has_alpha and has_digit
    return lowered.startswith(("bearer-", "token-", "secret-"))


def sanitize_path(path: str | None) -> str:
    """Remove query/fragment and redact identifier-like path segments.

    The policy keeps ordinary routing structure, replaces values following a
    sensitive key (for example ``/token/<value>``), replaces high-entropy or
    identifier-like segments, and caps the persisted path at 512 characters.
    """

    raw = (path or "/").split("?", 1)[0].split("#", 1)[0]
    if not raw.startswith("/"):
        raw = "/" + raw

    output: list[str] = []
    previous_sensitive = False
    for raw_segment in raw.split("/")[1:]:
        segment = raw_segment.split(";", 1)[0]
        decoded_segment = unquote(segment)
        lowered = decoded_segment.casefold()
        sensitive = (
            previous_sensitive
            or _looks_sensitive_segment(decoded_segment)
            or len(segment) > 64
            or any(ord(character) < 32 for character in decoded_segment)
        )
        output.append(":redacted" if sensitive else segment)
        previous_sensitive = lowered in _SENSITIVE_PATH_KEYS

    result = "/" + "/".join(output)
    if result != "/" and result.endswith("/") and not raw.endswith("/"):
        result = result.rstrip("/")
    if len(result) > MAX_PATH_LENGTH:
        result = result[: MAX_PATH_LENGTH - len("/:truncated")].rstrip("/")
        result += "/:truncated"
    return result or "/"


def sanitize_query_key(raw_key: str) -> str | None:
    key = unquote_plus(raw_key).strip()
    if not key:
        return None
    if (
        len(key) > 64
        or _looks_sensitive_segment(key)
        or any(ord(character) < 32 for character in key)
    ):
        return ":redacted_key"
    return key[:MAX_QUERY_KEY_LENGTH]


def extract_query_keys(query: str | None) -> list[str]:
    """Extract only unique query parameter names, never their values."""

    if not query:
        return []
    keys: list[str] = []
    seen: set[str] = set()
    for part in query.split("&"):
        raw_key = part.split("=", 1)[0]
        key = sanitize_query_key(raw_key)
        if key is None:
            continue
        if key not in seen:
            keys.append(key)
            seen.add(key)
    return keys


def sanitize_flow_error(error: object | None) -> str | None:
    """Map arbitrary proxy error text to a bounded non-sensitive category."""

    if error is None:
        return None
    return "flow_error"


class TrafficControlRecord(BaseModel):
    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["1.0"] = PROTOCOL_VERSION
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    type: Literal["control"] = "control"
    event: str = Field(min_length=1, max_length=64)
    run_id: str = Field(min_length=1, max_length=256)
    session_id: str = Field(min_length=1, max_length=256)
    timestamp_utc: str

    @field_validator("timestamp_utc", mode="before")
    @classmethod
    def _timestamp(cls, value: object) -> str:
        if not isinstance(value, (datetime, str, int, float)):
            raise TypeError("timestamp_utc has an unsupported type")
        return normalize_timestamp_utc(value)


class HttpRequestRecord(BaseModel):
    """The complete persisted request schema.

    There are deliberately no header, body, full URL, or query-value fields.
    ``extra='forbid'`` prevents an accidental caller from adding them.
    """

    model_config = ConfigDict(extra="forbid")

    protocol_version: Literal["1.0"] = PROTOCOL_VERSION
    schema_version: Literal["1.0"] = SCHEMA_VERSION
    type: Literal["http_request"] = "http_request"
    flow_id: str = Field(min_length=1, max_length=256)
    run_id: str = Field(min_length=1, max_length=256)
    session_id: str = Field(min_length=1, max_length=256)
    timestamp_utc: str
    method: str
    scheme: Literal["http", "https"]
    hostname: str
    port: int = Field(ge=1, le=65535)
    path: str = Field(min_length=1, max_length=MAX_PATH_LENGTH)
    query_keys: list[str] = Field(default_factory=list)
    status_code: int | None = Field(default=None, ge=100, le=599)
    request_size: int = Field(default=0, ge=0)
    response_size: int = Field(default=0, ge=0)
    tls: bool
    error: Literal["flow_error", "incomplete"] | None = None

    @field_validator("timestamp_utc", mode="before")
    @classmethod
    def _timestamp(cls, value: object) -> str:
        if not isinstance(value, (datetime, str, int, float)):
            raise TypeError("timestamp_utc has an unsupported type")
        return normalize_timestamp_utc(value)

    @field_validator("method", mode="before")
    @classmethod
    def _method(cls, value: object) -> str:
        normalized = str(value).strip().upper()
        if not _METHOD_PATTERN.fullmatch(normalized):
            raise ValueError("invalid HTTP method")
        return normalized

    @field_validator("hostname", mode="before")
    @classmethod
    def _hostname(cls, value: object) -> str:
        return normalize_hostname(str(value))

    @field_validator("path", mode="before")
    @classmethod
    def _path(cls, value: object) -> str:
        return sanitize_path(str(value))

    @field_validator("query_keys", mode="before")
    @classmethod
    def _query_keys(cls, value: object) -> list[str]:
        if value is None:
            return []
        if isinstance(value, (str, bytes)) or not isinstance(value, Sequence):
            raise TypeError("query_keys must be a sequence")
        keys: list[str] = []
        seen: set[str] = set()
        for item in value:
            key = sanitize_query_key(str(item))
            if key is not None and key not in seen:
                keys.append(key)
                seen.add(key)
        return keys


def build_http_request_record(
    *,
    flow_id: str,
    run_id: str,
    session_id: str,
    timestamp_utc: datetime | str | int | float,
    method: str,
    url: str | None = None,
    scheme: str | None = None,
    hostname: str | None = None,
    port: int | None = None,
    path: str | None = None,
    query_keys: Sequence[str] | None = None,
    status_code: int | None = None,
    request_size: int = 0,
    response_size: int = 0,
    error: object | None = None,
    request_headers: Mapping[str, object] | None = None,
    request_body: bytes | str | None = None,
    response_headers: Mapping[str, object] | None = None,
    response_body: bytes | str | None = None,
) -> HttpRequestRecord:
    """Construct a safe record while intentionally discarding sensitive input."""

    # These values are accepted at the boundary solely to make the privacy
    # contract explicit.  Do not inspect or interpolate them into exceptions.
    del request_headers, request_body, response_headers, response_body

    selected_scheme = (scheme or "").strip().casefold()
    selected_hostname = hostname
    selected_port = port
    selected_path = path
    selected_query_keys = list(query_keys) if query_keys is not None else None

    if url is not None:
        parsed = urlsplit(url)
        selected_scheme = parsed.scheme.casefold()
        selected_hostname = parsed.hostname
        try:
            parsed_port = parsed.port
        except ValueError as exc:
            raise ValueError("URL port is invalid") from exc
        selected_port = selected_port or parsed_port
        selected_path = parsed.path or "/"
        if selected_query_keys is None:
            selected_query_keys = extract_query_keys(parsed.query)

    if selected_scheme not in {"http", "https"}:
        raise ValueError("scheme must be http or https")
    if selected_hostname is None:
        raise ValueError("hostname is required")
    if selected_port is None:
        selected_port = 443 if selected_scheme == "https" else 80

    return HttpRequestRecord(
        flow_id=flow_id,
        run_id=run_id,
        session_id=session_id,
        timestamp_utc=timestamp_utc,
        method=method,
        scheme=selected_scheme,
        hostname=selected_hostname,
        port=selected_port,
        path=selected_path or "/",
        query_keys=selected_query_keys or [],
        status_code=status_code,
        request_size=request_size,
        response_size=response_size,
        tls=selected_scheme == "https",
        error=sanitize_flow_error(error),
    )


class TrafficJSONLWriter:
    """Append validated records as individual fsynced UTF-8 JSON lines."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self.path.touch(exist_ok=True)

    def _write_model(self, model: BaseModel) -> None:
        line = model.model_dump_json(exclude_none=False)
        with self._lock:
            with self.path.open("a", encoding="utf-8", newline="\n") as stream:
                stream.write(line)
                stream.write("\n")
                stream.flush()
                os.fsync(stream.fileno())

    def write_control(
        self,
        *,
        event: str,
        run_id: str,
        session_id: str,
        timestamp_utc: datetime | str | int | float,
    ) -> TrafficControlRecord:
        control = TrafficControlRecord(
            event=event,
            run_id=run_id,
            session_id=session_id,
            timestamp_utc=timestamp_utc,
        )
        self._write_model(control)
        return control

    def write_request(self, record: HttpRequestRecord) -> None:
        if not isinstance(record, HttpRequestRecord):
            raise TypeError("record must be HttpRequestRecord")
        self._write_model(record)


@dataclass(frozen=True, slots=True)
class TrafficValidationIssue:
    code: str
    line_number: int


@dataclass(slots=True)
class TrafficReadResult:
    records: list[HttpRequestRecord] = field(default_factory=list)
    controls: list[TrafficControlRecord] = field(default_factory=list)
    issues: list[TrafficValidationIssue] = field(default_factory=list)
    ready_seen: bool = False

    @property
    def malformed_count(self) -> int:
        return sum(
            issue.code.startswith("traffic_malformed")
            for issue in self.issues
        )

    @property
    def mismatch_count(self) -> int:
        return sum(
            issue.code in {
                "traffic_run_mismatch",
                "traffic_session_mismatch",
            }
            for issue in self.issues
        )


def load_traffic_jsonl(
    path: str | os.PathLike[str],
    *,
    run_id: str,
    session_id: str,
) -> TrafficReadResult:
    """Read only validated records belonging to the expected collection."""

    result = TrafficReadResult()
    source = Path(path)
    if not source.is_file():
        result.issues.append(
            TrafficValidationIssue("traffic_file_missing", 0)
        )
        return result

    with source.open("r", encoding="utf-8", errors="strict") as stream:
        for line_number, line in enumerate(stream, start=1):
            if len(line.encode("utf-8")) > MAX_JSONL_LINE_BYTES:
                result.issues.append(
                    TrafficValidationIssue(
                        "traffic_malformed_oversize",
                        line_number,
                    )
                )
                continue
            try:
                payload = json.loads(line)
            except (json.JSONDecodeError, TypeError, ValueError):
                result.issues.append(
                    TrafficValidationIssue(
                        "traffic_malformed_json",
                        line_number,
                    )
                )
                continue
            if not isinstance(payload, dict):
                result.issues.append(
                    TrafficValidationIssue(
                        "traffic_malformed_record",
                        line_number,
                    )
                )
                continue

            record_type = payload.get("type")
            try:
                if record_type == "control":
                    record: TrafficControlRecord | HttpRequestRecord = (
                        TrafficControlRecord.model_validate(payload)
                    )
                elif record_type == "http_request":
                    record = HttpRequestRecord.model_validate(payload)
                else:
                    result.issues.append(
                        TrafficValidationIssue(
                            "traffic_unknown_record_type",
                            line_number,
                        )
                    )
                    continue
            except ValidationError:
                result.issues.append(
                    TrafficValidationIssue(
                        "traffic_malformed_record",
                        line_number,
                    )
                )
                continue

            if record.run_id != run_id:
                result.issues.append(
                    TrafficValidationIssue(
                        "traffic_run_mismatch",
                        line_number,
                    )
                )
                continue
            if record.session_id != session_id:
                result.issues.append(
                    TrafficValidationIssue(
                        "traffic_session_mismatch",
                        line_number,
                    )
                )
                continue

            if isinstance(record, TrafficControlRecord):
                result.controls.append(record)
                if record.event == "mitm_ready":
                    result.ready_seen = True
            else:
                result.records.append(record)
    return result


class TrafficCollectionOutcome(str, Enum):
    COLLECTOR_FAILED = "collector_failed"
    SUCCESS_ZERO_REQUESTS = "collector_success_zero_requests"
    SUCCESS_REQUESTS_OBSERVED = "collector_success_requests_observed"


@dataclass(slots=True)
class TrafficCollectionResult:
    outcome: TrafficCollectionOutcome
    coverage: Literal["unavailable", "no_observations", "observed"]
    process_ready: bool
    addon_ready: bool
    records: list[HttpRequestRecord]
    issues: list[TrafficValidationIssue]

    @property
    def valid_request_count(self) -> int:
        return len(self.records)

    @property
    def malformed_count(self) -> int:
        return sum(
            issue.code.startswith("traffic_malformed")
            for issue in self.issues
        )

    @property
    def mismatch_count(self) -> int:
        return sum(
            issue.code in {
                "traffic_run_mismatch",
                "traffic_session_mismatch",
            }
            for issue in self.issues
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "outcome": self.outcome.value,
            "coverage": self.coverage,
            "process_ready": self.process_ready,
            "addon_ready": self.addon_ready,
            "valid_request_count": self.valid_request_count,
            "malformed_count": self.malformed_count,
            "mismatch_count": self.mismatch_count,
            "issues": [
                {"code": issue.code, "line_number": issue.line_number}
                for issue in self.issues
            ],
            "records": [
                record.model_dump(mode="json") for record in self.records
            ],
        }


def validate_traffic_jsonl(
    path: str | os.PathLike[str],
    *,
    run_id: str,
    session_id: str,
    process_ready: bool,
) -> TrafficCollectionResult:
    """Validate ownership and classify collector failure vs clean zero traffic."""

    read_result = load_traffic_jsonl(
        path,
        run_id=run_id,
        session_id=session_id,
    )
    failed = (
        not process_ready
        or not read_result.ready_seen
        or bool(read_result.issues)
    )
    if failed:
        outcome = TrafficCollectionOutcome.COLLECTOR_FAILED
        coverage: Literal[
            "unavailable", "no_observations", "observed"
        ] = "unavailable"
    elif read_result.records:
        outcome = TrafficCollectionOutcome.SUCCESS_REQUESTS_OBSERVED
        coverage = "observed"
    else:
        outcome = TrafficCollectionOutcome.SUCCESS_ZERO_REQUESTS
        coverage = "no_observations"

    return TrafficCollectionResult(
        outcome=outcome,
        coverage=coverage,
        process_ready=process_ready,
        addon_ready=read_result.ready_seen,
        records=read_result.records,
        issues=read_result.issues,
    )
