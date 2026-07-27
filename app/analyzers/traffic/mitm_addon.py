"""mitmproxy addon that writes privacy-preserving structured request JSONL.

The module deliberately keeps the mitmproxy import optional.  Unit tests use
small fake flow objects, while ``mitmdump -s`` supplies ``mitmproxy.ctx`` in a
real collection process.
"""

from __future__ import annotations

import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:  # pragma: no cover - exercised only when mitmproxy is installed.
    from mitmproxy import ctx as _mitm_ctx
except ImportError:  # Tests and static analysis do not require mitmproxy.
    _mitm_ctx = None

from app.tools.traffic_events import (
    HttpRequestRecord,
    TrafficJSONLWriter,
    build_http_request_record,
    extract_query_keys,
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


class SafeTrafficAddon:
    """Emit one bounded, validated record per completed or failed request."""

    def __init__(
        self,
        *,
        run_id: str | None = None,
        session_id: str | None = None,
        jsonl_path: str | Path | None = None,
        utc_now: Callable[[], datetime] = _utc_now,
    ) -> None:
        self.run_id = run_id
        self.session_id = session_id
        self.jsonl_path = Path(jsonl_path) if jsonl_path is not None else None
        self.utc_now = utc_now
        self._writer: TrafficJSONLWriter | None = None
        self._pending: dict[str, HttpRequestRecord] = {}
        self._emitted: set[str] = set()
        self._lock = threading.RLock()

    def load(self, loader: Any) -> None:
        """Register explicit process options used by :class:`MitmSession`."""

        loader.add_option(
            name="adsdk_run_id",
            typespec=str,
            default="",
            help="AdSDK Agent run owner",
        )
        loader.add_option(
            name="adsdk_session_id",
            typespec=str,
            default="",
            help="AdSDK Agent mitm session owner",
        )
        loader.add_option(
            name="adsdk_jsonl_path",
            typespec=str,
            default="",
            help="Owned structured request JSONL path",
        )

    def _configure_from_mitm(self) -> None:
        if self.run_id and self.session_id and self.jsonl_path is not None:
            return
        if _mitm_ctx is None:
            raise RuntimeError("mitm addon options are not configured")

        options = _mitm_ctx.options
        run_id = str(getattr(options, "adsdk_run_id", "")).strip()
        session_id = str(
            getattr(options, "adsdk_session_id", "")
        ).strip()
        jsonl_path = str(
            getattr(options, "adsdk_jsonl_path", "")
        ).strip()
        if not run_id or not session_id or not jsonl_path:
            raise RuntimeError("mitm addon ownership options are incomplete")
        self.run_id = run_id
        self.session_id = session_id
        self.jsonl_path = Path(jsonl_path)

    def _get_writer(self) -> TrafficJSONLWriter:
        self._configure_from_mitm()
        if self._writer is None:
            assert self.jsonl_path is not None
            self._writer = TrafficJSONLWriter(self.jsonl_path)
        return self._writer

    def running(self) -> None:
        """The control record is the sole addon-ready handshake."""

        writer = self._get_writer()
        assert self.run_id is not None
        assert self.session_id is not None
        writer.write_control(
            event="mitm_ready",
            run_id=self.run_id,
            session_id=self.session_id,
            timestamp_utc=self.utc_now(),
        )

    @staticmethod
    def _content_size(message: object | None) -> int:
        if message is None:
            return 0
        content = getattr(message, "raw_content", None)
        if content is None:
            return 0
        try:
            return len(content)
        except TypeError:
            return 0

    def _build_record(
        self,
        flow: Any,
        *,
        response: object | None = None,
        error: object | None = None,
        incomplete: bool = False,
    ) -> HttpRequestRecord:
        self._configure_from_mitm()
        request = flow.request
        raw_path = str(getattr(request, "path", "/"))
        path, separator, query = raw_path.partition("?")
        timestamp = getattr(request, "timestamp_start", None)
        if timestamp is None:
            timestamp = self.utc_now()
        selected_response = (
            response if response is not None else getattr(flow, "response", None)
        )
        status_code = (
            getattr(selected_response, "status_code", None)
            if selected_response is not None
            else None
        )
        safe_error: object | None
        if incomplete:
            safe_error = "incomplete"
        else:
            safe_error = error

        assert self.run_id is not None
        assert self.session_id is not None
        record = build_http_request_record(
            flow_id=str(flow.id),
            run_id=self.run_id,
            session_id=self.session_id,
            timestamp_utc=timestamp,
            method=str(getattr(request, "method", "")),
            scheme=str(getattr(request, "scheme", "")),
            hostname=str(getattr(request, "host", "")),
            port=int(getattr(request, "port", 0)),
            path=path,
            query_keys=extract_query_keys(query if separator else ""),
            status_code=status_code,
            request_size=self._content_size(request),
            response_size=self._content_size(selected_response),
            error=safe_error,
        )
        if incomplete:
            # ``build_http_request_record`` maps arbitrary errors to
            # ``flow_error``.  The bounded "incomplete" category is set only
            # internally and never incorporates proxy text.
            record = record.model_copy(update={"error": "incomplete"})
        return record

    def request(self, flow: Any) -> None:
        flow_id = str(flow.id)
        with self._lock:
            if flow_id in self._emitted:
                return
            self._pending[flow_id] = self._build_record(
                flow,
                response=None,
            )

    def _emit(
        self,
        flow: Any,
        *,
        response: object | None = None,
        error: object | None = None,
    ) -> None:
        flow_id = str(flow.id)
        with self._lock:
            if flow_id in self._emitted:
                return
            record = self._build_record(
                flow,
                response=response,
                error=error,
            )
            self._get_writer().write_request(record)
            self._emitted.add(flow_id)
            self._pending.pop(flow_id, None)

    def response(self, flow: Any) -> None:
        self._emit(flow, response=flow.response)

    def error(self, flow: Any) -> None:
        # The error object is passed only to the fixed-category mapper.  Its
        # message is never interpolated into logs or artifacts.
        self._emit(flow, error=getattr(flow, "error", True))

    def done(self) -> None:
        """Write safe metadata for requests still pending during shutdown."""

        with self._lock:
            pending = list(self._pending.items())
            self._pending.clear()
            for flow_id, record in pending:
                if flow_id in self._emitted:
                    continue
                safe_record = record.model_copy(
                    update={"error": "incomplete"}
                )
                self._get_writer().write_request(safe_record)
                self._emitted.add(flow_id)


# mitmproxy discovers this conventional module-level addon list.
addons = [SafeTrafficAddon()]
