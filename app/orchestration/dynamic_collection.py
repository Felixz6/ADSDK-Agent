"""Lifecycle coordinator for one isolated dynamic evidence collection.

The coordinator intentionally knows nothing about Frida or mitmproxy process
internals.  It only sequences two run-owned session objects and makes cleanup
ordering explicit.  Real adapters and tests can therefore share exactly the
same lifecycle without requiring either external tool to be installed.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Protocol

from app.core.clock import Clock as CollectionClock, SystemClock as SystemCollectionClock


class CollectionSession(Protocol):
    def start(self) -> Any: ...

    def wait_ready(self, timeout: float | None = None) -> None: ...

    def stop(self, timeout: float | None = None) -> None: ...


class FridaCollectionSession(CollectionSession, Protocol):
    def resume(self) -> None: ...


@dataclass(frozen=True, slots=True)
class DynamicCollectionConfig:
    consent_after_seconds: float | None = None
    pre_consent_seconds: float = 10
    post_consent_seconds: float = 10
    collection_timeout_seconds: float = 300
    frida_ready_timeout_seconds: float = 15
    frida_spawn_stability_seconds: float = 3
    frida_stop_timeout_seconds: float = 5
    mitm_ready_timeout_seconds: float = 10
    mitm_stop_timeout_seconds: float = 5
    enable_traffic: bool = True
    enable_ui_stimulation: bool = False

    def __post_init__(self) -> None:
        non_negative = {
            "pre_consent_seconds": self.pre_consent_seconds,
            "post_consent_seconds": self.post_consent_seconds,
            "consent_after_seconds": self.consent_after_seconds,
        }
        for name, value in non_negative.items():
            if value is not None and value < 0:
                raise ValueError(f"{name} must be greater than or equal to zero")

        positive = {
            "collection_timeout_seconds": self.collection_timeout_seconds,
            "frida_ready_timeout_seconds": self.frida_ready_timeout_seconds,
            "frida_spawn_stability_seconds": self.frida_spawn_stability_seconds,
            "frida_stop_timeout_seconds": self.frida_stop_timeout_seconds,
            "mitm_ready_timeout_seconds": self.mitm_ready_timeout_seconds,
            "mitm_stop_timeout_seconds": self.mitm_stop_timeout_seconds,
        }
        for name, value in positive.items():
            if value <= 0:
                raise ValueError(f"{name} must be greater than zero")


@dataclass(slots=True)
class DynamicTimeline:
    session_created_at: datetime
    session_created_monotonic_ms: float
    hook_ready_at: datetime | None = None
    hook_ready_monotonic_ms: float | None = None
    collection_started_at: datetime | None = None
    collection_started_monotonic_ms: float | None = None
    app_resumed_at: datetime | None = None
    app_resumed_monotonic_ms: float | None = None
    consent_at: datetime | None = None
    consent_monotonic_ms: float | None = None
    collection_ended_at: datetime | None = None
    collection_ended_monotonic_ms: float | None = None

    @staticmethod
    def _utc_text(value: datetime | None) -> str | None:
        if value is None:
            return None
        return (
            value.astimezone(UTC)
            .isoformat(timespec="milliseconds")
            .replace(
                "+00:00",
                "Z",
            )
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "session_created_at": self._utc_text(self.session_created_at),
            "session_created_monotonic_ms": self.session_created_monotonic_ms,
            "hook_ready_at": self._utc_text(self.hook_ready_at),
            "hook_ready_monotonic_ms": self.hook_ready_monotonic_ms,
            "collection_started_at": self._utc_text(self.collection_started_at),
            "collection_started_monotonic_ms": (self.collection_started_monotonic_ms),
            "app_resumed_at": self._utc_text(self.app_resumed_at),
            "app_resumed_monotonic_ms": self.app_resumed_monotonic_ms,
            "consent_at": self._utc_text(self.consent_at),
            "consent_monotonic_ms": self.consent_monotonic_ms,
            "collection_ended_at": self._utc_text(self.collection_ended_at),
            "collection_ended_monotonic_ms": (self.collection_ended_monotonic_ms),
        }


@dataclass(slots=True)
class DynamicCollectionResult:
    status: str
    timeline: DynamicTimeline
    primary_error_code: str | None = None
    primary_error: str | None = None
    cleanup_errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    outcomes: dict[str, str] = field(default_factory=dict)

    @property
    def ok(self) -> bool:
        return self.status == "success"


def _timestamp_utc(clock: CollectionClock) -> str:
    return clock.utc_now().astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def _control_event(
    event: str,
    clock: CollectionClock,
    **values: Any,
) -> dict[str, Any]:
    return {
        "protocol_version": "1.0",
        "schema_version": "1.0",
        "type": "control",
        "event": event,
        "timestamp_utc": _timestamp_utc(clock),
        "monotonic_ms": clock.monotonic() * 1000.0,
        **values,
    }


def _error_code(exc: BaseException, fallback: str) -> str:
    value = getattr(exc, "code", None)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return fallback


def _session_error(
    session: Any,
    fallback_code: str,
    fallback_message: str,
) -> RuntimeError:
    error = RuntimeError(str(getattr(session, "error_message", None) or fallback_message))
    error.code = str(  # type: ignore[attr-defined]
        getattr(session, "error_code", None) or fallback_code
    )
    return error


def _call_timeout_method(
    target: Any,
    method_name: str,
    timeout_seconds: float,
) -> Any:
    method = getattr(target, method_name)
    parameters = inspect.signature(method).parameters
    if "timeout" in parameters:
        return method(timeout=timeout_seconds)
    if "timeout_seconds" in parameters:
        return method(timeout_seconds=timeout_seconds)
    return method(timeout_seconds)


def _sleep_with_deadline(
    seconds: float,
    deadline: float | None,
    clock: CollectionClock,
) -> None:
    if seconds <= 0:
        return
    assert deadline is not None
    if clock.monotonic() + seconds > deadline:
        raise TimeoutError("dynamic collection timeout")
    clock.sleep(seconds)


def _record_primary_failure(
    result: DynamicCollectionResult,
    exc: BaseException,
    fallback_code: str,
) -> None:
    if result.primary_error_code is None:
        result.primary_error_code = _error_code(exc, fallback_code)
        result.primary_error = str(exc) or type(exc).__name__
    result.status = "failed"


def _record_degraded_warning(
    result: DynamicCollectionResult,
    exc: BaseException,
    fallback_code: str,
) -> None:
    if result.primary_error_code is None:
        result.primary_error_code = _error_code(exc, fallback_code)
        result.primary_error = str(exc) or type(exc).__name__
    result.status = "partial"
    result.warnings.append(
        f"{_error_code(exc, fallback_code)}: one dynamic collector is unavailable"
    )


def _setup_mitm_stage(
    mitm_session: CollectionSession | None,
    config: DynamicCollectionConfig,
    result: DynamicCollectionResult,
) -> tuple[bool, bool]:
    """Start and await readiness of the MITM proxy session if enabled."""
    if not config.enable_traffic:
        result.outcomes["mitm_start"] = "skipped"
        result.outcomes["mitm_ready"] = "skipped"
        return False, False

    if mitm_session is None:
        raise RuntimeError("traffic collection is enabled without a session")
    mitm_attempted = True
    traffic_ready = False
    try:
        started = mitm_session.start()
        if started is False:
            raise _session_error(
                mitm_session,
                "mitm_start_failed",
                "mitm session failed to start",
            )
        result.outcomes["mitm_start"] = "success"
    except BaseException as exc:
        result.outcomes["mitm_start"] = "failed"
        result.outcomes["mitm_ready"] = "skipped"
        _record_degraded_warning(result, exc, "mitm_start_failed")
        return mitm_attempted, False

    try:
        ready = _call_timeout_method(
            mitm_session,
            "wait_ready",
            config.mitm_ready_timeout_seconds,
        )
        if ready is False:
            raise _session_error(
                mitm_session,
                "mitm_ready_failed",
                "mitm session did not become ready",
            )
        result.outcomes["mitm_ready"] = "success"
        traffic_ready = True
    except TimeoutError as exc:
        result.outcomes["mitm_ready"] = "failed"
        _record_degraded_warning(result, exc, "mitm_ready_timeout")
    except BaseException as exc:
        result.outcomes["mitm_ready"] = "failed"
        _record_degraded_warning(result, exc, "mitm_ready_failed")

    return mitm_attempted, traffic_ready


def _run_network_fallback_window(
    mitm_session: CollectionSession,
    config: DynamicCollectionConfig,
    result: DynamicCollectionResult,
    active_clock: CollectionClock,
    timeline: DynamicTimeline,
    resume_without_frida: Callable[[], Any] | None,
) -> None:
    """Execute network-only traffic collection when Frida injection is unavailable."""
    collection_deadline = active_clock.monotonic() + config.collection_timeout_seconds
    timeline.collection_started_at = active_clock.utc_now()
    timeline.collection_started_monotonic_ms = active_clock.monotonic() * 1000.0
    try:
        mark_collecting = getattr(mitm_session, "mark_collecting", None)
        if callable(mark_collecting):
            mark_collecting()
        if resume_without_frida is None:
            raise RuntimeError("network-only collection has no app launch callback")
        resume_without_frida()
        result.outcomes["app_resume"] = "success"
        timeline.app_resumed_at = active_clock.utc_now()
        timeline.app_resumed_monotonic_ms = active_clock.monotonic() * 1000.0
        result.outcomes["consent_event"] = "skipped"
        network_window = max(
            config.pre_consent_seconds,
            (config.consent_after_seconds or 0) + config.post_consent_seconds,
        )
        _sleep_with_deadline(network_window, collection_deadline, active_clock)
        result.outcomes["dynamic_collection"] = "partial"
    except TimeoutError as network_exc:
        result.outcomes["dynamic_collection"] = "failed"
        _record_primary_failure(result, network_exc, "dynamic_collection_timeout")
    except BaseException as network_exc:
        result.outcomes["app_resume"] = "failed"
        result.outcomes["dynamic_collection"] = "failed"
        _record_primary_failure(result, network_exc, "network_only_collection_failed")


def _start_frida_stage(
    frida_session: FridaCollectionSession,
    mitm_session: CollectionSession | None,
    config: DynamicCollectionConfig,
    result: DynamicCollectionResult,
    active_clock: CollectionClock,
    timeline: DynamicTimeline,
    traffic_ready: bool,
    on_frida_started: Callable[[FridaCollectionSession], None] | None,
    resume_without_frida: Callable[[], Any] | None,
) -> tuple[bool, bool]:
    """Start Frida session or degrade to network-only fallback if permitted."""
    frida_attempted = True
    frida_start_notified = False
    try:
        started = frida_session.start()
        if started is False:
            raise _session_error(
                frida_session,
                "frida_spawn_failed",
                "Frida session failed to start",
            )
        if on_frida_started is not None:
            on_frida_started(frida_session)
            frida_start_notified = True
        result.outcomes["frida_spawn"] = "success"
        result.outcomes["frida_script_load"] = "success"
        return frida_attempted, False
    except BaseException as exc:
        if (
            on_frida_started is not None
            and not frida_start_notified
            and isinstance(getattr(frida_session, "pid", None), int)
            and getattr(frida_session, "pid") > 0
        ):
            on_frida_started(frida_session)
            frida_start_notified = True
        session_error_code = str(
            getattr(frida_session, "error_code", None) or getattr(exc, "code", None) or ""
        )
        result.outcomes["frida_spawn"] = (
            "success"
            if (
                getattr(frida_session, "pid", None) is not None
                and session_error_code != "frida_spawn_failed"
            )
            else "failed"
        )
        result.outcomes["frida_script_load"] = (
            "failed"
            if session_error_code in {"frida_attach_failed", "hook_load_failed"}
            else "skipped"
        )
        result.outcomes["frida_ready"] = "skipped"
        if not traffic_ready or mitm_session is None:
            _record_primary_failure(result, exc, "frida_spawn_failed")
            return frida_attempted, True
        _record_degraded_warning(result, exc, "frida_spawn_failed")
        _run_network_fallback_window(
            mitm_session,
            config,
            result,
            active_clock,
            timeline,
            resume_without_frida,
        )
        return frida_attempted, True


def _run_hooked_collection_window(
    frida_session: FridaCollectionSession,
    mitm_session: CollectionSession | None,
    config: DynamicCollectionConfig,
    result: DynamicCollectionResult,
    active_clock: CollectionClock,
    timeline: DynamicTimeline,
    traffic_ready: bool,
    emit_control_event: Callable[[dict[str, Any]], Any],
    stimulate_ui: Callable[[], Any] | None,
) -> bool:
    """Wait for hooks ready, resume target, stimulate UI, and handle consent window."""
    try:
        ready = _call_timeout_method(
            frida_session,
            "wait_ready",
            config.frida_ready_timeout_seconds,
        )
        if ready is False:
            raise _session_error(
                frida_session,
                "hook_ready_timeout",
                "Frida session did not become ready",
            )
        result.outcomes["frida_ready"] = "success"
    except TimeoutError as exc:
        result.outcomes["frida_ready"] = "failed"
        _record_primary_failure(result, exc, "hook_ready_timeout")
        return False
    except BaseException as exc:
        result.outcomes["frida_ready"] = "failed"
        _record_primary_failure(result, exc, "frida_protocol_error")
        return False

    timeline.hook_ready_at = active_clock.utc_now()
    timeline.hook_ready_monotonic_ms = active_clock.monotonic() * 1000.0
    timeline.collection_started_at = active_clock.utc_now()
    timeline.collection_started_monotonic_ms = active_clock.monotonic() * 1000.0
    collection_deadline = active_clock.monotonic() + config.collection_timeout_seconds

    try:
        emit_control_event(_control_event("collection_started", active_clock))
        mark_collecting = getattr(mitm_session, "mark_collecting", None)
        if traffic_ready and callable(mark_collecting):
            mark_collecting()
    except BaseException as exc:
        result.outcomes["dynamic_collection"] = "failed"
        _record_primary_failure(result, exc, "frida_protocol_error")
        return False

    try:
        frida_session.resume()
        result.outcomes["app_resume"] = "success"
    except BaseException as exc:
        result.outcomes["app_resume"] = "failed"
        _record_primary_failure(result, exc, "app_resume_failed")
        return False
    timeline.app_resumed_at = active_clock.utc_now()
    timeline.app_resumed_monotonic_ms = active_clock.monotonic() * 1000.0

    stable_waiter = getattr(frida_session, "wait_stable", None)
    if callable(stable_waiter):
        try:
            stable = _call_timeout_method(
                frida_session,
                "wait_stable",
                config.frida_spawn_stability_seconds,
            )
            if stable is False:
                raise _session_error(
                    frida_session,
                    "spawn_runtime_failed",
                    "Target process ended inside the spawn stability window",
                )
            result.outcomes["post_resume_stability"] = "success"
        except BaseException as exc:
            result.outcomes["post_resume_stability"] = "failed"
            _record_primary_failure(result, exc, "process_exited")
            return False
    else:
        result.outcomes["post_resume_stability"] = "not_observed"

    if config.enable_ui_stimulation and stimulate_ui is not None:
        try:
            stimulate_ui()
        except BaseException as exc:
            result.warnings.append(f"ui stimulation failed: {type(exc).__name__}")
            result.status = "partial"

    try:
        if config.consent_after_seconds is not None:
            _sleep_with_deadline(config.consent_after_seconds, collection_deadline, active_clock)
            consent_event = _control_event(
                "consent_granted",
                active_clock,
                source="configured_delay",
            )
            emit_control_event(consent_event)
            result.outcomes["consent_event"] = "success"
            timeline.consent_at = active_clock.utc_now()
            timeline.consent_monotonic_ms = active_clock.monotonic() * 1000.0
            _sleep_with_deadline(config.post_consent_seconds, collection_deadline, active_clock)
        else:
            result.outcomes["consent_event"] = "skipped"
            _sleep_with_deadline(config.pre_consent_seconds, collection_deadline, active_clock)
    except TimeoutError as exc:
        if config.consent_after_seconds is not None:
            result.outcomes.setdefault("consent_event", "failed")
        _record_primary_failure(result, exc, "dynamic_collection_timeout")
    except BaseException as exc:
        result.outcomes["consent_event"] = "failed"
        _record_primary_failure(result, exc, "consent_event_failed")

    result.outcomes["dynamic_collection"] = (
        "success" if result.status == "success" else result.status
    )
    return True


def _cleanup_collection_sessions(
    frida_session: FridaCollectionSession,
    mitm_session: CollectionSession | None,
    config: DynamicCollectionConfig,
    result: DynamicCollectionResult,
    *,
    frida_attempted: bool,
    mitm_attempted: bool,
) -> None:
    """Execute idempotent teardown on both Frida and MITM sessions."""
    if frida_attempted:
        try:
            stopped = _call_timeout_method(
                frida_session,
                "stop",
                config.frida_stop_timeout_seconds,
            )
            if stopped is False:
                raise _session_error(
                    frida_session,
                    "frida_stop_timeout",
                    "Frida cleanup did not complete",
                )
            result.outcomes["frida_stop"] = "success"
        except BaseException as exc:
            result.outcomes["frida_stop"] = "failed"
            result.cleanup_errors.append(f"Frida cleanup failed: {str(exc) or type(exc).__name__}")

    if mitm_attempted and mitm_session is not None:
        try:
            stopped = _call_timeout_method(
                mitm_session,
                "stop",
                config.mitm_stop_timeout_seconds,
            )
            if stopped is False:
                raise _session_error(
                    mitm_session,
                    "mitm_stop_timeout",
                    "mitm cleanup did not complete",
                )
            result.outcomes["mitm_stop"] = "success"
        except BaseException as exc:
            result.outcomes["mitm_stop"] = "failed"
            result.cleanup_errors.append(f"mitm cleanup failed: {str(exc) or type(exc).__name__}")
    else:
        result.outcomes.setdefault("mitm_stop", "skipped")

    if result.cleanup_errors:
        if result.status == "success":
            result.status = "partial"
        result.warnings.extend(result.cleanup_errors)


def run_dynamic_collection(
    *,
    frida_session: FridaCollectionSession,
    mitm_session: CollectionSession | None,
    config: DynamicCollectionConfig,
    emit_control_event: Callable[[dict[str, Any]], Any],
    clock: CollectionClock | None = None,
    stimulate_ui: Callable[[], Any] | None = None,
    resume_without_frida: Callable[[], Any] | None = None,
    on_frida_started: Callable[[FridaCollectionSession], None] | None = None,
) -> DynamicCollectionResult:
    """Run one spawn-gated collection and always clean its owned sessions.

    Session methods may raise typed exceptions exposing a ``code`` attribute.
    The first operational failure remains the primary error; any later cleanup
    problems are appended separately and never replace it.
    """

    active_clock = clock or SystemCollectionClock()
    timeline = DynamicTimeline(
        session_created_at=active_clock.utc_now(),
        session_created_monotonic_ms=active_clock.monotonic() * 1000.0,
    )
    result = DynamicCollectionResult(status="success", timeline=timeline)
    mitm_attempted = False
    frida_attempted = False

    try:
        mitm_attempted, traffic_ready = _setup_mitm_stage(mitm_session, config, result)
        frida_attempted, completed = _start_frida_stage(
            frida_session,
            mitm_session,
            config,
            result,
            active_clock,
            timeline,
            traffic_ready,
            on_frida_started,
            resume_without_frida,
        )
        if not completed:
            _run_hooked_collection_window(
                frida_session,
                mitm_session,
                config,
                result,
                active_clock,
                timeline,
                traffic_ready,
                emit_control_event,
                stimulate_ui,
            )
    finally:
        timeline.collection_ended_at = active_clock.utc_now()
        timeline.collection_ended_monotonic_ms = active_clock.monotonic() * 1000.0
        _cleanup_collection_sessions(
            frida_session,
            mitm_session,
            config,
            result,
            frida_attempted=frida_attempted,
            mitm_attempted=mitm_attempted,
        )

    return result
