from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

import pytest
from pydantic import ValidationError


@dataclass
class FakeClock:
    wall: datetime = datetime(2026, 7, 24, tzinfo=timezone.utc)
    monotonic_value: float = 100.0

    def utc_now(self) -> datetime:
        return self.wall

    def monotonic(self) -> float:
        return self.monotonic_value

    def sleep(self, seconds: float) -> None:
        self.wall += timedelta(seconds=seconds)
        self.monotonic_value += seconds


class FakeMitmSession:
    def __init__(
        self,
        calls: list[str],
        *,
        start_error: Exception | None = None,
        ready_error: Exception | None = None,
        stop_error: Exception | None = None,
    ) -> None:
        self.calls = calls
        self.start_error = start_error
        self.ready_error = ready_error
        self.stop_error = stop_error
        self.stop_calls = 0

    def start(self) -> None:
        self.calls.append("mitm.start")
        if self.start_error is not None:
            raise self.start_error

    def wait_ready(self, timeout: float | None = None) -> None:
        self.calls.append("mitm.wait_ready")
        if self.ready_error is not None:
            raise self.ready_error

    def stop(self, timeout: float | None = None) -> None:
        self.stop_calls += 1
        self.calls.append("mitm.stop")
        if self.stop_error is not None:
            raise self.stop_error


class FakeFridaSession:
    def __init__(
        self,
        calls: list[str],
        *,
        start_error: Exception | None = None,
        ready_error: Exception | None = None,
        resume_error: Exception | None = None,
        stop_error: Exception | None = None,
    ) -> None:
        self.calls = calls
        self.start_error = start_error
        self.ready_error = ready_error
        self.resume_error = resume_error
        self.stop_error = stop_error
        self.stop_calls = 0

    def start(self) -> None:
        self.calls.append("frida.start")
        if self.start_error is not None:
            raise self.start_error

    def wait_ready(self, timeout: float | None = None) -> None:
        self.calls.append("frida.wait_ready")
        if self.ready_error is not None:
            raise self.ready_error

    def resume(self) -> None:
        self.calls.append("frida.resume")
        if self.resume_error is not None:
            raise self.resume_error

    def stop(self, timeout: float | None = None) -> None:
        self.stop_calls += 1
        self.calls.append("frida.stop")
        if self.stop_error is not None:
            raise self.stop_error


def _import_collection_api() -> tuple[Any, Any]:
    from app.tools.dynamic_collection import (
        DynamicCollectionConfig,
        run_dynamic_collection,
    )

    return DynamicCollectionConfig, run_dynamic_collection


def test_ready_precedes_collection_start_and_app_resume() -> None:
    DynamicCollectionConfig, run_dynamic_collection = _import_collection_api()
    calls: list[str] = []
    controls: list[dict[str, Any]] = []
    clock = FakeClock()
    frida = FakeFridaSession(calls)
    mitm = FakeMitmSession(calls)

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            consent_after_seconds=2,
            pre_consent_seconds=0,
            post_consent_seconds=1,
            enable_traffic=True,
        ),
        emit_control_event=lambda event: (
            calls.append(f"control.{event['event']}"),
            controls.append(event),
        ),
        clock=clock,
    )

    assert result.status == "success"
    assert calls == [
        "mitm.start",
        "mitm.wait_ready",
        "frida.start",
        "frida.wait_ready",
        "control.collection_started",
        "frida.resume",
        "control.consent_granted",
        "frida.stop",
        "mitm.stop",
    ]
    assert result.timeline.collection_started_monotonic_ms == 100_000.0
    assert result.timeline.consent_monotonic_ms == 102_000.0
    assert controls[1]["source"] == "configured_delay"


def test_post_resume_crash_preserves_resume_success_and_fails_stability_gate() -> None:
    DynamicCollectionConfig, run_dynamic_collection = _import_collection_api()
    calls: list[str] = []

    class RuntimeCrash(RuntimeError):
        code = "process_crashed"

    class CrashingFrida(FakeFridaSession):
        error_code = "process_crashed"
        error_message = "native crash"

        def wait_stable(self, timeout_seconds: float) -> bool:
            calls.append(f"frida.wait_stable:{timeout_seconds}")
            raise RuntimeCrash("native crash")

    result = run_dynamic_collection(
        frida_session=CrashingFrida(calls),
        mitm_session=None,
        config=DynamicCollectionConfig(
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
            enable_traffic=False,
            frida_spawn_stability_seconds=3,
        ),
        emit_control_event=lambda event: calls.append(
            f"control.{event['event']}"
        ),
        clock=FakeClock(),
    )

    assert result.status == "failed"
    assert result.primary_error_code == "process_crashed"
    assert result.outcomes["app_resume"] == "success"
    assert result.outcomes["post_resume_stability"] == "failed"
    assert "frida.wait_stable:3" in calls


def test_frida_ready_failure_cleans_only_started_mitm_session() -> None:
    DynamicCollectionConfig, run_dynamic_collection = _import_collection_api()
    calls: list[str] = []
    frida = FakeFridaSession(calls, ready_error=TimeoutError("hook ready"))
    mitm = FakeMitmSession(calls)

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=lambda _: None,
        clock=FakeClock(),
    )

    assert result.status == "failed"
    assert result.primary_error_code == "hook_ready_timeout"
    assert calls == [
        "mitm.start",
        "mitm.wait_ready",
        "frida.start",
        "frida.wait_ready",
        "frida.stop",
        "mitm.stop",
    ]
    assert frida.stop_calls == 1
    assert mitm.stop_calls == 1


def test_mitm_ready_failure_degrades_to_hook_only_and_releases_mitm() -> None:
    DynamicCollectionConfig, run_dynamic_collection = _import_collection_api()
    calls: list[str] = []
    frida = FakeFridaSession(calls)
    mitm = FakeMitmSession(calls, ready_error=TimeoutError("mitm ready"))

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=lambda _: None,
        clock=FakeClock(),
    )

    assert result.status == "partial"
    assert result.primary_error_code == "mitm_ready_timeout"
    assert calls == [
        "mitm.start",
        "mitm.wait_ready",
        "frida.start",
        "frida.wait_ready",
        "frida.resume",
        "frida.stop",
        "mitm.stop",
    ]
    assert frida.stop_calls == 1


def test_frida_failure_degrades_to_network_only_without_consent() -> None:
    DynamicCollectionConfig, run_dynamic_collection = _import_collection_api()
    calls: list[str] = []

    class NetworkMitm(FakeMitmSession):
        def mark_collecting(self) -> None:
            calls.append("mitm.mark_collecting")

    frida = FakeFridaSession(
        calls,
        start_error=RuntimeError("need Gadget to attach on jailed Android"),
    )
    mitm = NetworkMitm(calls)

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            consent_after_seconds=8,
            pre_consent_seconds=10,
            post_consent_seconds=10,
        ),
        emit_control_event=lambda _: pytest.fail(
            "network-only mode must not synthesize consent controls"
        ),
        resume_without_frida=lambda: calls.append("adb.launch"),
        clock=FakeClock(),
    )

    assert result.status == "partial"
    assert result.outcomes["frida_spawn"] == "failed"
    assert result.outcomes["app_resume"] == "success"
    assert result.outcomes["consent_event"] == "skipped"
    assert result.timeline.consent_at is None
    assert "mitm.mark_collecting" in calls
    assert "adb.launch" in calls


def test_primary_failure_and_cleanup_failures_are_preserved_together() -> None:
    DynamicCollectionConfig, run_dynamic_collection = _import_collection_api()
    calls: list[str] = []
    frida = FakeFridaSession(
        calls,
        resume_error=RuntimeError("resume failed"),
        stop_error=RuntimeError("frida cleanup failed"),
    )
    mitm = FakeMitmSession(
        calls,
        stop_error=RuntimeError("mitm cleanup failed"),
    )

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
        ),
        emit_control_event=lambda event: calls.append(
            f"control.{event['event']}"
        ),
        clock=FakeClock(),
    )

    assert result.status == "failed"
    assert result.primary_error_code == "app_resume_failed"
    assert result.primary_error == "resume failed"
    assert len(result.cleanup_errors) == 2
    assert any("frida cleanup failed" in item for item in result.cleanup_errors)
    assert any("mitm cleanup failed" in item for item in result.cleanup_errors)


def test_traffic_disabled_skips_mitm_but_keeps_frida_lifecycle() -> None:
    DynamicCollectionConfig, run_dynamic_collection = _import_collection_api()
    calls: list[str] = []
    controls: list[dict[str, Any]] = []
    frida = FakeFridaSession(calls)
    mitm = FakeMitmSession(calls)

    result = run_dynamic_collection(
        frida_session=frida,
        mitm_session=mitm,
        config=DynamicCollectionConfig(
            consent_after_seconds=None,
            pre_consent_seconds=0,
            post_consent_seconds=0,
            enable_traffic=False,
        ),
        emit_control_event=controls.append,
        clock=FakeClock(),
    )

    assert result.status == "success"
    assert all(not call.startswith("mitm.") for call in calls)
    assert calls == [
        "frida.start",
        "frida.wait_ready",
        "frida.resume",
        "frida.stop",
    ]
    assert controls[0]["event"] == "collection_started"


@pytest.mark.parametrize(
    ("value", "field"),
    [
        (-1, "pre_consent_seconds"),
        (-1, "post_consent_seconds"),
        (-1, "consent_after_seconds"),
        (0, "collection_timeout_seconds"),
    ],
)
def test_collection_config_rejects_invalid_ranges(value: int, field: str) -> None:
    DynamicCollectionConfig, _ = _import_collection_api()
    values: dict[str, Any] = {
        "consent_after_seconds": None,
        "pre_consent_seconds": 0,
        "post_consent_seconds": 0,
        "collection_timeout_seconds": 60,
    }
    values[field] = value

    with pytest.raises(ValueError):
        DynamicCollectionConfig(**values)


def test_dynamic_request_accepts_collection_controls() -> None:
    from app.models import DynamicAnalyzeRequest

    request = DynamicAnalyzeRequest(
        apk_path="D:/fixtures/app.apk",
        enable_traffic=False,
        enable_ui_stimulation=True,
        collection_timeout_seconds=120,
    )

    assert request.enable_traffic is False
    assert request.enable_ui_stimulation is True
    assert request.collection_timeout_seconds == 120


@pytest.mark.parametrize("timeout", [0, 86_401])
def test_dynamic_request_rejects_collection_timeout_out_of_range(
    timeout: int,
) -> None:
    from app.models import DynamicAnalyzeRequest

    with pytest.raises(ValidationError):
        DynamicAnalyzeRequest(
            apk_path="D:/fixtures/app.apk",
            collection_timeout_seconds=timeout,
        )
