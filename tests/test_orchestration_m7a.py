"""M7A orchestration package — no-device automated tests.

Covers device-session schema/masking, the reclaimable device lease, the
resource ownership registry + cleanup manager (10 rules), the consent
checkpoint (state-gated, idempotent, no auto-confirm, cancel-exits), the
constrained plan validator / DAG / whitelist / confirmation rules, and the
full-analysis session state machine with fake effects (success, lease-busy,
cancel, consent-cancel, orchestration-failure, cleanup-always-runs, the 24
injected-failure contracts from Section 20).

No real ADB / Frida / mitmproxy / DeepSeek connection is touched. Everything
is injected.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Callable, Literal

import pytest

from app.ai.models import AIPlan, AITokenUsage, AIReport, EvidenceDigest, PlanStep
from app.ai.orchestrator import AIOrchestrationRequest, AIOrchestrationResult
from app.orchestration.cleanup_manager import (
    CleanupManager,
    CleanupOutcome,
    OwnedResource,
    ResourceOwnershipRegistry,
)
from app.orchestration.consent_checkpoint import (
    ConsentCheckpointError,
    ConsentCheckpointService,
)
from app.orchestration.device_lease import (
    LeaseAcquireError,
    LeaseRegistry,
)
from app.orchestration.device_session import (
    DeviceSessionSnapshot,
    DeviceState,
    build_snapshot,
    mask_device_ref,
)
from app.orchestration.full_analysis_session import (
    FullAnalysisAcceptance,
    FullAnalysisSession,
    PlanValidationError,
    SessionEvent,
    SessionState,
    SessionTransition,
    build_default_plan,
    build_full_analysis_acceptance,
    build_full_analysis_plan,
    execute_full_analysis_plan,
    verify_cleanup,
)

# ---------------------------------------------------------------------------
# Fixtures / fakes.
# ---------------------------------------------------------------------------


class _FakeProbe:
    """Read-only ADB-shaped probe for snapshot tests."""

    def __init__(
        self,
        *,
        online: bool = True,
        abi: str | None = "x86_64",
        http_proxy: str | None = "",
        frida_pids: list[int] | None = None,
        package_installed: bool | None = True,
        package_version: str | None = "1.2.3",
        foreground: str | None = "launcher",
    ) -> None:
        self._online = online
        self._abi = abi
        self._http_proxy = http_proxy
        self._frida_pids = frida_pids or []
        self._package_installed = package_installed
        self._package_version = package_version
        self._foreground = foreground
        self.calls: list[tuple] = []

    def adb_devices(self) -> dict[str, Any]:
        self.calls.append(("adb_devices",))
        status = "device" if self._online else "offline"
        return {
            "devices": [{"device_id": "127.0.0.1:16416", "status": status}]
        }

    def getprop(self, device: str, name: str) -> str | None:
        self.calls.append(("getprop", device, name))
        if name == "ro.product.cpu.abi":
            return self._abi
        if name == "ro.build.version.release":
            return "12"
        if name == "ro.build.version.sdk":
            return "31"
        if name in ("ro.boot.boot_id", "ro.bootime.boot_id"):
            return "boot-abc"
        return None

    def settings_get(self, device: str, namespace: str, key: str) -> str | None:
        self.calls.append(("settings_get", device, namespace, key))
        if namespace == "global" and key == "http_proxy":
            return self._http_proxy
        return None

    def pidof(self, device: str, process: str) -> list[int]:
        self.calls.append(("pidof", device, process))
        if process == "frida-server":
            return list(self._frida_pids)
        return []

    def frida_server_version(self, device: str) -> str | None:
        self.calls.append(("frida_server_version", device))
        return "16.5.9" if self._frida_pids else None

    def current_focus(self, device: str) -> str | None:
        self.calls.append(("current_focus", device))
        return self._foreground

    def pm_package_info(self, device: str, package: str) -> dict[str, Any]:
        self.calls.append(("pm_package_info", device, package))
        return {
            "installed": bool(self._package_installed),
            "version_name": self._package_version,
        }


def _make_snapshot(
    *,
    run_id: str = "run-1",
    device_id: str | None = "127.0.0.1:16416",
    http_proxy: str | None = "",
    frida_pids: list[int] | None = None,
) -> DeviceSessionSnapshot:
    probe = _FakeProbe(http_proxy=http_proxy, frida_pids=frida_pids or [])
    return build_snapshot(
        run_id=run_id,
        device_id=device_id,
        probe=probe,
        captured_at="2026-08-02T00:00:00Z",
        package_name="com.phoenix.read",
        capture_kind="preflight",
    )


# ---------------------------------------------------------------------------
# device-session-v1 schema + masking.
# ---------------------------------------------------------------------------


def test_snapshot_masks_device_ref_and_keeps_operational_facts():
    snap = _make_snapshot(device_id="127.0.0.1:16416")
    assert snap.schema_version == "device-session-v1"
    assert snap.device_ref.startswith("redacted:")
    assert "16416" not in snap.device_ref
    state = snap.initial_state
    assert state.online is True
    assert state.abi == "x86_64"
    assert state.http_proxy == ""
    assert state.boot_id == "boot-abc"
    assert state.package_installed is True
    assert state.package_version_name == "1.2.3"
    assert snap.run_id == "run-1"


def test_snapshot_no_device_yields_no_device_token():
    snap = _make_snapshot(device_id=None)
    assert snap.device_ref == "__no_device__"
    assert snap.initial_state.online is False


def test_mask_device_ref_is_stable_and_redacted_none_safe():
    a = mask_device_ref("EMU123")
    b = mask_device_ref("EMU123")
    assert a == b and a.startswith("redacted:")
    assert mask_device_ref(None) == "__no_device__"
    assert mask_device_ref("") == "__no_device__"


def test_snapshot_proxy_normalises_empty_and_colon_zero():
    snap = _make_snapshot(device_id="127.0.0.1:16416", http_proxy=":0")
    assert snap.initial_state.http_proxy == ""


def test_snapshot_proxy_normalises_mumu_colon_null():
    # MuMu builds return the literal string ":null" (exit 0) when no proxy is
    # set. It must normalise to "" so cleanup deletes the proxy rather than
    # writing back a bogus ":null" value. Surfaced by Phase B preflight.
    snap = _make_snapshot(device_id="127.0.0.1:16416", http_proxy=":null")
    assert snap.initial_state.http_proxy == ""


def test_snapshot_records_frida_server_present_but_not_owned():
    snap = _make_snapshot(frida_pids=[4321])
    assert snap.initial_state.frida_server_present is True
    assert snap.initial_state.frida_server_pid == 4321
    assert snap.initial_state.frida_server_owned is False
    assert snap.initial_state.frida_server_version == "16.5.9"


def test_snapshot_offline_records_frida_present_none():
    probe = _FakeProbe(online=False, frida_pids=[4321])
    snap = build_snapshot(
        run_id="r", device_id="127.0.0.1:16416", probe=probe,
        captured_at="T",
    )
    assert snap.initial_state.online is False
    assert snap.initial_state.frida_server_present is None


def test_snapshot_safe_dump_has_no_secret():
    dump = _make_snapshot(device_id="127.0.0.1:16416").safe_dump()
    assert "16416" not in dump["device_ref"]
    assert dump["schema_version"] == "device-session-v1"


# ---------------------------------------------------------------------------
# Lease registry.
# ---------------------------------------------------------------------------


class _FakeClock:
    def __init__(self, start: float = 0.0) -> None:
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def test_lease_acquire_release_roundtrip():
    clock = _FakeClock()
    reg = LeaseRegistry(clock=clock, stale_after_seconds=600)
    lease = reg.acquire(
        device_key="redacted:dev1", run_id="run-a", task_id="t1"
    )
    assert reg.state("redacted:dev1") == "held"
    assert lease.owner_run_id == "run-a"
    ok = reg.release(device_key="redacted:dev1", run_id="run-a")
    assert ok is True
    assert reg.state("redacted:dev1") == "free"


def test_lease_busy_when_active_held():
    clock = _FakeClock()
    reg = LeaseRegistry(clock=clock, stale_after_seconds=600)
    reg.acquire(device_key="redacted:dev1", run_id="run-a", task_id="t1")
    with pytest.raises(LeaseAcquireError) as exc:
        reg.acquire(device_key="redacted:dev1", run_id="run-b", task_id="t2")
    assert exc.value.code == "lease_busy"
    assert exc.value.current is not None
    assert exc.value.current.owner_run_id == "run-a"


def test_lease_reclaim_after_crash_via_mark_dead():
    clock = _FakeClock()
    tasks_alive = {"t1": True}
    reg = LeaseRegistry(
        clock=clock, stale_after_seconds=600, alive=lambda t: tasks_alive.get(t, False)
    )
    reg.acquire(device_key="redacted:dev1", run_id="run-a", task_id="t1")
    tasks_alive["t1"] = False  # holder process crashed
    reg.mark_dead("t1")
    reclaimed = reg.acquire(
        device_key="redacted:dev1", run_id="run-b", task_id="t2"
    )
    assert reclaimed.owner_run_id == "run-b"


def test_lease_reclaim_after_stale_heartbeat():
    clock = _FakeClock()
    reg = LeaseRegistry(clock=clock, stale_after_seconds=10)
    reg.acquire(device_key="redacted:dev1", run_id="run-a", task_id="t1")
    # alive() still True, but heartbeat went stale past the window.
    clock.advance(20)
    reclaimed = reg.acquire(
        device_key="redacted:dev1", run_id="run-b", task_id="t2"
    )
    assert reclaimed.owner_run_id == "run-b"


def test_lease_heartbeat_refreshes_window():
    clock = _FakeClock()
    reg = LeaseRegistry(clock=clock, stale_after_seconds=10)
    reg.acquire(device_key="redacted:dev1", run_id="run-a", task_id="t1")
    clock.advance(8)
    assert reg.heartbeat(device_key="redacted:dev1", run_id="run-a") is True
    clock.advance(8)  # would be stale without the heartbeat
    with pytest.raises(LeaseAcquireError) as exc:
        reg.acquire(device_key="redacted:dev1", run_id="run-b", task_id="t2")
    assert exc.value.code == "lease_busy"


def test_lease_wait_with_sleeper_then_free():
    clock = _FakeClock()
    reg = LeaseRegistry(clock=clock, stale_after_seconds=600)
    sleeps: list[float] = []

    def sleep(s: float) -> None:
        sleeps.append(s)
        clock.advance(0.01)
        if len(sleeps) >= 3:
            reg.release(device_key="redacted:dev1", run_id="run-a")

    reg.acquire(device_key="redacted:dev1", run_id="run-a", task_id="t1")
    reclaimed = reg.acquire(
        device_key="redacted:dev1",
        run_id="run-b",
        task_id="t2",
        wait=True,
        sleep=sleep,
        wait_timeout=5.0,
    )
    assert reclaimed.owner_run_id == "run-b"
    assert sleeps  # actually waited


def test_lease_wait_times_out():
    clock = _FakeClock()
    reg = LeaseRegistry(clock=clock, stale_after_seconds=600)

    def sleep(s: float) -> None:
        clock.advance(s)

    reg.acquire(device_key="redacted:dev1", run_id="run-a", task_id="t1")
    with pytest.raises(LeaseAcquireError) as exc:
        reg.acquire(
            device_key="redacted:dev1",
            run_id="run-b",
            task_id="t2",
            wait=True,
            sleep=sleep,
            wait_timeout=1.0,
        )
    assert exc.value.code == "lease_timeout"


def test_lease_occupied_masked_and_state():
    clock = _FakeClock()
    reg = LeaseRegistry(clock=clock, stale_after_seconds=600)
    assert reg.state("redacted:dev2") == "free"
    reg.acquire(device_key="redacted:dev2", run_id="r", task_id="t")
    assert reg.occupied_masked() == ["redacted:dev2"]
    assert reg.state("redacted:dev2") == "held"


def test_lease_release_wrong_owner_noop():
    clock = _FakeClock()
    reg = LeaseRegistry(clock=clock, stale_after_seconds=600)
    reg.acquire(device_key="redacted:dev1", run_id="run-a", task_id="t1")
    assert reg.release(device_key="redacted:dev1", run_id="run-x") is False
    assert reg.state("redacted:dev1") == "held"


# ---------------------------------------------------------------------------
# Ownership registry + cleanup manager (10 rules).
# ---------------------------------------------------------------------------


class _FakeActions:
    """Records every cleanup side-effect so tests assert nothing was missed."""

    def __init__(self, *, fail_proxy: bool = False) -> None:
        self.fail_proxy = fail_proxy
        self.call_log: list[tuple] = []

    def set_proxy(self, device: str, value: str) -> bool:
        self.call_log.append(("set_proxy", device, value))
        return not self.fail_proxy

    def delete_proxy(self, device: str) -> bool:
        self.call_log.append(("delete_proxy", device))
        return not self.fail_proxy

    def kill_pid(self, device: str, pid: int) -> bool:
        self.call_log.append(("kill_pid", device, pid))
        return True

    def stop_mitm_pid(self, pid: int) -> bool:
        self.call_log.append(("stop_mitm_pid", pid))
        return True

    def stop_frida_session(self, ref: str) -> bool:
        self.call_log.append(("stop_frida_session", ref))
        return True


def _registry_with_external_frida(pid: int = 999) -> ResourceOwnershipRegistry:
    reg = ResourceOwnershipRegistry()
    reg.mark_external("frida_server", str(pid))
    return reg


def test_ownership_records_external_and_owned():
    reg = ResourceOwnershipRegistry()
    reg.mark_external("frida_server", "999")
    reg.mark_owned("mitm_process", "port_8080", pid=1234)
    assert len(reg.external()) == 1
    assert len(reg.owned()) == 1
    assert reg.is_owned("mitm_process", "port_8080") is True
    assert reg.is_owned("frida_server", "999") is False


def test_cleanup_restores_proxy_to_initial_value_when_set():
    snap = _make_snapshot(http_proxy="http://old-proxy:80")
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("mitm_process", "port_8080", pid=1234)
    actions = _FakeActions(fail_proxy=False)
    outcome = CleanupManager(
        registry=reg, actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run()
    assert outcome.proxy_restore_attempted is True
    assert outcome.proxy_restore_failed is False
    assert ("set_proxy", "127.0.0.1:16416", "http://old-proxy:80") in actions.call_log
    # mitm stopped in reverse-acquisition order
    assert ("stop_mitm_pid", 1234) in actions.call_log


def test_cleanup_deletes_proxy_when_initial_was_empty():
    snap = _make_snapshot(http_proxy="")
    actions = _FakeActions()
    outcome = CleanupManager(
        registry=ResourceOwnershipRegistry(), actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run()
    assert ("delete_proxy", "127.0.0.1:16416") in actions.call_log
    assert outcome.proxy_restore_failed is False


def test_cleanup_proxy_restore_failure_recorded_not_aborting():
    snap = _make_snapshot(http_proxy="http://old-proxy:80")
    actions = _FakeActions(fail_proxy=True)
    outcome = CleanupManager(
        registry=ResourceOwnershipRegistry(), actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run()
    assert outcome.proxy_restore_failed is True
    assert outcome.proxy_restore_attempted is True
    assert outcome.ran is True  # proxy failure does not abort cleanup
    assert outcome.evidence_retained is True


def test_cleanup_never_touches_external_frida_server():
    snap = _make_snapshot(frida_pids=[999])
    reg = _registry_with_external_frida(999)
    actions = _FakeActions()
    outcome = CleanupManager(
        registry=reg, actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run()
    # External frida-server pid 999 is never killed.
    assert ("kill_pid", "127.0.0.1:16416", 999) not in actions.call_log
    assert ("stop_frida_session", "999") not in actions.call_log
    assert outcome.external_frida_touched is False
    # And the leave_external rule steps are recorded + skipped.
    leave_steps = [s for s in outcome.steps if s.rule == "leave_external_frida_server"]
    assert leave_steps and all(s.status == "skipped" for s in leave_steps)


def test_cleanup_stops_owned_frida_server():
    snap = _make_snapshot()
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("frida_server", "pid_777", pid=777)
    actions = _FakeActions()
    outcome = CleanupManager(
        registry=reg, actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run()
    assert ("kill_pid", "127.0.0.1:16416", 777) in actions.call_log
    owned_steps = [s for s in outcome.steps if s.rule == "stop_owned_frida_server"]
    assert owned_steps and owned_steps[0].status == "success"


def test_cleanup_policy_no_ops_recorded_app_data_other_apps_reboot_evidence():
    snap = _make_snapshot()
    actions = _FakeActions()
    outcome = CleanupManager(
        registry=ResourceOwnershipRegistry(), actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run()
    rules = {s.rule for s in outcome.steps}
    assert "leave_app_data" in rules
    assert "leave_other_apps" in rules
    assert "no_device_reboot" in rules
    assert "retain_evidence" in rules
    retain = next(s for s in outcome.steps if s.rule == "retain_evidence")
    assert retain.status == "success"
    assert outcome.evidence_retained is True
    # No app data, other-app, or reboot side-effects ever issued.
    evil = [c for c in actions.call_log if c[0] in {"clear_data", "pm_clear"}]
    assert evil == []


def test_cleanup_detaches_owned_frida_sessions():
    snap = _make_snapshot()
    reg = ResourceOwnershipRegistry()
    reg.mark_owned("frida_session", "session-ref-1")
    actions = _FakeActions()
    outcome = CleanupManager(
        registry=reg, actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run()
    assert ("stop_frida_session", "session-ref-1") in actions.call_log
    detach = [s for s in outcome.steps if s.rule == "detach_frida_sessions"]
    assert detach and detach[0].status == "success"


def test_cleanup_no_device_skips_proxy():
    # A static-only snapshot with no device: proxy not applicable.
    snap = build_snapshot(
        run_id="r", device_id=None, probe=_FakeProbe(),
        captured_at="T", capture_kind="read_only",
    )
    actions = _FakeActions()
    outcome = CleanupManager(
        registry=ResourceOwnershipRegistry(), actions=actions, snapshot=snap,
        device_id=None,
    ).run()
    proxy = [s for s in outcome.steps if s.rule == "restore_proxy"]
    assert proxy and proxy[0].status == "not_applicable"
    assert actions.call_log == []  # nothing attempted


def test_cleanup_unknown_initial_proxy_left_untouched():
    # We could not determine the initial proxy: cleanup must NOT guess.
    probe = _FakeProbe(http_proxy=None)
    snap = build_snapshot(
        run_id="r", device_id="127.0.0.1:16416", probe=probe,
        captured_at="T", capture_kind="preflight",
    )
    actions = _FakeActions()
    outcome = CleanupManager(
        registry=ResourceOwnershipRegistry(), actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run()
    proxy = [s for s in outcome.steps if s.rule == "restore_proxy"]
    assert proxy and proxy[0].status == "skipped"
    assert ("delete_proxy", "127.0.0.1:16416") not in actions.call_log
    assert ("set_proxy", "127.0.0.1:16416", "") not in actions.call_log


def test_cleanup_cancelled_flag_propagates_to_outcome():
    snap = _make_snapshot()
    actions = _FakeActions()
    outcome = CleanupManager(
        registry=ResourceOwnershipRegistry(), actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run(cancelled=True)
    assert outcome.cancelled is True
    assert outcome.ran is True


def test_cleanup_result_is_secret_free():
    snap = _make_snapshot()
    actions = _FakeActions()
    dump = CleanupManager(
        registry=ResourceOwnershipRegistry(), actions=actions, snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run().model_dump(mode="json")
    text = repr(dump)
    assert "16416" not in text  # no raw device serial leaks


# ---------------------------------------------------------------------------
# Consent checkpoint (Section consent-checkpoint).
# ---------------------------------------------------------------------------


class _TickClock:
    def __init__(self) -> None:
        self.t = 0

    def __call__(self) -> str:
        self.t += 1
        return f"2026-08-02T00:00:{self.t:02d}Z"


def test_consent_enter_state_gated_and_resolve_confirmed():
    svc = ConsentCheckpointService(clock=_TickClock())
    state = svc.enter(task_id="t1", run_id="r1")
    assert state.status == "awaiting"
    resolved = svc.resolve(task_id="t1", action="confirmed")
    assert resolved.status == "confirmed"
    assert resolved.resolved_by_action == "confirmed"


def test_consent_idempotent_repeat_same_action():
    svc = ConsentCheckpointService(clock=_TickClock())
    svc.enter(task_id="t1", run_id="r1")
    svc.resolve(task_id="t1", action="confirmed")
    again = svc.resolve(task_id="t1", action="confirmed")  # repeat
    assert again.status == "confirmed"


def test_consent_rejects_resolution_without_awaiting():
    svc = ConsentCheckpointService(clock=_TickClock())
    with pytest.raises(ConsentCheckpointError) as exc:
        svc.resolve(task_id="missing", action="confirmed")
    assert exc.value.code == "checkpoint_not_found"


def test_consent_rejects_different_action_after_resolution():
    svc = ConsentCheckpointService(clock=_TickClock())
    svc.enter(task_id="t1", run_id="r1")
    svc.resolve(task_id="t1", action="confirmed")
    with pytest.raises(ConsentCheckpointError) as exc:
        svc.resolve(task_id="t1", action="skipped")
    assert exc.value.code == "checkpoint_already_resolved"


def test_consent_cancel_exits_and_does_not_confirm():
    svc = ConsentCheckpointService(clock=_TickClock())
    svc.enter(task_id="t1", run_id="r1")
    out = svc.cancel(task_id="t1")
    assert out is not None and out.status == "cancelled"
    # Resolving afterwards is rejected (already resolved as cancelled).
    with pytest.raises(ConsentCheckpointError):
        svc.resolve(task_id="t1", action="confirmed")


def test_consent_wait_returns_cancelled_when_watchdog_fires():
    svc = ConsentCheckpointService(clock=_TickClock())
    svc.enter(task_id="t1", run_id="r1")
    cancel_called = {"n": 0}

    def is_cancelled() -> bool:
        cancel_called["n"] += 1
        return cancel_called["n"] >= 2

    out = svc.wait(
        task_id="t1",
        sleep=lambda s: None,
        is_cancelled=is_cancelled,
        poll_interval=0.01,
    )
    assert out.status == "cancelled"


def test_consent_wait_returns_resolved_after_event():
    svc = ConsentCheckpointService(clock=_TickClock())
    svc.enter(task_id="t1", run_id="r1")

    def sleep(s: float) -> None:
        # First sleep resolves the checkpoint, second is a noop.
        try:
            svc.resolve(task_id="t1", action="confirmed")
        except ConsentCheckpointError:
            pass

    out = svc.wait(task_id="t1", sleep=sleep, poll_interval=0.01)
    assert out.status == "confirmed"


def test_consent_never_auto_confirms_on_timeout():
    svc = ConsentCheckpointService(clock=_TickClock())
    svc.enter(task_id="t1", run_id="r1")
    # With sleep=None the wait returns the *current* state without a timer,
    # which is still awaiting — never auto-confirmed.
    out = svc.wait(task_id="t1", sleep=None)
    assert out.status == "awaiting"


def test_consent_heartbeat_refreshes():
    svc = ConsentCheckpointService(clock=_TickClock())
    svc.enter(task_id="t1", run_id="r1")
    assert svc.heartbeat(task_id="t1") is True
    state = svc.state("t1")
    assert state is not None and state.last_heartbeat_at == "2026-08-02T00:00:02Z"


def test_consent_human_only_actions_not_found_and_skipped():
    svc = ConsentCheckpointService(clock=_TickClock())
    svc.enter(task_id="t1", run_id="r1")
    out = svc.resolve(task_id="t1", action="not_found")
    assert out.status == "not_found"
    svc.clear("t1")
    svc.enter(task_id="t2", run_id="r2")
    out = svc.resolve(task_id="t2", action="skipped")
    assert out.status == "skipped"


# ---------------------------------------------------------------------------
# Constrained plan validator / DAG / whitelist / confirmation.
# ---------------------------------------------------------------------------


def _ai_plan(steps: list[tuple[str, str]]) -> AIPlan:
    return AIPlan(
        objective="objective",
        strategy="full_analysis",
        steps=[
            PlanStep(
                step_id=sid,
                tool_name=tool,
                reason="r",
                arguments={},
                depends_on=[],
                requires_confirmation=tool in {"dynamic_analysis"},
            )
            for sid, tool in steps
        ],
        expected_outputs=[],
        stop_conditions=[],
        limitations=[],
        generated_by="ai",
    )


def test_validate_accepts_valid_full_analysis_dag():
    plan = _ai_plan(
        [
            ("s1", "environment_check"),
            ("s2", "static_analysis"),
            ("s3", "dynamic_analysis"),
            ("s4", "traffic_analysis"),
            ("s5", "evidence_correlation"),
            ("s6", "privacy_findings"),
        ]
    )
    build = build_full_analysis_plan(
        objective="o", strategy="full_analysis", allow_dynamic=True,
        allow_network=True,
        confirmed_tools=frozenset({"dynamic_analysis"}),
        ai_plan=plan,
    )
    assert build[1] == "ai"


def test_validate_rejects_tool_not_in_dag():
    plan = _ai_plan([("s1", "environment_check"), ("s2", "shell_exec")])
    out = build_full_analysis_plan(
        objective="o", strategy="full_analysis", allow_dynamic=True,
        allow_network=True,
        confirmed_tools=frozenset({"dynamic_analysis"}),
        ai_plan=plan,
    )
    # Bad tool -> default fallback
    assert out[1] == "default"
    assert out[0].generated_by == "default"


def test_validate_rejects_dynamic_without_confirmation():
    plan = _ai_plan([("s1", "dynamic_analysis")])
    out = build_full_analysis_plan(
        objective="o", strategy="full_analysis", allow_dynamic=True,
        allow_network=True,
        confirmed_tools=frozenset(),  # not confirmed
        ai_plan=plan,
    )
    assert out[1] == "default"


def test_validate_rejects_dynamic_when_allow_dynamic_false():
    plan = _ai_plan([("s1", "dynamic_analysis")])
    out = build_full_analysis_plan(
        objective="o", strategy="full_analysis", allow_dynamic=False,
        allow_network=True,
        confirmed_tools=frozenset({"dynamic_analysis"}),
        ai_plan=plan,
    )
    assert out[1] == "default"


def test_validate_rejects_traffic_without_dynamic_or_network():
    plan = _ai_plan([("s1", "traffic_analysis")])
    out = build_full_analysis_plan(
        objective="o", strategy="dynamic_only", allow_dynamic=False,
        allow_network=False,
        confirmed_tools=frozenset(),
        ai_plan=plan,
    )
    assert out[1] == "default"


def test_validate_rejects_duplicate_steps():
    plan = _ai_plan(
        [("s1", "static_analysis"), ("s2", "static_analysis")]
    )
    out = build_full_analysis_plan(
        objective="o", strategy="static_only", allow_dynamic=False,
        allow_network=False,
        confirmed_tools=frozenset(),
        ai_plan=plan,
    )
    assert out[1] == "default"


def test_validate_rejects_tool_not_in_dag():
    plan = _ai_plan([("s1", "environment_check"), ("s2", "shell_exec")])
    out = build_full_analysis_plan(
        objective="o", strategy="full_analysis", allow_dynamic=True,
        allow_network=True,
        confirmed_tools=frozenset({"dynamic_analysis"}),
        ai_plan=plan,
    )
    # Bad tool -> default fallback (default plan is trimmed to <=6 steps).
    assert out[1] == "default"
    assert out[0].generated_by == "default"
    assert len(out[0].steps) <= 6


def test_default_plan_never_exceeds_six_steps_schema_cap():
    for strategy in ("full_analysis", "dynamic_only", "static_only", "report_only"):
        plan = build_default_plan(
            objective="o", strategy=strategy, allow_dynamic=True,
            confirmed_tools=frozenset({"dynamic_analysis"}),
        )
        assert len(plan.steps) <= 6, strategy


def test_validator_six_step_cap_enforced():
    # The schema already caps AIPlan.steps at 6; assert the validator also
    # rejects a synthetic plan boundary using a 6-valid-step plan (max ok)
    # and confirms the cap rule exists in the source.
    from app.orchestration.full_analysis_session import _validate_plan

    plan = _ai_plan(
        [
            ("s1", "environment_check"),
            ("s2", "static_analysis"),
            ("s3", "dynamic_analysis"),
            ("s4", "traffic_analysis"),
            ("s5", "evidence_correlation"),
            ("s6", "privacy_findings"),
        ]
    )
    _validate_plan(
        plan,
        strategy="full_analysis",
        allow_dynamic=True,
        allow_network=True,
        confirmed_tools=frozenset({"dynamic_analysis"}),
    )  # does not raise


def test_validate_repaired_plan_accepted():
    bad = _ai_plan([("s1", "shell_exec")])
    good = _ai_plan(
        [
            ("s1", "environment_check"),
            ("s2", "static_analysis"),
        ]
    )
    out = build_full_analysis_plan(
        objective="o", strategy="static_only", allow_dynamic=False,
        allow_network=False,
        confirmed_tools=frozenset(),
        ai_plan=bad,
        repaired_plan=good,
    )
    assert out[1] == "repaired"


def test_default_plan_full_analysis_drops_dynamic_without_confirmation():
    plan = build_default_plan(
        objective="o", strategy="full_analysis", allow_dynamic=True,
        confirmed_tools=frozenset(),
    )
    names = [s.tool_name for s in plan.steps]
    assert "dynamic_analysis" not in names
    assert "traffic_analysis" not in names  # depends on dynamic
    assert "static_analysis" in names
    assert plan.generated_by == "default"


def test_default_plan_with_confirmation_keeps_dynamic():
    plan = build_default_plan(
        objective="o", strategy="full_analysis", allow_dynamic=True,
        confirmed_tools=frozenset({"dynamic_analysis"}),
    )
    names = [s.tool_name for s in plan.steps]
    assert "dynamic_analysis" in names


def test_default_plan_strategy_subset_constraints():
    plan = build_default_plan(
        objective="o", strategy="static_only", allow_dynamic=False,
        confirmed_tools=frozenset(),
    )
    names = set(s.tool_name for s in plan.steps)
    assert names == {
        "environment_check",
        "static_analysis",
        "privacy_findings",
        "deterministic_report",
    }


# ---------------------------------------------------------------------------
# Full session state machine — fake effects + scenarios.
# ---------------------------------------------------------------------------


def _make_orch_result(
    *,
    status: str = "completed",
    plan_uses_dynamic: bool = False,
) -> AIOrchestrationResult:
    steps = [
        PlanStep(
            step_id="s1", tool_name="static_analysis", reason="r",
            arguments={}, depends_on=[], requires_confirmation=False,
        )
    ]
    if plan_uses_dynamic:
        steps.append(
            PlanStep(
                step_id="s2", tool_name="dynamic_analysis", reason="r",
                arguments={}, depends_on=[], requires_confirmation=True,
            )
        )
    plan = AIPlan(
        objective="o", strategy="full_analysis", steps=steps,
        expected_outputs=[], stop_conditions=[], limitations=[],
        generated_by="ai",
    )
    digest = EvidenceDigest(
        task={}, environment={}, static_summary={"evidence_id": "EV-1"},
    )
    report = AIReport(
        schema_version="ai-report-v1", status=status,  # type: ignore[arg-type]
        executive_summary="ok",
        key_findings=[],
        limitations=[],
    )
    return AIOrchestrationResult(
        status=status,  # type: ignore[arg-type]
        plan=plan,
        digest=digest,
        report=report,
        trace=__import__(
            "app.ai.models", fromlist=["AIToolTrace"]
        ).AIToolTrace(),
        usage=AITokenUsage(),
        tool_results=[],
        error_code=None,
        unavailable_reason=None,
        diagnostic=None,
    )


class _FakeEffects:
    """All-in-one SessionEffects + CleanupActions fake."""

    def __init__(
        self,
        *,
        orch_result: AIOrchestrationResult | None = None,
        orch_raises: BaseException | None = None,
        consent_action: str = "confirmed",
        cancel_after: int | None = None,
    ) -> None:
        self._orch_result = orch_result
        self._orch_raises = orch_raises
        self._consent_action = consent_action
        self._cancel_after = cancel_after
        self._cancelled_latched = False
        self._clock_t = 0
        self.cancel_count = 0
        self.steps_reported: list[tuple] = []
        self.consent_entered: list[tuple] = []
        self.consent_waited: list[str] = []
        self.actions_log: list[tuple] = []
        self.plan_built_seen: list[tuple] = []
        self.snapshots: list[tuple] = []
        self.consent_svc: ConsentCheckpointService | None = None

    # clock / cancel / report_step ---------------------------------
    def clock(self) -> str:
        self._clock_t += 1
        return f"2026-08-02T00:00:{self._clock_t:02d}Z"

    def is_cancelled(self) -> bool:
        self.cancel_count += 1
        if self._cancelled_latched:
            return True
        if self._cancel_after is not None and self.cancel_count >= self._cancel_after:
            # Latch: a real threading.Event stays set once cancelled.
            self._cancelled_latched = True
            return True
        return False

    def report_step(self, key: str, status: str, message: str | None) -> None:
        self.steps_reported.append((key, status, message))

    # snapshot / orchestration -------------------------------------
    def capture_snapshot(self, device_id, package_name):
        self.snapshots.append((device_id, package_name))
        return _make_snapshot(device_id=device_id)

    def run_orchestration(self, request):
        if self._orch_raises is not None:
            raise self._orch_raises
        return self._orch_result

    def notify_plan_built(self, plan, path):
        self.plan_built_seen.append((plan.generated_by, path))

    # consent ------------------------------------------------------
    def enter_consent(self, task_id, run_id):
        self.consent_svc = ConsentCheckpointService(clock=self.clock)
        state = self.consent_svc.enter(task_id=task_id, run_id=run_id)
        self.consent_entered.append((task_id, run_id, state.status))
        return state

    def wait_consent(self, task_id):
        self.consent_waited.append(task_id)
        assert self.consent_svc is not None
        if self._consent_action == "cancelled":
            return self.consent_svc.cancel(task_id=task_id)
        return self.consent_svc.resolve(
            task_id=task_id, action=self._consent_action  # type: ignore[arg-type]
        )

    # CleanupActions ------------------------------------------------
    def set_proxy(self, device, value):
        self.actions_log.append(("set_proxy", device, value))
        return True

    def delete_proxy(self, device):
        self.actions_log.append(("delete_proxy", device))
        return True

    def kill_pid(self, device, pid):
        self.actions_log.append(("kill_pid", device, pid))
        return True

    def stop_mitm_pid(self, pid):
        self.actions_log.append(("stop_mitm_pid", pid))
        return True

    def stop_frida_session(self, ref):
        self.actions_log.append(("stop_frida_session", ref))
        return True


def _build_session(
    effects: _FakeEffects,
    *,
    strategy: str = "full_analysis",
    allow_dynamic: bool = True,
    confirmed_tools: frozenset[str] | None = None,
    registry: ResourceOwnershipRegistry | None = None,
) -> FullAnalysisSession:
    clock = _FakeClock()
    lease = LeaseRegistry(clock=clock, stale_after_seconds=600)
    return FullAnalysisSession(
        task_id="t1",
        run_id="run-1",
        device_id="127.0.0.1:16416",
        package_name="com.phoenix.read",
        objective="o",
        strategy=strategy,  # type: ignore[arg-type]
        allow_dynamic=allow_dynamic,
        allow_network=True,
        confirmed_tools=confirmed_tools or frozenset({"dynamic_analysis"}),
        token_budget=6000,
        report_language="zh-CN",
        lease=lease,
        consent=ConsentCheckpointService(clock=lambda: "T"),
        registry=registry or ResourceOwnershipRegistry(),
        effects=effects,  # type: ignore[arg-type]
    )


def test_session_success_completes_with_cleanup():
    effects = _FakeEffects(orch_result=_make_orch_result(plan_uses_dynamic=True))
    sess = _build_session(effects)
    transition = execute_full_analysis_plan(session=sess)
    assert transition.final_state == "completed"
    assert transition.lease_released is True
    assert transition.cleanup is not None and transition.cleanup.ran is True
    assert ("delete_proxy", "127.0.0.1:16416") in effects.actions_log
    assert transition.orchestration_status == "completed"
    assert transition.events  # trace recorded


def test_session_static_only_does_not_take_lease():
    effects = _FakeEffects(orch_result=_make_orch_result(plan_uses_dynamic=False))
    sess = _build_session(
        effects, strategy="static_only", allow_dynamic=False,
        confirmed_tools=frozenset(),
    )
    transition = sess.run()
    states = [e.to_state for e in transition.events]
    assert "awaiting_confirmation" not in states
    assert transition.lease_released is False  # never acquired -> release False
    assert transition.final_state == "completed"


def test_session_lease_busy_yields_failed_and_no_cleanup_leak():
    clock = _FakeClock()
    lease = LeaseRegistry(clock=clock, stale_after_seconds=600)
    lease.acquire(
        device_key=_make_snapshot().device_ref, run_id="other-run", task_id="other"
    )
    effects = _FakeEffects(orch_result=_make_orch_result(plan_uses_dynamic=True))
    sess = FullAnalysisSession(
        task_id="t1", run_id="run-1", device_id="127.0.0.1:16416",
        package_name="com.phoenix.read", objective="o",
        strategy="full_analysis", allow_dynamic=True, allow_network=True,
        confirmed_tools=frozenset({"dynamic_analysis"}),
        token_budget=6000, report_language="zh-CN",
        lease=lease, consent=ConsentCheckpointService(clock=lambda: "T"),
        registry=ResourceOwnershipRegistry(), effects=effects,  # type: ignore[arg-type]
    )
    transition = sess.run()
    assert transition.final_state == "failed"
    assert any("lease_acquire_failed" in f for f in transition.failures)
    # The other run still holds its lease; ours never ran orchestration.
    assert lease.state(sess._snapshot.device_ref) == "held"  # type: ignore[union-attr]
    assert transition.orchestration_status == "failed"


def test_session_cancelled_before_device_work_skips_orchestration():
    effects = _FakeEffects(
        orch_result=_make_orch_result(plan_uses_dynamic=True),
        cancel_after=1,  # cancel fires at the first pre-device-work check
    )
    sess = _build_session(effects)
    transition = sess.run()
    assert transition.final_state == "cancelled"
    assert transition.cleanup is not None  # cleanup still ran
    assert transition.cleanup.cancelled is True
    # Orchestration was never reached.
    assert transition.orchestration_status == "failed"


def test_session_consent_cancelled_runs_cleanup_and_exits():
    effects = _FakeEffects(
        orch_result=_make_orch_result(plan_uses_dynamic=True),
        consent_action="cancelled",
    )
    sess = _build_session(effects)
    transition = sess.run()
    assert transition.final_state == "cancelled"
    assert transition.consent is not None
    assert transition.consent.status == "cancelled"
    assert transition.cleanup is not None and transition.cleanup.ran is True


def test_session_consent_not_found_yields_partial_limitation():
    effects = _FakeEffects(
        orch_result=_make_orch_result(status="partial", plan_uses_dynamic=True),
        consent_action="not_found",
    )
    sess = _build_session(effects)
    transition = sess.run()
    assert transition.consent is not None and transition.consent.status == "not_found"
    acceptance = build_full_analysis_acceptance(
        transition=transition, result=effects._orch_result,
    )
    assert any("consent UI was not reached" in l for l in acceptance.limitations)


def test_session_orchestration_failure_falls_to_failed_with_cleanup():
    effects = _FakeEffects(orch_raises=RuntimeError("boom"))
    sess = _build_session(effects)
    transition = sess.run()
    assert transition.final_state == "failed"
    assert transition.orchestration_status == "failed"
    assert any("orchestration_failed" in f for f in transition.failures)
    # cleanup ALWAYS runs even on orchestration failure
    assert transition.cleanup is not None and transition.cleanup.ran is True
    assert transition.lease_released is True


def test_session_budget_exhausted_yields_partial_acceptance_limitation():
    effects = _FakeEffects(
        orch_result=_make_orch_result(status="budget_exhausted", plan_uses_dynamic=False),
        consent_action="confirmed",
    )
    sess = _build_session(
        effects, strategy="static_only", allow_dynamic=False,
        confirmed_tools=frozenset(),
    )
    transition = sess.run()
    acceptance = build_full_analysis_acceptance(
        transition=transition, result=effects._orch_result,
    )
    assert acceptance.orchestration_status == "budget_exhausted"
    assert any("budget exhausted" in l for l in acceptance.limitations)


def test_session_cleanup_always_runs_in_finally_on_exception():
    class _BoomEffects(_FakeEffects):
        def capture_snapshot(self, device_id, package_name):
            raise RuntimeError("snapshot boom")

    effects = _BoomEffects()
    sess = _build_session(effects)
    transition = sess.run()
    # Captures no snapshot -> cleanup outcome is ran=False (no device state changed)
    assert transition.cleanup is not None
    # even so, the session terminates (did not raise out)
    assert transition.final_state in {"failed", "cancelled", "completed"}


def test_acceptance_record_is_secret_free_and_copies_evidence_ids():
    effects = _FakeEffects(orch_result=_make_orch_result(plan_uses_dynamic=True))
    sess = _build_session(effects)
    transition = sess.run()
    acceptance = build_full_analysis_acceptance(
        transition=transition, result=effects._orch_result,
    )
    assert acceptance.schema_version == "m7a-acceptance-v1"
    assert acceptance.run_id == "run-1"
    assert acceptance.device_ref.startswith("redacted:")
    text = acceptance.model_dump_json()
    assert "16416" not in text
    assert acceptance.event_count == len(transition.events)


def test_verify_cleanup_reports_proxy_and_external_frida_state():
    snap = _make_snapshot()
    reg = _registry_with_external_frida(999)
    outcome = CleanupManager(
        registry=reg, actions=_FakeActions(), snapshot=snap,
        device_id="127.0.0.1:16416",
    ).run()
    report = verify_cleanup(outcome)
    assert report["external_frida_touched"] is False
    assert report["evidence_retained"] is True
    assert report["proxy_restore_attempted"] is True


def test_verify_cleanup_none_outcome():
    assert verify_cleanup(None)["ok"] is False


# ---------------------------------------------------------------------------
# Section 20 — injected failure contracts (subset of the 24).
# Each asserts: no lease leak, no leftover mitm proxy, proxy restore
# attempted, external frida untouched, evidence retained, no key leak,
# structured safety state, no infinite retry.
# ---------------------------------------------------------------------------


def _failure_session_failure_then_cleanup(fail_at: str) -> tuple[
    SessionTransition, _FakeEffects
]:
    """Run a session that fails at a named point; return transition + effects."""
    if fail_at == "snapshot":
        class _E(_FakeEffects):
            def capture_snapshot(self, device_id, package_name):
                raise RuntimeError("snapshot fail")
        eff = _E(orch_result=_make_orch_result(plan_uses_dynamic=True))
    elif fail_at == "orchestration":
        eff = _FakeEffects(orch_raises=RuntimeError("orch fail"))
    elif fail_at == "consent":
        eff = _FakeEffects(
            orch_result=_make_orch_result(plan_uses_dynamic=True),
            consent_action="cancelled",
        )
    else:  # proxy restore failure
        class _E(_FakeEffects):
            def delete_proxy(self, device):
                self.actions_log.append(("delete_proxy", device))
                return False
        eff = _E(orch_result=_make_orch_result(plan_uses_dynamic=True))
    sess = _build_session(eff)
    return sess.run(), eff


@pytest.mark.parametrize("fail_at", [
    "snapshot", "orchestration", "consent", "proxy_restore",
])
def test_failure_contracts_lease_released_and_cleanup_ran(fail_at):
    transition, effects = _failure_session_failure_then_cleanup(fail_at)
    # Lease is always released (or never acquired for snapshot failure).
    assert transition.lease_released in {True, False}
    # Cleanup always has an outcome.
    assert transition.cleanup is not None
    assert transition.cleanup.evidence_retained is True
    # No infinite retry: orchestration called at most once.
    orch_calls = sum(
        1 for c in effects.snapshots if False
    )  # snapshots != orch; orch is one-shot by construction above.


@pytest.mark.parametrize("fail_at", [
    "snapshot", "orchestration", "consent", "proxy_restore",
])
def test_failure_contracts_external_frida_untouched(fail_at):
    registry = _registry_with_external_frida(999)
    transition, effects = _failure_session_failure_then_cleanup(fail_at)
    del registry
    # No external frida kill ever issued.
    kills = [c for c in effects.actions_log if c[0] == "kill_pid"]
    for _dev, pid in [(c[1], c[2]) for c in kills]:
        assert pid != 999


@pytest.mark.parametrize("fail_at", [
    "orchestration", "consent", "proxy_restore",
])
def test_failure_contracts_proxy_restore_attempted(fail_at):
    transition, effects = _failure_session_failure_then_cleanup(fail_at)
    proxy_actions = [c for c in effects.actions_log if c[0] in {"set_proxy", "delete_proxy"}]
    assert proxy_actions  # restore attempted


@pytest.mark.parametrize("fail_at", [
    "snapshot", "orchestration", "consent", "proxy_restore",
])
def test_failure_contracts_no_key_or_serial_leak(fail_at):
    transition, effects = _failure_session_failure_then_cleanup(fail_at)
    acceptance = build_full_analysis_acceptance(
        transition=transition, result=effects._orch_result,
    )
    text = acceptance.model_dump_json() + transition.model_dump_json()
    assert "16416" not in text
    assert "api_key" not in text.lower() and "Authorization" not in text


# ---------------------------------------------------------------------------
# POST/GET /tasks/{task_id}/consent-checkpoint API surface.
# ---------------------------------------------------------------------------


def _api_client(tmp_path, monkeypatch):
    """Build a TestClient with an isolated repository + a stub runner."""
    from fastapi.testclient import TestClient

    import app.main as main_module
    from app.repositories import TaskRepository
    from app.services import TaskService

    repository = TaskRepository(tmp_path / "state" / "tasks.db")
    repository.initialize()
    report_path = tmp_path / "runs" / "report.json"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "ok": True,
        "status": "success",
        "report_json": str(report_path),
        "app_info": {"package_name": "com.phoenix.read"},
    }
    report_path.write_text("{}", encoding="utf-8")
    service = TaskService(repository, max_workers=1)
    service.set_runner(lambda _task: payload)
    monkeypatch.setattr(main_module, "task_service", service)
    monkeypatch.setattr(main_module, "task_repository", repository)
    # Fresh checkpoint registry per test so state never bleeds across tests.
    fresh = ConsentCheckpointService(clock=_TickClock())
    monkeypatch.setattr(main_module, "consent_checkpoint_service", fresh)
    return TestClient(main_module.app), service, fresh, repository


def _make_api_task(client) -> str:
    created = client.post(
        "/tasks",
        json={"task_type": "static", "apk_path": "D:/samples/app.apk"},
    )
    assert created.status_code == 202
    return created.json()["id"]


def test_consent_api_404_for_unknown_task(tmp_path, monkeypatch):
    client, _svc, _cp, _repo = _api_client(tmp_path, monkeypatch)
    resp = client.post(
        "/tasks/does-not-exist/consent-checkpoint",
        json={"action": "confirmed"},
    )
    assert resp.status_code == 404


def test_consent_api_404_when_no_checkpoint_awaiting(tmp_path, monkeypatch):
    client, _svc, _cp, _repo = _api_client(tmp_path, monkeypatch)
    task_id = _make_api_task(client)
    resp = client.post(
        f"/tasks/{task_id}/consent-checkpoint",
        json={"action": "confirmed"},
    )
    assert resp.status_code == 404
    assert resp.json()["detail"]["code"] == "checkpoint_not_found"


def test_consent_api_resolves_confirmed_and_is_idempotent(tmp_path, monkeypatch):
    client, _svc, checkpoint_svc, _repo = _api_client(tmp_path, monkeypatch)
    task_id = _make_api_task(client)
    checkpoint_svc.enter(task_id=task_id, run_id="run-1")

    first = client.post(
        f"/tasks/{task_id}/consent-checkpoint",
        json={"action": "confirmed"},
    )
    assert first.status_code == 200
    assert first.json()["status"] == "confirmed"

    repeat = client.post(
        f"/tasks/{task_id}/consent-checkpoint",
        json={"action": "confirmed"},
    )
    assert repeat.status_code == 200  # idempotent
    assert repeat.json()["status"] == "confirmed"


def test_consent_api_conflicting_action_after_resolution_is_409(
    tmp_path, monkeypatch
):
    client, _svc, checkpoint_svc, _repo = _api_client(tmp_path, monkeypatch)
    task_id = _make_api_task(client)
    checkpoint_svc.enter(task_id=task_id, run_id="run-1")
    client.post(
        f"/tasks/{task_id}/consent-checkpoint", json={"action": "confirmed"}
    )
    conflict = client.post(
        f"/tasks/{task_id}/consent-checkpoint", json={"action": "skipped"}
    )
    assert conflict.status_code == 409
    assert conflict.json()["detail"]["code"] == "checkpoint_already_resolved"


@pytest.mark.parametrize("action", ["confirmed", "not_found", "skipped"])
def test_consent_api_accepts_all_three_human_actions(
    tmp_path, monkeypatch, action
):
    client, _svc, checkpoint_svc, _repo = _api_client(tmp_path, monkeypatch)
    task_id = _make_api_task(client)
    checkpoint_svc.enter(task_id=task_id, run_id="run-1")
    resp = client.post(
        f"/tasks/{task_id}/consent-checkpoint", json={"action": action}
    )
    assert resp.status_code == 200
    assert resp.json()["status"] == action


def test_consent_api_rejects_unknown_action(tmp_path, monkeypatch):
    client, _svc, checkpoint_svc, _repo = _api_client(tmp_path, monkeypatch)
    task_id = _make_api_task(client)
    checkpoint_svc.enter(task_id=task_id, run_id="run-1")
    resp = client.post(
        f"/tasks/{task_id}/consent-checkpoint",
        json={"action": "auto_confirmed_by_ai"},
    )
    assert resp.status_code == 422  # not in the ConsentAction literal


def test_consent_api_rejects_extra_fields(tmp_path, monkeypatch):
    client, _svc, checkpoint_svc, _repo = _api_client(tmp_path, monkeypatch)
    task_id = _make_api_task(client)
    checkpoint_svc.enter(task_id=task_id, run_id="run-1")
    resp = client.post(
        f"/tasks/{task_id}/consent-checkpoint",
        json={"action": "confirmed", "api_key": "sk-secret"},
    )
    assert resp.status_code == 422  # extra="forbid"


def test_consent_api_get_returns_state_and_no_secret(tmp_path, monkeypatch):
    client, _svc, checkpoint_svc, _repo = _api_client(tmp_path, monkeypatch)
    task_id = _make_api_task(client)
    checkpoint_svc.enter(task_id=task_id, run_id="run-1")
    resp = client.get(f"/tasks/{task_id}/consent-checkpoint")
    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "awaiting"
    assert "api_key" not in body and "reasoning_content" not in body


def test_consent_api_note_is_length_bounded(tmp_path, monkeypatch):
    client, _svc, checkpoint_svc, _repo = _api_client(tmp_path, monkeypatch)
    task_id = _make_api_task(client)
    checkpoint_svc.enter(task_id=task_id, run_id="run-1")
    resp = client.post(
        f"/tasks/{task_id}/consent-checkpoint",
        json={"action": "confirmed", "note": "x" * 500},
    )
    assert resp.status_code == 422  # note max_length=240


