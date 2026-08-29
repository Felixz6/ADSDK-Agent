"""M7B Phase C — traffic visibility hardening tests.

Goal: the system must deterministically distinguish why a collection saw
zero requests (proxy not configured / unreachable / collector down / target
socket activity invisible to the HTTP proxy / empty window). Facts only —
never raw socket tables, never transport attributions (UDP:443 is not QUIC),
never causal claims.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from app.analyzers.evidence_correlation import build_evidence_correlations
from app.core.device import DeviceContext
from app.frida.traffic_diagnostics import (
    diagnose_traffic,
    summarize_proc_net,
)
from app.tools.mitm_session import MitmSession, MitmSessionState, PortPool


# ---------------------------------------------------------------------------
# Fakes.
# ---------------------------------------------------------------------------
class FakeProcess:
    pid = 4242

    def poll(self) -> int | None:
        return None

    def terminate(self) -> None:
        pass

    def kill(self) -> None:
        pass

    def wait(self, timeout: float | None = None) -> int:
        return 0


class FakeProcessFactory:
    def __init__(self) -> None:
        self.process = FakeProcess()

    def __call__(self, *args: Any, **kwargs: Any) -> FakeProcess:
        return self.process


class FakeClock:
    def monotonic(self) -> float:
        return 100.0

    def sleep(self, seconds: float) -> None:
        pass


class FakeTreeTerminator:
    def __call__(self, pid: int) -> bool:
        return True


class FakeDeviceRunner:
    """Scripted adb responses; records every command for assertions."""

    def __init__(
        self,
        *,
        original_proxy: str = "null",
        probe_returncode: int = 0,
        probe_stderr: str = "",
        tcp_table: str | None = None,
        udp_table: str | None = None,
        fail_proc_tables: bool = False,
    ) -> None:
        self.original_proxy = original_proxy
        self.probe_returncode = probe_returncode
        self.probe_stderr = probe_stderr
        self.tcp_table = tcp_table
        self.udp_table = udp_table
        self.fail_proc_tables = fail_proc_tables
        self.commands: list[list[str]] = []
        self.put_calls = 0
        self.delete_calls = 0

    def __call__(self, command: list[str], cwd: Any = None, timeout: int = 10) -> dict[str, Any]:
        self.commands.append(list(command))
        text = " ".join(str(part) for part in command)
        if "settings" in text and " http_proxy" in text:
            if " get " in text or text.endswith("get global http_proxy"):
                return {"returncode": 0, "stdout": self.original_proxy, "stderr": "", "cmd": command}
            if " put " in text:
                self.put_calls += 1
                return {"returncode": 0, "stdout": "", "stderr": "", "cmd": command}
            if " delete " in text:
                self.delete_calls += 1
                return {"returncode": 0, "stdout": "", "stderr": "", "cmd": command}
        if "| nc " in text or text.endswith("nc -w 3 10.0.2.2 8080"):
            return {
                "returncode": self.probe_returncode,
                "stdout": "",
                "stderr": self.probe_stderr,
                "cmd": command,
            }
        if "/proc/net/" in text:
            if self.fail_proc_tables:
                raise OSError("device offline during snapshot")
            name = text.split("/proc/net/")[-1].split()[0]
            body = {
                "tcp": _TCP_ROWS if self.tcp_table is None else self.tcp_table,
                "tcp6": "",
                "udp": _UDP_ROWS if self.udp_table is None else self.udp_table,
                "udp6": "",
            }.get(name, "")
            return {"returncode": 0, "stdout": body, "stderr": "", "cmd": command}
        if "pidof" in text:
            return {"returncode": 0, "stdout": "4242 ", "stderr": "", "cmd": command}
        if "/proc/4242/status" in text:
            return {
                "returncode": 0,
                "stdout": "Name:  com.phoenix.read\nUid:  10000 10000 10000 10000\n",
                "stderr": "",
                "cmd": command,
            }
        return {"returncode": 0, "stdout": "", "stderr": "", "cmd": command}


# /proc/net/tcp row shape: sl local rem st tx:rx tr:when retrnsmt uid:inode ...
_TCP_ROWS = (
    "  sl local_address rem_address st tx_rx_queue tr_tm_when retrnsmt uid_inode\n"
    "   0: 0F02000A:9C40 0A0909C9:01BB 01 00000000:00000000 00:00000000 00000000 10000 0\n"
    "   1: 0F02000A:C350 0A0909C9:01BB 01 00000000:00000000 00:00000000 00000000 99999 0\n"
    "   2: 0F02000A:C351 0A0909C9:0050 06 00000000:00000000 00:00000000 00000000 99999 0\n"
)
_UDP_ROWS = (
    "  sl local_address rem_address st tx_rx_queue tr_tm_when retrnsmt uid_inode\n"
    "   0: 0F02000A:9C41 0A0909C9:01BB 07 00000000:00000000 00:00000000 00000000 10000 0\n"
)


def _session(
    tmp_path: Path,
    runner: FakeDeviceRunner,
    *,
    package_name: str | None = "com.phoenix.read",
) -> MitmSession:
    session = MitmSession(
        run_id="run-c",
        device=DeviceContext("127.0.0.1:16416"),
        traffic_dir=tmp_path / "run-c" / "traffic",
        port_pool=PortPool([18080], availability_probe=lambda _h, _p: True),
        process_factory=FakeProcessFactory(),
        process_tree_terminator=FakeTreeTerminator(),
        monotonic=FakeClock().monotonic,
        sleep=FakeClock().sleep,
        device_proxy_host="10.0.2.2",
        package_name=package_name,
        command_runner=runner,
    )
    return session


def _drain(session: MitmSession) -> None:
    session.jsonl_path.parent.mkdir(parents=True, exist_ok=True)
    session.jsonl_path.touch(exist_ok=True)


def _ready(session: MitmSession) -> None:
    _drain(session)
    payload = {
        "protocol_version": "1.0",
        "schema_version": "1.0",
        "type": "control",
        "event": "mitm_ready",
        "run_id": session.run_id,
        "session_id": session.session_id,
        "timestamp_utc": "2026-08-29T00:00:00.000Z",
    }
    with session.jsonl_path.open("a", encoding="utf-8") as stream:
        stream.write(json.dumps(payload) + "\n")
    assert session.wait_ready(timeout=1.0) is True


def _diagnose(session: MitmSession, *, requests: int = 0) -> dict[str, Any]:
    return diagnose_traffic(
        collector_outcome=(
            "collector_success_requests_observed"
            if requests
            else "collector_success_zero_requests"
        ),
        request_count=requests,
        session_status=session.to_status(),
        stderr_text="",
    )


# ---------------------------------------------------------------------------
# Parser facts.
# ---------------------------------------------------------------------------
def test_summarize_proc_net_reports_facts_and_discards_raw_data():
    summary = summarize_proc_net(tcp=_TCP_ROWS, udp=_UDP_ROWS)

    assert summary["tcp_rows"] == 3
    assert summary["tcp_established"] == 2
    assert summary["tcp_remote_443"] == 2
    assert summary["udp_rows"] == 1
    assert summary["udp_remote_443"] == 1
    assert summary["uid_socket_rows"]["10000"] >= 1
    # No raw rows, addresses or payloads survive.
    encoded = json.dumps(summary)
    assert "0F02000A" not in encoded
    assert "0A0909C9" not in encoded


# ---------------------------------------------------------------------------
# A/B — proxy config read + restoration (existing contract, re-pinned with
# the observation hooks in the loop).
# ---------------------------------------------------------------------------
def test_a_b_proxy_configured_probed_restored_and_observed(tmp_path: Path):
    runner = FakeDeviceRunner()
    session = _session(tmp_path, runner)
    assert session.start() is True
    _ready(session)
    session.mark_collecting()
    assert session.state is MitmSessionState.COLLECTING
    assert session.stop(timeout=1.0) is True

    status = session.to_status()
    assert status["device_proxy_configured"] is False  # restored resets the flag
    assert status["device_proxy_restored"] is True
    assert runner.put_calls == 1
    assert runner.delete_calls == 1  # original was null → delete, not put
    # The probe ran while the proxy was applied and the snapshot ran at stop.
    assert status["proxy_reachable"] is True
    assert status["network_observation"]["tcp_rows"] == 3
    assert status["network_observation"]["target_uid"] == 10000


# ---------------------------------------------------------------------------
# C — listener detection stays intact (existing semantics).
# ---------------------------------------------------------------------------
def test_c_listener_detected_when_ready(tmp_path: Path):
    runner = FakeDeviceRunner()
    session = _session(tmp_path, runner)
    session.start()
    _ready(session)
    session.wait_ready(timeout=1.0)
    diagnostics = _diagnose(session)
    assert diagnostics.host_listener == "listening"
    session.stop(timeout=1.0)


# ---------------------------------------------------------------------------
# D — proxy unreachable is a recorded fact.
# ---------------------------------------------------------------------------
def test_d_proxy_unreachable_recorded(tmp_path: Path):
    runner = FakeDeviceRunner(probe_returncode=1, probe_stderr="nc: connection refused")
    session = _session(tmp_path, runner)
    session.start()
    _ready(session)
    session.mark_collecting()
    session.stop(timeout=1.0)

    assert session.proxy_reachable is False
    diagnostics = _diagnose(session)
    assert diagnostics.proxy_reachable is False
    assert diagnostics.device_reachability == "unreachable"
    assert "traffic_proxy_unreachable" in diagnostics.reason_codes


# ---------------------------------------------------------------------------
# E — proxy reachable + zero requests: honest no-observations semantics.
# ---------------------------------------------------------------------------
def test_e_reachable_zero_requests_without_activity(tmp_path: Path):
    runner = FakeDeviceRunner(tcp_table="", udp_table="")
    session = _session(tmp_path, runner)
    session.start()
    _ready(session)
    session.mark_collecting()
    session.stop(timeout=1.0)

    diagnostics = _diagnose(session)
    assert diagnostics.proxy_reachable is True
    assert diagnostics.request_count == 0
    assert diagnostics.tcp_activity_observed is False
    assert "traffic_no_socket_activity_observed" in diagnostics.reason_codes
    assert "零请求不代表应用没有网络行为" in diagnostics.limitations


# ---------------------------------------------------------------------------
# F/G — TCP (and UDP:443) activity without a single HTTP request.
# ---------------------------------------------------------------------------
def test_f_tcp_activity_without_http_requests_is_a_distinct_state(tmp_path: Path):
    runner = FakeDeviceRunner()
    session = _session(tmp_path, runner)
    session.start()
    _ready(session)
    session.mark_collecting()
    session.stop(timeout=1.0)

    diagnostics = _diagnose(session)
    assert diagnostics.tcp_activity_observed is True
    assert diagnostics.request_count == 0
    assert "traffic_socket_activity_without_http_requests" in diagnostics.reason_codes
    assert "观察到 socket 活动，但未被 HTTP 代理采集到" in " ".join(
        diagnostics.limitations
    )


def test_g_udp_443_recorded_without_transport_attribution(tmp_path: Path):
    runner = FakeDeviceRunner()
    session = _session(tmp_path, runner)
    session.start()
    _ready(session)
    session.mark_collecting()
    session.stop(timeout=1.0)

    diagnostics = _diagnose(session)
    assert diagnostics.udp_activity_observed is True
    assert diagnostics.udp_port_443_observed is True
    assert "traffic_udp_443_observed" in diagnostics.reason_codes
    # Port evidence must never become a transport claim.
    payload = json.dumps(diagnostics.model_dump(), ensure_ascii=False).casefold()
    assert "quic" not in payload
    assert "http/3" not in payload
    assert "http3" not in payload


# ---------------------------------------------------------------------------
# H — requests observed keeps the success outcome.
# ---------------------------------------------------------------------------
def test_h_requests_observed_keeps_success_outcome(tmp_path: Path):
    runner = FakeDeviceRunner()
    session = _session(tmp_path, runner)
    session.start()
    _ready(session)
    session.mark_collecting()
    session.stop(timeout=1.0)

    diagnostics = _diagnose(session, requests=12)
    assert diagnostics.outcome == "collector_success_requests_observed"
    assert "traffic_zero_requests" not in diagnostics.reason_codes
    assert "traffic_socket_activity_without_http_requests" not in diagnostics.reason_codes


# ---------------------------------------------------------------------------
# I — no sensitive network data leaks into the diagnostics payload.
# ---------------------------------------------------------------------------
def test_i_no_sensitive_network_data_in_payload(tmp_path: Path):
    runner = FakeDeviceRunner()
    session = _session(tmp_path, runner)
    session.start()
    _ready(session)
    session.mark_collecting()
    session.stop(timeout=1.0)

    payload = json.dumps(session.to_status(), ensure_ascii=False)
    # Raw /proc rows, hex addresses and socket inodes never reach the artifact.
    assert "0F02000A" not in payload
    assert "0A0909C9" not in payload
    assert _TCP_ROWS.splitlines()[1].strip() not in payload


# ---------------------------------------------------------------------------
# K — cleanup survives an observation failure.
# ---------------------------------------------------------------------------
def test_k_cleanup_survives_observation_failure(tmp_path: Path):
    runner = FakeDeviceRunner(fail_proc_tables=True)
    session = _session(tmp_path, runner)
    session.start()
    _ready(session)
    session.mark_collecting()
    assert session.stop(timeout=1.0) is True

    assert session.to_status()["device_proxy_restored"] is True
    assert session.network_observation == {}


# ---------------------------------------------------------------------------
# L — deterministic correlation never claims causality, even with events.
# ---------------------------------------------------------------------------
def test_l_zero_requests_yields_no_pairs_and_no_causality():
    events = [
        {
            "event_id": f"ev-{index}",
            "type": "event",
            "timestamp_utc": f"2026-08-29T00:00:0{index}.000Z",
            "monotonic_ms": float(index) * 100.0,
            "category": "sensitive_setting_access",
            "api": "Settings.Secure.getString",
        }
        for index in range(1, 4)
    ]
    correlation = build_evidence_correlations(events, [])

    assert correlation.status == "no_observations"
    assert correlation.summary.correlated_pair_count == 0
    encoded = json.dumps(correlation.model_dump(), ensure_ascii=False)
    assert "导致" not in encoded
    assert "caused" not in encoded.casefold()


# ---------------------------------------------------------------------------
# diagnose_traffic is a pure mapping — no session required.
# ---------------------------------------------------------------------------
def test_diagnose_without_observation_stays_backward_compatible():
    diagnostics = diagnose_traffic(
        collector_outcome="collector_success_zero_requests",
        request_count=0,
        session_status={
            "device_proxy_configured": True,
            "device_proxy_restored": True,
            "ready_at": "now",
        },
        stderr_text="",
    )
    assert diagnostics.proxy_reachable is None
    assert diagnostics.device_reachability == "unknown"
    assert "traffic_zero_requests" in diagnostics.reason_codes
