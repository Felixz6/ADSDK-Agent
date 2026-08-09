from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
import threading
import json

import pytest

from app.frida.execution_modes import DynamicModePolicy, ExecutionMode
from app.frida.execution_session import PolicyFridaSession
from app.services.ai_task_service import AITaskService, RunScopedExecution


class _UnusedOrchestrator:
    pass


def test_unified_runner_context_is_claimed_once_when_static_then_dynamic(tmp_path: Path) -> None:
    """The production plan may request both tools, but owns one run context."""
    calls: list[str] = []

    def runner(strategy: str) -> dict[str, object]:
        calls.append(strategy)
        # This mirrors create_analysis_run_context's exclusive run-id claim.
        (tmp_path / "runs" / "RUN").mkdir(parents=True, exist_ok=False)
        return {
            "status": "success",
            "dynamic_events": [],
            "execution_decision": {"policy": strategy},
            "executor_strategy_receipt": {
                "executor_received_strategy": strategy,
                "executor_execution_strategy": "attach_existing",
                "executor_provenance_source": "real_executor",
            },
        }

    service = AITaskService(
        orchestrator=_UnusedOrchestrator(),  # type: ignore[arg-type]
        run_dir=tmp_path / "runs" / "RUN",
        unified_runner_with_strategy=runner,
    )
    service._effective_dynamic_strategy = "balanced"

    static = service.execute_tool("static_analysis", {})
    dynamic = service.execute_tool("dynamic_analysis", {})

    assert static.status == "success"
    assert dynamic.status == "success"
    assert calls == ["balanced"]
    assert service.executor_strategy_receipt == {
        "executor_received_strategy": "balanced",
        "executor_execution_strategy": "attach_existing",
        "executor_provenance_source": "real_executor",
    }


def test_real_proxy_endpoint_is_not_canonicalized_to_none() -> None:
    from app.orchestration.cleanup_manager import _proxy_semantic

    assert _proxy_semantic(":null") == _proxy_semantic("null") == ""
    assert _proxy_semantic("127.0.0.1:8080") == "127.0.0.1:8080"


def test_run_scoped_execution_single_flights_across_service_instances(tmp_path: Path) -> None:
    calls: list[str] = []
    entered = threading.Event()
    release = threading.Event()

    def runner(strategy: str) -> dict[str, object]:
        calls.append(strategy)
        entered.set()
        assert release.wait(2)
        return {"status": "success", "dynamic_events": []}

    execution = RunScopedExecution(runner)
    first = AITaskService(orchestrator=_UnusedOrchestrator(), run_dir=tmp_path / "r", unified_runner_with_strategy=execution)  # type: ignore[arg-type]
    second = AITaskService(orchestrator=_UnusedOrchestrator(), run_dir=tmp_path / "r", unified_runner_with_strategy=execution)  # type: ignore[arg-type]
    first._effective_dynamic_strategy = second._effective_dynamic_strategy = "balanced"
    results: list[object] = []
    threads = [threading.Thread(target=lambda: results.append(first.execute_tool("static_analysis", {}))), threading.Thread(target=lambda: results.append(second.execute_tool("dynamic_analysis", {})))]
    for thread in threads: thread.start()
    assert entered.wait(1)
    release.set()
    for thread in threads: thread.join(2)
    assert len(results) == 2
    assert calls == ["balanced"]


def test_run_scoped_execution_shares_first_exception() -> None:
    calls = 0

    def runner(_strategy: str) -> dict[str, object]:
        nonlocal calls
        calls += 1
        raise RuntimeError("first execution failed")

    execution = RunScopedExecution(runner)
    with pytest.raises(RuntimeError, match="first execution failed"):
        execution("balanced")
    with pytest.raises(RuntimeError, match="first execution failed"):
        execution("balanced")
    assert calls == 1


def test_run_context_claim_provenance_persists_owner_reuser_and_failure(tmp_path: Path) -> None:
    claims = tmp_path / "state" / "claims.json"
    run_dir = tmp_path / "runs" / "RUN"
    calls = 0

    def runner(_strategy: str) -> dict[str, object]:
        nonlocal calls
        calls += 1
        run_dir.mkdir(parents=True, exist_ok=False)
        raise FileExistsError(run_dir)

    execution = RunScopedExecution(
        runner, task_id="RUN", run_context_path=run_dir, diagnostics_path=claims
    )
    owner = AITaskService(orchestrator=_UnusedOrchestrator(), run_dir=run_dir, unified_runner_with_strategy=execution)  # type: ignore[arg-type]
    reuser = AITaskService(orchestrator=_UnusedOrchestrator(), run_dir=run_dir, unified_runner_with_strategy=execution)  # type: ignore[arg-type]
    owner._effective_dynamic_strategy = reuser._effective_dynamic_strategy = "balanced"
    owner.execute_tool("static_analysis", {})
    reuser.execute_tool("dynamic_analysis", {})

    events = json.loads(claims.read_text(encoding="utf-8"))["events"]
    assert calls == 1
    assert events[0]["single_flight_role"] == "owner"
    assert events[0]["caller_role"] == "static_consumer"
    assert any(event["operation"] == "reuse_same_failure" for event in events)
    assert any(event.get("exception_type") == "FileExistsError" for event in events)
    assert {event["service_instance_token"] for event in events} >= {owner._service_instance_token, reuser._service_instance_token}


def test_launch_then_attach_failure_never_leaks_private_datetime() -> None:
    """Reproduce the real launch-success/Frida-unavailable failure boundary."""

    class _UnavailableSession:
        error_code = "frida_server_unavailable"

        def start(self) -> None:
            raise RuntimeError(self.error_code)

        def stop(self) -> None:
            return None

    launched_at = datetime(2026, 8, 8, 8, 0, tzinfo=timezone.utc)
    execution = PolicyFridaSession(
        policy=DynamicModePolicy.BALANCED,
        session_factory=lambda _mode: _UnavailableSession(),
        launch_target=lambda: {
            "launch_requested_at": "2026-08-08T08:00:00.000Z",
            "launch_completed_at": "2026-08-08T08:00:00.100Z",
            "target_pid": 31163,
            "_launch_requested_datetime": launched_at,
        },
    )

    with pytest.raises(RuntimeError, match="frida_server_unavailable"):
        execution.start()

    assert execution.fallback_path == [ExecutionMode.LAUNCH_THEN_ATTACH.value]
    assert "_launch_requested_datetime" not in execution.launch_timing
    assert all(
        not isinstance(value, datetime)
        for value in execution.launch_timing.values()
    )
    payload = {
        "execution": {
            "launch_timing": execution.launch_timing,
            "attempts": [item.model_dump(mode="json") for item in execution.attempts],
        }
    }
    json.dumps(payload)


def test_frida_failure_result_retains_receipt_and_single_flight_result(
    tmp_path: Path,
) -> None:
    """Offline fixture distilled from real run 2ea12711: degrade, do not throw."""
    calls: list[str] = []

    def runner(strategy: str) -> dict[str, object]:
        calls.append(strategy)
        class _UnavailableSession:
            error_code = "frida_server_unavailable"

            def start(self) -> None:
                raise RuntimeError(self.error_code)

            def stop(self) -> None:
                return None

        frida = PolicyFridaSession(
            policy=DynamicModePolicy.BALANCED,
            session_factory=lambda _mode: _UnavailableSession(),
            launch_target=lambda: {
                "launch_requested_at": "2026-08-08T08:00:00.000Z",
                "target_pid": 31163,
                "_launch_requested_datetime": datetime(
                    2026, 8, 8, 8, 0, tzinfo=timezone.utc
                ),
            },
        )
        with pytest.raises(RuntimeError, match="frida_server_unavailable"):
            frida.start()

        return {
            "status": "failed",
            "dynamic_events": [],
            "requested_strategy": "attach_only",
            "effective_strategy": strategy,
            "executor_strategy_receipt": {
                "executor_received_strategy": strategy,
                "executor_execution_strategy": "none",
                "executor_provenance_source": "real_executor_failure_boundary",
            },
            "execution": {
                "launch_timing": frida.launch_timing,
                "attempts": [
                    item.model_dump(mode="json") for item in frida.attempts
                ],
                "failure_code": "frida_server_unavailable",
            },
            "collector_sessions": [],
            "dynamic_diagnostics": {
                "traffic_requests": 0,
                "deterministic_fallback": True,
            },
            "ownership_provenance": {
                "ownership": "owned_by_run",
                "created_by_run": True,
                "preexisting": False,
            },
        }

    execution = RunScopedExecution(runner)
    first = AITaskService(
        orchestrator=_UnusedOrchestrator(),  # type: ignore[arg-type]
        run_dir=tmp_path / "run",
        unified_runner_with_strategy=execution,
    )
    second = AITaskService(
        orchestrator=_UnusedOrchestrator(),  # type: ignore[arg-type]
        run_dir=tmp_path / "run",
        unified_runner_with_strategy=execution,
    )
    first._effective_dynamic_strategy = second._effective_dynamic_strategy = "balanced"

    static = first.execute_tool("static_analysis", {})
    dynamic = second.execute_tool("dynamic_analysis", {})

    assert calls == ["balanced"]
    assert static.status == "failed"
    assert dynamic.status == "partial"
    assert second.executor_strategy_receipt == {
        "executor_received_strategy": "balanced",
        "executor_execution_strategy": "none",
        "executor_provenance_source": "real_executor_failure_boundary",
    }
    assert execution._result is not None
    json.dumps(execution._result)
