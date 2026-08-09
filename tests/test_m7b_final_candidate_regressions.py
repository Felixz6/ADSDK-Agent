from __future__ import annotations

from pathlib import Path
import threading

import pytest

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
