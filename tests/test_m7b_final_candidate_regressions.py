from __future__ import annotations

from pathlib import Path

from app.services.ai_task_service import AITaskService


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
        "executor_execution_strategy": "balanced",
        "executor_provenance_source": "AITaskService.unified_runner_with_strategy",
    }


def test_real_proxy_endpoint_is_not_canonicalized_to_none() -> None:
    from app.orchestration.cleanup_manager import _proxy_semantic

    assert _proxy_semantic(":null") == _proxy_semantic("null") == ""
    assert _proxy_semantic("127.0.0.1:8080") == "127.0.0.1:8080"
