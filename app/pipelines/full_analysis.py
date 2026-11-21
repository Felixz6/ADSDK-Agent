"""Full analysis session orchestration, device snapshots, and resource registration."""

from __future__ import annotations

from pathlib import Path
from typing import Any

from fastapi.responses import JSONResponse

from app import config as app_config
from app.ai.orchestrator import AIOrchestrator
from app.ai.settings_service import resolve_effective_ai_settings
from app.ai.tool_registry import AIToolRegistry
from app.api.env import env_check
from app.config import (
    CONSENT_CHECKPOINT_WAIT_SECONDS,
    SCHEMA_VERSION,
)
from app.container import (
    ai_settings_service,
    consent_checkpoint_service,
    device_lease_registry,
)
from app.core.artifacts import atomic_write_json
from app.models import DynamicAnalyzeRequest
from app.orchestration.cleanup_manager import (
    CleanupDiagnostic,
    CleanupStep,
    ResourceOwnershipRegistry,
)
from app.orchestration.device_ops import (
    _adb_cleanup_action,
    _device_package_pids,
    _device_process_command,
    _host_process_command,
    _read_device_proxy,
    _stop_owned_host_pid,
)
from app.orchestration.device_session import (
    DeviceSessionSnapshot,
    DeviceState,
    mask_device_ref,
)
from app.orchestration.full_analysis_session import FullAnalysisSession
from app.orchestration.production_session_effects import ProductionSessionEffects
from app.pipelines.common import (
    _ai_cancelled,
    _public_ai_section,
    task_service_response_payload,
)
from app.repositories.task_repository import utc_now as task_utc_now
from app.services import AITaskService
from app.services.ai_task_service import RunScopedExecution
from app.tasks.models import TaskRecord
from app.tasks.runtime import report_step
from app.tools.utils import run_cmd
from app.traffic.mitm_runner import check_port_listening


def _capture_device_snapshot(
    *, run_id: str, device_id: str | None, package_name: str | None, capture_kind: str
) -> DeviceSessionSnapshot:
    state = DeviceState()
    if device_id:

        def adb(*args: str) -> dict[str, Any]:
            return run_cmd(["adb", "-s", device_id, *args])

        state.online = adb("get-state").get("stdout", "").strip() == "device"
        state.boot_id = (
            adb("shell", "cat", "/proc/sys/kernel/random/boot_id").get("stdout", "").strip() or None
        )
        state.abi = adb("shell", "getprop", "ro.product.cpu.abi").get("stdout", "").strip() or None
        proxy = adb("shell", "settings", "get", "global", "http_proxy").get("stdout", "").strip()
        state.http_proxy = "" if proxy in {"", ":0", ":null", "null"} else proxy
        if package_name:
            state.package_installed = bool(
                adb("shell", "pm", "path", package_name).get("stdout", "").strip()
            )
            target = adb("shell", "pidof", package_name).get("stdout", "").strip()
            state.foreground_package = package_name if target else None
        frida = adb("shell", "pidof", "frida-server").get("stdout", "").strip()
        state.frida_server_present = bool(frida)
        state.frida_server_pid = int(frida.split()[0]) if frida else None
        helper = adb("shell", "pidof", "re.frida.helper").get("stdout", "").strip()
        state.frida_helper_pids = [
            int(value) for value in helper.split() if value.isdigit() and int(value) > 0
        ]
    return DeviceSessionSnapshot(
        run_id=run_id,
        device_ref=mask_device_ref(device_id),
        captured_at=task_utc_now(),
        initial_state=state,
        capture_kind=capture_kind,
    )


def _target_pid(device_id: str, package_name: str) -> int | None:
    if not device_id or not package_name:
        return None
    result = run_cmd(["adb", "-s", device_id, "shell", "pidof", package_name])
    value = str(result.get("stdout") or "").strip().split()
    return int(value[0]) if value and value[0].isdigit() and int(value[0]) > 0 else None


def _resource_present(kind: str, detail: dict[str, Any]) -> bool | None:
    pid = int(detail.get("pid") or -1)
    if kind == "app_process":
        device = str(detail.get("device_id") or "")
        package_name = str(detail.get("expected_command_token") or "")
        package_pids = _device_package_pids(device, package_name)
        if package_pids is None:
            return None
        return bool(package_pids)
    if kind in {"frida_server", "frida_helper"}:
        return _device_process_command(str(detail.get("device_id") or ""), pid) is not None
    if kind == "mitm_process":
        return _host_process_command(pid) is not None
    if kind in {"mitm_port", "frida_port"}:
        port = int(detail.get("port") or -1)
        if port <= 0:
            return None
        return check_port_listening(
            port=port,
            host=str(detail.get("host") or "127.0.0.1"),
        )
    if kind == "frida_session":
        return None
    return None


def _resource_identity_matches(kind: str, detail: dict[str, Any]) -> bool:
    """Treat absence as a verified cleanup state; guard only live PID reuse."""
    pid = int(detail.get("pid") or -1)
    expected = str(detail.get("expected_command_token") or "").casefold()
    if kind in {"app_process", "frida_server", "frida_helper"}:
        command = _device_process_command(str(detail.get("device_id") or ""), pid)
    elif kind == "mitm_process":
        command = _host_process_command(pid)
    else:
        return True
    if command is None:
        return True
    return bool(expected) and expected in command.casefold()


def _register_owned_resources(
    *,
    report: dict[str, Any],
    registry: ResourceOwnershipRegistry,
    payload: dict[str, Any],
    initial_snapshot: DeviceSessionSnapshot,
) -> None:
    """Register only resources whose run/session provenance is explicit."""
    device_id = str(payload.get("device_id") or "")
    package_name = str(payload.get("package_name") or "")
    process = report.get("process_diagnostics")
    if (
        isinstance(process, dict)
        and isinstance(process.get("pid"), int)
        and process["pid"] > 0
        and initial_snapshot.initial_state.foreground_package != package_name
        and registry.get("app_process", str(process["pid"])) is None
    ):
        registry.mark_owned(
            "app_process",
            str(process["pid"]),
            pid=process["pid"],
            device_id=device_id,
            expected_command_token=package_name,
            preexisting=False,
            created_by_run=True,
        )

    sessions = report.get("collector_sessions")
    mitm = sessions.get("mitm") if isinstance(sessions, dict) else None
    if not isinstance(mitm, dict) or mitm.get("run_id") != report.get("run_id"):
        return
    pid = mitm.get("pid")
    session_id = mitm.get("session_id")
    if isinstance(pid, int) and pid > 0 and isinstance(session_id, str):
        registry.mark_owned(
            "mitm_process",
            session_id,
            pid=pid,
            expected_command_token="mitmdump",
            preexisting=False,
            created_by_run=True,
        )
    port = mitm.get("port") or mitm.get("listen_port")
    if isinstance(port, int) and port > 0 and isinstance(session_id, str):
        registry.mark_owned(
            "mitm_port",
            f"{session_id}:{port}",
            port=port,
            host=str(mitm.get("listen_host") or "127.0.0.1"),
            pid=pid,
            preexisting=False,
            created_by_run=True,
        )


def run_full_analysis_session(
    *, task: TaskRecord, payload: dict[str, Any]
) -> dict[str, Any] | JSONResponse:
    """Single production entry for ai_orchestrated full_analysis tasks."""
    from app.pipelines.dynamic import _dynamic_analyze_v2

    output_dir = app_config.OUTPUT_DIR
    run_dir = Path(output_dir) / "runs" / task.id
    effective = resolve_effective_ai_settings(ai_settings_service.store)
    ai_enabled = bool(effective["enabled"]) and bool(payload.get("ai_enabled", True))
    provider = ai_settings_service.factory.current() if ai_enabled else None
    orchestrator = AIOrchestrator(
        provider=provider,
        registry=AIToolRegistry(allow_dynamic_tools=bool(effective["allow_dynamic_tools"])),
        enabled=ai_enabled,
        cancelled=_ai_cancelled,
    )
    registry = ResourceOwnershipRegistry()
    report_holder: dict[str, dict[str, Any]] = {}
    initial_snapshot: dict[str, DeviceSessionSnapshot] = {}
    frida_session_stoppers: dict[str, Any] = {}

    def snapshot_factory(
        device_id: str | None, package_name: str | None, capture_kind: str
    ) -> DeviceSessionSnapshot:
        snapshot = _capture_device_snapshot(
            run_id=task.id,
            device_id=device_id,
            package_name=package_name,
            capture_kind=capture_kind,
        )
        initial_snapshot.setdefault("value", snapshot)
        if capture_kind == "read_only":
            for pid in snapshot.initial_state.frida_helper_pids:
                registry.mark_external(
                    "frida_helper",
                    str(pid),
                    pid=pid,
                    device_id=str(device_id or ""),
                    expected_command_token="re.frida.helper",
                    preexisting=True,
                    created_by_run=False,
                    cleanup_required=False,
                    verification_required=False,
                    ownership_source="preflight_pidof",
                    registered_at_stage="read_only_preflight",
                    run_id=task.id,
                )
        return snapshot

    def unified_runner(strategy: str) -> dict[str, Any]:
        request_payload = {
            key: value
            for key, value in payload.items()
            if key in DynamicAnalyzeRequest.model_fields
        }
        request_payload["dynamic_mode_policy"] = strategy
        deterministic = _dynamic_analyze_v2(
            DynamicAnalyzeRequest.model_validate(request_payload),
            ownership_registry=registry,
        )
        report = task_service_response_payload(deterministic)
        report_holder["value"] = report
        before = initial_snapshot.get("value")
        if before is not None:
            _register_owned_resources(
                report=report,
                registry=registry,
                payload=payload,
                initial_snapshot=before,
            )
        return report

    run_execution = RunScopedExecution(
        unified_runner,
        task_id=task.id,
        run_context_path=run_dir,
        diagnostics_path=Path(output_dir)
        / "state"
        / "task-diagnostics"
        / f"{task.id}.run-context-claims.json",
    )

    def stop_registered_frida_session(ref: str) -> bool:
        stopper = frida_session_stoppers.pop(ref, None)
        if not callable(stopper):
            return False
        result = stopper()
        return result is not False

    ai_service = AITaskService(
        orchestrator=orchestrator,
        run_dir=run_dir,
        unified_runner_with_strategy=run_execution,
        environment_probe=lambda: env_check(payload.get("device_id")),
    )
    effects = ProductionSessionEffects(
        task_id=task.id,
        run_id=task.id,
        ai_service=ai_service,
        consent_service=consent_checkpoint_service,
        snapshot_factory=snapshot_factory,
        clock=task_utc_now,
        is_cancelled=_ai_cancelled,
        report_step=lambda key, status, message=None: report_step(key, status, message),
        set_proxy_action=lambda device, value: _adb_cleanup_action(
            device, ["shell", "settings", "put", "global", "http_proxy", value]
        ),
        delete_proxy_action=lambda device: _adb_cleanup_action(
            device, ["shell", "settings", "delete", "global", "http_proxy"]
        ),
        kill_pid_action=lambda device, pid: _adb_cleanup_action(
            device, ["shell", "kill", str(pid)]
        ),
        stop_mitm_pid_action=_stop_owned_host_pid,
        stop_frida_session_action=stop_registered_frida_session,
        read_proxy_action=_read_device_proxy,
        resource_present_action=_resource_present,
        resource_identity_matches_action=_resource_identity_matches,
        force_stop_package_action=lambda device, package: _adb_cleanup_action(
            device, ["shell", "am", "force-stop", package]
        ),
        consent_wait_seconds=CONSENT_CHECKPOINT_WAIT_SECONDS,
    )
    session = FullAnalysisSession(
        task_id=task.id,
        run_id=task.id,
        device_id=payload.get("device_id"),
        package_name=payload.get("package_name"),
        objective=str(payload.get("objective") or "分析本次 APK 的隐私风险"),
        strategy="full_analysis",
        dynamic_mode_policy=str(payload.get("dynamic_mode_policy") or "balanced"),
        application_launch_allowed=True,
        allow_dynamic=bool(payload.get("allow_dynamic")),
        allow_network=bool(payload.get("allow_network")),
        confirmed_tools=frozenset(str(x) for x in payload.get("confirmed_tools") or []),
        token_budget=int(payload.get("token_budget") or 6000),
        report_language=str(payload.get("report_language") or effective["report_language"]),
        lease=device_lease_registry,
        consent=consent_checkpoint_service,
        registry=registry,
        effects=effects,
        run_dir=run_dir,
    )
    transition = session.run()
    before_snapshot = initial_snapshot.get("value") or getattr(transition, "snapshot", None)
    postflight_snapshot = (
        _capture_device_snapshot(
            run_id=task.id,
            device_id=payload.get("device_id"),
            package_name=payload.get("package_name"),
            capture_kind="postflight",
        )
        if before_snapshot is not None
        else None
    )
    postflight_target_pid = _target_pid(
        str(payload.get("device_id") or ""), str(payload.get("package_name") or "")
    )
    preflight_target_absent = bool(
        before_snapshot is not None
        and before_snapshot.initial_state.foreground_package != payload.get("package_name")
    )
    unclassified_new_target = (
        postflight_target_pid is not None
        and preflight_target_absent
        and registry.get("app_process", str(postflight_target_pid)) is None
    )
    if unclassified_new_target and transition.cleanup is not None:
        transition.cleanup.status = "partial"
        transition.cleanup.failures.append("unclassified_new_target")
        transition.cleanup.verification_attempted = True
        transition.cleanup.steps.append(
            CleanupStep(
                rule="ownership_accounting_completeness",
                target_kind="app_process",
                target_identity=str(postflight_target_pid),
                ownership="external",
                status="failed",
                safe_message="unclassified_new_target",
            )
        )
        transition.cleanup.diagnostics.append(
            CleanupDiagnostic(
                resource_type="app_process",
                identifier_hash=str(postflight_target_pid),
                preexisting=False,
                owned_by_run=False,
                created_by_run=False,
                cleanup_attempted=False,
                verification_attempted=True,
                verification_result="present",
                final_status="partial",
                reason_code="unclassified_new_target",
            )
        )
    report = report_holder.get(
        "value",
        {
            "schema_version": SCHEMA_VERSION,
            "run_id": task.id,
            "status": ("success" if transition.final_state == "completed" else "failed"),
            "error_code": transition.runtime_validation_error_code
            or "full_analysis_session_failed",
            "error": "; ".join(transition.failures)[:500] or "Full analysis session failed",
            "output_dir": str(run_dir),
        },
    )
    if effects.last_result is not None:
        report["ai_orchestration"] = _public_ai_section(effects.last_result)
    report["analysis_mode"] = "full_analysis"
    report["requested_strategy"] = transition.requested_strategy
    report["effective_strategy"] = transition.effective_strategy
    report["executor_strategy_receipt"] = effects.last_executor_strategy_receipt
    report["resource_ownership"] = [
        {
            "resource_type": item.kind,
            "resource_id": item.identity,
            "ownership": item.ownership,
            **dict(item.detail),
        }
        for item in registry.all_items()
    ]
    report["unclassified_new_target"] = (
        {"pid": postflight_target_pid, "reason_code": "unclassified_new_target"}
        if unclassified_new_target
        else None
    )
    report["cleanup_final_verification"] = (
        transition.cleanup.model_dump(mode="json") if transition.cleanup is not None else None
    )
    report["consent_checkpoint"] = (
        transition.consent.model_dump(mode="json") if transition.consent is not None else None
    )
    before_helpers = (
        set(before_snapshot.initial_state.frida_helper_pids) if before_snapshot else set()
    )
    after_helpers = (
        set(postflight_snapshot.initial_state.frida_helper_pids)
        if postflight_snapshot is not None
        else set()
    )
    owned_helpers = {
        int(item.detail.get("pid"))
        for item in registry.owned()
        if item.kind == "frida_helper" and isinstance(item.detail.get("pid"), int)
    }
    newly_unknown = sorted(after_helpers - before_helpers - owned_helpers)
    report["helper_provenance"] = {
        "process_name": "re.frida.helper",
        "before_pids": sorted(before_helpers),
        "after_pids": sorted(after_helpers),
        "owned_pids": sorted(owned_helpers),
        "preexisting_external_pids": sorted(before_helpers - owned_helpers),
        "unknown_newly_appeared_pids": newly_unknown,
        "postflight_capture": (
            postflight_snapshot.safe_dump() if postflight_snapshot is not None else None
        ),
    }
    if newly_unknown:
        report["status"] = "partial"
        report.setdefault("limitations", []).append(
            "new re.frida.helper PID has unknown provenance; it was not claimed or killed"
        )
    report["normalized"] = transition.normalized
    report["reason_code"] = transition.normalization_reason
    report["target_running"] = transition.target_running
    report["preflight_changed"] = transition.preflight_changed
    report["cleanup"] = transition.cleanup.model_dump(mode="json") if transition.cleanup else None
    if transition.final_state in {"failed", "cancelled"}:
        report["status"] = transition.final_state
    report["report_json"] = str(run_dir / "report.json")
    if (run_dir / "report.md").is_file():
        report["report_md"] = str(run_dir / "report.md")
    if (run_dir / "report.html").is_file():
        report["report_html"] = str(run_dir / "report.html")
    atomic_write_json(run_dir / "report.json", report)
    return report


capture_device_session_snapshot = _capture_device_snapshot
find_target_process_pid = _target_pid
check_owned_resource_present = _resource_present
match_owned_resource_identity = _resource_identity_matches
register_session_owned_resources = _register_owned_resources


__all__ = [
    "_capture_device_snapshot",
    "_register_owned_resources",
    "_resource_identity_matches",
    "_resource_present",
    "_target_pid",
    "capture_device_session_snapshot",
    "check_owned_resource_present",
    "find_target_process_pid",
    "match_owned_resource_identity",
    "register_session_owned_resources",
    "run_full_analysis_session",
]
