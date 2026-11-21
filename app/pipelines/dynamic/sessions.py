"""Device selection, session creation, and ownership callback management."""

from __future__ import annotations

import time
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any

from app.config import (
    FRIDA_SERVER_MANAGEMENT_ENABLED,
    FRIDA_SERVER_REMOTE_PATH,
    FRIDA_STOP_TIMEOUT_SECONDS,
    MITM_DEVICE_PROXY_HOST,
    MITM_LISTEN_HOST,
    MITM_STOP_TIMEOUT_SECONDS,
)
from app.container import Container
from app.core.clock import utc_now as _utc_now
from app.core.device import DeviceContext
from app.core.run_context import AnalysisRunContext
from app.core.status import StepResult, StepStatus
from app.frida import (
    DynamicModePolicy,
    ExecutionMode,
    FridaDiagnosticsRequest,
    PolicyFridaSession,
)
from app.frida.frida_session import FridaSession, FridaSessionError
from app.models import DynamicAnalyzeRequest
from app.orchestration.cleanup_manager import ResourceOwnershipRegistry
from app.pipelines.common import (
    StaticStageResult,
    _step_result,
    resolve_frida_hook_script,
)
from app.tasks.runtime import register_cleanup, report_step
from app.tools.adb_runner import (
    DeviceSelectionError,
    install_apk,
    launch_app,
    select_device_context,
)
from app.tools.utils import now_iso, run_cmd


@dataclass(slots=True)
class _DynamicEnvironment:
    context: AnalysisRunContext
    device_context: DeviceContext | None
    device_failure: bool
    install_ok: bool
    package_name: str
    frida_session: Any
    mitm_session: Any
    frida_diagnostic_payload: dict[str, Any] | None
    stimulate_ui: Any
    register_frida_started: Any
    frida_session_factory: Any = None


def _resolve_dynamic_tool(name: str, default: Any) -> Any:
    import sys

    dyn_mod = sys.modules.get("app.pipelines.dynamic")
    if dyn_mod is not None and hasattr(dyn_mod, name):
        return getattr(dyn_mod, name)
    return default


def _install_and_select_device(
    req: DynamicAnalyzeRequest,
    context: AnalysisRunContext,
    steps: list[StepResult],
    static_stage: StaticStageResult,
) -> tuple[AnalysisRunContext, DeviceContext | None, bool, bool, str]:
    """Select the target device and install the APK when the policy requires it."""
    unpack_ok = static_stage.unpack_ok
    package_name = static_stage.package_name or ""

    device_context: DeviceContext | None = None
    device_failure = False
    started = _utc_now()
    select_fn = _resolve_dynamic_tool("select_device_context", select_device_context)
    install_fn = _resolve_dynamic_tool("install_apk", install_apk)
    if unpack_ok and package_name:
        try:
            device_context = select_fn(req.device_id)
            context = replace(context, device_id=device_context.serial)
            steps.append(
                _step_result(
                    "device_selection",
                    StepStatus.SUCCESS,
                    started,
                    required=True,
                    details={"device": device_context.to_public_dict()},
                )
            )
        except DeviceSelectionError as exc:
            device_failure = True
            steps.append(
                _step_result(
                    "device_selection",
                    StepStatus.FAILED,
                    started,
                    required=True,
                    error_code=exc.code,
                    error_message=exc.message,
                )
            )
    else:
        steps.append(
            _step_result(
                "device_selection",
                StepStatus.SKIPPED,
                started,
                required=True,
                warnings=["runtime package or unpacked APK is unavailable"],
            )
        )

    install_ok = False
    started = _utc_now()
    if (
        device_context is not None
        and req.dynamic_mode_policy == DynamicModePolicy.ATTACH_ONLY.value
    ):
        install_ok = True
        steps.append(
            _step_result(
                "apk_install",
                StepStatus.SKIPPED,
                started,
                required=False,
                warnings=["attach_only policy skips APK re-install and preserves running target"],
                details={"policy": req.dynamic_mode_policy, "package": package_name},
            )
        )
    elif device_context is not None and not device_failure:
        report_step("apk_install", "running", "正在向目标设备安装 APK")
        install_result = install_fn(
            str(context.apk_path),
            device_context=device_context,
        )
        install_ok = install_result.get("returncode") == 0
        steps.append(
            _step_result(
                "apk_install",
                StepStatus.SUCCESS if install_ok else StepStatus.FAILED,
                started,
                required=True,
                error_code=None if install_ok else "apk_install_failed",
                error_message=None if install_ok else install_result.get("stderr"),
                details={"command": install_result.get("cmd")},
            )
        )
    else:
        steps.append(
            _step_result(
                "apk_install",
                StepStatus.SKIPPED,
                started,
                required=True,
                warnings=["APK install skipped because device selection failed"],
            )
        )

    from app.core.artifacts import atomic_write_text

    atomic_write_text(
        context.hook_log_path,
        f"[INFO] {now_iso()} structured dynamic collection prepared\n",
    )
    return context, device_context, device_failure, install_ok, package_name


def _noop_register_runtime_target(pid: int, *, ownership_source: str, created_by_run: bool) -> None:
    del pid, ownership_source, created_by_run


def _is_real_frida_factory(factory: Any, *, container: Container | None = None) -> bool:
    if factory is None:
        return False
    if container is not None and not container.frida_real_device:
        return False
    return bool(getattr(factory, "is_real", False))


def _report_frida_diagnostics(
    req: DynamicAnalyzeRequest,
    steps: list[StepResult],
    device_context: DeviceContext,
    package_name: str,
    diagnostics_service: Any = None,
) -> dict[str, Any]:
    """Run the layered Frida diagnostics and record its step."""
    report_step("frida_diagnostics", "running", "正在执行 Frida 分层诊断")
    if diagnostics_service is None:
        from app.frida import FridaDiagnosticsService

        diagnostics_service = FridaDiagnosticsService(
            project_root=Path(__file__).resolve().parent.parent.parent.parent,
            server_remote_path=FRIDA_SERVER_REMOTE_PATH,
            management_enabled=FRIDA_SERVER_MANAGEMENT_ENABLED,
        )
    diagnostic_result = diagnostics_service.diagnose(
        FridaDiagnosticsRequest(
            device_id=device_context.serial,
            package_name=package_name,
        )
    )
    frida_diagnostic_payload = diagnostic_result.model_dump(mode="json")
    diagnostic_status = (
        StepStatus.SUCCESS
        if diagnostic_result.overall_status == "ready"
        else StepStatus.PARTIAL
        if diagnostic_result.overall_status == "degraded"
        else StepStatus.FAILED
    )
    steps.append(
        _step_result(
            "frida_diagnostics",
            diagnostic_status,
            _utc_now(),
            required=req.dynamic_mode_policy == "strict",
            error_code=(
                diagnostic_result.issues[0].code
                if diagnostic_status is StepStatus.FAILED and diagnostic_result.issues
                else None
            ),
            error_message=(
                diagnostic_result.issues[0].summary
                if diagnostic_status is StepStatus.FAILED and diagnostic_result.issues
                else None
            ),
            details={
                "overall_status": diagnostic_result.overall_status,
                "recommended_mode": diagnostic_result.recommended_mode,
                "device_ref": diagnostic_result.device_ref,
            },
        )
    )
    return frida_diagnostic_payload


def _make_launch_target_for_attach(
    context: AnalysisRunContext,
    device_context: DeviceContext,
    package_name: str,
    register_runtime_target: Any,
) -> Any:
    """Launch the target and resolve the exact PID for attach-then-verify."""

    def launch_target_for_attach() -> dict[str, Any]:
        launch_requested = _utc_now()
        launch_fn = _resolve_dynamic_tool("launch_app", launch_app)
        run_cmd_fn = _resolve_dynamic_tool("run_cmd", run_cmd)
        time_mod = _resolve_dynamic_tool("time", time)
        launch_result = launch_fn(
            package_name,
            device_context=device_context,
        )
        if launch_result.get("returncode") != 0:
            raise FridaSessionError(
                "package_launch_failed",
                "Target package launch command failed",
            )
        deadline = time_mod.monotonic() + 5.0
        while time_mod.monotonic() < deadline:
            pid_result = run_cmd_fn(
                device_context.adb_command("shell", "pidof", package_name),
                timeout=3,
            )
            if pid_result.get("returncode") == 0 and str(pid_result.get("stdout") or "").strip():
                pid_observed = _utc_now()
                pid_text = str(pid_result.get("stdout") or "").strip().split()[0]
                pid = int(pid_text) if pid_text.isdigit() else 0
                if pid <= 0:
                    continue
                register_runtime_target(
                    pid,
                    ownership_source="launch_then_attach_pidof",
                    created_by_run=True,
                )
                return {
                    "launch_requested_at": launch_requested.isoformat(
                        timespec="milliseconds"
                    ).replace("+00:00", "Z"),
                    "pid_observed_at": pid_observed.isoformat(timespec="milliseconds").replace(
                        "+00:00", "Z"
                    ),
                    "_launch_requested_datetime": launch_requested,
                    "pid": pid,
                }
            time_mod.sleep(0.25)
        raise FridaSessionError(
            "package_process_not_found",
            "Target package did not expose a process after launch",
        )

    return launch_target_for_attach


def _build_real_frida_session(
    req: DynamicAnalyzeRequest,
    context: AnalysisRunContext,
    steps: list[StepResult],
    device_context: DeviceContext,
    package_name: str,
    script_path: Path,
    ownership_registry: ResourceOwnershipRegistry | None,
    register_runtime_target: Any,
    frida_session_factory: Any = None,
    diagnostics_service: Any = None,
    container: Container | None = None,
) -> tuple[Any, dict[str, Any] | None, Any]:
    """Build the real Frida session (policy or single-mode) and its diagnostics."""
    factory = frida_session_factory or FridaSession
    is_real_frida = _is_real_frida_factory(factory, container=container)
    frida_session: Any = None
    frida_diagnostic_payload: dict[str, Any] | None = None
    if is_real_frida:
        frida_diagnostic_payload = _report_frida_diagnostics(
            req, steps, device_context, package_name, diagnostics_service=diagnostics_service
        )
        register_runtime_target = _register_owned_target(
            context, device_context, package_name, ownership_registry
        )

        def make_frida_session(mode: ExecutionMode) -> FridaSession:
            return factory(
                run_id=context.run_id,
                device=device_context,
                package_name=package_name,
                script_path=script_path,
                event_log_path=context.events_raw_path,
                protocol_error_path=(context.run_dir / "frida.protocol-errors.jsonl"),
                stop_timeout_seconds=FRIDA_STOP_TIMEOUT_SECONDS,
                execution_mode=(
                    ExecutionMode.ATTACH_EXISTING.value
                    if mode is ExecutionMode.LAUNCH_THEN_ATTACH
                    else mode.value
                ),
            )

        frida_session = PolicyFridaSession(
            policy=DynamicModePolicy(req.dynamic_mode_policy),
            session_factory=make_frida_session,
            launch_target=_make_launch_target_for_attach(
                context,
                device_context,
                package_name,
                register_runtime_target,
            ),
        )
    else:
        frida_session = factory(
            run_id=context.run_id,
            device=device_context,
            package_name=package_name,
            script_path=script_path,
            event_log_path=context.events_raw_path,
            protocol_error_path=(context.run_dir / "frida.protocol-errors.jsonl"),
            stop_timeout_seconds=FRIDA_STOP_TIMEOUT_SECONDS,
        )
    return frida_session, frida_diagnostic_payload, register_runtime_target


def _make_collection_callbacks(
    context: AnalysisRunContext,
    device_context: DeviceContext,
    package_name: str,
    ownership_registry: ResourceOwnershipRegistry | None,
    register_runtime_target: Any,
) -> tuple[Any, Any]:
    """Create the UI-stimulation and Frida-started ownership callbacks."""

    def stimulate_ui() -> None:
        launch_fn = _resolve_dynamic_tool("launch_app", launch_app)
        result = launch_fn(
            package_name,
            device_context=device_context,
        )
        if result.get("returncode") != 0:
            raise RuntimeError("UI stimulation failed")

    def register_frida_started(session: Any) -> None:
        pid = getattr(session, "pid", None)
        if not isinstance(pid, int) or pid <= 0:
            return
        selected = getattr(session, "selected_mode", None)
        mode = getattr(selected, "value", selected)
        register_runtime_target(
            pid,
            ownership_source=(
                "frida_spawn"
                if mode == ExecutionMode.SPAWN_SUSPENDED.value
                else "frida_attach_existing"
            ),
            created_by_run=mode == ExecutionMode.SPAWN_SUSPENDED.value,
        )
        helper_pid = getattr(session, "helper_pid", None)
        if ownership_registry is not None and isinstance(helper_pid, int) and helper_pid > 0:
            ownership_registry.mark_owned(
                "frida_helper",
                str(helper_pid),
                pid=helper_pid,
                device_id=device_context.serial,
                expected_command_token="re.frida.helper",
                preexisting=False,
                created_by_run=True,
                cleanup_required=True,
                verification_required=True,
                ownership_source="frida_session_helper_start",
                registered_at_stage="helper_pid_available",
                run_id=context.run_id,
            )

    return stimulate_ui, register_frida_started


def _register_owned_target(
    context: AnalysisRunContext,
    device_context: DeviceContext,
    package_name: str,
    ownership_registry: ResourceOwnershipRegistry | None,
) -> Any:
    """Return the runtime-target registrar for the real Frida path."""

    def register_runtime_target(
        pid: int,
        *,
        ownership_source: str,
        created_by_run: bool,
    ) -> None:
        if ownership_registry is None or pid <= 0:
            return
        detail = {
            "pid": pid,
            "device_id": device_context.serial,
            "expected_command_token": package_name,
            "preexisting": not created_by_run,
            "created_by_run": created_by_run,
            "cleanup_required": created_by_run,
            "verification_required": created_by_run,
            "ownership_source": ownership_source,
            "registered_at_stage": "target_pid_available",
            "run_id": context.run_id,
        }
        if created_by_run:
            ownership_registry.mark_owned("app_process", str(pid), **detail)
        else:
            ownership_registry.mark_external("app_process", str(pid), **detail)

    return register_runtime_target


def _build_dynamic_sessions(
    req: DynamicAnalyzeRequest,
    context: AnalysisRunContext,
    steps: list[StepResult],
    device_context: DeviceContext | None,
    package_name: str,
    *,
    ownership_registry: ResourceOwnershipRegistry | None,
    frida_session_factory: Any = None,
    mitm_session_factory: Any = None,
    diagnostics_service: Any = None,
    container: Container | None = None,
) -> tuple[
    Any,
    Any,
    dict[str, Any] | None,
    Any,
    Any,
]:
    """Create the Frida/MITM session objects and their collection callbacks."""
    if device_context is None:
        return None, None, None, None, None

    script_path = resolve_frida_hook_script()
    frida_session, frida_diagnostic_payload, register_runtime_target = _build_real_frida_session(
        req,
        context,
        steps,
        device_context,
        package_name,
        script_path,
        ownership_registry,
        _noop_register_runtime_target,
        frida_session_factory=frida_session_factory,
        diagnostics_service=diagnostics_service,
        container=container,
    )
    mitm_session: Any = None
    if req.enable_traffic:
        from app.traffic.mitm_session import MitmSession

        mitm_factory = mitm_session_factory or MitmSession
        mitm_session = mitm_factory(
            run_id=context.run_id,
            device=device_context,
            traffic_dir=context.traffic_dir,
            listen_host=MITM_LISTEN_HOST,
            device_proxy_host=MITM_DEVICE_PROXY_HOST,
            stop_timeout=MITM_STOP_TIMEOUT_SECONDS,
            package_name=package_name,
        )

    register_cleanup(frida_session.stop)
    if mitm_session is not None:
        register_cleanup(mitm_session.stop)

    stimulate_ui, register_frida_started = _make_collection_callbacks(
        context,
        device_context,
        package_name,
        ownership_registry,
        register_runtime_target,
    )
    return (
        frida_session,
        mitm_session,
        frida_diagnostic_payload,
        stimulate_ui,
        register_frida_started,
    )


__all__ = [
    "_DynamicEnvironment",
    "_build_dynamic_sessions",
    "_build_real_frida_session",
    "_install_and_select_device",
    "_is_real_frida_factory",
    "_make_collection_callbacks",
    "_make_launch_target_for_attach",
    "_noop_register_runtime_target",
    "_register_owned_target",
    "_report_frida_diagnostics",
]
