"""Pipeline tools abstraction for deterministic execution and test injection."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol

from app.core.apk_unpack import unpack_apk
from app.core.device import DeviceContext
from app.core.manifest_parser import parse_manifest_info
from app.core.sdk_fingerprint import scan_for_sdks
from app.frida.hook_parser import parse_hook_to_events_json
from app.frida.logcat_collector import LogcatCollector
from app.orchestration.dynamic_collection import (
    DynamicCollectionConfig,
    DynamicCollectionResult,
    run_dynamic_collection,
)
from app.orchestration.timeline_rules import evaluate_timeline_rules
from app.reporting.report_writer import write_markdown_report
from app.tools.adb_runner import (
    install_apk,
    launch_app,
    select_device_context,
)
from app.tools.utils import run_cmd


class UnpackApkFn(Protocol):
    def __call__(self, apk_path: str, out_dir: str) -> dict[str, Any]: ...


class ParseManifestInfoFn(Protocol):
    def __call__(self, unpack_dir: str, *, apk_filename: str | None = None) -> dict[str, Any]: ...


class ScanForSdksFn(Protocol):
    def __call__(self, unpack_dir: str) -> list[dict[str, Any]]: ...


class SelectDeviceContextFn(Protocol):
    def __call__(self, device_id: str | None = None) -> DeviceContext: ...


class InstallApkFn(Protocol):
    def __call__(
        self, apk_path: str, device_context: DeviceContext | None = None
    ) -> dict[str, Any]: ...


class LaunchAppFn(Protocol):
    def __call__(
        self, package_name: str, device_context: DeviceContext | None = None
    ) -> dict[str, Any]: ...


class RunCmdFn(Protocol):
    def __call__(
        self, cmd: list[str], cwd: str | None = None, timeout: int = ...
    ) -> dict[str, Any]: ...


class RunDynamicCollectionFn(Protocol):
    def __call__(
        self,
        *,
        frida_session: Any,
        mitm_session: Any | None,
        config: DynamicCollectionConfig,
        emit_control_event: Callable[[dict[str, Any]], Any],
        clock: Any | None = None,
        stimulate_ui: Callable[[], Any] | None = None,
        resume_without_frida: Callable[[], Any] | None = None,
        on_frida_started: Callable[[Any], None] | None = None,
    ) -> DynamicCollectionResult: ...


class ParseHookToEventsJsonFn(Protocol):
    def __call__(
        self,
        log_path: str,
        output_path: str,
        *,
        sensitive_identifiers: dict[str, str] | None = None,
    ) -> list[dict[str, Any]]: ...


class EvaluateTimelineRulesFn(Protocol):
    def __call__(
        self,
        events_json_path: str,
        consent_time: str | None,
        pre_consent_seconds: int = 10,
        post_consent_seconds: int = 10,
        evidence_available: bool = True,
    ) -> dict[str, Any]: ...


class WriteMarkdownReportFn(Protocol):
    def __call__(self, report: dict[str, Any], report_path: str) -> None: ...


@dataclass(slots=True)
class PipelineTools:
    """Explicit collection of external system tools and side-effecting operations."""

    # 静态分析阶段工具
    unpack_apk: UnpackApkFn = unpack_apk
    scan_for_sdks: ScanForSdksFn = scan_for_sdks
    parse_manifest_info: ParseManifestInfoFn = parse_manifest_info

    # 设备与 ADB 工具
    select_device_context: SelectDeviceContextFn = select_device_context
    install_apk: InstallApkFn = install_apk
    launch_app: LaunchAppFn = launch_app
    run_cmd: RunCmdFn = run_cmd

    # 动态分析与时间轴判定
    run_dynamic_collection: RunDynamicCollectionFn = run_dynamic_collection
    parse_hook_to_events_json: ParseHookToEventsJsonFn = parse_hook_to_events_json
    evaluate_timeline_rules: EvaluateTimelineRulesFn = evaluate_timeline_rules
    logcat_collector_factory: Callable[..., Any] = LogcatCollector

    # 报告落盘与时钟休眠
    write_markdown_report: WriteMarkdownReportFn = write_markdown_report
    sleep: Callable[[float], None] = time.sleep


__all__ = [
    "EvaluateTimelineRulesFn",
    "InstallApkFn",
    "LaunchAppFn",
    "ParseHookToEventsJsonFn",
    "ParseManifestInfoFn",
    "PipelineTools",
    "RunCmdFn",
    "RunDynamicCollectionFn",
    "ScanForSdksFn",
    "SelectDeviceContextFn",
    "UnpackApkFn",
    "WriteMarkdownReportFn",
]
