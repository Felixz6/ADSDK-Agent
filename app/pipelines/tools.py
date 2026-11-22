"""Pipeline tools abstraction for deterministic execution and test injection."""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from app.core.apk_unpack import unpack_apk
from app.core.manifest_parser import parse_manifest_info
from app.core.sdk_fingerprint import scan_for_sdks
from app.frida.hook_parser import parse_hook_to_events_json
from app.frida.logcat_collector import LogcatCollector
from app.orchestration.dynamic_collection import run_dynamic_collection
from app.orchestration.timeline_rules import evaluate_timeline_rules
from app.reporting.report_writer import write_markdown_report
from app.tools.adb_runner import (
    install_apk,
    launch_app,
    select_device_context,
)
from app.tools.utils import run_cmd


@dataclass(slots=True)
class PipelineTools:
    """Explicit collection of external system tools and side-effecting operations."""

    # 静态分析阶段工具
    unpack_apk: Callable[..., Any] = unpack_apk
    scan_for_sdks: Callable[..., Any] = scan_for_sdks
    parse_manifest_info: Callable[..., Any] = parse_manifest_info

    # 设备与 ADB 工具
    select_device_context: Callable[..., Any] = select_device_context
    install_apk: Callable[..., Any] = install_apk
    launch_app: Callable[..., Any] = launch_app
    run_cmd: Callable[..., Any] = run_cmd

    # 动态分析与时间轴判定
    run_dynamic_collection: Callable[..., Any] = run_dynamic_collection
    parse_hook_to_events_json: Callable[..., Any] = parse_hook_to_events_json
    evaluate_timeline_rules: Callable[..., Any] = evaluate_timeline_rules
    logcat_collector_factory: Callable[..., Any] = LogcatCollector

    # 报告落盘与时钟休眠
    write_markdown_report: Callable[..., Any] = write_markdown_report
    sleep: Callable[[float], None] = time.sleep


__all__ = ["PipelineTools"]
