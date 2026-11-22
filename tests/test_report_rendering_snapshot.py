"""Baseline byte-for-byte golden snapshot tests for report rendering."""

from __future__ import annotations

import difflib
import os
from pathlib import Path

import pytest

from app.reporting.html_report import render_html_report
from app.reporting.report_writer import write_markdown_report

GOLDEN_DIR = Path(__file__).parent / "golden"


def _full_report() -> dict:
    return {
        "status": "success",
        "app_info": {
            "app_name": 'Demo & Test <App> "Special"',
            "package_name": "com.example.special.demo",
            "version_name": "1.2.3-alpha",
            "version_code": "10203",
            "permissions": [
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.READ_PHONE_STATE",
            ],
            "declared_permissions": [
                "android.permission.INTERNET",
                "android.permission.ACCESS_FINE_LOCATION",
            ],
            "custom_permissions": ["com.example.CUSTOM_PERM"],
            "component_permissions": ["android.permission.BIND_DEVICE_ADMIN"],
            "sensitive_permissions": ["android.permission.ACCESS_FINE_LOCATION"],
            "high_attention_permissions": ["android.permission.READ_PHONE_STATE"],
        },
        "sdks": [
            {
                "sdk_name": "Pangle",
                "category": "Ad",
                "package_pattern": "com.bytedance",
                "confidence": 0.95,
            },
            {
                "sdk_name": "Tencent Ads",
                "category": "Ad",
                "package_pattern": "com.qq.e",
                "confidence": 0.88,
            },
        ],
        "risk_summary": {
            "score": 68,
            "level": "high",
            "factors": ["pre_consent_sensitive_access", "unencrypted_traffic"],
        },
        "compliance_insight": {
            "summary": "Observation: Sensitive identifier accessed prior to user consent gate.",
            "recommendations": [
                "Ensure privacy pop-up explicitly covers advertising SDKs.",
                "Delay SDK initialization until consent is granted.",
            ],
        },
        "traffic_summary": {
            "status": "success",
            "total_requests": 3,
            "top_hosts": [
                {"host": "api.example.com", "count": 2},
                {"host": "adservice.invalid", "count": 1},
            ],
            "sample_requests": [
                {"method": "GET", "url": "https://api.example.com/v1/init", "status_code": 200},
            ],
        },
        "dynamic_events": [
            {
                "api": "Settings.Secure.getString",
                "arg": "android_id",
                "consent_state": "pre_consent",
                "timestamp": "2026-03-13T10:00:00.100Z",
                "result": "redacted:abc123",
            },
            {
                "api": "TelephonyManager.getDeviceId",
                "arg": None,
                "consent_state": "post_consent",
                "timestamp": "2026-03-13T10:00:05.200Z",
                "result": "redacted:imei456",
            },
            {
                "api": "ClipboardManager.getPrimaryClip",
                "arg": None,
                "consent_state": "unknown",
                "timestamp": "2026-03-13T10:00:09.300Z",
                "result": "called",
            },
        ],
        "ai_orchestration": {
            "status": "completed",
            "report_source": "ai",
            "model": "deepseek-chat",
            "token_usage": {"input_tokens": 1200, "output_tokens": 350},
            "executive_summary": "AI 合规研判：该应用在同意前即读取了设备硬件标识。",
            "key_findings": [
                {
                    "title": "同意前调用 android_id",
                    "severity": "high",
                    "description": "SDK 在未获取用户授权前读取了硬件标识符。",
                }
            ],
        },
        "evidence_correlation": {
            "status": "evaluated",
            "window_ms": 2500,
            "summary": {
                "dynamic_event_count": 3,
                "network_request_count": 3,
                "correlated_pair_count": 2,
            },
            "items": [
                {
                    "correlation_id": "corr-1",
                    "dynamic_event_id": "evt-1",
                    "request_id": "req-1",
                    "delta_ms": 120,
                    "confidence": "high",
                }
            ],
        },
        "privacy_findings": {
            "schema_version": "privacy-findings-v2",
            "status": "evaluated",
            "summary": {
                "total_findings": 1,
                "grade": "C",
            },
            "findings": [
                {
                    "finding_id": "find-1",
                    "rule_id": "pre_consent_device_id",
                    "category": "device_identifier",
                    "severity": "high",
                    "confidence": "high",
                    "status": "observed",
                    "title": "同意前读取设备标识符",
                    "narrative": "观测到在用户授权同意前读取了硬件序列号。",
                }
            ],
        },
        "steps": [
            {"name": "apk_unpack", "status": "success", "duration_ms": 120},
            {"name": "frida_diagnostics", "status": "success", "duration_ms": 85},
            {"name": "dynamic_collection", "status": "success", "duration_ms": 5200},
        ],
        "limitations": [
            "动态分析受限于预设自动化刺激脚本覆盖度。",
            "无法解密使用非标准加固证书的双向证书绑定通信。",
        ],
    }


def _minimal_report() -> dict:
    return {
        "status": "partial",
        "app_info": {
            "app_name": "Minimal",
            "package_name": "com.example.minimal",
            "version_name": "0.1",
            "version_code": "1",
        },
        "sdks": [],
        "dynamic_events": None,
        "traffic_summary": {},
        "risk_summary": {"score": 0, "level": "low", "factors": []},
        "steps": [],
        "limitations": [],
    }


def _assert_golden_match(actual: str, golden_file: Path):
    if os.getenv("UPDATE_GOLDEN") == "1":
        golden_file.parent.mkdir(parents=True, exist_ok=True)
        golden_file.write_text(actual, encoding="utf-8")
        return

    if not golden_file.is_file():
        pytest.fail(
            f"golden file missing: {golden_file}. Run with UPDATE_GOLDEN=1 to generate golden baseline."
        )

    expected = golden_file.read_text(encoding="utf-8")
    if actual != expected:
        diff = list(
            difflib.unified_diff(
                expected.splitlines(keepends=True),
                actual.splitlines(keepends=True),
                fromfile=f"golden:{golden_file.name}",
                tofile="actual",
                n=3,
            )
        )
        diff_preview = "".join(diff[:50])
        pytest.fail(
            f"Byte-for-byte golden mismatch in {golden_file.name}!\n"
            f"Diff preview (first 50 lines):\n{diff_preview}"
        )


def test_golden_report_full_html():
    report = _full_report()
    actual = render_html_report(report)
    golden_path = GOLDEN_DIR / "report_full.html"
    _assert_golden_match(actual, golden_path)


def test_golden_report_full_markdown(tmp_path: Path):
    report = _full_report()
    out = tmp_path / "actual.md"
    write_markdown_report(report, str(out))
    actual = out.read_text(encoding="utf-8")
    golden_path = GOLDEN_DIR / "report_full.md"
    _assert_golden_match(actual, golden_path)


def test_golden_report_minimal_html():
    report = _minimal_report()
    actual = render_html_report(report)
    golden_path = GOLDEN_DIR / "report_minimal.html"
    _assert_golden_match(actual, golden_path)


def test_golden_report_minimal_markdown(tmp_path: Path):
    report = _minimal_report()
    out = tmp_path / "actual.md"
    write_markdown_report(report, str(out))
    actual = out.read_text(encoding="utf-8")
    golden_path = GOLDEN_DIR / "report_minimal.md"
    _assert_golden_match(actual, golden_path)


def test_all_golden_files_exist_and_non_empty():
    """Verify all 4 golden files exist and contain non-trivial baseline content."""
    expected_files = [
        "report_full.html",
        "report_full.md",
        "report_minimal.html",
        "report_minimal.md",
    ]
    for filename in expected_files:
        golden_path = GOLDEN_DIR / filename
        assert golden_path.is_file(), f"golden file missing: {filename}"
        assert golden_path.stat().st_size > 0, f"golden file is empty: {filename}"
