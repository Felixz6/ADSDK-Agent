"""Baseline byte-for-byte snapshot tests for report rendering."""

from __future__ import annotations

from pathlib import Path

from app.reporting.html_report import render_html_report
from app.reporting.report_writer import write_markdown_report


def _sample_report() -> dict:
    return {
        "status": "success",
        "app_info": {
            "app_name": "DemoApp",
            "package_name": "com.example.demo",
            "version_name": "1.0.0",
            "version_code": "1",
            "permissions": ["android.permission.INTERNET"],
            "declared_permissions": ["android.permission.INTERNET"],
            "custom_permissions": [],
            "component_permissions": [],
            "sensitive_permissions": [],
            "high_attention_permissions": [],
        },
        "sdks": [
            {
                "sdk_name": "Pangle",
                "category": "Ad",
                "package_pattern": "com.bytedance",
                "confidence": 0.95,
            }
        ],
        "risk_summary": {
            "score": 45,
            "level": "medium",
            "factors": ["pre_consent_sensitive_access"],
        },
        "compliance_insight": {
            "summary": "Observational compliance summary.",
            "recommendations": ["Ensure user consent before accessing device ID."],
        },
        "traffic_summary": {
            "status": "success",
            "total_requests": 3,
            "top_hosts": [{"host": "api.example.com", "count": 3}],
        },
        "dynamic_events": [
            {
                "api": "Settings.Secure.getString",
                "consent_state": "pre_consent",
                "timestamp": "2026-03-13T10:00:00Z",
                "result": "redacted:abc",
            }
        ],
        "steps": [
            {"name": "apk_unpack", "status": "success", "duration_ms": 120},
            {"name": "frida_diagnostics", "status": "success", "duration_ms": 85},
        ],
        "limitations": ["Limited observation window."],
    }


def test_html_and_markdown_render_snapshot(tmp_path: Path):
    report = _sample_report()
    md_out = tmp_path / "report.md"
    write_markdown_report(report, str(md_out))
    html_out = render_html_report(report)

    assert md_out.is_file()
    assert len(md_out.read_text(encoding="utf-8")) > 500
    assert len(html_out) > 1000
    assert "<!doctype html>" in html_out
    assert "# Android 广告 SDK 分析报告" in md_out.read_text(encoding="utf-8")
