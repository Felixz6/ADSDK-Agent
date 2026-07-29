from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any, Iterable

from app.core.artifacts import atomic_write_text


def _text(value: Any) -> str:
    return "—" if value is None or value == "" else escape(str(value), quote=True)


def _risk_label(value: Any) -> str:
    return {
        "low": "低风险",
        "medium": "中风险",
        "high": "高风险",
        "critical": "严重风险",
    }.get(str(value or "").lower(), "未评估")


def _items(values: Iterable[Any], empty: str) -> str:
    rows = list(values)
    if not rows:
        return f'<p class="empty">{escape(empty)}</p>'
    return "<ul>" + "".join(f"<li>{_text(value)}</li>" for value in rows) + "</ul>"


def _kv(rows: Iterable[tuple[str, Any]]) -> str:
    return '<dl class="kv">' + "".join(
        f"<div><dt>{escape(label)}</dt><dd>{_text(value)}</dd></div>"
        for label, value in rows
    ) + "</dl>"


def _section(section_id: str, title: str, body: str) -> str:
    return f'<section id="{section_id}"><h2>{escape(title)}</h2>{body}</section>'


def _table(headers: list[str], rows: Iterable[Iterable[Any]], empty: str) -> str:
    rendered = list(rows)
    if not rendered:
        rendered = [[empty, *([""] * (len(headers) - 1))]]
    head = "".join(f"<th>{escape(item)}</th>" for item in headers)
    body = "".join(
        "<tr>" + "".join(f"<td>{_text(cell)}</td>" for cell in row) + "</tr>"
        for row in rendered
    )
    return f'<div class="table-wrap"><table><thead><tr>{head}</tr></thead><tbody>{body}</tbody></table></div>'


def render_html_report(report: dict[str, Any]) -> str:
    app = report.get("app_info") or {}
    risk = report.get("risk_summary") or {}
    snapshot = report.get("apk_snapshot") or {}
    diagnostics = report.get("diagnostics") or {}
    insight = report.get("compliance_insight") or {}
    traffic = report.get("traffic_summary") or {}
    events = report.get("dynamic_events")
    steps = report.get("steps") or []
    limitations = [str(item) for item in report.get("limitations") or []]
    execution = report.get("dynamic_execution") or {}
    evidence_quality = report.get("dynamic_evidence_quality") or {}
    process_diagnostics = report.get("process_diagnostics") or {}
    traffic_diagnostics = report.get("traffic_diagnostics") or {}
    environment_capabilities = report.get("environment_capabilities") or {}
    task_result = report.get("dynamic_task_result") or {}
    dynamic_trusted = (
        events is not None
        and report.get("collection_status") == "success"
        and not any(
            step.get("name") == "event_validation"
            and step.get("status") == "failed"
            for step in steps
        )
    )
    evidence_notice = ""
    if not dynamic_trusted:
        evidence_notice = (
            '<div class="notice warning"><strong>动态证据限制</strong>'
            "<p>未获得可信动态证据；相关规则无法评估；"
            "这不代表应用不存在对应行为。</p></div>"
        )

    categories = risk.get("category_scores") or []
    category_html = "".join(
        '<div class="bar-row">'
        f"<span>{_text(item.get('label') or item.get('category'))}</span>"
        f'<div class="bar"><i style="width:{max(0, min(100, int(item.get("score") or 0)))}%"></i></div>'
        f"<b>{_text(item.get('score'))}</b></div>"
        for item in categories
    ) or '<p class="empty">暂无风险维度评分。</p>'

    permissions = app.get("permissions") or []
    sensitive = set(app.get("sensitive_permissions") or [])
    sdks = report.get("sdks") or []
    rules: list[dict[str, Any]] = []
    for key in ("strict_dynamic_findings", "dynamic_findings"):
        rules.extend((report.get(key) or {}).get("rules") or [])
    hosts = traffic.get("top_hosts") or []
    actions = insight.get("priority_actions") or []

    sections = [
        _section(
            "summary",
            "执行摘要",
            evidence_notice
            + _kv(
                [
                    ("分析状态", report.get("status")),
                    ("风险评分", risk.get("score")),
                    ("风险等级", _risk_label(risk.get("level"))),
                    ("证据置信度", risk.get("confidence")),
                    ("识别 SDK", report.get("sdk_count")),
                    ("网络请求", traffic.get("total_requests")),
                ]
            ),
        ),
        _section(
            "application",
            "应用基本信息",
            _kv(
                [
                    ("应用名称", app.get("application_label")),
                    ("包名", app.get("package_name")),
                    ("版本名称", app.get("version_name")),
                    ("版本代码", app.get("version_code")),
                    ("APK SHA-256", report.get("apk_sha256")),
                    ("APK 文件大小", snapshot.get("snapshot_size_bytes")),
                ]
            ),
        ),
        _section(
            "scope",
            "分析范围与证据限制",
            _items(limitations, "报告未记录额外限制。") + evidence_notice,
        ),
        _section(
            "risk",
            "总体风险评分与维度分布",
            f'<div class="score">{_text(risk.get("score"))}<small>/ 100</small></div>{category_html}',
        ),
        _section(
            "permissions",
            "权限分析",
            _table(
                ["权限", "关注度"],
                ((permission, "高关注" if permission in sensitive else "普通") for permission in permissions),
                "未解析到权限。",
            ),
        ),
        _section(
            "sdks",
            "第三方 SDK 分析",
            _table(
                ["SDK", "厂商", "分类", "风险"],
                (
                    (
                        item.get("sdk_name"),
                        item.get("vendor"),
                        item.get("category"),
                        _risk_label(item.get("risk_level")),
                    )
                    for item in sdks
                ),
                "未识别到 SDK。",
            ),
        ),
        _section(
            "dynamic-quality",
            "动态可靠性：环境能力与本次采集结果",
            '<h3>环境能力</h3>'
            + _kv(
                [
                    ("Frida 通信", environment_capabilities.get("transport_available")),
                    ("进程枚举", environment_capabilities.get("process_enumeration_available")),
                    ("Attach", environment_capabilities.get("attach_available")),
                    ("Suspended spawn 创建", environment_capabilities.get("spawn_creation_available")),
                    ("恢复稳定性", environment_capabilities.get("spawn_resume_stable")),
                ]
            )
            + '<h3>本次采集结果</h3>'
            + _kv(
                [
                    ("最终执行模式", execution.get("selected_mode") or evidence_quality.get("mode") or "旧版报告未记录"),
                    ("执行策略", execution.get("policy") or "旧版报告未记录"),
                    ("进程结果", task_result.get("process_result") or process_diagnostics.get("status")),
                    ("证据等级", evidence_quality.get("level") or "待评定"),
                    ("崩溃信号", process_diagnostics.get("signal")),
                    ("崩溃码", process_diagnostics.get("signal_code")),
                    ("崩溃摘要", process_diagnostics.get("summary")),
                    ("关键组件", ", ".join(process_diagnostics.get("suspected_components") or [])),
                    ("诊断提示", process_diagnostics.get("reason_code")),
                    ("网络结局", traffic_diagnostics.get("outcome")),
                ]
            )
            + _table(
                ["执行尝试", "状态", "阶段", "进程结果", "恢复后存活(ms)"],
                (
                    (
                        item.get("mode"),
                        item.get("status"),
                        item.get("phase"),
                        item.get("process_result"),
                        item.get("post_resume_survival_ms"),
                    )
                    for item in execution.get("attempts") or []
                ),
                "旧版报告未记录尝试链。",
            )
            + _items(
                evidence_quality.get("limitations") or ["旧版报告未记录动态证据限制。"],
                "旧版报告未记录动态证据限制。",
            )
            + (
                '<details><summary>技术详情 · 完整 Native backtrace</summary><pre>'
                + _text("\n".join(process_diagnostics.get("native_frames") or []))
                + '</pre></details>'
                if process_diagnostics.get("native_frames")
                else ""
            )
            + '<div class="notice warning"><strong>证据边界</strong>'
            '<p>环境能力与单次任务结果独立；零请求仅表示本次未观察到请求；'
            'attach 与 launch_then_attach 存在启动覆盖边界；兼容性提示不等同于单一根因证明。</p></div>',
        ),
        _section(
            "dynamic",
            "动态行为与 Consent 前后对比",
            evidence_notice
            + _table(
                ["时间", "行为", "Consent"],
                (
                    (
                        item.get("timestamp_utc"),
                        item.get("api") or item.get("title"),
                        item.get("consent_state"),
                    )
                    for item in (events or [])[:200]
                ),
                "没有可信动态事件。",
            ),
        ),
        _section(
            "network",
            "网络请求分析与访问域名摘要",
            _kv(
                [
                    ("采集状态", traffic.get("status")),
                    ("采集结局", traffic.get("collector_outcome")),
                    ("覆盖度", traffic.get("coverage")),
                    ("请求总数", traffic.get("total_requests")),
                ]
            )
            + _table(
                ["域名", "次数"],
                ((item.get("host"), item.get("count")) for item in hosts),
                "没有可展示的访问域名。",
            ),
        ),
        _section(
            "rules",
            "规则评估结果",
            _table(
                ["规则", "状态", "说明"],
                (
                    (
                        rule.get("rule_id"),
                        rule.get("status"),
                        rule.get("reason") or rule.get("message"),
                    )
                    for rule in rules
                ),
                "没有可评估的规则结果。",
            ),
        ),
        _section(
            "evidence",
            "重点风险证据",
            _items(
                (
                    f"{item.get('title')}: {', '.join(item.get('evidence_refs') or [])}"
                    for item in risk.get("top_risks") or []
                ),
                "暂无重点风险证据。",
            ),
        ),
        _section(
            "actions",
            "P0 / P1 整改建议",
            _items(
                (
                    f"{item.get('priority')} · {item.get('action')}（{item.get('reason')}）"
                    for item in actions
                    if item.get("priority") in {"P0", "P1"}
                ),
                "暂无 P0/P1 整改建议。",
            ),
        ),
        _section(
            "pipeline",
            "分析步骤与完整性",
            _table(
                ["步骤", "状态", "耗时(ms)", "诊断"],
                (
                    (
                        step.get("name"),
                        step.get("status"),
                        step.get("duration_ms"),
                        step.get("error_message"),
                    )
                    for step in steps
                ),
                "没有步骤记录。",
            ),
        ),
        _section(
            "environment",
            "环境信息",
            _kv(
                [
                    ("报告版本", report.get("schema_version")),
                    ("Run ID", report.get("run_id")),
                    ("开始时间", report.get("analysis_started_at")),
                    ("总耗时(ms)", diagnostics.get("total_duration_ms")),
                    ("动态验收等级", report.get("dynamic_validation_level")),
                ]
            ),
        ),
        _section(
            "disclaimer",
            "免责声明",
            "<p>本报告反映指定样本、配置与采集窗口内获得的证据。"
            "缺少观测不等同于行为不存在；结论应结合人工复核与业务场景使用。</p>",
        ),
    ]
    nav = "".join(
        f'<a href="#{section_id}">{label}</a>'
        for section_id, label in [
            ("summary", "摘要"),
            ("application", "应用"),
            ("risk", "风险"),
            ("permissions", "权限"),
            ("sdks", "SDK"),
            ("dynamic", "动态"),
            ("dynamic-quality", "证据质量"),
            ("network", "网络"),
            ("rules", "规则"),
            ("actions", "整改"),
            ("pipeline", "完整性"),
        ]
    )
    return f"""<!doctype html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>AdSDK Agent 报告 · {_text(app.get("package_name") or report.get("run_id"))}</title>
<style>
:root{{--ink:#17223b;--muted:#62708d;--blue:#1479a8;--purple:#684db5;--danger:#b83b52;--line:#dce4f0;--paper:#fff;--soft:#f4f8fc}}
*{{box-sizing:border-box}}html{{scroll-behavior:smooth}}body{{margin:0;background:#eef3f9;color:var(--ink);font:14px/1.6 "Inter","Noto Sans SC","Microsoft YaHei",sans-serif}}
.cover{{min-height:72vh;padding:72px max(7vw,32px);display:flex;flex-direction:column;justify-content:center;color:white;background:linear-gradient(135deg,#071b36,#14385a 60%,#422f72)}}.cover .eyebrow{{letter-spacing:.18em;color:#9de4ff;text-transform:uppercase}}h1{{font-size:clamp(34px,6vw,68px);line-height:1.08;margin:.25em 0}}.cover p{{max-width:740px;color:#d8e7f8}}.meta{{margin-top:40px;max-width:900px}}
nav{{position:sticky;top:0;z-index:2;padding:12px max(5vw,24px);display:flex;gap:18px;overflow:auto;background:rgba(255,255,255,.94);border-bottom:1px solid var(--line);backdrop-filter:blur(12px)}}nav a{{color:var(--blue);text-decoration:none;white-space:nowrap}}
main{{width:min(1120px,calc(100% - 32px));margin:28px auto 64px}}section{{background:var(--paper);border:1px solid var(--line);border-radius:16px;padding:24px;margin:16px 0;box-shadow:0 10px 30px rgba(31,54,91,.07);break-inside:avoid}}h2{{margin:0 0 18px;font-size:20px;color:#142b4b}}.kv{{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1px;background:var(--line)}}.kv div{{padding:11px 13px;background:white}}dt{{font-size:12px;color:var(--muted)}}dd{{margin:2px 0 0;word-break:break-word}}.score{{font-size:52px;font-weight:750;color:var(--purple)}}.score small{{font-size:14px;color:var(--muted)}}.bar-row{{display:grid;grid-template-columns:150px 1fr 42px;gap:10px;align-items:center;margin:9px 0}}.bar{{height:8px;border-radius:99px;background:#e7edf6;overflow:hidden}}.bar i{{display:block;height:100%;background:linear-gradient(90deg,var(--blue),var(--purple))}}
.table-wrap{{overflow:auto}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px 12px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{font-size:12px;color:var(--muted);background:var(--soft)}}.notice{{padding:14px 16px;border-radius:10px;margin:10px 0 18px}}.notice.warning{{border:1px solid #e6be71;background:#fff8e8;color:#60471b}}.notice p{{margin:4px 0 0}}.empty{{color:var(--muted)}}
@media(max-width:720px){{.kv{{grid-template-columns:1fr}}section{{padding:18px}}.bar-row{{grid-template-columns:110px 1fr 34px}}}}
@media print{{@page{{size:A4;margin:16mm}}body{{background:white;font-size:10.5pt}}.cover{{min-height:245mm;page-break-after:always;-webkit-print-color-adjust:exact;print-color-adjust:exact}}nav{{display:none}}main{{width:auto;margin:0}}section{{box-shadow:none;border-radius:0;border:0;border-bottom:1px solid var(--line);padding:10mm 0;margin:0;page-break-inside:avoid}}table{{font-size:9pt}}a{{color:inherit;text-decoration:none}}}}
</style></head><body>
<header class="cover"><span class="eyebrow">AdSDK Agent · Professional Audit Report</span>
<h1>Android APK<br>隐私与合规分析报告</h1>
<p>结构化静态分析、动态证据、网络观测和确定性规则评估。</p>
<div class="meta">{_kv([("应用", app.get("application_label")), ("包名", app.get("package_name")), ("版本", app.get("version_name")), ("Run ID", report.get("run_id"))])}</div>
</header><nav>{nav}</nav><main>{''.join(sections)}</main></body></html>"""


def write_html_report(report: dict[str, Any], output_path: str | Path) -> Path:
    path = Path(output_path)
    atomic_write_text(path, render_html_report(report))
    return path
