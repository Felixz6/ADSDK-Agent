from app.core.artifacts import atomic_write_json, atomic_write_text


def _md_cell(value) -> str:
    if value is None:
        return ""
    text = str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def write_json_report(report: dict, report_path: str):
    atomic_write_json(report_path, report)


def write_markdown_report(report: dict, report_path: str):
    app_info = report.get("app_info", {}) or {}
    sdks = report.get("sdks", []) or []
    dynamic_findings = report.get("dynamic_findings", {}) or {}
    dynamic_rules = dynamic_findings.get("rules", []) if isinstance(dynamic_findings, dict) else []
    strict_dynamic_findings = report.get("strict_dynamic_findings", {}) or {}
    strict_rules = strict_dynamic_findings.get("rules", []) if isinstance(strict_dynamic_findings, dict) else []
    dynamic_events = report.get("dynamic_events", []) or []
    traffic_summary = report.get("traffic_summary", {}) or {}
    consent_time = report.get("consent_time")
    pre_consent_seconds = report.get("pre_consent_seconds")
    post_consent_seconds = report.get("post_consent_seconds")

    lines = []
    lines.append("# Android 广告 SDK 分析报告")
    lines.append("")
    lines.append("## 执行摘要")
    lines.append("")
    lines.append(f"- schema_version: `{_md_cell(report.get('schema_version'))}`")
    lines.append(f"- run_id: `{_md_cell(report.get('run_id'))}`")
    lines.append(f"- status: `{_md_cell(report.get('status'))}`")
    lines.append(f"- analysis_started_at: `{_md_cell(report.get('analysis_started_at'))}`")
    lines.append(f"- apk_sha256: `{_md_cell(report.get('apk_sha256'))}`")
    snapshot = report.get("apk_snapshot") or {}
    if snapshot:
        lines.append(
            "- apk_snapshot: "
            f"`{_md_cell(snapshot.get('snapshot_relative_path'))}`"
        )
    lines.append(f"- normalized_apk_name: `{_md_cell(report.get('normalized_apk_name'))}`")
    device = report.get("device") or {}
    if device:
        lines.append(f"- device_token: `{_md_cell(device.get('serial_token'))}`")
    warnings = report.get("warnings") or []
    if warnings:
        lines.append("")
        lines.append("### 警告")
        lines.append("")
        for warning in warnings:
            lines.append(f"- {_md_cell(warning)}")

    steps = report.get("steps") or []
    if steps:
        lines.append("")
        lines.append("### 分析步骤")
        lines.append("")
        lines.append("| name | status | duration_ms | error |")
        lines.append("|---|---|---:|---|")
        for step in steps:
            error = step.get("error_message") or "; ".join(step.get("warnings") or [])
            lines.append(
                f"| {_md_cell(step.get('name'))} | {_md_cell(step.get('status'))} | "
                f"{_md_cell(step.get('duration_ms'))} | {_md_cell(error)} |"
            )

    lines.append("")
    lines.append("## 基本信息")
    lines.append("")
    lines.append(f"- APK 路径: `{report.get('apk_path', '')}`")
    lines.append(f"- 包名: `{app_info.get('package_name')}`")
    lines.append(f"- 版本名: `{app_info.get('version_name')}`")
    lines.append(f"- 版本号: `{app_info.get('version_code')}`")
    lines.append(f"- 应用名: `{app_info.get('application_label')}`")
    lines.append("")
    lines.append("## SDK 识别结果")
    lines.append("")
    lines.append("| SDK | 包名 | 置信度 | 版本 |")
    lines.append("|---|---|---:|---|")

    if sdks:
        for sdk in sdks:
            lines.append(
                f"| {sdk.get('sdk_name')} | {sdk.get('package')} | {sdk.get('confidence')} | {sdk.get('version') or ''} |"
            )
    else:
        lines.append("| 未识别 | - | - | - |")

    if dynamic_findings:
        lines.append("")
        lines.append("## 动态规则判定")
        lines.append("")
        lines.append("| rule_id | status | details |")
        lines.append("|---|---|---|")
        if dynamic_rules:
            for rule in dynamic_rules:
                detail_items = []
                for key, value in rule.items():
                    if key in {"rule_id", "status"}:
                        continue
                    detail_items.append(f"{key}={value}")
                details = "; ".join(detail_items) if detail_items else "-"
                rule_status = rule.get("evaluation_status") or rule.get("status")
                lines.append(f"| {_md_cell(rule.get('rule_id'))} | {_md_cell(rule_status)} | {_md_cell(details)} |")
        else:
            lines.append("| - | - | - |")

    lines.append("")
    lines.append("## 同意前/同意后分析窗口说明")
    lines.append("")
    lines.append(f"- consent_time: `{_md_cell(consent_time)}`")
    lines.append(f"- pre_consent_seconds: `{_md_cell(pre_consent_seconds)}`")
    lines.append(f"- post_consent_seconds: `{_md_cell(post_consent_seconds)}`")

    if strict_dynamic_findings:
        lines.append("")
        lines.append("## 严格版动态规则结果")
        lines.append("")
        lines.append("| rule_id | status | details |")
        lines.append("|---|---|---|")
        if strict_rules:
            for rule in strict_rules:
                detail_items = []
                for key, value in rule.items():
                    if key in {"rule_id", "status"}:
                        continue
                    detail_items.append(f"{key}={value}")
                details = "; ".join(detail_items) if detail_items else "-"
                rule_status = rule.get("evaluation_status") or rule.get("status")
                lines.append(f"| {_md_cell(rule.get('rule_id'))} | {_md_cell(rule_status)} | {_md_cell(details)} |")
        else:
            lines.append("| - | - | - |")

    if dynamic_events:
        lines.append("")
        lines.append("## 动态事件时间线")
        lines.append("")
        lines.append("| # | timestamp_utc | type | action/event | api | consent_state |")
        lines.append("|---:|---|---|---|---|---|")
        for idx, event in enumerate(dynamic_events[:20], start=1):
            lines.append(
                f"| {idx} | {_md_cell(event.get('timestamp_utc') or event.get('timestamp'))} | "
                f"{_md_cell(event.get('type') or event.get('event_type'))} | "
                f"{_md_cell(event.get('action') or event.get('event'))} | "
                f"{_md_cell(event.get('api'))} | {_md_cell(event.get('consent_state'))} |"
            )

    lines.append("")
    lines.append("## 网络外发摘要")
    lines.append("")
    lines.append(f"- collection_status: `{_md_cell(traffic_summary.get('status'))}`")
    lines.append(f"- evaluation_status: `{_md_cell(traffic_summary.get('evaluation_status'))}`")
    lines.append(f"- total_requests: `{_md_cell(traffic_summary.get('total_requests'))}`")
    top_hosts = traffic_summary.get("top_hosts", []) or []
    if top_hosts:
        lines.append("")
        lines.append("| host | count |")
        lines.append("|---|---:|")
        for item in top_hosts[:20]:
            lines.append(f"| {_md_cell(item.get('host'))} | {_md_cell(item.get('count'))} |")

    lines.append("")
    lines.append("## 结论")
    lines.append("")
    lines.append(f"- 共识别到 `{report.get('sdk_count', 0)}` 个疑似广告/商业化 SDK")
    lines.append(f"- 本次分析状态：`{_md_cell(report.get('status'))}`")
    if report.get("status") != "success":
        lines.append("- 本次结果包含缺失或失败步骤，请结合警告与原始证据人工复核")
    lines.append("")

    atomic_write_text(report_path, "\n".join(lines))
