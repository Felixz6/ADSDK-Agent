# 计划废弃与兼容项清单 (Deprecations)

本文档追踪并标准化 ADSDK-Agent 代码库中计划在 `v0.4.0` 移除的兼容别名、遗留产物读取器与过渡逻辑。

---

## 1. 废弃项汇总表

| 序号 | 所在文件路径 | 行号位置 | 废弃符号 / 特性 | 替代方案 (推荐做法) | 计划移除版本 | 移除前需确认的事项 |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| 1 | `app/config.py` | 248 | `M7A_LEASE_STALE_SECONDS` 别名 | `DEVICE_LEASE_STALE_SECONDS` | `v0.4.0` | 确认外部启动脚本与 CI 环境变量均已迁移为新环境变量名 |
| 2 | `app/config.py` | 256 | `M7A_CONSENT_WAIT_SECONDS` 别名 | `CONSENT_CHECKPOINT_WAIT_SECONDS` | `v0.4.0` | 确认外部启动脚本与 CI 环境变量均已迁移为新环境变量名 |
| 3 | `app/frida/hook_parser.py` | 5, 209 | `read_legacy_hook_log` 及非结构化 hook.log 解析 | `parse_hook_to_events_json` (读取 JSONL 格式) | `v0.4.0` | 确认历史运行任务产物已完全完成结构化迁移或不再直接复用旧纯文本日志 |
| 4 | `app/traffic/traffic_parser.py` | 5, 162 | `read_legacy_traffic_log` 及纯文本流量日志读取 | `validate_traffic` / `requests.jsonl` | `v0.4.0` | 确认下游分析工具与报表均直接读取结构化 `requests.jsonl` |
| 5 | `app/orchestration/full_analysis_session.py` | 256 | `_validate_plan = _validate_session_plan_constraints` | `_validate_session_plan_constraints` | `v0.4.0` | 确认单元测试中无直接从私有模块引用 `_validate_plan` |
| 6 | `app/pipelines/full_analysis.py` | 579 | `capture_device_session_snapshot = _capture_device_snapshot` | `_capture_device_snapshot` | `v0.4.0` | 确认所有流水线与测试统一使用统一的快照入口 |
| 7 | `app/pipelines/full_analysis.py` | 580 | `find_target_process_pid = _target_pid` | `_target_pid` | `v0.4.0` | 确认 PID 查找统一通过进程监控或 `_target_pid` 抽象 |
| 8 | `app/pipelines/full_analysis.py` | 581 | `check_owned_resource_present = _resource_present` | `_resource_present` | `v0.4.0` | 确认资源存活性校验统一走所有权注册表与清理检查机制 |

---

## 2. 移除策略与建议
- **保留策略**：上述 8 处兼容别名与过渡接口在当前 `v0.3.0` 阶段保持原样可用，不破坏任何旧有用例或历史产物解析。
- **推荐迁移节奏**：建议在 `v0.3.0` 发布并稳定运行一段周期后，集中在 `v0.4.0-alpha` 开展一次兼容别名清理与旧归档清理。
