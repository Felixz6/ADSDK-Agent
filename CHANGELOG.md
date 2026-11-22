# 更新日志 (Changelog)

本项目遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.0.0/) 格式，版本号遵循 [语义化版本 (SemVer)](https://semver.org/lang/zh-CN/)。

## [Unreleased] - 2026-11-22

### Added
- **显式工具抽象 (`PipelineTools`)**：新增 `app/pipelines/tools.py`，为静态解包 (`unpack_apk`)、Manifest 提取 (`parse_manifest_info`)、SDK 特征扫描 (`scan_for_sdks`)、ADB 交互 (`select_device_context`, `install_apk`, `launch_app`, `run_cmd`)、动态采集与时间轴判定定义全套强类型 `Protocol`。
- **动态阶段纯共享模块 (`_shared.py`)**：新增 `app/pipelines/dynamic/_shared.py`，集中下沉流量统计摘要与失败降级纯函数，消除 `collection` 与 `report` 间的环状依赖。
- **安全信封生命周期测试套件 (`tests/test_safety_envelope_cleanup.py`)**：新增 12 个专有测试用例，全方位断言 MITM / Frida 在启动、就绪等待、采集窗口和终止阶段异常时的清理调用顺序，以及用户取消 (`TaskCancelled`) 时的代理恢复与租约释放。
- **全分析会话特征测试套件 (`tests/test_full_analysis_session_characterization.py`)**：新增 6 个测试用例，覆盖正常产物写入、设备离线阻断、Consent 超时受限、未登记新目标审计 (`unclassified_new_target`) 与 Frida Helper 异常发现。
- **字节级金标准快照测试严格模式**：强化 `test_report_rendering_snapshot.py`，在缺少 golden 文件时禁止静默创建并强制失败，仅在显式传入 `UPDATE_GOLDEN=1` 时允许更新。
- **计划废弃清单文档 (`docs/DEPRECATIONS.md`)**：全面梳理并在文档中追踪 8 处拟于 `v0.4.0` 移除的兼容项与迁移建议。

### Changed
- **依赖注入纯化与零 IO 保证**：`Container` 数据类增加 `tools: PipelineTools`，`create_app(container=...)` 与 `build_container(settings, tools=...)` 支持全量服务与工具注入。
- **清除生产代码与测试接缝**：彻底删除 `static_stage.py` 的 `_resolve_tool`、`sessions.py` 的 `_resolve_dynamic_tool` 以及所有 `sys.modules.get(...)` 反查；将测试中全部 48 处模块属性 monkeypatch 迁移为纯容器工具注入。
- **大函数模块化阶段拆分**：
  - `run_dynamic_collection`（原 334 行）拆分为 MITM 启动、Frida 启动/回退、Hook 采集窗口、清理终止等各独立子函数，主函数精简至 52 行。
  - `run_full_analysis_session`（原 290 行）拆解为会话装配、Postflight 审计、Helper 溯源、最终报告装配等阶段函数，主函数收敛至 35 行。
  - `_run_body`（原 236 行）拆分为规划阶段、新鲜度门禁、策略语义校验、租约锁门禁、执行与 Consent 等独立子函数，主函数收敛至 54 行。
  - `_prepare_run`（原 180 行）拆分为路径校验、哈希计算、上下文创建、APK 快照等步骤函数。
  - `run_static_stage`（原 188 行）拆分为解包、Manifest 解析、SDK 扫描等独立阶段函数。
- **静态类型覆盖扩展**：将 `app/ai/providers/`、`app/ai/planner.py`、`app/ai/plan_parser.py` 纳入 `mypy` 严格校验，全项目检查文件数提升至 67 个，全局 `type: ignore` 由 21 处压降至 6 处且均标注原因。
- **包导出清洁化**：清理 `dynamic/__init__.py` 与 `common.py` 的 `__all__` 导出列表，彻底移除非公开的私有下划线方法、`time` 及 `run_cmd`。

### Removed
- 移除 `app/pipelines/task_runner.py` 中遗留的空操作测试接缝 `ai_settings_service` 与 `task_service`，以及无调用方的兼容别名 `_run_persisted_task`。
- 移除 `tests/` 中针对 `task_runner.ai_settings_service` 与 `task_runner.task_service` 的多余 monkeypatch 补丁。
