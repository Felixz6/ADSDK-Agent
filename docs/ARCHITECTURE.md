# ADSDK Agent 架构设计说明书 (Architecture Design Document)

> 本文档正式定义 ADSDK-Agent 平台的系统整体架构、核心模块划分、数据流向、真机安全信封与取证协议契约。

---

## 1. 系统总体定位与设计原则

ADSDK-Agent 是一个面向 Android APK 的本地隐私合规审计与取证分析平台。系统坚持以下核心工程准则：

1. **隐私审计留在本机 (Local-Only Execution)**：APK 解包分析、动态插桩、流量镜像与证据比对全程在本地单机闭环完成，原始文件和敏感通信绝不上云。
2. **证据先于叙述 (Determinism First)**：所有的敏感行为计数、权限分类、流量观测与规则判定全部由本地确定性引擎生成。AI 不产生原始技术事实，仅在获得白名单工具与证据摘要后进行辅助编排与合规叙述润色。
3. **单调时钟 Consent 判定 (Monotonic Clock Consent)**：系统采用基于系统启动单调时钟（Monotonic Time）的切片判定机制，严格区分 `pre_consent`（同意前违规调用）、`post_consent`（同意后正常调用）与 `unknown`（时间不明），彻底杜绝依靠不可靠界面文本主观推测授权状态的漏洞。
4. **Zero-Leak 流量最小化脱敏 (Zero-Leak Redaction)**：网络流量拦截层严格执行最小化原则，仅记录 Host 与 URL 结构，彻底剔除并阻断 Cookie、Authorization 请求头、响应正文与敏感 Payload 的持久化。
5. **真机安全信封 (Hardware Safety Envelope)**：真机分析前强制通过确认门（Confirmation Gate），通过排他租约锁定、资源所有权注册（Resource Ownership Registry）、`try/finally` 幂等清理与网络代理自动恢复机制，确保宿主设备环境与网络配置零污染。

---

## 2. 系统整体分层架构

```
+-------------------------------------------------------------------------------+
|                       Web Frontend (React 18 + Vite 6)                        |
|   Dashboard | New Analysis | Tasks | Static | Dynamic | Traffic | Reports ... |
+-------------------------------------------------------------------------------+
                                      | HTTP REST / WebSocket
+-------------------------------------------------------------------------------+
|                          FastAPI API Gateway (app/api/)                       |
|   Routers: /tasks, /analysis, /dynamic, /traffic, /ai, /env, /comparisons     |
|   Middleware: CORS, AILocalOnlyMiddleware (本机写保护)                         |
|   Dependency Injection: app/api/deps.py (FastAPI Depends)                     |
+-------------------------------------------------------------------------------+
                                      |
+-------------------------------------------------------------------------------+
|                      Service Container (app/container.py)                     |
|   Singletons: TaskService, ComparisonService, AISettingsService, ...          |
|   Injectable Factories: frida_session_factory, mitm_session_factory           |
+-------------------------------------------------------------------------------+
                                      |
+-------------------------------------------------------------------------------+
|                         Pipelines (app/pipelines/)                            |
|   static.py            dynamic.py          full_analysis.py    task_runner.py |
|   +-----------------------------------------------------------------------+   |
|   | Common Static Stage (run_static_stage) & Public Report Formatting     |   |
|   +-----------------------------------------------------------------------+   |
+-------------------------------------------------------------------------------+
         |                     |                     |                   |
+-----------------+   +-----------------+   +-----------------+   +-------------+
|    app/core/    |   |   app/frida/    |   |  app/traffic/   |   |   app/ai/   |
| APK 快照与校验  |   | FridaSession    |   | MitmSession     |   | Planner     |
| 静态解包缓存    |   | 分层环境诊断    |   | 动态端口池分配  |   | Executor    |
| Manifest 解析   |   | 服务端生命周期  |   | Zero-Leak 脱敏  |   | Narrator    |
| SDK 指纹识别    |   | 事件流解析      |   | TrafficEvents   |   | Providers   |
| HMAC 稳定脱敏   |   | Native Bridge   |   | 请求抽屉适配    |   | 缓存与白名单|
+-----------------+   +-----------------+   +-----------------+   +-------------+
         \                     |                     /                   /
+-------------------------------------------------------------------------------+
|                   Orchestration & Safety (app/orchestration/)                 |
|   Device Lease Registry | Consent Checkpoint | Resource Ownership Registry    |
|   Device Ops Helpers    | Full Analysis Session State Machine                 |
+-------------------------------------------------------------------------------+
                                      |
+-------------------------------------------------------------------------------+
|                      Analyzers & Evidence Correlation                         |
|   app/analyzers/evidence_correlation.py  (时间接近双向窗口关联)               |
|   app/analyzers/privacy_findings.py      (observed / suspected / gap 规则判定)|
|   app/reporting/report_writer.py         (JSON / Markdown / HTML 报告组装)    |
+-------------------------------------------------------------------------------+
                                      |
+-------------------------------------------------------------------------------+
|                    Persistence & Storage (output/ & SQLite)                   |
|   SQLite DB: output/state/adsdk-agent.db (WAL 模式任务记录与步骤推进)         |
|   Run Directory: output/runs/<run_id>/ (自包含不可变证据包)                   |
+-------------------------------------------------------------------------------+
```

### 2.1 容器组装与应用生命周期初始化时序

系统严格区分**对象构造**与**I/O 初始化**，彻底杜绝模块导入期产生副作用：

1. **容器构造 (`build_container`)**：
   - 纯内存对象实例化与依赖装配（`TaskRepository`, `TaskService`, `ComparisonService`, `AISettingsService`, `LeaseRegistry` 等），**不做任何文件读写或数据库连接 I/O**。
   - 统一注入 `task_service.set_runner(run_persisted_task)`。
   - 实例化对象存入 `app.state.container`，所有接口依赖提供者（`app/api/deps.py`）均通过 `request.app.state.container` 动态解析。

2. **应用生命周期 (`lifespan`) 阶段执行顺序**：
   - `task_repository.initialize()`：连接 SQLite 并创建表结构、索引与约束迁移。
   - `repair_historical_application_names(...)`：检查并修复历史任务中缺失或资源引用形式的应用名称。
   - `task_service.recover()`：将服务中断前处于 `queued` 或 `running` 的遗留任务标记为 `failed`（一次启动过程仅执行一次）。
   - `yield` 运行服务。
   - 退出清理：`task_service.shutdown()` 优雅关闭后台线程池。

3. **测试夹具与依赖覆盖 (Fake Session Factory 注入)**：
   - **独立数据隔离**：测试推荐使用 `tests/conftest.py` 提供的 `make_test_app(tmp_path)`，使用基于临时目录的独立 SQLite 路径。
   - **依赖替换**：测试如需替换探针与抓包会话，使用 FastAPI 原生机制 `app.dependency_overrides`：
     ```python
     from app.api.deps import get_frida_session_factory, get_mitm_session_factory
     app.dependency_overrides[get_frida_session_factory] = lambda: FakeTestFridaSession
     app.dependency_overrides[get_mitm_session_factory] = lambda: FakeTestMitmSession
     ```
   - 全局 autouse fixture 会在每个用例结束后自动执行 `app.dependency_overrides.clear()`，杜绝跨用例污染。

4. **报告与诊断持久化契约字面量说明**：
   - 动态执行报告中的 `executor_strategy_receipt.executor_provenance_source` 用于记录执行策略决策归属。历史版本曾记录为 `app.main._dynamic_analyze_v2.execution_decision`，现版本统一标准化为 `app.pipelines.dynamic.execution_decision`，两者代表相同的执行语义。
   - `FullAnalysisAcceptance.schema_version` 固定为 `"m7a-acceptance-v1"`（历史契约字面量，锁定已落盘产物兼容性）。
   - `AIRuntimeDiagnostic.execution_pipeline_version` 固定为 `"m7b"`（历史契约字面量，供前端与下游分析套件比对流水线版本，勿随重构重命名）。

---

## 3. 核心领域模块职责

| 模块路径 | 职责定位 | 核心类与导出项 |
| :--- | :--- | :--- |
| `app/main.py` | 应用入口与生命周期胶水 (74 行精简入口) | `create_app()`, `lifespan` |
| `app/container.py` | 依赖容器与会话工厂 | `task_service`, `frida_session_factory`, `mitm_session_factory` |
| `app/api/deps.py` | FastAPI `Depends` 依赖注入提供方 | `get_task_service`, `get_frida_session_factory` 等 |
| `app/api/middleware.py` | 安全中间件 | `AILocalOnlyMiddleware`（防止远程主机篡改本机 AI 设置） |
| `app/pipelines/` | 分析流水线用例层 | `run_static_stage`, `dynamic_analyze`, `run_full_analysis_session` |
| `app/core/` | 静态取证与平台级基础安全工具 | `APKPathValidator`, `ManifestParser`, `redact_serial` |
| `app/frida/` | 动态插桩执行层与受控服务管理 | `FridaSession`, `FridaServerManager`, `FridaDiagnosticsService` |
| `app/traffic/` | 网络镜像与安全脱敏 | `MitmSession`, `check_port_listening`, `write_requests_jsonl` |
| `app/orchestration/` | 真机租约、确认门与清理状态机 | `FullAnalysisSession`, `ResourceOwnershipRegistry`, `LeaseRegistry` |
| `app/analyzers/` | 确定性证据分析与规则引擎 | `build_evidence_correlations`, `build_privacy_findings` |
| `app/ai/` | 安全信封内的辅助 AI 编排 | `AIOrchestrator`, `AIPlanner`, `AIExecutor`, `AINarrator` |
| `app/reporting/` | 报告多格式渲染与导出 | `write_full_report`, `render_html_report` |
| `app/repositories/` | SQLite 数据仓储 | `TaskRepository`, `TaskRecord` |

---

## 4. 关键数据流向与时序

### 4.1 静态分析流水线 (Static Pipeline)
1. 校验目标 APK 路径（限制白名单、防止路径穿越、ZIP 格式复核）。
2. 计算 SHA-256 哈希并在 `output/runs/<run_id>/input/app.apk` 建立原子快照。
3. 查询 `output/cache/static-unpack/<SHA256>/` 解包缓存；命中直接复用，未命中调用 `apktool` 解包并缓存。
4. 解析 `AndroidManifest.xml`（包名、组件、敏感权限分类、导出安全性）。
5. 扫描 smali 代码匹配广告/分析/推送 SDK 特征指纹。
6. 输出确定性静态报告数据结构。

### 4.2 动态采集与网络代理拦截流水线 (Dynamic Pipeline)
1. 设备环境与 ADB 连接探测；分配排他设备租约。
2. 动态端口池（默认 8080~8090）中分配空闲端口并启动 `MitmSession`。
3. 设置 Android 设备 HTTP/HTTPS 全局代理指向宿主监听端口。
4. 部署或附加 Frida 探针（支持 `strict`、`balanced`、`attach_only` 策略）。
5. 探针加载 `agent.compiled.js`，发送 `hook_ready` 控制消息；应用进入主界面后发送 `hook_status`。
6. 触发 Consent 人工检查点（若启用），记录用户授权的单调时间戳。
7. 捕获敏感 API 调用事件与脱敏网络流。
8. 经过固定稳定观察窗口后，触发 `finally` 资源清理：恢复设备代理、停止受控进程、释放端口租约。

### 4.3 证据关联与规则判定流水线 (Correlation & Findings)
1. 读取 `events.json` 与 `requests.jsonl`。
2. 双向滑动时间窗口（默认 2500ms）：
   - 敏感行为时戳 $T_1$ 与网络请求时戳 $T_2$ 满足 $|T_1 - T_2| \le 2500\text{ms}$ 时标记为高概率时间接近关联对。
3. 规则引擎扫描全部事实：
   - 依据权限申明、调用时序（pre/post consent）、目的域、SDK 所属关系判定 `observed`、`suspected` 与 `evidence_gap`。
4. 计算确定性合规风险分值。

### 4.4 受控 AI 辅助研判流水线 (AI Orchestration)
1. 构建紧凑语义压缩结构 `EvidenceDigest`（防御 Prompt 注入与字符膨胀）。
2. **第一阶段（规划）**：AIPlanner 请求模型生成执行步骤 DAG（仅限本地只读工具白名单）。
3. 校验器对模型返回的计划进行 Schema 校验、工具白名单校验、无环图校验与参数边界复核。
4. **执行阶段**：AIExecutor 严格按拓扑序调度执行并对输出字符进行边界截断。
5. **第二阶段（叙述）**：AINarrator 汇总证据摘要与工具执行结果，请求模型生成合规审计叙述。
6. 输出 `ai-plan.json`、`evidence-digest.json` 与 `ai-report.json`，并注入综合报告。

---

## 5. 产物目录持久化契约

单次任务的所有产物严格自包含于 `output/runs/<run_id>/`：

```text
output/runs/<run_id>/
├── input/app.apk                 # 审计目标 APK 快照备份
├── unpacked/                     # apktool 静态解包内容
├── hook.log                      # Frida 探针运行日志
├── events.json                   # 结构化敏感 API 调用事件列表
├── traffic/
│   ├── flows.mitm                # mitmproxy 二进制流量快照
│   ├── requests.jsonl            # 已脱敏的 HTTP 请求记录行
│   └── mitm.stderr.log           # 抓包服务日志
├── traffic_summary.json          # 流量采集统计摘要
├── correlations.json             # 行为—流量证据关联集 (correlation-v1)
├── privacy-findings.json         # 隐私发现清单 (privacy-findings-v2)
├── ai-plan.json                  # AI 规划生成的步骤 DAG (若启用 AI)
├── evidence-digest.json          # 传入模型的紧凑型证据摘要
├── ai-report.json                # AI 生成的合规研判与叙述
├── report.json                   # 综合合规审计全量数据快照 (注: 报告中 executor_strategy_receipt.executor_provenance_source 字段旧值为 app.main._dynamic_analyze_v2.execution_decision，新值为 app.pipelines.dynamic.execution_decision，两者含义相同)
├── report.md                     # Markdown 格式审计报告
└── report.html                   # 自包含样式的现代化 HTML 交互报告
```

---

## 6. 静态类型检查覆盖与待收敛计划

当前系统已对以下核心业务目录严格纳入 `mypy` 校验（共 54 个源文件，0 errors）：
- `app/core/`（静态分析、Manifest 解析、时钟协议）
- `app/orchestration/`（设备租约、确认门、清理状态机）
- `app/traffic/`（流量捕获与请求脱敏校验）
- `app/pipelines/`（分析流水线用例）
- `app/api/`（FastAPI 网关与依赖注入）
- `app/frida/`（第一批核心：diagnostics, server_manager, execution_session）

**尚未完全纳入严格模式的目录与收敛计划**：
- `app/ai/`：包含 LLM Provider 动态调用、Prompt 上下文组装与容错重试，目前通过结构化 Pydantic 模型确保运行时类型安全，计划在后续针对 Provider 协议与 AITaskService 进行静态类型收敛。
- `app/frida/` 其余文件（如 `process_monitor.py`、`traffic_diagnostics.py`）：计划随对应模块重构逐步纳入全局 files 配置。
