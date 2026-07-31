# AdSDK Agent

> 面向 Android APK 的本地隐私与合规分析平台。通过 Web 控制台完成 APK 提交、环境检测、静态分析、动态行为观测、网络流量采集与合规报告查看。

![AdSDK Agent Web 控制台](./docs/screenshots/01-home.png)

> [!IMPORTANT]
> 本项目仅用于已获得授权的 APK 测试、隐私审计与合规分析。请勿用于未授权目标。

## 项目简介

AdSDK Agent 由 Web 控制台和本地分析引擎共同组成：

- **Web 控制台**：基于 React + TypeScript，提供分析提交、设备选择、任务历史、环境检测、结果浏览和报告展示；
- **分析引擎**：基于 FastAPI，负责 APK 校验与快照、Manifest 解析、SDK 识别、Frida 动态采集、mitmproxy 流量观测和规则评估。

用户可以直接在浏览器中完成以下操作：

1. 输入待分析 APK 的本地绝对路径；
2. 选择静态分析或动态分析；
3. 检查 ADB、Frida、mitmproxy 和设备状态；
4. 配置目标设备、Consent 时间窗口和流量采集参数；
5. 查看权限、广告 SDK、动态事件、网络请求和规则状态；
6. 浏览本地任务历史及 JSON / Markdown 报告。

------

## Web 控制台

### 首页与仪表盘

- 展示后端连接状态和核心功能入口；
- 汇总本地分析历史、任务状态和风险规则；
- 后端不可达时提供明确的中文错误提示。

### 新建分析

- 输入 APK 绝对路径；
- 选择静态分析或动态分析；
- 动态分析支持精确选择 ADB `device_id`；
- 可配置 Consent 前后采集窗口、流量采集和 UI 刺激；
- 长耗时请求使用独立超时策略。

### 静态分析

- APK 路径、ZIP 格式、文件大小和允许根目录校验；
- 原子快照与 SHA-256 二次复核；
- Android Manifest、应用信息和权限解析；
- 由本地知识库识别广告、统计、推送、归因、定位和社交 SDK，并展示厂商、分类、风险等级与证据路径；
- 使用 `risk-v1` 生成 0–100 分的可解释风险摘要；仅有静态证据时明确降低置信度；
- 结构化规则结果和报告展示。

### 动态行为

- 使用 Frida Python API 精确绑定目标设备；
- 采用 suspended spawn，确保 Hook 先于应用恢复；
- 展示完整分析流水线和步骤状态；
- 将事件划分为 `pre_consent`、`post_consent` 和 `unknown`；
- 使用 `timeline-v1` 统一编排 Frida 行为与网络请求，并保留来源、时间、同意阶段和摘要；
- 展示严格规则、事件数量和协议错误；
- `not_evaluated` 始终表示证据不足，不会展示为“安全”。

### 网络流量

- 调用 mitmproxy / mitmdump 采集结构化请求；
- 区分环境自检与真实任务流量；
- 默认不保存 query value、认证头、Cookie 或请求正文；
- 明确区分：

```text
collector_failed
collector_success_zero_requests
collector_success_requests_observed
```

### 环境检测

- 检查 ADB、apktool、Frida、mitmproxy 和输出目录；
- 展示在线设备和可用性状态；
- 缺失数据使用“未提供”或“无法检测”，不会错误显示为“正常”。

### 报告与任务历史

- 展示 `matched`、`not_matched`、`not_evaluated`、`error` 四种规则状态；
- 展示风险摘要、证据限制和由 `insight-v1` 本地规则生成的合规解读及 P0/P1 整改建议；
- 查看静态分析和动态分析结果；
- 任务历史保存在当前浏览器的 `localStorage`；
- 本地历史不代表后端持久化任务，清理浏览器数据后会丢失。

### AI 编排分析（M6A，默认关闭）

在「新建分析」中选择 **AI 编排分析** 后，可填写分析目标、分析范围、是否允许动态分析与网络采集，以及 Token 预算。

职责边界是硬性的：

- **确定性工具负责事实**：静态分析、动态分析、`correlation-v1`、`privacy-findings-v2` 与全部计数、风险、证据均由既有确定性代码产生，AI 不参与；
- **AI 只负责调度与叙述**：选择白名单工具、安排顺序，并基于确定性证据摘要生成执行摘要、风险优先级、证据缺口与建议动作。

安全与降级：

- API Key 只从环境变量读取，不进入日志、数据库、接口响应、报告或前端；
- AI 只能返回**已注册工具名**与结构化参数，无法返回 Shell、adb、frida、mitmproxy 命令或任意路径；
- 改变设备状态的工具必须显式确认，未确认时状态为 `blocked_confirmation_required` 且不执行；
- APK 内文本、Manifest、网络字段与应用名称均按不可信数据处理，指令式内容会被中和后仅作为证据展示；
- AI 输出经确定性 **Evidence Reference Validator** 校验：不存在的证据引用被删除、无证据支撑的结论被降级、严重性与置信度不得高于原始证据、虚构域名/权限/SDK 被拒绝、法律合规结论被移除；
- AI 关闭、未配置、不可达、超预算或输出不合法时，一律降级为确定性报告模板，**不会**让静态或动态分析任务失败。

产物（写入 `output/runs/<run_id>/`）：

```text
ai-plan.json          # ai-plan-v1     模型生成的执行计划（或确定性默认计划）
evidence-digest.json  # evidence-digest-v1  代码生成的证据摘要（非 AI 生成）
ai-tool-trace.json    # 工具执行轨迹（仅安全元数据，不含推理过程）
ai-report.json        # ai-report-v1   经证据校验后的 AI 综合研判
```

只读接口：

```text
GET /ai/status                    # AI 可用性（绝不返回 API Key）
GET /tasks/{task_id}/ai-plan      # 该任务的 ai-plan.json
GET /tasks/{task_id}/ai-report    # 该任务的 ai-report.json
```

`/ai/status` 默认不探测外部模型（`reachable` 为 `null` 表示「未探测」）；只有显式传 `?probe=true` 才会按需检查一次可达性。

AI 配置接口（M6B，仅本机可写）：

```text
GET    /ai/settings               # 脱敏后的有效配置（绝不返回 API Key）
PUT    /ai/settings               # 保存可编辑配置 + 可选新 Key（请求体不记日志）
POST   /ai/settings/test          # 测试已保存配置或页面临时配置（临时 Key 不落盘）
DELETE /ai/settings/api-key       # 仅删除本机保存的 Key（环境变量 Key 不受影响）
```

低 Token 设计：正常路径最多两次模型调用（一次规划、一次报告）；候选工具由确定性 capability router 按分析范围筛选（默认不超过 6 个）；发送给模型的始终是压缩后的工具结果与证据摘要，绝不发送完整 `report.json`、Hook 日志、logcat、`requests.jsonl`、请求/响应正文或完整 Manifest。相同输入命中缓存时模型调用为 0 次。

------

## 技术架构

```text
┌─────────────────────────────────────────────────────────────┐
│                      React Web Console                      │
│  Dashboard / New Analysis / Static / Dynamic / Traffic     │
│  Reports / Environment / Tasks / Settings                  │
└───────────────────────────┬─────────────────────────────────┘
                            │ HTTP / JSON
┌───────────────────────────▼─────────────────────────────────┐
│                       FastAPI Engine                        │
│  Input Validation / Snapshot / Static Analysis / Pipeline  │
│  DeviceContext / Frida / MitmSession / Rule Evaluation     │
└───────────────┬───────────────────────┬─────────────────────┘
                │                       │
       ┌────────▼────────┐     ┌────────▼────────┐
       │ Android Device │     │ Local Artifacts │
       │ ADB + Frida    │     │ output/runs/    │
       └─────────────────┘     └─────────────────┘
```

### 前端技术栈

- React 18
- TypeScript（strict）
- Vite 6
- Tailwind CSS 3.4
- React Router 6
- TanStack Query 5
- Axios
- Zustand
- Framer Motion 11
- Lucide React
- Recharts
- Vitest + jsdom + Testing Library + MSW

### 后端技术栈

- Python 3.12+（推荐 Python 3.14）
- FastAPI
- Pydantic
- apktool
- ADB
- Frida
- mitmproxy / mitmdump
- pytest

------

## 快速开始

### 1. 克隆项目

```powershell
git clone <your-repository-url>
cd adsdk-agent
```

### 2. 配置 Python 环境

项目统一使用一个 `.venv`，后端、Frida 和 mitmproxy 均安装在该环境中。

推荐使用 Python 3.14：

```powershell
py -3.14 -m venv .venv
.venv\Scripts\Activate.ps1

$env:PYTHONUTF8 = "1"
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
Copy-Item .env.example .env
```

检查 Python 依赖：

```powershell
python -m pip check
```

预期输出：

```text
No broken requirements found.
```

确认项目命令优先来自当前虚拟环境：

```powershell
Get-Command python, frida, frida-ps, mitmdump |
  Select-Object Name, Source
```

`python`、`frida`、`frida-ps` 和 `mitmdump` 应优先指向：

```text
<项目目录>\.venv\Scripts\
```

并确保外部 Android 工具可用：

```powershell
adb version
apktool --version
frida --version
mitmdump --version
```

正式使用前，请修改 `.env` 中的脱敏密钥：

```env
REDACTION_HMAC_KEY=replace-with-a-strong-random-secret
```

### 3. 安装前端依赖

首次使用时执行：

```powershell
cd web
npm install
cd ..
```

如需自定义前端后端地址，可创建 `web/.env`：

```env
VITE_API_BASE_URL=http://127.0.0.1:8000
VITE_USE_MOCK=false
```

### 4. Windows 一键启动

完成后端虚拟环境和前端依赖安装后，可直接双击项目根目录中的：

```text
start-adsdk-agent.bat
```

脚本会自动：

- 使用 `.venv` 中的 Python 启动 FastAPI 后端，并优先调用同一环境中的 Frida 与 mitmdump；
- 启动 Vite Web 控制台；
- 检查 `8000` 和 `5173` 端口，避免重复启动；
- 服务就绪后自动打开浏览器。

默认地址：

```text
Web 控制台：http://127.0.0.1:5173
后端服务：http://127.0.0.1:8000
API 文档：http://127.0.0.1:8000/docs
```

停止前后端时双击：

```text
stop-adsdk-agent.bat
```

脚本仅停止由当前项目启动的前后端进程，并清理本地 `.run/` 进程记录目录。

### 5. 手动启动

需要分别查看或调试前后端时，也可以手动启动。

启动后端：

```powershell
.venv\Scripts\Activate.ps1
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

另开一个 PowerShell 启动前端：

```powershell
cd web
npm run dev
```

------

## 基本使用流程

### 静态分析

1. 将已授权 APK 放入允许目录，例如：

```text
D:\adsdk-agent\samples\demo.apk
```

2. 打开 Web 控制台；
3. 进入“新建分析”；
4. 输入 APK 的绝对路径；
5. 选择“静态分析”并提交；
6. 在静态分析页或报告页查看结果。

### 动态分析

1. 启动 Android 设备或模拟器；
2. 使用 ADB 确认设备在线：

```powershell
adb devices -l
```

3. 启动与主机 Frida 版本和设备 ABI 匹配的 `frida-server`；
4. 在 Web 控制台中选择动态分析；
5. 填写精确的 ADB serial；
6. 设置 Consent 时间窗口和流量采集参数；
7. 提交并查看分析流水线、事件和报告。

多台设备在线时必须传入精确 `device_id`。ADB 安装、Frida 设备选择和 `MitmSession` 会绑定同一个 `DeviceContext`。

------

## 仓库结构

```text
adsdk-agent/
├─ web/                         # Web 控制台
│  ├─ src/
│  │  ├─ api/                   # Axios 客户端与接口封装
│  │  ├─ components/            # 通用、布局、分析、报告、流量组件
│  │  ├─ hooks/                 # TanStack Query / API Hooks
│  │  ├─ pages/                 # 各业务页面
│  │  ├─ router/                # 路由与懒加载
│  │  ├─ stores/                # Zustand 状态
│  │  ├─ test/                  # Testing Library / MSW 测试基建
│  │  ├─ types/                 # 与 Pydantic 对齐的 TS 类型
│  │  ├─ utils/                 # 工具函数
│  │  └─ assets/                # 页面背景与静态资源
│  ├─ package.json
│  ├─ vite.config.ts
│  └─ vitest.config.ts
├─ app/                         # FastAPI 分析引擎
│  ├─ main.py                   # 应用入口与 API 路由
│  ├─ models.py                 # Pydantic 请求 / 响应模型
│  ├─ config.py                 # 环境与脱敏配置
│  ├─ core/                     # 任务编排、运行目录、设备上下文
│  ├─ analyzers/                # Manifest、SDK 和规则分析
│  ├─ ai/                       # AI 编排（默认关闭）
│  │  ├─ provider.py            # Provider 抽象 + OpenAI 兼容 / Mock 实现
│  │  ├─ tool_registry.py       # 白名单工具与确定性候选工具筛选
│  │  ├─ context_builder.py     # evidence-digest-v1 与 Prompt 注入防护
│  │  ├─ orchestrator.py        # 两阶段低 Token 编排、预算与降级
│  │  ├─ report_composer.py     # Evidence Reference 校验与确定性模板
│  │  ├─ cache.py               # 响应缓存（含 TTL 与损坏隔离）
│  │  ├─ settings_store.py      # 本机配置持久化 + 环境变量优先级
│  │  ├─ settings_service.py    # 配置校验、脱敏响应与 Provider 热更新
│  │  └─ secret_store.py        # Windows DPAPI 加密的 API Key 存储
│  ├─ services/                 # 任务服务与 AI 任务适配
│  ├─ tools/                    # apktool、ADB、Frida、mitmproxy 封装
│  └─ frida_hooks/              # Frida Hook 脚本
├─ tests/                       # 后端 pytest
├─ scripts/                     # 辅助与联调脚本
├─ samples/                     # 默认 APK 允许根目录
├─ docs/
│  ├─ FRONTEND_COMPLETION_REPORT.md
│  └─ screenshots/
├─ output/                      # 本地运行产物，不进入版本控制
├─ requirements.txt
├─ pytest.ini
├─ capture-screenshots.ps1
├─ start-adsdk-agent.bat        # Windows 一键启动入口
├─ start-adsdk-agent.ps1        # 前后端启动逻辑
├─ stop-adsdk-agent.bat         # Windows 一键停止入口
├─ stop-adsdk-agent.ps1         # 前后端停止与清理逻辑
└─ README.md
```

------

## 分析流程

```text
Web 提交分析请求
  -> 校验 APK 路径、格式和大小
  -> 创建 output/runs/<run_id>/
  -> 原子快照 APK 并复核 SHA-256
  -> 解析 Manifest、权限和广告 SDK
  -> 选择目标 Android 设备（动态分析）
  -> 创建 Frida 会话
  -> 创建 MitmSession（可选）
  -> spawn suspended
  -> 加载 Hook 并等待 hook_ready
  -> 写入 collection_started
  -> resume App
  -> 采集 Consent 前事件
  -> 写入 consent_granted
  -> 采集 Consent 后事件
  -> 停止并清理资源
  -> 汇总事件、流量和规则状态
  -> 生成 report.json 与 report.md
  -> Web 控制台展示结果
```

------

## 配置说明

| 配置项                        |      默认值 | 说明                                              |
| ----------------------------- | ----------: | ------------------------------------------------- |
| `APK_ALLOWED_ROOTS`           |   `samples` | 允许访问的 APK 根目录；Windows 多目录使用分号分隔 |
| `APK_MAX_SIZE_MB`             |      `1024` | APK 校验和快照的大小上限                          |
| `REDACTION_HMAC_KEY`          |  开发占位值 | 稳定 HMAC 脱敏密钥，部署时必须替换                |
| `FRIDA_READY_TIMEOUT_SECONDS` |        `15` | Hook-ready 等待超时                               |
| `FRIDA_SPAWN_STABILITY_SECONDS` | `3` | resume 后进程稳定观察窗口；窗口内结束按任务结果记录 |
| `FRIDA_STOP_TIMEOUT_SECONDS`  |         `5` | Frida 停止和清理超时                              |
| `MITM_PORT_START`             |      `8080` | mitmproxy 端口池起点                              |
| `MITM_PORT_END`               |      `8090` | mitmproxy 端口池终点                              |
| `MITM_LISTEN_HOST`            | `127.0.0.1` | mitmdump 监听地址                                 |
| `MITM_READY_TIMEOUT_SECONDS`  |        `10` | mitmproxy addon ready 超时                        |
| `MITM_STOP_TIMEOUT_SECONDS`   |         `5` | mitmproxy 进程树清理超时                          |
| `EVIDENCE_CORRELATION_WINDOW_MS` | `2500` | 动态事件—请求时间关联窗口，允许 100–10000 ms |

### AI 编排配置（全部默认关闭）

| 变量                       | 默认值               | 说明                                                   |
| -------------------------- | -------------------- | ------------------------------------------------------ |
| `AI_ENABLED`               | `false`              | 总开关；关闭时确定性分析与报告行为完全不变             |
| `AI_PROVIDER`              | `openai_compatible`  | Provider 实现；业务代码不绑定任何单一厂商              |
| `AI_BASE_URL`              |         空           | OpenAI 兼容端点根地址                                  |
| `AI_API_KEY`               |         空           | 环境变量方式配置密钥；不进入日志、库、响应、报告与前端 |
| `AI_MODEL`                 |         空           | 模型名                                                 |
| `AI_TIMEOUT_SECONDS`       | `60`                 | 单次模型调用超时                                       |
| `AI_MAX_ROUNDS`            | `2`                  | 模型调用轮数上限（正常路径：规划 1 次 + 报告 1 次）    |
| `AI_MAX_TOOL_CALLS`        | `6`                  | 工具调用次数上限；超出按固定优先级裁剪                 |
| `AI_MAX_INPUT_TOKENS`      | `6000`               | 单次请求输入上限                                       |
| `AI_MAX_OUTPUT_TOKENS`     | `1800`               | 单次请求输出上限                                       |
| `AI_MAX_TOOL_RESULT_CHARS` | `8000`               | 单个工具结果发送给模型前的字符上限                     |
| `AI_CACHE_ENABLED`         | `true`               | 相同输入复用结果；缓存中不保存 API Key                 |
| `AI_CACHE_TTL_SECONDS`     | `86400`              | 缓存过期时间；缓存损坏按未命中处理，不中断分析         |
| `AI_REPORT_LANGUAGE`       | `zh-CN`              | AI 报告语言                                            |
| `AI_ALLOW_DYNAMIC_TOOLS`   | `false`              | 为 false 时设备状态变更类工具永不进入候选列表          |

Token 与调用预算被超过时，系统停止继续调用模型、保留已有工具结果、生成确定性报告，并将 AI 状态标记为 `budget_exhausted`——**不会**让整个任务失败。

### 前端 AI 配置中心（M6B）

除 `.env` 环境变量外，也可在 **设置 → AI 编排** 卡片中直接配置 AI。两种方式并存，既有 `.env` 部署无需任何改动。

**配置优先级（固定）**

```text
环境变量  >  本机保存配置  >  代码默认值
```

存在对应环境变量的字段会出现在响应的 `locked_fields` 中，前端输入框禁用并提示「该字段由环境变量管理」；`field_sources` 逐字段给出 `default | environment | local_store`。本机保存**不会**覆盖环境变量，删除本机 Key 也不影响环境变量 Key。

**两份配置文件（分离存储）**

| 文件                            | 内容                     | 说明                                        |
| ------------------------------- | ------------------------ | ------------------------------------------- |
| `output/config/ai-settings.json` | 非密钥的可编辑配置       | 明文 JSON；**永不包含 API Key**             |
| `output/config/ai-secret.bin`    | API Key                  | Windows DPAPI 加密；只有当前 Windows 用户可解密 |

两者均为「临时文件 + `os.replace`」原子写入。配置 JSON 损坏时按默认值降级；密钥文件损坏或由他人复制而来时按「未配置」处理，**不会**导致后端启动失败。

**Windows DPAPI 说明**

密钥通过 `ctypes` 调用 `CryptProtectData` / `CryptUnprotectData` 加密（不引入额外依赖），加密结果与当前 Windows 用户账户绑定：换用户或换机器都无法解密。**非 Windows 平台不支持本机保存密钥**，保存时返回 `secret_persistence_unsupported`——绝不静默退回明文保存；这些平台请继续使用 `AI_API_KEY` 环境变量。

**API Key 保存与删除**

`PUT /ai/settings` 的 `api_key` 字段为只写：

- 字段缺失 → 保留现有 Key；
- 空字符串 → 保留现有 Key（**不是删除**）；
- 非空字符串 → 替换 Key。

删除必须调用独立接口 `DELETE /ai/settings/api-key`，前端对应「删除已保存 API Key」按钮并带二次确认。这样普通保存永远不会误删密钥。

**测试连接**

`POST /ai/settings/test` 可测试已保存配置，也可测试页面上尚未保存的临时配置（临时 Key 只存在于该次请求内存，不保存、不缓存、不写库、不写报告、不记日志）。

探测策略不只依赖 `GET /models`：

1. 先尝试 `GET /models`，2xx 即判定可达；
2. 若返回 404 / 405，改用一次最小聊天请求（`max_tokens=1`、固定短提示、不带工具、不产生报告）验证；
3. 401 / 403 → `authentication_failed`；超时 → `timeout`；其余传输失败 → `unreachable`。

响应中的 `models_endpoint_supported` 说明本次采用了哪条探测路径，因此**不会**因为网关不支持 `/models` 就误判为不可达。

**Provider 热更新**

保存配置后无需重启后端：进程内 `AIProviderFactory` 以锁保护重建 Provider，**新任务**使用最新配置，**正在运行的任务**继续使用其启动时捕获的快照；重建失败时保留旧 Provider 并返回结构化错误。

**安全边界**

- API Key 永不返回前端：读取接口只暴露 `api_key_configured`（布尔）与 `api_key_source`；
- Key 不写入 `localStorage` / `sessionStorage` / `IndexedDB` / URL / 前端构建产物 / 全局 Store，只存在于输入组件的局部状态，保存成功即清空、组件卸载即清除；
- Key 不进入任务 SQLite 库、报告、AI 缓存、日志、异常堆栈与测试快照；
- 写接口（`PUT` / `POST` / `DELETE`）仅允许 loopback 客户端（`127.0.0.1` / `::1`）；带 `Origin` 时必须属于已配置的前端来源，否则 403；无 `Origin` 的本机 CLI 请求放行；
- 写接口请求体永不记录日志；配置不可通过 GET 查询参数修改。

### `MITM_LISTEN_HOST` 安全说明

默认值 `127.0.0.1` 只监听宿主机 loopback。

将其设为 `0.0.0.0` 会监听所有主机网络接口，仅应在受信任的本地测试网络中使用。模拟器中的 `127.0.0.1` 指向模拟器自身，不是 Windows 宿主机；应将设备代理指向模拟器可访问的宿主机地址，例如部分 QEMU / MuMu 环境中的 `10.0.2.2:<port>`。实际地址应以当前模拟器网络为准。

### 多 Worker 部署

端口租约目前由进程内资源管理器维护。使用多个 Uvicorn worker 时，应为各 worker 配置不同的 mitmproxy 端口段。

------

## API

| 方法   | 路径               | 用途             |
| ------ | ------------------ | ---------------- |
| `GET`  | `/`                | 服务状态         |
| `GET`  | `/env/check`       | 环境和设备检查   |
| `GET`  | `/traffic/check`   | 流量采集环境自检 |
| `POST` | `/analyze`         | 静态分析         |
| `POST` | `/dynamic/analyze` | 动态分析         |
| `GET`  | `/ai/status`       | AI 可用性（不返回 API Key） |
| `GET`  | `/tasks/{id}/ai-plan`   | 该任务的 `ai-plan.json`   |
| `GET`  | `/tasks/{id}/ai-report` | 该任务的 `ai-report.json` |

### 静态分析请求

```powershell
curl -X POST http://127.0.0.1:8000/analyze `
  -H "Content-Type: application/json" `
  -d '{"apk_path":"D:\\adsdk-agent\\samples\\demo.apk"}'
```

### 动态分析请求

```powershell
curl -X POST http://127.0.0.1:8000/dynamic/analyze `
  -H "Content-Type: application/json" `
  -d '{
    "apk_path":"D:\\adsdk-agent\\samples\\demo.apk",
    "device_id":"emulator-5554",
    "consent_after_seconds":8,
    "pre_consent_seconds":10,
    "post_consent_seconds":10,
    "enable_traffic":true,
    "enable_ui_stimulation":false,
    "collection_timeout_seconds":300
  }'
```

### 动态分析参数

| 参数                         | 默认值       | 说明                                       |
| ---------------------------- | ------------ | ------------------------------------------ |
| `apk_path`                   | 必填         | APK 绝对路径，且必须位于允许根目录         |
| `device_id`                  | 多设备时必填 | 精确的 ADB serial                          |
| `consent_after_seconds`      | 按需设置     | 从 `collection_started` 起计算的同意时间点 |
| `pre_consent_seconds`        | `10`         | Consent 前采集窗口                         |
| `post_consent_seconds`       | `10`         | Consent 后采集窗口                         |
| `enable_traffic`             | `true`       | 是否启用网络采集                           |
| `enable_ui_stimulation`      | `false`      | 是否启用 UI 刺激                           |
| `collection_timeout_seconds` | `300`        | 动态分析总超时                             |

------

## Consent 时间语义

项目使用：

- **UTC**：用于报告展示；
- **monotonic**：用于 Consent 边界判定，避免系统时间变化影响结果。

```text
event.monotonic < consent.monotonic   -> pre_consent
event.monotonic >= consent.monotonic  -> post_consent
invalid or missing timing data        -> unknown
```

规则：

1. Hook-ready 后，App 仍保持 suspended；
2. 写入 `collection_started`；
3. 恢复 App；
4. 从 `collection_started` 的 monotonic 基准计算 Consent；
5. 精确落在 Consent 边界的事件归入 `post_consent`；
6. 缺少合法 monotonic 或控制事件时归入 `unknown`；
7. 旧自由文本 Hook 日志不会通过文件顺序推断 Consent。

旧日志兼容状态：

```text
timing_reliable = false
consent_state = unknown
```

依赖严格时间证据的规则将返回 `not_evaluated`。

------

## 输出产物

```text
output/runs/<run_id>/
├─ input/
│  └─ app.apk
├─ unpacked/
├─ hook.log
├─ events.raw.jsonl
├─ events.json
├─ frida.protocol-errors.jsonl
├─ traffic/
│  ├─ flows.mitm
│  ├─ requests.jsonl
│  └─ mitm.stderr.log
├─ traffic_summary.json
├─ sessions.json
├─ report.json
└─ report.md
```

| 文件                          | 说明                                     |
| ----------------------------- | ---------------------------------------- |
| `input/app.apk`               | 经过校验和 SHA-256 复核的任务快照        |
| `unpacked/`                   | APK 静态解包结果                         |
| `hook.log`                    | 安全生命周期诊断日志                     |
| `events.raw.jsonl`            | 通过协议校验的结构化 Frida 事件          |
| `events.json`                 | 兼容旧消费者的规范化事件数组             |
| `frida.protocol-errors.jsonl` | 无效消息和协议错误                       |
| `traffic/flows.mitm`          | mitmproxy 会话文件                       |
| `traffic/requests.jsonl`      | 脱敏后的结构化请求                       |
| `traffic_summary.json`        | 网络采集摘要                             |
| `sessions.json`               | run / session 所有权、状态和脱敏设备信息 |
| `report.json`                 | 最终机器可读报告及完成标记               |
| `report.md`                   | 最终人工可读报告                         |

------

## 状态语义

### 步骤状态

| 状态      | 含义           |
| --------- | -------------- |
| `success` | 成功完成       |
| `partial` | 仅获得部分结果 |
| `failed`  | 执行失败       |
| `skipped` | 未执行         |

### 规则状态

| 状态            | 含义                   |
| --------------- | ---------------------- |
| `matched`       | 证据满足规则           |
| `not_matched`   | 证据有效，但未满足规则 |
| `not_evaluated` | 缺少可信证据，无法判断 |
| `error`         | 规则执行发生错误       |

采集失败、Hook-ready 超时或协议不可信时，依赖相关证据的规则必须为 `not_evaluated`，不能解释为“未发现行为”。

网络采集成功但零请求时：

```text
coverage = no_observations
```

这只表示当前采集窗口没有观测结果，不代表应用没有网络行为。

------

## 隐私与安全

- Android ID、OAID 等原值默认不从 Hook 端发送；
- 正式产物仅保留存在性、长度和脱敏 token；
- `REDACTION_HMAC_KEY` 用于生成稳定 HMAC 脱敏值；
- 网络请求默认不保存 query value、认证头、Cookie 或正文；
- 无效 Frida 消息与正式事件分离；
- 每次任务使用独立 run、session、端口和输出目录；
- 报告仅保留脱敏设备 token；
- Web 页面不会将 `not_evaluated` 展示为“安全”。

------

## 测试

### 后端

```powershell
pytest
```

测试覆盖：

- API 契约；
- APK 输入校验和快照；
- SHA-256 一致性；
- 运行目录隔离；
- 设备选择；
- Frida 事件协议；
- 流量状态；
- 脱敏逻辑；
- MITM 监听配置；
- 动态分析错误路径。

### 前端

```powershell
cd web
npm run typecheck
npm run test
npm run build
```

测试覆盖：

- API 错误归一化；
- 动态请求超时；
- 页面路由；
- 表单校验；
- 静态与动态结果展示；
- Consent 分类；
- 规则四态；
- 设备 token 脱敏；
- 环境状态；
- 浏览器本地任务历史；
- `not_evaluated` 风险展示不变量。

完整验收记录：

```text
docs/FRONTEND_COMPLETION_REPORT.md
```

页面截图：

```text
docs/screenshots/
```

------

## 已知限制

- 后端 API 仍为同步接口；
- 浏览器任务历史尚未由后端持久化；
- 尚未提供任务恢复、取消和实时进度接口；
- 端口租约仅支持进程内管理；
- SSL Pinning 可能降低 HTTPS 流量可见性；
- 动态事件与网络请求仅按可信时间信息做轻量关联，不表达因果；
- 部分 APK 的反调试、兼容性或启动行为可能导致动态采集失败；
- 当前报告以 JSON 和 Markdown 为主要持久化格式。

------

## 后续规划

1. SQLite 本地任务系统；
2. 异步、可恢复的分析流水线；
3. 任务状态、进度和取消接口；
4. 跨进程端口与设备资源租约；
5. 扩展事件—请求关联的可观测时间来源；
6. 更完整的规则库和 SDK 指纹库；
7. HTML / 可导出可视化报告；
8. 前端任务实时更新与历史持久化。

------

## 许可证

本项目采用 [Apache License 2.0](LICENSE)。

------

## 静态解包缓存

- 默认位置：`output/cache/static-unpack/<APK_SHA256>/`。
- 缓存键仅使用 APK SHA-256，与 `output/runs/<run_id>/` 分离。
- `metadata.json` 记录 apktool 版本和缓存格式版本；版本变化、元数据异常或 Manifest 缺失时自动重建。
- 发布采用临时目录和原子替换，同 SHA-256 并发请求在进程内串行构建。
- 清理方式：停止后端后删除 `output/cache/static-unpack/`；下次请求会自动冷启动重建。
- `output/` 已被 `.gitignore` 排除，缓存和真实分析产物都不进入 Git。

MuMu/QEMU 流量采集需显式配置 `MITM_LISTEN_HOST=0.0.0.0` 和经实测可达的 `MITM_DEVICE_PROXY_HOST`；任务结束时恢复设备原 `http_proxy` 值。

---

## 产品化任务工作流（2026-07）

### 任务中心与持久化

新建分析统一通过 `POST /tasks` 创建。接口快速返回任务记录和 `id`，任务由单进程线程池在后台运行；旧的 `POST /analyze` 与 `POST /dynamic/analyze` 继续保留同步语义。

SQLite 默认位置：

```text
output/state/adsdk-agent.db
```

可通过环境变量覆盖：

```env
TASK_DATABASE_PATH=D:\private-state\adsdk-agent.db
```

数据库首次使用时自动建表，不需要手工迁移。主要表：

- `tasks`：任务类型、状态、APK 元数据、脱敏设备标识、真实进度、错误、风险和报告索引；
- `task_steps`：真实流水线步骤、状态、百分比、消息和时间；
- `comparisons`：`comparison-v1` 确定性对比结果。

启动时，遗留的 `queued` / `running` 任务会被标记为失败并写明“进程异常中断”，不会错误保留为运行中。新任务进入 SQLite；旧 `localStorage` 历史仅在任务中心的“浏览器旧记录”区域只读展示。

### 异步执行、实时进度与取消

- `/tasks/{task_id}` 页面优先订阅 `ws://127.0.0.1:8000/ws/tasks/{task_id}`；
- WebSocket 尚未建立或断开时，以 3 秒 HTTP 轮询兜底；
- 终态 `completed`、`failed`、`cancelled` 停止轮询；
- 进度来自 APK 校验、快照、解包、Manifest、SDK、动态会话、流量、规则和报告等真实回调；
- 同一设备的动态任务使用独占锁，运行结束后释放；
- 仅 `queued` / `running` 可取消。取消先写入信号，在安全点停止，并执行 Frida、mitmdump、设备代理和资源租约清理后写入 `cancelled`；
- `failed`、`cancelled`、`completed` 可重试，重试会创建新任务，不覆盖原记录。

原始 ADB serial 只存在于 SQLite 的私有执行载荷中；任务 REST 响应、WebSocket 消息和页面均使用脱敏标识。

### 新增 API

```text
POST   /tasks
GET    /tasks
GET    /tasks/system/status
GET    /tasks/{task_id}
GET    /tasks/{task_id}/report
POST   /tasks/{task_id}/cancel
POST   /tasks/{task_id}/retry
DELETE /tasks/{task_id}
GET    /tasks/{task_id}/artifacts/json
GET    /tasks/{task_id}/artifacts/markdown
GET    /tasks/{task_id}/artifacts/html
WS     /ws/tasks/{task_id}
POST   /comparisons
GET    /comparisons/{comparison_id}
```

`GET /tasks` 支持 `status`、`task_type`、`keyword`、`page`、`page_size`、`sort`。所有新请求与响应均有 Pydantic 模型、输入约束、明确状态码和稳定的 `{detail: {code, message}}` 错误结构。

### 专业 HTML 报告与 PDF

每次分析在原有 `report.json`、`report.md` 之外生成：

```text
output/runs/<run_id>/report.html
```

HTML 使用转义后的结构化数据、独立打印 CSS、分页控制和高对比打印颜色。报告页提供：

- 打印 / 导出 PDF（打开 HTML 后使用浏览器打印）；
- 下载 HTML；
- 下载 JSON；
- 下载 Markdown；
- 复制报告摘要。

HTML 不写入认证头、Cookie、请求正文、原始设备标识或 `REDACTION_HMAC_KEY`。动态证据不足时明确标记“无法评估”，不解释为安全。

### APK 版本对比

“版本对比”从两个具有有效 JSON 报告的已完成任务中选择基准版本和目标版本。后端以确定性集合算法比较：

- 版本、SHA-256 与风险分；
- 权限和高风险权限；
- SDK、厂商与分类；
- 规则状态；
- 域名；
- 动态敏感行为。

新增、删除、保持不变分别展示；缺少动态证据时该维度标记为不可比较。包名不同默认阻止，用户明确勾选后可进行跨应用对比。同一 APK 的两次任务预期 SHA-256 相同且无版本差异。

### 数据库与本地产物清理

先停止前后端，再按需要清理：

```powershell
.\stop-adsdk-agent.ps1

# 仅重建任务索引；分析产物保留
Remove-Item -LiteralPath .\output\state\adsdk-agent.db

# 清理静态解包缓存；下次分析自动重建
Remove-Item -LiteralPath .\output\cache\static-unpack -Recurse
```

任务中心删除默认只删除 SQLite 记录与关联报告索引，保留 `output/runs/<run_id>/`，避免误删其他任务产物。`output/`、SQLite WAL/SHM、临时任务目录、日志、样本和 `.env` 均由 `.gitignore` 排除。

### MuMu 本地联调

所有动态命令必须显式绑定设备：

```powershell
$device = 'TARGET_DEVICE'
$apk = 'D:\adsdk-agent\samples\hongguo.apk'

adb devices -l
adb -s $device get-state
adb -s $device shell getprop ro.product.cpu.abi
adb -s $device shell getprop ro.build.version.release
adb -s $device shell settings get global http_proxy
```

动态任务请求示例：

```json
{
  "task_type": "dynamic",
  "apk_path": "D:\\adsdk-agent\\samples\\hongguo.apk",
  "device_id": "TARGET_DEVICE",
  "enable_traffic": true,
  "enable_ui_stimulation": false,
  "pre_consent_seconds": 5,
  "post_consent_seconds": 5,
  "collection_timeout_seconds": 60
}
```

验收结束后再次检查 `http_proxy`，并检查是否残留本任务拥有的 `mitmdump`、Frida 会话或设备锁。APK 自终止、反调试、SSL Pinning 或未产生请求都按实际证据记录；不会补造事件或流量。

### 已知限制

- 执行器为本地单进程线程池，不是跨机器分布式队列；
- 进程异常退出时，正在运行的任务在下次启动后标记失败，需要手动重试；
- 浏览器 PDF 结果依赖用户本机打印设置，后端不生成原生 PDF；
- 动态分析质量仍取决于应用可运行性、Frida 兼容性、证书信任和 SSL Pinning；
- 删除任务默认保留完整分析目录，磁盘回收由操作者在停止服务后按目录执行。

## M4 动态分析可靠性

- `strict` 只接受 `spawn_suspended`，失败后不降级；
- `balanced` 优先启动前 Hook，失败后只选择具有真实语义的已有进程 attach，并记录每次尝试；
- `attach_only` 不覆盖启动阶段，报告会明确降低证据等级；
- `dynamic-evidence-quality-v1` 使用 A/B/C/D 及覆盖、限制、可信/不可信能力解释结果；
- `frida-diagnostics-v1` 分别检查 host、device、server、transport、target；
- 诊断保持只读，打开页面不会触发部署、启动或停止；
- 平台不联网下载 frida-server，不覆盖未知远端文件，不停止用户已有进程；
- 零请求不等于无网络行为，快速退出也不会直接解释为反调试。

新增配置：

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `FRIDA_SERVER_MANAGEMENT_ENABLED` | `false` | 是否允许用户显式执行本地 server 管理 |
| `FRIDA_SERVER_LOCAL_PATH` | 空 | 用户配置的本地可信文件；平台不联网下载 |
| `FRIDA_SERVER_REMOTE_PATH` | `/data/local/tmp/frida-server` | 设备端受控路径 |
| `FRIDA_SERVER_START_TIMEOUT_SECONDS` | `10` | 受控启动超时 |
| `FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS` | `10` | transport 握手超时 |
| `FRIDA_SERVER_STOP_ON_TASK_END` | `false` | 是否停止任务启动且拥有的 server |

新增 API：`POST /frida/diagnostics`、`GET /frida/status`、
`POST /frida/server/deploy`、`POST /frida/server/start` 和
`POST /frida/server/stop`。动态请求新增 `dynamic_mode_policy`，默认 `balanced`。

完整流程见 [动态可靠性](docs/DYNAMIC_RELIABILITY.md)、[Frida 诊断](docs/FRIDA_DIAGNOSTICS.md)
与 [MuMu 验收](docs/MUMU_DYNAMIC_ACCEPTANCE.md)。

## M5A 动态事件与网络请求证据关联

- `correlation-v1` 对同一任务内已有 Frida 事件和安全网络请求元数据做确定性时间关联；
- 默认窗口为 `2500 ms`，每个动态事件最多保留时间差最小的 5 个候选；
- 两侧具有可比单调时钟时优先使用 monotonic；否则仅在 UTC 均可信且 `run_id` 一致时降级；
- Consent 阶段明确冲突的候选不进入结果；缺少观察、时间不足和模块异常分别使用
  `no_observations`、`not_evaluated`、`error`；
- 输出写入 `output/runs/<run_id>/correlations.json`，并嵌入 JSON、Markdown 和 HTML 报告；
- 关联只表示“时间上接近”或“可能相关”，不表示动态事件触发请求，也不证明数据由某 API 上传；
- 关联结果仅包含事件标识、事件类型、请求标识、脱敏主机、方法、时间差、Consent、置信度和原因码，
  不写入 Cookie、Header、正文、原始 URL 或 query value。

## M5B 可解释隐私发现

- `privacy-findings-v2` 把已有静态、动态、网络、Consent 时间线和 `correlation-v1` 证据
  转换为确定性、可追溯、可解释的隐私发现；
- 七条规则独立评估：`PF-PRECONSENT-SENSITIVE-EVENT`、`PF-PRECONSENT-NETWORK`、
  `PF-PRECONSENT-CORRELATED-ACTIVITY`、`PF-CONSENT-STATE-UNKNOWN`、
  `PF-DYNAMIC-EVIDENCE-GAP`、`PF-NETWORK-EVIDENCE-GAP`、`PF-POSTCONSENT-OBSERVATION`；
- 每条发现区分 `finding_type`：`observed`（已观察技术事实）、`suspected`（疑似风险提示）、
  `evidence_gap`（证据缺口）；规则状态区分 `matched`、`not_matched`、`not_evaluated`、`error`；
- 严重性与置信度独立：动态证据等级 A 支持高置信，B 高到中，C 最高中，D 不形成确定性动态结论；
  关联置信度、UTC 墙钟降级和未知 Consent 阶段各自独立压低置信度上限；
- `finding_id` 由 schema 版本、`rule_id`、排序后的证据标识和 Consent 阶段做 SHA-256 派生，
  相同输入得到相同标识与相同排序；
- 规则之间故障隔离：Manifest 解析失败不阻塞动态规则，缺少 `correlation-v1` 不阻塞独立规则，
  单条规则异常只把该规则记为 `error`，其余规则继续评估；
- 输出写入 `output/runs/<run_id>/privacy-findings.json`，并嵌入 JSON、Markdown 和 HTML 报告；
  模块异常时报告仍生成，`privacy_findings.status` 为 `error`；
- 发现只包含事件标识、事件类型、请求标识、脱敏主机、方法、粗粒度路径摘要、时间、Consent 阶段、
  关联标识和证据等级，不写入 Cookie、Authorization、Token、请求体、响应体、完整 query value、
  原始设备序列号、Android ID、IMEI、OAID、广告 ID 或未脱敏设备路径；
- 结果是风险提示，不是法律合规结论。未观察到某项行为不代表该行为不存在，
  `not_evaluated` 代表证据不足，不代表安全或合规。


### M4.2 MuMu suspended-spawn 可靠性边界

- 环境能力与单次任务结果分别建模。目标进程崩溃时，已验证的 transport、进程枚举、Attach 与 spawn 创建能力仍按真实结果保留。
- `strict` 只运行 `spawn_suspended`。resume 成功后还需通过 `FRIDA_SPAWN_STABILITY_SECONDS` 稳定窗口；窗口内 Native crash 记录为 `process_crashed`，不触发降级。
- `balanced` 在 suspended-spawn 的稳定窗口内发生运行时崩溃时，保留首次尝试的 Hook、resume、存活时间和崩溃证据，清理该会话后使用正常 Android 启动，再执行 `launch_then_attach`。
- `attach_only` 保留正在运行的目标，不重新安装 APK，也不 force-stop；目标进程缺席时返回 `package_process_not_found`，默认证据等级 C。
- `launch_then_attach` 记录 `launch_requested_at`、`pid_observed_at`、`attach_started_at`、`attach_completed_at` 和 `startup_gap_ms`，默认证据等级 C。只有显式验证早期生命周期覆盖时才评为 B，且不自动评为 A。
- 主动 `application-requested` detach 且 `crash=None` 属于正常清理。完整 Native backtrace 保存在 `dynamic/process-diagnostics.json`，页面和正文默认仅展示摘要。
- 外部启动的 `frida-server` 不属于任务所有权；任务结束只清理由平台显式启动并记录 ownership 的 server。
