# AdSDK Agent

面向 Android APK 的本地隐私与合规证据采集原型，支持静态分析、动态行为采集、网络流量观测和结构化报告输出，并附带一个基于 React + TypeScript 的 Web 控制台（`web/`）用于可视化提交流程与报告浏览。

> 本项目仅用于已获得授权的 APK 测试与合规分析。

## 目录

- [项目概述](#项目概述)
- [核心能力](#核心能力)
- [仓库结构](#仓库结构)
- [工作流程](#工作流程)
- [运行环境](#运行环境)
- [快速开始](#快速开始)
- [配置说明](#配置说明)
- [api 使用](#api-使用)
- [consent 时间语义](#consent-时间语义)
- [输出产物](#输出产物)
- [状态语义](#状态语义)
- [隐私与安全设计](#隐私与安全设计)
- [Web 控制台](#web-控制台)
- [已知限制](#已知限制)
- [后续规划](#后续规划)
- [测试](#测试)

## 项目概述

AdSDK Agent 用于在本地环境中分析 Android APK 的隐私与合规风险，主要覆盖以下场景：

1. 校验并安全快照 APK；
2. 解析 Manifest，识别常见广告 SDK；
3. 使用 Frida 采集动态行为事件；
4. 使用 mitmproxy 采集结构化网络请求；
5. 按用户同意前后划分行为时间段；
6. 输出机器可读和人工可读报告。

每次分析任务均创建独立运行目录，避免不同任务之间的输入、会话、端口和结果相互污染。

## 核心能力

### 1. APK 输入校验与快照

- 校验 APK 是否为绝对路径；
- 限制 APK 必须位于允许的根目录内；
- 校验 ZIP 格式和文件大小上限；
- 为每次请求创建独立的 `output/runs/<run_id>/`；
- 将 APK 流式、原子地快照为 `input/app.apk`；
- 快照完成后重新校验 SHA-256；
- apktool、ADB 等后续组件只读取快照文件，不直接读取原始 APK。

### 2. 静态分析

- 解析 Android Manifest；
- 提取基础应用信息；
- 识别常见广告 SDK；
- 生成静态分析结果和报告。

### 3. Frida 动态采集

- 使用 Frida Python API；
- 通过 `DeviceContext.serial` 精确选择设备；
- 采用 suspended spawn，确保 Hook 在应用恢复运行前完成加载；
- 使用 typed JSONL 记录结构化事件；
- 无效消息写入协议错误文件，不进入正式事件流；
- 兼容读取旧版自由文本 Hook 日志。

Frida 生命周期如下：

```text
spawn(suspended)
  -> load
  -> hook_ready
  -> collection_started
  -> resume
  -> consent_granted
  -> stop
```

### 4. 网络流量采集

- 每次任务创建独立 `MitmSession`；
- 每个会话使用独立 `session_id`、端口租约和输出目录；
- mitmproxy addon 输出结构化请求到 `traffic/requests.jsonl`；
- 默认不保存 query value、认证头、Cookie 或请求正文；
- 区分以下三类采集结果：

```text
collector_failed
collector_success_zero_requests
collector_success_requests_observed
```

### 5. 设备与会话隔离

ADB 安装、Frida 设备选择和 `MitmSession` 均绑定同一个 `DeviceContext`。

多台设备同时在线时，调用方必须传入精确的 `device_id`。报告中仅记录稳定脱敏后的设备 token，不保存设备原始标识。

### 6. API 兼容性

当前保留以下接口：

- `GET /` — 服务信息
- `POST /analyze`
- `POST /dynamic/analyze`
- `GET /env/check`
- `GET /traffic/check`

## 仓库结构

```text
adsdk-agent/
├─ app/                # FastAPI 后端:输入校验、静态/动态分析、mitmproxy/Frida 采集、报告生成
│  ├─ main.py          # FastAPI 入口与路由
│  ├─ models.py        # Pydantic 契约(请求/响应/事件字段)
│  ├─ config.py        # 环境与脱敏配置
│  ├─ core/            # 核心编排:运行目录、设备上下文、会话隔离
│  ├─ analyzers/       # 静态解析与 SDK 识别、规则评估
│  ├─ tools/           # apktool/ADB/frida/mitmproxy 封装
│  └─ frida_hooks/     # Frida Hook 脚本
├─ tests/              # pytest 用例(端点契约、隔离性、状态/脱敏、设备选择、动态 API)
├─ scripts/            # 辅助脚本
├─ samples/            # APK 样本根(APK_ALLOWED_ROOTS 默认指向此处)
├─ web/                # React + TypeScript Web 控制台(见「Web 控制台」章节)
│  ├─ src/
│  │  ├─ api/          # axios 集中于此:client/system/analysis/tasks
│  │  ├─ hooks/        # useApi:页面经 hooks 调用后端
│  │  ├─ pages/        # Home/Static/Dynamic/Traffic/Environment/Tasks/TaskDetail/Dashboard/Reports/Settings
│  │  ├─ components/   # 通用、布局、分析、报告、流量组件
│  │  ├─ stores/       # Zustand(分析状态、UI)
│  │  ├─ types/        # 与后端 Pydantic 对齐的 TS 类型
│  │  ├─ router/       # 路由定义(惰性加载页面 + AppShell)
│  │  ├─ test/         # 测试基建(render/msw 等统一封装)
│  │  └─ utils/        # 纯函数与 cn 双字语
│  └─ *.test.ts(x)     # Vitest 单测(隐私不变量、错误归一化、各页面/组件,见「测试」)
├─ docs/
│  ├─ FRONTEND_COMPLETION_REPORT.md   # 前端验收完成报告
│  └─ screenshots/                    # 8 张前端页面截图(无头 Chrome 截取)
├─ requirements.txt
├─ pytest.ini
├─ run.ps1
├─ capture-screenshots.ps1            # 截图脚本(用无头 Chrome 对本地 dev server 截图)
└─ README.md
```

`output/`、`.venv/`、`web/dist/`、`web/node_modules/`、`*.test-tmp*`、`pytest-cache-files-*` 均为运行时/测试产物,已与版本控制无关(见根 `.gitignore` 与 `web/.gitignore`)。

## 工作流程

一次典型动态分析任务包含以下阶段：

```text
接收请求
  -> 校验 APK 路径、格式和大小
  -> 创建独立 run 目录
  -> 原子快照 APK 并复核 SHA-256
  -> 静态解析 Manifest 和 SDK
  -> 选择目标 Android 设备
  -> 创建 Frida 会话
  -> 创建 mitmproxy 会话（可选）
  -> 启动 suspended App
  -> 加载 Hook 并等待 hook_ready
  -> 写入 collection_started
  -> 恢复 App 运行
  -> 采集 consent 前事件
  -> 写入 consent_granted
  -> 采集 consent 后事件
  -> 停止采集并清理资源
  -> 汇总事件、流量和状态
  -> 生成 report.json 与 report.md
```

## 运行环境

### 系统要求

- Windows 10 或 Windows 11；
- Python 3.11 及以上；
- 本阶段实际测试环境为 Python 3.14。

### 外部依赖

- `adb`
- `apktool`
- `mitmproxy` / `mitmdump`
- Frida Python 包
- Android 设备端 `frida-server`

建议先确认相关命令已加入 `PATH`，并确保 Android 设备可通过 ADB 正常访问。

## 快速开始

### 1. 创建虚拟环境

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2. 安装项目依赖

```powershell
pip install -r requirements.txt
```

动态采集还需要安装与本机及设备端版本匹配的 Frida，并安装 mitmproxy：

```powershell
pip install frida frida-tools mitmproxy
```

### 3. 创建配置文件

```powershell
Copy-Item .env.example .env
```

部署或正式测试前，必须修改 `.env` 中的敏感配置，尤其是 `REDACTION_HMAC_KEY`。

### 4. 启动服务

```powershell
uvicorn app.main:app --host 127.0.0.1 --port 8000
```

服务启动后，可通过环境检查接口确认本地依赖状态：

```powershell
curl http://127.0.0.1:8000/env/check
```

网络采集环境可通过以下接口检查：

```powershell
curl http://127.0.0.1:8000/traffic/check
```

## 配置说明

| 配置项 | 默认值 | 说明 |
|---|---:|---|
| `APK_ALLOWED_ROOTS` | `samples` | 允许访问的 APK 根目录；Windows 下多个目录使用分号分隔 |
| `APK_MAX_SIZE_MB` | `1024` | APK 校验和快照共同使用的大小上限 |
| `REDACTION_HMAC_KEY` | 开发占位值 | 稳定 HMAC 脱敏密钥，部署时必须替换 |
| `FRIDA_READY_TIMEOUT_SECONDS` | `15` | 等待 Hook-ready 的超时时间 |
| `FRIDA_STOP_TIMEOUT_SECONDS` | `5` | Frida 会话停止和清理超时时间 |
| `MITM_PORT_START` | `8080` | mitmproxy 端口池起始端口 |
| `MITM_PORT_END` | `8090` | mitmproxy 端口池结束端口 |
| `MITM_LISTEN_HOST` | `127.0.0.1` | mitmdump 绑定的网卡。默认 `127.0.0.1`(仅宿主 loopback)对非仿真器部署零行为变更。设为 `0.0.0.0` 会**监听所有主机网络接口**(会被同网任意主机/仿真器访客访问),仅应在受信任的本地测试网络中使用。使用模拟器时,访客机 `127.0.0.1` 是其自身 loopback(非宿主),**不应把 `127.0.0.1` 当作模拟器访问宿主机的地址**;应将设备代理指向模拟器可访问的宿主机地址,例如本次 MuMu 实测的 QEMU 网关 `10.0.2.2:<port>` |
| `MITM_READY_TIMEOUT_SECONDS` | `10` | 等待 mitmproxy addon ready 的超时时间 |
| `MITM_STOP_TIMEOUT_SECONDS` | `5` | mitmproxy 进程树停止和清理超时时间 |

### 多 Worker 部署注意事项

当前端口租约由进程内资源管理器维护。

使用多个 Uvicorn worker 时，应为每个 worker 分配不同的 mitmproxy 端口段；否则可能出现端口租约冲突。跨进程资源租约将在后续阶段实现。

## API 使用

### 静态分析

```powershell
curl -X POST http://127.0.0.1:8000/analyze `
  -H "Content-Type: application/json" `
  -d '{"apk_path":"D:\\authorized-apks\\demo.apk"}'
```

### 动态分析

```powershell
curl -X POST http://127.0.0.1:8000/dynamic/analyze `
  -H "Content-Type: application/json" `
  -d '{
    "apk_path":"D:\\authorized-apks\\demo.apk",
    "device_id":"emulator-5554",
    "consent_after_seconds":8,
    "pre_consent_seconds":10,
    "post_consent_seconds":10,
    "enable_traffic":true,
    "enable_ui_stimulation":false,
    "collection_timeout_seconds":300
  }'
```

### 动态分析参数说明

| 参数 | 默认值 | 说明 |
|---|---|---|
| `apk_path` | —（必填） | 待分析 APK 的绝对路径，且必须位于允许根目录内 |
| `device_id` | —（多设备时必填） | 目标设备的精确 ADB serial；多设备在线时必须提供 |
| `consent_after_seconds` | —（按需设置） | 从 `collection_started` 起，经过指定秒数后写入 consent 事件 |
| `pre_consent_seconds` | `10` | consent 前采集窗口配置 |
| `post_consent_seconds` | `10` | consent 后采集窗口配置 |
| `enable_traffic` | `true` | 是否启用 mitmproxy 网络采集 |
| `enable_ui_stimulation` | `false` | 是否启用 UI 刺激流程 |
| `collection_timeout_seconds` | `300` | 整个动态采集流程的超时时间 |

## Consent 时间语义

项目使用两类时间：

- UTC：用于报告展示和人工阅读；
- monotonic：用于 consent 边界判定，避免系统时间变化影响结果。

### 时间边界规则

1. Hook-ready 通过后，App 仍处于 suspended 状态；
2. 系统写入 `collection_started`；
3. 随后恢复 App 运行；
4. `consent_after_seconds` 从 `collection_started` 的 monotonic 基准开始计算；
5. 事件 monotonic 小于 consent 边界时，归类为 `pre_consent`；
6. 事件 monotonic 大于或等于 consent 边界时，归类为 `post_consent`；
7. 精确落在边界上的事件归入 `post_consent`；
8. 缺少合法 monotonic 或 consent 控制事件时，归类为 `unknown`。

```text
event.monotonic < consent.monotonic   -> pre_consent
event.monotonic >= consent.monotonic  -> post_consent
invalid or missing timing data         -> unknown
```

### 旧日志兼容规则

旧版自由文本 Hook 日志仍可读取，但具有以下限制：

```text
timing_reliable = false
consent_state = unknown
```

系统不会使用文件行顺序推断 consent 前后关系。依赖严格时间边界的规则将返回 `not_evaluated`。

### 严格时间规则

仅当存在合法 monotonic 时钟时，以下规则才会被评估：

- `pre_consent_sensitive_access_strict`：同意前访问敏感标识 — 任一敏感 API 命中即判 `matched`
- `pre_consent_high_frequency_sensitive_access`：同意前高频访问敏感标识 — Android ID ≥ 3 次、剪贴板 ≥ 1 次判 `matched`

缺少合法单调时钟时，上述规则一律返回 `not_evaluated`，不会被曲解为"没有发现行为"。

## 输出产物

每次任务在独立目录中生成产物：

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

### 关键文件说明

| 文件 | 说明 |
|---|---|
| `input/app.apk` | 经校验和 SHA-256 复核后的任务快照 |
| `unpacked/` | APK 静态解包结果 |
| `hook.log` | 安全生命周期诊断日志，不承载 Frida 原始 stdout |
| `events.raw.jsonl` | 仅包含通过协议校验的结构化 Frida 事件 |
| `events.json` | 为旧消费者保留的规范化事件数组 |
| `frida.protocol-errors.jsonl` | Frida 无效消息和协议错误记录 |
| `traffic/flows.mitm` | mitmproxy 原始流量会话文件 |
| `traffic/requests.jsonl` | 脱敏后的结构化网络请求 |
| `traffic/mitm.stderr.log` | mitmproxy 标准错误日志 |
| `traffic_summary.json` | 网络采集结果摘要 |
| `sessions.json` | run/session 所有权、脱敏设备、状态、时间和错误码 |
| `report.json` | 最终机器可读结果及任务完成标记 |
| `report.md` | 最终人工可读报告 |

## 状态语义

### 步骤状态

| 状态 | 含义 |
|---|---|
| `success` | 步骤成功完成 |
| `partial` | 步骤仅获得部分结果 |
| `failed` | 步骤执行失败 |
| `skipped` | 步骤未执行 |

### 规则状态

| 状态 | 含义 |
|---|---|
| `matched` | 证据满足规则条件 |
| `not_matched` | 证据有效，但未满足规则条件 |
| `not_evaluated` | 缺少可信证据，无法进行规则判断 |
| `error` | 规则执行过程发生错误 |

### 证据不足处理原则

采集失败、Hook-ready 超时或协议不可信时，依赖相关证据的规则必须标记为 `not_evaluated`，不能解释为“未发现行为”。

网络采集成功但未观察到请求时，将明确记录：

```text
coverage = no_observations
```

这表示当前采集窗口内没有观测结果，不等同于应用不存在网络行为。

## 隐私与安全设计

- Android ID、OAID 等原值默认不从 Hook 端发送；
- 正式产物只保留标识是否存在、长度和脱敏 token；
- `REDACTION_HMAC_KEY` 用于生成稳定 HMAC 脱敏值；
- 网络请求默认不保存 query value、认证头、Cookie 或正文；
- 无效 Frida 消息与正式事件分离存储；
- 每次任务使用独立 run、session、端口和输出目录；
- 报告仅记录脱敏设备 token，不保存原始设备标识。

## Web 控制台

仓库根目录下的 `web/` 是一个基于 **React 18 + TypeScript(strict)+ Vite 6 + Tailwind 3.4 + React Router 6 + TanStack Query 5 + Axios + Zustand + Framer Motion 11 + Lucide + Recharts** 的前端控制台，用于可视化提交流程与浏览报告，**不修改后端任何契约**，仅消费已有 FastAPI 接口。

### 目录

```text
web/
├─ src/
│  ├─ api/          # axios 仅在此封装:client(拦截与错误归一化)、system、analysis、tasks
│  ├─ hooks/        # useApi hooks;页面经 hooks 调用后端,不直连 axios
│  ├─ pages/        # Home / Static / Dynamic / Traffic / Environment / Tasks / TaskDetail / Dashboard / Reports / Settings
│  ├─ components/   # 通用、布局、分析、报告、流量组件
│  ├─ stores/       # Zustand(分析状态、UI)
│  ├─ types/        # 与后端 Pydantic 字段逐一对齐的 TS 类型
│  ├─ router/       # 路由定义(惰性加载页面 + AppShell)
│  ├─ test/         # 测试基建(renderWithProviders、msw-server 等统一封装)
│  ├─ utils/        # 纯函数与 cn 双语拼接
│  ├─ assets/       # ad-sdk-background.jpg(星空二次元背景,禁裁剪/拉伸/加字)
│  └─ *.test.ts(x)  # Vitest 单测(共 13 个文件,见「测试」):api/client、api/tasks、types/api、utils、各页面(Home/NewAnalysis/Static/Dynamic/Tasks/Reports/Environment)与组件(RiskBadge、EnvironmentStatusCard)
├─ index.html
├─ package.json
├─ vite.config.ts
├─ vitest.config.ts
├─ tsconfig*.json
└─ .env             # VITE_API_BASE_URL=http://127.0.0.1:8000, VITE_USE_MOCK=false
```

### 运行

```powershell
cd web
npm install
npm run dev        # 开发服务器(http://localhost:5173)
npm run build      # tsc -b && vite build,产物到 web/dist/
npm run typecheck  # tsc --noEmit -p tsconfig.app.json
npm run test       # vitest run
npm run preview    # 预览构建产物
```

`web/.env` 中 `VITE_API_BASE_URL` 指向后端 FastAPI(默认 `http://127.0.0.1:8000`)。后端未运行时，前端会给出"无法连接后端"的友好提示，而非崩溃或暂时性重试刷屏。

### 设计与安全约束

- 视觉为"星空中的二次元安全分析控制台"：深蓝夜空、青色星点、毛玻璃面板、克制动效；尊重 `prefers-reduced-motion`。
- 表单均有 `label`、支持键盘可达性、字体可缩放至 125%/150%。
- 颜色统一使用 CSS 变量，不硬编码十六进制色值；图标仅用 Lucide React，不引入未配置的远程 CDN。
- **绝不展示原始敏感标识**（Android ID / OAID / Cookie / 认证头等）；网络请求仅保留 `query_keys`(键名,不含值)等脱敏字段。
- **绝不把 `not_evaluated` 呈现为"安全/未发现风险"**；报告按 `matched` / `not_matched` / `not_evaluated` / `error` 如实呈现，并据此派生风险等级。
- axios 仅集中在 `src/api/*`；页面通过 `useApi` hooks 调用，未在组件中直接 `axios.*`。

## 已知限制

- 当前 API 为同步接口；
- 尚未提供 SQLite 任务系统；
- 尚未支持任务恢复、取消和进度查询；
- 当前端口租约仅支持进程内管理；
- SSL Pinning 可能降低 HTTPS 流量可见性；
- 当前阶段未加入 SSL Pinning 处理；
- 动态行为事件与网络请求尚未实现完整关联；
- 报告目前仅输出 JSON 和 Markdown；
- 尚未加入 Redis、Celery 或插件系统;
- 后端 API 仍为同步接口(`web/` 前端为异步可视化层,不改变此特性)。

## 后续规划

下一阶段建议优先实现：

1. SQLite 本地任务系统；
2. 可恢复的分析流水线；
3. 任务状态和进度查询；
4. 任务取消机制；
5. 跨进程资源与端口租约；
6. 动态事件与网络请求关联器；
7. 更完整的报告展示能力。

## 测试

### 后端(pytest)

```powershell
pytest
```

`pytest.ini` 配置：`testpaths=tests`、`addopts=-ra`、`tmp_path_retention_policy=failed`、`tmp_path_retention_count=2`。开发依赖 `httpx` 用于客户端测试，覆盖端点契约、隔离性、状态/脱敏、设备选择与动态 API 等场景。本工作区实测 **133 passed**（1 个非阻断的 Starlette/httpx2 弃用警告）。

### 前端(Vitest)

```powershell
cd web
npm run typecheck   # tsc --noEmit -p tsconfig.app.json
npm run test        # vitest run
npm run build       # tsc -b && vite build
```

前端单测基于 Vitest 2 + jsdom + @testing-library/react + user-event + MSW 2，统一渲染封装见 `web/src/test/render.tsx`（`renderWithProviders` 包裹 QueryClientProvider(禁用重试) + createMemoryRouter + ToastViewport），MSW 处理位于 `web/src/test/msw-server`。本工作区实测 **130 / 130 通过，13 个测试文件**，覆盖：

| 文件 | 覆盖要点 |
|------|----------|
| `api/client.test.ts`、`api/tasks.test.ts` | axios 错误归一化、动态超时(≥600000ms)、本地任务 ID(随机 UUID) |
| `types/api.test.ts`、`utils/utils.test.ts` | 与后端对齐的 TS 类型契约、纯函数与 cn 拼接 |
| `pages/Home`、`pages/NewAnalysis`、`pages/Tasks` | 首页信息卡、新建分析向导、任务中心(含本地性声明) |
| `pages/StaticAnalysis`、`pages/DynamicAnalysis` | 空态/导航、StatCard 计数、缺失字段以「—」「否」占位而非「正常」 |
| `pages/Reports`、`pages/Environment` | 报告呈现、环境自检如实呈现 |
| `components/common/RiskBadge`、`components/report/EnvironmentStatusCard` | 风险等级徽章、环境状态卡片 |

> 前端验收的完整记录（含真实联调结果与 8 张 1440×900 截图）见 `docs/FRONTEND_COMPLETION_REPORT.md` 与 `docs/screenshots/`。截图脚本为仓库根的 `capture-screenshots.ps1`。
