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
| `FRIDA_STOP_TIMEOUT_SECONDS`  |         `5` | Frida 停止和清理超时                              |
| `MITM_PORT_START`             |      `8080` | mitmproxy 端口池起点                              |
| `MITM_PORT_END`               |      `8090` | mitmproxy 端口池终点                              |
| `MITM_LISTEN_HOST`            | `127.0.0.1` | mitmdump 监听地址                                 |
| `MITM_READY_TIMEOUT_SECONDS`  |        `10` | mitmproxy addon ready 超时                        |
| `MITM_STOP_TIMEOUT_SECONDS`   |         `5` | mitmproxy 进程树清理超时                          |

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
- 动态事件与网络请求尚未完成完整关联；
- 部分 APK 的反调试、兼容性或启动行为可能导致动态采集失败；
- 当前报告以 JSON 和 Markdown 为主要持久化格式。

------

## 后续规划

1. SQLite 本地任务系统；
2. 异步、可恢复的分析流水线；
3. 任务状态、进度和取消接口；
4. 跨进程端口与设备资源租约；
5. 动态事件与网络请求关联；
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
$device = '127.0.0.1:16416'
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
  "device_id": "127.0.0.1:16416",
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
