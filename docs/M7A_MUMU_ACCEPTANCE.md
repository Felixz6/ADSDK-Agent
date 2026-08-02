# M7A — MuMu 真机验收记录

本文档是 M7A 全链路编排在真机上的验收模板与结论记录。

**当前状态：阶段 A（无设备自动化开发与测试）已完成；阶段 B/C/D 尚未执行。**

---

## 阶段划分

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| A | 无设备自动化开发与测试（Mock 一切外部依赖） | ✅ 已完成 |
| B | 只读设备预检（不安装、不改代理、不起 frida、不跑动态） | ⏸ 待用户启动 MuMu |
| C | 显式确认门（需精确输入确认词） | ⏸ 阻塞于 B |
| D | 真机全链路验收（一次真实 full_analysis） | ⏸ 阻塞于 C |

---

## 阶段 A 验收结论（已完成）

### 测试基线

| 项 | 变更前 | 变更后 | 说明 |
| --- | --- | --- | --- |
| 后端用例 | 610 | 698 | 新增 88 项（`tests/test_orchestration_m7a.py`） |
| 前端用例文件 | 28 | 30 | 新增 2 个 |
| 前端用例 | 291 | 325 | 新增 34 项 |
| `npm run typecheck` | 通过 | 通过 | — |
| `npm run build` | 通过 | 通过 | — |

### 已知的既有失败（非本轮回归）

`tests/test_m4_frida_reliability.py` 中有 2 项失败：

- `test_diagnostics_are_layered_ready_and_serial_is_private`
- `test_successful_handshake_outweighs_hidden_server_process_name`

二者均断言 `overall_status == 'ready'` 而实际为 `'blocked'`。已通过
`git stash` 在**未包含本轮改动**的干净工作树上复现同样的 2 项失败，
确认为既有问题，不是 M7A 引入的回归。

### 交付内容

- `app/orchestration/` 五个模块（见 `docs/M7A_AI_FULL_ANALYSIS.md`）
- `GET/POST /tasks/{task_id}/consent-checkpoint` 两个接口
- 取消任务时一并取消 Consent 检查点（等待立即退出并进入清理）
- 前端：`ConsentCheckpointCard`、NewAnalysis 设备变更范围清单、
  `useConsentCheckpoint` / `useResolveConsentCheckpoint`
- 配置：`M7A_LEASE_STALE_SECONDS`、`M7A_CONSENT_WAIT_SECONDS`

### 阶段 A 期间**未**接触的东西

- 未连接真实设备、未运行 ADB / Frida / mitmproxy
- 未调用真实 DeepSeek
- 未安装/卸载任何 APK、未清除任何应用数据、未修改任何设备代理

---

## 阶段 B 预检清单（只读，待执行）

前置：请启动 MuMu，并确认设备地址为 `127.0.0.1:16416`。
（平台不会替你启动模拟器。）

只读检查项：

- `adb devices` — 设备在线且已授权
- `getprop ro.product.cpu.abi` / `ro.build.version.release` / `ro.build.version.sdk`
- `settings get global http_proxy` — **读取本轮真实初始值，绝不硬编码历史值**
- 目标包 `com.phoenix.read` 是否已安装、版本号
- 目标包当前 PID / 前台包名
- `pidof frida-server` — 是否存在外部 frida-server 及其版本
- 抓包相关端口占用情况
- 设备租约当前状态

**阶段 B 严禁**：安装/卸载 APK、清除数据、force-stop、修改代理、
启停 frida-server、启动应用、运行动态分析。

---

## 阶段 C 确认门（待执行）

阶段 B 通过后，会列出本次将执行的设备变更动作清单与限制说明，
并要求精确输入确认词 `CONFIRM_M7A_DEVICE_CHANGES`。
未获得该确认词，不得进入阶段 D。

---

## 阶段 D 验收记录（待执行）

> 下表在阶段 D 真实执行后填写。**在真实运行发生之前，所有字段保持为"未执行"。**

| # | 字段 | 值 |
| --- | --- | --- |
| 1 | run_id | 未执行 |
| 2 | task_id | 未执行 |
| 3 | device_ref（掩码） | 未执行 |
| 4 | 包名 | 未执行 |
| 5 | APK sha256 | 未执行 |
| 6 | 开始时间 | 未执行 |
| 7 | 结束时间 | 未执行 |
| 8 | 最终状态 | 未执行 |
| 9 | 计划来源（ai/repaired/default） | 未执行 |
| 10 | 执行的步骤 | 未执行 |
| 11 | 复用的产物 | 未执行 |
| 12 | Frida 策略与回退路径 | 未执行 |
| 13 | 初始代理值 | 未执行 |
| 14 | 代理是否复原 | 未执行 |
| 15 | 外部 frida-server 是否被触碰 | 未执行 |
| 16 | 抓包端口与 PID 归属 | 未执行 |
| 17 | Consent 结论 | 未执行 |
| 18 | 采集到的事件数 | 未执行 |
| 19 | 采集到的请求数 | 未执行 |
| 20 | 关联结果数 | 未执行 |
| 21 | 隐私发现数 | 未执行 |
| 22 | AI 状态与 token 用量 | 未执行 |
| 23 | 清理结果与失败项 | 未执行 |
| 24 | limitations | 未执行 |

---

## 合格判定

阶段 D 允许 `partial` 的情形（须同时给出完整 limitations 且清理完成）：

- Native Bridge 兼容性导致的 spawn 降级
  （标记为 `native_bridge_compatibility_suspected`，
  **不得**标记为 `anti_debug_confirmed`）
- TLS pinning 导致的流量可见性不足
- Consent 界面不可达
- 某个工具不可用
- AI 的瞬时失败

任何情况下都必须满足：无租约泄漏、无残留抓包进程、代理已尝试复原、
外部 frida-server 未被停止、证据已保留、无密钥泄漏。
