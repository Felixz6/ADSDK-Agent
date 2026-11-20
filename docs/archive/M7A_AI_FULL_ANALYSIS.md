# M7A — 真机 AI 全链路编排、安全确认、失败恢复与资源清理

本文档描述 `app/orchestration/` 提供的全链路编排能力：它把已有的确定性分析工具
与 M6A/M6C AI 编排器包在一层**安全信封**里，使一次完整分析可以在单台真机上
安全地跑完并复原设备状态。

本模块**不产生任何新的检测结论**。事实由确定性工具产出；AI 只负责在固定 DAG
内做受约束的计划选择、风险排序与最终叙述。

---

## 1. 职责边界

| 层 | 负责 | 不负责 |
| --- | --- | --- |
| 确定性工具（静态/动态/流量/关联/隐私发现/报告） | 全部事实 | 计划选择、叙述 |
| M6A/M6C `AIOrchestrator` | 受约束计划、工具执行、证据摘要、最终报告 | 设备生命周期、资源所有权 |
| M7A `FullAnalysisSession` | 状态机、租约、快照、确认门、Consent 检查点、清理与复原、验收记录 | 检测逻辑、事实 |

**AI 绝不生成或执行任意 Shell、ADB、Frida、SQL 或 Python。** 模型只能返回
已注册的工具名 + 通过 Pydantic 校验的结构化参数；未注册的名字在执行前即被拒绝。

---

## 2. 模块结构

```
app/orchestration/
├── __init__.py                 公共导出
├── device_session.py           device-session-v1 快照（掩码 device_ref）
├── device_lease.py             可回收的设备租约（心跳 + 陈旧回收）
├── cleanup_manager.py          资源所有权注册表 + 10 条清理规则
├── consent_checkpoint.py       Consent 人工检查点服务
└── full_analysis_session.py    状态机 + 受约束计划 + 验收记录
```

---

## 3. `device-session-v1` 设备会话快照

在任何改变设备状态的工具运行**之前**，先采一份只读快照，作为"我们动手之前设备
长什么样"的唯一事实来源，清理时据此复原。

关键约束：

- **不保存完整 serial**。只保存 `Redactor` 产出的稳定掩码 `device_ref`
  （形如 `redacted:<token>`）。它足以在一次运行内关联产物，但对只能读到报告或
  数据库的人毫无价值。
- `http_proxy` 记录**初始**代理值：
  - `""` 表示"当时没有设代理"（清理时执行 delete）
  - 具体值表示"当时有代理"（清理时 set 回该值）
  - `None` 表示"我们没能确定"——清理时**不猜**，保持原样并记录 `skipped`
- 探针（`SnapshotProbe`）是注入的，且按契约只读；任一探测失败降级为该字段
  `None`，不会中断快照。

---

## 4. 资源所有权：`external` vs `owned_by_run`

沿用 `FridaServerManager`（从不接管未知 frida-server）与 `MitmSession.PortPool`
（端口按持有者释放）已经确立的纪律：

- `external` —— 运行前就存在的资源。**永不停止、永不删除。**
  典型：用户自己起的 frida-server、用户已有的代理设置、其他应用。
- `owned_by_run` —— 本轮启动的资源。**必须清理**，按获取的逆序拆除。

`ResourceOwnershipRegistry` 以 `(kind, identity)` 为键登记，`CleanupManager`
只对 `owned_by_run` 动手。

---

## 5. 十条清理规则

`CleanupManager.run()` 在 `try/finally` 中执行，**每次运行都遍历全部 10 条**；
不适用的记 `not_applicable`，使清理轨迹完整可审计。

| # | 规则 | 说明 |
| --- | --- | --- |
| 1 | `stop_mitm_processes` | 停止本轮启动的抓包进程 |
| 2 | `restore_device_proxy` | 按快照复原代理，**失败也不中断后续清理** |
| 3 | `detach_frida_sessions` | 断开本轮建立的 Frida 会话 |
| 4 | `leave_external_frida_server` | **永不**停止外部 frida-server |
| 5 | `stop_owned_frida_server` | 仅当本轮启动过才停止 |
| 6 | `leave_app_data` | **永不**清除应用数据（显式空操作） |
| 7 | `leave_other_apps` | **永不**修改其他应用（显式空操作） |
| 8 | `no_device_reboot` | **永不**重启设备（显式空操作） |
| 9 | `retain_evidence` | **永不**删除本轮证据产物 |
| 10 | `release_lease` | 释放设备租约 |

代理复原失败记录在 `proxy_restore_failed` 上并进入报告的 limitations，
但不会让清理提前退出。

---

## 6. 可回收的设备租约

`LeaseRegistry` 在原有 `threading.Lock` 之上提供可持久判定、可回收的租约：

- 一台设备同时只允许一个会改变状态的任务。
- 纯静态任务**不取租约**。
- Consent 等待期间**持有**租约，并持续心跳。
- 取消即释放租约。
- 崩溃后留下的**陈旧**租约可被回收：持有者在本进程内已不存活（`mark_dead`），
  或心跳超过 `M7A_LEASE_STALE_SECONDS`（默认 600 秒）。
- **心跳仍活跃的租约永不被抢占**；并发获取要么排队（`wait=True`）要么失败
  （`lease_busy`）。
- 重试是新的 `run_id`。

---

## 7. Consent 人工检查点

平台**不会自动点击 UI**，也不会替操作员判断是否出现过 Consent 界面。
任务进入 `awaiting_consent_action` 后，由人在真机上完成动作，再回报结论：

| action | 含义 |
| --- | --- |
| `confirmed` | 已在应用内看到并完成 Consent 动作 |
| `not_found` | 本轮未观察到 Consent 界面（记为**证据**，不是失败） |
| `skipped` | 本轮显式跳过 Consent 环节 |

### 接口

```
GET  /tasks/{task_id}/consent-checkpoint   读取当前检查点（无等待中 → 404）
POST /tasks/{task_id}/consent-checkpoint   {"action": "...", "note": "..."}
```

规则：

- **状态受门控**：非等待态提交返回 409。
- **幂等**：重复提交同一 action 返回 200 且状态不变。
- **AI 不得自动确认**：该路由只有人工客户端会调用。
- **超时永不产生 `confirmed`**：看门狗只能 `cancelled`——退出等待并进入清理。
- 取消任务会一并取消检查点，使等待立即退出。

---

## 8. 受约束计划（固定 DAG）

AI 只能在固定 DAG 内**选择或跳过**步骤：

```
environment_check → static_analysis → dynamic_analysis → traffic_analysis
    → evidence_correlation → privacy_findings → deterministic_report
    → ai_synthesis（编排器的最终模型调用，不是模型可调用的工具）
```

AI **可以**决定：复用已有产物、balanced 还是 attach_only、是否继续到 partial、
风险优先级。

AI **不可以**：改变确认要求、跳过清理、新增工具、执行 Shell/ADB/Frida、
生成 mitm 命令、删除产物、清除数据、重启设备、自动确认 Consent、
自动点击 UI、绕过 SSL Pinning、停止外部 frida-server。

计划需通过白名单/schema/DAG/风险/确认/设备能力校验。不合法 → 最多 1 次结构化
修复 → 否则使用确定性默认计划。

> 注：`AIPlan.steps` 的 schema 上限是 6 步，而 full_analysis DAG 枚举 7 个工具，
> 因此默认计划会按 `tool_registry.prioritize_steps` 的固定优先级裁剪到 6 步。

---

## 9. 状态机

```
queued → preflight → planning → awaiting_confirmation → preparing_device
  → static_analysis → starting_capture → dynamic_pre_consent
  → awaiting_consent_action → dynamic_post_consent → stopping_capture
  → correlating → privacy_findings → deterministic_report → ai_synthesis
  → cleanup → completed
```

**失败与取消同样必须进入 `cleanup`。** `FullAnalysisSession.run()` 被拆成
`run()` + `_run_body()`：`_run_body` 只返回早期终态，从不自行清理或定稿；
`run()` 在 `finally` 中统一释放租约、执行清理、清除检查点，然后才定稿
`SessionTransition`。这保证了任何退出路径（含 lease busy、取消、Consent 取消、
未预期异常）都带有完整的 `cleanup` 结果。

---

## 10. Token 与调用预算

沿用 M6C：计划 1 次、报告 1 次、修复至多 1 次；`thinking` 关闭；分阶段输出上限；
证据摘要由**代码**构建（top-10 发现），不含日志、请求体、Manifest 原文或
reasoning_content。预算耗尽 → 停止模型调用、完成清理、保留确定性报告、
AI 状态记为 `budget_exhausted`、任务记为 partial——**不算失败**。

---

## 11. 安全不变量

任何本模块产出的产物都**不含**：

- API Key、Authorization 头
- 完整设备 serial（只有掩码 `device_ref`）
- 完整 Prompt、模型原文、reasoning_content / Chain of Thought
- 请求/响应体、Cookie

`FullAnalysisAcceptance` 与 `SessionTransition` 的序列化结果在测试中被断言
不含上述内容。

---

## 12. 配置

| 环境变量 | 默认 | 说明 |
| --- | --- | --- |
| `M7A_LEASE_STALE_SECONDS` | 600 | 租约多久无心跳后可被回收（仍存活的持有者永不被抢占） |
| `M7A_CONSENT_WAIT_SECONDS` | 900 | Consent 等待上限；到点**不会**自动确认，只退出等待并记为 partial |

---

## 13. 测试

`tests/test_orchestration_m7a.py`（88 项）覆盖：快照 schema 与掩码、租约的获取/
释放/心跳/陈旧回收/忙等/超时、所有权注册表、10 条清理规则（含外部 frida
不被触碰、代理复原失败不中断）、Consent 检查点（状态门控/幂等/取消退出/
永不自动确认）、受约束计划校验、会话状态机各场景，以及 Section 20 的失败注入
契约与 Consent API 的 HTTP 表面。

全部使用注入的假件——**不接触真实设备、ADB、Frida、mitmproxy 或 DeepSeek。**
