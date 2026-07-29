# M4.2 动态分析可靠性

## 环境能力与任务结果

环境能力独立记录：

- `transport_available`
- `process_enumeration_available`
- `attach_available`
- `spawn_creation_available`
- `spawn_resume_stable`

单次任务结果记录执行模式、spawn、attach、Hook 加载、resume、进程结果和结构化崩溃。目标进程崩溃不会覆盖已经验证的 Frida 环境能力。

## 执行策略

| 策略 | 行为 | 证据边界 |
|---|---|---|
| `strict` | 仅执行 `spawn_suspended` | resume 后需通过稳定窗口；窗口内进程结束会保留为任务失败，不降级 |
| `balanced` | 先执行 `spawn_suspended`；稳定窗口内运行失败后，清理首次会话，正常启动并 `launch_then_attach` | 首次崩溃与降级后的采集证据同时保留 |
| `attach_only` | 仅附加已经运行的精确目标 PID | 跳过重新安装和 force-stop，只覆盖附加后的行为 |

Frida `spawn()` 本身具有 suspended 语义，因此不增加名称不同但语义相同的“普通 spawn”。

## Suspended 启动脚本握手

Android 进程处于 suspended 状态时，Frida Java bridge 可能尚未出现。脚本先发送结构化 `hook_ready`，证明脚本已经加载且消息通道可用；Java 运行时出现后，再安装 Java Hook 并发送 `hook_status`。

`collection_started` 与 `consent_granted` 控制消息在 Java bridge 尚未出现时也可发送。这样不会为了等待 Java 初始化而提前 resume，也不会把脚本加载成功误写成 Java Hook 已安装。

## 稳定窗口

`FRIDA_SPAWN_STABILITY_SECONDS` 默认值为 `3`。只有目标在 resume 后存活到窗口结束，且会话没有因 crash、exit、kill 或 transport loss 分离，`spawn_suspended` 的运行阶段才标记为成功。

`balanced` 的运行时降级链：

```text
spawn_suspended
  spawn -> attach -> hook_loaded -> hook_ready -> resume
  -> process_crashed/process_exited/process_killed/transport_lost
  -> cleanup
launch_then_attach
  normal_launch -> exact_pid -> attach -> hook_loaded -> collecting
```

## Native 崩溃

`process-diagnostics-v2` 记录：

- `signal`、`signal_code`、`fault_address`
- `process_name`、`thread_name`、`process_uptime`
- `native_frames`、`suspected_components`
- `summary`、`confidence`、`alternative_explanations`

当日志同时涉及 `libhoudini.so`、`libhp15_x86_64.so` 或 MMKV 时，可给出 `native_bridge_compatibility_suspected` 诊断提示。该提示表示兼容性方向，不表示已证明单一根因。

完整 backtrace 保存到 `dynamic/process-diagnostics.json`；网页、Markdown 和 HTML 默认展示摘要，技术详情折叠显示。

## 证据等级

- **A**：`spawn_suspended` 通过稳定窗口，且 transport、Hook-ready、事件协议和 Consent 边界可信。
- **B**：仅在显式、可验证的早期生命周期覆盖成立时使用。
- **C**：`attach_only` 或默认 `launch_then_attach`，启动阶段存在覆盖边界。
- **D**：缺少可信进程内动态事件。

`launch_then_attach` 记录 `launch_requested_at`、`pid_observed_at`、`attach_started_at`、`attach_completed_at` 和 `startup_gap_ms`，不会自动评为 A。

## 清理

- 主动 detach 的 `reason=application-requested` 与 `crash=None` 属于正常清理。
- 设备代理恢复到任务前值。
- 任务只清理自己拥有的 Frida、mitmdump、端口租约和设备锁。
- 外部手工启动的 `frida-server` 不属于平台 ownership，任务结束时保持运行。
