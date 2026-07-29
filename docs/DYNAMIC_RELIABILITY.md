# M4 动态分析可靠性

## 执行策略

| 策略 | 行为 | 证据边界 |
|---|---|---|
| `strict` | 只执行 `spawn_suspended` | Hook 失败即停止，不发生静默降级 |
| `balanced` | 启动前 Hook 优先，失败后 attach 已运行进程 | 每次尝试与原因码进入报告 |
| `attach_only` | 只附加现有进程 | 不覆盖启动阶段，Consent 前完整性不可证明 |

Frida 的 `spawn()` 本身具有 suspended 语义，因此实现没有添加没有不同语义的
“普通 spawn”。当前真实降级目标是 `attach_existing`。

## 证据等级

- **A**：启动前 Hook、transport、hook_ready、事件协议和时间边界可信。
- **B**：启动后较早接入，后续事件可信，但启动阶段有缺口。
- **C**：附加已运行进程，仅作为补充观察。
- **D**：没有可信进程内动态事件，仅保留静态或有限网络证据。

`dynamic-evidence-quality-v1` 同时记录 `coverage`、`limitations`、
`trusted_capabilities`、`untrusted_capabilities` 和 `reason_codes`。

## 退出诊断

本地任务产物包括 `dynamic/process-diagnostics.json`、
`dynamic/logcat-summary.json` 和 `dynamic/logcat-tail.txt`。logcat 只保留目标
包、目标 PID 与 Android 崩溃信号相关的有限行数和字节数，并替换已知设备标识。
单独退出不会得到确定反调试结论；`anti_debug_suspected` 同时给出支持证据、其他
解释和置信度。

## 网络零请求

`collector_success_zero_requests` 继续保留。`traffic-diagnostics-v1` 另外记录
代理、监听、TLS、Pinning 疑似和恢复状态。零请求不会被解释为应用无网络行为；
Pinning 疑似要求 TLS 失败与采集器/代理状态形成组合证据。

## 清理

Frida 与 mitmproxy 会话属于单个 run/session，停止幂等。设备代理恢复为任务前
值。未知监听器、用户已有 frida-server 和未知远端文件不会被接管或删除。
