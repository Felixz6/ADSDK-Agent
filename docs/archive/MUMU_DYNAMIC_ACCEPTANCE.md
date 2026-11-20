# MuMu 动态可靠性验收

## 已确认基线（2026-07-29）

- 设备：MuMu、Android 15、x86_64、SELinux Permissive。
- 主机 Python binding、CLI 与设备端 `frida-server`：`17.16.4`。
- 设备端 server 以 root 运行，`127.0.0.1:27042` 正常监听。
- 正常启动后 attach、脚本执行和 5 秒会话保持均成功。
- 主动 detach：`reason=application-requested`、`crash=None`。
- suspended spawn 的 spawn、attach、脚本加载、脚本消息和 resume 均成功；resume 后约 0.5–1 秒发生 Native crash。
- 崩溃摘要：`SIGSEGV / SEGV_ACCERR`、`trying to execute non-executable memory`。
- 关键栈涉及 `libhoudini.so`、`libhp15_x86_64.so` 与 `com.tencent.mmkv.MMKV.initialize`。
- 不使用 Frida 的正常冷启动可持续运行并显示 SplashActivity，未观察到相同 Fatal signal。

边界结论：现有证据支持“suspended-spawn 与当前 MuMu x86_64 / ARM64 Native Bridge 启动链存在较高兼容性相关性”，不写成已证明的单一根因。

## 修复后真实任务

设备标识在持久化报告中已脱敏。以下任务均关闭网络采集，聚焦 Frida 执行路径。

### strict

- Run ID：`a780c323-9b07-4afd-83e7-cd2200552805`
- HTTP/任务状态：`500 / failed`（严格策略的唯一运行路径崩溃）。
- `spawn_suspended` 成功完成 spawn、attach、脚本加载、Hook-ready 与 resume。
- resume 后存活 `473 ms`，稳定窗口内记录 `process_crashed`。
- 结构化结果：`native_sigsegv`、`SIGSEGV`、`SEGV_ACCERR`、`trying to execute non-executable memory`。
- 环境能力仍为：transport、进程枚举、attach、spawn 创建可用；当前目标 `spawn_resume_stable=false`。
- 无自动降级，证据等级 D。

### balanced

- Run ID：`295daad2-05ba-4d7b-9a14-309f3fba1564`
- HTTP/任务状态：`200 / partial`。
- 第一次 `spawn_suspended` 在 resume 后存活 `489 ms` 并发生 Native crash；完整崩溃证据保留。
- 清理第一次会话后正常启动目标并执行 `launch_then_attach`，随后进入稳定采集。
- 启动时间：launch 请求到 PID 观察 `443 ms`；到 attach 完成 `1077 ms`。
- 尝试链：`spawn_suspended(failed: spawn_runtime_failed) -> launch_then_attach(success)`。
- 最终证据等级 C。

### attach_only

- Run ID：`1332b21a-3fe5-43c1-be9f-7166514da6e7`
- HTTP/任务状态：`200 / partial`。
- 提交任务前使用 Android 正常启动目标，附加前后 PID 均为同一进程。
- `attach_existing`、脚本加载与稳定采集成功。
- 任务跳过 APK 重装与 force-stop；结束时主动 detach 被分类为 `normal_cleanup`。
- 最终证据等级 C。

## 每次任务后的清理检查

```powershell
adb -s TARGET_DEVICE shell settings get global http_proxy
Get-Process mitmdump,mitmproxy -ErrorAction SilentlyContinue
Get-NetTCPConnection -State Listen |
  Where-Object LocalPort -ge 8080 |
  Where-Object LocalPort -le 8090
```

三组任务后的实测：

- 设备代理：`:null`。
- 宿主机：无任务残留的 mitm 进程，无 8080–8090 残留监听。
- 外部手工启动的 `frida-server` PID 保持不变，任务未执行停止操作。
