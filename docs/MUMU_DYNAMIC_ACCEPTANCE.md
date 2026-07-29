# MuMu 动态可靠性验收

## 边界

真实设备标识只进入本地命令参数；REST、WebSocket、JSON、Markdown、HTML、文档和浏览器存储只保留脱敏引用。验收过程不联网获取 `frida-server`，也不自动部署或启动设备端服务。

## 只读基线

```powershell
adb devices -l
adb -s TARGET_DEVICE get-state
adb -s TARGET_DEVICE shell getprop ro.product.cpu.abi
adb -s TARGET_DEVICE shell getprop ro.build.version.release
adb -s TARGET_DEVICE shell getprop ro.build.version.sdk
adb -s TARGET_DEVICE shell getenforce
adb -s TARGET_DEVICE shell id
adb -s TARGET_DEVICE shell settings get global http_proxy
.venv\Scripts\python.exe -c "import frida; print(frida.__version__)"
.venv\Scripts\frida.exe --version
.venv\Scripts\frida-ps.exe --version
```

记录代理原值，再从环境页选择脱敏设备引用并手动运行完整诊断，核对主机组件、ADB、ABI、root、服务文件、服务进程、transport、目标进程和推荐模式。

## 2026-07-29 实机结果

- 设备：MuMu，Android 15 / API 35 / x86_64，SELinux `Permissive`；报告只记录 `redacted:80a563aa336c4fdde661`。
- 主机：项目 `.venv` 的 Frida Python、CLI、`frida-ps` 均为 `17.16.4`。
- 设备：`su` 可用；已配置服务文件存在且版本为 `17.16.4`。
- 只读握手：精确设备进程枚举成功；设备侧未观察到名为 `frida-server` 的进程，因此整体状态为 `degraded`。
- `strict`：运行 `d50b88e8-80cd-4f36-8491-df65781589a5`，`spawn_suspended` 返回 `frida_server_unavailable`，无静默降级，生成 D 级边界报告。
- `balanced`：最终运行 `2003236c-397f-46e0-8ea3-1b4b057d1643`，依次保留 `spawn_suspended → attach_existing → launch_then_attach` 三次尝试；前两项分别记录服务不可用、目标进程未运行，启动后附加再次得到 `frida_server_unavailable`，生成 D 级边界报告。
- 网络采集器成功启动但观察到 0 条请求；结论保持为“零请求”，未据此确认无网络行为或存在 SSL Pinning。
- 清理：`resource_cleanup=success`，设备代理恢复为原值，未观察到本任务残留的 `mitmdump`、监听端口或托管服务进程。

## 动态任务核对项

1. `strict` 只尝试 `spawn_suspended`。
2. `balanced` 按真实能力尝试 `spawn_suspended`、`attach_existing`、`launch_then_attach`。
3. 报告包含 `frida_diagnostics`、各模式 attempt、`resource_cleanup`、`evidence_evaluation`。
4. Hook 事件、证据等级、进程退出分类、零请求说明和代理恢复均基于已落盘证据。
5. 阻塞时仍写出静态证据、网络侧观察、真实错误码、失败尝试和能力边界。

## 验收后检查

```powershell
adb -s TARGET_DEVICE get-state
adb -s TARGET_DEVICE shell settings get global http_proxy
Get-Process mitmdump,mitmproxy -ErrorAction SilentlyContinue
Get-NetTCPConnection -State Listen |
  Where-Object LocalPort -ge 8080 |
  Where-Object LocalPort -le 8090
```

报告按“已确认、未知、推断”三类边界填写；环境阻塞不会覆盖真实失败证据。
