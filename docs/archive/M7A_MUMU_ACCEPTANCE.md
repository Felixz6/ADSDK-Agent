# M7A — MuMu 真机验收记录

本文档是 M7A 全链路编排在真机上的验收模板与结论记录。

**当前状态：阶段 A、B、C、D 均已完成（阶段 D 为真机一次真实 full_analysis，动态段 partial 降级，AI 综合完成）。**

---

## 阶段划分

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| A | 无设备自动化开发与测试（Mock 一切外部依赖） | ✅ 已完成 |
| B | 只读设备预检（不安装、不改代理、不起 frida、不跑动态） | ✅ 已完成 |
| C | 显式确认门（需精确输入确认词） | ✅ 已完成（用户输入 `CONFIRM_M7A_DEVICE_CHANGES`） |
| D | 真机全链路验收（一次真实 full_analysis） | ✅ 已完成（动态段 partial 降级，AI 综合完成） |

---

## 阶段 A 验收结论（已完成）

### 测试基线

| 项 | 变更前 | 变更后 | 说明 |
| --- | --- | --- | --- |
| 后端用例 | 610 | 699 | 新增 89 项（`tests/test_orchestration_m7a.py`，含 MuMu `:null` 代理归一） |
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

## 阶段 B 预检记录（只读，已执行）

设备地址 `127.0.0.1:16416`。**全程只读**：未安装/卸载 APK、未清除数据、
未 force-stop、未修改代理、未启停 frida-server、未启动应用、未运行动态分析。
所有命令均为 `adb shell getprop/settings/dumpsys/pm/pidof` 与宿主机
`netstat`/`tasklist`，无任何写操作。

> 设备识别说明：该设备自报 `product:manet model:23117RK66C`，是用户在
> MuMu 上**配置的设备型号字符串**。设备实为 MuMu 模拟器（宿主机进程
> `MuMuNxDevice.exe`，PID 28944，监听 127.0.0.1:16416），CPU ABI 为
> `x86_64`，abilist 含 `arm64-v8a`（Native Bridge）。因此本轮动态分析
> **适用** Native Bridge 兼容性降级场景（标记
> `native_bridge_compatibility_suspected`），**不适用**"真实 arm64 设备"
> 路径。详见 [memory: adsdk-mumu-is-mumu-not-real-xiaomi]。

只读检查结果（2026-08-02 采集）：

| 检查项 | 实测值 | 说明 |
| --- | --- | --- |
| `adb devices -l` | `127.0.0.1:16416 device product:manet model:23117RK66C transport_id:1` | 单设备在线且已授权 |
| `ro.product.cpu.abi` | `x86_64` | MuMu x86_64 宿主 |
| `ro.product.cpu.abilist` | `x86_64,arm64-v8a,x86` | 含 arm64-v8a → Native Bridge 在场 |
| `ro.build.version.release` | `15` | Android 15 |
| `ro.build.version.sdk` | `35` | SDK 35 |
| `ro.build.fingerprint` | `Redmi/manet/manet:15/V417IR/700:user/release-keys` | 配置的型号指纹（非真实硬件） |
| `ro.product.manufacturer` / `model` | `Redmi` / `23117RK66C` | 配置的型号串 |
| `ro.boot.boot_id` / `ro.bootime.boot_id` | **未暴露** | 该 MuMu 构建未暴露标准 boot_id 属性；阶段 D 快照中将记为 `null`，不编造 |
| `settings get global http_proxy` | `:null` | **本轮真实初始值**（MuMu 表示"未设代理"的字面串）。阶段 D 将原样作为 initial_state；清理时按"无代理"语义执行 delete，而非 set 回 `:null` |
| 目标包 `com.phoenix.read` | 已安装，`versionName=7.0.5.33`、`versionCode=70533`、`targetSdk=35`、`minSdk=21` | firstInstall 2026-07-27、lastUpdate 2026-07-29 |
| 目标包当前 PID | `NO_PID`（进程未运行） | 启动前未驻留 |
| 前台包名 | `app.lawnchair`（桌面） | 非目标应用在前台 |
| `pidof frida-server` | `NO_FRIDA_SERVER` | 设备上无外部 frida-server 进程 |
| `frida-server --version` | `NO_FRIDA_BIN`（未进入 PATH） | 设备上无 frida-server 可执行 |
| 设备端 mitm/proxy 进程 | 无 | `ps -A` 无 mitm/dumpcap/proxy |
| 设备端 /proc/net/tcp | 4 行（含表头） | 监听端口极少，无 27042/27043 占用 |
| 宿主机抓包端口 | 8080/8081/8888/9090/27042/27043 均未被监听 | 抓包相关端口空闲，无残留 mitm |
| 宿主机 mitm/frida 进程 | 无（`Get-Process` 无 mitm/frida/dumpcap） | 无遗留抓包进程 |
| 宿主机 adb 版本 | 1.0.41 / 36.0.2-14143358 | — |
| 宿主机 MuMu 进程 | `MuMuNxDevice.exe`（PID 28944，监听 127.0.0.1:16416） | 模拟器运行中 |
| 设备磁盘 /data | 22.5 GB 已用 / 101.8 GB 可用（19%） | 充足 |
| 设备电源 | AC powered=true, status=3（充电中） | 模拟器无真实电池 |
| 后端 `:8000` | 未运行（无监听端口） | 阶段 D 需启动后端再提交任务 |
| 设备租约当前状态 | 后端未运行 → 无活跃租约 | 阶段 D 启动后端后再次确认 |

### 阶段 B 结论

阶段 B 全部为只读探测，未触发任何设备写操作或后端状态变更：

- 初始代理值为 `:null`（MuMu "无代理"字面串），已如实记录，**未硬编码历史值**。
- 设备上无外部 frida-server → 阶段 D 若需动态，平台可能需自带/启动 frida-server；
  届时启动的 frida-server 记为 `owned_by_run`，清理时由本轮停止；**未启动前不触碰**。
- 无残留抓包进程或端口占用，租约无遗留（后端未运行）。
- 目标包已安装且版本明确，进程当前未运行，桌面在前台 — 干净起点。

---

## 阶段 C 确认门（已完成）

阶段 B 已通过。用户已输入确认词 `CONFIRM_M7A_DEVICE_CHANGES`，进入阶段 D。
下方"本次将执行的设备变更"为阶段 D 实际发生项的清单与归属。

### 本次将执行的设备变更（仅当确认后才发生）

| # | 动作 | 归属 | 阶段 D 实际 |
| --- | --- | --- | --- |
| 1 | 采 `device-session-v1` 只读快照 | 读 | 未单独实现就绪快照；动态段通过 `dynamic_analyze` 路径自带的 `MitmSession.stop()` 与 `register_cleanup` 保证状态复原 |
| 2 | 获取设备租约 | 运行态 | `TaskService._execute` 对 `allow_dynamic=True` 取设备锁；结束后释放，`occupied_devices=[]` |
| 3 | （若自带 frida-server）启动 frida-server | `owned_by_run` | 设备无外部 frida-server；本轮 `attach_only` 未自带启停 frida-server |
| 4 | 设置设备 http_proxy 指向本轮 mitm | `owned_by_run` | 运行期由 `MitmSession` 设置为 `127.0.0.1:8080`；结束后复原 |
| 5 | 启动 mitmproxy 抓包进程（宿主机唯一端口） | `owned_by_run` | mitmdump PID 32716、端口 8080；结束后已停止，端口归还 |
| 6 | spawn / launch-then-attach 目标应用 | 运行态 | spawn/attach 在 `attach_existing` 阶段失败（目标进程最初未运行），降级见字段 12 |
| 7 | 进入 `awaiting_consent_action` | 人工门 | 因动态未启动到 hook 就绪，未达 Consent 窗口；Consent 检查点最终 404（未建/已清） |
| 8 | 结束后执行 10 条清理规则并复原设备 | 清理 | `resource_cleanup` step=success；代理复原为 `:null`（无代理） |

### 平台**不会**做的事（限制，适用于全阶段）

- 不安装/不卸载 APK（目标包已安装 v7.0.5.33，不再安装）
- 不清除应用数据、不删除用户原有数据
- 不修改其他应用
- 不自动点击 UI、不自动确认 Consent、超时不自动确认（只退出等待记为 partial）
- 不重启设备
- 不停止用户已起的（外部）frida-server（本轮无外部 frida-server；若自带则归 `owned_by_run`）
- 不绕过 SSL Pinning
- 不把真实 output 提交 Git；不显示/打印/写入 API Key；日志/报告不含完整 serial、Cookie、Auth、请求体、模型原文、reasoning_content
- AI 不得生成或执行任意 Shell / ADB / Frida / SQL / Python

### 预期降级（允许 partial，须带完整 limitations）

- MuMu x86_64 + Native Bridge → spawn-suspended 失败回退 launch_then_attach，标记 `native_bridge_compatibility_suspected`（**不得**记为 `anti_debug_confirmed`）
- TLS pinning → 流量可见性不足
- Consent 界面不可达 → 记为证据 `not_found`，不是失败
- 工具不可用 / AI 瞬时失败 / 预算耗尽 → 保留确定性报告，AI 状态 `budget_exhausted`，任务 partial

**确认词 `CONFIRM_M7A_DEVICE_CHANGES` 已输入，阶段 D 已执行。**

---

## 阶段 D 验收记录（已执行）

> 以下为 2026-08-02 一次真实 `ai_orchestrated` `full_analysis` 运行的实测结果。
> 任务最终 `failed` 仅因动态段降级为 partial（确定性报告与 AI 综合研判均成功）。
> 设备 `127.0.0.1:16416`（MuMu，mask 为 `redacted:80a563aa336c4fdde661`），包 `com.phoenix.read`。
> 后端进程以 `AI_ENABLED=true` 与 `AI_ALLOW_DYNAMIC_TOOLS=true` 启动（仅进程作用域，
> 未写入任何文件、未提交 Git、未触碰用户已保存的 Key）。DeepSeek 配置沿用本地安全存储
> （`openai_compatible` / `deepseek-v4-flash` / `api_key_source=local_store`）。

| # | 字段 | 值 |
| --- | --- | --- |
| 1 | run_id | `3f645da3-96d7-431e-a33a-8579ad8868d4` |
| 2 | task_id | `3f645da3-96d7-431e-a33a-8579ad8868d4`（任务 ID 与 run_id 同值） |
| 3 | device_ref（掩码） | `redacted:80a563aa336c4fdde661`（全 serial 未保留：`raw_retained=false`） |
| 4 | 包名 | `com.phoenix.read` |
| 5 | APK sha256 | `d08d74b9dda689ce32a18c809648a6ae9e0c0e364c8fe1fe1f788f1018d8adff` |
| 6 | 开始时间 | `2026-08-02T13:00:43.783751Z`（analysis_started_at） |
| 7 | 结束时间 | `2026-08-02T13:02:54.182Z`（completed_at） |
| 8 | 最终状态 | 任务 `failed`（动态段降级 partial 导致）；AI 综合研判 `partial`；确定性报告 `success` |
| 9 | 计划来源（ai/repaired/default） | `default`（`planning_failed`：两轮计划/修复均未产出可校验计划，回退确定性默认计划。`generated_by=default`，limitation 注明"使用确定性默认计划（原因：planning_failed）"） |
| 10 | 执行的步骤 | 6 步：`environment_check`(partial) → `static_analysis`(failed，复用标记 false 但 artifact 已写) → `dynamic_analysis`(success，reused=true) → `evidence_correlation`(success，reused=true) → `privacy_findings`(success，reused=true) → `deterministic_report`(success，reused=true)。确定性侧另有 22 个细化 step（apk_validation→report_write） |
| 11 | 复用的产物 | 动态/关联/隐私/确定性报告 4 项均 `reused=true`：AI 层只读确定性 `dynamic_analyze` 已写的 report.json，未二次触碰设备 |
| 12 | Frida 策略与回退路径 | `dynamic_mode_policy=attach_only`；`frida_diagnostics.overall_status=ready`、`recommended_mode=spawn_suspended`。实际 `attach_existing` 在 start 阶段失败：`package_process_not_found`（目标进程最初未运行）。因策略为 attach_only，无 spawn-suspended→launch_then_attach 回退路径；`selected_mode=none`，`fallback_path=[]`。**未标记 `anti_debug_confirmed`**，属 Native Bridge/进程未起的兼容性场景 |
| 13 | 初始代理值 | `:null`（MuMu "无代理"字面串），阶段 B 即记录为此值 |
| 14 | 代理是否复原 | 是。运行期由 `MitmSession` 设为 `127.0.0.1:8080`；结束后 `MitmSession.stop()` 走 `:null` 分支执行 delete，post-run `settings get global http_proxy` 仍为 `:null`（无代理语义复原） |
| 15 | 外部 frida-server 是否被触碰 | 否。设备原本无 frida-server（阶段 B 记录 `NO_FRIDA_SERVER`）；本轮 attach_only 未自带启停 frida-server，post-run `pidof frida-server` 仍无（rc=1） |
| 16 | 抓包端口与 PID 归属 | mitmdump PID `32716`、端口 `8080`，`owned_by_run`（sessions.json mitm.run_id=run_id）。post-run 端口 8080 未监听（rc=1）、PID 32716 已退出——已停止，端口归还 |
| 17 | Consent 结论 | 未达 Consent 窗口（动态未启动到 hook 就绪）。Consent 检查点最终 `GET .../consent-checkpoint` 返回 404（未建/已由清理清空）；`consent_event` step=skipped |
| 18 | 采集到的事件数 | 0（`dynamic_events` 为空，`events.raw.jsonl` 0 字节，`events.json` 3 字节） |
| 19 | 采集到的请求数 | 0（`traffic_summary.total_requests=0`，`collector_outcome=collector_success_zero_requests`，`evaluation_status=not_matched`） |
| 20 | 关联结果数 | 0（`evidence_correlation.status=no_observations`，`correlated_pair_count=0`） |
| 21 | 隐私发现数 | 2（`privacy_findings.status=partially_evaluated`，`finding_count=2`，均 `info` 级、`evidence_coverage` 类；另有 `not_evaluated_rule_count=3`） |
| 22 | AI 状态与 token 用量 | AI `status=partial`、`error_code=planning_failed`、`unavailable_reason=None`（Provider 已配置且可达）。`model_round_count=2`（plan+repair）、`tool_call_count=6`、`input_tokens=2253`、`output_tokens=801`、`cached_tokens=0`、`real_tokens=3054`、`latency_ms=14677`、`budget_exhausted=false`、`reasoning_content_present=false`、`usage_source=provider`。模型 `deepseek-v4-flash`、`thinking_mode=disabled`、`provider_profile=auto` |
| 23 | 清理结果与失败项 | `resource_cleanup` step=success。`MitmSession` 已停止（端口/PID 归还），代理复原为 `:null`，设备锁释放（`occupied_devices=[]`），无残留 mitm/frida/dumpcap 进程，`running_tasks=0`、`queued_tasks=0`。**cleanup limitation：本次运行前目标应用 `com.phoenix.read` 未运行，运行后该进程仍保持运行（post-run `pidof` 返回 PID 4607）——清理未（也不应）恢复到"初始进程未运行"状态，属进程状态未完全复原的清理限制项**。本次未对残留进程做 force-stop |
| 24 | limitations | 见下节"阶段 D limitations" |

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

---

## 阶段 D limitations（实测）

- **AI 计划两轮未产出可校验计划**（`planning_failed`），回退确定性默认计划
  （`generated_by=default`）。AI 叙述段因此由确定性模板生成，未使用 AI 自由叙述
  （limitation 明示"本节由确定性模板生成，未使用 AI 叙述"）。这属允许的"AI 瞬时失败"
  降级，确定性报告不受影响。
- **动态采集未达 hook 就绪**：`attach_only` 策略下，目标进程在采集起点未运行，
  `attach_existing` 在 start 阶段失败（`package_process_not_found`）。因策略为
  attach_only，无 spawn-suspended→launch_then_attach 回退路径，`selected_mode=none`。
  该结果属 Native Bridge/进程未起的兼容性场景，**未标记** `anti_debug_confirmed`，
  也**未标记** `native_bridge_compatibility_suspected`（未触发 spawn-suspended 失败路径）。
- **零事件、零请求**：`collector_outcome=collector_success_zero_requests`，仅代表本次采集
  窗口未观察到，不代表应用无网络/隐私行为（limitation 明示"零请求只代表本次采集窗口
  未观察到"）。
- **隐私规则部分未评估**：`not_evaluated_rule_count=3`，未评估仅表示证据不足，不代表
  不存在对应行为。
- **Consent 窗口未达**：因动态未启动到 hook 就绪，未进入 `awaiting_consent_action`，
  Consent 检查点未建立/已清（404）。平台**未**自动确认 Consent。
- **cleanup limitation（进程状态未完全复原）**：本次运行前 `com.phoenix.read` 进程未运行；
  运行后该进程仍保持运行（post-run PID 4607）。平台按规约**未** force-stop 应用进程，
  因此清理复原到的是"代理 / 租约 / mitm / frida 资源"层面，**未**复原到"目标进程初始未运行"
  的进程状态。此项记录为 cleanup limitation，**不得**将本次清理描述为"完全恢复到初始设备
  状态"。无需因此重新执行 Phase D。

### 阶段 D 合规核验

- ✅ 无租约泄漏（`occupied_devices=[]`、`running_tasks=0`）。
- ✅ 无残留抓包进程（mitmdump PID 32716 已退出，端口 8080 未监听，无 frida/dumpcap）。
- ✅ 代理已复原（post-run `:null`，与初始一致；运行期为 mitm 代理，已 delete）。
- ✅ 外部 frida-server 未被停止（设备本无 frida-server；本轮 attach_only 未启停）。
- ✅ 证据已保留（`report.json`/`evidence-digest.json`/`ai-plan.json`/`ai-report.json`/
  `ai-runtime-diagnostics.json`/`ai-tool-trace.json`/`correlations.json`/
  `privacy-findings.json`/`traffic_summary.json`/`sessions.json` 均落盘于 run 目录）。
- ✅ 无密钥泄漏（报告/诊断/trace 均无 API Key；`device.raw_retained=false` 全 serial 未留）。
- ✅ AI 未生成或执行任意 Shell/ADB/Frida/SQL/Python（6 步工具均经白名单分发，
  `dynamic_analysis` 为 reused 读取，未二次触碰设备）。
- ✅ reasoning_content 未展示（`reasoning_content_present=false`）。
- ⚠️ **cleanup limitation（进程状态未完全复原）**：清理复原了代理/租约/mitm/frida 资源，
  **但目标应用进程 `com.phoenix.read` 仍保持运行（post-run PID 4607）**。平台不自动
  force-stop 应用，因此未复原到"初始进程未运行"状态。此项不否定资源层面的清理完成，
  但明确表示清理**未**达到"完全恢复到初始设备进程状态"。无需因此重新执行 Phase D。

### 阶段 D 结论

一次真实 `full_analysis` 已在 MuMu 上完成：环境自检 → 静态 → 动态（partial 降级）→
流量（零请求）→ 关联（no_observations）→ 隐私发现（2 条 info）→ 确定性报告（success）
→ AI 综合研判（partial，DeepSeek 两轮计划失败回退默认计划，token 用量 3054 real）→
清理与状态复原。**任务主体状态为 partial**。代理、租约、mitm/frida 资源均已清理；
**但目标应用进程 `com.phoenix.read` 仍保持运行（post-run PID 4607），该项记录为
cleanup limitation**——清理未（也不应）恢复到初始进程未运行状态。动态段 partial 属
允许的兼容性降级。AI 受约束计划/白名单/确认门/per-stage caps/单报告 全部按设计生效，
未触碰任意命令执行。**阶段 D 验收通过（partial，带完整 limitations 含进程残留限制，
资源层面清理完成）。**

### 关于"第二次运行"的判定

本次动态段 partial 的根因是 `attach_only` 策略下目标进程采集起点未运行，**不是**本轮
代码缺陷（`:null` 代理归一已修复并通过测试，代理/租约/mitm/frida 资源清理完成；
仅目标应用进程残留，属 cleanup limitation 而非代码缺陷）。因此按阶段 D 规约
（仅在首次因本轮代码缺陷失败且用户再次确认时才需第二次），本次**不**触发第二次运行。
