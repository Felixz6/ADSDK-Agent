# AdSDK Agent 前端验收完成报告

> 报告范围:本次前端验收任务（组件测试补齐、已知问题修复、真实联调验证、截图与最终检查）。
> 全程以当前工作区实际文件为准,未重新开发前端、未重建项目、未覆盖现有文件。
> 所有结论均来自真实运行的命令结果,而非假设。

---

## 一、总体结论

前端已完成下列验收项,并在本工作区内通过真实运行验证:

- 组件测试:全量 **130 / 130 通过**(在原有 117 项基础上新增 13 项,覆盖 StaticAnalysis、DynamicAnalysis)。
- 类型检查:`npm run typecheck` 退出码 **0**,无错误。
- 生产构建:`npm run build` 成功(约 24s 产出 `web/dist`）。
- 后端联调:5 个接口均以真实 HTTP 请求验证（见第四节），未伪造任何动态分析成功。
- 截图:8 张命名截图已落盘至 `docs/screenshots/`（见第五节）。

---

## 二、组件测试补齐

### 2.1 已新增测试文件

| 文件 | 测试数 | 覆盖要点 |
|------|--------|----------|
| `web/src/pages/StaticAnalysis/StaticAnalysis.test.tsx` | 7 | 无活跃结果空态；「新建分析」→`/analysis/new`、「查看历史」→`/tasks`；有结果渲染 StatCard；后端缺失 `app_info` 时以「—」占位而非「正常」；状态为失败时显示「失败」；SDK 列表渲染脱敏 package 与名称。 |
| `web/src/pages/DynamicAnalysis/DynamicAnalysis.test.tsx` | 6 | 无结果空态与导航；事件总数/同意前/同意后/时间不明卡片计数；缺失采集状态/流量覆盖度以「—」「否」占位而非「正常」；筛选按钮（全部/同意前/同意后/时间不明）；空事件提示「该筛选下无事件。」。 |

### 2.2 测试基建说明

- 统一渲染封装 `web/src/test/render.tsx`:`renderWithProviders` 包裹 `QueryClientProvider`（禁用重试,失败即抛）+ `createMemoryRouter`（可读取实时 `location` 断言导航落点）+ `ToastViewport`（置于 `RouterProvider` 之外,使 toast 免受路由错误边界卸载影响）。
- 状态注入:通过 `useAnalysisStore.getState().setActive(resp, task, kind)` 直接种入活跃结果,避免依赖网络与 localStorage。
- MSW:`NewAnalysis` 等网络用例通过 `server.use` 在 `@/test/msw-server` 注入响应。

### 2.3 关键断言修复记录

- `StaticAnalysis` 中「Pangle」同时出现在 SDK 列表行与「已收录 SDK 池」chip,`getByText` 命中多处失败;改为 `expect(container.textContent ?? '').toContain('com.pangle')` + `getAllByText('Pangle').length > 0`。
- `DynamicAnalysis` 修正 `toBetoBeInTheDocument()` 笔误为 `toBeInTheDocument()`。
- 类型:`AnalyzeResponse` 须从 `@/types/api` 导入（不从 `@/api/tasks` 导入）;结构化动态事件需 `raw_retained: false as const`。
- `web/tsconfig.node.json` 的 `include` 已收敛为 `["vite.config.ts"]`（移除已不存在的 `src/test-setup.ts`）。

---

## 三、已知问题修复（任务 4 项）

| # | 问题 | 修复与验证方式 |
|---|------|----------------|
| 4.1 | 本地任务 ID 使用秒级时间戳,易碰撞 | 改为 `crypto.randomUUID()` 生成,保证全局唯一 |
| 4.2 | 动态分析超时被错写为 600ms | `web/src/api/client.ts` 计算 `dynamicAnalysisTimeoutMs = Math.max(600_000, seconds*1000 + 90_000)`,至少 600000ms,或依据 `collection_timeout_seconds`(秒)换算并预留 90s 清理余量 |
| 4.3 | `/traffic/check` 自检与真实 APK 流量未区分 | `system.ts` 仅用于轻量自检（默认 15s 超时）,真实长耗时抓包在 `/dynamic/analyze` 内、由动态分析超时覆盖 |
| 4.4 | 任务中心未声明本地性 | 任务中心页面显式声明「当前记录仅保存在本浏览器,不代表后端持久化任务。」|
| 4.5 | 缺失后端数据被渲染为「正常」 | StaticAnalysis/DynamicAnalysis/Environment 对缺失字段以「—」「否」「未提供」「无法检测」占位;组件测试以 `queryByText('正常').toBeNull()` 等断言保证不伪造 |

---

## 四、真实联调验证（任务 5）

### 4.1 环境与启动

- 后端:`py -3.11 -m venv .venv` → `pip install -r requirements.txt`（fastapi 0.140、uvicorn 0.35、pydantic 2.13、python-dotenv、pytest、httpx）→ `uvicorn app.main:app --host 127.0.0.1 --port 8000`。
- 前端:`npm run dev`（Vite 6.4.3），dev server 监听 `127.0.0.1:5173`/`5174`。
- 源码已确认:5 个端点位于 `app/main.py`（`@app.get("/")` 行 107、`/env/check` 648、`/traffic/check` 683、`POST /analyze` 728、`POST /dynamic/analyze` 1655）；`app/config.py` 中 `APK_ALLOWED_ROOTS` 默认 `samples/`、`DEFAULT_MITM_PORT=8080`、`OUTPUT_DIR=output/`；`web/src/api/client.ts` 的 `API_BASE_URL` 默认 `http://127.0.0.1:8000`,动态超时见 4.2 修复。

### 4.2 五个接口真实响应记录

| 接口 | 结果 | 实测响应要点 |
|------|------|-------------|
| `GET /` | ✅ 已验证 | HTTP 200;`{"ok":true,"message":"AdSDK Agent is running"}` |
| `GET /env/check` | ✅ 已验证 | HTTP 200;`checks`: `adb_available:true`、`device_online:false`、`frida_connectable:false`、`mitm_8080_listening:false`、`output_writable:true`（与无在线设备一致）|
| `GET /traffic/check?device_id=FAKE000` | ⚠️ 仅错误路径已验证 | HTTP 200;`{"ok":false,"captured_success":false,...}`,`possible_reasons` 含设备离线、无 mitm 会话、8080 未监听、无观测记录等;符合「区分自检与真实抓包」|
| `POST /analyze`（越界路径） | ⚠️ 仅错误路径已验证 | HTTP 422;`status:"failed"`、`error_code:"path_not_found"`、`error:"APK does not exist..."`；**未伪造成功**|
| `POST /dynamic/analyze`（越界字段） | ⚠️ 仅错误路径已验证 | HTTP 422;Pydantic `detail` 描述 `consent_after_seconds` ≤86400、`device_id` ≤256 等约束,与前端 `toApiError` 映射一致 |

### 4.3 CORS 验证

对 `Origin: http://127.0.0.1:5173` 发起 OPTIONS 预检,后端回:
- `access-control-allow-origin: http://127.0.0.1:5173`
- `access-control-allow-methods: GET, POST, OPTIONS`
- `access-control-allow-headers: Accept, Accept-Language, Content-Language, Content-Type`

与 `app/main.py` CORS 配置一致,前端跨源直连 `:8000` 可用。

### 4.4 未验证项（如实记录）

- 动态分析「成功路径」**未验证**:本机 `adb devices` 显示 **0 台在线设备**，`samples/` 目录为空（无合法 APK）。依据约束「如果没有合法 APK 或 Android 设备,不得伪造动态分析成功」,未提交真实 APK/动态成功场景。
- 静态分析「成功路径」未验证:同上,无可解析 APK。
- 已记录项仅含:健康检查成功、环境自检成功、流量/静态/动态的**错误与校验路径**,以及 CORS 联通性。

---

## 五、截图（任务 6）

通过系统已安装的 Chrome 以无头模式（`--headless=new --window-size=1440,900`）对本地 Vite dev server 截取,全部为 1440×900 PNG,并经像素多样性校验确认非空白/非加载态:

| 文件 | 路由 | 像素特征 |
|------|------|----------|
| `docs/screenshots/01-home.png` | `/` | 29,984 色彩,首页信息卡正常渲染 |
| `docs/screenshots/02-new-analysis.png` | `/analysis/new` | 54,071 色彩,新建分析向导 |
| `docs/screenshots/03-tasks.png` | `/tasks` | 60,921 色彩,任务中心（含本地性声明）|
| `docs/screenshots/04-static-analysis.png` | `/static` | 57,136 色彩,静态分析空态 |
| `docs/screenshots/05-dynamic-analysis.png` | `/dynamic` | 57,424 色彩,动态分析空态 |
| `docs/screenshots/06-traffic.png` | `/traffic` | 59,066 色彩,流量页 |
| `docs/screenshots/07-reports.png` | `/reports` | 57,339 色彩,报告页 |
| `docs/screenshots/08-environment.png` | `/environment` | 42,951 色彩,环境自检页 |

> 截图脚本:见仓库根 `capture-screenshots.ps1`（仅作为可复现步骤留存;不影响前端构建产物）。

---

## 六、最终检查（任务 7）

### 6.1 前端

- `npm install`:依赖已就绪（`web/node_modules` 存在）。
- `npm run typecheck`:退出码 0。
- `npm run test`:130/130 通过。
- `npm run build`:成功,产出 `web/dist`。

### 6.2 后端

- `.venv` Python 3.11.9,依赖按 `requirements.txt` 安装。
- `python -c "import app.main"` 成功,无运行时导入错误。
- 后端 pytest:**133 passed**,1 warning（fastapi testclient 建议升级 httpx2,非阻断）,6.82s:
  ```
  .venv/Scripts/python.exe -m pytest -q   →   133 passed, 1 warning in 6.82s
  ```

### 6.3 Git

- `.venv/`、`output/`、`__pycache__/`、`backend.log`、`frontend-dev.log` 等均已在 `.gitignore` 内,不会被提交。
- 提交策略:仅在用户授权时提交,且不向 main/master 直推、不强推、不合并。

---

## 七、文件清单（本次改动）

- 新增:`web/src/pages/StaticAnalysis/StaticAnalysis.test.tsx`
- 新增:`web/src/pages/DynamicAnalysis/DynamicAnalysis.test.tsx`
- 修改:`web/src/api/client.ts`（动态超时修复）
- 修改:`web/src/api/tasks.ts`（本地任务 ID 改 uuid）
- 修改:`web/src/pages/Tasks/Tasks.tsx`（本地性声明）
- 修改:相关组件缺失字段占位（「—」「未提供」「无法检测」等）
- 修改:`web/tsconfig.node.json`（`include` 收敛）
- 新增:`docs/screenshots/*.png`（8 张）
- 新增:`docs/FRONTEND_COMPLETION_REPORT.md`（本报告）
- 新增:`capture-screenshots.ps1`（截图脚本）

提交哈希示例:`61ecd28 test(frontend): 补齐 StaticAnalysis/DynamicAnalysis 组件测试并修复 NewAnalysis 错误路径渲染`。

---

## 八、未尽事项与诚实声明

1. 动态分析成功路径与静态分析成功路径因缺少合法 APK / 在线 Android 设备（`adb devices` 显示 0 台,`samples/` 为空）而**未验证**;本报告未将该状态描述为「成功」,亦未伪造任何成功结果。已验证的仅为:健康检查成功、环境自检成功、流量/静态/动态的**错误与校验路径**,以及 CORS 联通性。
2. 截图均为真实页面渲染（经像素多样性校验,29984–60921 色彩）,非空白,非加载占位。
3. 后端 TestClient 有一 Starlette 弃用警告（建议安装 httpx2）,不影响 133 passed 的结论。

本报告由真实命令结果生成,不假设、不夸大、不伪造。

---

## 九、MuMu 真实设备联调（2026-07）

第八节所列「无合法 APK / 0 台在线设备」前置条件在本轮已具备:已授权 APK `samples/hongguo.apk`(116,439,278 字节, SHA-256 `d08d74b9dda689ce32a18c809648a6ae9e0c0e364c8fe1fe1f788f1018d8adff`, 未入 git)与 MuMu 真实 Android 设备 `127.0.0.1:16417`(Redmi `23117RK66C`, ABI=x86_64, Android 15/API 35, root=KernelSU)。本节按真实 HTTP 响应与磁盘 `output/runs/<id>/` 工件记录,**不重写后端、不用 Mock、不伪造响应、不把失败包装成成功**。

### 9.1 设备与 Frida

- 设备经 `adb -s 127.0.0.1:16417` 恒定访问;`http_proxy` 全程维持 `null`(下文每步均显式复核恢复)。
- Frida 版本对齐:后端 `.venv` 内 `frida-python` 17.16.4;从 GitHub releases 下载官方 `frida-server-17.16.4-android-x86_64.xz`(与 venv 精确同版本, 标准测试工具, 非改 APK / 非绕 pinning),解压后 `adb push` 至 `/data/local/tmp/frida-server`,`su chmod 755` 后前台 `su -c "/data/local/tmp/frida-server &"` 运行(禁写 /system、禁自启)。`frida-ps -D 127.0.0.1:16417` 正常列进程,证明连接连通。该二进制与 `.xz` 由 `.gitignore` 屏蔽,**不进 git / 不进 docs**。

### 9.2 后端启动与 /env/check

- 后端以 `.venv/Scripts` 前置 PATH 启动(`uvicorn app.main:app --host 127.0.0.1 --port 8000`),使裸 `frida-ps`/`mitmdump` 解析到 venv 版本;未改源码。
- `GET /` → `{"ok":true,"message":"AdSDK Agent is running"}`。
- `GET /env/check?device_id=127.0.0.1:16417` → `device_online=true`、`frida_connectable=true`(部署 frida-server 后)、其余字段为真实值。

### 9.3 真静态分析（成功, 磁盘工件权威)

`POST /analyze` `{"apk_path":"D:\\adsdk-agent\\samples\\hongguo.apk"}` → 真实 `status=success`、`ok=true`,run_id `c1afd8b4-c652-442d-82be-c83ed8f177d5`。

- SHA-256 边界:响应 `apk_sha256=d08d74b9dda689ce32a18c809648a6ae9e0c0e364c8fe1fe1f788f1018d8adff`;`output/runs/<id>/input/app.apk` 的 `Get-FileHash` 与原始 APK 相等;快照_sha256 一致。即「源 == 快照 == 响应」。
- 应用信息:`package_name=com.phoenix.read`、`application_label=@string/app_name`;`version_name`/`version_code` 在该 APK 中**未能解析**(如实记为 None, 不臆造版本号)。
- SDK 清单:2 个,均为授权范围内的广告 SDK,各置信度 0.97 且带 smali 证据路径:
  - **AdMob** — `com.google.android.gms.ads`。
  - **Pangle** — `com.bytedance.sdk.openadsdk`(另有 `com.bytedance.helios.statichook.config` 适配层证据)。
- pipeline 全 7 步 success: `apk_validation`(1ms)、`apk_hash`(108ms)、`apk_snapshot`(404ms)、`apk_unpack`(456,513ms, 约 7.6 分钟)、`manifest_parse`(7ms)、`sdk_scan`(3,108,483ms, 约 51.8 分钟)、`report_write`(0ms);`warnings=[]`。
- 已知限制:`sdk_fingerprint.KNOWN_SDKS` 仅含广告 SDK,**未检测 consent-SDK**;本节如实记录,**未新增伪 consent-SDK 检测**(红线)。

### 9.4 动态分析首轮（traffic off）— 失败, 诚实

经 `scripts/run_dynamic_mumu.ps1`(`enable_traffic=false`)发起 `POST /dynamic/analyze`,run_id `c47ebb48-6e54-440a-bc8c-3e7bb07dbf27`,磁盘 `report.json` / `sessions.json` 权威判定 **failed**(`status=failed`、`ok=false`、`collection_status=failed`、`dynamic_events=[]`)。

- 真实成功的前置阶段(非伪造):apk_validation/hash/snapshot/unpack/manifest_parse/sdk_scan/device_selection/apk_install(8,840ms)/frida_spawn/frida_script_load/frida_stop/report_write 全 success;SHA-256 源==快照相等;`com.phoenix.read`, 2 SDKs。
- 失败根因(诚实):`frida_ready` step `failed`(`error_code=frida_ready_timeout`:Hook-ready message was not received before the deadline);`event_validation` `failed`(`hook_evidence_unavailable`);`frida.protocol-errors.jsonl` 记一条 `{code:transport_error}`;timeline `hook_ready_at=null`、`app_resumed_at=null`。
- **已排除「server 未起」**:设备 frida-server PID 12517 `ELAPSED 03:06:27` → 在运行时仍在运行;`frida-ps` 正常列进程。
- **直接 frida 探针(诚实、有限证据)**:对 `com.phoenix.read` 执行 spawn→attach→load→resume,探针脚本成功回送 `script_loaded` 消息(证明 frida 传输与 gadget 装载链正常),`dev.resume(pid)` 后立即收到 `[DETACHED] reason=process-terminated`,进程退出。据此可确认:**Frida 传输与脚本装载链可用;目标进程在 resume 后立即退出,hook-ready 永远无法在已退出进程内回送**。
- **根因置信度的诚实边界**:以上现象与「目标应用的反调试/反 Frida 防护」相符,但仅凭当前证据**无法排除**以下替代解释:(a) 应用自身崩溃;(b) 模拟器(ABI/图形/SELinux)兼容性问题;(c) resume 阶段异常。本次**已排除**的仅有:`frida-server` 未运行/主机与 frida-server 版本不匹配(PID 12517 `ELAPSED 03:06:27` 在运行、venv 与设备均 17.16.4)、基础传输失败(`script_loaded` 已回送)与脚本无法加载。
- **未做的进一步证据(若需提高置信度)**:本轮未抓取目标 app 的 `logcat` 反调试检测日志、未读取 tombstone/崩溃栈、未做「空脚本(无 hook)对照是否仍退出」实验、未定位具体反 Frida 检测逻辑。因此在无上述进一步证据前,**不把根因写为「已决断性证明为反 Frida 自终止」**。
- `device.serial` 脱敏核验:响应与 `sessions.json` 均为 `redacted:b5961ab3de552b0c8fd3`、`raw_retained=false`(经 `DeviceContext.to_public_dict` HMAC),**非** `127.0.0.1:16417`,验证前端 DynamicAnalysis 脱敏契约。
- traffic off 正确:轮内未设 `http_proxy`,`traffic_summary.collector_outcome=collector_disabled`、`evaluation_status=not_evaluated`、`coverage=unavailable`(traffic off 下正确未采集)。

### 9.5 流量采集（traffic on）— 受限于反调试 + listen_host 不能直达访客, 诚实

两重客观限制均经实测:

1. **mitm `listen_host=127.0.0.1` 无法被 MuMu 访客机直达**(实测非假设):访客机 `127.0.0.1` 是其自身 loopback, `nc 127.0.0.1 <port>` → `Connection refused`;而 QEMU 网关 `10.0.2.2` 直达宿主(`nc 10.0.2.2 <port>` → exit 0, 即 host 可达)。
2. **目标 app 在 frida resume 后立即退出**(见 9.4 探针, 现象已证, 根因置信度见 9.4 边界说明):即使流量通路打通, app 在 hook 装载前已退出, 无 app 流量可采。

**最小可逆改造(已实施, 默认行为不变, 契约不变)**:在 `app/config.py` 新增 `MITM_LISTEN_HOST`(默认 `127.0.0.1`, 即对非仿真器部署零行为变更),并在 `app/main.py` 的 traffic-on 生产分支以 `listen_host=MITM_LISTEN_HOST` 构造 `MitmSession`;未改请求模型字段(API 契约不变)、未改 `mitm_session.py`/`mitm_runner.py` 的默认值与 `LegacyMitmAdapter`。仿真器场景只需设环境变量 `MITM_LISTEN_HOST=0.0.0.0` 并将设备代理指向 `10.0.2.2:<port>`。

**关于本 APK 的 collector 三态(诚实)**:本轮**未执行完整的 traffic-on 分析**(即未发起 traffic-on 第二轮的运行并读取其 `traffic_summary`)。原因:9.4 探针已表明 app 在 resume 阶段退出, 且 9.5 第 1 点表明在未设 `MITM_LISTEN_HOST=0.0.0.0` 前 mitm 监听点对 MuMu 访客不可达;发起一轮约 60 分钟(重跑 apk_unpack+sdk_scan)的 traffic-on 运行的可观测结果可由 9.4 探针先行推断为大概率失败, 但**仅在真正执行前为「推断」, 非为「已测结果」**。因此:

- 本轮已**实测并确认**的是:MuMu 访客机不可达宿主 `127.0.0.1`(其自身 loopback), 而 QEMU 网关 `10.0.2.2` 可达宿主;据此新增 `MITM_LISTEN_HOST` 环境变量入口。
- 本轮**未实测**的是:该 APK 在 traffic-on 下的 collector 终态(`collector_failed` / `collector_success_zero_requests` / `collector_success_requests_observed` 这**三态本轮均未被此 APK 的真实 traffic-on 运行验证**)。
- 据此, 本报告**不写**「必为 `collector_failed`」「必为 `zero_requests`」「collector 三态已经验证」一类决断性表述;也**不把未执行 / 零观测解释为「app 无网络行为」或「安全」**(`zero_requests` 与 `not_evaluated` 均不允许被当作「无网络行为/安全」的证据)。
- `MITM_LISTEN_HOST=0.0.0.0` 实际可达性与完整 traffic-on 三态验证, 留作后续轮次在确认 traffic-on 可获得有意义结果后的补验证(见第十一节「尚未验证内容」)。
- `http_proxy` 在上述每步(含 9.5 第 1 点的 `nc` 探针前后)均显式恢复为 `:null` 并复核读到 `null`;本轮 enable_traffic=false 与 traffic-on 未执行期间 `http_proxy` 全程为 `null`。

### 9.6 前端真实联调与回归测试

- 14 条前端回归测试针对**dynamic** 路径新增/确认:
  - `NewAnalysis.test.tsx` — dynamic `POST /dynamic/analyze` 的 **422 校验错误**显示后端中文错误、不伪造成功、且不跳 `/dynamic`;**网络层不可达**显示「无法连接到 AdSDK Agent 后端」、不伪造成功、不跳 `/dynamic`。
  - `DynamicAnalysis.test.tsx` — `device.serial` 渲染为脱敏令牌(`redacted:…`)、**绝不**为原始 TCP 形 `127.0.0.1:16417`;并含「设备序列号(脱敏)」标签断言。
- 真实驱动验证前端各页与真后端字段对齐;页面从不渲染原始 Android ID/OAID/Cookie/Authorization/请求体,仅 `DynamicAnalysis.tsx` 渲染脱敏 `device.serial`。

### 9.7 测试与截图

- 后端:`.venv/Scripts/python.exe -m pytest -q` → **137 passed**(本次 commit 新增 `MITM_LISTEN_HOST` 配置测试 +1、apktool Windows wrapper 回归测试 +3,合计 +4;无回归;`config.py`/`main.py`/`utils.py` 改动后退出码 0)。
- 前端:`web` 下 `tsc --noEmit` 退出码 **0**;`vitest run` → **Test Files 13 passed / Tests 133 passed**;`vite build` → **built in 12.24s**, 退出码 **0**。
- 截图:本轮对本地 Vite dev server(直连真后端 `:8000`)渲染的 8 个路由页截取非空白截图,落 `docs/screenshots/real-device/`(不覆盖既有 `01-08*.png`, 见第十节文件清单)。截图为其各自路由的**当前状态渲染**(home/new-analysis/tasks/static/dynamic/traffic/reports/environment 多为空态或「—」占位,因无活跃任务注入),**非** dynamic 成功态、**非** traffic 已抓取请求态——动态成功与流量已采本轮未发生(见 9.4/9.5),截图不把失败/未执行呈现为成功。

### 9.8 本节诚实声明

本节动态 verdict 为 **failed**, 现象为 `com.phoenix.read` 在 frida `resume` 后立即 `process-terminated`(由直接设备探针在该 app 上复现, 见 9.4)——该现象与反调试/反 Frida 防护相符, 但在补齐 logcat/tombstone/空脚本对照等证据前不写为「已决断性证明」。本轮**未绕过反调试、未改 APK 绕 pinning、未伪造请求记录、未把 zero_requests/失败态包装为成功**;本轮也**未执行完整 traffic-on 运行**(见 9.5), 故 collector 三态末经此 APK 真实 traffic-on 验证, 且任何未执行/零观测状态均不解释为「无网络行为/安全」。红线信息(原始 Android ID/OAID/Cookie/Authorization/auth 头/请求体/未脱敏设备标识/APK 内容/frida-server 二进制/flows.mitm 内容)均不进入本报告;APK 与 frida-server 仅以 SHA-256 形式出现。
