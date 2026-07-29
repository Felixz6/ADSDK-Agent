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
$device = 'TARGET_DEVICE'
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
  "device_id": "TARGET_DEVICE",
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

## M4 动态可靠性工作流

动态任务在正式采集前执行 `frida-diagnostics-v1`，并把 host、device、server、
transport、target 的结论写入任务步骤和报告。`strict` 不降级；`balanced` 记录
启动前 Hook 失败和 attach 路径；`attach_only` 明确缺少启动阶段覆盖。

任务结束后报告保存 `dynamic_execution`、`dynamic_evidence_quality`、
`process_diagnostics` 和 `traffic_diagnostics`。前端、Markdown 与 HTML 均解释
证据等级，而不是只显示字母。旧报告缺少这些字段时显示“旧版报告未记录”。

server 管理默认关闭，诊断不会产生部署或启动副作用。管理启用后仍需要用户逐次
确认；停止操作仅作用于平台启动并登记 PID 所有权的进程。
