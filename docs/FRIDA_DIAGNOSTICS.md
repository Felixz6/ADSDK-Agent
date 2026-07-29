# Frida 分层诊断与受控 server 生命周期

## 只读诊断

`POST /frida/diagnostics` 请求必须包含明确 `device_id`，可选 `package_name`。
响应 schema 为 `frida-diagnostics-v1`，分为 host、device、server、transport
和 target。每项包含 `status`、`detected_value`、`expected_value`、`error_code`、
`message`、`remediation` 与 `evidence`。公开响应只包含 HMAC 脱敏设备引用。

诊断不部署、不启动、不停止，也不联网下载。

## 本地文件配置

```env
FRIDA_SERVER_MANAGEMENT_ENABLED=false
FRIDA_SERVER_LOCAL_PATH=
FRIDA_SERVER_REMOTE_PATH=/data/local/tmp/frida-server
FRIDA_SERVER_START_TIMEOUT_SECONDS=10
FRIDA_SERVER_HANDSHAKE_TIMEOUT_SECONDS=10
FRIDA_SERVER_STOP_ON_TASK_END=false
```

管理默认关闭。启用后，部署前校验普通文件、大小、SHA-256、ELF 架构、设备 ABI
和版本。上传使用临时名称，校验大小后再移动到最终路径。已有未知文件不会被覆盖。

## 所有权

启动前检查已有进程和端口。平台只登记自己启动的 PID；`stop` 只处理登记 PID，
用户原本运行的服务返回 `not_owned`。取消和异常清理保持幂等。

## 故障排查

| 错误码 | 排查 |
|---|---|
| `host_frida_missing` | 确认后端来自项目 `.venv` |
| `host_frida_component_mismatch` | 统一 binding/CLI 主版本 |
| `device_offline` / `device_unauthorized` | 恢复 ADB device 状态 |
| `frida_server_binary_missing` | 配置可信本地文件后显式部署 |
| `frida_server_abi_mismatch` | 使用与设备 ABI 一致的 ELF |
| `frida_server_version_mismatch` | 统一主机与 server 版本 |
| `frida_server_transport_unreachable` | 检查 PID、权限、27042 与握手 |
| `hook_ready_timeout` | 检查脚本协议和目标是否快速退出 |
