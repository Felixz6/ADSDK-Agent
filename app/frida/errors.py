"""Stable dynamic-analysis error taxonomy and compatibility mappings."""

from __future__ import annotations

from enum import Enum


class DynamicErrorCode(str, Enum):
    HOST_FRIDA_MISSING = "host_frida_missing"
    HOST_FRIDA_IMPORT_FAILED = "host_frida_import_failed"
    HOST_FRIDA_CLI_MISSING = "host_frida_cli_missing"
    HOST_FRIDA_VERSION_UNKNOWN = "host_frida_version_unknown"
    HOST_FRIDA_COMPONENT_MISMATCH = "host_frida_component_mismatch"
    DEVICE_NOT_FOUND = "device_not_found"
    DEVICE_OFFLINE = "device_offline"
    DEVICE_UNAUTHORIZED = "device_unauthorized"
    DEVICE_COMMAND_FAILED = "device_command_failed"
    DEVICE_ABI_UNSUPPORTED = "device_abi_unsupported"
    DEVICE_STORAGE_INSUFFICIENT = "device_storage_insufficient"
    ROOT_UNAVAILABLE = "root_unavailable"
    SU_COMMAND_FAILED = "su_command_failed"
    REMOTE_DIRECTORY_UNWRITABLE = "remote_directory_unwritable"
    FRIDA_SERVER_BINARY_MISSING = "frida_server_binary_missing"
    FRIDA_SERVER_NOT_EXECUTABLE = "frida_server_not_executable"
    FRIDA_SERVER_ABI_MISMATCH = "frida_server_abi_mismatch"
    FRIDA_SERVER_VERSION_MISMATCH = "frida_server_version_mismatch"
    FRIDA_SERVER_START_DENIED = "frida_server_start_denied"
    FRIDA_SERVER_START_TIMEOUT = "frida_server_start_timeout"
    FRIDA_SERVER_EXITED = "frida_server_exited"
    FRIDA_SERVER_PORT_CONFLICT = "frida_server_port_conflict"
    FRIDA_SERVER_TRANSPORT_UNREACHABLE = "frida_server_transport_unreachable"
    PACKAGE_NOT_INSTALLED = "package_not_installed"
    PACKAGE_LAUNCH_FAILED = "package_launch_failed"
    PACKAGE_PROCESS_NOT_FOUND = "package_process_not_found"
    SPAWN_DENIED = "spawn_denied"
    SPAWN_TIMEOUT = "spawn_timeout"
    SPAWN_FAILED = "spawn_failed"
    ATTACH_FAILED = "attach_failed"
    ATTACH_TIMEOUT = "attach_timeout"
    HOOK_SCRIPT_INVALID = "hook_script_invalid"
    HOOK_SCRIPT_LOAD_FAILED = "hook_script_load_failed"
    HOOK_READY_TIMEOUT = "hook_ready_timeout"
    HOOK_PROTOCOL_ERROR = "hook_protocol_error"
    PROCESS_EXITED = "process_exited"
    PROCESS_CRASHED = "process_crashed"
    PROCESS_KILLED = "process_killed"
    APP_SELF_TERMINATION_SUSPECTED = "app_self_termination_suspected"
    ANTI_DEBUG_SUSPECTED = "anti_debug_suspected"
    COLLECTION_TIMEOUT = "collection_timeout"
    COLLECTION_CANCELLED = "collection_cancelled"
    RESOURCE_CLEANUP_FAILED = "resource_cleanup_failed"
    TRAFFIC_PROXY_NOT_APPLIED = "traffic_proxy_not_applied"
    TRAFFIC_HOST_UNREACHABLE = "traffic_host_unreachable"
    TRAFFIC_CA_UNVERIFIED = "traffic_ca_unverified"
    TRAFFIC_TLS_FAILURE_OBSERVED = "traffic_tls_failure_observed"
    TRAFFIC_PINNING_SUSPECTED = "traffic_pinning_suspected"
    TRAFFIC_COLLECTOR_FAILED = "traffic_collector_failed"
    TRAFFIC_ZERO_REQUESTS = "traffic_zero_requests"


LEGACY_ERROR_MAP: dict[str, str] = {
    "frida_server_unavailable": DynamicErrorCode.FRIDA_SERVER_TRANSPORT_UNREACHABLE.value,
    "frida_version_mismatch": DynamicErrorCode.FRIDA_SERVER_VERSION_MISMATCH.value,
    "frida_device_not_found": DynamicErrorCode.DEVICE_NOT_FOUND.value,
    "frida_spawn_failed": DynamicErrorCode.SPAWN_FAILED.value,
    "frida_attach_failed": DynamicErrorCode.ATTACH_FAILED.value,
    "hook_load_failed": DynamicErrorCode.HOOK_SCRIPT_LOAD_FAILED.value,
    "frida_protocol_error": DynamicErrorCode.HOOK_PROTOCOL_ERROR.value,
    "dynamic_collection_timeout": DynamicErrorCode.COLLECTION_TIMEOUT.value,
}


def legacy_error_code(code: str | None) -> str | None:
    """Return the precise M4 code while accepting historical persisted values."""

    if code is None:
        return None
    normalized = code.strip()
    return LEGACY_ERROR_MAP.get(normalized, normalized)


ERROR_MESSAGES_ZH: dict[str, str] = {
    DynamicErrorCode.HOST_FRIDA_MISSING.value: "项目虚拟环境中未安装 Frida Python 组件",
    DynamicErrorCode.HOST_FRIDA_IMPORT_FAILED.value: "Frida Python 组件导入失败",
    DynamicErrorCode.HOST_FRIDA_CLI_MISSING.value: "项目虚拟环境中未找到 Frida 命令行工具",
    DynamicErrorCode.HOST_FRIDA_COMPONENT_MISMATCH.value: "Frida Python、CLI 或设备端版本不兼容",
    DynamicErrorCode.DEVICE_NOT_FOUND.value: "未找到指定设备",
    DynamicErrorCode.DEVICE_OFFLINE.value: "指定设备当前离线",
    DynamicErrorCode.DEVICE_UNAUTHORIZED.value: "指定设备尚未授权 ADB 连接",
    DynamicErrorCode.FRIDA_SERVER_BINARY_MISSING.value: "设备端未找到已配置的 Frida 服务文件",
    DynamicErrorCode.FRIDA_SERVER_VERSION_MISMATCH.value: "主机与设备端 Frida 版本不兼容",
    DynamicErrorCode.FRIDA_SERVER_TRANSPORT_UNREACHABLE.value: "无法与设备端 Frida 服务建立连接",
    DynamicErrorCode.SPAWN_FAILED.value: "启动前 Hook 模式执行失败",
    DynamicErrorCode.ATTACH_FAILED.value: "附加目标进程失败",
    DynamicErrorCode.HOOK_READY_TIMEOUT.value: "Hook 初始化在限定时间内未就绪",
    DynamicErrorCode.PROCESS_CRASHED.value: "目标应用运行期间发生崩溃",
    DynamicErrorCode.ANTI_DEBUG_SUSPECTED.value: "观察到疑似反调试行为，现有证据尚不足以确认",
    DynamicErrorCode.TRAFFIC_ZERO_REQUESTS.value: "采集器运行正常，但本次窗口未观察到请求",
}


def chinese_error_message(code: str | None, fallback: str = "动态分析状态未知") -> str:
    precise = legacy_error_code(code)
    return ERROR_MESSAGES_ZH.get(precise or "", fallback)
