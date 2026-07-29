import type { DynamicModePolicy } from '@/types/api'

export const DYNAMIC_ERROR_ZH: Record<string, string> = {
  host_frida_missing: '项目虚拟环境中未安装 Frida 组件',
  host_frida_import_failed: 'Frida Python 组件导入失败',
  host_frida_cli_missing: '项目虚拟环境中未找到 Frida 命令行工具',
  host_frida_component_mismatch: '主机 Frida 组件版本不一致',
  device_not_found: '未找到指定设备',
  device_offline: '指定设备当前离线',
  device_unauthorized: '指定设备尚未授权 ADB',
  frida_server_binary_missing: '设备端未找到 Frida 服务文件',
  frida_server_version_mismatch: '主机与设备端 Frida 版本不兼容',
  frida_server_transport_unreachable: '无法与设备端 Frida 服务建立连接',
  spawn_failed: '启动前 Hook 模式执行失败',
  attach_failed: '附加目标进程失败',
  hook_ready_timeout: 'Hook 初始化未在限定时间内就绪',
  process_crashed: '目标应用运行期间发生崩溃',
  anti_debug_suspected: '观察到疑似反调试行为',
  traffic_zero_requests: '采集器正常运行，但窗口内未观察到请求',
}

export function dynamicErrorLabel(code?: string | null): string {
  return code ? DYNAMIC_ERROR_ZH[code] ?? '动态分析组件返回诊断信息' : '状态未知'
}

export const MODE_COPY: Record<DynamicModePolicy, { label: string; detail: string }> = {
  strict: {
    label: '严格模式',
    detail: '只接受启动前 Hook；失败即停止，不发生静默降级。',
  },
  balanced: {
    label: '平衡模式',
    detail: '优先启动前 Hook，失败后按可信顺序附加并记录证据缺口。',
  },
  attach_only: {
    label: '仅附加模式',
    detail: '只观察已运行进程；不覆盖启动阶段，证据等级通常为 C。',
  },
}
