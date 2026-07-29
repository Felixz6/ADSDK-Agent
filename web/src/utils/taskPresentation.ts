import type { TaskRecord, TaskType } from '@/types/tasks'

const RESOURCE_REFERENCE = /^[@?]/
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i

export function apkFilename(path: string | null | undefined): string {
  return path?.split(/[\\/]/).pop()?.trim() || ''
}

export function safeApplicationName(input: {
  appName?: string | null
  apkPath?: string | null
  packageName?: string | null
}): string {
  const candidates = [
    input.appName,
    apkFilename(input.apkPath),
    input.packageName,
    '未知应用',
  ]
  return candidates.find((candidate) => {
    const value = candidate?.trim()
    return value && !RESOURCE_REFERENCE.test(value) && !UUID.test(value)
  })?.trim() || '未知应用'
}

export function taskTitle(task: TaskRecord): string {
  const name = safeApplicationName({
    appName: task.app_name,
    apkPath: task.apk_path,
    packageName: task.package_name,
  })
  if (task.task_type !== 'comparison') return name
  return name.endsWith('版本对比') ? name : `${name} · 版本对比`
}

export function taskSubtitle(task: TaskRecord): string {
  if (task.task_type === 'comparison') {
    const base = shortTaskId(String(task.request_payload.base_task_id || ''))
    const target = shortTaskId(String(task.request_payload.target_task_id || ''))
    return base && target ? `基准 ${base} → 目标 ${target}` : '历史版本差异'
  }
  const packageName = task.package_name || '包名待解析'
  const filename = apkFilename(task.apk_path) || 'APK 文件待确认'
  return `${packageName} · ${filename}`
}

export function shortTaskId(value: string | null | undefined): string {
  return value?.trim().slice(0, 8) || ''
}

export function shortDeviceLabel(value: string | null | undefined): string {
  if (!value) return '未绑定'
  const token = value.includes(':') ? value.split(':').pop() || value : value
  return `设备 ${token.slice(0, 8)}`
}

export function taskTypeLabel(type: TaskType): string {
  return type === 'static' ? '静态' : type === 'dynamic' ? '动态' : '对比'
}

export function taskTypeLongLabel(type: TaskType): string {
  return type === 'static' ? '静态分析' : type === 'dynamic' ? '动态分析' : '版本对比'
}

export function riskLevelLabel(value: string | null | undefined): string {
  const labels: Record<string, string> = {
    low: '低风险',
    medium: '中风险',
    high: '高风险',
    critical: '严重风险',
  }
  return labels[String(value || '').toLowerCase()] || '未评估'
}

export function riskConfidenceLabel(value: string | null | undefined): string {
  const labels: Record<string, string> = {
    low: '较低',
    medium: '中等',
    high: '较高',
  }
  return labels[String(value || '').toLowerCase()] || '待确认'
}

export function localizeRiskText(value: string): string {
  return value.replace(/\b(critical|medium|high|low)\b/gi, (level) => riskLevelLabel(level))
}

export function riskBadgeLevel(
  value: string | null | undefined,
): 'low' | 'medium' | 'high' | 'unknown' {
  const normalized = String(value || '').toLowerCase()
  if (normalized === 'critical' || normalized === 'high') return 'high'
  if (normalized === 'medium') return 'medium'
  if (normalized === 'low') return 'low'
  return 'unknown'
}

export function formatVersion(task: Pick<TaskRecord, 'version_name' | 'version_code'>): string {
  if (!task.version_name && !task.version_code) return '版本未知'
  return `${task.version_name || '—'} (${task.version_code || '—'})`
}
