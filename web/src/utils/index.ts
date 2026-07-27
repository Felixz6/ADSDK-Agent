import { clsx, type ClassValue } from 'clsx'

/** 合并 className,支持条件与尾随覆盖 */
export function cn(...inputs: ClassValue[]): string {
  return clsx(inputs)
}

/** 毫秒 -> "1.2s" / "12分34秒" */
export function formatDuration(ms?: number | null): string {
  if (ms == null || Number.isNaN(ms)) return '—'
  if (ms < 1000) return `${Math.round(ms)}ms`
  const s = ms / 1000
  if (s < 60) return `${s.toFixed(s < 10 ? 1 : 0)}s`
  const m = Math.floor(s / 60)
  const sec = Math.round(s % 60)
  if (m < 60) return `${m}分${sec}秒`
  const h = Math.floor(m / 60)
  return `${h}时${m % 60}分`
}

/** ISO / ISO8601 -> "2026-07-25 16:30" 本地时间,失败回退原值或占位 */
export function formatDateTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
}

/** 简短时间 HH:mm:ss */
export function formatTime(iso?: string | null): string {
  if (!iso) return '—'
  const d = new Date(iso)
  if (Number.isNaN(d.getTime())) return iso
  const p = (n: number) => String(n).padStart(2, '0')
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

/** 文件大小可读化 */
export function formatBytes(bytes?: number | null): string {
  if (bytes == null || Number.isNaN(bytes)) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let v = bytes / 1024
  let i = 0
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024
    i += 1
  }
  return `${v.toFixed(v < 10 ? 2 : 1)} ${units[i]}`
}

/**
 * 本地历史 Repository 的唯一 ID(仅用于浏览器本地记录,不与后端 run_id 一致)。
 *
 * 优先使用 crypto.randomUUID()(在同一毫秒内连续调用也不会重复)。
 * 当 crypto.randomUUID 不可用(如非安全上下文 http://)时,回退到
 * "时间戳(毫秒)+ 计数器 + 随机后缀"组合,并在同一毫秒内单调递增以保证唯一性。
 *
 * 不再使用秒级时间戳作为唯一来源 —— 秒级时间戳在同一秒内多次调用会产生重复。
 */
let __localRunIdFallbackCounter = 0
let __localRunIdFallbackLastMs = 0
export function makeLocalRunId(): string {
  // 优先使用平台 crypto.randomUUID
  const g = globalThis as { crypto?: Crypto }
  if (g.crypto?.randomUUID) {
    return `local-${g.crypto.randomUUID()}`
  }
  // 回退路径:毫秒时间戳 + 同毫秒单调计数 + 随机后缀,保证同一毫秒内不重复
  const now = Date.now()
  if (now !== __localRunIdFallbackLastMs) {
    __localRunIdFallbackLastMs = now
    __localRunIdFallbackCounter = 0
  } else {
    __localRunIdFallbackCounter += 1
  }
  const rand =
    (g.crypto?.getRandomValues?.(new Uint8Array(4)) as Uint8Array | undefined) ??
    null
  const randHex = rand
    ? Array.from(rand, (b) => b.toString(16).padStart(2, '0')).join('')
    : __localRunIdFallbackCounter.toString(36)
  return `local-${now.toString(36)}-${__localRunIdFallbackCounter.toString(36)}-${randHex}`
}

/** 复制到剪贴板,返回是否成功 */
export async function copyText(text: string): Promise<boolean> {
  try {
    await navigator.clipboard.writeText(text)
    return true
  } catch {
    return false
  }
}

/** 安全取值:对象键可能缺失时回退 */
export function safePick<T, K extends keyof T>(obj: T | null | undefined, key: K, fallback: T[K]): T[K] {
  if (obj && typeof obj === 'object' && key in obj) {
    return obj[key] ?? fallback
  }
  return fallback
}
