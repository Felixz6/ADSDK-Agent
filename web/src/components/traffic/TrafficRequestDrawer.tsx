import { useEffect } from 'react'
import { motion, AnimatePresence } from 'framer-motion'
import { X, ShieldOff, Lock, Globe, Clock } from 'lucide-react'
import { cn, formatDateTime, formatBytes } from '@/utils'
import type { HttpRequestRecord } from '@/types/api'

export interface TrafficRequestDrawerProps {
  record: HttpRequestRecord | null
  onClose: () => void
}

/** 字段名翻译表(仅展示,不改后端语义) */
const FIELD_LABEL: Record<keyof HttpRequestRecord, string> = {
  protocol_version: '协议版本',
  schema_version: 'Schema 版本',
  type: '类型',
  flow_id: 'Flow ID',
  run_id: 'Run ID',
  session_id: 'Session ID',
  timestamp_utc: '时间(UTC)',
  method: '方法',
  scheme: 'Scheme',
  hostname: '主机',
  port: '端口',
  path: '路径',
  query_keys: '查询键名',
  status_code: '状态码',
  request_size: '请求大小',
  response_size: '响应大小',
  tls: 'TLS',
  error: '错误',
}

export function TrafficRequestDrawer({ record, onClose }: TrafficRequestDrawerProps) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  return (
    <AnimatePresence>
      {record && (
        <motion.div
          className="fixed inset-0 z-[120] flex justify-end"
          initial={{ opacity: 0 }}
          animate={{ opacity: 1 }}
          exit={{ opacity: 0 }}
          transition={{ duration: 0.15 }}
          role="dialog"
          aria-modal="true"
          aria-label="请求详情"
        >
          <div className="absolute inset-0 bg-[rgba(3,8,22,0.62)] backdrop-blur-sm" onClick={onClose} aria-hidden />
          <motion.aside
            initial={{ x: 40, opacity: 0 }}
            animate={{ x: 0, opacity: 1 }}
            exit={{ x: 40, opacity: 0 }}
            transition={{ duration: 0.2, ease: 'easeOut' }}
            className="relative w-[min(92vw,520px)] h-full glass-strong border-l border-[var(--border-soft)] flex flex-col"
          >
            <header className="flex items-center justify-between gap-2 px-4 h-[var(--topbar-h)] border-b border-[var(--border-soft)]">
              <div className="flex items-center gap-2 min-w-0">
                {record.scheme === 'https' ? <Lock size={16} className="text-[var(--success)]" /> : <Globe size={16} className="text-[var(--accent-blue)]" />}
                <span className="text-sm font-semibold text-[var(--text-primary)] truncate">
                  {record.method} · {record.hostname ?? '(主机未记录)'}
                </span>
              </div>
              <button type="button" onClick={onClose} aria-label="关闭" className="text-[var(--text-tertiary)] hover:text-[var(--text-primary)]">
                <X size={18} />
              </button>
            </header>

            <div className="flex-1 overflow-y-auto p-4 flex flex-col gap-3">
              <Banner record={record} />

              <dl className="grid grid-cols-1 gap-1.5">
                {(Object.keys(FIELD_LABEL) as (keyof HttpRequestRecord)[]).map((k) => {
                  const value = record[k]
                  return <Field key={k} label={FIELD_LABEL[k]} value={formatValue(k, value)} mono />
                })}
              </dl>

              <Note />
            </div>
          </motion.aside>
        </motion.div>
      )}
    </AnimatePresence>
  )
}

function Banner({ record }: { record: HttpRequestRecord }) {
  const hasError = Boolean(record.error)
  return (
    <div
      className={cn(
        'rounded-[12px] px-3 py-2.5 border flex items-center gap-2 text-xs',
        hasError
          ? 'border-[rgba(242,139,155,0.4)] bg-[rgba(242,139,155,0.08)] text-[var(--danger)]'
          : 'border-[var(--border-soft)] bg-[rgba(120,216,255,0.06)] text-[var(--text-secondary)]',
      )}
    >
      {hasError ? <X size={14} /> : <ShieldOff size={14} className="text-[var(--warning)]" />}
      <span>
        单条记录仅含元数据(主机、路径脱敏段、查询键名);不含请求头、请求体、原始 URL、Cookie 与鉴权信息。
      </span>
    </div>
  )
}

function Field({ label, value, mono }: { label: string; value: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1 border-b border-[var(--border-soft)]/40">
      <dt className={cn('text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide shrink-0 pt-0.5', mono && '')}>{label}</dt>
      <dd className={cn('text-sm text-[var(--text-primary)] text-right break-all', mono && 'font-mono text-[13px]')}>{value}</dd>
    </div>
  )
}

function Note() {
  return (
    <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed flex items-start gap-1.5">
      <Clock size={12} className="mt-0.5" />
      时间戳、flow/run/session 均来自后端采集层;未提供同意时段与可疑外发等业务派生字段。
    </p>
  )
}

function formatValue(key: keyof HttpRequestRecord, value: unknown): string {
  if (value == null) return '—'
  if (key === 'timestamp_utc') return formatDateTime(value as string) || (value as string)
  if (key === 'query_keys') return (value as string[]).length ? (value as string[]).join(', ') : '(无)'
  if (key === 'request_size' || key === 'response_size') return formatBytes(value as number)
  if (key === 'port') return String(value)
  if (key === 'status_code') return value == null ? '—' : String(value)
  return String(value)
}

export default TrafficRequestDrawer
