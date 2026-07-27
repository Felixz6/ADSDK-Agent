import { motion } from 'framer-motion'
import { ShieldCheck, ShieldAlert, ShieldOff, Hand, MousePointerClick } from 'lucide-react'
import { cn, formatDateTime } from '@/utils'
import type { DynamicTimeline } from '@/types/api'

interface ConsentTimelineProps {
  timeline: DynamicTimeline | null
  /** consent 实际发生时间(monotonic,timeline.consent_monotonic_ms) */
  consentMonotonicMs?: number | null
  preSeconds?: number | null
  postSeconds?: number | null
  /** 结构化事件可按 monotonic 落入前/后区间 */
  eventCount?: { pre: number; post: number; unknown: number }
}

const MARKERS = [
  { key: 'hook_ready_at', label: 'Hook 就绪', icon: ShieldCheck, tone: 'accent' as const },
  { key: 'collection_started_at', label: '采集开始', icon: MousePointerClick, tone: 'info' as const },
  { key: 'consent_at', label: '用户同意', icon: Hand, tone: 'warning' as const },
  { key: 'app_resumed_at', label: '应用恢复', icon: ShieldCheck, tone: 'info' as const },
  { key: 'collection_ended_at', label: '采集结束', icon: ShieldOff, tone: 'neutral' as const },
]

const toneClass: Record<'accent' | 'info' | 'warning' | 'neutral' | 'danger', string> = {
  accent: 'text-[var(--accent-purple)] border-[rgba(182,161,255,0.5)]',
  info: 'text-[var(--accent-blue)] border-[rgba(120,216,255,0.5)]',
  warning: 'text-[var(--warning)] border-[rgba(242,203,119,0.5)]',
  neutral: 'text-[var(--status-neutral)] border-[rgba(127,147,186,0.45)]',
  danger: 'text-[var(--danger)] border-[rgba(242,139,155,0.5)]',
}

export function ConsentTimeline({ timeline, consentMonotonicMs, preSeconds, postSeconds, eventCount }: ConsentTimelineProps) {
  if (!timeline) {
    return <p className="text-sm text-[var(--text-tertiary)]">未提供动态时间线数据。</p>
  }

  return (
    <div className="flex flex-col gap-3">
      <div className="flex items-center justify-between text-xs text-[var(--text-tertiary)]">
        <span>会话开始 {formatDateTime(timeline.session_created_at)}</span>
        {preSeconds != null && postSeconds != null && (
          <span>
            同意前窗口 {preSeconds}s / 同意后窗口 {postSeconds}s
          </span>
        )}
      </div>

      <ol className="relative">
        <span className="absolute left-[13px] top-2 bottom-2 w-[2px] bg-[var(--border-soft)] -translate-x-1/2" aria-hidden />
        {MARKERS.map((m, i) => {
          const ts = (timeline as Record<string, unknown>)[m.key] as string | null | undefined
          const Icon = m.icon
          const isConsent = m.key === 'consent_at'
          return (
            <li key={m.key} className="relative flex gap-3 pb-3 last:pb-0">
              <motion.div
                initial={{ opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                transition={{ delay: Math.min(i * 0.05, 0.4) }}
                className={cn(
                  'z-10 flex items-center justify-center w-7 h-7 rounded-full border-2 bg-[var(--bg-deep)] shrink-0',
                  toneClass[m.tone],
                  isConsent && 'ring-2 ring-[rgba(242,203,119,0.25)]',
                )}
              >
                <Icon size={14} />
              </motion.div>
              <div className="flex-1 min-w-0 pt-0.5">
                <div className="flex items-center justify-between gap-2 flex-wrap">
                  <span className="text-sm font-medium text-[var(--text-primary)]">{m.label}</span>
                  <span className="text-xs text-[var(--text-tertiary)]">{formatDateTime(ts) || '—'}</span>
                </div>
                {isConsent && eventCount && (
                  <p className="text-xs text-[var(--text-secondary)] mt-0.5">
                    同意前事件 {eventCount.pre} · 同意后事件 {eventCount.post} · 时间不明 {eventCount.unknown}
                  </p>
                )}
              </div>
            </li>
          )
        })}
      </ol>

      {consentMonotonicMs == null && (
        <p className="text-xs text-[var(--warning)] flex items-center gap-1.5">
          <ShieldAlert size={13} /> 未捕获到同意时间点,前/后窗口无法精确划分,相关时间统计将标注为「时间不明」。
        </p>
      )}
    </div>
  )
}

export default ConsentTimeline
