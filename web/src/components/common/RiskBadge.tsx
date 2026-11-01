import { cn } from '@/utils'

/**
 * RiskBadge — 风险等级徽标。
 * 不展示原始敏感标识,仅按规则命中数推导风险语气。
 */
export type RiskLevel = 'high' | 'medium' | 'low' | 'unknown'

const toneClass: Record<RiskLevel, string> = {
  high: 'bg-[var(--danger-soft)] text-[var(--danger)] border-[var(--danger-line)]',
  medium: 'bg-[var(--warning-soft)] text-[var(--warning)] border-[var(--warning-line)]',
  low: 'bg-[var(--success-soft)] text-[var(--success)] border-[var(--success-line)]',
  unknown: 'bg-[var(--neutral-soft)] text-[var(--status-neutral)] border-[var(--neutral-line)]',
}

const labelMap: Record<RiskLevel, string> = {
  high: '高风险',
  medium: '中风险',
  low: '低风险',
  unknown: '未评估',
}

export function RiskBadge({ level, label, className }: { level: RiskLevel; label?: string; className?: string }) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-md border px-2.5 py-0.5 text-xs font-semibold',
        toneClass[level],
        className,
      )}
    >
      <span
        className={cn(
          'inline-block w-1.5 h-1.5 rounded-full',
          level === 'high' && 'bg-[var(--danger)]',
          level === 'medium' && 'bg-[var(--warning)]',
          level === 'low' && 'bg-[var(--success)]',
          level === 'unknown' && 'bg-[var(--status-neutral)]',
        )}
        aria-hidden
      />
      {label ?? labelMap[level]}
    </span>
  )
}

/** 依据规则统计推导整体风险语气(仅用于提示,不替代人工研判) */
export function deriveRiskLevel(input: {
  matched: number
  not_evaluated: number
  errored: number
}): RiskLevel {
  if (input.matched > 0) return 'high'
  if (input.errored > 0) return 'unknown'
  if (input.not_evaluated > 0) return 'unknown'
  return 'low'
}

export default RiskBadge
