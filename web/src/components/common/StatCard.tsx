import { type ReactNode } from 'react'
import { motion } from 'framer-motion'
import { cn } from '@/utils'
import { GlassCard } from './GlassCard'

export interface StatCardProps {
  label: string
  value: ReactNode
  hint?: ReactNode
  icon?: ReactNode
  tone?: 'default' | 'success' | 'warning' | 'danger' | 'accent' | 'neutral'
  /** 用于嵌入 MetricStrip 时去掉外层卡片边框与投影 */
  embedded?: boolean
  className?: string
}

const toneColor: Record<NonNullable<StatCardProps['tone']>, string> = {
  default: 'text-[var(--text-secondary)]',
  success: 'text-[var(--success)]',
  warning: 'text-[var(--warning)]',
  danger: 'text-[var(--danger)]',
  accent: 'text-[var(--accent-purple)]',
  neutral: 'text-[var(--status-neutral)]',
}

export function StatCard({
  label,
  value,
  hint,
  icon,
  tone = 'default',
  embedded = false,
  className,
}: StatCardProps) {
  const inner = (
    <div className="flex items-start justify-between gap-3">
      <div className="min-w-0 flex-1">
        <p className="text-xs font-medium text-[var(--text-tertiary)] truncate">{label}</p>
        <motion.p
          initial={{ opacity: 0, y: 3 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.2 }}
          className="mt-1.5 text-2xl font-semibold tracking-[-0.02em] tabular-nums text-[var(--text-primary)] truncate"
        >
          {value}
        </motion.p>
        {hint && (
          <p className="mt-1 text-xs text-[var(--text-secondary)] truncate">{hint}</p>
        )}
      </div>
      {icon && (
        <div className={cn('mt-0.5 shrink-0 opacity-85', toneColor[tone])} aria-hidden>
          {icon}
        </div>
      )}
    </div>
  )

  if (embedded) {
    return (
      <div className={cn('min-w-0 px-4 py-3.5', className)}>
        {inner}
      </div>
    )
  }

  return (
    <GlassCard padding="md" highlight className={cn('min-w-0', className)}>
      {inner}
    </GlassCard>
  )
}

export function MetricStrip({
  children,
  className,
}: {
  children: ReactNode
  className?: string
}) {
  return (
    <div
      className={cn(
        'metric-strip divide-y divide-[var(--hairline)] lg:divide-y-0 lg:divide-x',
        className,
      )}
    >
      {children}
    </div>
  )
}

export default StatCard