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
  className?: string
}

const toneColor: Record<NonNullable<StatCardProps['tone']>, string> = {
  default: 'text-[var(--accent-blue)]',
  success: 'text-[var(--success)]',
  warning: 'text-[var(--warning)]',
  danger: 'text-[var(--danger)]',
  accent: 'text-[var(--accent-purple)]',
  neutral: 'text-[var(--status-neutral)]',
}

export function StatCard({ label, value, hint, icon, tone = 'default', className }: StatCardProps) {
  return (
    <GlassCard padding="md" highlight className={cn('min-w-0', className)}>
      <div className="flex items-start gap-3">
        {icon && (
          <div
            className={cn(
              'flex items-center justify-center w-10 h-10 rounded-[10px]',
              'bg-[rgba(120,216,255,0.08)] border border-[var(--border-soft)]',
              toneColor[tone],
            )}
            aria-hidden
          >
            {icon}
          </div>
        )}
        <div className="min-w-0 flex-1">
          <p className="text-xs text-[var(--text-tertiary)] tracking-wide">{label}</p>
          <motion.p
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.25 }}
            className="text-2xl font-semibold text-[var(--text-primary)] mt-1 truncate"
          >
            {value}
          </motion.p>
          {hint && <p className="text-xs text-[var(--text-secondary)] mt-1">{hint}</p>}
        </div>
      </div>
    </GlassCard>
  )
}

export default StatCard
