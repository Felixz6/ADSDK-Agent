import { cn } from '@/utils'
import type { StepStatus, RuleEvaluationStatus } from '@/types/api'

type Tone = 'success' | 'warning' | 'danger' | 'neutral' | 'info' | 'accent'

const toneClass: Record<Tone, string> = {
  success: 'bg-[rgba(121,224,195,0.14)] text-[var(--success)] border-[rgba(121,224,195,0.4)]',
  warning: 'bg-[rgba(242,203,119,0.14)] text-[var(--warning)] border-[rgba(242,203,119,0.4)]',
  danger: 'bg-[rgba(242,139,155,0.14)] text-[var(--danger)] border-[rgba(242,139,155,0.42)]',
  neutral: 'bg-[rgba(127,147,186,0.16)] text-[var(--status-neutral)] border-[rgba(127,147,186,0.4)]',
  info: 'bg-[rgba(120,216,255,0.12)] text-[var(--accent-blue)] border-[rgba(120,216,255,0.4)]',
  accent: 'bg-[rgba(182,161,255,0.14)] text-[var(--accent-purple)] border-[rgba(182,161,255,0.42)]',
}

const dotClass: Record<Tone, string> = {
  success: 'bg-[var(--success)]',
  warning: 'bg-[var(--warning)]',
  danger: 'bg-[var(--danger)]',
  neutral: 'bg-[var(--status-neutral)]',
  info: 'bg-[var(--accent-blue)]',
  accent: 'bg-[var(--accent-purple)]',
}

export interface StatusBadgeProps {
  tone: Tone
  label: string
  /** 显示左侧小圆点 */
  dot?: boolean
  className?: string
  size?: 'sm' | 'md'
}

export function StatusBadge({ tone, label, dot = true, className, size = 'sm' }: StatusBadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border font-medium whitespace-nowrap',
        size === 'sm' ? 'px-2.5 py-0.5 text-xs' : 'px-3 py-1 text-sm',
        toneClass[tone],
        className,
      )}
    >
      {dot && <span className={cn('inline-block w-1.5 h-1.5 rounded-full', dotClass[tone])} aria-hidden />}
      {label}
    </span>
  )
}

/* -------- StepStatus 文案与色调映射 -------- */

export const STEP_STATUS_TONE: Record<StepStatus, Tone> = {
  success: 'success',
  partial: 'warning',
  failed: 'danger',
  skipped: 'neutral',
}

export const STEP_STATUS_LABEL: Record<StepStatus, string> = {
  success: '成功',
  partial: '部分完成',
  failed: '失败',
  skipped: '已跳过',
}

/** 用于批量步骤结果的展示 */
export function StepStatusBadge({ status }: { status: StepStatus }) {
  return <StatusBadge tone={STEP_STATUS_TONE[status]} label={STEP_STATUS_LABEL[status]} />
}

/* -------- 规则判定状态(强调 not_evaluated 绝不为「安全」) -------- */

export const RULE_STATUS_TONE: Record<RuleEvaluationStatus, Tone> = {
  matched: 'danger',
  not_matched: 'success',
  not_evaluated: 'neutral',
  error: 'warning',
}

export const RULE_STATUS_LABEL: Record<RuleEvaluationStatus, string> = {
  matched: '命中(疑似违规)',
  not_matched: '未命中',
  // 文案明确:未评估 ≠ 安全
  not_evaluated: '未评估',
  error: '评估出错',
}

export function RuleStatusBadge({ status }: { status: RuleEvaluationStatus }) {
  return <StatusBadge tone={RULE_STATUS_TONE[status]} label={RULE_STATUS_LABEL[status]} />
}

export default StatusBadge
