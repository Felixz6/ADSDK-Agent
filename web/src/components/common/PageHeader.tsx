import { type ReactNode } from 'react'
import { cn } from '@/utils'

export interface PageHeaderProps {
  title: string
  description?: ReactNode
  /** 标题右侧操作区 */
  actions?: ReactNode
  /** 面包屑等行上方提示 */
  eyebrow?: ReactNode
  className?: string
}

export function PageHeader({ title, description, actions, eyebrow, className }: PageHeaderProps) {
  return (
    <div
      className={cn(
        'flex flex-col gap-3 pb-4 border-b border-[var(--hairline)] sm:flex-row sm:items-end sm:justify-between',
        className,
      )}
    >
      <div className="min-w-0">
        {eyebrow && (
          <div className="mb-1 text-xs font-medium text-[var(--text-tertiary)]">{eyebrow}</div>
        )}
        <h1 className="text-[clamp(1.45rem,2.2vw,1.875rem)] font-semibold leading-[1.15] tracking-[-0.025em] text-[var(--text-primary)]">
          {title}
        </h1>
        {description && (
          <p className="mt-1.5 max-w-2xl text-sm leading-relaxed text-[var(--text-secondary)]">
            {description}
          </p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2 flex-wrap shrink-0">{actions}</div>}
    </div>
  )
}

export default PageHeader