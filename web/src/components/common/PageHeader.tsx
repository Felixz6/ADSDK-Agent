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
    <div className={cn('flex flex-col gap-2 sm:flex-row sm:items-end sm:justify-between', className)}>
      <div className="min-w-0">
        {eyebrow && (
          <div className="text-xs text-[var(--text-tertiary)] mb-1 tracking-wide">{eyebrow}</div>
        )}
        <h1 className="text-xl sm:text-2xl font-semibold text-[var(--text-primary)] tracking-tight">
          {title}
        </h1>
        {description && (
          <p className="text-sm text-[var(--text-secondary)] mt-1.5 max-w-2xl">{description}</p>
        )}
      </div>
      {actions && <div className="flex items-center gap-2 flex-wrap">{actions}</div>}
    </div>
  )
}

export default PageHeader
