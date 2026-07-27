import { type ReactNode } from 'react'
import { cn } from '@/utils'

interface StateShellProps {
  icon: ReactNode
  title: string
  description?: string
  action?: ReactNode
  className?: string
}

function StateShell({ icon, title, description, action, className }: StateShellProps) {
  return (
    <div
      className={cn(
        'flex flex-col items-center justify-center text-center gap-3 py-12 px-6',
        className,
      )}
    >
      <div className="text-[var(--text-tertiary)] opacity-80">{icon}</div>
      <div>
        <p className="text-[var(--text-primary)] font-medium">{title}</p>
        {description && (
          <p className="text-sm text-[var(--text-secondary)] mt-1.5 max-w-md">{description}</p>
        )}
      </div>
      {action && <div className="mt-1">{action}</div>}
    </div>
  )
}

export function EmptyState(props: StateShellProps) {
  return <StateShell {...props} />
}

export function LoadingState({ title = '加载中…', description, className }: { title?: string; description?: string; className?: string }) {
  return (
    <StateShell
      className={className}
      icon={<span className="inline-block w-6 h-6 rounded-full border-2 border-[var(--accent-blue)] border-t-transparent animate-spin" />}
      title={title}
      description={description}
    />
  )
}

export function ErrorState(props: StateShellProps) {
  return <StateShell {...props} />
}

export default EmptyState
