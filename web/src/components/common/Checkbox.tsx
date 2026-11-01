import { Check } from 'lucide-react'
import { cn } from '@/utils'

export function Checkbox({
  checked,
  onChange,
  label,
  description,
  className,
}: {
  checked: boolean
  onChange: (checked: boolean) => void
  label: string
  description?: string
  className?: string
}) {
  return (
    <label className={cn('inline-flex items-start gap-3 cursor-pointer select-none', className)}>
      <input
        type="checkbox"
        checked={checked}
        onChange={(event) => onChange(event.target.checked)}
        className="sr-only peer"
      />
      <span
        aria-hidden
        className={cn(
          'mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-[6px] border transition-all',
          checked
            ? 'border-[var(--accent-blue)] bg-[var(--accent-blue)] text-[var(--text-on-accent)]'
            : 'border-[var(--hairline)] bg-[var(--bg-panel)] text-transparent',
        )}
      >
        <Check size={13} strokeWidth={3} />
      </span>
      <span className="min-w-0">
        <span className="block text-xs text-[var(--text-secondary)]">{label}</span>
        {description && (
          <span className="mt-0.5 block text-[11px] text-[var(--text-tertiary)]">
            {description}
          </span>
        )}
      </span>
    </label>
  )
}

