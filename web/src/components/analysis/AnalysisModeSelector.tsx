import { useId } from 'react'
import { FileSearch, Activity, Network } from 'lucide-react'
import { cn } from '@/utils'

export type AnalysisMode = 'static' | 'dynamic' | 'traffic'

interface ModeOption {
  value: AnalysisMode
  label: string
  desc: string
  icon: typeof FileSearch
}

const OPTIONS: ModeOption[] = [
  { value: 'static', label: '静态分析', desc: '解包识别 SDK 与清单', icon: FileSearch },
  { value: 'dynamic', label: '动态分析', desc: ' consenting 前后行为取证', icon: Activity },
  { value: 'traffic', label: '流量观测', desc: '记录网络外发样本', icon: Network },
]

export interface AnalysisModeSelectorProps {
  value: AnalysisMode
  onChange: (m: AnalysisMode) => void
  disabled?: boolean
}

export function AnalysisModeSelector({ value, onChange, disabled }: AnalysisModeSelectorProps) {
  const baseName = useId()
  return (
    <fieldset className="flex flex-col gap-2" disabled={disabled}>
      <legend className="text-sm font-medium text-[var(--text-secondary)] mb-1">分析模式</legend>
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5">
        {OPTIONS.map((opt) => {
          const Icon = opt.icon
          const active = value === opt.value
          return (
            <label
              key={opt.value}
              className={cn(
                'cursor-pointer rounded-[12px] p-3 border transition-colors flex flex-col gap-1.5',
                active
                  ? 'glass-strong border-[var(--border-active)] bg-[rgba(120,216,255,0.10)]'
                  : 'glass border-[var(--border-soft)] hover:bg-[rgba(157,192,255,0.08)]',
                disabled && 'opacity-60 cursor-not-allowed',
              )}
            >
              <span className="flex items-center gap-2">
                <input
                  type="radio"
                  name={baseName}
                  checked={active}
                  onChange={() => onChange(opt.value)}
                  className="sr-only"
                />
                <Icon size={18} className={cn(active ? 'text-[var(--accent-blue)]' : 'text-[var(--text-tertiary)]')} />
                <span className={cn('font-medium text-sm', active ? 'text-[var(--text-primary)]' : 'text-[var(--text-secondary)]')}>
                  {opt.label}
                </span>
              </span>
              <span className="text-xs text-[var(--text-tertiary)]">{opt.desc}</span>
            </label>
          )
        })}
      </div>
    </fieldset>
  )
}

export default AnalysisModeSelector
