import { AlertTriangle, ShieldCheck } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import type { RiskLevel, RiskSummary } from '@/types/api'
import { riskConfidenceLabel } from '@/utils/taskPresentation'

const levelLabel: Record<RiskLevel, string> = {
  low: '低风险',
  medium: '中风险',
  high: '高风险',
  critical: '严重风险',
}

const levelTone = {
  low: 'success',
  medium: 'warning',
  high: 'danger',
  critical: 'danger',
} as const

export function RiskSummaryCard({ summary }: { summary?: RiskSummary | null }) {
  if (!summary) {
    return (
      <GlassCard padding="md">
        <div className="flex items-start gap-2 text-sm text-[var(--text-tertiary)]">
          <ShieldCheck size={17} className="mt-0.5 shrink-0" />
          <span>旧版报告未包含综合风险评分；现有分析结果仍可继续查看。</span>
        </div>
      </GlassCard>
    )
  }
  return (
    <GlassCard padding="md" highlight>
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div>
          <p className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide">综合风险</p>
          <div className="flex items-baseline gap-2 mt-1">
            <strong className="text-3xl text-[var(--text-primary)]">{summary.score}</strong>
            <span className="text-sm text-[var(--text-tertiary)]">/ 100</span>
          </div>
        </div>
        <div className="flex flex-col items-end gap-1.5">
          <StatusBadge tone={levelTone[summary.level]} label={levelLabel[summary.level]} />
          <span className="text-[11px] text-[var(--text-tertiary)]">
            置信度：{riskConfidenceLabel(summary.confidence)} · {summary.calculation_version}
          </span>
        </div>
      </div>
      {summary.category_scores.length > 0 && (
        <div className="grid grid-cols-2 sm:grid-cols-3 gap-2 mt-4">
          {summary.category_scores.map((item) => (
            <div key={item.category} className="rounded-[9px] border border-[var(--border-soft)] p-2 min-w-0">
              <div className="flex justify-between gap-2 text-xs">
                <span className="text-[var(--text-secondary)] truncate">{item.label}</span>
                <span className="text-[var(--text-primary)]">{item.score}</span>
              </div>
              <div className="h-1 rounded-full bg-[rgba(127,147,186,0.16)] mt-1.5 overflow-hidden">
                <div className="h-full bg-[var(--warning)]" style={{ width: `${Math.min(100, item.score)}%` }} />
              </div>
            </div>
          ))}
        </div>
      )}
      {summary.top_risks.length > 0 && (
        <ul className="mt-3 flex flex-col gap-1.5">
          {summary.top_risks.slice(0, 3).map((risk) => (
            <li key={risk.id} className="flex items-start gap-2 text-xs text-[var(--text-secondary)]">
              <AlertTriangle size={13} className="text-[var(--warning)] shrink-0 mt-0.5" />
              <span className="break-words">{risk.title}（+{risk.score}）</span>
            </li>
          ))}
        </ul>
      )}
      {summary.confidence_reasons.length > 0 && (
        <p className="text-[11px] text-[var(--warning)] mt-3 break-words">
          证据覆盖提示：{summary.confidence_reasons.join('；')}
        </p>
      )}
    </GlassCard>
  )
}
