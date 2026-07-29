import { AlertTriangle, ClipboardCheck } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import type { ComplianceInsightData } from '@/types/api'
import { localizeRiskText, riskLevelLabel } from '@/utils/taskPresentation'

export function ComplianceInsight({ insight }: { insight?: ComplianceInsightData | null }) {
  if (!insight) {
    return (
      <GlassCard padding="md">
        <p className="text-sm text-[var(--text-tertiary)]">旧版报告未包含本地合规解读。</p>
      </GlassCard>
    )
  }
  return (
    <GlassCard padding="md" highlight>
      <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
        <ClipboardCheck size={15} /> 合规解读
      </h3>
      <p className="text-sm text-[var(--text-secondary)] leading-relaxed mt-2">{localizeRiskText(insight.overall_assessment)}</p>
      {insight.key_findings.length > 0 && (
        <ul className="mt-3 flex flex-col gap-2">
          {insight.key_findings.map((finding, index) => (
            <li key={`${finding.title}-${index}`} className="rounded-[9px] border border-[var(--border-soft)] p-3">
              <div className="flex items-center gap-2 flex-wrap">
                <strong className="text-sm text-[var(--text-primary)] break-words">{finding.title}</strong>
                <StatusBadge tone={finding.severity === 'high' || finding.severity === 'critical' ? 'danger' : 'warning'} label={riskLevelLabel(finding.severity)} />
              </div>
              <p className="text-xs text-[var(--text-secondary)] mt-1">{finding.summary}</p>
              <p className="text-xs text-[var(--accent-blue)] mt-1">建议：{finding.recommendation}</p>
            </li>
          ))}
        </ul>
      )}
      {insight.priority_actions.length > 0 && (
        <div className="mt-3">
          <p className="text-xs font-medium text-[var(--text-primary)] mb-1">整改优先级</p>
          {insight.priority_actions.map((action, index) => (
            <p key={`${action.priority}-${index}`} className="text-xs text-[var(--text-secondary)] py-1">
              <b className="text-[var(--warning)]">{action.priority}</b> · {action.action}
            </p>
          ))}
        </div>
      )}
      {insight.limitations.length > 0 && (
        <div className="mt-3 flex items-start gap-2 text-xs text-[var(--warning)]">
          <AlertTriangle size={14} className="shrink-0 mt-0.5" />
          <span className="break-words">证据限制：{insight.limitations.join('；')}</span>
        </div>
      )}
      <p className="text-[10px] text-[var(--text-tertiary)] mt-3">{insight.generator_version} · 本地规则生成</p>
    </GlassCard>
  )
}
