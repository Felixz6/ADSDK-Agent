import { GlassCard } from '@/components/common/GlassCard'
import { RuleStatusBadge } from '@/components/common/StatusBadge'
import { cn } from '@/utils'
import type { RuleEvaluationStatus, StrictDynamicFindings, DynamicFindings } from '@/types/api'

interface RuleLike {
  rule_id: string
  status: RuleEvaluationStatus
  legacy_status?: string | null
}

const RULE_DESC: Record<string, string> = {
  pre_consent_sensitive_access: '同意前存在任意敏感系统 API 访问',
  high_frequency_sensitive_access: '同意前高频敏感访问(android_id ≥3,剪贴板 ≥1)',
  pre_consent_sensitive_access_strict: '严格规则:同意前任意敏感访问即命中',
  pre_consent_high_frequency_sensitive_access: '严格规则:同意前高频敏感访问',
}

export interface ReportRuleCardProps {
  findings: DynamicFindings | StrictDynamicFindings | null
  /** 是否严格版(影响标题与显示窗口) */
  strict?: boolean
}

export function ReportRuleCard({ findings, strict = false }: ReportRuleCardProps) {
  const rules = findings?.rules as RuleLike[] | undefined
  if (!rules || rules.length === 0) {
    return (
      <GlassCard padding="md">
        <p className="text-sm text-[var(--text-tertiary)]">
          未提供规则判定结果{!strict ? '(':''}。`not_evaluated` 表示该规则未被评估,不等于「安全」{!strict ? ')':''}。
        </p>
      </GlassCard>
    )
  }

  const summary = (findings as { summary?: string; evaluation_summary?: string | null }).summary
  const evaluationSummary = (findings as { evaluation_summary?: string | null }).evaluation_summary

  return (
    <GlassCard padding="md" highlight className="flex flex-col gap-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <div>
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">
            {strict ? '严格版动态规则结果' : '动态规则判定'}
          </h3>
          <p className="text-[11px] text-[var(--text-tertiary)]">共 {rules.length} 条规则</p>
        </div>
      </div>

      <div className="flex flex-col gap-2">
        {rules.map((r) => (
          <div
            key={r.rule_id}
            className={cn(
              'flex items-center justify-between gap-3 rounded-[12px] px-3 py-2.5 border',
              'border-[var(--border-soft)]',
            )}
          >
            <div className="min-w-0">
              <p className="text-sm text-[var(--text-primary)] font-medium truncate">{r.rule_id}</p>
              <p className="text-[11px] text-[var(--text-tertiary)] truncate">
                {RULE_DESC[r.rule_id] ?? '动态规则'}
              </p>
            </div>
            <RuleStatusBadge status={r.status} />
          </div>
        ))}
      </div>

      {summary && (
        <div className="text-xs text-[var(--text-secondary)] leading-relaxed">
          <p className="text-[var(--text-tertiary)] mb-0.5">摘要</p>
          {summary}
        </div>
      )}
      {evaluationSummary && (
        <div className="text-xs text-[var(--text-secondary)] leading-relaxed">
          <p className="text-[var(--text-tertiary)] mb-0.5">评估说明</p>
          {evaluationSummary}
        </div>
      )}
      <p className="text-[11px] text-[var(--text-tertiary)]">
        说明:`未评估` 仅表示规则未运行/数据缺失,绝不代表「无风险」。
      </p>
    </GlassCard>
  )
}

export default ReportRuleCard
