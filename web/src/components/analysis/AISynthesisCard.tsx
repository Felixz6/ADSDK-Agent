import { Bot, Lightbulb, ListChecks, ShieldAlert, ShieldQuestion } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { cn } from '@/utils'
import type { AIOrchestrationSection } from '@/types/tasks'

interface Props {
  section?: AIOrchestrationSection | null
}

const STATUS_LABEL: Record<string, string> = {
  completed: '综合研判完成',
  partial: '部分完成(已降级)',
  failed: '综合研判失败',
  budget_exhausted: '触及预算上限',
  disabled: 'AI 未启用',
}

const SEVERITY_LABEL: Record<string, string> = {
  high: '高',
  medium: '中',
  low: '低',
  info: '提示',
}

const CONFIDENCE_LABEL: Record<string, string> = {
  high: '高',
  medium: '中',
  low: '低',
}

function severityTone(severity: string): 'danger' | 'warning' | 'neutral' {
  if (severity === 'high') return 'danger'
  if (severity === 'medium') return 'warning'
  return 'neutral'
}

export function AISynthesisCard({ section }: Props) {
  // 旧报告没有 AI 字段:整个区块不渲染,页面其余部分完全不受影响。
  if (!section) return null

  const report = section.report
  const disabled = section.status === 'disabled'

  return (
    <GlassCard padding="md" highlight className="min-w-0 overflow-hidden" data-testid="ai-synthesis-card">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-[var(--text-primary)]">
            <Bot size={16} className="text-[var(--accent-purple)]" /> AI 综合研判
          </h3>
          <p className="mt-1 text-xs text-[var(--text-tertiary)]">
            本区块只做叙述与优先级归纳；确定性证据表格不受 AI 影响。
          </p>
        </div>
        <StatusBadge
          tone={section.status === 'completed' ? 'success' : section.status === 'failed' ? 'danger' : 'warning'}
          label={STATUS_LABEL[section.status] ?? section.status}
        />
      </div>

      {disabled ? (
        <p className="mt-4 flex items-start gap-2 text-xs text-[var(--text-secondary)]">
          <ShieldQuestion size={14} className="mt-0.5 shrink-0" />
          本次任务未启用 AI 综合研判；确定性证据与报告已完整生成。
        </p>
      ) : (
        <>
          {report?.executive_summary && (
            <section className="mt-4" aria-label="执行摘要">
              <p className="text-xs font-medium text-[var(--text-primary)]">执行摘要</p>
              <p className="mt-1.5 break-words text-xs leading-relaxed text-[var(--text-secondary)]">
                {report.executive_summary}
              </p>
            </section>
          )}

          {report?.risk_priorities?.length ? (
            <section className="mt-4" aria-label="风险优先级">
              <p className="flex items-center gap-1.5 text-xs font-medium text-[var(--text-primary)]">
                <ShieldAlert size={13} /> 风险优先级
              </p>
              <ul className="mt-1.5 list-disc space-y-1 pl-4 text-xs text-[var(--text-secondary)]">
                {report.risk_priorities.map((item) => (
                  <li key={item} className="break-words">{item}</li>
                ))}
              </ul>
            </section>
          ) : null}

          {report?.key_findings?.length ? (
            <section className="mt-4" aria-label="关键发现">
              <p className="text-xs font-medium text-[var(--text-primary)]">关键发现</p>
              <ul className="mt-2 flex flex-col gap-2">
                {report.key_findings.map((finding) => (
                  <li
                    key={finding.title}
                    className="min-w-0 rounded-[10px] border border-[var(--border-soft)] p-2.5"
                  >
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <span className="min-w-0 break-words text-xs font-medium text-[var(--text-primary)]">
                        {finding.title}
                      </span>
                      <span className="flex shrink-0 items-center gap-1.5">
                        <StatusBadge
                          tone={severityTone(finding.severity)}
                          label={`严重性 ${SEVERITY_LABEL[finding.severity] ?? finding.severity}`}
                        />
                        <span className="text-[10px] text-[var(--text-tertiary)]">
                          置信度 {CONFIDENCE_LABEL[finding.confidence] ?? finding.confidence}
                        </span>
                      </span>
                    </div>
                    {finding.summary && (
                      <p className="mt-1.5 break-words text-[11px] leading-relaxed text-[var(--text-secondary)]">
                        {finding.summary}
                      </p>
                    )}
                    {finding.evidence_refs?.length ? (
                      <p className="mt-1.5 break-all font-mono text-[10px] text-[var(--text-tertiary)]">
                        证据引用：{finding.evidence_refs.join('、')}
                      </p>
                    ) : (
                      <p className="mt-1.5 text-[10px] text-[var(--text-tertiary)]">
                        无直接证据引用（已降级为提示）
                      </p>
                    )}
                  </li>
                ))}
              </ul>
            </section>
          ) : null}

          {report?.evidence_gaps?.length ? (
            <section className="mt-4" aria-label="证据缺口">
              <p className="flex items-center gap-1.5 text-xs font-medium text-[var(--text-primary)]">
                <ShieldQuestion size={13} /> 证据缺口
              </p>
              <ul className="mt-1.5 list-disc space-y-1 pl-4 text-xs text-[var(--text-secondary)]">
                {report.evidence_gaps.map((item) => (
                  <li key={item} className="break-words">{item}</li>
                ))}
              </ul>
            </section>
          ) : null}

          {report?.recommended_actions?.length ? (
            <section className="mt-4" aria-label="建议动作">
              <p className="flex items-center gap-1.5 text-xs font-medium text-[var(--text-primary)]">
                <Lightbulb size={13} /> 建议下一步
              </p>
              <ul className="mt-1.5 list-disc space-y-1 pl-4 text-xs text-[var(--text-secondary)]">
                {report.recommended_actions.map((item) => (
                  <li key={item} className="break-words">{item}</li>
                ))}
              </ul>
            </section>
          ) : null}

          {report?.evidence_refs?.length ? (
            <section className="mt-4" aria-label="证据引用">
              <p className="flex items-center gap-1.5 text-xs font-medium text-[var(--text-primary)]">
                <ListChecks size={13} /> Evidence refs
              </p>
              <p className="mt-1.5 break-all font-mono text-[10px] text-[var(--text-tertiary)]">
                {report.evidence_refs.join('、')}
              </p>
            </section>
          ) : null}

          {report?.limitations?.length ? (
            <ul className="mt-3 list-disc space-y-1 pl-4 text-[11px] text-[var(--text-tertiary)]">
              {report.limitations.map((item) => (
                <li key={item} className="break-words">{item}</li>
              ))}
            </ul>
          ) : null}
        </>
      )}

      <div className={cn('mt-4 rounded-[10px] border border-[rgba(230,190,113,0.28)] px-3 py-2')}>
        <p className="break-words text-[11px] leading-relaxed text-[var(--text-secondary)]" data-testid="ai-disclaimer">
          {report?.disclaimer
            || 'AI 综合研判基于本次任务中已有的结构化技术证据生成。AI 不直接读取或验证原始敏感数据，本结果不构成法律合规结论。未观察到某项行为不代表该行为不会在其他设备、时间、账号或操作路径下发生。'}
        </p>
      </div>
    </GlassCard>
  )
}
