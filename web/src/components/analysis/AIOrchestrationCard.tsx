import { Bot, CheckCircle2, Clock, Coins, Database, Layers, ShieldQuestion, XCircle } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { cn } from '@/utils'
import type { AIOrchestrationSection, AIToolStatus } from '@/types/tasks'

interface Props {
  section?: AIOrchestrationSection | null
  loading?: boolean
}

const STATUS_LABEL: Record<string, string> = {
  completed: 'AI 综合研判完成',
  partial: '部分完成(已降级)',
  failed: 'AI 编排失败',
  budget_exhausted: '已触及预算上限',
  disabled: 'AI 未启用',
}

const TOOL_STATUS_LABEL: Record<AIToolStatus, string> = {
  success: '成功',
  partial: '部分成功',
  failed: '失败',
  not_run: '未执行',
  blocked_confirmation_required: '待确认',
}

const TOOL_LABEL: Record<string, string> = {
  environment_check: '环境自检',
  static_analysis: '静态分析',
  dynamic_analysis: '动态分析',
  traffic_analysis: '网络观察',
  evidence_correlation: '证据关联',
  privacy_findings: '隐私发现',
  deterministic_report: '确定性报告',
  task_status: '任务状态',
  artifact_summary: '产物摘要',
}

function statusTone(status: string): 'success' | 'warning' | 'danger' | 'neutral' {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'disabled') return 'neutral'
  return 'warning'
}

export function AIOrchestrationCard({ section, loading }: Props) {
  if (loading) {
    return (
      <GlassCard padding="md" highlight data-testid="ai-orchestration-card">
        <p className="text-xs text-[var(--text-tertiary)]">正在加载 AI 编排信息…</p>
      </GlassCard>
    )
  }

  // 旧任务/旧报告没有 ai_orchestration 字段:中性提示,不展示为异常。
  if (!section) {
    return (
      <GlassCard padding="md" data-testid="ai-orchestration-card">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-[var(--text-primary)]">
          <Bot size={16} className="text-[var(--accent-purple)]" /> AI 编排
        </h3>
        <p className="mt-2 flex items-start gap-2 text-xs text-[var(--text-secondary)]">
          <ShieldQuestion size={14} className="mt-0.5 shrink-0" />
          本任务未使用 AI 编排；确定性分析与报告不受影响。
        </p>
      </GlassCard>
    )
  }

  const usage = section.usage
  const trace = section.trace
  const reusedCount = trace?.steps?.filter((step) => step.reused).length ?? 0
  const blocked = trace?.steps?.filter((step) => step.status === 'blocked_confirmation_required') ?? []

  return (
    <GlassCard padding="md" highlight className="min-w-0 overflow-hidden" data-testid="ai-orchestration-card">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="min-w-0">
          <h3 className="flex items-center gap-2 text-sm font-semibold text-[var(--text-primary)]">
            <Bot size={16} className="text-[var(--accent-purple)]" /> AI 编排
          </h3>
          <p className="mt-1 text-xs text-[var(--text-tertiary)]">
            AI 只负责调度与叙述；全部事实、数字与证据来自确定性工具结果。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <StatusBadge tone={statusTone(section.status)} label={STATUS_LABEL[section.status] ?? section.status} />
          {usage?.cache_hit && <StatusBadge tone="success" label="命中缓存" />}
          {usage?.budget_exhausted && <StatusBadge tone="warning" label="预算已用尽" />}
          {section.plan?.generated_by === 'default' && <StatusBadge tone="neutral" label="确定性默认计划" />}
        </div>
      </div>

      <dl className="mt-4 grid min-w-0 grid-cols-2 gap-3 lg:grid-cols-4">
        <Metric icon={<Layers size={14} />} k="计划步骤" v={String(section.plan?.steps?.length ?? 0)} />
        <Metric icon={<Database size={14} />} k="已复用工具" v={String(reusedCount)} />
        <Metric icon={<Clock size={14} />} k="模型调用轮数" v={String(usage?.model_round_count ?? 0)} />
        <Metric
          icon={<Coins size={14} />}
          k={usage?.usage_is_estimate ? 'Token(估算)' : 'Token(实际)'}
          v={String((usage?.input_tokens ?? 0) + (usage?.output_tokens ?? 0) + (usage?.estimated_tokens ?? 0))}
        />
      </dl>

      {usage?.usage_is_estimate && (
        <p className="mt-2 text-[11px] text-[var(--text-tertiary)]">
          供应商未返回真实 usage，以上为明确标注的估算值，不等同于实际计费 Token 数。
        </p>
      )}

      {blocked.length > 0 && (
        <div className="mt-3 rounded-[10px] border border-[rgba(242,139,155,0.28)] p-3" data-testid="ai-blocked-confirmations">
          <p className="text-xs font-medium text-[var(--warning)]">待确认项（{blocked.length}）</p>
          <ul className="mt-1.5 list-disc space-y-1 pl-4 text-[11px] text-[var(--text-secondary)]">
            {blocked.map((step) => (
              <li key={step.step_id}>
                {TOOL_LABEL[step.tool_name] ?? step.tool_name} · 需显式确认后才会改变设备状态
              </li>
            ))}
          </ul>
        </div>
      )}

      {section.plan?.steps?.length ? (
        <section className="mt-4" aria-label="AI 计划与工具执行">
          <p className="text-xs font-medium text-[var(--text-primary)]">计划步骤与工具执行</p>
          <ol className="mt-2 flex flex-col gap-2">
            {section.plan.steps.map((step) => {
              const executed = trace?.steps?.find((item) => item.step_id === step.step_id)
              const status = executed?.status ?? 'not_run'
              return (
                <li
                  key={step.step_id}
                  className="min-w-0 rounded-[10px] border border-[var(--border-soft)] p-2.5 text-xs"
                >
                  <div className="flex flex-wrap items-center justify-between gap-2">
                    <span className="flex min-w-0 items-center gap-1.5 text-[var(--text-primary)]">
                      {status === 'success' ? (
                        <CheckCircle2 size={13} className="shrink-0 text-[var(--success)]" />
                      ) : status === 'failed' ? (
                        <XCircle size={13} className="shrink-0 text-[var(--danger)]" />
                      ) : (
                        <ShieldQuestion size={13} className="shrink-0 text-[var(--text-tertiary)]" />
                      )}
                      <span className="truncate">{TOOL_LABEL[step.tool_name] ?? step.tool_name}</span>
                    </span>
                    <span className="flex shrink-0 items-center gap-1.5">
                      {executed?.reused && (
                        <span className="rounded-[6px] bg-[rgba(121,224,195,0.14)] px-1.5 py-0.5 text-[10px] text-[var(--success)]">
                          已复用
                        </span>
                      )}
                      <span className="text-[10px] text-[var(--text-tertiary)]">{TOOL_STATUS_LABEL[status]}</span>
                    </span>
                  </div>
                  {step.reason && (
                    <p className="mt-1 break-words text-[11px] text-[var(--text-tertiary)]">{step.reason}</p>
                  )}
                </li>
              )
            })}
          </ol>
        </section>
      ) : null}

      {section.plan?.limitations?.length ? (
        <ul className="mt-3 list-disc space-y-1 pl-4 text-[11px] text-[var(--text-tertiary)]">
          {section.plan.limitations.map((item) => (
            <li key={item}>{item}</li>
          ))}
        </ul>
      ) : null}
    </GlassCard>
  )
}

function Metric({ icon, k, v }: { icon: React.ReactNode; k: string; v: string }) {
  return (
    <div className={cn('min-w-0 rounded-[10px] border border-[var(--border-soft)] p-2.5')}>
      <dt className="flex items-center gap-1.5 text-[10px] text-[var(--text-tertiary)]">
        {icon}
        <span className="truncate">{k}</span>
      </dt>
      <dd className="mt-1 truncate text-sm font-medium text-[var(--text-primary)]" title={v}>
        {v}
      </dd>
    </div>
  )
}
