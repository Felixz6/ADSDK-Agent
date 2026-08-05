import { Bot, CheckCircle2, Clock, Coins, Database, Layers, ShieldQuestion, XCircle } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { cn } from '@/utils'
import type {
  AIErrorObservation,
  AIOrchestrationSection,
  AIPerRoundUsage,
  AIRuntimeDiagnostic,
  AIToolStatus,
} from '@/types/tasks'

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

const USAGE_SOURCE_LABEL: Record<string, string> = {
  provider: '供应商真实',
  estimated: '本地估算',
  unavailable: '未知',
}

const ROUND_TYPE_LABEL: Record<string, string> = {
  plan: '规划',
  report: '报告',
  repair: '修复',
}

const ERROR_CODE_LABEL: Record<string, string> = {
  ai_not_configured: '未配置',
  ai_provider_timeout: '超时(408)',
  ai_provider_unreachable: '上游不可达(可重试)',
  ai_provider_authentication_failed: '鉴权失败(401/403,不可重试)',
  ai_provider_model_not_found: '模型不存在(404)',
  ai_provider_rate_limited: '限流(429,可重试)',
  ai_provider_error: '上游错误(其他 4xx)',
  ai_provider_invalid_json: '响应非法 JSON',
  ai_provider_invalid_response: '响应无效',
}

const OUTCOME_LABEL: Record<string, string> = {
  ok: '正常',
  degraded: '已降级',
  failed: '失败',
  disabled: '未启用',
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

      {section.diagnostic ? <DiagnosticsBlock diag={section.diagnostic} /> : null}
    </GlassCard>
  )
}

function outcomeTone(outcome: string): 'success' | 'warning' | 'danger' | 'neutral' {
  if (outcome === 'ok') return 'success'
  if (outcome === 'failed') return 'danger'
  if (outcome === 'disabled') return 'neutral'
  return 'warning'
}

/**
 * 运行时诊断块。仅展示可观事实(token 真实/估算来源、每轮来源、分类错误、
 * 延迟/缓存/重试/降级状态、结局)。绝不展示 reasoning_content 内容——仅每轮
 * 是否出现该字段的布尔。
 */
function DiagnosticsBlock({ diag }: { diag: AIRuntimeDiagnostic }) {
  const usage = diag.usage
  const realTotal = usage.real_tokens
  const estimatedTotal = usage.estimated_total_tokens
  const aggregateTotal =
    (usage.input_tokens ?? 0) + (usage.output_tokens ?? 0) + (usage.estimated_tokens ?? 0)
  return (
    <section
      className="mt-4 rounded-[10px] border border-[var(--border-soft)] p-3"
      aria-label="AI 运行时诊断"
      data-testid="ai-runtime-diagnostics"
    >
      <div className="flex flex-wrap items-center justify-between gap-2">
        <p className="flex items-center gap-1.5 text-xs font-medium text-[var(--text-primary)]">
          <Clock size={13} className="text-[var(--text-tertiary)]" /> 运行时诊断
        </p>
        <div className="flex flex-wrap items-center gap-1.5">
          <StatusBadge
            tone={outcomeTone(diag.outcome)}
            label={`结局: ${OUTCOME_LABEL[diag.outcome] ?? diag.outcome}`}
          />
          {diag.cache_enabled && (
            <StatusBadge
              tone={diag.cache_hit ? 'success' : 'neutral'}
              label={diag.cache_hit ? '缓存命中' : '缓存未命中'}
            />
          )}
          {!diag.enabled && <StatusBadge tone="neutral" label="AI 未启用" />}
        </div>
      </div>

      {diag.model && (
        <p className="mt-2 text-[11px] text-[var(--text-tertiary)]">
          模型 {diag.model}
          {diag.provider_profile ? ` · 配置 ${diag.provider_profile}` : ''}
          {diag.thinking_mode ? ` · ${diag.thinking_mode}` : ''}
        </p>
      )}

      <dl className="mt-2 grid min-w-0 grid-cols-2 gap-2 lg:grid-cols-4">
        <Metric icon={<Layers size={14} />} k="总轮数" v={String(diag.total_rounds)} />
        <Metric icon={<Clock size={14} />} k="总重试" v={String(diag.total_retries)} />
        <Metric icon={<Coins size={14} />} k="真实 Token" v={String(realTotal)} />
        <Metric
          icon={<Coins size={14} />}
          k="估算 Token"
          v={String(estimatedTotal)}
        />
      </dl>
      <p className="mt-1.5 text-[11px] text-[var(--text-tertiary)]">
        Token 合计 {aggregateTotal}（来源:
        {USAGE_SOURCE_LABEL[usage.usage_source] ?? usage.usage_source}
        ）。真实与估算分别列示,便于区分实际计费与本地推算。
      </p>

      <div className="mt-3 min-w-0 rounded-[8px] bg-[var(--bg-tertiary)] p-2.5 text-[11px] text-[var(--text-secondary)]" data-testid="m7b-plan-diagnostics">
        <p className="font-medium text-[var(--text-primary)]">计划与策略诊断</p>
        <dl className="mt-1.5 grid grid-cols-1 gap-x-3 gap-y-1 sm:grid-cols-2">
          <DiagnosticValue k="计划来源" v={diag.plan_source} />
          <DiagnosticValue k="首轮校验" v={diag.planning_failed ? '失败' : '通过或未执行'} />
          <DiagnosticValue k="修复" v={`尝试 ${yesNo(diag.repair_attempted)} · 成功 ${yesNo(diag.repair_succeeded)}`} />
          <DiagnosticValue k="确定性回退" v={yesNo(diag.fallback_used ?? diag.deterministic_plan_fallback)} />
          <DiagnosticValue k="校验错误" v={diag.validation_error_code} />
          <DiagnosticValue k="JSON 路径" v={diag.validation_json_path} />
          <DiagnosticValue k="请求/生效策略" v={strategyPair(diag.requested_strategy, diag.effective_strategy)} />
          <DiagnosticValue k="归一化" v={diag.normalized ? `是${diag.normalization_reason ? ` · ${diag.normalization_reason}` : ''}` : '否'} />
          <DiagnosticValue k="目标运行中" v={yesNo(diag.target_running)} />
          <DiagnosticValue k="预检变化" v={yesNo(diag.preflight_changed)} />
          <DiagnosticValue k="AI 报告来源" v={diag.report_source} />
          <DiagnosticValue k="证据校验" v={diag.report_source === 'deterministic_fallback' ? '确定性回退' : '已验证'} />
        </dl>
      </div>

      {usage.rounds?.length ? (
        <div className="mt-3" data-testid="ai-diagnostic-rounds">
          <p className="text-[11px] font-medium text-[var(--text-secondary)]">每轮来源明细</p>
          <ul className="mt-1.5 space-y-1">
            {usage.rounds.map((round) => (
              <RoundRow key={round.round_index} round={round} />
            ))}
          </ul>
        </div>
      ) : null}

      {diag.errors?.length ? (
        <div className="mt-3" data-testid="ai-diagnostic-errors">
          <p className="text-[11px] font-medium text-[var(--warning)]">
            分类错误（{diag.errors.length}）
          </p>
          <ul className="mt-1.5 space-y-1">
            {diag.errors.map((err, index) => (
              <ErrorRow key={index} err={err} />
            ))}
          </ul>
        </div>
      ) : null}

      {diag.deterministic_fallback && (
        <p className="mt-2 text-[11px] text-[var(--text-tertiary)]">
          本次最终降级为确定性模板生成,未由成功模型调用产出该产物。
        </p>
      )}
    </section>
  )
}

function yesNo(value: boolean | undefined): string {
  return value ? '是' : '否'
}

function strategyPair(requested?: string, effective?: string): string {
  if (!requested && !effective) return '—'
  return `${requested || '—'} → ${effective || '—'}`
}

function DiagnosticValue({ k, v }: { k: string; v?: string | null }) {
  return (
    <div className="flex min-w-0 gap-1">
      <dt className="shrink-0 text-[var(--text-tertiary)]">{k}:</dt>
      <dd className="min-w-0 break-words text-[var(--text-primary)]">{v || '—'}</dd>
    </div>
  )
}

function RoundRow({ round }: { round: AIPerRoundUsage }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-1.5 text-[11px] text-[var(--text-secondary)]">
      <span>
        <span className="text-[var(--text-primary)]">
          {ROUND_TYPE_LABEL[round.round_type] ?? round.round_type} #{round.round_index}
        </span>
        {round.retry_count > 0 && (
          <span className="ml-1 text-[var(--text-tertiary)]">重试 {round.retry_count}</span>
        )}
      </span>
      <span className="flex flex-wrap items-center gap-1.5">
        {round.cache_hit && (
          <span className="rounded-[6px] bg-[rgba(121,224,195,0.14)] px-1.5 py-0.5 text-[10px] text-[var(--success)]">
            命中缓存
          </span>
        )}
        <span className="text-[10px] text-[var(--text-tertiary)]">
          {USAGE_SOURCE_LABEL[round.usage_source] ?? round.usage_source}
        </span>
        <span className="text-[10px] text-[var(--text-tertiary)]">
          in/out {round.input_tokens}/{round.output_tokens}
        </span>
        <span className="text-[10px] text-[var(--text-tertiary)]">{round.latency_ms}ms</span>
      </span>
    </li>
  )
}

function ErrorRow({ err }: { err: AIErrorObservation }) {
  return (
    <li className="flex flex-wrap items-center justify-between gap-1.5 text-[11px] text-[var(--text-secondary)]">
      <span>
        <span className="text-[var(--danger)]">
          {ERROR_CODE_LABEL[err.code] ?? err.code}
        </span>
        {err.stage && (
          <span className="ml-1 text-[var(--text-tertiary)]">
            @{ROUND_TYPE_LABEL[err.stage] ?? err.stage}#{err.attempt}
          </span>
        )}
        {err.http_status != null && (
          <span className="ml-1 text-[var(--text-tertiary)]">HTTP {err.http_status}</span>
        )}
      </span>
      <span className="text-[10px] text-[var(--text-tertiary)]">
        {err.retryable ? '可重试' : '不可重试'}
        {err.finalized ? ' · 已终结' : ' · 进行中'}
        {err.latency_ms ? ` · ${err.latency_ms}ms` : ''}
      </span>
    </li>
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
