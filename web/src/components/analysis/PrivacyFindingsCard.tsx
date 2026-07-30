import { useState } from 'react'
import { ChevronDown, ChevronRight, ShieldCheck, ShieldQuestion } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { cn } from '@/utils'
import type {
  PrivacyEvidenceRef,
  PrivacyEvidenceType,
  PrivacyFinding,
  PrivacyFindingConfidence,
  PrivacyFindingSeverity,
  PrivacyFindingType,
  PrivacyFindings,
} from '@/types/api'

const STATUS_COPY: Record<PrivacyFindings['status'], string> = {
  evaluated: '所有可评估规则均已完成判定；结果是风险提示，不是法律合规结论。',
  partially_evaluated: '部分规则因证据不足未评估；未评估不代表安全或合规。',
  not_evaluated: '本次证据不足，未形成可判定的隐私发现结果。',
  no_observations: '本次没有可用于隐私发现的观察记录；这不代表相关行为不存在。',
  error: '隐私发现模块执行异常；主报告与原始证据仍可查看。',
}

const SEVERITY_LABEL: Record<PrivacyFindingSeverity, string> = {
  high: '高关注',
  medium: '中关注',
  low: '低关注',
  info: '信息',
}

const SEVERITY_CLASS: Record<PrivacyFindingSeverity, string> = {
  high: 'border-[rgba(242,139,155,0.45)] text-[var(--danger)]',
  medium: 'border-[rgba(242,203,119,0.45)] text-[var(--warning)]',
  low: 'border-[rgba(157,192,255,0.4)] text-[var(--accent-blue)]',
  info: 'border-[rgba(127,147,186,0.45)] text-[var(--status-neutral)]',
}

const CONFIDENCE_LABEL: Record<PrivacyFindingConfidence, string> = {
  high: '高置信',
  medium: '中置信',
  low: '低置信',
}

const TYPE_LABEL: Record<PrivacyFindingType, string> = {
  observed: '已观察事实',
  suspected: '疑似风险提示',
  evidence_gap: '证据缺口',
}

const TYPE_CLASS: Record<PrivacyFindingType, string> = {
  observed: 'border-[rgba(91,224,184,0.4)] text-[var(--success)]',
  suspected: 'border-[rgba(178,140,255,0.45)] text-[var(--accent-purple)]',
  evidence_gap: 'border-[rgba(127,147,186,0.45)] text-[var(--status-neutral)]',
}

const EVIDENCE_LABEL: Record<PrivacyEvidenceType, string> = {
  manifest: 'Manifest',
  dynamic_event: '动态事件',
  network_request: '网络请求',
  correlation: '关联',
  timeline: '时间线',
  diagnostic: '诊断',
}

/** Fixed order of the evidence chain; missing links are simply absent. */
const EVIDENCE_ORDER: PrivacyEvidenceType[] = [
  'manifest',
  'timeline',
  'dynamic_event',
  'correlation',
  'network_request',
  'diagnostic',
]

const REASON_COPY: Record<string, string> = {
  pre_consent_sensitive_api_observed: '在 Consent 之前观察到敏感 API 调用记录。',
  pre_consent_network_request_observed: '在 Consent 之前观察到网络请求记录。',
  post_consent_observation_only: '相关观察仅出现在 Consent 之后。',
  temporal_proximity_only: '仅存在时间接近关系，未建立因果关系。',
  no_causality_established: '证据不支持“事件触发了请求”这一结论。',
  consent_boundary_missing: '缺少可信的 Consent 时间边界。',
  consent_state_unknown: '部分观察的 Consent 阶段无法判定。',
  dynamic_evidence_unavailable: '本次没有可信的动态事件证据。',
  dynamic_evidence_grade_insufficient: '动态证据等级不足以形成确定性动态结论。',
  network_evidence_unavailable: '本次没有可信的网络侧证据。',
  correlation_not_available: '本次没有可用的事件—请求关联结果。',
  correlation_confidence_capped: '关联置信度限制了本发现的置信度上限。',
  utc_time_fallback: '时间对齐依赖墙钟时间，置信度上限为低。',
  manifest_evidence_unavailable: 'Manifest 证据不可用，相关静态判断未评估。',
  observation_window_limited: '结论仅覆盖本次采集窗口。',
  no_matching_observation: '在可评估证据中没有匹配到该规则的观察。',
  rule_execution_error: '该规则执行异常，其他规则不受影响。',
  evidence_refs_truncated: '证据引用数量过多，仅展示前若干条。',
}

const CONSENT_LABEL: Record<PrivacyFinding['consent_state'], string> = {
  pre_consent: 'Consent 前',
  post_consent: 'Consent 后',
  unknown: 'Consent 阶段未知',
}

export function PrivacyFindingsCard({
  findings,
}: {
  findings?: PrivacyFindings | null
}) {
  if (findings == null) {
    return (
      <GlassCard padding="md">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
          <ShieldCheck size={15} /> 可解释隐私发现
        </h3>
        <p className="mt-3 text-sm text-[var(--text-tertiary)]">
          旧版报告未生成可解释隐私发现结果。
        </p>
      </GlassCard>
    )
  }

  const summary = findings.summary
  return (
    <GlassCard padding="md" highlight className="min-w-0">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
            <ShieldCheck size={15} /> 可解释隐私发现
          </h3>
          <p className="mt-1 text-xs text-[var(--text-tertiary)]">
            {STATUS_COPY[findings.status]}
          </p>
        </div>
        <StatusBadge
          tone={
            findings.status === 'evaluated'
              ? 'success'
              : findings.status === 'error'
                ? 'warning'
                : findings.status === 'partially_evaluated'
                  ? 'info'
                  : 'neutral'
          }
          label={findings.status}
        />
      </div>

      <p className="mt-3 rounded-[10px] border border-[rgba(242,203,119,0.35)] px-3 py-2 text-[11px] leading-relaxed text-[var(--text-secondary)] break-words">
        {findings.disclaimer}
      </p>

      <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
        <Metric label="发现数量" value={summary.finding_count} />
        <Metric label="已观察事实" value={summary.confirmed_observation_count} />
        <Metric label="疑似风险提示" value={summary.suspected_risk_count} />
        <Metric label="证据缺口" value={summary.evidence_gap_count} />
        <Metric label="未评估规则" value={summary.not_evaluated_rule_count} />
      </div>

      {findings.findings.length > 0 ? (
        <ul className="mt-4 flex flex-col gap-2 min-w-0">
          {findings.findings.map((item) => (
            <FindingRow key={item.finding_id} finding={item} />
          ))}
        </ul>
      ) : (
        <p className="mt-4 rounded-[10px] border border-[var(--border-soft)] px-3 py-4 text-center text-sm text-[var(--text-tertiary)]">
          本次观察中没有形成可展示的隐私发现。
        </p>
      )}

      {findings.limitations.length > 0 && (
        <div className="mt-4 flex items-start gap-2 text-xs text-[var(--text-secondary)]">
          <ShieldQuestion size={14} className="mt-0.5 shrink-0 text-[var(--warning)]" />
          <div className="min-w-0">
            <p className="font-medium text-[var(--text-primary)]">证据限制</p>
            <ul className="mt-1 list-disc pl-4 break-words">
              {findings.limitations.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <details className="mt-4 rounded-[10px] border border-[var(--border-soft)] px-3 py-2 min-w-0">
        <summary className="cursor-pointer text-xs text-[var(--text-tertiary)]">
          规则评估明细
        </summary>
        <ul className="mt-2 flex flex-col gap-1.5">
          {findings.rule_results.map((rule) => (
            <li
              key={rule.rule_id}
              className="flex items-start justify-between gap-2 flex-wrap text-[11px]"
            >
              <span className="min-w-0 break-all font-mono text-[var(--text-secondary)]">
                {rule.rule_id}
              </span>
              <span className="shrink-0 text-[var(--text-tertiary)]">{rule.status}</span>
            </li>
          ))}
        </ul>
      </details>
    </GlassCard>
  )
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="rounded-[10px] border border-[var(--border-soft)] px-2.5 py-2 min-w-0">
      <p className="text-[10px] text-[var(--text-tertiary)] truncate">{label}</p>
      <p className="mt-0.5 text-base font-semibold text-[var(--text-primary)]">{value}</p>
    </div>
  )
}

function FindingRow({ finding }: { finding: PrivacyFinding }) {
  const [open, setOpen] = useState(false)
  const chain = EVIDENCE_ORDER.map((type) => ({
    type,
    refs: finding.evidence_refs.filter((ref) => ref.evidence_type === type),
  })).filter((group) => group.refs.length > 0)

  return (
    <li className="rounded-[12px] border border-[var(--border-soft)] p-3 min-w-0">
      <div className="flex items-start justify-between gap-2 flex-wrap">
        <p className="min-w-0 break-words text-sm font-medium text-[var(--text-primary)]">
          {finding.title}
        </p>
        <div className="flex items-center gap-1.5 flex-wrap shrink-0">
          <span
            className={cn(
              'rounded-full border px-2 py-0.5 text-[11px]',
              SEVERITY_CLASS[finding.severity],
            )}
          >
            {SEVERITY_LABEL[finding.severity]}
          </span>
          <span
            className={cn(
              'rounded-full border px-2 py-0.5 text-[11px]',
              TYPE_CLASS[finding.finding_type],
            )}
          >
            {TYPE_LABEL[finding.finding_type]}
          </span>
          <span className="rounded-full border border-[rgba(127,147,186,0.45)] px-2 py-0.5 text-[11px] text-[var(--text-tertiary)]">
            {CONFIDENCE_LABEL[finding.confidence]}
          </span>
        </div>
      </div>

      <p className="mt-1.5 text-xs text-[var(--text-secondary)] break-words">
        {finding.summary}
      </p>
      <p className="mt-1 text-[11px] text-[var(--text-tertiary)] break-words">
        {CONSENT_LABEL[finding.consent_state]} · 证据 {finding.evidence_refs.length} 条
      </p>

      {finding.reason_codes.length > 0 && (
        <ul className="mt-2 flex flex-col gap-1">
          {finding.reason_codes.map((code) => (
            <li key={code} className="text-[11px] text-[var(--text-secondary)] break-words">
              · {REASON_COPY[code] ?? code}
            </li>
          ))}
        </ul>
      )}

      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="mt-2 flex items-center gap-1 text-[11px] text-[var(--accent-blue)]"
      >
        {open ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
        证据链（{chain.length} 个环节）
      </button>

      {open && (
        <div className="mt-2 flex flex-col gap-2 min-w-0">
          <p className="text-[11px] text-[var(--text-tertiary)] break-words">
            {finding.explanation}
          </p>
          {chain.length > 0 ? (
            chain.map((group) => (
              <EvidenceGroup key={group.type} type={group.type} refs={group.refs} />
            ))
          ) : (
            <p className="text-[11px] text-[var(--text-tertiary)]">
              本发现没有可展示的证据引用。
            </p>
          )}
          {finding.limitations.length > 0 && (
            <ul className="list-disc pl-4 text-[11px] text-[var(--text-secondary)] break-words">
              {finding.limitations.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          )}
        </div>
      )}
    </li>
  )
}

function EvidenceGroup({
  type,
  refs,
}: {
  type: PrivacyEvidenceType
  refs: PrivacyEvidenceRef[]
}) {
  return (
    <div className="rounded-[10px] border border-[var(--border-soft)] px-2.5 py-2 min-w-0">
      <p className="text-[10px] uppercase tracking-wide text-[var(--text-tertiary)]">
        {EVIDENCE_LABEL[type]}
      </p>
      <ul className="mt-1 flex flex-col gap-1">
        {refs.map((ref) => (
          <li
            key={`${ref.evidence_type}-${ref.evidence_id}`}
            className="min-w-0 break-words text-[11px] text-[var(--text-secondary)]"
          >
            {ref.label}
            <span className="ml-1 break-all font-mono text-[10px] text-[var(--text-tertiary)]">
              {ref.artifact}#{ref.evidence_id}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default PrivacyFindingsCard
