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
  high: 'bg-[var(--danger-soft)] border-[var(--danger-line)] text-[var(--danger)]',
  medium: 'bg-[var(--warning-soft)] border-[var(--warning-line)] text-[var(--warning)]',
  low: 'bg-[var(--fill-quiet)] border-[var(--hairline)] text-[var(--text-secondary)]',
  info: 'bg-[var(--neutral-soft)] border-[var(--neutral-line)] text-[var(--status-neutral)]',
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

const TYPE_TEXT_CLASS: Record<PrivacyFindingType, string> = {
  observed: 'text-[var(--success)]',
  suspected: 'text-[var(--warning)]',
  evidence_gap: 'text-[var(--status-neutral)]',
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

      <p className="mt-3 rounded-[10px] border border-[var(--warning-line)] bg-[var(--warning-soft)] px-3 py-2 text-xs leading-relaxed text-[var(--text-secondary)] break-words">
        {findings.disclaimer}
      </p>

      <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 divide-y sm:divide-y-0 sm:divide-x divide-[var(--hairline)] rounded-[12px] border border-[var(--hairline)] bg-[var(--bg-soft)] overflow-hidden">
        <Metric label="发现数量" value={summary.finding_count} />
        <Metric label="已观察事实" value={summary.confirmed_observation_count} />
        <Metric label="疑似风险提示" value={summary.suspected_risk_count} />
        <Metric label="证据缺口" value={summary.evidence_gap_count} />
        <Metric label="未评估规则" value={summary.not_evaluated_rule_count} />
      </div>

      {findings.findings.length > 0 ? (
        <ul className="mt-4 divide-y divide-[var(--hairline)] border-t border-b border-[var(--hairline)] min-w-0">
          {findings.findings.map((item) => (
            <FindingRow key={item.finding_id} finding={item} />
          ))}
        </ul>
      ) : (
        <p className="mt-4 rounded-[10px] border border-[var(--hairline)] bg-[var(--bg-soft)] px-3 py-4 text-center text-sm text-[var(--text-tertiary)]">
          本次观察中没有形成可展示的隐私发现。
        </p>
      )}

      {findings.limitations.length > 0 && (
        <div className="mt-4 flex items-start gap-2 text-xs text-[var(--text-secondary)]">
          <ShieldQuestion size={14} className="mt-0.5 shrink-0 text-[var(--warning)]" />
          <div className="min-w-0">
            <p className="font-medium text-[var(--text-primary)]">证据限制</p>
            <ul className="mt-1 list-disc pl-4 break-words space-y-0.5">
              {findings.limitations.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <details className="mt-4 rounded-[10px] border border-[var(--hairline)] px-3 py-2 min-w-0">
        <summary className="cursor-pointer text-xs font-medium text-[var(--text-tertiary)] hover:text-[var(--text-primary)] transition-colors">
          规则评估明细（{findings.rule_results.length}）
        </summary>
        <ul className="mt-2 divide-y divide-[var(--hairline)]">
          {findings.rule_results.map((rule) => (
            <li
              key={rule.rule_id}
              className="flex items-start justify-between gap-2 flex-wrap py-1.5 text-xs"
            >
              <span className="min-w-0 break-all font-mono text-[var(--text-secondary)]">
                {rule.rule_id}
              </span>
              <span className="shrink-0 text-[var(--text-tertiary)] font-mono">{rule.status}</span>
            </li>
          ))}
        </ul>
      </details>
    </GlassCard>
  )
}

function Metric({ label, value }: { label: string; value: number }) {
  return (
    <div className="px-3 py-2.5 min-w-0">
      <p className="text-[11px] text-[var(--text-tertiary)] truncate">{label}</p>
      <p className="mt-0.5 text-lg font-semibold tabular-nums text-[var(--text-primary)]">{value}</p>
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
    <li className="py-3.5 min-w-0">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0 flex-1">
          <p className="break-words text-sm font-semibold text-[var(--text-primary)]">
            {finding.title}
          </p>
          <div className="mt-1 flex items-center gap-2 flex-wrap text-xs text-[var(--text-tertiary)]">
            <span className={cn('font-medium', TYPE_TEXT_CLASS[finding.finding_type])}>
              {TYPE_LABEL[finding.finding_type]}
            </span>
            <span aria-hidden>·</span>
            <span>{CONFIDENCE_LABEL[finding.confidence]}</span>
            <span aria-hidden>·</span>
            <span className="tabular-nums">
              {CONSENT_LABEL[finding.consent_state]} · 证据 {finding.evidence_refs.length} 条
            </span>
          </div>
        </div>
        <span
          className={cn(
            'shrink-0 rounded-full border px-2.5 py-0.5 text-xs font-medium',
            SEVERITY_CLASS[finding.severity],
          )}
        >
          {SEVERITY_LABEL[finding.severity]}
        </span>
      </div>

      <p className="mt-2 text-xs leading-relaxed text-[var(--text-secondary)] break-words">
        {finding.summary}
      </p>

      {finding.reason_codes.length > 0 && (
        <ul className="mt-2 flex flex-col gap-1">
          {finding.reason_codes.map((code) => (
            <li key={code} className="text-xs text-[var(--text-secondary)] break-words">
              · {REASON_COPY[code] ?? code}
            </li>
          ))}
        </ul>
      )}

      <button
        type="button"
        onClick={() => setOpen((value) => !value)}
        aria-expanded={open}
        className="mt-2.5 inline-flex items-center gap-1 text-xs font-medium text-[var(--text-primary)] hover:underline"
      >
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        证据链（{chain.length} 个环节）
      </button>

      {open && (
        <div className="mt-2.5 flex flex-col gap-2.5 rounded-[10px] bg-[var(--bg-soft)] p-3 min-w-0">
          <p className="text-xs leading-relaxed text-[var(--text-secondary)] break-words">
            {finding.explanation}
          </p>
          {chain.length > 0 ? (
            <div className="divide-y divide-[var(--hairline)] border-t border-[var(--hairline)]">
              {chain.map((group) => (
                <EvidenceGroup key={group.type} type={group.type} refs={group.refs} />
              ))}
            </div>
          ) : (
            <p className="text-xs text-[var(--text-tertiary)]">
              本发现没有可展示的证据引用。
            </p>
          )}
          {finding.limitations.length > 0 && (
            <ul className="list-disc pl-4 text-xs text-[var(--text-secondary)] break-words space-y-0.5">
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
    <div className="py-2 first:pt-2 last:pb-0 min-w-0">
      <p className="text-[11px] font-medium uppercase tracking-wide text-[var(--text-tertiary)]">
        {EVIDENCE_LABEL[type]}
      </p>
      <ul className="mt-1 flex flex-col gap-1">
        {refs.map((ref) => (
          <li
            key={`${ref.evidence_type}-${ref.evidence_id}`}
            className="min-w-0 break-words text-xs text-[var(--text-secondary)]"
          >
            {ref.label}
            <span className="ml-1.5 break-all font-mono text-[11px] text-[var(--text-tertiary)]">
              {ref.artifact}#{ref.evidence_id}
            </span>
          </li>
        ))}
      </ul>
    </div>
  )
}

export default PrivacyFindingsCard