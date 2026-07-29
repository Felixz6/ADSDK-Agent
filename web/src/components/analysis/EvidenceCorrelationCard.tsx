import { Link2, ShieldQuestion } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { cn } from '@/utils'
import type {
  CorrelationConfidence,
  EvidenceCorrelation,
  EvidenceCorrelationItem,
} from '@/types/api'

const STATUS_COPY: Record<EvidenceCorrelation['status'], string> = {
  evaluated: '已按可信时间信息完成计算；关联仅表示时间接近或可能相关。',
  no_observations: '动态事件或网络请求没有形成可供关联的观察记录。',
  not_evaluated: '事件与请求存在，但时间信息不足，未进行关联判断。',
  error: '关联模块执行异常；主报告与原始证据仍可查看。',
}

const CONFIDENCE_LABEL: Record<CorrelationConfidence, string> = {
  high: '高',
  medium: '中',
  low: '低',
}

const CONFIDENCE_CLASS: Record<CorrelationConfidence, string> = {
  high: 'border-[rgba(91,224,184,0.4)] text-[var(--success)]',
  medium: 'border-[rgba(242,203,119,0.45)] text-[var(--warning)]',
  low: 'border-[rgba(127,147,186,0.45)] text-[var(--status-neutral)]',
}

export function EvidenceCorrelationCard({
  correlation,
}: {
  correlation?: EvidenceCorrelation | null
}) {
  if (correlation == null) {
    return (
      <GlassCard padding="md">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
          <Link2 size={15} /> 动态事件与网络请求关联
        </h3>
        <p className="mt-3 text-sm text-[var(--text-tertiary)]">
          旧版本报告未生成事件—网络关联结果。
        </p>
      </GlassCard>
    )
  }

  const summary = correlation.summary
  return (
    <GlassCard padding="md" highlight className="min-w-0">
      <div className="flex items-start justify-between gap-3 flex-wrap">
        <div className="min-w-0">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
            <Link2 size={15} /> 动态事件与网络请求关联
          </h3>
          <p className="mt-1 text-xs text-[var(--text-tertiary)]">
            {STATUS_COPY[correlation.status]}
          </p>
        </div>
        <StatusBadge
          tone={
            correlation.status === 'evaluated'
              ? 'success'
              : correlation.status === 'error'
                ? 'warning'
                : 'neutral'
          }
          label={correlation.status}
        />
      </div>

      <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-2">
        <Metric label="动态事件" value={summary.dynamic_event_count} />
        <Metric label="网络请求" value={summary.network_request_count} />
        <Metric label="关联数量" value={summary.correlated_pair_count} />
        <Metric label="高置信" value={summary.high_confidence_count} />
        <Metric label="中置信" value={summary.medium_confidence_count} />
        <Metric label="低置信" value={summary.low_confidence_count} />
      </div>
      <p className="mt-2 text-[11px] text-[var(--text-tertiary)]">
        时间窗口 {correlation.window_ms} ms
      </p>

      {correlation.items.length > 0 ? (
        <ul className="mt-4 flex flex-col gap-2 min-w-0">
          {correlation.items.slice(0, 50).map((item) => (
            <CorrelationRow key={item.correlation_id} item={item} />
          ))}
        </ul>
      ) : (
        <p className="mt-4 rounded-[10px] border border-[var(--border-soft)] px-3 py-4 text-center text-sm text-[var(--text-tertiary)]">
          {correlation.status === 'evaluated'
            ? '未观察到时间窗口内的可关联证据。'
            : STATUS_COPY[correlation.status]}
        </p>
      )}

      {correlation.limitations.length > 0 && (
        <div className="mt-4 flex items-start gap-2 text-xs text-[var(--text-secondary)]">
          <ShieldQuestion size={14} className="mt-0.5 shrink-0 text-[var(--warning)]" />
          <div className="min-w-0">
            <p className="font-medium text-[var(--text-primary)]">证据限制</p>
            <ul className="mt-1 list-disc pl-4 break-words">
              {correlation.limitations.map((item, index) => (
                <li key={index}>{item}</li>
              ))}
            </ul>
          </div>
        </div>
      )}

      <details className="mt-4 rounded-[10px] border border-[var(--border-soft)] px-3 py-2 min-w-0">
        <summary className="cursor-pointer text-xs text-[var(--text-tertiary)]">
          技术详情
        </summary>
        <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all text-[11px] text-[var(--text-secondary)]">
          {JSON.stringify(correlation, null, 2)}
        </pre>
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

function CorrelationRow({ item }: { item: EvidenceCorrelationItem }) {
  return (
    <li className="rounded-[12px] border border-[var(--border-soft)] p-3 min-w-0">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <p className="min-w-0 break-all font-mono text-xs text-[var(--text-primary)]">
          {item.event_type} ↔ {item.request_method} {item.request_host}
        </p>
        <span
          className={cn(
            'shrink-0 rounded-full border px-2 py-0.5 text-[11px]',
            CONFIDENCE_CLASS[item.confidence],
          )}
        >
          {CONFIDENCE_LABEL[item.confidence]}置信
        </span>
      </div>
      <p className="mt-1 text-xs text-[var(--text-secondary)] break-words">
        时间差 {item.delta_ms} ms · {consentLabel(item.consent_state)}
      </p>
      <p className="mt-1 text-xs text-[var(--text-tertiary)] break-words">{item.summary}</p>
      <p className="mt-1 break-all font-mono text-[10px] text-[var(--text-tertiary)]">
        {item.reason_codes.join(' · ')}
      </p>
    </li>
  )
}

function consentLabel(value: EvidenceCorrelationItem['consent_state']) {
  return {
    pre_consent: 'Consent 前',
    post_consent: 'Consent 后',
    unknown: 'Consent 阶段未知',
  }[value]
}

export default EvidenceCorrelationCard
