import { useMemo, useState } from 'react'
import { Activity, ChevronDown, Filter } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import type { BehaviorTimelineData, ConsentState, TimelineEvent } from '@/types/api'

type SourceFilter = 'all' | TimelineEvent['source']
type ConsentFilter = 'all' | ConsentState

export function BehaviorTimeline({ timeline }: { timeline?: BehaviorTimelineData | null }) {
  const [source, setSource] = useState<SourceFilter>('all')
  const [consent, setConsent] = useState<ConsentFilter>('all')
  const [riskOnly, setRiskOnly] = useState(true)
  const [visible, setVisible] = useState(50)
  const events = useMemo(
    () => (timeline?.events ?? []).filter((event) => {
      if (source !== 'all' && event.source !== source) return false
      if (consent !== 'all' && event.consent_state !== consent) return false
      return !riskOnly || event.severity !== 'low'
    }),
    [timeline, source, consent, riskOnly],
  )

  return (
    <GlassCard padding="md" highlight>
      <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
          <Activity size={15} /> 行为时间线
        </h3>
        <div className="flex items-center gap-2 flex-wrap">
          <FilterSelect ariaLabel="来源筛选" value={source} onChange={(value) => setSource(value as SourceFilter)}
            options={[['all', '全部来源'], ['frida', 'Frida'], ['network', '网络'], ['system', '系统'], ['control', '控制']]} />
          <FilterSelect ariaLabel="Consent 筛选" value={consent} onChange={(value) => setConsent(value as ConsentFilter)}
            options={[['all', '全部状态'], ['pre_consent', '同意前'], ['post_consent', '同意后'], ['unknown', '时间不明']]} />
          <button type="button" onClick={() => setRiskOnly((value) => !value)}
            className="text-xs rounded-[8px] border border-[var(--border-soft)] px-2.5 py-1.5 text-[var(--text-secondary)]">
            {riskOnly ? '仅风险事件' : '全部事件'}
          </button>
        </div>
      </div>
      {!timeline ? (
        <p className="text-sm text-[var(--text-tertiary)] py-5 text-center">旧版报告未提供统一时间线。</p>
      ) : timeline.events.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)] py-5 text-center">当前任务没有可展示的事件。</p>
      ) : events.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)] py-5 text-center">当前筛选条件下没有事件。</p>
      ) : (
        <ol className="relative border-l border-[var(--border-soft)] ml-2 flex flex-col gap-2">
          {events.slice(0, visible).map((event, index, shown) => (
            <TimelineRow
              key={event.id}
              event={event}
              showConsentBoundary={
                event.consent_state === 'post_consent'
                && shown[index - 1]?.consent_state !== 'post_consent'
              }
            />
          ))}
        </ol>
      )}
      {timeline && !timeline.timing_reliable && (
        <p className="text-[11px] text-[var(--warning)] mt-3">时间证据不足；未基于文件顺序推测 Consent 状态。</p>
      )}
      {events.length > visible && (
        <button type="button" onClick={() => setVisible((value) => value + 50)}
          className="mt-3 text-xs text-[var(--accent-blue)] inline-flex items-center gap-1">
          再显示 50 条 <ChevronDown size={13} />
        </button>
      )}
    </GlassCard>
  )
}

function TimelineRow({ event, showConsentBoundary }: { event: TimelineEvent; showConsentBoundary: boolean }) {
  const [open, setOpen] = useState(false)
  const tone = event.consent_state === 'pre_consent' ? 'danger' : event.consent_state === 'post_consent' ? 'success' : 'neutral'
  const label = event.consent_state === 'pre_consent' ? '同意前' : event.consent_state === 'post_consent' ? '同意后' : '时间不明'
  return (
    <li className="pl-4 min-w-0">
      {showConsentBoundary && (
        <div className="mb-2 -ml-4 flex items-center gap-2 text-[11px] text-[var(--success)]" role="separator">
          <span className="h-px flex-1 bg-[var(--success)]/40" />
          <span>Consent 边界</span>
          <span className="h-px flex-1 bg-[var(--success)]/40" />
        </div>
      )}
      <span className="absolute -left-1.5 mt-3 w-3 h-3 rounded-full bg-[var(--accent-blue)] border-2 border-[var(--bg-deep)]" />
      <button type="button" onClick={() => setOpen((value) => !value)}
        className="w-full text-left rounded-[9px] border border-[var(--border-soft)] p-2.5 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-[11px] font-mono text-[var(--text-tertiary)]">
            {event.relative_ms == null ? '时间未知' : `+${event.relative_ms} ms`}
          </span>
          <StatusBadge tone={tone} label={label} size="sm" />
          <span className="text-[10px] text-[var(--accent-purple)] uppercase">{event.source}</span>
        </div>
        <p className="text-sm text-[var(--text-primary)] mt-1 break-words">{event.title}</p>
        {open && (
          <div className="text-xs text-[var(--text-secondary)] mt-2 break-all">
            <p>{event.description}</p>
            {event.evidence_ref && <p className="font-mono mt-1">{event.evidence_ref}</p>}
          </div>
        )}
      </button>
    </li>
  )
}

function FilterSelect({ ariaLabel, value, onChange, options }: {
  ariaLabel: string
  value: string
  onChange: (value: string) => void
  options: [string, string][]
}) {
  return (
    <label className="inline-flex items-center gap-1 rounded-[8px] border border-[var(--border-soft)] px-2">
      <Filter size={12} className="text-[var(--text-tertiary)]" />
      <select aria-label={ariaLabel} value={value} onChange={(event) => onChange(event.target.value)}
        className="bg-transparent text-xs text-[var(--text-secondary)] py-1.5 outline-none">
        {options.map(([option, label]) => <option key={option} value={option}>{label}</option>)}
      </select>
    </label>
  )
}
