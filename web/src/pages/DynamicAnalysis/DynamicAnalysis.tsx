import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  Activity,
  Hand,
  ShieldQuestion,
  AlertTriangle,
  Eye,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { RiskSummaryCard } from '@/components/analysis/RiskSummaryCard'
import { BehaviorTimeline } from '@/components/analysis/BehaviorTimeline'
import { ComplianceInsight } from '@/components/report/ComplianceInsight'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard } from '@/components/common/StatCard'
import { ConsentTimeline } from '@/components/report/ConsentTimeline'
import { ReportRuleCard } from '@/components/report/ReportRuleCard'
import { PipelineTimeline } from '@/components/report/PipelineTimeline'
import { StatusBadge } from '@/components/common/StatusBadge'
import { useActiveResult, NoActiveResult } from '@/pages/shared/NoActiveResult'
import { useAnalysisStore } from '@/stores/analysisStore'
import { useTaskReport } from '@/hooks/useTasks'
import { ErrorState, LoadingState } from '@/components/common/States'
import type {
  DynamicEvent,
  StructuredDynamicEvent,
  LegacyDynamicEvent,
  StepResult,
} from '@/types/api'
import { formatDateTime, formatTime, cn } from '@/utils'

export default function DynamicAnalysis() {
  const [searchParams] = useSearchParams()
  const taskId = searchParams.get('task_id') ?? undefined
  const localResp = useActiveResult('dynamic')
  const remote = useTaskReport(taskId)
  const resp = remote.data?.report ?? localResp
  const task = useAnalysisStore((s) => s.task)

  if (taskId && remote.isLoading) return <GlassCard padding="none"><LoadingState title="正在加载动态报告…" /></GlassCard>
  if (taskId && remote.isError) return <GlassCard padding="none"><ErrorState icon={<AlertTriangle size={28} />} title="动态报告加载失败" description={remote.error.message} /></GlassCard>
  if (!resp) return <NoActiveResult expected="dynamic" />

  const events = resp.dynamic_events ?? []
  const counts = countConsentStates(events)
  const strict = resp.strict_dynamic_findings
  const mild = resp.dynamic_findings
  const fridaSession = resp.collector_sessions?.frida
  const mitmSession = resp.collector_sessions?.mitm

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="动态分析"
        description="同意前/同意后敏感 API 行为取证。同意时段由单调时钟划分;未捕获同意点的事件标注为「时间不明」。"
        eyebrow={`任务 ${taskId ?? task?.local_id ?? ''} · 完成于 ${formatDateTime(task?.created_at)}`}
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="事件总数" value={events.length} tone="default" icon={<Activity size={18} />} />
        <StatCard label="同意前" value={counts.pre} tone="danger" icon={<Hand size={18} />} />
        <StatCard label="同意后" value={counts.post} tone="success" />
        <StatCard label="时间不明" value={counts.unknown} tone="warning" icon={<ShieldQuestion size={18} />} />
      </div>

      <RiskSummaryCard summary={resp.risk_summary} />

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <GlassCard padding="md" highlight>
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">同意时间线</h3>
          <ConsentTimeline
            timeline={resp.dynamic_timeline}
            consentMonotonicMs={resp.dynamic_timeline?.consent_monotonic_ms ?? null}
            preSeconds={resp.pre_consent_seconds}
            postSeconds={resp.post_consent_seconds}
            eventCount={{ pre: counts.pre, post: counts.post, unknown: counts.unknown }}
          />
        </GlassCard>

        <GlassCard padding="md" highlight className="flex flex-col gap-3">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">动态采集状态</h3>
          <KV k="采集状态" v={resp.collection_status ?? '—'} />
          <KV k="动态验收等级" v={resp.dynamic_validation_level ?? 'C'} />
          <KV k="流量覆盖度" v={coverageLabel(resp.traffic_coverage)} />
          <KV k="同意前/后窗口" v={`${resp.pre_consent_seconds ?? '—'} / ${resp.post_consent_seconds ?? '—'} 秒`} />
          <KV k="启用流量采集" v={resp.enable_traffic ? '是' : '否'} />
          <KV k="UI 刺激" v={resp.enable_ui_stimulation ? '是' : '否'} />
          <KV k="采集超时" v={`${resp.collection_timeout_seconds ?? '—'} 秒`} />
          <KV k="设备序列号(脱敏)" v={resp.device?.serial ?? '—'} mono />
          {fridaSession && <KV k="Frida" v={collectorSummary(fridaSession)} mono />}
          {mitmSession && <KV k="mitmproxy" v={collectorSummary(mitmSession)} mono />}
        </GlassCard>
      </div>

      <ReportRuleCard findings={strict} strict />
      <ReportRuleCard findings={mild} />

      <BehaviorTimeline timeline={resp.timeline} />

      <ComplianceInsight insight={resp.compliance_insight} />

      <GlassCard padding="md">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">动态分析步骤</h3>
        <PipelineTimeline steps={filterDynamicSteps(resp.steps)} />
      </GlassCard>

      <EventList events={events} />

      {resp.limitations.length > 0 && (
        <GlassCard padding="md">
          <h3 className="text-sm font-semibold text-[var(--warning)] mb-2 flex items-center gap-1.5">
            <AlertTriangle size={15} /> 局限说明
          </h3>
          <ul className="text-xs text-[var(--text-secondary)] list-disc pl-4 flex flex-col gap-1">
            {resp.limitations.map((l, i) => <li key={i}>{l}</li>)}
          </ul>
        </GlassCard>
      )}
    </div>
  )
}

function EventList({ events }: { events: DynamicEvent[] }) {
  const [filter, setFilter] = useState<'all' | 'pre' | 'post' | 'unknown'>('all')
  const filtered = events.filter((e) => {
    if (filter === 'all') return true
    const cs = consentStateOf(e)
    return cs === filter || (filter === 'unknown' && cs === 'unknown')
  })

  return (
    <GlassCard padding="md" highlight>
      <div className="flex items-center justify-between gap-2 flex-wrap mb-3">
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">动态事件</h3>
        <div className="flex items-center gap-1">
          {(['all', 'pre', 'post', 'unknown'] as const).map((f) => {
            const label = { all: '全部', pre: '同意前', post: '同意后', unknown: '时间不明' }[f]
            return (
              <button
                key={f}
                type="button"
                onClick={() => setFilter(f)}
                className={cn(
                  'text-xs px-2.5 py-1 rounded-[8px] border transition-colors',
                  filter === f
                    ? 'glass-strong border-[var(--border-active)] text-[var(--text-primary)]'
                    : 'border-[var(--border-soft)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]',
                )}
              >
                {label}
              </button>
            )
          })}
        </div>
      </div>
      {filtered.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)] py-6 text-center">该筛选下无事件。</p>
      ) : (
        <ul className="flex flex-col gap-1.5 max-h-[460px] overflow-y-auto pr-1">
          {filtered.slice(0, 200).map((e, i) => (
            <EventRow key={i} event={e} />
          ))}
        </ul>
      )}
      {filtered.length > 200 && (
        <p className="text-[11px] text-[var(--text-tertiary)] mt-2">仅展示前 200 条,共 {filtered.length} 条。</p>
      )}
    </GlassCard>
  )
}

function EventRow({ event }: { event: DynamicEvent }) {
  const structured = isStructured(event)
  const api = structured ? event.api : (event as LegacyDynamicEvent).api ?? '(unknown)'
  const ts = structured ? event.timestamp_utc : (event as LegacyDynamicEvent).timestamp ?? null
  const cs = consentStateOf(event)
  const idType = structured ? (event as StructuredDynamicEvent).identifier_type : (event as LegacyDynamicEvent).identifier_type
  const idPresent = structured ? (event as StructuredDynamicEvent).identifier_present : (event as LegacyDynamicEvent).identifier_present
  const valueToken = structured ? (event as StructuredDynamicEvent).value_token : null
  const legacy = structured ? false : (event as LegacyDynamicEvent).legacy_format
  const reliable = structured ? true : false

  const tone =
    cs === 'pre_consent' ? 'danger' : cs === 'post_consent' ? 'success' : 'neutral'
  const label =
    cs === 'pre_consent' ? '同意前' : cs === 'post_consent' ? '同意后' : '时间不明'

  return (
    <li className="rounded-[10px] border border-[var(--border-soft)] px-3 py-2 flex items-center gap-3">
      <span className="shrink-0">
        <StatusBadge tone={tone as 'danger' | 'success' | 'neutral'} label={label} size="sm" />
      </span>
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-[var(--text-primary)] font-mono truncate">{api}</span>
          {idType && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-[rgba(182,161,255,0.10)] text-[var(--accent-purple)] border border-[var(--border-soft-purple)] inline-flex items-center gap-1">
              <Eye size={11} /> {idType}{idPresent === false ? '(未见)' : ''}
            </span>
          )}
          {valueToken && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-[rgba(127,147,186,0.10)] text-[var(--status-neutral)] font-mono">
              {valueToken}
            </span>
          )}
          {legacy && <span className="text-[10px] text-[var(--text-tertiary)]">遗留格式</span>}
          {!reliable && <span className="text-[10px] text-[var(--warning)]">时钟不可靠</span>}
        </div>
      </div>
      <span className="text-[11px] text-[var(--text-tertiary)] shrink-0">{formatTime(ts)}</span>
    </li>
  )
}

/* -------- helpers -------- */

function isStructured(e: DynamicEvent): e is StructuredDynamicEvent {
  return (e as { type?: string }).type === 'event'
}

function consentStateOf(e: DynamicEvent): 'pre_consent' | 'post_consent' | 'unknown' {
  if (isStructured(e)) return structuredState(e.consent_state)
  const legacy = e as LegacyDynamicEvent
  return structuredState(legacy.consent_state ?? 'unknown')
}

function structuredState(s: string): 'pre_consent' | 'post_consent' | 'unknown' {
  if (s === 'pre_consent') return 'pre_consent'
  if (s === 'post_consent') return 'post_consent'
  return 'unknown'
}

function countConsentStates(events: DynamicEvent[]) {
  let pre = 0
  let post = 0
  let unknown = 0
  for (const e of events) {
    if ((e as { type?: string }).type === 'control') continue
    const s = consentStateOf(e)
    if (s === 'pre_consent') pre += 1
    else if (s === 'post_consent') post += 1
    else unknown += 1
  }
  return { pre, post, unknown }
}

function filterDynamicSteps(steps: StepResult[]): StepResult[] {
  const dynamicNames = new Set([
    'device_selection', 'apk_install', 'mitm_start', 'mitm_ready',
    'frida_spawn', 'frida_script_load', 'frida_ready', 'app_resume',
    'dynamic_collection', 'consent_event', 'frida_stop', 'mitm_stop',
    'event_validation', 'traffic_validation',
  ])
  return steps.filter((s) => dynamicNames.has(s.name))
}

function coverageLabel(c: string | null): string {
  if (!c) return '—'
  return ({ unavailable: '不可用', no_observations: '无观测', observed: '已观测' } as Record<string, string>)[c] ?? c
}

function collectorSummary(session: Record<string, unknown>): string {
  const state = String(session.state ?? 'unknown')
  const code = session.error_code ? String(session.error_code) : null
  const stderr = session.stderr_tail
    ? String(session.stderr_tail).replace(/\s+/g, ' ').slice(0, 180)
    : null
  return [state, code, stderr].filter(Boolean).join(' · ')
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1 border-b border-[var(--border-soft)]/40">
      <dt className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide shrink-0 pt-0.5">{k}</dt>
      <dd className={cn('text-sm text-[var(--text-primary)] text-right break-all', mono && 'font-mono text-[13px]')}>{v}</dd>
    </div>
  )
}
