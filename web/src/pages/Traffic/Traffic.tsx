import { useMemo, useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import { Network, Loader2, Hand, ShieldAlert, Info } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard } from '@/components/common/StatCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { EmptyState, ErrorState, LoadingState } from '@/components/common/States'
import { TrafficRequestDrawer } from '@/components/traffic/TrafficRequestDrawer'
import { DeviceSelector } from '@/components/analysis/DeviceSelector'
import { useTrafficCheck } from '@/hooks/useApi'
import { useTaskReport } from '@/hooks/useTasks'
import type { TrafficCheckResponse, HttpRequestRecord, CollectorOutcome, TrafficSummary } from '@/types/api'
import { formatBytes, cn } from '@/utils'

const COLLECTOR_LABEL: Record<CollectorOutcome, string> = {
  collector_failed: '采集失败',
  collector_success_zero_requests: '采集成功·零请求',
  collector_success_requests_observed: '采集成功·观测到请求',
  collector_disabled: '采集未启用',
}

export default function Traffic() {
  const [searchParams] = useSearchParams()
  const taskId = searchParams.get('task_id') ?? undefined
  const taskReport = useTaskReport(taskId)
  const [deviceId, setDeviceId] = useState('')
  const [enabled, setEnabled] = useState(false)
  const query = useTrafficCheck(deviceId, enabled)
  const [active, setActive] = useState<HttpRequestRecord | null>(null)

  const samples = useMemo<HttpRequestRecord[]>(() => {
    // 后端 /traffic/check 返回请求样本;类型层为防御性 Record<string,unknown>[],此处按已记录字段窄化为 HttpRequestRecord[]。
    const raw = (query.data?.sample_requests ?? []) as unknown as HttpRequestRecord[]
    return raw.filter((r) => typeof r === 'object' && r !== null && r.type === 'http_request')
  }, [query.data])

  if (taskId && taskReport.isLoading) {
    return <GlassCard padding="none"><LoadingState title="正在加载任务流量证据…" /></GlassCard>
  }
  if (taskId && taskReport.isError) {
    return <GlassCard padding="none"><ErrorState icon={<ShieldAlert size={28} />} title="任务流量加载失败" description={taskReport.error.message} /></GlassCard>
  }
  if (taskId) {
    return <TaskTraffic taskId={taskId} summary={taskReport.data?.report?.traffic_summary ?? null} />
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="网络外发"
        description="对指定设备执行流量捕获自检(GET /traffic/check)。仅返回请求元数据样本,不含原始头/体/URL。"
      />

      <div
        role="note"
        aria-live="polite"
        className="glass rounded-[12px] border border-[var(--border-active)] bg-[rgba(91,205,255,0.06)] px-4 py-3 flex items-start gap-2.5"
      >
        <Info size={18} className="text-[var(--accent-blue)] shrink-0 mt-0.5" aria-hidden="true" />
        <div className="text-[13px] leading-relaxed text-[var(--text-secondary)] space-y-1">
          <p>
            <strong className="text-[var(--text-primary)]">本页展示的是 <code className="font-mono">/traffic/check</code> 环境自检结果,不是某次 APK 动态采集任务的流量。</strong>
            后端目前没有「按任务读取流量」的接口,因此页面仅展示自检取得的摘要与样本,绝不把自检样本伪造成真实 APK 的采集结果。
          </p>
          <p className="text-[12px] text-[var(--text-tertiary)]">
            数据来源分三类,均如实标注:①「自检环境」— <code className="font-mono">/traffic/check</code> 探测;②「真实采集」— 由 <code className="font-mono">/dynamic/analyze</code> 在动态任务内完成(其结果在「任务」页查看),本页不展示;③「演示样本」— 无任何来源时显示空态,绝不伪造请求。
          </p>
        </div>
      </div>

      <GlassCard padding="md" highlight className="flex flex-col gap-3">
        <DeviceSelector value={deviceId} onChange={setDeviceId} disabled={query.isFetching} />
        <div className="flex items-center gap-2">
          <button
            type="button"
            disabled={!deviceId.trim()}
            onClick={() => setEnabled(true)}
            className={cn(
              'inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm font-medium transition',
              !deviceId.trim() ? 'opacity-50 cursor-not-allowed' : '',
              !enabled ? 'bg-[var(--accent-blue)] text-[var(--text-on-accent)] hover:brightness-110' : '',
            )}
          >
            <Network size={15} /> 执行流量自检
          </button>
          {enabled && (
            <button
              type="button"
              onClick={() => setEnabled(false)}
              className="text-xs px-3 py-1.5 rounded-[10px] border border-[var(--border-soft)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]"
            >
              停用
            </button>
          )}
          {query.isFetching && <Loader2 size={16} className="animate-spin text-[var(--accent-blue)]" />}
        </div>
      </GlassCard>

      {!enabled && (
        <EmptyState
          icon={<Network size={28} />}
          title="尚未发起流量自检"
          description="选择设备后点击「执行流量自检」,系统将向 GET /traffic/check 发起请求并展示请求样本与采集摘要。"
        />
      )}

      {enabled && query.isPending && (
        <GlassCard padding="md"><div className="flex items-center gap-2 text-sm text-[var(--text-secondary)]"><Loader2 size={16} className="animate-spin" /> 正在采集流量自检结果…</div></GlassCard>
      )}

      {enabled && query.isError && (
        <GlassCard padding="md">
          <ErrorState
            icon={<ShieldAlert size={28} />}
            title="流量自检失败"
            description={(query.error as { message?: string })?.message ?? '请确认设备在线与 mitmproxy 状态后重试。'}
          />
        </GlassCard>
      )}

      {enabled && query.data && (
        <TrafficResultPanel data={query.data} samples={samples} onOpen={setActive} />
      )}

      <TrafficRequestDrawer record={active} onClose={() => setActive(null)} />
    </div>
  )
}

function TaskTraffic({ taskId, summary }: { taskId: string; summary: TrafficSummary | null }) {
  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="网络外发"
        description="当前展示指定任务持久化报告中的真实流量采集结果。"
        eyebrow={`任务 ${taskId}`}
      />
      {!summary ? (
        <GlassCard padding="none">
          <EmptyState icon={<Network size={28} />} title="无任务流量证据" description="任务未启用流量采集或采集结果未形成；这不代表应用不存在网络行为。" />
        </GlassCard>
      ) : (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <StatCard label="采集状态" value={summary.status} tone={summary.status === 'success' ? 'success' : 'danger'} />
            <StatCard label="请求总数" value={summary.total_requests} tone="default" />
            <StatCard label="覆盖度" value={summary.coverage} tone="accent" />
            <StatCard label="采集结局" value={COLLECTOR_LABEL[summary.collector_outcome]} tone={summary.collector_outcome === 'collector_failed' ? 'danger' : 'success'} />
          </div>
          <GlassCard padding="md" highlight>
            <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">访问域名摘要</h3>
            {summary.top_hosts.length ? (
              <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                {summary.top_hosts.map((host) => (
                  <li key={host.host ?? 'unknown'} className="rounded-[10px] border border-[var(--border-soft)] px-3 py-2 flex items-center justify-between gap-3">
                    <span className="text-sm text-[var(--text-secondary)] font-mono truncate">{host.host ?? '(未记录)'}</span>
                    <span className="text-xs text-[var(--text-tertiary)]">{host.count}</span>
                  </li>
                ))}
              </ul>
            ) : (
              <p className="text-sm text-[var(--text-tertiary)]">采集流程未记录到可确认域名；零请求不等于无网络行为。</p>
            )}
          </GlassCard>
        </>
      )}
    </div>
  )
}

function TrafficResultPanel({
  data,
  samples,
  onOpen,
}: {
  data: TrafficCheckResponse
  samples: HttpRequestRecord[]
  onOpen: (r: HttpRequestRecord) => void
}) {
  const outcome = (data as unknown as { collector_outcome?: CollectorOutcome }).collector_outcome
  const coverage = (data as unknown as { coverage?: string }).coverage
  return (
    <>
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="采集成功率" value={data.captured_success ? '是' : '否'} tone={data.captured_success ? 'success' : 'danger'} icon={<Network size={18} />} />
        <StatCard label="请求计数" value={data.captured_request_count} tone="default" />
        <StatCard label="Flow 文件" value={data.flow_file_size != null ? formatBytes(data.flow_file_size) : '—'} tone="accent" />
        <StatCard
          label="采集结局"
          value={outcome ? COLLECTOR_LABEL[outcome] : (coverage ? coverage : '—')}
          tone={outcome === 'collector_success_requests_observed' ? 'success' : outcome === 'collector_failed' ? 'danger' : 'neutral'}
        />
      </div>

      <GlassCard padding="md" highlight>
        <div className="flex items-center justify-between gap-2 mb-2">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">Top 主机<span className="ml-2 text-[11px] font-normal text-[var(--status-neutral)] align-middle">· 自检摘要</span></h3>
        </div>
        <TopHosts data={data} />
      </GlassCard>

      {data.possible_reasons.length > 0 && (
        <GlassCard padding="md">
          <h3 className="text-sm font-semibold text-[var(--warning)] mb-2">可能原因</h3>
          <ul className="text-xs text-[var(--text-secondary)] list-disc pl-4 flex flex-col gap-1">
            {data.possible_reasons.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </GlassCard>
      )}

      <GlassCard padding="md" highlight>
        <div className="flex items-center justify-between gap-2 mb-2">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">请求样本<span className="ml-2 text-[11px] font-normal text-[var(--status-neutral)] align-middle">· 仅自检样本(摘要)</span></h3>
        </div>
        <p className="text-xs text-[var(--text-tertiary)] mb-3 inline-flex items-center gap-1.5">
          <Hand size={13} /> 单条记录仅含方法、主机、路径脱敏段与查询键名,绝不含请求头/请求体/原始 URL/Cookie/鉴权信息。
          本表为自检样本,不代表任何真实 APK 的采集结果;若后端未返回完整请求清单,则以「摘要」为准,不进行补全或伪造。
        </p>
        {samples.length === 0 ? (
          <EmptyState icon={<Network size={26} />} title="无请求样本" description="本次自检未观测到 HTTP 请求样本。" />
        ) : (
          <ul className="flex flex-col gap-1.5 max-h-[480px] overflow-y-auto pr-1">
            {samples.slice(0, 200).map((r, i) => (
              <li key={r.flow_id ?? i}>
                <button
                  type="button"
                  onClick={() => onOpen(r)}
                  className="w-full text-left rounded-[10px] border border-[var(--border-soft)] px-3 py-2 hover:border-[var(--border-active)] transition-colors"
                >
                  <div className="flex items-center gap-2 flex-wrap">
                    <StatusBadge tone={r.scheme === 'https' ? 'success' : 'info'} label={r.scheme.toUpperCase()} dot={false} />
                    <span className="text-sm text-[var(--text-primary)] font-mono">{r.method}</span>
                    <span className="text-sm text-[var(--text-secondary)] truncate flex-1">{r.hostname ?? '(无主机)'}</span>
                    <span className="text-[11px] text-[var(--text-tertiary)] shrink-0">{r.status_code ?? '—'}</span>
                  </div>
                  {r.path && <p className="text-[11px] text-[var(--text-tertiary)] font-mono truncate mt-0.5">{r.path}</p>}
                </button>
              </li>
            ))}
          </ul>
        )}
        {samples.length > 200 && (
          <p className="text-[11px] text-[var(--text-tertiary)] mt-2">仅展示前 200 条,共 {samples.length} 条。</p>
        )}
      </GlassCard>
    </>
  )
}

function TopHosts({ data }: { data: TrafficCheckResponse }) {
  // /traffic/check 的 sample_requests 是宽松对象;若后端同时给了 top_hosts 直接用
  const topHosts = (data as unknown as { top_hosts?: { host: string | null; count: number }[] }).top_hosts
  if (topHosts && topHosts.length > 0) {
    return (
      <ul className="flex flex-col gap-1.5">
        {topHosts.slice(0, 8).map((h, i) => (
          <li key={i} className="flex items-center justify-between gap-3 text-sm">
            <span className="text-[var(--text-primary)] font-mono truncate">{h.host ?? '(未记录)'}</span>
            <span className="text-[var(--text-tertiary)] shrink-0">{h.count}</span>
          </li>
        ))}
      </ul>
    )
  }
  // 否则从样本里统计主机
  const fromSamples = (data.sample_requests ?? []) as { hostname?: string | null }[]
  const map = new Map<string, number>()
  for (const s of fromSamples) {
    const host = s.hostname ?? '(未记录)'
    map.set(host, (map.get(host) ?? 0) + 1)
  }
  const arr = [...map.entries()].sort((a, b) => b[1] - a[1])
  if (!arr.length) return <p className="text-sm text-[var(--text-tertiary)]">无主机统计。</p>
  return (
    <ul className="flex flex-col gap-1.5">
      {arr.slice(0, 8).map(([host, count]) => (
        <li key={host} className="flex items-center justify-between gap-3 text-sm">
          <span className="text-[var(--text-primary)] font-mono truncate">{host}</span>
          <span className="text-[var(--text-tertiary)] shrink-0">{count}</span>
        </li>
      ))}
    </ul>
  )
}
