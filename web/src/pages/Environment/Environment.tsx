import { useState } from 'react'
import { Cpu, Loader2, RefreshCw, Network, ShieldAlert, Hand } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard } from '@/components/common/StatCard'
import { EnvironmentStatusCard } from '@/components/report/EnvironmentStatusCard'
import { EmptyState, ErrorState } from '@/components/common/States'
import { DeviceSelector } from '@/components/analysis/DeviceSelector'
import { useEnvCheck, useTrafficCheck, useServiceHealth } from '@/hooks/useApi'
import type { TrafficCheckResponse } from '@/types/api'
import { formatBytes, cn } from '@/utils'

export default function Environment() {
  const health = useServiceHealth()
  const [deviceId, setDeviceId] = useState('')
  const env = useEnvCheck(deviceId || undefined)
  const [trafficEnabled, setTrafficEnabled] = useState(false)
  const traffic = useTrafficCheck(deviceId, trafficEnabled)

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="环境检测"
        description="校验 AdSDK Agent 后端依赖:ADB / 设备 / Frida / mitmproxy / 输出目录 / 流量捕获。"
        actions={
          <button
            type="button"
            onClick={() => { env.refetch(); health.refetch() }}
            className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] text-xs border border-[var(--border-soft)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
          >
            <RefreshCw size={13} className={env.isFetching ? 'animate-spin' : ''} /> 刷新
          </button>
        }
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="后端服务" value={health.data?.ok ? '在线' : health.isError ? '不可达' : '检测中'} tone={health.data?.ok ? 'success' : health.isError ? 'danger' : 'neutral'} icon={<Cpu size={18} />} />
        <StatCard label="ADB 工具" value={labelFromBool(env.data?.checks.adb_available)} tone={toneFromBool(env.data?.checks.adb_available)} />
        <StatCard label="设备在线" value={env.data ? `${env.data.details.device.online_count} 台` : '—'} tone={env.data?.checks.device_online ? 'success' : 'neutral'} />
        <StatCard label="mitmproxy" value={labelFromBool(env.data?.checks.mitm_8080_listening)} tone={toneFromBool(env.data?.checks.mitm_8080_listening)} />
      </div>

      <GlassCard padding="md" highlight className="flex flex-col gap-3">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
          <Cpu size={15} /> 选择目标设备
        </h3>
        <DeviceSelector value={deviceId} onChange={setDeviceId} disabled={env.isFetching} />
        <div className="flex items-center gap-2 flex-wrap">
          <button
            type="button"
            disabled={!deviceId.trim()}
            onClick={() => setTrafficEnabled(true)}
            className={cn(
              'inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm font-medium transition',
              !deviceId.trim() ? 'opacity-50 cursor-not-allowed' : '',
              !trafficEnabled ? 'bg-[var(--accent-blue)] text-[var(--text-on-accent)] hover:brightness-110' : '',
            )}
          >
            <Network size={15} /> 流量自检
          </button>
          {trafficEnabled && (
            <button
              type="button"
              onClick={() => setTrafficEnabled(false)}
              className="text-xs px-3 py-1.5 rounded-[10px] border border-[var(--border-soft)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]"
            >
              停用
            </button>
          )}
          {env.isFetching && <Loader2 size={16} className="animate-spin text-[var(--accent-blue)]" />}
        </div>
      </GlassCard>

      {env.isPending && (
        <GlassCard padding="md"><div className="flex items-center gap-2 text-sm text-[var(--text-secondary)]"><Loader2 size={16} className="animate-spin" /> 正在执行环境自检…</div></GlassCard>
      )}

      {env.isError && (
        <GlassCard padding="md">
          <ErrorState
            icon={<ShieldAlert size={28} />}
            title="环境自检失败"
            description={(env.error as { message?: string })?.message ?? '请确认后端服务在线后重试。'}
          />
        </GlassCard>
      )}

      {env.data && (
        <>
          <EnvironmentStatusCard
            env={env.data}
            traffic={trafficEnabled && traffic.data ? traffic.data : null}
            trafficTriggered={trafficEnabled}
          />

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            <DetailCard title="ADB 详情" data={env.data.details.adb} />
            <DetailCard title="Frida 详情" data={env.data.details.frida} />
            <DetailCard title="mitmproxy 详情" data={env.data.details.mitm} />
            <DetailCard title="输出目录详情" data={env.data.details.output} />
          </div>

          {env.data.details.device.devices.length > 0 && (
            <GlassCard padding="md">
              <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2">在线设备列表</h3>
              <p className="text-[11px] text-[var(--text-tertiary)] mb-2 inline-flex items-center gap-1.5">
                <Hand size={13} /> 设备序列号经脱敏回显,请勿作为身份凭证外泄。
              </p>
              <ul className="flex flex-col gap-1.5">
                {env.data.details.device.devices.map((d) => (
                  <li key={d.device_id} className="flex items-center gap-2 text-xs">
                    <span className="font-mono px-2 py-1 rounded-md border border-[var(--border-soft)] text-[var(--text-secondary)]">{d.device_id}</span>
                    <span className="text-[var(--text-tertiary)]">{d.status}</span>
                  </li>
                ))}
              </ul>
            </GlassCard>
          )}
        </>
      )}

      {trafficEnabled && traffic.isError && (
        <GlassCard padding="md">
          <ErrorState
            icon={<ShieldAlert size={28} />}
            title="流量自检失败"
            description={(traffic.error as { message?: string })?.message ?? '请确认 mitmproxy 与设备在线后重试。'}
          />
        </GlassCard>
      )}

      {trafficEnabled && traffic.data && <TrafficDetail data={traffic.data} />}

      {!env.isPending && !env.isError && !env.data && (
        <EmptyState icon={<Cpu size={28} />} title="无环境数据" description="点击「刷新」重新发起自检。" />
      )}
    </div>
  )
}

function DetailCard({ title, data }: { title: string; data: object }) {
  const entries = Object.entries(data)
  return (
    <GlassCard padding="md" highlight>
      <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2">{title}</h3>
      {entries.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)]">无明细。</p>
      ) : (
        <dl className="flex flex-col gap-1">
          {entries.map(([k, v]) => (
            <div key={k} className="flex items-start justify-between gap-3 py-1 border-b border-[var(--border-soft)]/40">
              <dt className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide shrink-0 pt-0.5">{k}</dt>
              <dd className="text-xs text-[var(--text-primary)] text-right break-all font-mono max-w-[60%]">{formatValue(v)}</dd>
            </div>
          ))}
        </dl>
      )}
    </GlassCard>
  )
}

function TrafficDetail({ data }: { data: TrafficCheckResponse }) {
  return (
    <GlassCard padding="md" highlight>
      <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2">流量自检结果</h3>
      <dl className="grid grid-cols-2 sm:grid-cols-3 gap-3">
        <KV k="采集成功" v={data.captured_success ? '是' : '否'} />
        <KV k="请求计数" v={`${data.captured_request_count}`} />
        <KV k="Flow 文件" v={data.flow_file_size != null ? formatBytes(data.flow_file_size) : '—'} />
      </dl>
      {data.possible_reasons.length > 0 && (
        <div className="mt-3">
          <p className="text-xs text-[var(--warning)] mb-1">可能原因</p>
          <ul className="text-xs text-[var(--text-secondary)] list-disc pl-4 flex flex-col gap-1">
            {data.possible_reasons.map((r, i) => <li key={i}>{r}</li>)}
          </ul>
        </div>
      )}
    </GlassCard>
  )
}

function KV({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex flex-col gap-0.5">
      <dt className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide">{k}</dt>
      <dd className="text-sm text-[var(--text-primary)] font-mono">{v}</dd>
    </div>
  )
}

function labelFromBool(v: boolean | null | undefined): string {
  if (v == null) return '—'
  return v ? '正常' : '异常'
}
function toneFromBool(v: boolean | null | undefined): 'success' | 'danger' | 'neutral' {
  if (v == null) return 'neutral'
  return v ? 'success' : 'danger'
}
function formatValue(v: unknown): string {
  if (typeof v === 'string') return v
  if (typeof v === 'number') return String(v)
  if (typeof v === 'boolean') return v ? '是' : '否'
  if (Array.isArray(v)) return v.length ? v.map(String).join(', ') : '空'
  if (v == null) return '—'
  try {
    return JSON.stringify(v)
  } catch {
    return String(v)
  }
}

// (无尾部哨兵 — env 通过 env.data 条件渲染被使用)
