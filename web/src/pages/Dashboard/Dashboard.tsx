import { useNavigate } from 'react-router-dom'
import { type ReactNode } from 'react'
import {
  Activity,
  FileSearch,
  Network,
  Cpu,
  Layers,
  TrendingUp,
  ArrowRight,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard } from '@/components/common/StatCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { RiskBadge } from '@/components/common/RiskBadge'
import { EmptyState } from '@/components/common/States'
import { useServiceHealth } from '@/hooks/useApi'
import { listLocalTasks } from '@/api/tasks'
import { formatDateTime } from '@/utils'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'

export default function Dashboard() {
  const navigate = useNavigate()
  const health = useServiceHealth()
  const tasks = listLocalTasks()

  const totals = tasks.reduce(
    (acc, t) => {
      acc.total += 1
      const st = t.status ?? 'unknown'
      acc[st] = (acc[st] ?? 0) + 1
      const s = t.summary
      acc.matched += s ? s.matched : 0
      acc.notMatched += s ? s.not_matched : 0
      acc.notEvaluated += s ? s.not_evaluated : 0
      acc.errored += s ? s.errored : 0
      return acc
    },
    { total: 0, succeeded: 0, partial: 0, failed: 0, skipped: 0, matched: 0, notMatched: 0, notEvaluated: 0, errored: 0 } as Record<string, number>,
  )

  const chartData = [
    { name: '已命中', value: totals.matched, fill: 'var(--status-danger)' },
    { name: '未命中', value: totals.notMatched, fill: 'var(--success)' },
    { name: '未评估', value: totals.notEvaluated, fill: 'var(--status-neutral)' },
    { name: '异常', value: totals.errored, fill: 'var(--warning)' },
  ]

  const recent = tasks.slice(0, 6)
  const riskCounts = { low: 0, medium: 0, high: 0, critical: 0 }
  for (const task of tasks) {
    if (task.risk_level) riskCounts[task.risk_level] += 1
  }
  const latestRiskTask =
    tasks.find(
      (task) => task.risk_level && typeof task.risk_score === 'number',
    ) ?? null
  const latestRisk = latestRiskTask?.risk_level ?? null

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="控制台"
        description="AdSDK Agent 状态总览:后端健康、本地任务统计与最近活动。"
        eyebrow="概览"
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="后端状态" value={health.data?.ok ? '在线' : health.isError ? '不可达' : '检测中'} tone={health.data?.ok ? 'success' : health.isError ? 'danger' : 'neutral'} icon={<Cpu size={18} />} />
        <StatCard label="本地任务" value={totals.total} tone="default" icon={<Layers size={18} />} />
        <StatCard label="静态分析" value={tasks.filter((t) => t.kind === 'static').length} tone="accent" icon={<FileSearch size={18} />} />
        <StatCard label="动态分析" value={tasks.filter((t) => t.kind === 'dynamic').length} tone="accent" icon={<Activity size={18} />} />
      </div>

      <GlassCard padding="md">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div>
            <p className="text-[11px] text-[var(--text-tertiary)]">最近综合风险</p>
            {latestRiskTask && latestRisk ? (
              <div className="mt-1 flex items-center gap-2">
                <strong className="text-2xl text-[var(--text-primary)]">
                  {latestRiskTask.risk_score}
                </strong>
                <span className="text-xs text-[var(--text-tertiary)]">/ 100</span>
                <RiskBadge
                  level={latestRisk === 'critical' ? 'high' : latestRisk}
                  label={latestRisk}
                />
              </div>
            ) : (
              <span className="text-sm text-[var(--text-tertiary)]">暂无数据</span>
            )}
          </div>
          <div className="flex items-center gap-3 text-xs text-[var(--text-secondary)] flex-wrap">
            <span>严重 <b className="text-[var(--danger)]">{riskCounts.critical}</b></span>
            <span>高 <b className="text-[var(--danger)]">{riskCounts.high}</b></span>
            <span>中 <b className="text-[var(--warning)]">{riskCounts.medium}</b></span>
            <span>低 <b className="text-[var(--success)]">{riskCounts.low}</b></span>
          </div>
          <span className="text-xs text-[var(--text-secondary)]">高风险任务：{riskCounts.high + riskCounts.critical}</span>
        </div>
      </GlassCard>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <GlassCard padding="md" highlight className="lg:col-span-2">
          <div className="flex items-center justify-between mb-3">
            <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
              <TrendingUp size={15} /> 规则评估汇总
            </h3>
            <span className="text-[11px] text-[var(--text-tertiary)]">基于本地任务记录</span>
          </div>
          {totals.total === 0 ? (
            <EmptyState icon={<Activity size={26} />} title="暂无任务数据" description="完成一次分析后,规则评估结果将汇总于此。" />
          ) : (
            <div className="h-[220px]">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="rgba(127,147,186,0.12)" />
                  <XAxis dataKey="name" tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} axisLine={{ stroke: 'rgba(127,147,186,0.2)' }} tickLine={false} />
                  <YAxis tick={{ fontSize: 11, fill: 'var(--text-tertiary)' }} axisLine={false} tickLine={false} allowDecimals={false} />
                  <Tooltip
                    cursor={{ fill: 'rgba(157,192,255,0.06)' }}
                    contentStyle={{ background: 'rgba(13,20,48,0.92)', border: '1px solid var(--border-soft)', borderRadius: 10, fontSize: 12, color: 'var(--text-primary)' }}
                  />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </GlassCard>

        <GlassCard padding="md" highlight>
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-1.5">
            <Network size={15} /> 快捷入口
          </h3>
          <div className="flex flex-col gap-2">
            <QuickAction icon={<FileSearch size={16} />} label="新建静态分析" onClick={() => navigate('/analysis/new')} />
            <QuickAction icon={<Activity size={16} />} label="新建动态分析" onClick={() => navigate('/analysis/new')} />
            <QuickAction icon={<Network size={16} />} label="流量自检" onClick={() => navigate('/traffic')} />
            <QuickAction icon={<Cpu size={16} />} label="环境检测" onClick={() => navigate('/environment')} />
          </div>
        </GlassCard>
      </div>

      <GlassCard padding="md">
        <div className="flex items-center justify-between mb-3">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">最近活动</h3>
          <button type="button" onClick={() => navigate('/tasks')} className="text-xs text-[var(--accent-blue)] hover:underline inline-flex items-center gap-1">
            全部任务 <ArrowRight size={12} />
          </button>
        </div>
        {recent.length === 0 ? (
          <EmptyState icon={<Activity size={26} />} title="暂无任务" description="前往「新建分析」提交首次分析。" />
        ) : (
          <ul className="flex flex-col gap-1.5">
            {recent.map((t) => (
              <li key={t.local_id}>
                <button
                  type="button"
                  onClick={() => navigate(`/tasks/${t.local_id}`)}
                  className="w-full text-left rounded-[10px] border border-[var(--border-soft)] px-3 py-2 hover:border-[var(--border-active)] transition-colors flex items-center gap-3"
                >
                  <span className="shrink-0">
                    <StatusBadge
                      tone={t.status === 'success' ? 'success' : t.status === 'failed' ? 'danger' : t.status === 'partial' ? 'warning' : 'neutral'}
                      label={t.kind === 'static' ? '静态' : '动态'}
                      size="sm"
                    />
                  </span>
                  <span className="text-sm text-[var(--text-primary)] font-mono truncate flex-1">{t.package_name || t.apk_path}</span>
                  {t.risk_level && <RiskBadge level={t.risk_level === 'critical' ? 'high' : t.risk_level} label={t.risk_level} />}
                  <span className="text-[11px] text-[var(--text-tertiary)] shrink-0">{formatDateTime(t.created_at)}</span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </GlassCard>
    </div>
  )
}

function QuickAction({ icon, label, onClick }: { icon: ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="flex items-center gap-2.5 px-3 py-2.5 rounded-[10px] border border-[var(--border-soft)] hover:border-[var(--border-active)] hover:bg-[rgba(157,192,255,0.06)] transition-colors text-left"
    >
      <span className="text-[var(--accent-blue)]">{icon}</span>
      <span className="text-sm text-[var(--text-secondary)] flex-1">{label}</span>
      <ArrowRight size={14} className="text-[var(--text-tertiary)]" />
    </button>
  )
}
