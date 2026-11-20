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
  ShieldAlert,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard, MetricStrip } from '@/components/common/StatCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { RiskBadge } from '@/components/common/RiskBadge'
import { EmptyState } from '@/components/common/States'
import { useServiceHealth } from '@/hooks/useApi'
import { useTasks } from '@/hooks/useTasks'
import { formatDateTime } from '@/utils'
import { riskBadgeLevel, riskLevelLabel, taskTypeLabel } from '@/utils/taskPresentation'
import {
  BarChart,
  Bar,
  Cell,
  XAxis,
  YAxis,
  Tooltip,
  ResponsiveContainer,
  CartesianGrid,
} from 'recharts'

export default function Dashboard() {
  const navigate = useNavigate()
  const health = useServiceHealth()
  const tasksQuery = useTasks({ page: 1, page_size: 100 })
  const tasks = tasksQuery.data?.items ?? []

  const totals = tasks.reduce(
    (acc, t) => {
      acc.total += 1
      const st = t.status ?? 'unknown'
      acc[st] = (acc[st] ?? 0) + 1
      return acc
    },
    {
      total: 0,
      completed: 0,
      running: 0,
      failed: 0,
      cancelled: 0,
      queued: 0,
    } as Record<string, number>,
  )

  const chartData = [
    { name: '已完成', value: totals.completed, fill: 'var(--success)' },
    { name: '分析中', value: totals.running, fill: 'var(--accent-blue)' },
    { name: '排队中', value: totals.queued, fill: 'var(--status-neutral)' },
    { name: '失败/取消', value: totals.failed + totals.cancelled, fill: 'var(--danger)' },
  ]

  const recent = tasks.slice(0, 6)
  const riskCounts: Record<'low' | 'medium' | 'high' | 'critical', number> = {
    low: 0,
    medium: 0,
    high: 0,
    critical: 0,
  }
  for (const task of tasks) {
    if (task.risk_level && task.risk_level in riskCounts) {
      riskCounts[task.risk_level as keyof typeof riskCounts] += 1
    }
  }
  const latestRiskTask =
    tasks.find(
      (task) => task.risk_level && typeof task.risk_score === 'number',
    ) ?? null
  const latestRisk = latestRiskTask?.risk_level ?? null
  const highRiskTotal = riskCounts.high + riskCounts.critical

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="概览"
        description="后端健康状态、持久化任务统计与最近一次风险评估。"
        eyebrow="工作台 · 概览"
      />

      <MetricStrip>
        <StatCard
          embedded
          label="后端状态"
          value={health.data?.ok ? '在线' : health.isError ? '不可达' : '检测中'}
          tone={health.data?.ok ? 'success' : health.isError ? 'danger' : 'neutral'}
          icon={<Cpu size={17} />}
        />
        <StatCard
          embedded
          label="已记录任务"
          value={totals.total}
          tone="default"
          icon={<Layers size={17} />}
        />
        <StatCard
          embedded
          label="静态分析"
          value={tasks.filter((t) => t.task_type === 'static').length}
          tone="accent"
          icon={<FileSearch size={17} />}
        />
        <StatCard
          embedded
          label="动态分析"
          value={tasks.filter((t) => t.task_type === 'dynamic').length}
          tone="accent"
          icon={<Activity size={17} />}
        />
      </MetricStrip>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* 左侧 2/3：规则评估汇总图表 */}
        <GlassCard padding="md" highlight className="lg:col-span-2 flex flex-col">
          <div className="flex items-center justify-between gap-2 mb-3">
            <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
              <TrendingUp size={15} /> 规则评估汇总
            </h3>
            <span className="text-xs text-[var(--text-tertiary)]">基于本地任务记录</span>
          </div>
          {totals.total === 0 ? (
            <EmptyState
              icon={<Activity size={26} />}
              title="暂无任务数据"
              description="完成一次分析后，规则评估结果将汇总于此。"
            />
          ) : (
            <div className="h-[220px] mt-auto">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={chartData} margin={{ top: 8, right: 8, left: -16, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="var(--hairline)" vertical={false} />
                  <XAxis
                    dataKey="name"
                    tick={{ fontSize: 12, fill: 'var(--text-tertiary)' }}
                    axisLine={{ stroke: 'var(--hairline)' }}
                    tickLine={false}
                  />
                  <YAxis
                    tick={{ fontSize: 12, fill: 'var(--text-tertiary)' }}
                    axisLine={false}
                    tickLine={false}
                    allowDecimals={false}
                  />
                  <Tooltip
                    cursor={{ fill: 'var(--fill-quiet)' }}
                    contentStyle={{
                      background: 'var(--bg-panel)',
                      border: '1px solid var(--hairline)',
                      borderRadius: 10,
                      fontSize: 12,
                      color: 'var(--text-primary)',
                    }}
                  />
                  <Bar dataKey="value" radius={[6, 6, 0, 0]} maxBarSize={44}>
                    {chartData.map((entry) => (
                      <Cell key={entry.name} fill={entry.fill} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
          )}
        </GlassCard>

        {/* 右侧 1/3：最近综合风险 + 快捷入口 */}
        <div className="flex flex-col gap-4">
          <GlassCard padding="md" highlight>
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
                <ShieldAlert size={15} /> 最近综合风险
              </h3>
              <span className="text-xs text-[var(--text-tertiary)] tabular-nums">
                高风险任务：{highRiskTotal}
              </span>
            </div>

            <div className="mt-3">
              {latestRiskTask && latestRisk ? (
                <div className="flex items-baseline gap-2.5 flex-wrap">
                  <strong className="text-3xl font-semibold tracking-tight tabular-nums text-[var(--text-primary)]">
                    {latestRiskTask.risk_score}
                  </strong>
                  <span className="text-xs text-[var(--text-tertiary)]">/ 100</span>
                  <RiskBadge
                    level={riskBadgeLevel(latestRisk)}
                    label={riskLevelLabel(latestRisk)}
                  />
                </div>
              ) : (
                <p className="text-sm text-[var(--text-tertiary)]">暂无数据</p>
              )}
            </div>

            <dl className="mt-4 pt-3 border-t border-[var(--hairline)] grid grid-cols-4 gap-2 text-center">
              <RiskDistributionItem label="严重" value={riskCounts.critical} tone="text-[var(--danger)]" />
              <RiskDistributionItem label="高" value={riskCounts.high} tone="text-[var(--danger)]" />
              <RiskDistributionItem label="中" value={riskCounts.medium} tone="text-[var(--warning)]" />
              <RiskDistributionItem label="低" value={riskCounts.low} tone="text-[var(--success)]" />
            </dl>
          </GlassCard>

          <GlassCard padding="md" className="flex-1">
            <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2.5 flex items-center gap-1.5">
              <Network size={15} /> 快捷入口
            </h3>
            <div className="divide-y divide-[var(--hairline)] -mx-2">
              <QuickAction icon={<FileSearch size={15} />} label="新建静态分析" onClick={() => navigate('/analysis/new')} />
              <QuickAction icon={<Activity size={15} />} label="新建动态分析" onClick={() => navigate('/analysis/new')} />
              <QuickAction icon={<Network size={15} />} label="流量自检" onClick={() => navigate('/traffic')} />
              <QuickAction icon={<Cpu size={15} />} label="环境检测" onClick={() => navigate('/environment')} />
            </div>
          </GlassCard>
        </div>
      </div>

      {/* 最近活动：极简分隔线列表 */}
      <GlassCard padding="none">
        <div className="flex items-center justify-between px-5 py-3.5 border-b border-[var(--hairline)]">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">最近活动</h3>
          <button
            type="button"
            onClick={() => navigate('/tasks')}
            className="text-xs font-medium text-[var(--text-secondary)] hover:text-[var(--text-primary)] inline-flex items-center gap-1 transition-colors"
          >
            全部任务 <ArrowRight size={13} />
          </button>
        </div>

        {recent.length === 0 ? (
          <EmptyState
            icon={<Activity size={26} />}
            title="暂无任务"
            description="前往「新建分析」提交首次分析。"
          />
        ) : (
          <ul className="divide-y divide-[var(--hairline)]">
            {recent.map((t) => (
              <li key={t.id}>
                <button
                  type="button"
                  onClick={() => navigate(`/tasks/${t.id}`)}
                  className="w-full text-left px-5 py-3 hover:bg-[var(--fill-hover)] transition-colors flex items-center gap-3"
                >
                  <span className="shrink-0">
                    <StatusBadge
                      tone={
                        t.status === 'completed'
                          ? 'success'
                          : t.status === 'failed'
                            ? 'danger'
                            : t.status === 'running'
                              ? 'info'
                              : 'neutral'
                      }
                      label={taskTypeLabel(t.task_type)}
                      size="sm"
                    />
                  </span>
                  <span className="text-sm text-[var(--text-primary)] font-mono truncate flex-1">
                    {t.package_name || t.apk_path}
                  </span>
                  {t.risk_level && (
                    <RiskBadge
                      level={riskBadgeLevel(t.risk_level)}
                      label={riskLevelLabel(t.risk_level)}
                    />
                  )}
                  <span className="text-xs text-[var(--text-tertiary)] tabular-nums shrink-0 hidden sm:inline">
                    {formatDateTime(t.created_at)}
                  </span>
                </button>
              </li>
            ))}
          </ul>
        )}
      </GlassCard>
    </div>
  )
}

function RiskDistributionItem({
  label,
  value,
  tone,
}: {
  label: string
  value: number
  tone: string
}) {
  return (
    <div>
      <dt className="text-[11px] text-[var(--text-tertiary)]">{label}</dt>
      <dd className={`mt-0.5 text-sm font-semibold tabular-nums ${tone}`}>{value}</dd>
    </div>
  )
}

function QuickAction({
  icon,
  label,
  onClick,
}: {
  icon: ReactNode
  label: string
  onClick: () => void
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      className="w-full flex items-center gap-2.5 px-2 py-2.5 rounded-[8px] hover:bg-[var(--fill-hover)] transition-colors text-left group"
    >
      <span className="text-[var(--text-tertiary)] group-hover:text-[var(--text-primary)] transition-colors">
        {icon}
      </span>
      <span className="text-sm text-[var(--text-secondary)] group-hover:text-[var(--text-primary)] flex-1 transition-colors">
        {label}
      </span>
      <ArrowRight
        size={14}
        className="text-[var(--text-tertiary)] group-hover:translate-x-0.5 transition-transform"
      />
    </button>
  )
}