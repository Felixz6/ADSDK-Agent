import { useState } from 'react'
import {
  Activity,
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  Clock3,
  FileSearch,
  Fingerprint,
  GitCompareArrows,
  Globe2,
  Network,
  Plus,
  ShieldAlert,
  ShieldCheck,
  Trash2,
} from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { GlassCard } from '@/components/common/GlassCard'
import { Checkbox } from '@/components/common/Checkbox'
import { EmptyState, ErrorState, LoadingState } from '@/components/common/States'
import { StatCard } from '@/components/common/StatCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { useComparisons, useCreateComparison, useTasks } from '@/hooks/useTasks'
import { useUIStore } from '@/stores/uiStore'
import { formatDateTime } from '@/utils'
import {
  formatVersion,
  safeApplicationName,
  shortTaskId,
  taskTypeLongLabel,
} from '@/utils/taskPresentation'
import type { ComparisonResult, DifferenceSet, TaskRecord } from '@/types/tasks'

const CAPABILITIES = [
  { icon: ShieldCheck, label: '权限', description: '新增、移除与高风险权限' },
  { icon: Fingerprint, label: 'SDK 及厂商', description: '组件、厂商和用途分类' },
  { icon: ShieldAlert, label: '风险评分', description: '风险分与等级变化' },
  { icon: FileSearch, label: '规则状态', description: '命中与评估状态差异' },
  { icon: Globe2, label: '网络域名', description: '网络外发目标增减' },
  { icon: Activity, label: '动态行为', description: '敏感 API 行为变化' },
  { icon: Network, label: '证据覆盖率', description: '识别证据是否充分' },
]

export default function Comparison() {
  const pushToast = useUIStore((state) => state.pushToast)
  const tasks = useTasks({ status: 'completed', page: 1, page_size: 100 })
  const comparisons = useComparisons()
  const createMutation = useCreateComparison()
  const [baseId, setBaseId] = useState('')
  const [targetId, setTargetId] = useState('')
  const [allowCrossApp, setAllowCrossApp] = useState(false)
  const [result, setResult] = useState<ComparisonResult | null>(null)
  const selectableTasks = (tasks.data?.items ?? []).filter(
    (task) => task.task_type !== 'comparison' && task.report_json_path,
  )

  async function compare() {
    if (!baseId || !targetId || baseId === targetId) {
      pushToast({ kind: 'warning', message: '请选择两个不同的已完成任务。', duration: 3500 })
      return
    }
    try {
      const comparison = await createMutation.mutateAsync({
        base_task_id: baseId,
        target_task_id: targetId,
        allow_cross_app: allowCrossApp,
      })
      setResult(comparison)
      pushToast({ kind: 'success', message: '确定性对比已完成。', duration: 2500 })
    } catch (error) {
      pushToast({ kind: 'error', message: (error as { message?: string }).message ?? '对比失败', duration: 5000 })
    }
  }

  return (
    <div className="flex min-w-0 flex-col gap-5">
      <PageHeader
        title="版本对比"
        description="选择两个具有有效报告的已完成任务，查看权限、SDK、规则、域名与动态证据差异。"
        eyebrow="历史版本 · 确定性差异"
      />

      {tasks.isLoading ? (
        <GlassCard padding="none"><LoadingState title="正在加载可对比版本…" /></GlassCard>
      ) : tasks.isError ? (
        <GlassCard padding="none"><ErrorState icon={<AlertTriangle size={28} />} title="版本列表加载失败" description={tasks.error.message} /></GlassCard>
      ) : (
        <GlassCard padding="lg" highlight className="min-w-0">
          <div className="grid grid-cols-1 items-end gap-4 lg:grid-cols-[minmax(0,1fr)_auto_minmax(0,1fr)]">
            <TaskSelect label="基准版本" value={baseId} onChange={setBaseId} tasks={selectableTasks} />
            <ArrowRight size={20} className="mb-3 hidden text-[var(--accent-purple)] lg:block" />
            <TaskSelect label="目标版本" value={targetId} onChange={setTargetId} tasks={selectableTasks} />
          </div>
          <div className="mt-4 flex flex-col justify-between gap-3 sm:flex-row sm:items-center">
            <Checkbox
              checked={allowCrossApp}
              onChange={setAllowCrossApp}
              label="允许跨包名对比"
              description="仅在确认两个任务属于预期样本时启用"
            />
            <button
              type="button"
              onClick={() => void compare()}
              disabled={createMutation.isPending || selectableTasks.length < 2}
              className="control-primary"
            >
              <GitCompareArrows size={16} /> {createMutation.isPending ? '正在计算…' : '生成差异报告'}
            </button>
          </div>
          {selectableTasks.length < 2 && (
            <p className="mt-4 rounded-[10px] border border-[rgba(242,203,119,0.22)] bg-[rgba(242,203,119,0.06)] px-3 py-2 text-xs text-[var(--warning)]">
              至少需要两个带有效报告的静态或动态任务。
            </p>
          )}
        </GlassCard>
      )}

      {result ? (
        <ComparisonResultView result={result} />
      ) : (
        <ComparisonWelcome />
      )}

      <RecentComparisons
        loading={comparisons.isLoading}
        error={comparisons.isError ? comparisons.error.message : null}
        items={comparisons.data ?? []}
        onOpen={setResult}
      />
    </div>
  )
}

function TaskSelect({ label, value, onChange, tasks }: { label: string; value: string; onChange: (value: string) => void; tasks: TaskRecord[] }) {
  return (
    <label className="flex min-w-0 flex-col gap-2">
      <span className="text-xs uppercase tracking-wide text-[var(--text-tertiary)]">{label}</span>
      <select
        value={value}
        onChange={(event) => onChange(event.target.value)}
        className="glass min-w-0 rounded-[12px] px-3 py-2.5 text-sm text-[var(--text-primary)] outline-none focus:border-[var(--border-active)]"
      >
        <option value="" className="bg-[var(--bg-deep)]">请选择任务</option>
        {tasks.map((task) => (
          <option key={task.id} value={task.id} className="bg-[var(--bg-deep)]">
            {taskOptionLabel(task)}
          </option>
        ))}
      </select>
    </label>
  )
}

function taskOptionLabel(task: TaskRecord): string {
  const app = safeApplicationName({
    appName: task.app_name,
    apkPath: task.apk_path,
    packageName: task.package_name,
  })
  const sha = task.apk_sha256?.slice(0, 10) || 'SHA 待确认'
  return `${app} · ${taskTypeLongLabel(task.task_type)} · ${formatDateTime(task.created_at)} · ${formatVersion(task)} · ${sha}`
}

function ComparisonWelcome() {
  return (
    <GlassCard padding="lg" className="overflow-hidden" highlight>
      <div className="mx-auto max-w-5xl">
        <div className="mx-auto max-w-2xl text-center">
          <span className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl border border-[rgba(120,216,255,0.24)] bg-[rgba(120,216,255,0.08)] text-[var(--accent-blue)] shadow-[0_0_32px_rgba(120,216,255,0.1)]">
            <GitCompareArrows size={24} />
          </span>
          <h2 className="mt-4 text-base font-semibold text-[var(--text-primary)]">选择两个版本，建立清晰的变化视图</h2>
          <p className="mt-2 text-sm leading-relaxed text-[var(--text-secondary)]">
            结果严格区分“没有变化”和“证据不足”，历史对比可在下方直接重新打开。
          </p>
        </div>
        <div className="mt-6 grid grid-cols-2 gap-3 md:grid-cols-4">
          {CAPABILITIES.map(({ icon: Icon, label, description }, index) => (
            <div
              key={label}
              className={`rounded-[14px] border border-[rgba(157,192,255,0.1)] bg-[rgba(7,18,38,0.32)] p-3.5 ${index === CAPABILITIES.length - 1 ? 'col-span-2 md:col-span-1' : ''}`}
            >
              <Icon size={17} className="text-[var(--accent-purple)]" />
              <p className="mt-2 text-sm font-medium text-[var(--text-primary)]">{label}</p>
              <p className="mt-1 text-[11px] leading-relaxed text-[var(--text-tertiary)]">{description}</p>
            </div>
          ))}
        </div>
      </div>
    </GlassCard>
  )
}

function RecentComparisons({
  loading,
  error,
  items,
  onOpen,
}: {
  loading: boolean
  error: string | null
  items: ComparisonResult[]
  onOpen: (result: ComparisonResult) => void
}) {
  return (
    <GlassCard padding="md" className="min-w-0">
      <div className="mb-3 flex items-center justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">最近对比</h2>
          <p className="mt-1 text-[11px] text-[var(--text-tertiary)]">打开已有结果时不会重新执行分析。</p>
        </div>
        <Clock3 size={17} className="text-[var(--accent-purple)]" />
      </div>
      {loading ? (
        <LoadingState title="正在加载历史对比…" />
      ) : error ? (
        <ErrorState icon={<AlertTriangle size={24} />} title="历史对比加载失败" description={error} />
      ) : items.length ? (
        <ul className="grid grid-cols-1 gap-2 lg:grid-cols-2">
          {items.map((item) => (
            <li key={item.id}>
              <button
                type="button"
                onClick={() => onOpen(item)}
                className="group flex w-full min-w-0 items-center gap-3 rounded-[12px] border border-[rgba(157,192,255,0.09)] bg-[rgba(7,18,38,0.28)] px-3 py-3 text-left transition-colors hover:border-[rgba(120,216,255,0.25)] hover:bg-[rgba(120,216,255,0.045)]"
                title={`对比 ID：${item.id}`}
              >
                <span className="flex h-9 w-9 shrink-0 items-center justify-center rounded-[10px] bg-[rgba(182,161,255,0.1)] text-[var(--accent-purple)]">
                  <GitCompareArrows size={17} />
                </span>
                <span className="min-w-0 flex-1">
                  <span className="block truncate text-sm font-medium text-[var(--text-primary)]">{comparisonTitle(item)}</span>
                  <span className="mt-1 block truncate text-[11px] text-[var(--text-tertiary)]">
                    {comparisonSubtitle(item)}
                  </span>
                </span>
                <StatusBadge tone={item.evidence_complete ? 'success' : 'neutral'} label={item.evidence_complete ? '证据完整' : '部分证据'} />
              </button>
            </li>
          ))}
        </ul>
      ) : (
        <EmptyState
          icon={<GitCompareArrows size={26} />}
          title="还没有历史对比"
          description="完成首次版本对比后，结果会保存在这里便于复查。"
        />
      )}
    </GlassCard>
  )
}

function comparisonTitle(result: ComparisonResult): string {
  const summary = result.target_summary
  const name = safeApplicationName({
    appName: asString(summary.app_name),
    apkPath: asString(summary.apk_path),
    packageName: asString(summary.package_name),
  })
  return `${name} · 版本对比`
}

function comparisonSubtitle(result: ComparisonResult): string {
  const baseVersion = summaryVersion(result.base_summary)
  const targetVersion = summaryVersion(result.target_summary)
  const created = result.created_at ? formatDateTime(result.created_at) : '时间待记录'
  return `${baseVersion || shortTaskId(result.base_task_id)} → ${targetVersion || shortTaskId(result.target_task_id)} · ${created}`
}

function summaryVersion(summary: Record<string, unknown>): string {
  const versionName = asString(summary.version_name)
  const versionCode = asString(summary.version_code)
  if (!versionName && !versionCode) return ''
  return `${versionName || '—'} (${versionCode || '—'})`
}

function ComparisonResultView({ result }: { result: ComparisonResult }) {
  return (
    <div className="flex flex-col gap-5" data-testid="comparison-result">
      {result.warnings.map((warning) => (
        <GlassCard key={warning} padding="md" className="border-[rgba(242,203,119,0.45)]">
          <p className="flex items-center gap-2 text-sm text-[var(--warning)]"><AlertTriangle size={16} /> {warning}</p>
        </GlassCard>
      ))}
      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="风险分变化" value={result.risk_score_delta == null ? '未评估' : `${result.risk_score_delta > 0 ? '+' : ''}${result.risk_score_delta}`} tone={result.risk_score_delta != null && result.risk_score_delta > 0 ? 'danger' : result.risk_score_delta == null ? 'neutral' : 'success'} icon={<ShieldAlert size={18} />} />
        <StatCard label="新增权限" value={result.permissions.added.length} tone="warning" icon={<Plus size={18} />} />
        <StatCard label="新增 SDK" value={result.sdks.added.length} tone="accent" icon={<Plus size={18} />} />
        <StatCard label="证据完整性" value={result.evidence_complete ? '可比较' : '部分证据'} tone={result.evidence_complete ? 'success' : 'neutral'} icon={<CheckCircle2 size={18} />} />
      </div>

      <GlassCard padding="md" highlight>
        <div className="mb-4 flex items-center justify-between gap-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">总体变化摘要</h2>
          <StatusBadge tone="accent" label="差异报告" />
        </div>
        <ul className="grid grid-cols-1 gap-2 sm:grid-cols-2">
          {result.highlights.length
            ? result.highlights.map((item) => <li key={item} className="rounded-[10px] border border-[rgba(157,192,255,0.09)] px-3 py-2 text-sm text-[var(--text-secondary)]">{item}</li>)
            : <li className="text-sm text-[var(--text-tertiary)]">暂无显著变化摘要。</li>}
        </ul>
      </GlassCard>

      <GlassCard padding="md">
        <h2 className="mb-3 text-sm font-semibold text-[var(--text-primary)]">版本概要</h2>
        <div className="grid grid-cols-1 gap-3 lg:grid-cols-2">
          <VersionSummary label="基准版本" summary={result.base_summary} />
          <VersionSummary label="目标版本" summary={result.target_summary} />
        </div>
      </GlassCard>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        <DiffCard title="权限差异" diff={result.permissions} />
        <DiffCard title="高风险权限" diff={result.high_risk_permissions} />
        <DiffCard title="SDK 差异" diff={result.sdks} />
        <DiffCard title="SDK 厂商与分类" diff={mergeDiff(result.sdk_vendors, result.sdk_categories)} />
        <DiffCard title="规则状态差异" diff={result.rules} />
        <DiffCard title="访问域名差异" diff={result.domains} />
        <DiffCard title="动态敏感行为" diff={result.dynamic_behaviors} />
      </div>
    </div>
  )
}

function VersionSummary({ label, summary }: { label: string; summary: Record<string, unknown> }) {
  const appName = safeApplicationName({
    appName: asString(summary.app_name),
    apkPath: asString(summary.apk_path),
    packageName: asString(summary.package_name),
  })
  return (
    <div className="rounded-[12px] border border-[rgba(157,192,255,0.1)] p-4">
      <p className="mb-2 text-xs text-[var(--accent-blue)]">{label}</p>
      <p className="text-sm font-medium text-[var(--text-primary)]">{appName}</p>
      <p className="mt-1 break-all font-mono text-xs text-[var(--text-tertiary)]">{value(summary.package_name)}</p>
      <p className="mt-2 text-xs text-[var(--text-secondary)]">版本 {value(summary.version_name)} ({value(summary.version_code)}) · 风险分 {value(summary.risk_score, '未评估')}</p>
    </div>
  )
}

function DiffCard({ title, diff }: { title: string; diff: DifferenceSet }) {
  return (
    <GlassCard padding="md">
      <div className="mb-3 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">{title}</h3>
        {diff.unavailable && <StatusBadge tone="neutral" label="未评估" />}
      </div>
      {diff.unavailable ? (
        <p className="text-xs text-[var(--text-tertiary)]">至少一个版本缺少可信动态证据；缺失状态不会被解释为“没有行为”。</p>
      ) : (
        <div className="grid grid-cols-1 gap-3 sm:grid-cols-3">
          <DiffList title="新增" icon={<Plus size={13} />} values={diff.added} tone="warning" />
          <DiffList title="删除" icon={<Trash2 size={13} />} values={diff.removed} tone="success" />
          <DiffList title="保持不变" icon={<CheckCircle2 size={13} />} values={diff.unchanged} tone="neutral" />
        </div>
      )}
    </GlassCard>
  )
}

function DiffList({ title, icon, values, tone }: { title: string; icon: React.ReactNode; values: string[]; tone: 'warning' | 'success' | 'neutral' }) {
  const color = tone === 'warning' ? 'text-[var(--warning)]' : tone === 'success' ? 'text-[var(--success)]' : 'text-[var(--text-tertiary)]'
  return (
    <div className="min-w-0">
      <p className={`inline-flex items-center gap-1 text-xs ${color}`}>{icon}{title} · {values.length}</p>
      <ul className="mt-2 flex max-h-40 flex-col gap-1 overflow-auto">
        {values.length ? values.map((item) => <li key={item} className="break-all font-mono text-xs text-[var(--text-secondary)]">{item}</li>) : <li className="text-xs text-[var(--text-tertiary)]">无</li>}
      </ul>
    </div>
  )
}

function mergeDiff(first: DifferenceSet, second: DifferenceSet): DifferenceSet {
  return {
    added: [...first.added, ...second.added],
    removed: [...first.removed, ...second.removed],
    unchanged: [...first.unchanged, ...second.unchanged],
    unavailable: first.unavailable || second.unavailable,
  }
}

function asString(input: unknown): string {
  return input == null ? '' : String(input)
}

function value(input: unknown, fallback = '—'): string {
  return input == null || input === '' ? fallback : String(input)
}
