import { useState } from 'react'
import {
  AlertTriangle,
  ArrowRight,
  CheckCircle2,
  GitCompareArrows,
  Plus,
  ShieldAlert,
  Trash2,
} from 'lucide-react'
import { PageHeader } from '@/components/common/PageHeader'
import { GlassCard } from '@/components/common/GlassCard'
import { EmptyState, ErrorState, LoadingState } from '@/components/common/States'
import { StatCard } from '@/components/common/StatCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { useCreateComparison, useTasks } from '@/hooks/useTasks'
import { useUIStore } from '@/stores/uiStore'
import type { ComparisonResult, DifferenceSet, TaskRecord } from '@/types/tasks'

export default function Comparison() {
  const pushToast = useUIStore((state) => state.pushToast)
  const tasks = useTasks({ status: 'completed', page: 1, page_size: 100 })
  const createMutation = useCreateComparison()
  const [baseId, setBaseId] = useState('')
  const [targetId, setTargetId] = useState('')
  const [allowCrossApp, setAllowCrossApp] = useState(false)
  const [result, setResult] = useState<ComparisonResult | null>(null)

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
    <div className="flex flex-col gap-5">
      <PageHeader
        title="版本对比"
        description="选择两个具有有效静态报告的已完成任务，查看权限、SDK、规则、域名与动态证据差异。"
        eyebrow="Comparison · comparison-v1"
      />

      {tasks.isLoading ? (
        <GlassCard padding="none"><LoadingState title="正在加载可对比版本…" /></GlassCard>
      ) : tasks.isError ? (
        <GlassCard padding="none"><ErrorState icon={<AlertTriangle size={28} />} title="版本列表加载失败" description={tasks.error.message} /></GlassCard>
      ) : (tasks.data?.items.length ?? 0) < 2 ? (
        <GlassCard padding="none">
          <EmptyState icon={<GitCompareArrows size={28} />} title="至少需要两个已完成任务" description="先创建两次静态或动态分析，再返回此处进行版本对比。" />
        </GlassCard>
      ) : (
        <GlassCard padding="lg" highlight>
          <div className="grid grid-cols-1 lg:grid-cols-[1fr_auto_1fr] gap-4 items-end">
            <TaskSelect label="基准版本" value={baseId} onChange={setBaseId} tasks={tasks.data?.items ?? []} />
            <ArrowRight size={20} className="hidden lg:block text-[var(--accent-purple)] mb-3" />
            <TaskSelect label="目标版本" value={targetId} onChange={setTargetId} tasks={tasks.data?.items ?? []} />
          </div>
          <div className="mt-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <label className="inline-flex items-center gap-2 text-xs text-[var(--text-secondary)]">
              <input type="checkbox" checked={allowCrossApp} onChange={(event) => setAllowCrossApp(event.target.checked)} className="accent-[var(--accent-blue)]" />
              允许包名不同的跨应用对比（默认不推荐）
            </label>
            <button type="button" onClick={() => void compare()} disabled={createMutation.isPending} className="control-primary">
              <GitCompareArrows size={16} /> {createMutation.isPending ? '正在计算…' : '生成差异报告'}
            </button>
          </div>
        </GlassCard>
      )}

      {result && <ComparisonResultView result={result} />}
    </div>
  )
}

function TaskSelect({ label, value, onChange, tasks }: { label: string; value: string; onChange: (value: string) => void; tasks: TaskRecord[] }) {
  return (
    <label className="flex flex-col gap-2">
      <span className="text-xs text-[var(--text-tertiary)] uppercase tracking-wide">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} className="glass rounded-[12px] px-3 py-2.5 text-sm text-[var(--text-primary)] outline-none focus:border-[var(--border-active)]">
        <option value="" className="bg-[var(--bg-deep)]">请选择任务</option>
        {tasks.filter((task) => task.task_type !== 'comparison' && task.report_json_path).map((task) => (
          <option key={task.id} value={task.id} className="bg-[var(--bg-deep)]">
            {task.app_name || task.package_name || task.apk_path || task.id} · {task.version_name || '版本未知'}
          </option>
        ))}
      </select>
    </label>
  )
}

function ComparisonResultView({ result }: { result: ComparisonResult }) {
  return (
    <>
      {result.warnings.map((warning) => (
        <GlassCard key={warning} padding="md" className="border-[rgba(242,203,119,0.45)]">
          <p className="text-sm text-[var(--warning)] flex items-center gap-2"><AlertTriangle size={16} /> {warning}</p>
        </GlassCard>
      ))}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="风险分变化" value={result.risk_score_delta == null ? '—' : `${result.risk_score_delta > 0 ? '+' : ''}${result.risk_score_delta}`} tone={result.risk_score_delta && result.risk_score_delta > 0 ? 'danger' : 'success'} icon={<ShieldAlert size={18} />} />
        <StatCard label="新增权限" value={result.permissions.added.length} tone="warning" icon={<Plus size={18} />} />
        <StatCard label="新增 SDK" value={result.sdks.added.length} tone="accent" icon={<Plus size={18} />} />
        <StatCard label="证据完整性" value={result.evidence_complete ? '可比较' : '受限'} tone={result.evidence_complete ? 'success' : 'neutral'} icon={<CheckCircle2 size={18} />} />
      </div>

      <GlassCard padding="md" highlight>
        <div className="flex items-center justify-between gap-3 mb-4">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">总体变化摘要</h2>
          <StatusBadge tone="accent" label={result.schema_version} />
        </div>
        <ul className="grid grid-cols-1 sm:grid-cols-2 gap-2">
          {result.highlights.map((item) => <li key={item} className="rounded-[10px] border border-[var(--border-soft)] px-3 py-2 text-sm text-[var(--text-secondary)]">{item}</li>)}
        </ul>
      </GlassCard>

      <GlassCard padding="md">
        <h2 className="text-sm font-semibold text-[var(--text-primary)] mb-3">版本概要</h2>
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <VersionSummary label="基准版本" summary={result.base_summary} />
          <VersionSummary label="目标版本" summary={result.target_summary} />
        </div>
      </GlassCard>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <DiffCard title="权限差异" diff={result.permissions} />
        <DiffCard title="高风险权限" diff={result.high_risk_permissions} />
        <DiffCard title="SDK 差异" diff={result.sdks} />
        <DiffCard title="SDK 厂商与分类" diff={mergeDiff(result.sdk_vendors, result.sdk_categories)} />
        <DiffCard title="规则状态差异" diff={result.rules} />
        <DiffCard title="访问域名差异" diff={result.domains} />
        <DiffCard title="动态敏感行为" diff={result.dynamic_behaviors} />
      </div>
    </>
  )
}

function VersionSummary({ label, summary }: { label: string; summary: Record<string, unknown> }) {
  return (
    <div className="rounded-[12px] border border-[var(--border-soft)] p-4">
      <p className="text-xs text-[var(--accent-blue)] mb-2">{label}</p>
      <p className="text-sm font-medium text-[var(--text-primary)]">{value(summary.app_name) || value(summary.package_name)}</p>
      <p className="text-xs text-[var(--text-tertiary)] font-mono mt-1">{value(summary.package_name)}</p>
      <p className="text-xs text-[var(--text-secondary)] mt-2">版本 {value(summary.version_name)} ({value(summary.version_code)}) · 风险 {value(summary.risk_score)}</p>
    </div>
  )
}

function DiffCard({ title, diff }: { title: string; diff: DifferenceSet }) {
  return (
    <GlassCard padding="md">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-[var(--text-primary)]">{title}</h3>
        {diff.unavailable && <StatusBadge tone="neutral" label="无法比较" />}
      </div>
      {diff.unavailable ? (
        <p className="text-xs text-[var(--text-tertiary)]">至少一个版本缺少可信动态证据；此处不将缺失解释为无行为。</p>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
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
    <div>
      <p className={`text-xs inline-flex items-center gap-1 ${color}`}>{icon}{title} · {values.length}</p>
      <ul className="mt-2 flex flex-col gap-1 max-h-40 overflow-auto">
        {values.length ? values.map((item) => <li key={item} className="text-xs text-[var(--text-secondary)] font-mono break-all">{item}</li>) : <li className="text-xs text-[var(--text-tertiary)]">无</li>}
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

function value(input: unknown): string {
  return input == null || input === '' ? '—' : String(input)
}
