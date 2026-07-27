import { useParams, useNavigate } from 'react-router-dom'
import { useState, type ReactNode } from 'react'
import {
  ArrowLeft,
  Trash2,
  Package,
  Clock,
  ShieldAlert,
  FileText,
  CheckCircle2,
  XCircle,
  AlertTriangle,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard } from '@/components/common/StatCard'
import { EmptyState } from '@/components/common/States'
import { ConfirmDialog } from '@/components/common/ConfirmDialog'
import { getLocalTask, deleteLocalTask } from '@/api/tasks'
import { useAnalysisStore } from '@/stores/analysisStore'
import { useUIStore } from '@/stores/uiStore'
import { formatDateTime, cn } from '@/utils'

export default function TaskDetail() {
  const params = useParams<{ id: string }>()
  const navigate = useNavigate()
  const pushToast = useUIStore((s) => s.pushToast)
  const task = getLocalTask(params.id ?? '')
  const active = useAnalysisStore((s) => s.active)
  const [confirmDelete, setConfirmDelete] = useState(false)

  // 内存中若有该任务的活跃结果,提供「查看结果」入口
  const hasActiveResult = active != null && task != null && active.run_id != null && task.run_id === active.run_id

  if (!task) {
    return (
      <EmptyState
        icon={<ShieldAlert size={28} />}
        title="未找到任务"
        description="该任务记录不存在或已被删除。"
        action={
          <button
            type="button"
            onClick={() => navigate('/tasks')}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm border border-[var(--border-soft)] text-[var(--text-secondary)] hover:bg-[rgba(157,192,255,0.08)]"
          >
            <ArrowLeft size={15} /> 返回任务列表
          </button>
        }
      />
    )
  }

  function handleDelete() {
    deleteLocalTask(task!.local_id)
    setConfirmDelete(false)
    pushToast({ kind: 'success', message: '已删除该任务记录。', duration: 2500 })
    navigate('/tasks')
  }

  const tone: 'success' | 'danger' | 'warning' | 'neutral' =
    task.status === 'success' ? 'success' : task.status === 'failed' ? 'danger' : task.status === 'partial' ? 'warning' : 'neutral'

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="任务详情"
        description="本地分析任务记录的元数据与规则评估摘要。原始敏感标识不入库,故此处仅展示统计。"
        eyebrow={`任务 ${task.local_id}`}
        actions={
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => navigate('/tasks')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] text-xs border border-[var(--border-soft)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
            >
              <ArrowLeft size={14} /> 列表
            </button>
            <button
              type="button"
              onClick={() => setConfirmDelete(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] text-xs border border-[var(--border-soft)] text-[var(--danger)] hover:bg-[rgba(255,107,138,0.08)]"
            >
              <Trash2 size={14} /> 删除
            </button>
          </div>
        }
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="分析类型" value={task.kind === 'static' ? '静态' : '动态'} tone="accent" icon={<Package size={18} />} />
        <StatCard label="整体状态" value={statusLabel(task.status)} tone={tone} icon={task.status === 'success' ? <CheckCircle2 size={18} /> : task.status === 'failed' ? <XCircle size={18} /> : <AlertTriangle size={18} />} />
        <StatCard label="创建时间" value={formatDateTime(task.created_at)} tone="default" icon={<Clock size={18} />} />
        <StatCard label="识别 SDK 数" value={task.sdk_count ?? '—'} tone="success" />
      </div>

      <GlassCard padding="md" highlight>
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">基本信息</h3>
        <dl className="flex flex-col gap-1">
          <KV k="本地任务 ID" v={task.local_id} mono />
          <KV k="后端 run_id" v={task.run_id ?? '—(未返回)'} mono />
          <KV k="APK 路径(展示)" v={task.apk_path || '—'} />
          <KV k="包名" v={task.package_name ?? '—'} mono />
          <KV k="报告产物" v={task.has_report ? '已生成' : '未生成'} />
          <KV k="产物数量" v={`${task.artifacts_count}`} />
        </dl>
      </GlassCard>

      {task.summary ? (
        <GlassCard padding="md" highlight>
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-1">规则评估摘要</h3>
          <p className="text-[11px] text-[var(--text-tertiary)] mb-3">
            「未评估」仅表示规则未运行或数据缺失,绝不代表「无风险」。
          </p>
          <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
            <SummaryBox label="已命中" value={task.summary.matched} tone="danger" icon={<ShieldAlert size={15} />} />
            <SummaryBox label="未命中" value={task.summary.not_matched} tone="success" icon={<CheckCircle2 size={15} />} />
            <SummaryBox label="未评估" value={task.summary.not_evaluated} tone="neutral" icon={<AlertTriangle size={15} />} />
            <SummaryBox label="异常" value={task.summary.errored} tone="warning" icon={<AlertTriangle size={15} />} />
          </div>
        </GlassCard>
      ) : (
        <GlassCard padding="md">
          <EmptyState icon={<FileText size={26} />} title="无规则评估摘要" description="该任务未产生规则结果(可能为失败或仅静态分析)。" />
        </GlassCard>
      )}

      {task.error && (
        <GlassCard padding="md">
          <h3 className="text-sm font-semibold text-[var(--danger)] mb-2 flex items-center gap-1.5">
            <ShieldAlert size={15} /> 错误信息
          </h3>
          {task.error_code && <p className="text-xs text-[var(--text-tertiary)] mb-1">错误代码:{task.error_code}</p>}
          <p className="text-sm text-[var(--text-secondary)] font-mono break-all">{task.error}</p>
        </GlassCard>
      )}

      {hasActiveResult && (
        <GlassCard padding="md" highlight>
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-1">本次结果仍驻留内存</h3>
              <p className="text-xs text-[var(--text-tertiary)]">可在对应结果页继续查看完整分析细节。</p>
            </div>
            <button
              type="button"
              onClick={() => navigate(task.kind === 'dynamic' ? '/dynamic' : '/static')}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] text-sm bg-[var(--accent-blue)] text-[var(--text-on-accent)] hover:brightness-110"
            >
              查看结果
            </button>
          </div>
        </GlassCard>
      )}

      <ConfirmDialog
        open={confirmDelete}
        title="删除该任务记录?"
        description="此操作仅删除本地浏览器中的该任务记录,不会影响后端已产生的产物文件。"
        confirmLabel="删除"
        tone="danger"
        onConfirm={handleDelete}
        onCancel={() => setConfirmDelete(false)}
      />
    </div>
  )
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1 border-b border-[var(--border-soft)]/40">
      <dt className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide shrink-0 pt-0.5">{k}</dt>
      <dd className={cn('text-sm text-[var(--text-primary)] text-right break-all', mono && 'font-mono text-[13px]')}>{v}</dd>
    </div>
  )
}

function SummaryBox({ label, value, tone, icon }: { label: string; value: number; tone: 'danger' | 'success' | 'neutral' | 'warning'; icon: ReactNode }) {
  const color =
    tone === 'danger' ? 'text-[var(--danger)]' :
    tone === 'success' ? 'text-[var(--success)]' :
    tone === 'warning' ? 'text-[var(--warning)]' :
    'text-[var(--status-neutral)]'
  return (
    <div className="rounded-[12px] border border-[var(--border-soft)] px-3 py-2.5 flex flex-col gap-1">
      <span className="text-[11px] text-[var(--text-tertiary)] inline-flex items-center gap-1">{icon}{label}</span>
      <span className={cn('text-xl font-semibold', color)}>{value}</span>
    </div>
  )
}

function statusLabel(s: string | null): string {
  if (!s) return '—'
  switch (s) {
    case 'success': return '成功'
    case 'partial': return '部分成功'
    case 'failed': return '失败'
    case 'skipped': return '已跳过'
    default: return s
  }
}
