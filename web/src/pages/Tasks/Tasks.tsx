import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  AlertTriangle,
  Ban,
  ChevronLeft,
  ChevronRight,
  FileText,
  Filter,
  ListChecks,
  RefreshCw,
  Search,
  Trash2,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { EmptyState, ErrorState, LoadingState } from '@/components/common/States'
import { StatusBadge } from '@/components/common/StatusBadge'
import { RiskBadge } from '@/components/common/RiskBadge'
import { StatCard } from '@/components/common/StatCard'
import { ConfirmDialog } from '@/components/common/ConfirmDialog'
import { listLocalTasks } from '@/api/tasks'
import { useCancelTask, useDeleteTask, useRetryTask, useTasks } from '@/hooks/useTasks'
import { useUIStore } from '@/stores/uiStore'
import { formatDateTime } from '@/utils'
import {
  riskBadgeLevel,
  riskLevelLabel,
  shortDeviceLabel,
  taskSubtitle,
  taskTitle,
  taskTypeLabel,
} from '@/utils/taskPresentation'
import type { TaskRecord, TaskStatus, TaskType } from '@/types/tasks'

type PendingAction = { type: 'cancel' | 'delete'; task: TaskRecord } | null

const STATUS_LABEL: Record<TaskStatus, string> = {
  queued: '排队中',
  running: '分析中',
  completed: '已完成',
  failed: '失败',
  cancelled: '已取消',
}

export default function Tasks() {
  const navigate = useNavigate()
  const pushToast = useUIStore((state) => state.pushToast)
  const [keyword, setKeyword] = useState('')
  const [status, setStatus] = useState<TaskStatus | ''>('')
  const [taskType, setTaskType] = useState<TaskType | ''>('')
  const [page, setPage] = useState(1)
  const [pending, setPending] = useState<PendingAction>(null)
  const [showLegacy, setShowLegacy] = useState(false)
  const legacy = listLocalTasks()

  const tasks = useTasks({
    keyword: keyword.trim() || undefined,
    status,
    task_type: taskType,
    page,
    page_size: 20,
  })
  const running = useTasks({ status: 'running', page: 1, page_size: 1 })
  const completed = useTasks({ status: 'completed', page: 1, page_size: 1 })
  const failed = useTasks({ status: 'failed', page: 1, page_size: 1 })
  const cancelMutation = useCancelTask()
  const deleteMutation = useDeleteTask()
  const retryMutation = useRetryTask()

  async function confirmAction() {
    if (!pending) return
    try {
      if (pending.type === 'cancel') {
        await cancelMutation.mutateAsync(pending.task.id)
        pushToast({ kind: 'success', message: '取消信号已发送，正在执行资源清理。', duration: 3500 })
      } else {
        await deleteMutation.mutateAsync(pending.task.id)
        pushToast({ kind: 'success', message: '任务记录已删除。', duration: 2500 })
      }
      setPending(null)
    } catch (error) {
      pushToast({ kind: 'error', message: (error as { message?: string }).message ?? '操作失败', duration: 5000 })
    }
  }

  async function retry(task: TaskRecord) {
    try {
      const response = await retryMutation.mutateAsync(task.id)
      pushToast({ kind: 'success', message: '已创建重试任务。', duration: 2500 })
      navigate(`/tasks/${response.task.id}`)
    } catch (error) {
      pushToast({ kind: 'error', message: (error as { message?: string }).message ?? '重试失败', duration: 5000 })
    }
  }

  const renderActions = (task: TaskRecord) => ({
    onOpen: () => navigate(`/tasks/${task.id}`),
    onCancel: () => setPending({ type: 'cancel', task }),
    onDelete: () => setPending({ type: 'delete', task }),
    onRetry: () => void retry(task),
    onReport: () => navigate(`/reports?task_id=${task.id}`),
  })

  return (
    <div className="flex min-w-0 flex-col gap-5">
      <PageHeader
        title="任务中心"
        description="SQLite 持久化的分析任务、实时步骤、报告索引与资源生命周期。"
        eyebrow="任务 · 后端持久化"
      />

      <div className="grid grid-cols-2 gap-3 lg:grid-cols-4">
        <StatCard label="全部任务" value={tasks.data?.total ?? '—'} tone="default" icon={<ListChecks size={18} />} />
        <StatCard label="分析中" value={running.data?.total ?? '—'} tone="accent" icon={<RefreshCw size={18} />} />
        <StatCard label="已完成" value={completed.data?.total ?? '—'} tone="success" icon={<FileText size={18} />} />
        <StatCard label="失败" value={failed.data?.total ?? '—'} tone="danger" icon={<AlertTriangle size={18} />} />
      </div>

      <GlassCard padding="md" className="flex flex-col gap-3">
        <div className="flex flex-col gap-3 lg:flex-row lg:items-center">
          <label className="glass flex min-w-0 flex-1 items-center gap-2 rounded-[10px] px-3 py-2 focus-within:border-[var(--border-active)]">
            <Search size={16} className="text-[var(--text-tertiary)]" />
            <span className="sr-only">搜索任务</span>
            <input
              value={keyword}
              onChange={(event) => { setKeyword(event.target.value); setPage(1) }}
              placeholder="按应用、包名、APK 路径或任务 ID 搜索"
              className="w-full min-w-0 bg-transparent text-sm text-[var(--text-primary)] outline-none"
            />
          </label>
          <div className="flex flex-wrap gap-2">
            <FilterSelect
              label="状态"
              value={status}
              onChange={(value) => { setStatus(value as TaskStatus | ''); setPage(1) }}
              options={[
                ['全部状态', ''],
                ['排队中', 'queued'],
                ['分析中', 'running'],
                ['已完成', 'completed'],
                ['失败', 'failed'],
                ['已取消', 'cancelled'],
              ]}
            />
            <FilterSelect
              label="类型"
              value={taskType}
              onChange={(value) => { setTaskType(value as TaskType | ''); setPage(1) }}
              options={[
                ['全部类型', ''],
                ['静态分析', 'static'],
                ['动态分析', 'dynamic'],
                ['版本对比', 'comparison'],
              ]}
            />
          </div>
        </div>
      </GlassCard>

      {tasks.isLoading ? (
        <GlassCard padding="none"><LoadingState title="正在加载后端任务…" /></GlassCard>
      ) : tasks.isError ? (
        <GlassCard padding="none">
          <ErrorState
            icon={<AlertTriangle size={28} />}
            title="任务中心暂时不可用"
            description={tasks.error.message}
            action={<button type="button" onClick={() => void tasks.refetch()} className="control-button">重新加载</button>}
          />
        </GlassCard>
      ) : !tasks.data?.items.length ? (
        <GlassCard padding="none">
          <EmptyState
            icon={<Filter size={28} />}
            title="没有匹配的后端任务"
            description="新建分析后，任务会立即进入这里并持续写入真实进度。"
          />
        </GlassCard>
      ) : (
        <GlassCard padding="none" highlight className="min-w-0 overflow-hidden">
          <div className="hidden overflow-x-auto xl:block" data-testid="task-desktop-table">
            <table className="w-full min-w-[980px] text-left">
              <thead className="border-b border-[rgba(157,192,255,0.09)] text-[11px] uppercase tracking-wide text-[var(--text-tertiary)]">
                <tr>
                  {['应用 / APK', '类型', '设备', '状态', '阶段与进度', '风险', '创建时间', '操作'].map((label) => (
                    <th key={label} className="px-4 py-3.5 font-medium">{label}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {tasks.data.items.map((task) => (
                  <TaskRow key={task.id} task={task} {...renderActions(task)} />
                ))}
              </tbody>
            </table>
          </div>

          <div className="divide-y divide-[rgba(157,192,255,0.07)] xl:hidden" data-testid="task-mobile-list">
            {tasks.data.items.map((task) => (
              <TaskCard key={task.id} task={task} {...renderActions(task)} />
            ))}
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 border-t border-[rgba(157,192,255,0.08)] px-4 py-3 text-xs text-[var(--text-tertiary)]">
            <span>共 {tasks.data.total} 条 · 第 {tasks.data.page} / {Math.max(1, tasks.data.pages)} 页</span>
            <div className="flex gap-2">
              <button type="button" aria-label="上一页" title="上一页" disabled={page <= 1} onClick={() => setPage((value) => value - 1)} className="control-icon"><ChevronLeft size={15} /></button>
              <button type="button" aria-label="下一页" title="下一页" disabled={page >= tasks.data.pages} onClick={() => setPage((value) => value + 1)} className="control-icon"><ChevronRight size={15} /></button>
            </div>
          </div>
        </GlassCard>
      )}

      {legacy.length > 0 && (
        <GlassCard padding="md">
          <button type="button" onClick={() => setShowLegacy((value) => !value)} className="flex w-full items-center justify-between text-left">
            <span>
              <strong className="text-sm text-[var(--text-primary)]">浏览器旧记录</strong>
              <span className="ml-2 text-xs text-[var(--text-tertiary)]">{legacy.length} 条 · 只读兼容</span>
            </span>
            <ChevronRight size={16} className={showLegacy ? 'rotate-90' : ''} />
          </button>
          {showLegacy && (
            <ul className="mt-3 flex flex-col gap-2">
              {legacy.map((task) => (
                <li key={task.local_id} className="rounded-[10px] border border-[rgba(157,192,255,0.1)] px-3 py-2">
                  <p className="truncate text-sm text-[var(--text-primary)]">{task.package_name || task.apk_path}</p>
                  <p className="text-[11px] text-[var(--text-tertiary)]">浏览器旧记录 · {formatDateTime(task.created_at)}</p>
                </li>
              ))}
            </ul>
          )}
        </GlassCard>
      )}

      <ConfirmDialog
        open={pending !== null}
        title={pending?.type === 'cancel' ? '取消该任务？' : '删除该任务记录？'}
        description={
          pending?.type === 'cancel'
            ? '后台将在安全点停止，并清理设备代理、Frida 会话、mitmdump 进程及资源租约。'
            : '删除 SQLite 索引记录；分析产物默认保留，避免误删其他任务目录。'
        }
        confirmLabel={pending?.type === 'cancel' ? '发送取消信号' : '删除记录'}
        tone="danger"
        onConfirm={() => void confirmAction()}
        onCancel={() => setPending(null)}
      />
    </div>
  )
}

type TaskActions = {
  onOpen: () => void
  onCancel: () => void
  onDelete: () => void
  onRetry: () => void
  onReport: () => void
}

function TaskRow({ task, ...actions }: { task: TaskRecord } & TaskActions) {
  return (
    <tr className="border-b border-[rgba(157,192,255,0.07)] transition-colors last:border-b-0 hover:bg-[rgba(157,192,255,0.035)]">
      <td className="max-w-[280px] px-4 py-4">
        <ApplicationIdentity task={task} onOpen={actions.onOpen} />
      </td>
      <td className="px-4 py-4"><StatusBadge className="min-w-[68px] justify-center" tone="info" label={taskTypeLabel(task.task_type)} /></td>
      <td className="px-4 py-4 text-xs text-[var(--text-secondary)]">
        <span className="font-mono" title={task.device_id || '未绑定设备'}>{shortDeviceLabel(task.device_id)}</span>
      </td>
      <td className="px-4 py-4"><StatusBadge className="min-w-[68px] justify-center" tone={statusTone(task.status)} label={STATUS_LABEL[task.status]} /></td>
      <td className="min-w-[190px] px-4 py-4"><Progress task={task} /></td>
      <td className="px-4 py-4"><Risk task={task} /></td>
      <td className="whitespace-nowrap px-4 py-4 text-xs text-[var(--text-tertiary)]">{formatDateTime(task.created_at)}</td>
      <td className="px-4 py-4"><ActionButtons task={task} {...actions} /></td>
    </tr>
  )
}

function TaskCard({ task, ...actions }: { task: TaskRecord } & TaskActions) {
  return (
    <article className="min-w-0 px-4 py-4 transition-colors hover:bg-[rgba(157,192,255,0.035)]">
      <div className="flex min-w-0 items-start justify-between gap-3">
        <ApplicationIdentity task={task} onOpen={actions.onOpen} />
        <ActionButtons task={task} {...actions} />
      </div>
      <div className="mt-3 flex flex-wrap items-center gap-2">
        <StatusBadge className="min-w-[68px] justify-center" tone="info" label={taskTypeLabel(task.task_type)} />
        <StatusBadge className="min-w-[68px] justify-center" tone={statusTone(task.status)} label={STATUS_LABEL[task.status]} />
        <Risk task={task} />
      </div>
      <div className="mt-3 grid min-w-0 grid-cols-1 gap-3 sm:grid-cols-[minmax(0,1fr)_auto] sm:items-end">
        <Progress task={task} />
        <div className="min-w-0 text-[11px] text-[var(--text-tertiary)] sm:text-right">
          <p className="truncate font-mono" title={task.device_id || '未绑定设备'}>{shortDeviceLabel(task.device_id)}</p>
          <p className="mt-1">{formatDateTime(task.created_at)}</p>
        </div>
      </div>
    </article>
  )
}

function ApplicationIdentity({ task, onOpen }: { task: TaskRecord; onOpen: () => void }) {
  return (
    <button type="button" onClick={onOpen} className="min-w-0 max-w-full text-left" title={`任务 ID：${task.id}`}>
      <p className="truncate text-sm font-semibold text-[var(--text-primary)]">{taskTitle(task)}</p>
      <p className="mt-1 truncate text-[11px] text-[var(--text-tertiary)]" title={taskSubtitle(task)}>{taskSubtitle(task)}</p>
    </button>
  )
}

function Progress({ task }: { task: TaskRecord }) {
  const cancelledStage = task.status === 'cancelled'
    ? stageLabel(task.cancelled_at_stage || task.current_stage)
    : null
  return (
    <div className="min-w-0">
      <div className="mb-1.5 flex items-center justify-between gap-3 text-[11px] text-[var(--text-tertiary)]">
        <span className="truncate">{stageLabel(task.current_stage)}</span>
        <span className="shrink-0">{task.progress_percent}%</span>
      </div>
      <div className="h-1.5 overflow-hidden rounded-full bg-[rgba(127,147,186,0.18)]">
        <span className="block h-full bg-[var(--accent-blue)] transition-[width]" style={{ width: `${task.progress_percent}%` }} />
      </div>
      {cancelledStage && <p className="mt-1.5 truncate text-[11px] text-[var(--warning)]">取消于：{cancelledStage}</p>}
    </div>
  )
}

function Risk({ task }: { task: TaskRecord }) {
  return (
    <RiskBadge
      className="min-w-[76px] justify-center"
      level={riskBadgeLevel(task.risk_level)}
      label={riskLevelLabel(task.risk_level)}
    />
  )
}

function ActionButtons({ task, onCancel, onDelete, onRetry, onReport }: { task: TaskRecord } & TaskActions) {
  const active = task.status === 'queued' || task.status === 'running'
  return (
    <div className="flex shrink-0 items-center gap-1">
      {active ? (
        <button type="button" aria-label="取消任务" title="取消任务" onClick={onCancel} className="control-icon text-[var(--warning)]"><Ban size={14} /></button>
      ) : task.task_type !== 'comparison' ? (
        <button type="button" aria-label="重新分析" title="重新分析" onClick={onRetry} className="control-icon"><RefreshCw size={14} /></button>
      ) : null}
      {task.report_json_path && (
        <button type="button" aria-label="查看报告" title="查看报告" onClick={onReport} className="control-icon"><FileText size={14} /></button>
      )}
      {!active && (
        <button type="button" aria-label="删除任务" title="删除任务" onClick={onDelete} className="control-icon text-[var(--danger)]"><Trash2 size={14} /></button>
      )}
    </div>
  )
}

function FilterSelect({ label, value, onChange, options }: { label: string; value: string; onChange: (value: string) => void; options: [string, string][] }) {
  return (
    <label className="glass flex items-center gap-2 rounded-[10px] px-3 py-2">
      <span className="text-[11px] text-[var(--text-tertiary)]">{label}</span>
      <select value={value} onChange={(event) => onChange(event.target.value)} className="bg-transparent text-xs text-[var(--text-primary)] outline-none">
        {options.map(([text, option]) => <option key={option} value={option} className="bg-[var(--bg-deep)]">{text}</option>)}
      </select>
    </label>
  )
}

function statusTone(status: TaskStatus): 'success' | 'warning' | 'danger' | 'neutral' | 'info' {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'running') return 'info'
  if (status === 'queued') return 'warning'
  return 'neutral'
}

function stageLabel(stage: string | null): string {
  const labels: Record<string, string> = {
    input_validation: '输入校验',
    apk_validation: 'APK 校验',
    apk_hash: 'SHA-256 复核',
    apk_snapshot: 'APK 快照',
    apk_unpack: 'APK 解包',
    manifest_parse: 'Manifest 解析',
    sdk_scan: 'SDK 识别',
    device_selection: '设备校验',
    apk_install: '安装 APK',
    frida_spawn: '启动应用',
    frida_script_load: '加载 Hook',
    frida_ready: '等待 Hook',
    mitm_start: '启动流量采集',
    collection_start: '动态采集',
    app_resume: '恢复应用',
    consent_boundary: 'Consent 边界',
    event_validation: '证据校验',
    resource_cleanup: '资源清理',
    rule_evaluation: '规则评估',
    report_write: '生成报告',
    completed: '已完成',
    failed: '失败',
    cancelled: '已取消',
  }
  return stage ? labels[stage] ?? stage : '等待开始'
}
