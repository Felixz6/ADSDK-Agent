import { useState } from 'react'
import { useNavigate, useParams } from 'react-router-dom'
import {
  AlertTriangle,
  ArrowLeft,
  Ban,
  CheckCircle2,
  Clock,
  FileText,
  Package,
  RefreshCw,
  ShieldAlert,
  Trash2,
  Wifi,
  WifiOff,
  XCircle,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { DynamicReliabilityCard } from '@/components/analysis/DynamicReliabilityCard'
import { EvidenceCorrelationCard } from '@/components/analysis/EvidenceCorrelationCard'
import type { DynamicExecutionSummary, DynamicModePolicy } from '@/types/api'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard } from '@/components/common/StatCard'
import { EmptyState, ErrorState, LoadingState } from '@/components/common/States'
import { ConfirmDialog } from '@/components/common/ConfirmDialog'
import { StatusBadge } from '@/components/common/StatusBadge'
import { useCancelTask, useDeleteTask, useLiveTask, useRetryTask, useTaskReport } from '@/hooks/useTasks'
import { useUIStore } from '@/stores/uiStore'
import { cn, formatDateTime } from '@/utils'
import {
  apkFilename,
  safeApplicationName,
  taskSubtitle,
  taskTitle,
  taskTypeLongLabel,
} from '@/utils/taskPresentation'
import type { TaskStatus, TaskStepStatus } from '@/types/tasks'

type PendingAction = 'cancel' | 'delete' | null

const STATUS_LABEL: Record<TaskStatus, string> = {
  queued: '排队中',
  running: '分析中',
  completed: '已完成',
  failed: '失败',
  cancelled: '已取消',
}

export default function TaskDetail() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const pushToast = useUIStore((state) => state.pushToast)
  const taskQuery = useLiveTask(id)
  const reportQuery = useTaskReport(id, {
    enabled: Boolean(
      id
      && taskQuery.data?.task_type === 'dynamic'
      && taskQuery.data?.report_json_path,
    ),
  })
  const cancelMutation = useCancelTask()
  const retryMutation = useRetryTask()
  const deleteMutation = useDeleteTask()
  const [pending, setPending] = useState<PendingAction>(null)

  if (taskQuery.isLoading) {
    return <GlassCard padding="none"><LoadingState title="正在加载任务详情…" /></GlassCard>
  }
  if (taskQuery.isError) {
    return (
      <GlassCard padding="none">
        <ErrorState
          icon={<ShieldAlert size={28} />}
          title={taskQuery.error.status === 404 ? '未找到任务' : '任务详情加载失败'}
          description={taskQuery.error.message}
          action={<button type="button" onClick={() => navigate('/tasks')} className="control-button"><ArrowLeft size={14} /> 返回任务中心</button>}
        />
      </GlassCard>
    )
  }
  const task = taskQuery.data
  if (!task) {
    return <EmptyState icon={<ShieldAlert size={28} />} title="未找到任务" />
  }

  const taskId = task.id
  const active = task.status === 'queued' || task.status === 'running'
  const reliabilityAttempts = task.steps
    .filter((item) => item.step_key.endsWith('_attempt'))
    .filter((item) => item.status === 'success' || item.status === 'failed')
    .map((item) => ({
      mode: (
        item.step_key === 'attach_attempt'
          ? 'attach_existing'
          : item.step_key.replace(/_attempt$/, '')
      ) as DynamicExecutionSummary['attempts'][number]['mode'],
      status: item.status as 'success' | 'failed',
      reason_code: item.status === 'failed' ? task.error_code : null,
      message: item.message ?? (item.status === 'success' ? '执行成功' : '执行失败'),
    }))
  const successfulAttempt = [...reliabilityAttempts].reverse().find((item) => item.status === 'success')
  const dynamicExecution: DynamicExecutionSummary | null = task.task_type === 'dynamic' ? {
    policy: (task.request_payload.dynamic_mode_policy as DynamicModePolicy | undefined) ?? 'balanced',
    selected_mode: successfulAttempt?.mode ?? 'none',
    attempts: reliabilityAttempts,
    fallback_path: reliabilityAttempts.length > 1 ? reliabilityAttempts.slice(1).map((item) => item.mode) : [],
  } : null

  async function confirmAction() {
    if (!pending || !task) return
    try {
      if (pending === 'cancel') {
        await cancelMutation.mutateAsync(task.id)
        pushToast({ kind: 'success', message: '取消信号已发送，等待安全清理完成。', duration: 3500 })
      } else {
        await deleteMutation.mutateAsync(task.id)
        pushToast({ kind: 'success', message: '任务记录已删除。', duration: 2500 })
        navigate('/tasks')
      }
      setPending(null)
    } catch (error) {
      pushToast({ kind: 'error', message: (error as { message?: string }).message ?? '操作失败', duration: 5000 })
    }
  }

  async function retry() {
    try {
      const response = await retryMutation.mutateAsync(taskId)
      pushToast({ kind: 'success', message: '重试任务已创建。', duration: 2500 })
      navigate(`/tasks/${response.task.id}`)
    } catch (error) {
      pushToast({ kind: 'error', message: (error as { message?: string }).message ?? '重试失败', duration: 5000 })
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title={taskTitle(task)}
        description={taskSubtitle(task)}
        eyebrow={`任务详情 · ${taskTypeLongLabel(task.task_type)}`}
        actions={
          <div className="flex items-center gap-2 flex-wrap">
            <button type="button" onClick={() => navigate('/tasks')} className="control-button"><ArrowLeft size={14} /> 列表</button>
            {task.report_json_path && <button type="button" onClick={() => navigate(`/reports?task_id=${task.id}`)} className="control-button"><FileText size={14} /> 专业报告</button>}
            {active ? (
              <button type="button" onClick={() => setPending('cancel')} className="control-button text-[var(--warning)]"><Ban size={14} /> 取消</button>
            ) : (
              <>
                {task.task_type !== 'comparison' && <button type="button" onClick={() => void retry()} className="control-button"><RefreshCw size={14} /> 重新分析</button>}
                <button type="button" onClick={() => setPending('delete')} className="control-button text-[var(--danger)]"><Trash2 size={14} /> 删除</button>
              </>
            )}
          </div>
        }
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="分析类型" value={taskTypeLongLabel(task.task_type)} tone="accent" icon={<Package size={18} />} />
        <StatCard label="任务状态" value={STATUS_LABEL[task.status]} tone={statusCardTone(task.status)} icon={statusIcon(task.status)} />
        <StatCard label="当前进度" value={`${task.progress_percent}%`} tone={active ? 'default' : 'success'} icon={<Clock size={18} />} />
        <StatCard label="实时通道" value={active ? taskQuery.socketConnected ? 'WebSocket' : 'HTTP 轮询' : '已停止'} tone={taskQuery.socketConnected ? 'success' : 'neutral'} icon={taskQuery.socketConnected ? <Wifi size={18} /> : <WifiOff size={18} />} />
      </div>

      <GlassCard padding="md" highlight>
        <div className="flex items-center justify-between gap-3 mb-2">
          <div>
            <h3 className="text-sm font-semibold text-[var(--text-primary)]">总体进度</h3>
            <p className="text-xs text-[var(--text-tertiary)] mt-1">
              {task.status === 'cancelled'
                ? `取消于：${stageLabel(task.cancelled_at_stage || task.current_stage)}`
                : stageLabel(task.current_stage)}
            </p>
          </div>
          <StatusBadge tone={statusTone(task.status)} label={STATUS_LABEL[task.status]} />
        </div>
        <div className="h-2.5 rounded-full bg-[rgba(127,147,186,0.2)] overflow-hidden">
          <span className="block h-full bg-gradient-to-r from-[var(--accent-blue)] to-[var(--accent-purple)] transition-[width] duration-300" style={{ width: `${task.progress_percent}%` }} />
        </div>
      </GlassCard>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <GlassCard padding="md">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">任务信息</h3>
          <dl className="flex flex-col gap-1">
            <KV k="任务 ID" v={task.id} mono />
            <KV k="应用名称" v={safeApplicationName({ appName: task.app_name, apkPath: task.apk_path, packageName: task.package_name })} />
            <KV k="包名" v={task.package_name ?? '待解析'} mono />
            <KV k="APK 文件" v={apkFilename(task.apk_path) || '待确认'} />
            <KV k="SHA-256" v={task.apk_sha256 ?? '待生成'} mono />
            <KV k="版本" v={`${task.version_name ?? '未知'} (${task.version_code ?? '未知'})`} />
            <KV k="设备标识（脱敏）" v={task.device_id ?? '未绑定'} mono />
          </dl>
        </GlassCard>
        <GlassCard padding="md">
          <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">配置与产物</h3>
          <dl className="flex flex-col gap-1">
            <KV k="流量采集" v={task.enable_traffic ? '启用' : '未启用'} />
            <KV k="UI 刺激" v={task.enable_ui_stimulation ? '启用' : '未启用'} />
            <KV k="创建时间" v={formatDateTime(task.created_at)} />
            <KV k="开始时间" v={formatDateTime(task.started_at)} />
            <KV k="完成时间" v={formatDateTime(task.completed_at)} />
            <KV k="报告 JSON" v={task.report_json_path ? '已生成' : '未生成'} />
            <KV k="报告 HTML" v={task.report_html_path ? '已生成，可打印' : '未生成'} />
          </dl>
        </GlassCard>
      </div>

      {task.task_type === 'dynamic' && (
        <>
          <DynamicReliabilityCard execution={dynamicExecution} />
          {task.report_json_path && (
            <EvidenceCorrelationCard
              correlation={reportQuery.data?.report?.evidence_correlation}
            />
          )}
        </>
      )}

      <GlassCard padding="md" highlight>
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-4">步骤时间线</h3>
        {task.steps.length ? (
          <ol className="relative ml-2 border-l border-[var(--border-soft)]">
            {task.steps.map((step, index) => (
              <li key={step.id} className="relative pl-6 pb-5 last:pb-0">
                <span className={cn('absolute -left-[6px] top-1 w-3 h-3 rounded-full border-2 border-[var(--bg-deep)]', stepDot(step.status), step.status === 'running' && 'animate-pulse')} />
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-medium text-[var(--text-primary)]">{stageLabel(step.step_name)}</p>
                    {step.message && (
                      <>
                        <p className="mt-1 text-xs text-[var(--text-secondary)]">{friendlyStepMessage(step.message)}</p>
                        {isTechnicalStepMessage(step.message) && (
                          <details className="mt-2 rounded-[8px] border border-[rgba(157,192,255,0.08)] px-2.5 py-1.5">
                            <summary className="cursor-pointer text-[11px] text-[var(--text-tertiary)]">技术详情</summary>
                            <p className="mt-1.5 break-all font-mono text-[11px] text-[var(--text-tertiary)]">{step.message}</p>
                          </details>
                        )}
                      </>
                    )}
                    <p className="text-[11px] text-[var(--text-tertiary)] mt-1">
                      {formatDateTime(step.started_at)}{step.completed_at ? ` → ${formatDateTime(step.completed_at)}` : ''}
                    </p>
                  </div>
                  <span className="text-[11px] text-[var(--text-tertiary)] shrink-0">{index + 1} · {step.progress_percent}%</span>
                </div>
              </li>
            ))}
          </ol>
        ) : (
          <EmptyState icon={<Clock size={26} />} title={task.status === 'queued' ? '等待开始' : '暂无步骤记录'} description="真实分析步骤完成后会写入此处。" />
        )}
      </GlassCard>

      {(task.error_code || task.error_message) && (
        <GlassCard padding="md" className="border-[rgba(242,139,155,0.35)]">
          <h3 className="text-sm font-semibold text-[var(--danger)] flex items-center gap-2"><ShieldAlert size={16} /> 诊断信息</h3>
          <p className="text-sm text-[var(--text-secondary)] mt-2">{task.error_message ?? '任务执行未完成，请查看步骤时间线。'}</p>
          {task.error_code && (
            <details className="mt-3 rounded-[10px] border border-[rgba(157,192,255,0.08)] px-3 py-2">
              <summary className="cursor-pointer text-xs text-[var(--text-tertiary)]">技术详情</summary>
              <p className="mt-2 break-all font-mono text-xs text-[var(--text-secondary)]">{task.error_code}</p>
            </details>
          )}
        </GlassCard>
      )}

      <ConfirmDialog
        open={pending !== null}
        title={pending === 'cancel' ? '取消该任务？' : '删除该任务记录？'}
        description={pending === 'cancel'
          ? '任务会在安全点停止；设备代理、Frida、mitmdump 与资源租约完成清理后才进入“已取消”。'
          : '仅删除 SQLite 记录和报告索引，分析产物默认保留。'}
        confirmLabel={pending === 'cancel' ? '发送取消信号' : '删除记录'}
        tone="danger"
        onConfirm={() => void confirmAction()}
        onCancel={() => setPending(null)}
      />
    </div>
  )
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 border-b border-[var(--border-soft)]/40">
      <dt className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide shrink-0">{k}</dt>
      <dd className={cn('text-sm text-[var(--text-primary)] text-right break-all', mono && 'font-mono text-[12px]')}>{v}</dd>
    </div>
  )
}

function statusTone(status: TaskStatus): 'success' | 'warning' | 'danger' | 'neutral' | 'info' {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'running') return 'info'
  if (status === 'queued') return 'warning'
  return 'neutral'
}

function statusCardTone(status: TaskStatus): 'success' | 'danger' | 'warning' | 'neutral' | 'default' {
  if (status === 'completed') return 'success'
  if (status === 'failed') return 'danger'
  if (status === 'running') return 'default'
  if (status === 'queued') return 'warning'
  return 'neutral'
}

function statusIcon(status: TaskStatus) {
  if (status === 'completed') return <CheckCircle2 size={18} />
  if (status === 'failed') return <XCircle size={18} />
  return <AlertTriangle size={18} />
}

function stepDot(status: TaskStepStatus): string {
  if (status === 'success') return 'bg-[var(--success)]'
  if (status === 'failed') return 'bg-[var(--danger)]'
  if (status === 'partial') return 'bg-[var(--warning)]'
  if (status === 'running') return 'bg-[var(--accent-blue)]'
  return 'bg-[var(--status-neutral)]'
}

function stageLabel(stage: string | null): string {
  const labels: Record<string, string> = {
    input_validation: '输入校验',
    apk_validation: 'APK 路径校验',
    apk_hash: 'SHA-256 复核',
    apk_snapshot: '原子 APK 快照',
    apk_unpack: 'apktool 解包',
    manifest_parse: 'Manifest 与权限解析',
    sdk_scan: '第三方 SDK 识别',
    device_selection: '设备校验与租约',
    apk_install: '安装 APK',
    frida_spawn: 'Frida suspended spawn',
    frida_script_load: '加载 Hook',
    frida_ready: '等待 Hook-ready',
    mitm_ready: '流量代理就绪',
    mitm_start: '启动流量采集',
    collection_start: 'Consent 前动态采集',
    dynamic_collection: '动态行为采集',
    app_resume: '恢复应用',
    consent_boundary: 'Consent 边界',
    consent_event: '用户同意事件',
    frida_stop: '停止 Frida 会话',
    mitm_stop: '停止流量采集',
    event_validation: '动态证据校验',
    traffic_validation: '流量证据校验',
    resource_cleanup: '资源清理',
    rule_evaluation: '规则评估',
    report_write: '生成报告',
    completed: '任务完成',
    failed: '任务失败',
    cancelled: '任务已取消',
  }
  return stage ? labels[stage] ?? stage : '等待开始'
}

function friendlyStepMessage(message: string): string {
  if (message.startsWith('frida_server_unavailable:')) {
    return 'Frida 会话未就绪，已保留网络侧采集结果。'
  }
  if (message === 'Frida hook evidence unavailable; network-only collection retained') {
    return 'Hook 证据缺失，已保留网络侧采集结果。'
  }
  return message
}

function isTechnicalStepMessage(message: string): boolean {
  return friendlyStepMessage(message) !== message
}
