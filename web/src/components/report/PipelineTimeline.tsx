import { motion } from 'framer-motion'
import {
  CheckCircle2,
  XCircle,
  AlertTriangle,
  MinusCircle,
  Clock,
  type LucideIcon,
} from 'lucide-react'
import { cn, formatDuration, formatDateTime } from '@/utils'
import type { StepResult, StepStatus } from '@/types/api'

const ICON: Record<StepStatus, LucideIcon> = {
  success: CheckCircle2,
  partial: AlertTriangle,
  failed: XCircle,
  skipped: MinusCircle,
}

const COLOR: Record<StepStatus, string> = {
  success: 'text-[var(--success)] border-[rgba(121,224,195,0.5)]',
  partial: 'text-[var(--warning)] border-[rgba(242,203,119,0.5)]',
  failed: 'text-[var(--danger)] border-[rgba(242,139,155,0.5)]',
  skipped: 'text-[var(--status-neutral)] border-[rgba(127,147,186,0.45)]',
}

const LINE: Record<StepStatus, string> = {
  success: 'bg-[rgba(121,224,195,0.5)]',
  partial: 'bg-[rgba(242,203,119,0.5)]',
  failed: 'bg-[rgba(242,139,155,0.5)]',
  skipped: 'bg-[rgba(127,147,186,0.35)]',
}

/** 简短中文步骤名翻译(仅用于展示;后端原始 name 在副标题保留) */
const STEP_NAME_LABEL: Record<string, string> = {
  apk_validation: 'APK 校验',
  apk_hash: '哈希计算',
  apk_snapshot: 'APK 快照',
  apk_unpack: '解包',
  manifest_parse: '清单解析',
  sdk_scan: 'SDK 扫描',
  report_write: '报告写入',
  device_selection: '设备选择',
  apk_install: '安装 APK',
  mitm_start: '启动 mitmproxy',
  mitm_ready: 'mitm 就绪',
  frida_spawn: 'Frida spawn',
  frida_script_load: '载入 Frida 脚本',
  frida_ready: 'Frida 就绪',
  app_resume: '恢复应用',
  dynamic_collection: '动态采集',
  consent_event: '同意事件',
  frida_stop: '停止 Frida',
  mitm_stop: '停止 mitm',
  event_validation: '事件校验',
  traffic_validation: '流量校验',
}

export function PipelineTimeline({ steps }: { steps: StepResult[] }) {
  if (!steps.length) {
    return <p className="text-sm text-[var(--text-tertiary)]">暂无步骤数据。</p>
  }
  return (
    <ol className="relative flex flex-col gap-0">
      {steps.map((step, i) => {
        const Icon = ICON[step.status] ?? MinusCircle
        const isLast = i === steps.length - 1
        return (
          <li key={`${step.name}-${i}`} className="relative flex gap-3 pb-4">
            {!isLast && (
              <span
                className={cn(
                  'absolute left-[11px] top-7 bottom-0 w-[2px] -translate-x-1/2',
                  LINE[step.status],
                )}
                aria-hidden
              />
            )}
            <motion.div
              initial={{ opacity: 0, scale: 0.85 }}
              animate={{ opacity: 1, scale: 1 }}
              transition={{ delay: Math.min(i * 0.03, 0.4), duration: 0.2 }}
              className={cn(
                'z-10 flex items-center justify-center w-6 h-6 rounded-full border-2 bg-[var(--bg-deep)] shrink-0',
                COLOR[step.status],
              )}
            >
              <Icon size={14} />
            </motion.div>
            <div className={cn('flex-1 min-w-0 glass rounded-[12px] px-3.5 py-2.5', step.status === 'failed' && 'border-[rgba(242,139,155,0.4)]')}>
              <div className="flex items-center justify-between gap-2 flex-wrap">
                <div className="min-w-0">
                  <p className="text-sm font-medium text-[var(--text-primary)] truncate">
                    {STEP_NAME_LABEL[step.name] ?? step.name}
                  </p>
                  <p className="text-[11px] text-[var(--text-tertiary)] truncate">
                    {step.name}
                    {step.required ? ' · 必需' : ' · 可选'}
                  </p>
                </div>
                <div className="flex items-center gap-2 text-[11px] text-[var(--text-tertiary)] shrink-0">
                  {step.duration_ms != null && (
                    <span className="inline-flex items-center gap-1">
                      <Clock size={12} /> {formatDuration(step.duration_ms)}
                    </span>
                  )}
                </div>
              </div>

              <div className="mt-1.5 flex flex-col gap-1 text-xs text-[var(--text-secondary)]">
                <div className="flex items-center gap-2 flex-wrap">
                  <span>开始 {formatDateTime(step.started_at)}</span>
                  <span>结束 {formatDateTime(step.ended_at)}</span>
                </div>
                {step.outputs.length > 0 && (
                  <p className="text-[var(--text-tertiary)]">产物:{step.outputs.slice(0, 3).join(', ')}{step.outputs.length > 3 ? ` 等 ${step.outputs.length} 项` : ''}</p>
                )}
                {step.warnings.length > 0 && (
                  <p className="text-[var(--warning)]">警告:{step.warnings.length} 条</p>
                )}
                {step.error_message && (
                  <p className="text-[var(--danger)] break-words">错误:{step.error_message}</p>
                )}
              </div>
            </div>
          </li>
        )
      })}
    </ol>
  )
}

export default PipelineTimeline
