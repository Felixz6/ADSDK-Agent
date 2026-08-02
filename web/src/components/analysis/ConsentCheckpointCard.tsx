import { useState } from 'react'
import { HandHeart, ShieldQuestion, XCircle } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { cn } from '@/utils'
import type {
  ConsentCheckpointAction,
  ConsentCheckpointState,
} from '@/types/tasks'

/**
 * M7A — Consent 手动检查点卡片。
 *
 * 平台不会自动点击 UI、不会清除应用数据、也不会替操作员判断是否出现过
 * Consent 界面。请在真机上人工完成动作后,在此如实回报结论:
 *
 * - 已确认:在应用内看到并完成了 Consent 动作
 * - 未发现:本轮没有观察到 Consent 界面(记为证据,而非失败)
 * - 跳过:本轮显式跳过 Consent 环节
 *
 * 任何超时都不会自动变成"已确认";取消任务只会退出等待并进入清理。
 * 本卡片不展示 API Key、完整设备序列号、Prompt 原文、模型原文或
 * reasoning_content。
 */

const ACTION_COPY: Record<
  ConsentCheckpointAction,
  { label: string; hint: string }
> = {
  confirmed: {
    label: '已确认',
    hint: '我已在应用内看到并完成了 Consent 动作',
  },
  not_found: {
    label: '未发现',
    hint: '本轮没有观察到 Consent 界面(将记为证据缺口)',
  },
  skipped: {
    label: '跳过',
    hint: '本轮显式跳过 Consent 环节',
  },
}

const STATUS_COPY: Record<ConsentCheckpointState['status'], string> = {
  awaiting: '正在等待人工完成 Consent 动作并回报结论。',
  confirmed: '操作员已确认完成 Consent 动作。',
  not_found: '操作员回报本轮未发现 Consent 界面;动态证据按"部分"处理。',
  skipped: '操作员显式跳过了本轮 Consent 环节。',
  cancelled: '任务已取消,等待已退出并进入资源清理。',
  expired: '等待窗口已结束;未自动确认,本轮按"部分"处理。',
}

interface ConsentCheckpointCardProps {
  state: ConsentCheckpointState
  onResolve: (action: ConsentCheckpointAction, note: string) => void
  isSubmitting?: boolean
  errorMessage?: string | null
}

export function ConsentCheckpointCard({
  state,
  onResolve,
  isSubmitting = false,
  errorMessage = null,
}: ConsentCheckpointCardProps) {
  const [note, setNote] = useState('')
  const awaiting = state.status === 'awaiting'

  return (
    <GlassCard>
      <div className="flex flex-col gap-4">
        <div className="flex items-start gap-3">
          <span
            className={cn(
              'mt-0.5 shrink-0',
              awaiting ? 'text-[var(--warning)]' : 'text-[var(--status-neutral)]',
            )}
            aria-hidden="true"
          >
            {awaiting ? <HandHeart size={20} /> : <ShieldQuestion size={20} />}
          </span>
          <div className="min-w-0 flex-1">
            <h3 className="text-base font-semibold">Consent 手动检查点</h3>
            <p className="mt-1 text-sm text-[var(--text-secondary)]">
              {STATUS_COPY[state.status]}
            </p>
          </div>
          <span
            data-testid="consent-status"
            className={cn(
              'shrink-0 rounded-full border px-2.5 py-0.5 text-xs',
              awaiting
                ? 'border-[rgba(242,203,119,0.45)] text-[var(--warning)]'
                : 'border-[rgba(127,147,186,0.45)] text-[var(--status-neutral)]',
            )}
          >
            {state.status}
          </span>
        </div>

        <p className="text-xs leading-relaxed text-[var(--text-secondary)]">
          平台不会自动点击 UI、不会清除应用数据,也不会替你判断是否出现过 Consent
          界面。请在真机上人工完成动作后如实回报结论。超时不会自动确认。
        </p>

        {awaiting ? (
          <>
            <label className="flex flex-col gap-1.5 text-sm">
              <span className="text-[var(--text-secondary)]">
                备注(可选,最长 240 字,请勿填写任何密钥或完整设备序列号)
              </span>
              <input
                type="text"
                value={note}
                maxLength={240}
                onChange={(event) => setNote(event.target.value)}
                placeholder="例如:在首页弹窗完成同意"
                className="control-input"
                data-testid="consent-note"
              />
            </label>

            <div className="flex flex-wrap gap-2">
              {(
                ['confirmed', 'not_found', 'skipped'] as ConsentCheckpointAction[]
              ).map((action) => (
                <button
                  key={action}
                  type="button"
                  disabled={isSubmitting}
                  onClick={() => onResolve(action, note)}
                  title={ACTION_COPY[action].hint}
                  data-testid={`consent-action-${action}`}
                  className="control-button"
                >
                  {ACTION_COPY[action].label}
                </button>
              ))}
            </div>
          </>
        ) : (
          <dl className="grid gap-2 text-xs sm:grid-cols-2">
            <div>
              <dt className="text-[var(--text-secondary)]">结论</dt>
              <dd>{state.resolved_by_action ?? '—'}</dd>
            </div>
            <div>
              <dt className="text-[var(--text-secondary)]">完成时间</dt>
              <dd>{state.resolved_at ?? '—'}</dd>
            </div>
          </dl>
        )}

        {errorMessage ? (
          <p
            role="alert"
            data-testid="consent-error"
            className="flex items-center gap-1.5 text-xs text-[var(--danger)]"
          >
            <XCircle size={14} aria-hidden="true" />
            {errorMessage}
          </p>
        ) : null}
      </div>
    </GlassCard>
  )
}

export default ConsentCheckpointCard
