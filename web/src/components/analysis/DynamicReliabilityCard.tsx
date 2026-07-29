import { Activity, AlertTriangle, CheckCircle2, Copy, ShieldQuestion } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import type {
  DynamicEvidenceQuality,
  DynamicExecutionSummary,
  FridaDiagnosticsResponse,
} from '@/types/api'
import { copyText } from '@/utils'
import { dynamicErrorLabel } from '@/utils/dynamicReliability'

interface Props {
  diagnostics?: FridaDiagnosticsResponse | null
  execution?: DynamicExecutionSummary | null
  evidence?: DynamicEvidenceQuality | null
  process?: {
    status: string
    duration_ms?: number | null
    most_likely_cause?: string
    confidence?: string
  } | null
  traffic?: {
    outcome: string
    proxy_status: string
    pinning_suspected: boolean
    request_count: number
    limitations: string[]
  } | null
  loading?: boolean
  onRefresh?: () => void
}

const STATUS = {
  ready: { label: '就绪', tone: 'success' as const },
  degraded: { label: '降级可用', tone: 'warning' as const },
  blocked: { label: '阻塞', tone: 'danger' as const },
  error: { label: '检测失败', tone: 'danger' as const },
}

export function DynamicReliabilityCard({
  diagnostics,
  execution,
  evidence,
  process,
  traffic,
  loading,
  onRefresh,
}: Props) {
  const state = diagnostics ? STATUS[diagnostics.overall_status] : null
  const issue = diagnostics?.issues[0]
  const summary = {
    diagnostics,
    execution,
    evidence,
    process,
    traffic,
  }
  return (
    <GlassCard padding="md" highlight className="min-w-0 overflow-hidden" data-testid="dynamic-reliability-card">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-[var(--text-primary)]">
            <Activity size={16} className="text-[var(--accent-blue)]" /> 动态分析就绪度
          </h3>
          <p className="mt-1 text-xs text-[var(--text-tertiary)]">
            主机、设备、frida-server、transport、执行模式与证据边界。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {state && <StatusBadge tone={state.tone} label={state.label} />}
          {evidence && <StatusBadge tone={evidence.level === 'A' ? 'success' : evidence.level === 'D' ? 'danger' : 'warning'} label={`证据 ${evidence.level} 级`} />}
          {onRefresh && (
            <button type="button" disabled={loading} onClick={onRefresh} className="control-button">
              {loading ? '检测中…' : '重新检测'}
            </button>
          )}
          <button type="button" onClick={() => copyText(JSON.stringify(summary, null, 2))} className="control-button">
            <Copy size={13} /> 复制诊断摘要
          </button>
        </div>
      </div>

      {!diagnostics && !execution && !evidence ? (
        <div className="mt-4 flex items-start gap-2 rounded-[10px] border border-[var(--border-soft)] p-3 text-xs text-[var(--text-secondary)]">
          <ShieldQuestion size={16} className="mt-0.5 shrink-0" />
          尚未检测。选择明确设备后可手动运行，不会自动部署或启动服务。
        </div>
      ) : (
        <div className="mt-4 grid min-w-0 grid-cols-1 gap-3 lg:grid-cols-2">
          {diagnostics && (
            <div className="rounded-[10px] border border-[var(--border-soft)] p-3">
              <p className="text-xs font-medium text-[var(--text-primary)]">分层诊断</p>
              <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
                <Item k="主机 Frida" v={sectionLabel(diagnostics.host.status)} />
                <Item k="设备连接" v={sectionLabel(diagnostics.device.status)} />
                <Item k="frida-server" v={sectionLabel(diagnostics.server.status)} />
                <Item k="Transport" v={sectionLabel(diagnostics.transport.status)} />
                <Item k="目标应用" v={sectionLabel(diagnostics.target.status)} />
                <Item k="推荐模式" v={diagnostics.recommended_mode} mono />
              </dl>
              <p className="mt-2 text-[11px] text-[var(--text-tertiary)]">
                {diagnostics.management_enabled ? '受控管理已启用' : '自动管理未启用'}
              </p>
            </div>
          )}

          {(execution || evidence) && (
            <div className="rounded-[10px] border border-[var(--border-soft)] p-3">
              <p className="text-xs font-medium text-[var(--text-primary)]">执行与证据</p>
              <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
                <Item k="最终模式" v={execution?.selected_mode ?? evidence?.mode ?? '旧版报告未记录'} mono />
                <Item k="策略" v={execution?.policy ?? '旧版报告未记录'} />
                <Item k="证据等级" v={evidence?.level ?? '无法判断'} />
                <Item k="降级次数" v={`${execution?.fallback_path.length ?? 0}`} />
              </dl>
              {execution?.attempts.map((attempt, index) => (
                <div key={`${attempt.mode}-${index}`} className="mt-2 flex items-start gap-2 text-xs">
                  {attempt.status === 'success' ? <CheckCircle2 size={14} className="text-[var(--success)]" /> : <AlertTriangle size={14} className="text-[var(--warning)]" />}
                  <span className="min-w-0 text-[var(--text-secondary)]">
                    {attempt.mode} · {attempt.status === 'success' ? '成功' : dynamicErrorLabel(attempt.reason_code)}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {issue && (
        <details className="mt-3 rounded-[10px] border border-[rgba(242,139,155,0.25)] p-3">
          <summary className="cursor-pointer text-xs text-[var(--warning)]">
            {dynamicErrorLabel(issue.code)} · 查看技术详情
          </summary>
          <p className="mt-2 text-xs text-[var(--text-secondary)]">{issue.remediation}</p>
          <code className="mt-2 block break-all text-[11px] text-[var(--text-tertiary)]">{issue.code}</code>
        </details>
      )}

      {process && (
        <p className="mt-3 text-xs text-[var(--text-secondary)]">
          进程：{process.most_likely_cause ?? process.status}
          {process.duration_ms != null ? ` · ${process.duration_ms} ms` : ''}
          {process.confidence ? ` · 置信度 ${process.confidence}` : ''}
        </p>
      )}
      {traffic && (
        <div className="mt-3 text-xs text-[var(--text-secondary)]">
          网络：{traffic.request_count} 个请求 · 代理 {traffic.proxy_status} · {traffic.outcome}
          {traffic.pinning_suspected && <span className="ml-2 text-[var(--warning)]">疑似 Pinning（并非确定结论）</span>}
          {traffic.request_count === 0 && <p className="mt-1 text-[var(--text-tertiary)]">零请求不代表应用没有网络行为。</p>}
        </div>
      )}
      {evidence?.limitations.length ? (
        <ul className="mt-3 list-disc space-y-1 pl-4 text-[11px] text-[var(--text-tertiary)]">
          {evidence.limitations.map((item) => <li key={item}>{item}</li>)}
        </ul>
      ) : null}
    </GlassCard>
  )
}

function sectionLabel(status: string) {
  return status === 'pass' ? '就绪' : status === 'warning' ? '降级' : status === 'not_configured' ? '未配置' : status === 'error' ? '异常' : '无法判断'
}

function Item({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] text-[var(--text-tertiary)]">{k}</dt>
      <dd className={`${mono ? 'font-mono' : ''} truncate text-[var(--text-secondary)]`} title={v}>{v}</dd>
    </div>
  )
}
