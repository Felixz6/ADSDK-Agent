import { Activity, AlertTriangle, CheckCircle2, Copy, ShieldQuestion } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import type {
  DynamicEvidenceQuality,
  DynamicExecutionSummary,
  DynamicTaskResult,
  FridaDiagnosticsResponse,
  FridaEnvironmentCapabilities,
  ProcessDiagnostics,
} from '@/types/api'
import { copyText } from '@/utils'
import { dynamicErrorLabel } from '@/utils/dynamicReliability'

interface Props {
  diagnostics?: FridaDiagnosticsResponse | null
  capabilities?: FridaEnvironmentCapabilities | null
  execution?: DynamicExecutionSummary | null
  taskResult?: DynamicTaskResult | null
  evidence?: DynamicEvidenceQuality | null
  process?: ProcessDiagnostics | null
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
  ready: { label: '通信就绪', tone: 'success' as const },
  degraded: { label: '部分能力待确认', tone: 'warning' as const },
  blocked: { label: '环境检查受阻', tone: 'danger' as const },
  error: { label: '环境检查异常', tone: 'danger' as const },
}

export function DynamicReliabilityCard({
  diagnostics,
  capabilities,
  execution,
  taskResult,
  evidence,
  process,
  traffic,
  loading,
  onRefresh,
}: Props) {
  const state = diagnostics ? STATUS[diagnostics.overall_status] : null
  const issue = diagnostics?.issues[0]
  const environment = capabilities ?? diagnostics?.capabilities ?? null
  const crash = process?.status === 'process_crashed' ? process : null
  const summary = {
    diagnostics,
    environment_capabilities: environment,
    execution,
    task_result: taskResult,
    evidence,
    process,
    traffic,
  }

  return (
    <GlassCard padding="md" highlight className="min-w-0 overflow-hidden" data-testid="dynamic-reliability-card">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h3 className="flex items-center gap-2 text-sm font-semibold text-[var(--text-primary)]">
            <Activity size={16} className="text-[var(--accent-blue)]" /> 动态分析可靠性
          </h3>
          <p className="mt-1 text-xs text-[var(--text-tertiary)]">
            环境能力与本次采集结果独立展示，进程崩溃不会覆盖已验证的 Frida 通信能力。
          </p>
        </div>
        <div className="flex flex-wrap items-center gap-2">
          {state && <StatusBadge tone={state.tone} label={state.label} />}
          {evidence && (
            <StatusBadge
              tone={evidence.level === 'A' ? 'success' : evidence.level === 'D' ? 'danger' : 'warning'}
              label={`证据 ${evidence.level} 级`}
            />
          )}
          {onRefresh && (
            <button type="button" disabled={loading} onClick={onRefresh} className="control-button">
              {loading ? '检查中…' : '重新检查'}
            </button>
          )}
          <button type="button" onClick={() => copyText(JSON.stringify(summary, null, 2))} className="control-button">
            <Copy size={13} /> 复制诊断摘要
          </button>
        </div>
      </div>

      {!diagnostics && !environment && !execution && !evidence && !taskResult ? (
        <div className="mt-4 flex items-start gap-2 rounded-[10px] border border-[var(--border-soft)] p-3 text-xs text-[var(--text-secondary)]">
          <ShieldQuestion size={16} className="mt-0.5 shrink-0" />
          尚未检查。选择设备后可执行只读环境检查，任务运行结果会在完成后单独展示。
        </div>
      ) : (
        <div className="mt-4 grid min-w-0 grid-cols-1 gap-3 lg:grid-cols-2">
          <section className="rounded-[10px] border border-[var(--border-soft)] p-3" aria-label="环境能力">
            <p className="text-xs font-medium text-[var(--text-primary)]">环境能力</p>
            <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
              <Item k="Frida 通信" v={capabilityLabel(environment?.transport_available, '正常')} />
              <Item k="进程枚举" v={capabilityLabel(environment?.process_enumeration_available, '正常')} />
              <Item k="Attach" v={capabilityLabel(environment?.attach_available, '可用')} />
              <Item k="Suspended spawn" v={capabilityLabel(environment?.spawn_creation_available, '创建和注入可用')} />
              <Item
                k="恢复稳定性"
                v={
                  environment?.spawn_resume_stable === false
                    ? '当前样本不兼容'
                    : capabilityLabel(environment?.spawn_resume_stable, '稳定')
                }
              />
              <Item
                k="推荐模式"
                v={
                  environment?.spawn_resume_stable === false
                    ? 'attach_only / balanced'
                    : diagnostics?.recommended_mode ?? '待任务验证'
                }
                mono
              />
            </dl>
            {diagnostics && (
              <p className="mt-2 text-[11px] text-[var(--text-tertiary)]">
                主机 {sectionLabel(diagnostics.host.status)} · 设备 {sectionLabel(diagnostics.device.status)} ·
                Server {sectionLabel(diagnostics.server.status)} · Transport {sectionLabel(diagnostics.transport.status)}
              </p>
            )}
          </section>

          <section className="rounded-[10px] border border-[var(--border-soft)] p-3" aria-label="本次采集结果">
            <p className="text-xs font-medium text-[var(--text-primary)]">本次采集结果</p>
            <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
              <Item k="最终模式" v={execution?.selected_mode ?? taskResult?.execution_mode ?? evidence?.mode ?? '旧报告未记录'} mono />
              <Item k="策略" v={execution?.policy ?? '旧报告未记录'} />
              <Item k="进程结果" v={taskResult?.process_result ?? process?.status ?? '待观察'} mono />
              <Item k="证据等级" v={evidence?.level ?? '待评定'} />
            </dl>
            {execution?.attempts.map((attempt, index) => (
              <div key={`${attempt.mode}-${index}`} className="mt-2 rounded-[8px] border border-[var(--border-soft)] p-2 text-xs">
                <div className="flex items-start gap-2">
                  {attempt.status === 'success'
                    ? <CheckCircle2 size={14} className="shrink-0 text-[var(--success)]" />
                    : <AlertTriangle size={14} className="shrink-0 text-[var(--warning)]" />}
                  <span className="min-w-0 text-[var(--text-secondary)]">
                    {attempt.mode} · {attemptStatus(attempt.status)}
                    {attempt.phase ? ` · ${phaseLabel(attempt.phase)}` : ''}
                  </span>
                </div>
                {attempt.post_resume_survival_ms != null && (
                  <p className="mt-1 pl-5 text-[11px] text-[var(--text-tertiary)]">
                    恢复后存活 {attempt.post_resume_survival_ms} ms
                  </p>
                )}
                {attempt.process_result && attempt.process_result !== 'running' && (
                  <p className="mt-1 pl-5 text-[11px] text-[var(--warning)]">
                    {dynamicErrorLabel(attempt.reason_code)} · {attempt.process_result}
                  </p>
                )}
              </div>
            ))}
            {execution?.launch_timing && (
              <p className="mt-2 text-[11px] text-[var(--text-tertiary)]">
                正常启动至附加完成间隙：{execution.launch_timing.startup_gap_ms ?? '待记录'} ms
              </p>
            )}
          </section>
        </div>
      )}

      {crash && (
        <section className="mt-3 rounded-[10px] border border-[rgba(242,139,155,0.28)] p-3">
          <p className="text-xs font-medium text-[var(--warning)]">Native 崩溃摘要</p>
          <p className="mt-2 text-xs leading-relaxed text-[var(--text-secondary)]">
            {crash.most_likely_cause ?? '恢复后的观察窗口记录到原生崩溃。'}
          </p>
          <dl className="mt-2 grid grid-cols-2 gap-2 text-xs">
            <Item k="信号" v={[crash.signal, crash.signal_code].filter(Boolean).join(' / ') || '待解析'} mono />
            <Item k="摘要" v={crash.summary ?? '待解析'} />
            <Item k="关键组件" v={crash.suspected_components?.join(', ') || '待解析'} mono />
            <Item k="诊断提示" v={crash.reason_code ?? 'native_runtime_crash'} mono />
          </dl>
          {crash.native_frames?.length ? (
            <details className="mt-3 rounded-[8px] border border-[var(--border-soft)] px-3 py-2">
              <summary className="cursor-pointer text-[11px] text-[var(--text-tertiary)]">
                技术详情 · 完整 Native backtrace（{crash.native_frames.length} 帧）
              </summary>
              <pre className="mt-2 max-h-72 overflow-auto whitespace-pre-wrap break-all text-[10px] text-[var(--text-tertiary)]">
                {crash.native_frames.join('\n')}
              </pre>
            </details>
          ) : null}
        </section>
      )}

      {issue && (
        <details className="mt-3 rounded-[10px] border border-[rgba(242,139,155,0.25)] p-3">
          <summary className="cursor-pointer text-xs text-[var(--warning)]">
            {dynamicErrorLabel(issue.code)} · 查看环境检查详情
          </summary>
          <p className="mt-2 text-xs text-[var(--text-secondary)]">{issue.remediation}</p>
          <code className="mt-2 block break-all text-[11px] text-[var(--text-tertiary)]">{issue.code}</code>
        </details>
      )}

      {process && process.status !== 'process_crashed' && process.status !== 'normal_cleanup' && (
        <p className="mt-3 text-xs text-[var(--text-secondary)]">
          进程：{process.most_likely_cause ?? process.status}
          {process.duration_ms != null ? ` · ${process.duration_ms} ms` : ''}
          {process.confidence ? ` · 置信度 ${process.confidence}` : ''}
        </p>
      )}
      {traffic && (
        <div className="mt-3 text-xs text-[var(--text-secondary)]">
          网络：{traffic.request_count} 个请求 · 代理 {traffic.proxy_status} · {traffic.outcome}
          {traffic.pinning_suspected && <span className="ml-2 text-[var(--warning)]">疑似 Pinning（诊断提示）</span>}
          {traffic.request_count === 0 && <p className="mt-1 text-[var(--text-tertiary)]">零请求只表示采集器本次未观察到请求。</p>}
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

function capabilityLabel(value: boolean | null | undefined, available: string) {
  return value === true ? available : value === false ? '本次验证未通过' : '待验证'
}

function sectionLabel(status: string) {
  return status === 'pass' ? '正常' : status === 'warning' ? '部分通过' : status === 'not_configured' ? '未配置' : status === 'error' ? '异常' : '待确认'
}

function attemptStatus(status: string) {
  return status === 'success' ? '成功' : status === 'failed' ? '失败' : status === 'running' ? '进行中' : '跳过'
}

function phaseLabel(phase: string) {
  const labels: Record<string, string> = {
    start: '启动',
    hook_loaded: 'Hook 已加载',
    hook_ready: 'Hook 已就绪',
    resumed: '已恢复',
    post_resume_stability: '恢复稳定窗口',
    collecting: '采集中',
  }
  return labels[phase] ?? phase
}

function Item({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="min-w-0">
      <dt className="text-[10px] text-[var(--text-tertiary)]">{k}</dt>
      <dd className={`${mono ? 'font-mono' : ''} break-words text-[var(--text-secondary)]`} title={v}>{v}</dd>
    </div>
  )
}
