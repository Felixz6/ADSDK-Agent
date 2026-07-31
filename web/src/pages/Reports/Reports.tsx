import { useState } from 'react'
import { useSearchParams } from 'react-router-dom'
import {
  FileText,
  Copy,
  ShieldCheck,
  ShieldQuestion,
  Activity,
  Hand,
  Network,
  Download,
  Boxes,
  Megaphone,
  BadgeCheck,
  ShieldAlert,
  Printer,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { AISynthesisCard } from '@/components/analysis/AISynthesisCard'
import { RiskSummaryCard } from '@/components/analysis/RiskSummaryCard'
import { SdkIntelligencePanel } from '@/components/analysis/SdkIntelligencePanel'
import { PermissionSummaryPanel } from '@/components/analysis/PermissionSummaryPanel'
import { DynamicReliabilityCard } from '@/components/analysis/DynamicReliabilityCard'
import { EvidenceCorrelationCard } from '@/components/analysis/EvidenceCorrelationCard'
import { PrivacyFindingsCard } from '@/components/analysis/PrivacyFindingsCard'
import { ComplianceInsight } from '@/components/report/ComplianceInsight'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard } from '@/components/common/StatCard'
import { EmptyState, ErrorState, LoadingState } from '@/components/common/States'
import { ReportRuleCard } from '@/components/report/ReportRuleCard'
import { NoActiveResult } from '@/pages/shared/NoActiveResult'
import { useAnalysisStore } from '@/stores/analysisStore'
import { useUIStore } from '@/stores/uiStore'
import { useTaskReport } from '@/hooks/useTasks'
import { absoluteApiUrl } from '@/api/taskCenter'
import type { AnalyzeResponse, RuleEvaluationStatus } from '@/types/api'
import type { AIOrchestrationSection } from '@/types/tasks'
import { cn, copyText } from '@/utils'
import { riskLevelLabel, safeApplicationName } from '@/utils/taskPresentation'

export default function Reports() {
  const [searchParams] = useSearchParams()
  const taskId = searchParams.get('task_id') ?? undefined
  const remote = useTaskReport(taskId)
  // 报告页以「内存中最近一次活跃结果」为准;不限模式,动态/静态皆可查看元信息。
  const staticResp = useActiveResult2('static')
  const dynamicResp = useActiveResult2('dynamic')
  const resp = remote.data?.report ?? dynamicResp ?? staticResp
  const pushToast = useUIStore((s) => s.pushToast)
  const [tab, setTab] = useState<'rules' | 'report' | 'traffic'>('rules')

  if (taskId && remote.isLoading) return <GlassCard padding="none"><LoadingState title="正在加载持久化报告…" /></GlassCard>
  if (taskId && remote.isError) return <GlassCard padding="none"><ErrorState icon={<ShieldAlert size={28} />} title="报告加载失败" description={remote.error.message} /></GlassCard>
  if (!resp) return <NoActiveResultWrapper />

  const kind = useAnalysisStore.getState().kind
  const isDynamic = taskId ? resp.collection_status != null : kind === 'dynamic'
  const strict = resp.strict_dynamic_findings
  const mild = resp.dynamic_findings
  const counts = countStatuses([...(strict?.rules ?? []), ...(mild?.rules ?? [])])
  const traffic = resp.traffic_summary
  const advertisingSdkCount = resp.sdks.filter((sdk) => sdk.category === 'advertising').length
  const dynamicSdkCount = resp.sdks.filter((sdk) => sdk.dynamic_correlated).length
  const attentionSdkCount = resp.sdks.filter((sdk) => sdk.risk_level === 'high' || sdk.risk_level === 'critical').length
  const applicationName = safeApplicationName({
    appName: resp.app_info?.application_label,
    apkPath: resp.normalized_apk_name || resp.apk_path,
    packageName: resp.app_info?.package_name,
  })
  // 旧报告没有 ai_orchestration 字段:AI 区块不渲染,其余部分完全不变。
  const aiSection = (resp as { ai_orchestration?: AIOrchestrationSection }).ai_orchestration ?? null

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title={applicationName}
        description="规则评估结论与可读报告/流量摘要。所有敏感标识已脱敏;未评估绝不等于无风险。"
        eyebrow={`分析报告 · ${isDynamic ? '动态分析' : '静态分析'}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {remote.data?.html_url && (
              <a href={absoluteApiUrl(remote.data.html_url) ?? '#'} target="_blank" rel="noreferrer" className="control-button">
                <Printer size={14} /> 打印 / 导出 PDF
              </a>
            )}
            {remote.data?.html_url && <DownloadLink href={remote.data.html_url} label="HTML" />}
            {remote.data?.json_url && <DownloadLink href={remote.data.json_url} label="JSON" />}
            {remote.data?.markdown_url && <DownloadLink href={remote.data.markdown_url} label="Markdown" />}
            <button type="button" onClick={() => { copyText(reportSummary(resp)); pushToast({ kind: 'success', message: '已复制报告摘要。', duration: 2500 }) }} className="control-button">
              <Copy size={14} /> 复制摘要
            </button>
          </div>
        }
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="规则命中" value={counts.matched} tone="danger" icon={<Hand size={18} />} />
        <StatCard label="未命中" value={counts.not_matched} tone="success" icon={<ShieldCheck size={18} />} />
        <StatCard label="未评估" value={counts.not_evaluated} tone="neutral" icon={<ShieldQuestion size={18} />} />
        <StatCard label="异常" value={counts.error} tone="warning" icon={<Activity size={18} />} />
      </div>

      <RiskSummaryCard summary={resp.risk_summary} />

      <AISynthesisCard section={aiSection} />

      {isDynamic && (
        <>
          <DynamicReliabilityCard
              diagnostics={resp.frida_diagnostics}
              capabilities={resp.environment_capabilities}
              execution={resp.dynamic_execution}
              taskResult={resp.dynamic_task_result}
              evidence={resp.dynamic_evidence_quality}
              process={resp.process_diagnostics}
              traffic={resp.traffic_diagnostics}
          />
          <EvidenceCorrelationCard correlation={resp.evidence_correlation} />
          <PrivacyFindingsCard findings={resp.privacy_findings} />
        </>
      )}

      <ComplianceInsight insight={resp.compliance_insight} />
      <PermissionSummaryPanel appInfo={resp.app_info} />

      {resp.sdks.length > 0 && (
        <>
          <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
            <StatCard label="SDK 总数" value={resp.sdks.length} tone="default" icon={<Boxes size={18} />} />
            <StatCard label="广告 SDK" value={advertisingSdkCount} tone="accent" icon={<Megaphone size={18} />} />
            <StatCard label="动态佐证" value={dynamicSdkCount} tone="success" icon={<BadgeCheck size={18} />} />
            <StatCard label="高关注 SDK" value={attentionSdkCount} tone="warning" icon={<ShieldAlert size={18} />} />
          </div>
          <SdkIntelligencePanel sdks={resp.sdks} />
        </>
      )}

      <div className="flex items-center gap-1 glass rounded-[12px] p-1 w-fit">
        {([
          { k: 'rules', label: '规则结论', icon: <ShieldCheck size={14} /> },
          { k: 'report', label: '可读报告', icon: <FileText size={14} /> },
          { k: 'traffic', label: '流量摘要', icon: <Network size={14} /> },
        ] as const).map((t) => (
          <button
            key={t.k}
            type="button"
            onClick={() => setTab(t.k)}
            className={cn(
              'inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] text-xs font-medium transition-colors',
              tab === t.k ? 'glass-strong text-[var(--text-primary)]' : 'text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]',
            )}
          >
            {t.icon}{t.label}
          </button>
        ))}
      </div>

      {tab === 'rules' && (
        <div className="flex flex-col gap-4">
          {isDynamic ? (
            <>
              <ReportRuleCard findings={strict} strict />
              <ReportRuleCard findings={mild} />
            </>
          ) : (
            <GlassCard padding="md">
              <EmptyState
                icon={<ShieldCheck size={26} />}
                title="静态分析无动态规则结论"
                description="静态分析不评估同意前/后敏感访问规则。请发起动态分析以获得规则结论。"
              />
            </GlassCard>
          )}
          <GlassCard padding="md">
            <p className="text-[11px] text-[var(--text-tertiary)] leading-relaxed">
              规则状态说明:<b className="text-[var(--danger)]">命中</b> 表示规则命中违规模式;
              <b className="text-[var(--success)]"> 未命中</b> 表示规则已运行但未发现违规;
              <b className="text-[var(--status-neutral)]"> 未评估</b> 仅表示规则未运行或数据缺失,
              <b>绝不代表无风险</b>;
              <b className="text-[var(--warning)]"> 异常</b> 表示规则执行出错。
            </p>
          </GlassCard>
        </div>
      )}

      {tab === 'report' && (
        <GlassCard padding="md" highlight>
          <div className="flex items-center justify-between gap-2 flex-wrap mb-3">
            <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
              <FileText size={15} /> 报告产物
            </h3>
            {resp.report_md && (
              <button
                type="button"
                onClick={() => {
                  copyText(resp.report_md ?? '')
                  pushToast({ kind: 'success', message: '已复制报告 Markdown 文本。', duration: 2500 })
                }}
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] text-xs border border-[var(--border-soft)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
              >
                <Copy size={13} /> 复制报告
              </button>
            )}
          </div>
          <dl className="flex flex-col gap-1 mb-3">
            <KV k="报告 Markdown 路径" v={resp.report_md ?? '—(未生成)'} mono />
            <KV k="报告 JSON 路径" v={resp.report_json ?? '—(未生成)'} mono />
            <KV k="专业 HTML 路径" v={resp.report_html ?? '—(未生成)'} mono />
            <KV k="输出目录" v={resp.output_dir ?? '—'} mono />
          </dl>
          <p className="text-xs text-[var(--text-tertiary)] mb-2 inline-flex items-center gap-1.5">
            <Download size={13} /> 持久化任务可通过页面顶部下载；打印视图使用专用 CSS，浏览器可另存为 PDF。
          </p>
          {resp.report_md ? (
            <div className="glass rounded-[10px] p-3 max-h-[420px] overflow-auto">
              <pre className="text-[12px] leading-relaxed text-[var(--text-secondary)] whitespace-pre-wrap font-mono">{resp.report_md}</pre>
            </div>
          ) : (
            <p className="text-sm text-[var(--text-tertiary)] py-4 text-center">本次分析未生成可读报告。</p>
          )}
        </GlassCard>
      )}

      {tab === 'traffic' && (
        <GlassCard padding="md" highlight>
          {traffic ? (
            <>
              <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-1.5">
                <Network size={15} /> 流量摘要
              </h3>
              <div className="grid grid-cols-2 sm:grid-cols-3 gap-3 mb-3">
                <StatCard label="总请求数" value={traffic.total_requests} tone="default" />
                <StatCard label="覆盖度" value={traffic.coverage} tone="accent" />
                <StatCard label="采集结局" value={traffic.collector_outcome} tone={traffic.status === 'success' ? 'success' : 'danger'} />
              </div>
              {traffic.top_hosts.length > 0 && (
                <div className="mb-3">
                  <p className="text-[11px] text-[var(--text-tertiary)] mb-1">Top 主机</p>
                  <ul className="flex flex-col gap-1">
                    {traffic.top_hosts.slice(0, 8).map((h) => (
                      <li key={h.host ?? 'na'} className="flex items-center justify-between gap-3 text-sm">
                        <span className="text-[var(--text-secondary)] font-mono truncate">{h.host ?? '(未记录)'}</span>
                        <span className="text-[var(--text-tertiary)] shrink-0">{h.count}</span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {traffic.warnings.length > 0 && (
                <div>
                  <p className="text-xs text-[var(--warning)] mb-1">警告</p>
                  <ul className="text-xs text-[var(--text-secondary)] list-disc pl-4 flex flex-col gap-1">
                    {traffic.warnings.map((w, i) => <li key={i}>{w}</li>)}
                  </ul>
                </div>
              )}
              <p className="text-[11px] text-[var(--text-tertiary)] mt-3">
                单条请求明细(方法/主机/路径脱敏段/查询键名)请见「网络外发」页。不含请求头、请求体、原始 URL 与鉴权信息。
              </p>
            </>
          ) : (
            <EmptyState icon={<Network size={26} />} title="无流量摘要" description="本次分析未启用或未采集到流量数据。" />
          )}
        </GlassCard>
      )}
    </div>
  )
}

function NoActiveResultWrapper() {
  // 报告页允许静态或动态任一活跃结果存在
  return <NoActiveResult expected="dynamic" />
}

function DownloadLink({ href, label }: { href: string; label: string }) {
  return (
    <a href={absoluteApiUrl(href) ?? '#'} download className="control-button">
      <Download size={14} /> {label}
    </a>
  )
}

function reportSummary(resp: AnalyzeResponse): string {
  const app = resp.app_info
  const risk = resp.risk_summary
  const statusLabels: Record<string, string> = {
    success: '成功',
    partial: '部分完成',
    failed: '失败',
    skipped: '已跳过',
  }
  return [
    `AdSDK Agent 报告摘要`,
    `应用：${safeApplicationName({ appName: app?.application_label, apkPath: resp.normalized_apk_name || resp.apk_path, packageName: app?.package_name })}`,
    `包名：${app?.package_name ?? '待解析'}`,
    `风险：${risk?.score ?? '未评估'} / ${riskLevelLabel(risk?.level)}`,
    `SDK：${resp.sdk_count}`,
    `状态：${statusLabels[resp.status] ?? '未评估'}`,
    `提示：未评估仅表示证据不足，不代表安全。`,
  ].join('\n')
}

// 与 useActiveResult 等价的内联访问器(报告页兼容两种 kind)
function useActiveResult2(expected: 'static' | 'dynamic') {
  const store = useAnalysisStore()
  return store.active && store.kind === expected ? store.active : null
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1 border-b border-[var(--border-soft)]/40">
      <dt className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide shrink-0 pt-0.5">{k}</dt>
      <dd className={cn('text-sm text-[var(--text-primary)] text-right break-all', mono && 'font-mono text-[13px]')}>{v}</dd>
    </div>
  )
}

function countStatuses(rules: { status?: RuleEvaluationStatus }[]) {
  let matched = 0
  let not_matched = 0
  let not_evaluated = 0
  let error = 0
  for (const r of rules) {
    switch (r.status) {
      case 'matched': matched += 1; break
      case 'not_matched': not_matched += 1; break
      case 'not_evaluated': not_evaluated += 1; break
      case 'error': error += 1; break
      default: break
    }
  }
  return { matched, not_matched, not_evaluated, error }
}
