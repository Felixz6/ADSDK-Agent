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
  ChevronDown,
  Wrench,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { AISynthesisCard } from '@/components/analysis/AISynthesisCard'
import { AIOrchestrationCard } from '@/components/analysis/AIOrchestrationCard'
import { RiskSummaryCard } from '@/components/analysis/RiskSummaryCard'
import { SdkIntelligencePanel } from '@/components/analysis/SdkIntelligencePanel'
import { PermissionSummaryPanel } from '@/components/analysis/PermissionSummaryPanel'
import { DynamicReliabilityCard } from '@/components/analysis/DynamicReliabilityCard'
import { EvidenceCorrelationCard } from '@/components/analysis/EvidenceCorrelationCard'
import { PrivacyFindingsCard } from '@/components/analysis/PrivacyFindingsCard'
import { ComplianceInsight } from '@/components/report/ComplianceInsight'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard, MetricStrip } from '@/components/common/StatCard'
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

  if (taskId && remote.isLoading) {
    return <GlassCard padding="none"><LoadingState title="正在加载持久化报告…" /></GlassCard>
  }
  if (taskId && remote.isError) {
    return (
      <GlassCard padding="none">
        <ErrorState
          icon={<ShieldAlert size={28} />}
          title="报告加载失败"
          description={remote.error.message}
        />
      </GlassCard>
    )
  }
  if (!resp) return <NoActiveResultWrapper />

  const kind = useAnalysisStore.getState().kind
  const isDynamic = taskId ? resp.collection_status != null : kind === 'dynamic'
  const strict = resp.strict_dynamic_findings
  const mild = resp.dynamic_findings
  const counts = countStatuses([...(strict?.rules ?? []), ...(mild?.rules ?? [])])
  const traffic = resp.traffic_summary
  const advertisingSdkCount = resp.sdks.filter((sdk) => sdk.category === 'advertising').length
  const dynamicSdkCount = resp.sdks.filter((sdk) => sdk.dynamic_correlated).length
  const attentionSdkCount = resp.sdks.filter(
    (sdk) => sdk.risk_level === 'high' || sdk.risk_level === 'critical',
  ).length
  const applicationName = safeApplicationName({
    appName: resp.app_info?.application_label,
    apkPath: resp.normalized_apk_name || resp.apk_path,
    packageName: resp.app_info?.package_name,
  })
  // 旧报告没有 ai_orchestration 字段:AI 区块不渲染,其余部分完全不变。
  const aiSection = (resp as { ai_orchestration?: AIOrchestrationSection }).ai_orchestration ?? null

  const anchors = [
    { id: 'section-overview', label: '核心结论' },
    ...(isDynamic ? [{ id: 'section-dynamic', label: '动态与隐私发现' }] : []),
    { id: 'section-static', label: '权限与 SDK' },
    { id: 'section-artifacts', label: '规则与产物' },
    { id: 'section-diagnostics', label: '运行诊断' },
  ]

  return (
    <div className="flex flex-col gap-6">
      <PageHeader
        title={applicationName}
        description="规则评估结论与可读报告/流量摘要。所有敏感标识已脱敏；未评估绝不等于无风险。"
        eyebrow={`分析报告 · ${isDynamic ? '动态分析' : '静态分析'}${resp.app_info?.package_name ? ` · ${resp.app_info.package_name}` : ''}`}
        actions={
          <div className="flex flex-wrap items-center gap-2">
            {remote.data?.html_url && (
              <a
                href={absoluteApiUrl(remote.data.html_url) ?? '#'}
                target="_blank"
                rel="noreferrer"
                className="control-primary"
              >
                <Printer size={14} /> 打印 / 导出 PDF
              </a>
            )}
            {remote.data?.html_url && <DownloadLink href={remote.data.html_url} label="HTML" />}
            {remote.data?.json_url && <DownloadLink href={remote.data.json_url} label="JSON" />}
            {remote.data?.markdown_url && <DownloadLink href={remote.data.markdown_url} label="Markdown" />}
            <button
              type="button"
              onClick={() => {
                copyText(reportSummary(resp))
                pushToast({ kind: 'success', message: '已复制报告摘要。', duration: 2500 })
              }}
              className="control-button"
            >
              <Copy size={14} /> 复制摘要
            </button>
          </div>
        }
      />

      {/* 快速分区跳转栏 */}
      <nav
        aria-label="报告分区导航"
        className="flex items-center gap-1.5 overflow-x-auto pb-1 -mt-2"
      >
        {anchors.map((item) => (
          <a
            key={item.id}
            href={`#${item.id}`}
            className="shrink-0 rounded-full border border-[var(--hairline)] bg-[var(--bg-soft)] px-3 py-1 text-xs font-medium text-[var(--text-secondary)] hover:border-[var(--border-active)] hover:text-[var(--text-primary)] transition-colors no-underline"
          >
            {item.label}
          </a>
        ))}
      </nav>

      {/* 一、核心结论 */}
      <section id="section-overview" className="flex flex-col gap-4 scroll-mt-32">
        <MetricStrip>
          <StatCard embedded label="规则命中" value={counts.matched} tone="danger" icon={<Hand size={17} />} />
          <StatCard embedded label="未命中" value={counts.not_matched} tone="success" icon={<ShieldCheck size={17} />} />
          <StatCard embedded label="未评估" value={counts.not_evaluated} tone="neutral" icon={<ShieldQuestion size={17} />} />
          <StatCard embedded label="异常" value={counts.error} tone="warning" icon={<Activity size={17} />} />
        </MetricStrip>

        <RiskSummaryCard summary={resp.risk_summary} />
        <AISynthesisCard section={aiSection} />
        <ComplianceInsight insight={resp.compliance_insight} />
      </section>

      {/* 二、动态证据与可解释隐私发现 */}
      {isDynamic && (
        <section id="section-dynamic" className="flex flex-col gap-4 scroll-mt-32">
          <SectionHeading
            title="动态证据与隐私发现"
            subtitle="按单调时钟与可信边界组织的动态观察结果。"
          />
          <PrivacyFindingsCard findings={resp.privacy_findings} />
          <EvidenceCorrelationCard correlation={resp.evidence_correlation} />
          <DynamicReliabilityCard
            diagnostics={resp.frida_diagnostics}
            capabilities={resp.environment_capabilities}
            execution={resp.dynamic_execution}
            taskResult={resp.dynamic_task_result}
            evidence={resp.dynamic_evidence_quality}
            process={resp.process_diagnostics}
            traffic={resp.traffic_diagnostics}
          />
        </section>
      )}

      {/* 三、权限与 SDK 情报 */}
      <section id="section-static" className="flex flex-col gap-4 scroll-mt-32">
        <SectionHeading
          title="权限与第三方 SDK"
          subtitle="基于 AndroidManifest 与静态指纹库识别的组件清单。"
        />
        <PermissionSummaryPanel appInfo={resp.app_info} />

        {resp.sdks.length > 0 && (
          <>
            <MetricStrip>
              <StatCard embedded label="SDK 总数" value={resp.sdks.length} tone="default" icon={<Boxes size={17} />} />
              <StatCard embedded label="广告 SDK" value={advertisingSdkCount} tone="accent" icon={<Megaphone size={17} />} />
              <StatCard embedded label="动态佐证" value={dynamicSdkCount} tone="success" icon={<BadgeCheck size={17} />} />
              <StatCard embedded label="高关注 SDK" value={attentionSdkCount} tone="warning" icon={<ShieldAlert size={17} />} />
            </MetricStrip>
            <SdkIntelligencePanel sdks={resp.sdks} />
          </>
        )}
      </section>

      {/* 四、规则明细 / 可读报告 / 流量摘要 */}
      <section id="section-artifacts" className="flex flex-col gap-4 scroll-mt-32">
        <div className="flex flex-wrap items-center justify-between gap-3">
          <SectionHeading title="规则结论与产物" />
          <div className="inline-flex items-center gap-1 rounded-full bg-[var(--bg-soft)] p-1 border border-[var(--hairline)]">
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
                  'inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-full text-xs font-medium transition-colors',
                  tab === t.k
                    ? 'bg-[var(--text-primary)] text-[var(--bg-deep)] shadow-sm'
                    : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)]',
                )}
              >
                {t.icon}
                {t.label}
              </button>
            ))}
          </div>
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
            <p className="text-xs text-[var(--text-tertiary)] leading-relaxed px-1">
              规则状态说明：<b className="text-[var(--danger)]">命中</b> 表示规则命中违规模式；
              <b className="text-[var(--success)]"> 未命中</b> 表示规则已运行但未发现违规；
              <b className="text-[var(--status-neutral)]"> 未评估</b> 仅表示规则未运行或数据缺失，
              <b>绝不代表无风险</b>；
              <b className="text-[var(--warning)]"> 异常</b> 表示规则执行出错。
            </p>
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
                  className="control-button text-xs"
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
            <p className="text-xs text-[var(--text-tertiary)] mb-3 inline-flex items-center gap-1.5">
              <Download size={13} /> 持久化任务可通过页面顶部下载；打印视图使用专用 CSS，浏览器可另存为 PDF。
            </p>
            {resp.report_md ? (
              <div className="rounded-[10px] border border-[var(--hairline)] bg-[var(--bg-soft)] p-3.5 max-h-[460px] overflow-auto">
                <pre className="text-xs leading-relaxed text-[var(--text-secondary)] whitespace-pre-wrap font-mono">
                  {resp.report_md}
                </pre>
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
                <div className="grid grid-cols-1 sm:grid-cols-3 divide-y sm:divide-y-0 sm:divide-x divide-[var(--hairline)] rounded-[12px] border border-[var(--hairline)] mb-4">
                  <StatCard embedded label="总请求数" value={traffic.total_requests} tone="default" />
                  <StatCard embedded label="覆盖度" value={traffic.coverage} tone="accent" />
                  <StatCard
                    embedded
                    label="采集结局"
                    value={traffic.collector_outcome}
                    tone={traffic.status === 'success' ? 'success' : 'danger'}
                  />
                </div>
                {traffic.top_hosts.length > 0 && (
                  <div className="mb-4">
                    <p className="text-xs font-medium text-[var(--text-tertiary)] mb-2">Top 主机</p>
                    <ul className="divide-y divide-[var(--hairline)] border-t border-b border-[var(--hairline)]">
                      {traffic.top_hosts.slice(0, 8).map((h) => (
                        <li key={h.host ?? 'na'} className="flex items-center justify-between gap-3 py-2 text-sm">
                          <span className="text-[var(--text-primary)] font-mono truncate">{h.host ?? '(未记录)'}</span>
                          <span className="text-[var(--text-secondary)] tabular-nums shrink-0">{h.count}</span>
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
                {traffic.warnings.length > 0 && (
                  <div>
                    <p className="text-xs font-medium text-[var(--warning)] mb-1">警告</p>
                    <ul className="text-xs text-[var(--text-secondary)] list-disc pl-4 flex flex-col gap-1">
                      {traffic.warnings.map((w, i) => <li key={i}>{w}</li>)}
                    </ul>
                  </div>
                )}
                <p className="text-xs text-[var(--text-tertiary)] mt-3">
                  单条请求明细（方法/主机/路径脱敏段/查询键名）请见「网络外发」页。不含请求头、请求体、原始 URL 与鉴权信息。
                </p>
              </>
            ) : (
              <EmptyState icon={<Network size={26} />} title="无流量摘要" description="本次分析未启用或未采集到流量数据。" />
            )}
          </GlassCard>
        )}
      </section>

      {/* 五、技术与 AI 运行诊断（默认折叠，减少主报告流干扰） */}
      <section id="section-diagnostics" className="scroll-mt-32">
        <details className="group rounded-[var(--radius-glass)] border border-[var(--hairline)] bg-[var(--bg-soft)]">
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3.5 text-sm font-medium text-[var(--text-primary)] select-none">
            <span className="flex items-center gap-2">
              <Wrench size={15} className="text-[var(--text-tertiary)]" />
              <span>AI 编排与运行诊断</span>
              <span className="text-xs font-normal text-[var(--text-tertiary)]">
                {aiSection ? `· ${aiSection.status}` : '· 确定性模式'}
              </span>
            </span>
            <ChevronDown
              size={16}
              className="text-[var(--text-tertiary)] transition-transform group-open:rotate-180"
            />
          </summary>
          <div className="flex flex-col gap-4 border-t border-[var(--hairline)] p-4 bg-[var(--bg-deep)] rounded-b-[var(--radius-glass)]">
            <AIOrchestrationCard section={aiSection} />
            <M7BReportDiagnostics section={aiSection} report={resp as unknown as Record<string, unknown>} />
          </div>
        </details>
      </section>
    </div>
  )
}

function SectionHeading({ title, subtitle }: { title: string; subtitle?: string }) {
  return (
    <div>
      <h2 className="text-base font-semibold tracking-tight text-[var(--text-primary)]">{title}</h2>
      {subtitle && <p className="mt-0.5 text-xs text-[var(--text-tertiary)]">{subtitle}</p>}
    </div>
  )
}

function M7BReportDiagnostics({
  section,
  report,
}: {
  section: AIOrchestrationSection | null
  report: Record<string, unknown>
}) {
  const diag = section?.diagnostic
  const consent = (report.consent ?? report.consent_checkpoint ?? null) as Record<string, unknown> | null
  const cleanup = (report.cleanup ?? report.cleanup_outcome ?? null) as Record<string, unknown> | null
  const cleanupLimitations = (cleanup?.limitations ?? report.cleanup_limitations ?? []) as unknown
  const limitations = Array.isArray(cleanupLimitations) ? cleanupLimitations.map(String) : []
  const value = (v: unknown) => (v == null || v === '' ? '—' : String(v))
  return (
    <GlassCard padding="md" className="min-w-0 overflow-hidden" data-testid="m7b-report-diagnostics">
      <h3 className="text-sm font-semibold text-[var(--text-primary)]">M7B 运行诊断</h3>
      <dl className="mt-3 grid min-w-0 grid-cols-1 gap-x-6 gap-y-1.5 text-xs sm:grid-cols-2">
        <KV k="计划来源" v={value(diag?.plan_source)} />
        <KV k="首轮校验" v={diag?.planning_failed ? '失败' : '无失败记录'} />
        <KV k="校验错误" v={value(diag?.validation_error_code)} mono />
        <KV k="JSON 路径" v={value(diag?.validation_json_path)} mono />
        <KV
          k="修复 / 回退"
          v={`尝试 ${diag?.repair_attempted ? '是' : '否'} · 成功 ${diag?.repair_succeeded ? '是' : '否'} · 回退 ${diag?.fallback_used ? '是' : '否'}`}
        />
        <KV
          k="请求 / 生效策略"
          v={`${value(diag?.requested_strategy)} → ${value(diag?.effective_strategy)}`}
        />
        <KV k="归一化" v={diag?.normalized ? `是 · ${value(diag.normalization_reason)}` : '否'} />
        <KV
          k="目标运行 / 预检变化"
          v={`${diag?.target_running ? '是' : '否'} / ${diag?.preflight_changed ? '是' : '否'}`}
        />
        <KV k="Consent" v={value(consent?.status)} />
        <KV
          k="AI 报告 / 证据校验"
          v={`${value(diag?.report_source)} / ${diag?.report_source === 'deterministic_fallback' ? '确定性回退' : '已验证'}`}
        />
        <KV
          k="模型轮次 / Token"
          v={`${value(diag?.total_rounds)} / ${value(diag?.usage?.usage_source)}${diag?.cache_hit ? ' · cache' : ''}`}
        />
        <KV k="清理状态" v={value(cleanup?.status ?? cleanup?.ok)} />
      </dl>
      {limitations.length > 0 && (
        <ul className="mt-3 list-disc space-y-1 break-words pl-4 text-xs text-[var(--text-tertiary)]">
          {limitations.map((item, i) => (
            <li key={i}>{item}</li>
          ))}
        </ul>
      )}
    </GlassCard>
  )
}

function NoActiveResultWrapper() {
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

function useActiveResult2(expected: 'static' | 'dynamic') {
  const store = useAnalysisStore()
  return store.active && store.kind === expected ? store.active : null
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1.5 border-b border-[var(--hairline)]">
      <dt className="text-xs text-[var(--text-tertiary)] shrink-0 pt-0.5">{k}</dt>
      <dd className={cn('text-sm text-[var(--text-primary)] text-right break-all', mono && 'font-mono text-xs')}>
        {v}
      </dd>
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
      case 'matched':
        matched += 1
        break
      case 'not_matched':
        not_matched += 1
        break
      case 'not_evaluated':
        not_evaluated += 1
        break
      case 'error':
        error += 1
        break
      default:
        break
    }
  }
  return { matched, not_matched, not_evaluated, error }
}