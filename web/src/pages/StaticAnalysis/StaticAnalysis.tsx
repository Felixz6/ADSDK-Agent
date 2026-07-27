import { Copy, CheckCircle2, ShieldCheck, Package } from 'lucide-react'
import { useState, type ReactNode } from 'react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { StatCard } from '@/components/common/StatCard'
import { PipelineTimeline } from '@/components/report/PipelineTimeline'
import { STEP_STATUS_LABEL } from '@/components/common/StatusBadge'
import { KNOWN_SDK_NAMES, type SdkHit } from '@/types/api'
import { useActiveResult, NoActiveResult } from '@/pages/shared/NoActiveResult'
import { useAnalysisStore } from '@/stores/analysisStore'
import { useUIStore } from '@/stores/uiStore'
import { RiskBadge, deriveRiskLevel } from '@/components/common/RiskBadge'
import { cn, copyText, formatDateTime } from '@/utils'

export default function StaticAnalysis() {
  const resp = useActiveResult('static')
  const task = useAnalysisStore((s) => s.task)
  const pushToast = useUIStore((s) => s.pushToast)

  if (!resp) return renderShell(<NoActiveResult expected="static" />)

  const info = resp.app_info
  const matched = countMatched(resp.dynamic_findings?.rules as { status?: string }[] | undefined)
  const risk = deriveRiskLevel({
    matched,
    not_evaluated: 0,
    errored: 0,
  })

  return renderShell(
    <div className="flex flex-col gap-5">
      <PageHeader
        title="静态分析"
        description="基于 AndroidManifest 解析与 SDK 指纹识别的结果概览。原始敏感字段已脱敏。"
        eyebrow={`任务 ${task?.local_id ?? ''} · 完成于 ${formatDateTime(task?.created_at)}`}
        actions={<RiskBadge level={risk} />}
      />

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="应用包名" value={info?.package_name ?? '—'} tone="default" icon={<Package size={18} />} hint={info?.application_label ?? undefined} />
        <StatCard label="版本" value={info?.version_name ?? '—'} tone="accent" hint={info?.version_code != null ? `versionCode ${info.version_code}` : undefined} />
        <StatCard label="识别 SDK 数" value={resp.sdk_count} tone="success" icon={<ShieldCheck size={18} />} />
        <StatCard label="整体状态" value={STEP_STATUS_LABEL[resp.status] ?? resp.status} tone={resp.status === 'success' ? 'success' : 'warning'} icon={<CheckCircle2 size={18} />} />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <GlassCard padding="md" highlight className="lg:col-span-1 flex flex-col gap-2">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">APK 快照</h3>
          <KV k="来源路径(展示)" v={resp.apk_snapshot?.source_path_display ?? '—'} copy={resp.apk_snapshot?.source_path_display ?? null} onCopy={() => pushToast({ kind: 'success', message: '已复制(脱敏路径)。', duration: 2000 })} />
          <KV k="快照状态" v={resp.apk_snapshot?.snapshot_status ?? '—'} />
          <KV k="快照大小" v={resp.apk_snapshot?.snapshot_size_bytes != null ? fmtBytes(resp.apk_snapshot.snapshot_size_bytes) : '—'} />
          <KV k="SHA-256" v={resp.apk_sha256 ?? '—'} mono />
        </GlassCard>

        <GlassCard padding="md" highlight className="lg:col-span-2 flex flex-col gap-2">
          <h3 className="text-sm font-semibold text-[var(--text-primary)]">SDK 识别结果</h3>
          {resp.sdks.length === 0 ? (
            <p className="text-sm text-[var(--text-tertiary)] py-4">未识别到已收录 SDK。</p>
          ) : (
            <ul className="flex flex-col gap-2">
              {resp.sdks.map((sdk, i) => (
                <SdkRow key={`${sdk.package}-${i}`} sdk={sdk} />
              ))}
            </ul>
          )}
          <KnownSdks />
        </GlassCard>
      </div>

      <GlassCard padding="md" highlight>
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3">分析步骤</h3>
        <PipelineTimeline steps={resp.steps} />
      </GlassCard>

      {resp.warnings.length > 0 && (
        <GlassCard padding="md">
          <h3 className="text-sm font-semibold text-[var(--warning)] mb-2">警告</h3>
          <ul className="text-xs text-[var(--text-secondary)] list-disc pl-4 flex flex-col gap-1">
            {resp.warnings.map((w, i) => <li key={i}>{w}</li>)}
          </ul>
        </GlassCard>
      )}
    </div>,
  )

  function renderShell(content: ReactNode) {
    return <div className="flex flex-col gap-5">{content}</div>
  }
}

function SdkRow({ sdk }: { sdk: SdkHit }) {
  const isKnown = (KNOWN_SDK_NAMES as readonly string[]).includes(sdk.sdk_name)
  return (
    <li className="rounded-[10px] border border-[var(--border-soft)] px-3 py-2 flex items-start gap-3">
      <div className="min-w-0 flex-1">
        <div className="flex items-center gap-2">
          <span className="text-sm font-medium text-[var(--text-primary)] truncate">{sdk.sdk_name}</span>
          {isKnown && (
            <span className="text-[10px] px-1.5 py-0.5 rounded-md bg-[rgba(120,216,255,0.12)] text-[var(--accent-blue)] border border-[var(--border-soft)]">
              已收录
            </span>
          )}
          <span className="text-[11px] text-[var(--text-tertiary)]">{sdk.package}</span>
        </div>
        {sdk.version && <p className="text-[11px] text-[var(--text-tertiary)] mt-0.5">version: {sdk.version}</p>}
        {sdk.evidence.length > 0 && (
          <p className="text-[11px] text-[var(--text-tertiary)] mt-0.5 truncate">
            证据:{sdk.evidence[0].detector} · {sdk.evidence[0].description}
          </p>
        )}
      </div>
      <span className="text-xs text-[var(--text-secondary)] shrink-0">{Math.round(sdk.confidence * 100)}%</span>
    </li>
  )
}

function KnownSdks() {
  return (
    <div className="mt-2">
      <p className="text-[11px] text-[var(--text-tertiary)] mb-1">已收录 SDK 池</p>
      <div className="flex flex-wrap gap-1.5">
        {KNOWN_SDK_NAMES.map((name) => (
          <span key={name} className="text-[10px] px-1.5 py-0.5 rounded-md border border-[var(--border-soft)] text-[var(--text-tertiary)]">
            {name}
          </span>
        ))}
      </div>
    </div>
  )
}

function KV({ k, v, mono, copy, onCopy }: { k: string; v: string; mono?: boolean; copy?: string | null; onCopy?: () => void }) {
  const [copied, setCopied] = useState(false)
  async function doCopy() {
    if (!copy) return
    const ok = await copyText(copy)
    setCopied(ok)
    onCopy?.()
    setTimeout(() => setCopied(false), 1200)
  }
  return (
    <div className="flex items-start justify-between gap-3 py-1 border-b border-[var(--border-soft)]/40">
      <dt className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide shrink-0 pt-0.5">{k}</dt>
      <dd className={cn('text-sm text-[var(--text-primary)] text-right break-all flex items-center gap-1.5', mono && 'font-mono text-[13px]')}>
        <span>{v}</span>
        {copy && (
          <button type="button" onClick={doCopy} aria-label="复制" className="text-[var(--text-tertiary)] hover:text-[var(--accent-blue)]" title="复制">
            {copied ? <CheckCircle2 size={13} className="text-[var(--success)]" /> : <Copy size={13} />}
          </button>
        )}
      </dd>
    </div>
  )
}

function countMatched(rules?: { status?: string }[]) {
  return (rules ?? []).filter((r) => r.status === 'matched').length
}

function fmtBytes(n: number) {
  if (n < 1024) return `${n} B`
  return `${(n / 1024 / 1024).toFixed(2)} MB`
}
