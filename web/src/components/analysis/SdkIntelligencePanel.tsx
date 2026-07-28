import { useMemo, useState } from 'react'
import { ChevronDown, PackageSearch } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import type { SdkHit } from '@/types/api'

export function SdkIntelligencePanel({ sdks }: { sdks: SdkHit[] }) {
  const [category, setCategory] = useState('all')
  const [risk, setRisk] = useState('all')
  const categories = [...new Set(sdks.map((sdk) => sdk.category).filter(Boolean))]
  const filtered = useMemo(
    () => sdks.filter((sdk) =>
      (category === 'all' || sdk.category === category)
      && (risk === 'all' || sdk.risk_level === risk)),
    [sdks, category, risk],
  )
  return (
    <GlassCard padding="md" highlight>
      <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
          <PackageSearch size={15} /> SDK 风险知识
        </h3>
        <div className="flex gap-2">
          <select aria-label="SDK 分类筛选" value={category} onChange={(event) => setCategory(event.target.value)}
            className="bg-transparent text-xs border border-[var(--border-soft)] rounded-[8px] px-2 py-1.5">
            <option value="all">全部分类</option>
            {categories.map((item) => <option key={item} value={item ?? ''}>{item}</option>)}
          </select>
          <select aria-label="SDK 风险筛选" value={risk} onChange={(event) => setRisk(event.target.value)}
            className="bg-transparent text-xs border border-[var(--border-soft)] rounded-[8px] px-2 py-1.5">
            <option value="all">全部风险</option>
            <option value="low">低</option><option value="medium">中</option>
            <option value="high">高</option><option value="critical">严重</option>
          </select>
        </div>
      </div>
      {filtered.length === 0 ? (
        <p className="text-sm text-[var(--text-tertiary)] py-4 text-center">当前筛选下未识别到 SDK。</p>
      ) : (
        <ul className="flex flex-col gap-2">
          {filtered.map((sdk, index) => <SdkDetail key={`${sdk.id ?? sdk.package}-${index}`} sdk={sdk} />)}
        </ul>
      )}
    </GlassCard>
  )
}

function SdkDetail({ sdk }: { sdk: SdkHit }) {
  const [open, setOpen] = useState(false)
  const tone = sdk.risk_level === 'high' || sdk.risk_level === 'critical' ? 'danger'
    : sdk.risk_level === 'medium' ? 'warning' : 'neutral'
  return (
    <li className="rounded-[10px] border border-[var(--border-soft)] p-3 min-w-0">
      <button type="button" onClick={() => setOpen((value) => !value)} className="w-full text-left">
        <div className="flex items-center gap-2 min-w-0 flex-wrap">
          <strong className="text-sm text-[var(--text-primary)] break-words">{sdk.sdk_name}</strong>
          <StatusBadge tone={tone} label={sdk.risk_level ?? '未分级'} size="sm" />
          <span className="text-[11px] text-[var(--text-tertiary)]">{sdk.vendor ?? '厂商未知'} · {sdk.category ?? '未分类'}</span>
          <span className="ml-auto text-[11px] text-[var(--text-tertiary)]">{sdk.evidence.length} 条证据 <ChevronDown size={12} className="inline" /></span>
        </div>
        <p className="text-[11px] font-mono text-[var(--text-tertiary)] mt-1 break-all">{sdk.package}</p>
        <p className="text-[11px] text-[var(--text-secondary)] mt-1">
          {sdk.dynamic_correlated ? '已有动态行为佐证' : '仅静态识别，未据此断言实际采集行为'}
        </p>
      </button>
      {open && (
        <ul className="mt-2 flex flex-col gap-1 text-xs text-[var(--text-secondary)]">
          {sdk.evidence.map((item, index) => (
            <li key={`${item.detector}-${index}`} className="break-all">
              [{item.source_type}] {item.relative_path} · {item.description}
            </li>
          ))}
        </ul>
      )}
    </li>
  )
}
