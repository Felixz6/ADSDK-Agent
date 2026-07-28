import { useMemo, useState } from 'react'
import { ChevronDown, ChevronUp, KeyRound } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatCard } from '@/components/common/StatCard'
import type { AppInfo } from '@/types/api'

export function PermissionSummaryPanel({ appInfo }: { appInfo?: AppInfo | null }) {
  const [expanded, setExpanded] = useState(false)
  const [sensitiveOnly, setSensitiveOnly] = useState(true)
  const declared = appInfo?.declared_permissions ?? appInfo?.permissions ?? []
  const sensitive = appInfo?.sensitive_permissions ?? []
  const highAttention = appInfo?.high_attention_permissions ?? []
  const custom = appInfo?.custom_permissions ?? []
  const component = appInfo?.component_permissions ?? []
  const visible = useMemo(
    () => (sensitiveOnly ? sensitive : declared),
    [declared, sensitive, sensitiveOnly],
  )

  if (!appInfo) return null

  return (
    <GlassCard padding="md" highlight>
      <div className="flex items-center justify-between gap-3 flex-wrap mb-3">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] flex items-center gap-1.5">
          <KeyRound size={15} /> 权限清单
        </h3>
        <button
          type="button"
          onClick={() => setExpanded((value) => !value)}
          className="text-xs text-[var(--accent-blue)] inline-flex items-center gap-1"
        >
          {expanded ? '收起详情' : '展开详情'}
          {expanded ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        </button>
      </div>
      <div className="grid grid-cols-2 sm:grid-cols-3 xl:grid-cols-5 gap-2">
        <StatCard label="申请权限总数" value={declared.length} tone="default" />
        <StatCard label="敏感权限" value={sensitive.length} tone="warning" />
        <StatCard label="高关注权限" value={highAttention.length} tone="danger" />
        <StatCard label="自定义权限" value={custom.length} tone="accent" />
        <StatCard label="组件保护权限" value={component.length} tone="neutral" />
      </div>
      {expanded && (
        <div className="mt-3">
          <div className="flex items-center gap-2 mb-2">
            <button
              type="button"
              onClick={() => setSensitiveOnly(true)}
              className={`text-xs rounded-[8px] px-2.5 py-1.5 border ${sensitiveOnly ? 'border-[var(--warning)] text-[var(--warning)]' : 'border-[var(--border-soft)] text-[var(--text-secondary)]'}`}
            >
              仅敏感权限
            </button>
            <button
              type="button"
              onClick={() => setSensitiveOnly(false)}
              className={`text-xs rounded-[8px] px-2.5 py-1.5 border ${!sensitiveOnly ? 'border-[var(--accent-blue)] text-[var(--accent-blue)]' : 'border-[var(--border-soft)] text-[var(--text-secondary)]'}`}
            >
              全部申请权限
            </button>
          </div>
          {visible.length ? (
            <ul className="grid grid-cols-1 lg:grid-cols-2 gap-1.5">
              {visible.map((permission) => (
                <li
                  key={permission}
                  title={permission}
                  className="text-xs font-mono text-[var(--text-secondary)] break-all rounded-[8px] border border-[var(--border-soft)] px-2.5 py-2"
                >
                  {permission}
                </li>
              ))}
            </ul>
          ) : (
            <p className="text-xs text-[var(--text-tertiary)] py-2">
              当前分类没有权限。
            </p>
          )}
        </div>
      )}
    </GlassCard>
  )
}
