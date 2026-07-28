import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ListChecks, Trash2, Search, Filter, AlertTriangle } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { EmptyState } from '@/components/common/States'
import { StatusBadge } from '@/components/common/StatusBadge'
import { RiskBadge } from '@/components/common/RiskBadge'
import { ConfirmDialog } from '@/components/common/ConfirmDialog'
import { cn } from '@/utils'
import { listLocalTasks, clearLocalTasks, deleteLocalTask, type LocalTaskRecord } from '@/api/tasks'
import { useUIStore } from '@/stores/uiStore'
import { formatDateTime } from '@/utils'

type KindFilter = 'all' | 'static' | 'dynamic'
type StatusFilter = 'all' | 'success' | 'partial' | 'failed'

export default function Tasks() {
  const navigate = useNavigate()
  const pushToast = useUIStore((s) => s.pushToast)
  const [, force] = useState(0)
  const [search, setSearch] = useState('')
  const [kindFilter, setKindFilter] = useState<KindFilter>('all')
  const [statusFilter, setStatusFilter] = useState<StatusFilter>('all')
  const [confirmClear, setConfirmClear] = useState(false)

  const all = listLocalTasks()

  const filtered = useMemo(() => {
    const q = search.trim().toLowerCase()
    return all.filter((t) => {
      if (kindFilter !== 'all' && t.kind !== kindFilter) return false
      if (statusFilter !== 'all' && t.status !== statusFilter) return false
      if (q) {
        const hay = `${t.package_name} ${t.apk_path} ${t.local_id} ${t.run_id ?? ''}`.toLowerCase()
        if (!hay.includes(q)) return false
      }
      return true
    })
  }, [all, search, kindFilter, statusFilter])

  function refresh() {
    force((n) => n + 1)
  }

  function handleDelete(t: LocalTaskRecord) {
    deleteLocalTask(t.local_id)
    pushToast({ kind: 'success', message: '已删除该任务记录。', duration: 2500 })
    refresh()
  }

  function handleClearAll() {
    clearLocalTasks()
    setConfirmClear(false)
    pushToast({ kind: 'success', message: '已清空全部本地任务记录。', duration: 2500 })
    refresh()
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="任务"
        description="本地分析任务记录(浏览器持久化)。后端不提供任务列表端点,记录仅存于本设备。"
        eyebrow="历史"
        actions={
          all.length > 0 ? (
            <button
              type="button"
              onClick={() => setConfirmClear(true)}
              className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-[10px] text-xs border border-[var(--border-soft)] text-[var(--danger)] hover:bg-[rgba(255,107,138,0.08)]"
            >
              <Trash2 size={14} /> 清空全部
            </button>
          ) : undefined
        }
      />

      <div
        role="note"
        aria-live="polite"
        className="glass rounded-[12px] border border-[rgba(245,166,35,0.45)] bg-[rgba(245,166,35,0.08)] px-4 py-3 flex items-start gap-2.5"
      >
        <AlertTriangle size={18} className="text-[var(--warning)] shrink-0 mt-0.5" aria-hidden="true" />
        <div className="text-[13px] leading-relaxed text-[var(--text-secondary)]">
          <strong className="text-[var(--text-primary)]">当前记录保存在本浏览器中,不代表后端持久化任务。</strong>
          清理浏览器数据后,这些记录将丢失。后端当前为同步接口,不提供任务列表 / 状态 / 进度查询端点,
          因此页面仅展示真实分析返回支撑的状态(成功 / 部分 / 失败),不会出现伪造的「排队中 / 运行中 / 已取消」状态。
        </div>
      </div>

      <div className="flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between">
        <label className="flex items-center gap-2 glass rounded-[10px] px-3 py-1.5 w-full sm:w-72 focus-within:border-[var(--border-active)]">
          <span className="sr-only">搜索</span>
          <Search size={16} className="text-[var(--text-tertiary)] shrink-0" />
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="按包名 / 路径 / 任务 ID 搜索"
            className="bg-transparent outline-none text-sm text-[var(--text-primary)] w-full placeholder:text-[var(--text-tertiary)]"
          />
        </label>
        <div className="flex items-center gap-2 flex-wrap">
          <FilterSelect label="类型" value={kindFilter} onChange={(v) => setKindFilter(v as KindFilter)} options={[{ label: '全部', value: 'all' }, { label: '静态', value: 'static' }, { label: '动态', value: 'dynamic' }]} />
          <FilterSelect label="状态" value={statusFilter} onChange={(v) => setStatusFilter(v as StatusFilter)} options={[{ label: '全部', value: 'all' }, { label: '成功', value: 'success' }, { label: '部分', value: 'partial' }, { label: '失败', value: 'failed' }]} />
        </div>
      </div>

      {all.length === 0 ? (
        <EmptyState
          icon={<ListChecks size={28} />}
          title="尚无任务记录"
          description="完成一次分析后,任务会出现在这里以便回看。"
        />
      ) : filtered.length === 0 ? (
        <EmptyState
          icon={<Filter size={26} />}
          title="无匹配任务"
          description="当前筛选条件下没有记录,试着放宽搜索或筛选。"
        />
      ) : (
        <GlassCard padding="md" highlight>
          <ul className="flex flex-col gap-1.5">
            {filtered.map((t) => (
              <li key={t.local_id} className="rounded-[10px] border border-[var(--border-soft)] px-3 py-2.5 hover:border-[var(--border-active)] transition-colors flex items-center gap-3">
                <button
                  type="button"
                  onClick={() => navigate(`/tasks/${t.local_id}`)}
                  className="flex items-center gap-3 flex-1 min-w-0 text-left"
                >
                  <StatusBadge
                    tone={t.status === 'success' ? 'success' : t.status === 'failed' ? 'danger' : t.status === 'partial' ? 'warning' : 'neutral'}
                    label={t.kind === 'static' ? '静态' : '动态'}
                    size="sm"
                  />
                  {t.risk_level && (
                    <RiskBadge level={t.risk_level === 'critical' ? 'high' : t.risk_level} label={t.risk_level} />
                  )}
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-[var(--text-primary)] font-mono truncate">{t.package_name || t.apk_path}</p>
                    <p className="text-[11px] text-[var(--text-tertiary)] truncate">
                      {t.local_id} · {formatDateTime(t.created_at)}
                    </p>
                  </div>
                  <div className="hidden sm:flex items-center gap-3 text-[11px] text-[var(--text-tertiary)] shrink-0">
                    <span>命中 <b className="text-[var(--danger)]">{t.summary?.matched ?? 0}</b></span>
                    <span>未命中 <b className="text-[var(--success)]">{t.summary?.not_matched ?? 0}</b></span>
                    <span>未评估 <b className="text-[var(--status-neutral)]">{t.summary?.not_evaluated ?? 0}</b></span>
                  </div>
                </button>
                <button
                  type="button"
                  onClick={() => handleDelete(t)}
                  aria-label="删除任务"
                  className="shrink-0 text-[var(--text-tertiary)] hover:text-[var(--danger)] p-1 rounded-md"
                >
                  <Trash2 size={15} />
                </button>
              </li>
            ))}
          </ul>
          <p className="text-[11px] text-[var(--text-tertiary)] mt-3">共 {filtered.length} 条 / 全部 {all.length} 条。</p>
        </GlassCard>
      )}

      <ConfirmDialog
        open={confirmClear}
        title="清空全部任务记录?"
        description="此操作将删除本设备上保存的所有本地任务记录,无法恢复。"
        confirmLabel="清空"
        tone="danger"
        onConfirm={handleClearAll}
        onCancel={() => setConfirmClear(false)}
      />
    </div>
  )
}

function FilterSelect({
  label,
  value,
  onChange,
  options,
}: {
  label: string
  value: string
  onChange: (v: string) => void
  options: { label: string; value: string }[]
}) {
  return (
    <label className="inline-flex items-center gap-1.5 glass rounded-[10px] px-2.5 py-1.5">
      <span className="sr-only">{label}</span>
      <Filter size={14} className="text-[var(--text-tertiary)]" />
      <select
        value={value}
        onChange={(e) => onChange(e.target.value)}
        aria-label={label}
        className={cn('bg-transparent outline-none text-sm text-[var(--text-primary)] cursor-pointer')}
      >
        {options.map((o) => (
          <option key={o.value} value={o.value} className="bg-[#0d1430] text-[var(--text-primary)]">
            {o.label}
          </option>
        ))}
      </select>
    </label>
  )
}
