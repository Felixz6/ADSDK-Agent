import { useState, type ReactNode } from 'react'
import {
  Sun,
  Moon,
  PanelLeftClose,
  PanelLeftOpen,
  Trash2,
  Server,
  Info,
  Github,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { ConfirmDialog } from '@/components/common/ConfirmDialog'
import { StatusBadge } from '@/components/common/StatusBadge'
import { useUIStore, applyTheme, type Theme } from '@/stores/uiStore'
import { useAnalysisStore } from '@/stores/analysisStore'
import { useServiceHealth } from '@/hooks/useApi'
import { clearLocalTasks, listLocalTasks } from '@/api/tasks'
import { API_BASE_URL } from '@/api/client'
import { cn } from '@/utils'

export default function Settings() {
  const theme = useUIStore((s) => s.theme)
  const setTheme = useUIStore((s) => s.setTheme)
  const toggleSidebar = useUIStore((s) => s.toggleSidebar)
  const sidebarCollapsed = useUIStore((s) => s.sidebarCollapsed)
  const clearActive = useAnalysisStore((s) => s.clear)
  const pushToast = useUIStore((s) => s.pushToast)
  const health = useServiceHealth()
  const [confirmClearTasks, setConfirmClearTasks] = useState(false)
  const [, force] = useState(0)

  const taskCount = listLocalTasks().length

  function changeTheme(t: Theme) {
    setTheme(t)
    applyTheme(t)
    pushToast({ kind: 'success', message: t === 'dark' ? '已切换至深空主题。' : '已切换至亮色主题。', duration: 2000 })
  }

  function handleClearTasks() {
    clearLocalTasks()
    setConfirmClearTasks(false)
    pushToast({ kind: 'success', message: '已清空全部本地任务记录。', duration: 2500 })
    force((n) => n + 1)
  }

  function handleClearActive() {
    clearActive()
    pushToast({ kind: 'success', message: '已清除内存中活跃分析结果。', duration: 2000 })
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="设置"
        description="前端偏好与本地数据管理。后端连接地址由环境变量 VITE_API_BASE_URL 配置。"
        eyebrow="偏好"
      />

      <GlassCard padding="md" highlight>
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-1.5">
          <Sun size={15} /> 主题
        </h3>
        <div className="flex items-center gap-2">
          <ThemeOption current={theme} value="dark" label="深空" icon={<Moon size={16} />} onSelect={changeTheme} />
          <ThemeOption current={theme} value="light" label="亮色" icon={<Sun size={16} />} onSelect={changeTheme} />
        </div>
        <p className="text-[11px] text-[var(--text-tertiary)] mt-2">推荐使用深空主题以呈现「星空控制台」视觉效果。</p>
      </GlassCard>

      <GlassCard padding="md" highlight>
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-1.5">
          <PanelLeftClose size={15} /> 侧边栏
        </h3>
        <button
          type="button"
          onClick={toggleSidebar}
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm border border-[var(--border-soft)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]"
        >
          {sidebarCollapsed ? <PanelLeftOpen size={15} /> : <PanelLeftClose size={15} />}
          {sidebarCollapsed ? '展开侧边栏' : '折叠侧边栏'}
        </button>
        <p className="text-[11px] text-[var(--text-tertiary)] mt-2">也可使用快捷键 Ctrl/⌘ + B 切换。</p>
      </GlassCard>

      <GlassCard padding="md" highlight>
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-1.5">
          <Server size={15} /> 后端连接
        </h3>
        <dl className="flex flex-col gap-1 mb-3">
          <KV k="API 根地址" v={API_BASE_URL} mono />
          <KV k="在线状态" v={' '} />
        </dl>
        <div className="mb-2">
          <StatusBadge
            tone={health.data?.ok ? 'success' : health.isError ? 'danger' : 'neutral'}
            label={health.data?.ok ? '在线' : health.isError ? '不可达' : '检测中'}
          />
        </div>
        <p className="text-[11px] text-[var(--text-tertiary)]">
          修改地址需在项目根目录的 .env 文件设置 VITE_API_BASE_URL 后重启开发服务器,前端不做运行时改写。
        </p>
      </GlassCard>

      <GlassCard padding="md" highlight>
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-1.5">
          <Trash2 size={15} /> 本地数据管理
        </h3>
        <div className="flex flex-col gap-2">
          <button
            type="button"
            onClick={handleClearActive}
            className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm border border-[var(--border-soft)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] w-fit"
          >
            清除内存中活跃分析结果
          </button>
          <button
            type="button"
            onClick={() => setConfirmClearTasks(true)}
            disabled={taskCount === 0}
            className={cn(
              'inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm border w-fit',
              taskCount === 0 ? 'opacity-50 cursor-not-allowed border-[var(--border-soft)] text-[var(--text-tertiary)]' : 'border-[var(--border-soft)] text-[var(--danger)] hover:bg-[rgba(255,107,138,0.08)]',
            )}
          >
            <Trash2 size={14} /> 清空全部本地任务记录({taskCount})
          </button>
        </div>
        <p className="text-[11px] text-[var(--text-tertiary)] mt-2">本地任务记录仅保存在浏览器,不与后端同步,删除不影响后端产物文件。</p>
      </GlassCard>

      <GlassCard padding="md">
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-2 flex items-center gap-1.5">
          <Info size={15} /> 关于
        </h3>
        <p className="text-xs text-[var(--text-secondary)] leading-relaxed">
          AdSDK Agent Web —— 星空中的二次元安全分析控制台。前端采用 React 18 + TypeScript + Vite + Tailwind,
          与本地 FastAPI Agent 后端对接,提供静态/动态分析与隐私合规取证可视化。
          所有敏感标识(设备标识、Cookie、鉴权令牌、原始 URL)一律脱敏或不予展示。
        </p>
        <div className="mt-3 inline-flex items-center gap-1.5 text-[11px] text-[var(--text-tertiary)]">
          <Github size={13} /> 版本 1.0.0 · schema 1.0
        </div>
      </GlassCard>

      <ConfirmDialog
        open={confirmClearTasks}
        title="清空全部任务记录?"
        description="此操作将删除本设备上保存的所有本地任务记录,无法恢复。"
        confirmLabel="清空"
        tone="danger"
        onConfirm={handleClearTasks}
        onCancel={() => setConfirmClearTasks(false)}
      />
    </div>
  )
}

function ThemeOption({
  current,
  value,
  label,
  icon,
  onSelect,
}: {
  current: Theme
  value: Theme
  label: string
  icon: ReactNode
  onSelect: (v: Theme) => void
}) {
  const active = current === value
  return (
    <button
      type="button"
      onClick={() => onSelect(value)}
      className={cn(
        'inline-flex items-center gap-2 px-3.5 py-2 rounded-[12px] text-sm border transition-colors',
        active ? 'glass-strong border-[var(--border-active)] text-[var(--text-primary)]' : 'border-[var(--border-soft)] text-[var(--text-tertiary)] hover:text-[var(--text-secondary)]',
      )}
    >
      {icon}{label}
    </button>
  )
}

function KV({ k, v, mono }: { k: string; v: string; mono?: boolean }) {
  return (
    <div className="flex items-start justify-between gap-3 py-1 border-b border-[var(--border-soft)]/40">
      <dt className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide shrink-0 pt-0.5">{k}</dt>
      <dd className={cn('text-sm text-[var(--text-primary)] text-right break-all', mono && 'font-mono text-[13px]')}>{v}</dd>
    </div>
  )
}
