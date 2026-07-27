import { useLocation } from 'react-router-dom'
import { Menu, Sun, Moon, SatelliteDish } from 'lucide-react'
import { useUIStore } from '@/stores/uiStore'
import { useServiceHealth } from '@/hooks/useApi'
import { cn } from '@/utils'

function formatTimestamp(ms: number | undefined): string {
  if (!ms || Number.isNaN(ms)) return '—'
  const d = new Date(ms)
  if (Number.isNaN(d.getTime())) return '—'
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}

const TITLE_MAP: Record<string, { title: string; sub: string }> = {
  '/': { title: '首页', sub: '星空中的二次元安全分析控制台' },
  '/dashboard': { title: '仪表盘', sub: '历史任务与分析统计' },
  '/analysis/new': { title: '新建分析', sub: '四步提交向导' },
  '/tasks': { title: '任务列表', sub: '本地历史记录' },
  '/static': { title: '静态分析', sub: 'AndroidManifest 与 SDK 识别' },
  '/dynamic': { title: '动态分析', sub: '同意前 / 同意后事件时间线' },
  '/traffic': { title: '网络外发', sub: '流量观测摘要' },
  '/reports': { title: '报告', sub: '规则判定与结论' },
  '/environment': { title: '环境检测', sub: 'ADB / Frida / mitmproxy' },
  '/settings': { title: '设置', sub: '偏好与关于' },
}

function resolveTitle(pathname: string): { title: string; sub: string } {
  if (TITLE_MAP[pathname]) return TITLE_MAP[pathname]
  if (pathname.startsWith('/tasks/')) return { title: '任务详情', sub: '流水线时间线与结果' }
  return { title: 'AdSDK Agent', sub: '' }
}

export function Topbar() {
  const { pathname } = useLocation()
  const setMobileOpen = useUIStore((s) => s.setMobileDrawerOpen)
  const theme = useUIStore((s) => s.theme)
  const toggleTheme = useUIStore((s) => s.toggleTheme)
  const health = useServiceHealth()
  const { title, sub } = resolveTitle(pathname)

  const reachable = Boolean(health.data?.ok)
  const stale = (health.data && health.data.ok ? 1 : 0) as number

  return (
    <header
      className={cn(
        'sticky top-0 z-40 h-[var(--topbar-h)] flex items-center gap-3 px-4',
        'glass border-b border-[var(--border-soft)]',
      )}
    >
      <button
        type="button"
        className="md:hidden w-9 h-9 rounded-lg flex items-center justify-center text-[var(--text-secondary)] hover:bg-[rgba(157,192,255,0.08)]"
        onClick={() => setMobileOpen(true)}
        aria-label="打开导航"
      >
        <Menu size={20} />
      </button>

      <div className="min-w-0 flex-1">
        <p className="text-sm font-semibold text-[var(--text-primary)] truncate leading-tight">{title}</p>
        {sub && <p className="text-[11px] text-[var(--text-tertiary)] truncate leading-tight">{sub}</p>}
      </div>

      <div className="flex items-center gap-2">
        <div
          className="hidden sm:flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-full border"
          role="status"
          aria-label="后端连接状态"
          data-stale={stale}
          style={{
            borderColor: reachable ? 'rgba(121,224,195,0.42)' : 'rgba(242,139,155,0.42)',
            color: reachable ? 'var(--success)' : 'var(--danger)',
            background: reachable ? 'rgba(121,224,195,0.12)' : 'rgba(242,139,155,0.12)',
          }}
          title={reachable ? `后端在线 · ${formatTimestamp(health.dataUpdatedAt)}` : '后端未连接'}
        >
          <span
            className="w-1.5 h-1.5 rounded-full"
            style={{ background: reachable ? 'var(--success)' : 'var(--danger)' }}
            aria-hidden
          />
          {reachable ? '后端在线' : '后端离线'}
        </div>

        <button
          type="button"
          onClick={toggleTheme}
          aria-label={theme === 'dark' ? '切换到浅色主题' : '切换到深色主题'}
          title={theme === 'dark' ? '浅色主题' : '深色主题'}
          className="w-9 h-9 rounded-lg flex items-center justify-center text-[var(--text-secondary)] hover:bg-[rgba(157,192,255,0.08)]"
        >
          {theme === 'dark' ? <Sun size={18} /> : <Moon size={18} />}
        </button>

        <div className="w-9 h-9 rounded-lg flex items-center justify-center text-[var(--accent-blue)] border border-[var(--border-soft)] bg-[rgba(120,216,255,0.08)]">
          <SatelliteDish size={18} />
        </div>
      </div>
    </header>
  )
}

export default Topbar
