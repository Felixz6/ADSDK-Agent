import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  PlusCircle,
  ListChecks,
  FileSearch,
  Activity,
  Network,
  FileText,
  Cpu,
  Settings,
  ChevronLeft,
  ShieldCheck,
  Home,
} from 'lucide-react'
import { useUIStore } from '@/stores/uiStore'
import { cn } from '@/utils'

interface NavItem {
  to: string
  label: string
  icon: typeof LayoutDashboard
  /** 简要副标题(折叠态不展示) */
  desc?: string
  end?: boolean
}

const NAV_GROUPS: { title: string; items: NavItem[] }[] = [
  {
    title: '总览',
    items: [
      { to: '/', label: '首页', icon: Home, desc: '星空分析控制台', end: true },
      { to: '/dashboard', label: '仪表盘', icon: LayoutDashboard, desc: '历史与统计' },
    ],
  },
  {
    title: '分析',
    items: [
      { to: '/analysis/new', label: '新建分析', icon: PlusCircle, desc: '四步向导' },
      { to: '/tasks', label: '任务列表', icon: ListChecks, desc: '本地历史' },
      { to: '/tasks/:id', label: '任务详情', icon: FileSearch, desc: '流水线时间线' },
    ].map((i) => (i.to === '/tasks/:id' ? { ...i, hidden: true } : i)) as unknown as NavItem[],
  },
  {
    title: '结果',
    items: [
      { to: '/static', label: '静态分析', icon: FileSearch, desc: '清单与 SDK' },
      { to: '/dynamic', label: '动态分析', icon: Activity, desc: '同意前/后时间线' },
      { to: '/traffic', label: '网络外发', icon: Network, desc: '流量观测' },
      { to: '/reports', label: '报告', icon: FileText, desc: '规则判定摘要' },
    ],
  },
  {
    title: '系统',
    items: [
      { to: '/environment', label: '环境检测', icon: Cpu, desc: 'ADB / Frida / mitm' },
      { to: '/settings', label: '设置', icon: Settings, desc: '偏好与关于' },
    ],
  },
]

function NavRow({ item, collapsed }: { item: NavItem; collapsed: boolean }) {
  const Icon = item.icon
  return (
    <NavLink
      to={item.to}
      end={item.end}
      className={({ isActive }) =>
        cn(
          'group flex items-center gap-3 rounded-[12px] px-3 py-2 text-sm transition-colors relative',
          collapsed && 'justify-center px-0',
          isActive
            ? 'bg-[rgba(120,216,255,0.12)] text-[var(--text-primary)] border border-[var(--border-active)]'
            : 'text-[var(--text-secondary)] hover:text-[var(--text-primary)] hover:bg-[rgba(157,192,255,0.08)] border border-transparent',
        )
      }
      title={collapsed ? item.label : undefined}
    >
      <Icon size={18} className="shrink-0 text-[var(--accent-blue)] group-[.active]:text-[var(--accent-blue)]" />
      {!collapsed && (
        <span className="flex flex-col leading-tight">
          <span className="font-medium">{item.label}</span>
          {item.desc && <span className="text-[11px] text-[var(--text-tertiary)]">{item.desc}</span>}
        </span>
      )}
    </NavLink>
  )
}

export function Sidebar() {
  const collapsed = useUIStore((s) => s.sidebarCollapsed)
  const toggle = useUIStore((s) => s.toggleSidebar)

  return (
    <aside
      style={{ width: collapsed ? 'var(--sidebar-w-collapsed)' : 'var(--sidebar-w)' }}
      className={cn(
        'hidden md:flex flex-col shrink-0 h-[100dvh] sticky top-0',
        'glass-strong border-r border-[var(--border-soft)]',
        'transition-[width] duration-200',
      )}
    >
      <div className="flex items-center gap-2.5 px-4 h-[var(--topbar-h)] border-b border-[var(--border-soft)]">
        <div className="w-9 h-9 rounded-[12px] bg-[rgba(120,216,255,0.12)] border border-[var(--border-active)] flex items-center justify-center shrink-0">
          <ShieldCheck size={20} className="text-[var(--accent-blue)]" />
        </div>
        {!collapsed && (
          <div className="flex flex-col leading-tight min-w-0">
            <span className="text-sm font-semibold text-[var(--text-primary)] truncate">AdSDK Agent</span>
            <span className="text-[11px] text-[var(--text-tertiary)] truncate">安全合规分析控制台</span>
          </div>
        )}
        <button
          type="button"
          onClick={toggle}
          aria-label={collapsed ? '展开侧边栏' : '收起侧边栏'}
          className={cn(
            'ml-auto w-7 h-7 rounded-lg flex items-center justify-center',
            'text-[var(--text-tertiary)] hover:text-[var(--text-primary)] hover:bg-[rgba(157,192,255,0.08)]',
            collapsed && 'mx-auto ml-0',
          )}
          aria-expanded={!collapsed}
        >
          <ChevronLeft size={16} className={cn('transition-transform', collapsed && 'rotate-180')} />
        </button>
      </div>

      <nav className="flex-1 overflow-y-auto px-2 py-3 flex flex-col gap-4" aria-label="主导航">
        {NAV_GROUPS.map((group) => (
          <div key={group.title} className="flex flex-col gap-1">
            {!collapsed && (
              <p className="px-3 text-[11px] uppercase tracking-wider text-[var(--text-tertiary)] mb-0.5">
                {group.title}
              </p>
            )}
            {group.items
              .filter((i) => !(i as { hidden?: boolean }).hidden)
              .map((item) => (
                <NavRow key={item.to} item={item} collapsed={collapsed} />
              ))}
          </div>
        ))}
      </nav>

      <div className="px-3 py-3 border-t border-[var(--border-soft)]">
        <a
          href="https://127.0.0.1:8000/"
          target="_blank"
          rel="noreferrer"
          className={cn(
            'flex items-center gap-2 text-xs text-[var(--text-tertiary)] hover:text-[var(--text-secondary)] transition-colors',
            collapsed && 'justify-center',
          )}
        >
          <span className="w-1.5 h-1.5 rounded-full bg-[var(--success)] animate-pulse" aria-hidden />
          {!collapsed && <span>后端 127.0.0.1:8000</span>}
        </a>
      </div>
    </aside>
  )
}

/** 移动端抽屉式导航 */
export function MobileSidebar() {
  const open = useUIStore((s) => s.mobileDrawerOpen)
  const setOpen = useUIStore((s) => s.setMobileDrawerOpen)
  if (!open) return null
  return (
    <div className="md:hidden fixed inset-0 z-[100]" role="dialog" aria-modal="true" aria-label="导航">
      <div className="absolute inset-0 bg-[rgba(3,8,22,0.6)] backdrop-blur-sm" onClick={() => setOpen(false)} />
      <aside className="absolute left-0 top-0 h-full w-[280px] max-w-[86vw] glass-strong border-r border-[var(--border-soft)] flex flex-col">
        <div className="flex items-center gap-2.5 px-4 h-[var(--topbar-h)] border-b border-[var(--border-soft)]">
          <div className="w-9 h-9 rounded-[12px] bg-[rgba(120,216,255,0.12)] border border-[var(--border-active)] flex items-center justify-center">
            <ShieldCheck size={20} className="text-[var(--accent-blue)]" />
          </div>
          <div className="flex flex-col leading-tight">
            <span className="text-sm font-semibold text-[var(--text-primary)]">AdSDK Agent</span>
            <span className="text-[11px] text-[var(--text-tertiary)]">安全合规分析控制台</span>
          </div>
        </div>
        <nav className="flex-1 overflow-y-auto px-2 py-3 flex flex-col gap-4" onClick={() => setOpen(false)}>
          {NAV_GROUPS.map((group) => (
            <div key={group.title} className="flex flex-col gap-1">
              <p className="px-3 text-[11px] uppercase tracking-wider text-[var(--text-tertiary)] mb-0.5">
                {group.title}
              </p>
              {group.items
                .filter((i) => !(i as { hidden?: boolean }).hidden)
                .map((item) => (
                  <NavRow key={item.to} item={item} collapsed={false} />
                ))}
            </div>
          ))}
        </nav>
      </aside>
    </div>
  )
}
