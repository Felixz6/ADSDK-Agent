import { useEffect, useId, useState } from 'react'
import { NavLink, useLocation, useNavigate } from 'react-router-dom'
import { Sun, Moon, ShieldCheck, Plus, Menu, X } from 'lucide-react'
import { AnimatePresence, motion } from 'framer-motion'
import { useServiceHealth } from '@/hooks/useApi'
import { useUIStore } from '@/stores/uiStore'

const PRIMARY = [
  { to: '/', label: '产品', end: true },
  { to: '/dashboard', label: '概览' },
  { to: '/tasks', label: '任务' },
  { to: '/reports', label: '报告' },
  { to: '/environment', label: '环境' },
]

const DIRECTORY = [
  { to: '/', label: '产品', end: true },
  { to: '/dashboard', label: '概览' },
  { to: '/analysis/new', label: '新建分析' },
  { to: '/tasks', label: '任务' },
  { to: '/comparisons', label: '版本对比' },
  { to: '/static', label: '静态分析' },
  { to: '/dynamic', label: '动态分析' },
  { to: '/traffic', label: '流量' },
  { to: '/reports', label: '报告' },
  { to: '/environment', label: '环境' },
  { to: '/settings', label: '设置' },
]

const SUBNAV = DIRECTORY.filter((item) => item.to !== '/')

export function SiteNav() {
  const navigate = useNavigate()
  const { pathname } = useLocation()
  const health = useServiceHealth()
  const theme = useUIStore((s) => s.theme)
  const toggleTheme = useUIStore((s) => s.toggleTheme)
  const menuId = useId()
  const [open, setOpen] = useState(false)
  const [scrolled, setScrolled] = useState(false)
  const [hoveredPrimary, setHoveredPrimary] = useState<string | null>(null)
  const [hoveredSubnav, setHoveredSubnav] = useState<string | null>(null)
  const [newBtnHovered, setNewBtnHovered] = useState(false)

  const home = pathname === '/'
  const reachable = Boolean(health.data?.ok)

  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 4)
    onScroll()
    window.addEventListener('scroll', onScroll, { passive: true })
    return () => window.removeEventListener('scroll', onScroll)
  }, [])

  useEffect(() => {
    setOpen(false)
  }, [pathname])

  useEffect(() => {
    if (!open) return
    const previous = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    const onKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') setOpen(false)
    }
    window.addEventListener('keydown', onKey)
    return () => {
      document.body.style.overflow = previous
      window.removeEventListener('keydown', onKey)
    }
  }, [open])

  const isPrimaryActive = (item: (typeof PRIMARY)[number]) => {
    if (item.end) return pathname === item.to
    return pathname === item.to || pathname.startsWith(`${item.to}/`)
  }

  const isSubnavActive = (to: string) => {
    if (to === '/analysis/new') return pathname === '/analysis/new'
    return pathname === to || pathname.startsWith(`${to}/`)
  }

  return (
    <>
      <header className="site-nav" data-scrolled={scrolled ? 'true' : 'false'} data-subnav={home ? undefined : 'true'}>
        <div className="site-nav-row">
          <NavLink to="/" className="wordmark" end aria-label="AdSDK Agent 首页">
            <div className="brand-icon">
              <ShieldCheck size={20} strokeWidth={2.2} />
            </div>
            <div className="brand-text">
              <span className="brand-title">AdSDK Agent</span>
              <span className="brand-tag">合规审计</span>
            </div>
          </NavLink>

          <nav
            className="nav-links"
            aria-label="主要"
            onMouseLeave={() => setHoveredPrimary(null)}
          >
            {PRIMARY.map((item) => {
              const isActive = isPrimaryActive(item)
              const isHovered = hoveredPrimary === item.to

              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  end={item.end}
                  className="nav-link"
                  onMouseEnter={() => setHoveredPrimary(item.to)}
                  onFocus={() => setHoveredPrimary(item.to)}
                >
                  {/* 鼠标悬停半透明浮动胶囊 */}
                  <AnimatePresence>
                    {isHovered && !isActive && (
                      <motion.span
                        layoutId="nav-hover-pill"
                        className="nav-hover-pill"
                        initial={{ opacity: 0, scale: 0.92 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.92 }}
                        transition={{
                          type: 'spring',
                          stiffness: 450,
                          damping: 32,
                        }}
                      />
                    )}
                  </AnimatePresence>

                  {/* 切换页面时的平滑流动滑块 */}
                  {isActive && (
                    <motion.span
                      layoutId="site-nav-active-pill"
                      className="nav-active-pill"
                      transition={{
                        type: 'spring',
                        stiffness: 420,
                        damping: 32,
                      }}
                    />
                  )}

                  <span className="nav-link-label">{item.label}</span>
                </NavLink>
              )
            })}
          </nav>

          <div className="nav-tools">
            <span
              className="nav-status"
              data-ok={health.isPending ? undefined : reachable ? 'true' : 'false'}
              role="status"
              title={reachable ? '后端服务在线 (127.0.0.1:8000)' : '后端服务未连接'}
            >
              <i aria-hidden className="status-dot" />
              <span className="status-text">{health.isPending ? '检测中' : reachable ? '在线' : '离线'}</span>
            </span>

            <button
              type="button"
              onClick={toggleTheme}
              className="theme-toggle"
              aria-label={theme === 'dark' ? '切换到浅色主题' : '切换到深色主题'}
              title={theme === 'dark' ? '浅色主题' : '深色主题'}
            >
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={theme}
                  initial={{ rotate: -80, scale: 0.5, opacity: 0 }}
                  animate={{ rotate: 0, scale: 1, opacity: 1 }}
                  exit={{ rotate: 80, scale: 0.5, opacity: 0 }}
                  transition={{ duration: 0.22, ease: [0.23, 1, 0.32, 1] }}
                  className="inline-flex items-center justify-center"
                >
                  {theme === 'dark' ? <Sun size={18} strokeWidth={2.2} /> : <Moon size={18} strokeWidth={2.2} />}
                </motion.span>
              </AnimatePresence>
            </button>

            <button
              type="button"
              className="pill pill-primary nav-cta-button"
              onClick={() => navigate('/analysis/new')}
              onMouseEnter={() => setNewBtnHovered(true)}
              onMouseLeave={() => setNewBtnHovered(false)}
            >
              <motion.span
                className="inline-flex items-center justify-center"
                animate={{
                  rotate: newBtnHovered ? 90 : 0,
                  scale: newBtnHovered ? 1.15 : 1,
                }}
                transition={{
                  type: 'spring',
                  stiffness: 400,
                  damping: 22,
                }}
              >
                <Plus size={16} strokeWidth={2.4} />
              </motion.span>
              <span>新建分析</span>
            </button>

            <button
              type="button"
              className="menu-button"
              aria-expanded={open}
              aria-controls={menuId}
              aria-label={open ? '关闭目录' : '打开目录'}
              onClick={() => setOpen((value) => !value)}
            >
              <AnimatePresence mode="wait" initial={false}>
                <motion.span
                  key={open ? 'close' : 'open'}
                  initial={{ rotate: -60, scale: 0.6, opacity: 0 }}
                  animate={{ rotate: 0, scale: 1, opacity: 1 }}
                  exit={{ rotate: 60, scale: 0.6, opacity: 0 }}
                  transition={{ duration: 0.18, ease: [0.23, 1, 0.32, 1] }}
                  className="inline-flex items-center justify-center"
                >
                  {open ? <X size={20} /> : <Menu size={20} />}
                </motion.span>
              </AnimatePresence>
            </button>
          </div>
        </div>

        {!home && (
          <nav
            className="site-subnav-row"
            aria-label="工作区"
            onMouseLeave={() => setHoveredSubnav(null)}
          >
            {SUBNAV.map((item) => {
              const isSubActive = isSubnavActive(item.to)
              const isSubHovered = hoveredSubnav === item.to

              return (
                <NavLink
                  key={item.to}
                  to={item.to}
                  className="subnav-link"
                  onMouseEnter={() => setHoveredSubnav(item.to)}
                  onFocus={() => setHoveredSubnav(item.to)}
                >
                  <AnimatePresence>
                    {isSubHovered && !isSubActive && (
                      <motion.span
                        layoutId="subnav-hover-pill"
                        className="subnav-hover-pill"
                        initial={{ opacity: 0, scale: 0.94 }}
                        animate={{ opacity: 1, scale: 1 }}
                        exit={{ opacity: 0, scale: 0.94 }}
                        transition={{
                          type: 'spring',
                          stiffness: 450,
                          damping: 32,
                        }}
                      />
                    )}
                  </AnimatePresence>

                  {isSubActive && (
                    <motion.span
                      layoutId="site-subnav-active-pill"
                      className="subnav-active-pill"
                      transition={{
                        type: 'spring',
                        stiffness: 420,
                        damping: 32,
                      }}
                    />
                  )}

                  <span className="subnav-link-label">{item.label}</span>
                </NavLink>
              )
            })}
          </nav>
        )}
      </header>

      <div id={menuId} className="directory" data-open={open ? 'true' : 'false'} hidden={!open}>
        <nav aria-label="全部页面">
          {DIRECTORY.map((item) => (
            <NavLink key={item.to} to={item.to} end={item.end} onClick={() => setOpen(false)}>
              {item.label}
            </NavLink>
          ))}
        </nav>
      </div>
    </>
  )
}

export default SiteNav
