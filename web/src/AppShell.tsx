import { type ReactNode, useEffect } from 'react'
import { useLocation } from 'react-router-dom'
import { SiteNav } from '@/components/layout/SiteNav'
import { SiteFooter } from '@/components/layout/SiteFooter'
import { ToastViewport } from '@/components/common/Toast'
import { useUIStore, applyTheme } from '@/stores/uiStore'

export interface AppShellProps {
  children: ReactNode
}

export function AppShell({ children }: AppShellProps) {
  const theme = useUIStore((s) => s.theme)
  const { pathname } = useLocation()

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  return (
    <div className="site">
      <a className="skip" href="#main">
        跳到主要内容
      </a>
      <SiteNav />
      <main id="main" tabIndex={-1} className={pathname === '/' ? 'site-home' : 'site-page'}>
        {children}
      </main>
      <SiteFooter />
      <ToastViewport />
    </div>
  )
}

export default AppShell
