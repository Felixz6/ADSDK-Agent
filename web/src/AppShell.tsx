import { type ReactNode, useEffect } from 'react'
import { Sidebar, MobileSidebar } from '@/components/layout/Sidebar'
import { Topbar } from '@/components/layout/Topbar'
import { ToastViewport } from '@/components/common/Toast'
import { useUIStore, applyTheme } from '@/stores/uiStore'

export interface AppShellProps {
  children: ReactNode
}

/** 全局应用骨架:背景 + 侧栏 + 顶栏 + 内容区 + Toast */
export function AppShell({ children }: AppShellProps) {
  const theme = useUIStore((s) => s.theme)

  useEffect(() => {
    applyTheme(theme)
  }, [theme])

  return (
    <div className="relative min-h-[100dvh]">
      <div className="app-background" aria-hidden />
      <div className="app-overlay-top fixed top-0 inset-x-0 h-[140px] z-30 pointer-events-none" aria-hidden />

      <div className="relative z-10 flex">
        <Sidebar />

        <div className="flex-1 min-w-0 flex flex-col">
          <Topbar />
          <main
            className="flex-1 min-w-0 px-4 sm:px-6 py-5 max-w-[1400px] w-full mx-auto"
            tabIndex={-1}
          >
            {children}
          </main>
          <footer className="px-6 py-4 text-[11px] text-[var(--text-tertiary)] text-center">
            AdSDK Agent · 安卓广告 SDK 合规取证控制台 · 原始敏感标识一律脱敏展示
          </footer>
        </div>
      </div>

      <MobileSidebar />
      <ToastViewport />
    </div>
  )
}

export default AppShell
