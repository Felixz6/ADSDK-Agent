/**
 * UI 状态 store:侧边栏折叠、主题、Toast 队列
 * 使用 Zustand(store + persist 仅持久化偏好)。
 */
import { create } from 'zustand'
import { persist } from 'zustand/middleware'

export type Theme = 'dark' | 'light'

export interface ToastItem {
  id: string
  kind: 'success' | 'error' | 'info' | 'warning'
  message: string
  /** 自动消失时长,0 表示不自动关闭 */
  duration: number
}

interface UIState {
  /** 侧边栏折叠(桌面) */
  sidebarCollapsed: boolean
  toggleSidebar: () => void
  setSidebarCollapsed: (v: boolean) => void
  /** 移动端抽屉打开 */
  mobileDrawerOpen: boolean
  setMobileDrawerOpen: (v: boolean) => void

  /** 主题 */
  theme: Theme
  setTheme: (t: Theme) => void
  toggleTheme: () => void

  /** Toast 队列 */
  toasts: ToastItem[]
  pushToast: (t: Omit<ToastItem, 'id'>) => string
  dismissToast: (id: string) => void
}

let toastSeq = 0
function nextToastId(): string {
  toastSeq += 1
  return `t${Date.now().toString(36)}-${toastSeq}`
}

export const useUIStore = create<UIState>()(
  persist(
    (set, get) => ({
      sidebarCollapsed: false,
      toggleSidebar: () => set((s) => ({ sidebarCollapsed: !s.sidebarCollapsed })),
      setSidebarCollapsed: (v) => set({ sidebarCollapsed: v }),
      mobileDrawerOpen: false,
      setMobileDrawerOpen: (v) => set({ mobileDrawerOpen: v }),

      theme: 'dark',
      setTheme: (t) => set({ theme: t }),
      toggleTheme: () => set((s) => ({ theme: s.theme === 'dark' ? 'light' : 'dark' })),

      toasts: [],
      pushToast: (t) => {
        const id = nextToastId()
        set((s) => ({ toasts: [...s.toasts, { ...t, id }] }))
        if (t.duration > 0) {
          setTimeout(() => get().dismissToast(id), t.duration)
        }
        return id
      },
      dismissToast: (id) => set((s) => ({ toasts: s.toasts.filter((x) => x.id !== id) })),
    }),
    {
      name: 'adsdk-agent:ui',
      // 仅持久化偏好,Toast/抽屉态不持久化
      partialize: (s) => ({ sidebarCollapsed: s.sidebarCollapsed, theme: s.theme }),
    },
  ),
)

/** 应用主题到 <html data-theme> */
export function applyTheme(theme: Theme): void {
  const root = document.documentElement
  if (theme === 'light') root.setAttribute('data-theme', 'light')
  else root.removeAttribute('data-theme')
}
