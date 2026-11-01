import { describe, it, expect, beforeEach } from 'vitest'
import { screen, fireEvent, within, waitFor } from '@testing-library/react'
import { renderWithProviders } from '@/test/render'
import { SiteNav } from './SiteNav'
import { useUIStore } from '@/stores/uiStore'

describe('SiteNav 顶部导航栏 (Abdullah 宽幅高对比胶囊体系)', () => {
  beforeEach(() => {
    useUIStore.setState({ theme: 'light' })
  })

  it('渲染品牌商标与合规标签', () => {
    renderWithProviders(<SiteNav />)
    expect(screen.getByText('AdSDK Agent')).toBeInTheDocument()
    expect(screen.getByText('合规审计')).toBeInTheDocument()
  })

  it('渲染主要胶囊导航项', () => {
    renderWithProviders(<SiteNav />)
    const mainNav = screen.getByRole('navigation', { name: '主要' })
    expect(within(mainNav).getByText('产品')).toBeInTheDocument()
    expect(within(mainNav).getByText('概览')).toBeInTheDocument()
    expect(within(mainNav).getByText('任务')).toBeInTheDocument()
    expect(within(mainNav).getByText('报告')).toBeInTheDocument()
    expect(within(mainNav).getByText('环境')).toBeInTheDocument()
  })

  it('渲染操作区：新建分析按钮与主题切换按钮', () => {
    renderWithProviders(<SiteNav />)
    expect(screen.getByRole('button', { name: /新建分析/ })).toBeInTheDocument()
    const themeBtn = screen.getByRole('button', { name: /切换到深色主题/ })
    expect(themeBtn).toBeInTheDocument()

    // 点击切换主题
    fireEvent.click(themeBtn)
    expect(useUIStore.getState().theme).toBe('dark')
  })

  it('移动端目录抽屉开关响应正常', () => {
    renderWithProviders(<SiteNav />)
    const menuBtn = screen.getByRole('button', { name: '打开目录' })
    expect(menuBtn).toBeInTheDocument()

    fireEvent.click(menuBtn)
    expect(screen.getByRole('button', { name: '关闭目录' })).toBeInTheDocument()
  })

  it('胶囊导航链接与品牌项使用纯胶囊样式，无下划线修饰', () => {
    renderWithProviders(<SiteNav />)
    const brandLink = screen.getByRole('link', { name: /AdSDK Agent 首页/ })
    expect(brandLink).toHaveClass('wordmark')

    const mainNav = screen.getByRole('navigation', { name: '主要' })
    const productLink = within(mainNav).getByRole('link', { name: '产品' })
    expect(productLink).toHaveClass('nav-link')
  })

  it('渲染活跃胶囊滑块且不包含顶部进度指示线', () => {
    const { container } = renderWithProviders(<SiteNav />)
    // 顶部不应挂载进度指示条
    expect(container.querySelector('.nav-page-indicator-line')).toBeNull()

    // 活跃页面包含平滑流动滑块 .nav-active-pill
    const activePill = container.querySelector('.nav-active-pill')
    expect(activePill).toBeInTheDocument()
  })

  it('鼠标悬停非活跃导航项时触发浮动胶囊底色', async () => {
    const { container } = renderWithProviders(<SiteNav />)
    const mainNav = screen.getByRole('navigation', { name: '主要' })
    const tasksLink = within(mainNav).getByRole('link', { name: '任务' })

    // 初始状态下不应有对任务项的悬浮态
    expect(container.querySelector('.nav-hover-pill')).toBeNull()

    // 鼠标移入任务项
    fireEvent.mouseEnter(tasksLink)
    expect(container.querySelector('.nav-hover-pill')).toBeInTheDocument()

    // 鼠标离开导航区触发退出动画
    fireEvent.mouseLeave(mainNav)
    await waitFor(() => {
      const hoverPill = container.querySelector('.nav-hover-pill')
      // Framer Motion exit 过程或者已移出 DOM
      expect(!hoverPill || hoverPill.getAttribute('style')?.includes('opacity: 0')).toBe(true)
    })
  })
})
