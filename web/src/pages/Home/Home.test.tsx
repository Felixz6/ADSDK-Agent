import { describe, it, expect, beforeEach } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Home from './Home'
import { renderWithProviders } from '@/test/render'
import { clearLocalTasks, recordTask } from '@/api/tasks'
import { server } from '@/test/msw-server'
import type { AnalyzeResponse } from '@/types/api'

beforeEach(() => {
  localStorage.clear()
  clearLocalTasks()
})

describe('Home — 后端已连接', () => {
  it('健康检查返回 ok 时,显示「已连接」横幅', async () => {
    renderWithProviders(<Home />)
    expect(await screen.findByText(/已连接 AdSDK Agent 后端/)).toBeInTheDocument()
  })

  it('点击「新建分析」可导航至 /analysis/new', async () => {
    const user = userEvent.setup()
    const { router } = renderWithProviders(<Home />)
    await user.click(await screen.findByRole('button', { name: /新建分析/ }))
    expect(router.state.location.pathname).toBe('/analysis/new')
  })

  it('点击「查看仪表盘」导航至 /dashboard', async () => {
    const user = userEvent.setup()
    const { router } = renderWithProviders(<Home />)
    await user.click(await screen.findByRole('button', { name: /查看仪表盘/ }))
    expect(router.state.location.pathname).toBe('/dashboard')
  })

  it('点击「静态分析」特性卡导航至 /static', async () => {
    const user = userEvent.setup()
    const { router } = renderWithProviders(<Home />)
    await user.click(await screen.findByRole('button', { name: /静态分析/ }))
    expect(router.state.location.pathname).toBe('/static')
  })

  it('最近有本地记录时显示在「最近提交」', async () => {
    recordTask('static', { apk_path: 'D:/authorized/a.apk' }, { run_id: 'r1', status: 'success' } as AnalyzeResponse)
    renderWithProviders(<Home />)
    expect(await screen.findByText(/D:\/authorized\/a\.apk/)).toBeInTheDocument()
  })
})

describe('Home — 后端不可达(中文友好错误)', () => {
  it('GET / 返回 500 时显示「后端未连接」中文提示,而非崩溃', async () => {
    server.use(
      http.get('http://127.0.0.1:8000/', () =>
        new HttpResponse('Internal Server Error', { status: 500 }),
      ),
    )
    renderWithProviders(<Home />)
    // 注意:5xx 不映射为 unreachable,但 ok 字段为假,故显示未连接横幅。
    expect(await screen.findByText(/后端未连接/)).toBeInTheDocument()
  })

  it('GET / 网络层失败时显示「后端未连接」与中文引导信息', async () => {
    server.use(
      http.get('http://127.0.0.1:8000/', () => HttpResponse.error()),
    )
    renderWithProviders(<Home />)
    expect(await screen.findByText(/后端未连接/)).toBeInTheDocument()
    expect(await screen.findByText(/请启动本地 FastAPI/)).toBeInTheDocument()
  })
})
