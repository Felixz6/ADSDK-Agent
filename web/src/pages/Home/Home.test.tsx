import { describe, it, expect, beforeEach } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Home from './Home'
import { renderWithProviders } from '@/test/render'
import { clearLocalTasks, recordTask } from '@/api/tasks'
import { server } from '@/test/msw-server'
import type { AnalyzeResponse } from '@/types/api'
import type { TaskRecord } from '@/types/tasks'

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

  it('统计卡按静态、动态、版本对比和运行中四种清晰口径展示', async () => {
    server.use(
      http.get('http://127.0.0.1:8000/tasks', ({ request }) => {
        const params = new URL(request.url).searchParams
        const taskType = params.get('task_type')
        const status = params.get('status')
        const total = taskType === 'static' ? 2 : taskType === 'dynamic' ? 3 : taskType === 'comparison' ? 2 : status === 'running' ? 0 : 7
        return HttpResponse.json({ items: [], total, page: 1, page_size: Number(params.get('page_size') || 20), pages: total ? 1 : 0 })
      }),
    )
    renderWithProviders(<Home />)
    expect((await screen.findAllByText('静态分析')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('动态分析').length).toBeGreaterThan(0)
    expect(screen.getAllByText('版本对比').length).toBeGreaterThan(0)
    expect(screen.getByText('运行中任务')).toBeInTheDocument()
    expect(screen.queryByText('全部任务')).not.toBeInTheDocument()
  })

  it('最近提交使用名称回退、中文风险、类型和报告入口', async () => {
    const recent: TaskRecord = {
      id: 'task-recent',
      task_type: 'static',
      status: 'completed',
      apk_path: 'D:/samples/hongguo.apk',
      apk_snapshot_path: null,
      apk_sha256: 'a'.repeat(64),
      package_name: 'com.phoenix.read',
      app_name: '@string/app_name',
      version_name: '7.0.5.33',
      version_code: '70533',
      device_id: null,
      enable_traffic: false,
      enable_ui_stimulation: false,
      progress_percent: 100,
      current_stage: 'completed',
      cancelled_at_stage: null,
      error_code: null,
      error_message: null,
      report_json_path: 'D:/output/report.json',
      report_markdown_path: null,
      report_html_path: null,
      risk_score: 12,
      risk_level: 'low',
      request_payload: {},
      created_at: '2026-07-29T01:00:00Z',
      started_at: null,
      completed_at: '2026-07-29T01:01:00Z',
      updated_at: '2026-07-29T01:01:00Z',
      steps: [],
    }
    server.use(http.get('http://127.0.0.1:8000/tasks', ({ request }) => {
      const params = new URL(request.url).searchParams
      const isRecent = !params.get('status') && !params.get('task_type')
      return HttpResponse.json({ items: isRecent ? [recent] : [], total: isRecent ? 1 : 0, page: 1, page_size: Number(params.get('page_size') || 20), pages: isRecent ? 1 : 0 })
    }))
    renderWithProviders(<Home />)

    expect(await screen.findByText('hongguo.apk')).toBeInTheDocument()
    expect(screen.queryByText('@string/app_name')).not.toBeInTheDocument()
    expect(screen.getByText('低风险')).toBeInTheDocument()
    expect(screen.getAllByText('静态分析').length).toBeGreaterThan(0)
    expect(screen.getByRole('button', { name: '查看报告' })).toBeInTheDocument()
    expect(screen.getByText('完成于')).toBeInTheDocument()
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
