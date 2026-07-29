import { beforeEach, describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Tasks from './Tasks'
import { renderWithProviders } from '@/test/render'
import { server } from '@/test/msw-server'
import { clearLocalTasks, recordTask } from '@/api/tasks'
import type { TaskRecord } from '@/types/tasks'

const API = 'http://127.0.0.1:8000'

function task(overrides: Partial<TaskRecord> = {}): TaskRecord {
  return {
    id: 'task-1',
    task_type: 'static',
    status: 'completed',
    apk_path: 'D:/samples/app.apk',
    apk_snapshot_path: null,
    apk_sha256: 'a'.repeat(64),
    package_name: 'com.example.app',
    app_name: 'Example',
    version_name: '1.0',
    version_code: '1',
    device_id: null,
    enable_traffic: false,
    enable_ui_stimulation: false,
    progress_percent: 100,
    current_stage: 'completed',
    cancelled_at_stage: null,
    error_code: null,
    error_message: null,
    report_json_path: 'D:/output/report.json',
    report_markdown_path: 'D:/output/report.md',
    report_html_path: 'D:/output/report.html',
    risk_score: 12,
    risk_level: 'low',
    request_payload: { task_type: 'static', apk_path: 'D:/samples/app.apk' },
    created_at: '2026-07-29T01:00:00Z',
    started_at: '2026-07-29T01:00:01Z',
    completed_at: '2026-07-29T01:00:02Z',
    updated_at: '2026-07-29T01:00:02Z',
    steps: [],
    ...overrides,
  }
}

function listHandler(items: TaskRecord[]) {
  return http.get(`${API}/tasks`, ({ request }) => {
    const status = new URL(request.url).searchParams.get('status')
    const filtered = status ? items.filter((item) => item.status === status) : items
    return HttpResponse.json({
      items: filtered,
      total: filtered.length,
      page: 1,
      page_size: 20,
      pages: filtered.length ? 1 : 0,
    })
  })
}

beforeEach(() => {
  localStorage.clear()
  clearLocalTasks()
  server.use(listHandler([]))
})

describe('Tasks — 后端持久化任务中心', () => {
  it('加载中显示真实等待状态', async () => {
    server.use(http.get(`${API}/tasks`, () => new Promise(() => undefined)))
    renderWithProviders(<Tasks />)
    expect(await screen.findByText('正在加载后端任务…')).toBeInTheDocument()
  })

  it('空列表显示后端任务空态', async () => {
    renderWithProviders(<Tasks />)
    expect(await screen.findByText('没有匹配的后端任务')).toBeInTheDocument()
  })

  it('后端错误显示可诊断错误状态', async () => {
    server.use(
      http.get(`${API}/tasks`, () =>
        HttpResponse.json(
          { detail: { code: 'database_error', message: '任务数据库暂时不可用' } },
          { status: 503 },
        ),
      ),
    )
    renderWithProviders(<Tasks />)
    expect(await screen.findByText('任务中心暂时不可用')).toBeInTheDocument()
    expect(screen.getByText('任务数据库暂时不可用')).toBeInTheDocument()
  })

  it('展示持久化任务并支持搜索参数与详情导航', async () => {
    server.use(listHandler([task()]))
    const user = userEvent.setup()
    const { router } = renderWithProviders(<Tasks />)

    expect((await screen.findAllByText('Example')).length).toBeGreaterThan(0)
    expect(screen.getAllByText(/com\.example\.app · app\.apk/).length).toBeGreaterThan(0)
    expect(screen.getAllByText('低风险').length).toBeGreaterThan(0)
    expect(screen.getAllByText('已完成').length).toBeGreaterThan(0)
    await user.click(screen.getAllByText('Example')[0])
    expect(router.state.location.pathname).toBe('/tasks/task-1')
  })

  it('运行中任务需确认后发送取消信号', async () => {
    const running = task({
      id: 'task-running',
      status: 'running',
      progress_percent: 42,
      current_stage: 'dynamic_collection',
      completed_at: null,
      report_json_path: null,
      report_markdown_path: null,
      report_html_path: null,
    })
    let cancelCalled = false
    server.use(
      listHandler([running]),
      http.post(`${API}/tasks/task-running/cancel`, () => {
        cancelCalled = true
        return HttpResponse.json({
          task: { ...running, status: 'cancelled' },
          message: '已发送取消信号',
        })
      }),
    )
    const user = userEvent.setup()
    renderWithProviders(<Tasks />)

    await screen.findAllByText('Example')
    await user.click(screen.getAllByRole('button', { name: '取消任务' })[0])
    expect(screen.getByText('取消该任务？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '发送取消信号' }))
    await vi.waitFor(() => expect(cancelCalled).toBe(true))
    expect(await screen.findByText(/取消信号已发送/)).toBeInTheDocument()
  })

  it('终态任务需确认后删除 SQLite 记录', async () => {
    let deleted = false
    server.use(
      listHandler([task()]),
      http.delete(`${API}/tasks/task-1`, () => {
        deleted = true
        return new HttpResponse(null, { status: 204 })
      }),
    )
    const user = userEvent.setup()
    renderWithProviders(<Tasks />)

    await screen.findAllByText('Example')
    await user.click(screen.getAllByRole('button', { name: '删除任务' })[0])
    expect(screen.getByText('删除该任务记录？')).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '删除记录' }))
    await vi.waitFor(() => expect(deleted).toBe(true))
    expect(await screen.findByText('任务记录已删除。')).toBeInTheDocument()
  })

  it('失败任务可创建新的重试任务并进入详情', async () => {
    const failed = task({
      id: 'task-failed',
      status: 'failed',
      error_code: 'task_execution_failed',
      error_message: '后台任务执行失败',
      report_json_path: null,
      report_markdown_path: null,
      report_html_path: null,
    })
    server.use(
      listHandler([failed]),
      http.post(`${API}/tasks/task-failed/retry`, () =>
        HttpResponse.json({
          task: { ...failed, id: 'task-retry', status: 'queued' },
          message: '已创建重试任务',
        }),
      ),
    )
    const user = userEvent.setup()
    const { router } = renderWithProviders(<Tasks />)
    await screen.findAllByText('Example')
    await user.click(screen.getAllByRole('button', { name: '重新分析' })[0])
    await vi.waitFor(() => expect(router.state.location.pathname).toBe('/tasks/task-retry'))
    expect(await screen.findByText('已创建重试任务。')).toBeInTheDocument()
  })

  it('旧 localStorage 记录保留为明确的只读兼容区', async () => {
    recordTask('static', { apk_path: 'D:/legacy.apk', package_name: 'com.legacy' }, null)
    const user = userEvent.setup()
    renderWithProviders(<Tasks />)

    const toggle = await screen.findByRole('button', { name: /浏览器旧记录/ })
    expect(screen.getByText(/1 条 · 只读兼容/)).toBeInTheDocument()
    await user.click(toggle)
    expect(screen.getByText('com.legacy')).toBeInTheDocument()
  })

  it('隐藏资源引用、缩短设备标识并保留完整 Tooltip', async () => {
    server.use(listHandler([task({
      app_name: '@string/app_name',
      device_id: 'redacted:80a563aa99887766',
      risk_level: null,
    })]))
    renderWithProviders(<Tasks />)

    expect((await screen.findAllByText('app.apk')).length).toBeGreaterThan(0)
    expect(screen.queryByText('@string/app_name')).not.toBeInTheDocument()
    expect(screen.getAllByText('设备 80a563aa').length).toBeGreaterThan(0)
    expect(screen.getAllByTitle('redacted:80a563aa99887766').length).toBeGreaterThan(0)
    expect(screen.getAllByText('未评估').length).toBeGreaterThan(0)
  })

  it('对比任务使用友好标题，已取消任务显示停止步骤', async () => {
    const comparison = task({
      id: '11111111-2222-4333-8444-555555555555',
      task_type: 'comparison',
      app_name: 'Example · 版本对比',
      apk_path: null,
      package_name: 'com.example.app',
      request_payload: { base_task_id: 'aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee', target_task_id: 'ffffffff-1111-4222-8333-444444444444' },
      report_json_path: null,
    })
    const cancelled = task({
      id: 'cancelled-1',
      status: 'cancelled',
      current_stage: 'cancelled',
      cancelled_at_stage: 'apk_install',
      report_json_path: null,
    })
    server.use(listHandler([comparison, cancelled]))
    renderWithProviders(<Tasks />)

    expect((await screen.findAllByText('Example · 版本对比')).length).toBeGreaterThan(0)
    expect(screen.queryByText(comparison.id)).not.toBeInTheDocument()
    expect(screen.getAllByText('取消于：安装 APK').length).toBeGreaterThan(0)
  })

  it('桌面表格与窄屏卡片均受响应式容器约束', async () => {
    server.use(listHandler([task()]))
    renderWithProviders(<Tasks />)
    await screen.findAllByText('Example')
    expect(screen.getByTestId('task-desktop-table')).toHaveClass('hidden', 'overflow-x-auto')
    expect(screen.getByTestId('task-mobile-list')).toHaveClass('xl:hidden')
  })
})
