import { beforeEach, describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import userEvent, { type UserEvent } from '@testing-library/user-event'
import NewAnalysis from '@/pages/NewAnalysis/NewAnalysis'
import Settings from '@/pages/Settings/Settings'
import { renderWithProviders } from '@/test/render'
import { server } from '@/test/msw-server'

const API = 'http://127.0.0.1:8000'

const AI_STATUS_ENABLED = {
  enabled: true,
  provider: 'openai_compatible',
  model: 'gpt-4o-mini',
  configured: true,
  reachable: null,
  last_error_code: null,
  default_token_budget: 6000,
  max_rounds: 2,
  max_tool_calls: 6,
  report_language: 'zh-CN',
  allow_dynamic_tools: false,
}

const AI_STATUS_DISABLED = {
  ...AI_STATUS_ENABLED,
  enabled: false,
  configured: false,
  model: '',
  last_error_code: 'ai_not_configured',
}

beforeEach(() => {
  localStorage.clear()
  server.use(
    http.post(`${API}/tasks`, async () =>
      HttpResponse.json({ id: 'task-ai', status: 'queued' }, { status: 202 }),
    ),
    http.get(`${API}/env/check`, () =>
      HttpResponse.json({ checks: {}, details: { device: { devices: [], online_count: 0 } } }),
    ),
    http.get(`${API}/ai/status`, () => HttpResponse.json(AI_STATUS_ENABLED)),
    http.get(`${API}/tasks/system/status`, () =>
      HttpResponse.json({
        database_ok: true,
        database_path: 'D:/output/state/adsdk-agent.db',
        running_tasks: 0,
        queued_tasks: 0,
        occupied_devices: [],
      }),
    ),
    http.get(`${API}/`, () => HttpResponse.json({ ok: true, message: 'running' })),
  )
})

async function reachAIOptions(user: UserEvent, apkPath = 'D:/authorized/sample.apk') {
  await user.click(screen.getByLabelText(/AI 编排分析/))
  await user.click(screen.getByRole('button', { name: /下一步/ }))
  const pathInput = await screen.findByLabelText(/APK 路径/)
  await user.type(pathInput, apkPath)
  await user.click(screen.getByRole('button', { name: /下一步/ }))
}

describe('NewAnalysis — AI 编排分析', () => {
  it('可选择 AI 编排模式并展示分析目标与范围', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)

    expect(await screen.findByLabelText(/分析目标/)).toBeInTheDocument()
    expect(screen.getByText('仅静态')).toBeInTheDocument()
    expect(screen.getByText('完整分析')).toBeInTheDocument()
    expect(screen.getByText('仅出报告')).toBeInTheDocument()
  })

  it('展示 Token 预算输入且默认取后端配置', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)

    const budget = await screen.findByLabelText(/Token 预算/)
    // 默认值来自 /ai/status 的 default_token_budget,不是无限值。
    await vi.waitFor(() => expect(budget).toHaveValue(6000))
    expect(screen.getByText(/不允许无限值/)).toBeInTheDocument()
  })

  it('AI 关闭时展示中性提示且仍可提交', async () => {
    server.use(http.get(`${API}/ai/status`, () => HttpResponse.json(AI_STATUS_DISABLED)))
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)

    const notice = await screen.findByTestId('ai-disabled-notice')
    expect(notice).toHaveTextContent(/AI 功能当前未启用|尚未配置完成/)
    expect(notice).toHaveTextContent(/确定性默认计划/)
    // 提交按钮不因 AI 关闭而禁用。
    await user.click(screen.getByRole('button', { name: /下一步/ }))
    expect(screen.getByRole('button', { name: /提交后台任务/ })).toBeEnabled()
  })

  it('提交 AI 任务携带目标、范围与预算', async () => {
    let received: Record<string, unknown> | undefined
    server.use(
      http.post(`${API}/tasks`, async ({ request }) => {
        received = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ id: 'task-ai', status: 'queued' }, { status: 202 })
      }),
    )
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    await user.type(await screen.findByLabelText(/分析目标/), '只做静态隐私检查')
    await user.click(screen.getByRole('button', { name: /下一步/ }))
    await user.click(screen.getByRole('button', { name: /提交后台任务/ }))

    await vi.waitFor(() => expect(router.state.location.pathname).toBe('/tasks/task-ai'))
    expect(received).toMatchObject({
      task_type: 'ai_orchestrated',
      apk_path: 'D:/authorized/sample.apk',
      objective: '只做静态隐私检查',
      analysis_scope: 'static_only',
      allow_dynamic: false,
      token_budget: 6000,
    })
    // 未允许动态时不得预先确认设备状态变更类工具。
    expect(received?.confirmed_tools).toEqual([])
  })

  it('允许动态分析时必须显式选择设备', async () => {
    let posted = false
    server.use(
      http.post(`${API}/tasks`, async () => {
        posted = true
        return HttpResponse.json({ id: 'task-ai', status: 'queued' }, { status: 202 })
      }),
    )
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    await user.click(await screen.findByLabelText(/允许动态分析/))
    await user.click(screen.getByRole('button', { name: /下一步/ }))
    await user.click(screen.getByRole('button', { name: /提交后台任务/ }))

    expect(await screen.findByText(/必须显式选择在线设备/)).toBeInTheDocument()
    expect(posted).toBe(false)
  })
})

describe('Settings — AI 配置展示', () => {
  it('展示 AI 启用状态、Provider、Model 与预算限制', async () => {
    renderWithProviders(<Settings />)

    expect(await screen.findByText('已启用')).toBeInTheDocument()
    expect(screen.getByText('openai_compatible')).toBeInTheDocument()
    expect(screen.getByText('gpt-4o-mini')).toBeInTheDocument()
    expect(screen.getByText('默认 Token 预算')).toBeInTheDocument()
    expect(screen.getByText('最大模型轮数')).toBeInTheDocument()
    expect(screen.getByText('最大工具调用数')).toBeInTheDocument()
  })

  it('绝不展示 API Key', async () => {
    const secret = 'sk-should-never-render'
    server.use(
      http.get(`${API}/ai/status`, () =>
        // 即使后端异常回传了额外字段,前端也只渲染已知的白名单字段。
        HttpResponse.json({ ...AI_STATUS_ENABLED, api_key: secret }),
      ),
    )
    const { container } = renderWithProviders(<Settings />)
    await screen.findByText('已启用')

    expect(container.textContent).not.toContain(secret)
    expect(container.textContent).not.toContain('API Key：')
    expect(screen.getByText(/仅从后端环境变量读取/)).toBeInTheDocument()
  })
})
