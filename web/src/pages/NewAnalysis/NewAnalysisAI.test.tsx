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

/**
 * M6B：Settings 的 AI 卡片由只读展示改为可编辑表单,数据源从 /ai/status
 * 换成脱敏的 /ai/settings。此 fixture 与后端 `AISettingsResponse` 一致,
 * 结构上就**不含** api_key —— 前端无从取得密钥原值。
 */
const AI_SETTINGS_CONFIGURED = {
  schema_version: 'ai-settings-v1',
  enabled: true,
  provider: 'openai_compatible',
  base_url: 'https://example.com/v1',
  model: 'gpt-4o-mini',
  api_key_configured: true,
  api_key_source: 'local_store',
  default_token_budget: 6000,
  max_rounds: 2,
  max_tool_calls: 6,
  timeout_seconds: 60,
  max_input_tokens: 6000,
  max_output_tokens: 1800,
  cache_enabled: true,
  cache_ttl_seconds: 86400,
  allow_dynamic_tools: false,
  report_language: 'zh-CN',
  field_sources: {
    enabled: 'local_store',
    provider: 'default',
    base_url: 'local_store',
    model: 'local_store',
  },
  locked_fields: [],
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
    http.get(`${API}/ai/settings`, () => HttpResponse.json(AI_SETTINGS_CONFIGURED)),
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

  // -- M7A: explicit device-state-change confirmation checklist ----------
  it('未开启动态分析时不展示设备变更清单', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    expect(screen.queryByTestId('device-change-checklist')).toBeNull()
  })

  it('开启动态分析后展示设备状态变更范围清单', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    await user.click(await screen.findByLabelText(/允许动态分析/))
    const panel = await screen.findByTestId('device-change-checklist')
    expect(panel).toBeInTheDocument()
    expect(panel.textContent).toContain('本次运行将改变设备状态')
  })

  it('清单声明会恢复设备代理为初始值', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    await user.click(await screen.findByLabelText(/允许动态分析/))
    const panel = await screen.findByTestId('device-change-checklist')
    expect(panel.textContent).toContain('恢复为初始值')
  })

  it('清单明确不清除应用数据、不卸载、不修改其他应用', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    await user.click(await screen.findByLabelText(/允许动态分析/))
    const panel = await screen.findByTestId('device-change-checklist')
    expect(panel.textContent).toContain('不清除应用数据')
    expect(panel.textContent).toContain('不卸载应用')
    expect(panel.textContent).toContain('不修改其他应用')
  })

  it('清单明确不自动点击 UI、不自动确认 Consent、不重启设备', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    await user.click(await screen.findByLabelText(/允许动态分析/))
    const panel = await screen.findByTestId('device-change-checklist')
    expect(panel.textContent).toContain('不自动点击 UI')
    expect(panel.textContent).toContain('不自动确认 Consent')
    expect(panel.textContent).toContain('不重启设备')
  })

  it('清单明确不停止外部 frida-server 且不绕过 SSL Pinning', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    await user.click(await screen.findByLabelText(/允许动态分析/))
    const panel = await screen.findByTestId('device-change-checklist')
    expect(panel.textContent).toContain('外部 frida-server')
    expect(panel.textContent).toContain('不绕过 SSL Pinning')
  })

  it('清单说明 Consent 需人工完成且超时不会自动确认', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    await user.click(await screen.findByLabelText(/允许动态分析/))
    const panel = await screen.findByTestId('device-change-checklist')
    expect(panel.textContent).toContain('人工完成')
    expect(panel.textContent).toContain('超时不会自动确认')
  })

  it('清单不包含任何 API Key、完整设备序列号或模型原文', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    await user.click(await screen.findByLabelText(/允许动态分析/))
    const panel = await screen.findByTestId('device-change-checklist')
    const text = panel.textContent ?? ''
    expect(text).not.toContain('sk-')
    expect(text).not.toContain('127.0.0.1:16416')
    expect(text.toLowerCase()).not.toContain('api_key')
    expect(text).not.toContain('reasoning_content')
  })

  it('关闭动态分析后清单随之隐藏', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachAIOptions(user)
    const toggle = await screen.findByLabelText(/允许动态分析/)
    await user.click(toggle)
    expect(await screen.findByTestId('device-change-checklist')).toBeInTheDocument()
    await user.click(toggle)
    await vi.waitFor(() =>
      expect(screen.queryByTestId('device-change-checklist')).toBeNull(),
    )
  })
})

describe('Settings — AI 配置展示', () => {
  it('展示 AI 启用状态、Provider、Model 与预算限制', async () => {
    renderWithProviders(<Settings />)

    // M6B：状态摘要 + 可编辑表单(取代原只读 KV 列表)。
    expect(await screen.findByText('AI 已启用')).toBeInTheDocument()
    expect(screen.getByLabelText(/^Provider/)).toHaveValue('openai_compatible')
    expect(screen.getByLabelText(/^Model/)).toHaveValue('gpt-4o-mini')
    expect(screen.getByLabelText(/默认 Token 预算/)).toHaveValue(6000)
    expect(screen.getByLabelText(/最大模型轮数/)).toHaveValue(2)
    expect(screen.getByLabelText(/最大工具调用数/)).toHaveValue(6)
  })

  it('绝不展示 API Key', async () => {
    const secret = 'sk-should-never-render'
    server.use(
      // 即使后端异常回传了额外字段,前端也只渲染已知的白名单字段。
      http.get(`${API}/ai/settings`, () =>
        HttpResponse.json({ ...AI_SETTINGS_CONFIGURED, api_key: secret }),
      ),
      http.get(`${API}/ai/status`, () =>
        HttpResponse.json({ ...AI_STATUS_ENABLED, api_key: secret }),
      ),
    )
    const { container } = renderWithProviders(<Settings />)
    await screen.findByText('AI 已启用')

    expect(container.textContent).not.toContain(secret)
    // Key 输入框存在但为空,且绝不回填已保存的密钥。
    const keyInput = screen.getByLabelText(/API Key/) as HTMLInputElement
    expect(keyInput.value).toBe('')
    expect(keyInput.placeholder).toMatch(/留空表示保持不变/)
    expect(screen.getByText(/仅提交到本机后端/)).toBeInTheDocument()
  })
})
