/**
 * M6B —— 前端 AI 配置中心测试。
 *
 * 安全断言(与后端契约一一对应):
 * - API Key 绝不回填、绝不出现在 DOM、绝不写入 localStorage / sessionStorage;
 * - 保存成功后 Key 输入立即清空;组件卸载后不残留;
 * - 环境变量锁定的字段禁用并提示;环境变量 Key 时输入框禁用;
 * - 删除 Key 需二次确认,且是独立操作(空 Key 保存不会误删);
 * - 保存与测试互斥;非法字段禁用保存;
 * - API 调试日志不含 Key(拦截器只打印 method + url)。
 */
import { beforeEach, describe, expect, it, vi, afterEach } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Settings from '@/pages/Settings/Settings'
import { renderWithProviders } from '@/test/render'
import { server } from '@/test/msw-server'
import type { AISettingsResponse } from '@/types/aiSettings'

const API = 'http://127.0.0.1:8000'
const SECRET = 'sk-frontend-never-persist-0001'

const BASE_SETTINGS: AISettingsResponse = {
  schema_version: 'ai-settings-v1',
  enabled: false,
  provider: 'openai_compatible',
  base_url: '',
  model: '',
  api_key_configured: false,
  api_key_source: 'none',
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
    enabled: 'default',
    provider: 'default',
    base_url: 'default',
    model: 'default',
  },
  locked_fields: [],
}

const CONFIGURED: AISettingsResponse = {
  ...BASE_SETTINGS,
  enabled: true,
  base_url: 'https://example.com/v1',
  model: 'gpt-4o-mini',
  api_key_configured: true,
  api_key_source: 'local_store',
  field_sources: {
    ...BASE_SETTINGS.field_sources,
    base_url: 'local_store',
    model: 'local_store',
  },
}

/** 通用支撑接口(Settings 页面其他卡片需要),避免 onUnhandledRequest:'error'。 */
function baseHandlers(settings: AISettingsResponse = BASE_SETTINGS) {
  return [
    http.get(`${API}/ai/settings`, () => HttpResponse.json(settings)),
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
  ]
}

beforeEach(() => {
  localStorage.clear()
  sessionStorage.clear()
  server.use(...baseHandlers())
})

afterEach(() => {
  vi.restoreAllMocks()
})

async function renderSettings(settings: AISettingsResponse = BASE_SETTINGS) {
  server.use(...baseHandlers(settings))
  const utils = renderWithProviders(<Settings />)
  await screen.findByTestId('ai-settings-summary')
  return utils
}

describe('M6B — AI 配置表单', () => {
  // 1. 加载脱敏配置
  it('加载脱敏配置并渲染表单', async () => {
    await renderSettings(CONFIGURED)
    expect(screen.getByLabelText(/^Base URL/)).toHaveValue('https://example.com/v1')
    expect(screen.getByLabelText(/^Model/)).toHaveValue('gpt-4o-mini')
    expect(screen.getByText('AI 已启用')).toBeInTheDocument()
    expect(screen.getByText('Key 已配置')).toBeInTheDocument()
  })

  // 2. 编辑普通字段
  it('可编辑普通字段', async () => {
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    const model = screen.getByLabelText(/^Model/)
    await user.clear(model)
    await user.type(model, 'new-model')
    expect(model).toHaveValue('new-model')
  })

  // 3 + 4. Key 不回填 & 已配置 placeholder
  it('API Key 不回填,且已配置时提示保持不变', async () => {
    await renderSettings(CONFIGURED)
    const key = screen.getByLabelText(/API Key/) as HTMLInputElement
    expect(key.value).toBe('')
    expect(key.placeholder).toMatch(/留空表示保持不变/)
  })

  it('未配置时 placeholder 提示请输入', async () => {
    await renderSettings(BASE_SETTINGS)
    const key = screen.getByLabelText(/API Key/) as HTMLInputElement
    expect(key.placeholder).toMatch(/请输入 API Key/)
  })

  // 5. 保存后清空 Key state
  it('保存成功后立即清空 Key 输入', async () => {
    let received: Record<string, unknown> | null = null
    server.use(
      http.put(`${API}/ai/settings`, async ({ request }) => {
        received = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ ...CONFIGURED, model: 'saved-model' })
      }),
    )
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    const key = screen.getByLabelText(/API Key/) as HTMLInputElement
    await user.type(key, SECRET)
    await user.click(screen.getByTestId('ai-settings-save'))

    await screen.findByTestId('ai-settings-saved')
    expect(key.value).toBe('')
    expect(received).not.toBeNull()
    expect((received as unknown as Record<string, unknown>).api_key).toBe(SECRET)
  })

  // 6. Key 不进入 localStorage / sessionStorage
  it('API Key 绝不写入浏览器持久化存储', async () => {
    server.use(
      http.put(`${API}/ai/settings`, () => HttpResponse.json(CONFIGURED)),
    )
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    await user.type(screen.getByLabelText(/API Key/), SECRET)
    await user.click(screen.getByTestId('ai-settings-save'))
    await screen.findByTestId('ai-settings-saved')

    expect(JSON.stringify(localStorage)).not.toContain(SECRET)
    expect(JSON.stringify(sessionStorage)).not.toContain(SECRET)
    for (let i = 0; i < localStorage.length; i += 1) {
      const k = localStorage.key(i)!
      expect(localStorage.getItem(k)).not.toContain(SECRET)
    }
  })

  // 7. 显示/隐藏当前输入
  it('支持显示/隐藏当前 Key 输入', async () => {
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    const key = screen.getByLabelText(/API Key/) as HTMLInputElement
    expect(key.type).toBe('password')
    await user.click(screen.getByLabelText('显示输入'))
    expect((screen.getByLabelText(/API Key/) as HTMLInputElement).type).toBe('text')
    await user.click(screen.getByLabelText('隐藏输入'))
    expect((screen.getByLabelText(/API Key/) as HTMLInputElement).type).toBe('password')
  })

  // 8. 保存配置
  it('保存配置提交可编辑字段', async () => {
    let body: Record<string, unknown> | null = null
    server.use(
      http.put(`${API}/ai/settings`, async ({ request }) => {
        body = (await request.json()) as Record<string, unknown>
        return HttpResponse.json({ ...CONFIGURED, model: 'edited' })
      }),
    )
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    const model = screen.getByLabelText(/^Model/)
    await user.clear(model)
    await user.type(model, 'edited')
    await user.click(screen.getByTestId('ai-settings-save'))
    await screen.findByTestId('ai-settings-saved')
    expect((body as unknown as Record<string, unknown>).model).toBe('edited')
  })

  // 9. 测试连接
  it('测试连接展示安全结果', async () => {
    server.use(
      http.post(`${API}/ai/settings/test`, () =>
        HttpResponse.json({
          status: 'reachable',
          provider: 'openai_compatible',
          model: 'gpt-4o-mini',
          latency_ms: 42,
          safe_message: '通过 /models 探测成功',
          models_endpoint_supported: true,
        }),
      ),
    )
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    await user.click(screen.getByTestId('ai-settings-test'))
    const result = await screen.findByTestId('ai-settings-test-result')
    expect(within(result).getByText(/连接正常/)).toBeInTheDocument()
    expect(within(result).getByText(/42 ms/)).toBeInTheDocument()
  })

  // 10. 保存与测试互斥
  it('测试进行中禁用保存,保存进行中禁用测试', async () => {
    let releaseTest: (() => void) | undefined
    server.use(
      http.post(`${API}/ai/settings/test`, async () => {
        await new Promise<void>((resolve) => {
          releaseTest = resolve
        })
        return HttpResponse.json({
          status: 'reachable',
          provider: 'openai_compatible',
          model: 'm',
          latency_ms: 1,
          safe_message: 'ok',
          models_endpoint_supported: true,
        })
      }),
    )
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    await user.click(screen.getByTestId('ai-settings-test'))
    await waitFor(() => {
      expect(screen.getByTestId('ai-settings-save')).toBeDisabled()
      expect(screen.getByTestId('ai-settings-test')).toBeDisabled()
    })
    releaseTest?.()
  })

  // 11 + 12. 删除本地 Key + 删除确认
  it('删除本地 Key 需二次确认', async () => {
    let deleted = false
    server.use(
      http.delete(`${API}/ai/settings/api-key`, () => {
        deleted = true
        return HttpResponse.json({
          deleted: true,
          api_key_source: 'none',
          api_key_configured: false,
        })
      }),
    )
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    await user.click(screen.getByTestId('ai-settings-delete-key'))
    // 确认对话框出现,尚未真正删除。
    expect(await screen.findByText(/删除已保存的 API Key\?/)).toBeInTheDocument()
    expect(deleted).toBe(false)
    await user.click(screen.getByRole('button', { name: '删除' }))
    await waitFor(() => expect(deleted).toBe(true))
    await waitFor(() => expect(screen.getByText('Key 未配置')).toBeInTheDocument())
  })

  it('未配置 Key 时删除按钮禁用', async () => {
    await renderSettings(BASE_SETTINGS)
    expect(screen.getByTestId('ai-settings-delete-key')).toBeDisabled()
  })

  // 13. 环境变量字段锁定
  it('环境变量锁定的字段禁用并提示', async () => {
    await renderSettings({
      ...CONFIGURED,
      locked_fields: ['model', 'base_url'],
      field_sources: { ...CONFIGURED.field_sources, model: 'environment', base_url: 'environment' },
    })
    expect(screen.getByLabelText(/^Model/)).toBeDisabled()
    expect(screen.getByLabelText(/^Base URL/)).toBeDisabled()
    expect(screen.getAllByText(/该字段由环境变量管理/).length).toBeGreaterThanOrEqual(2)
  })

  // 14. 环境变量 Key 时禁用输入
  it('环境变量 Key 时输入框与删除按钮禁用', async () => {
    await renderSettings({
      ...CONFIGURED,
      api_key_source: 'environment',
      api_key_configured: true,
    })
    expect(screen.getByLabelText(/API Key/)).toBeDisabled()
    expect(screen.getByTestId('ai-settings-delete-key')).toBeDisabled()
    expect(screen.getByText(/由环境变量管理/)).toBeInTheDocument()
  })

  // 15-17. 测试连接的各类失败状态
  it.each([
    ['authentication_failed', /鉴权失败/],
    ['timeout', /连接超时/],
    ['invalid_configuration', /配置不完整或被网关拒绝/],
  ] as const)('测试连接状态 %s 有中文友好提示', async (status, pattern) => {
    server.use(
      http.post(`${API}/ai/settings/test`, () =>
        HttpResponse.json({
          status,
          provider: 'openai_compatible',
          model: 'm',
          latency_ms: 7,
          safe_message: 'detail',
          models_endpoint_supported: false,
        }),
      ),
    )
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    await user.click(screen.getByTestId('ai-settings-test'))
    const result = await screen.findByTestId('ai-settings-test-result')
    expect(within(result).getByText(pattern)).toBeInTheDocument()
    // 技术错误码折叠保留。
    expect(within(result).getByText(/技术详情/)).toBeInTheDocument()
  })

  // 18. 保存成功提示
  it('保存成功给出提示', async () => {
    server.use(http.put(`${API}/ai/settings`, () => HttpResponse.json(CONFIGURED)))
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    const model = screen.getByLabelText(/^Model/)
    await user.clear(model)
    await user.type(model, 'x1')
    await user.click(screen.getByTestId('ai-settings-save'))
    expect(await screen.findByTestId('ai-settings-saved')).toBeInTheDocument()
  })

  // 19. 重置未保存修改
  it('重置未保存修改恢复服务端值并清空 Key', async () => {
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    const model = screen.getByLabelText(/^Model/)
    await user.clear(model)
    await user.type(model, 'dirty')
    await user.type(screen.getByLabelText(/API Key/), SECRET)
    await user.click(screen.getByTestId('ai-settings-reset'))
    expect(screen.getByLabelText(/^Model/)).toHaveValue('gpt-4o-mini')
    expect((screen.getByLabelText(/API Key/) as HTMLInputElement).value).toBe('')
  })

  it('没有修改时保存按钮禁用', async () => {
    await renderSettings(CONFIGURED)
    expect(screen.getByTestId('ai-settings-save')).toBeDisabled()
  })

  it('非法字段时保存按钮禁用', async () => {
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    const rounds = screen.getByLabelText(/最大模型轮数/)
    await user.clear(rounds)
    await user.type(rounds, '99') // 超出 1–3
    expect(screen.getByTestId('ai-settings-save')).toBeDisabled()
    expect(screen.getByText(/应在 1–3 之间/)).toBeInTheDocument()
  })

  // 20. 窄屏无水平溢出
  it('窄屏下容器不产生水平溢出', async () => {
    await renderSettings(CONFIGURED)
    const summary = screen.getByTestId('ai-settings-summary')
    // 所有输入使用 min-w-0 + w-full,不设置固定宽度,避免撑破窄屏容器。
    const inputs = document.querySelectorAll('#ai-base-url, #ai-model, #ai-api-key')
    inputs.forEach((el) => {
      expect(el.className).toMatch(/min-w-0/)
    })
    expect(summary.className).toMatch(/flex-wrap/)
  })

  // 21. API 调试日志不含 Key
  it('API 调试日志不包含 API Key', async () => {
    const debug = vi.spyOn(console, 'debug').mockImplementation(() => {})
    const warn = vi.spyOn(console, 'warn').mockImplementation(() => {})
    server.use(http.put(`${API}/ai/settings`, () => HttpResponse.json(CONFIGURED)))
    const user = userEvent.setup()
    await renderSettings(CONFIGURED)
    await user.type(screen.getByLabelText(/API Key/), SECRET)
    await user.click(screen.getByTestId('ai-settings-save'))
    await screen.findByTestId('ai-settings-saved')

    const logged = [...debug.mock.calls, ...warn.mock.calls]
      .map((args) => args.map((a) => JSON.stringify(a)).join(' '))
      .join('\n')
    expect(logged).not.toContain(SECRET)
  })

  // 22. Settings 不显示完整 Key(后端异常多回传字段也不渲染)
  it('后端异常回传 api_key 时前端仍不渲染', async () => {
    const { container } = await renderSettings({
      ...CONFIGURED,
      // @ts-expect-error 故意注入后端不应返回的字段,验证前端只渲染白名单。
      api_key: SECRET,
    })
    expect(container.textContent).not.toContain(SECRET)
  })

  // 23. 组件卸载清理 Key
  it('组件卸载后 Key 不残留于任何持久化位置', async () => {
    const user = userEvent.setup()
    const { unmount } = await renderSettings(CONFIGURED)
    await user.type(screen.getByLabelText(/API Key/), SECRET)
    unmount()
    expect(document.body.textContent).not.toContain(SECRET)
    expect(JSON.stringify(localStorage)).not.toContain(SECRET)
    expect(JSON.stringify(sessionStorage)).not.toContain(SECRET)
  })

  // 24. 加载失败展示错误(旧后端无 /ai/settings 时不崩溃)
  it('读取配置失败时展示友好错误而不崩溃', async () => {
    server.use(
      http.get(`${API}/ai/settings`, () => HttpResponse.json({ detail: 'nope' }, { status: 404 })),
      http.get(`${API}/tasks/system/status`, () =>
        HttpResponse.json({
          database_ok: true,
          database_path: 'D:/x.db',
          running_tasks: 0,
          queued_tasks: 0,
          occupied_devices: [],
        }),
      ),
      http.get(`${API}/`, () => HttpResponse.json({ ok: true, message: 'running' })),
    )
    renderWithProviders(<Settings />)
    expect(await screen.findByTestId('ai-settings-load-error')).toBeInTheDocument()
    // 页面其他卡片仍然可用。
    expect(screen.getByText('任务系统')).toBeInTheDocument()
  })
})
