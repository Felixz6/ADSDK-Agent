import { beforeEach, describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import userEvent, { type UserEvent } from '@testing-library/user-event'
import NewAnalysis from './NewAnalysis'
import { renderWithProviders } from '@/test/render'
import { server } from '@/test/msw-server'

const API = 'http://127.0.0.1:8000'

beforeEach(() => {
  localStorage.clear()
  server.use(
    http.post(`${API}/tasks`, async () =>
      HttpResponse.json({ id: 'task-static', status: 'queued' }, { status: 202 }),
    ),
    http.get(`${API}/env/check`, () =>
      HttpResponse.json({
        checks: {},
        details: { device: { devices: [], online_count: 0 } },
      }),
    ),
  )
})

async function reachInput(user: UserEvent) {
  await user.click(screen.getByRole('button', { name: /下一步/ }))
  return screen.findByLabelText(/APK 路径/)
}

async function reachStaticSubmit(user: UserEvent, apkPath: string) {
  const pathInput = await reachInput(user)
  await user.type(pathInput, apkPath)
  await user.click(screen.getByRole('button', { name: /下一步/ }))
  await user.click(screen.getByRole('button', { name: /下一步/ }))
}

async function reachDynamicSubmit(user: UserEvent, apkPath: string, deviceId = '127.0.0.1:16416') {
  await user.click(screen.getByLabelText(/动态分析/))
  const pathInput = await reachInput(user)
  await user.type(pathInput, apkPath)
  await user.click(screen.getByRole('button', { name: /下一步/ }))
  const device = await screen.findByLabelText(/目标设备/)
  await user.type(device, deviceId)
  await user.click(screen.getByRole('button', { name: /下一步/ }))
}

describe('NewAnalysis — 持久化任务提交', () => {
  it('APK 路径为空时阻止继续', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachInput(user)
    expect(screen.getByRole('button', { name: /下一步/ })).toBeDisabled()
  })

  it('静态提交调用 POST /tasks 并进入任务详情', async () => {
    let received: Record<string, unknown> | undefined
    server.use(
      http.post(`${API}/tasks`, async ({ request }) => {
        received = await request.json() as Record<string, unknown>
        return HttpResponse.json({ id: 'task-static', status: 'queued' }, { status: 202 })
      }),
    )
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await reachStaticSubmit(user, 'D:/authorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交后台任务/ }))

    await vi.waitFor(() => expect(router.state.location.pathname).toBe('/tasks/task-static'))
    expect(received).toMatchObject({
      task_type: 'static',
      apk_path: 'D:/authorized/sample.apk',
    })
    expect(await screen.findByText(/任务已进入后台队列/)).toBeInTheDocument()
  })

  it('请求挂起时显示真实创建状态并禁用提交按钮', async () => {
    let resolvePost!: () => void
    server.use(
      http.post(`${API}/tasks`, () =>
        new Promise<void>((resolve) => { resolvePost = resolve })
          .then(() => HttpResponse.json({ id: 'task-pending', status: 'queued' }, { status: 202 })),
      ),
    )
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await reachStaticSubmit(user, 'D:/authorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交后台任务/ }))

    expect(await screen.findByRole('button', { name: /正在创建任务/ })).toBeDisabled()
    resolvePost()
  })

  it('后端结构化校验错误原样展示且停留在向导', async () => {
    server.use(
      http.post(`${API}/tasks`, () =>
        HttpResponse.json(
          { detail: { code: 'invalid_apk_path', message: 'APK 路径不在允许根目录内' } },
          { status: 422 },
        ),
      ),
    )
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await reachStaticSubmit(user, 'D:/unauthorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交后台任务/ }))

    expect(await screen.findByText('APK 路径不在允许根目录内')).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/')
  })

  it('后端不可达时显示连接诊断且不伪造任务', async () => {
    server.use(http.post(`${API}/tasks`, () => HttpResponse.error()))
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await reachStaticSubmit(user, 'D:/authorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交后台任务/ }))

    expect(await screen.findByText(/无法连接到 AdSDK Agent 后端/)).toBeInTheDocument()
    expect(router.state.location.pathname).toBe('/')
  })

  it('动态提交携带显式设备与采集参数', async () => {
    let received: Record<string, unknown> | undefined
    server.use(
      http.post(`${API}/tasks`, async ({ request }) => {
        received = await request.json() as Record<string, unknown>
        return HttpResponse.json({ id: 'task-dynamic', status: 'queued' }, { status: 202 })
      }),
    )
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await reachDynamicSubmit(user, 'D:/authorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交后台任务/ }))

    await vi.waitFor(() => expect(router.state.location.pathname).toBe('/tasks/task-dynamic'))
    expect(received).toMatchObject({
      task_type: 'dynamic',
      device_id: '127.0.0.1:16416',
      enable_traffic: true,
      pre_consent_seconds: 10,
      post_consent_seconds: 10,
    })
  })
})
