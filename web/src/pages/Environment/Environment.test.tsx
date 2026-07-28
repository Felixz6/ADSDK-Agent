import { describe, it, expect, beforeEach } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Environment from './Environment'
import { renderWithProviders } from '@/test/render'
import { server } from '@/test/msw-server'
import type { EnvCheckResponse, TrafficCheckResponse } from '@/types/api'

const ENV_OK: EnvCheckResponse = {
  ok: true,
  device_id: '<redacted>',
  checks: {
    adb_available: true,
    device_online: true,
    frida_connectable: false,
    mitm_8080_listening: true,
    output_writable: true,
  },
  details: {
    adb: { ok: true, stdout: '', stderr: '', cmd: ['adb'] },
    device: { ok: true, device_id: null, target: null, devices: [], online_count: 1 },
    frida: { ok: false, returncode: 1, stdout: '', stderr: 'no', cmd: [] },
    mitm: { port: 8080, listening: true },
    output: { ok: true, path: '/out', error: null },
  },
}

const ENV_FAIL: EnvCheckResponse = {
  ok: false,
  device_id: '<redacted>',
  checks: {
    adb_available: true,
    device_online: false,
    frida_connectable: false,
    mitm_8080_listening: false,
    output_writable: false,
  },
  details: {
    adb: { ok: true, stdout: '', stderr: '', cmd: ['adb'] },
    device: { ok: false, device_id: null, target: null, devices: [], online_count: 0 },
    frida: { ok: false, returncode: null, stdout: '', stderr: '', cmd: [] },
    mitm: { port: 8080, listening: false },
    output: { ok: false, path: '/out', error: 'EACCES' },
  },
}

beforeEach(() => {
  server.use(
    http.get('http://127.0.0.1:8000/env/check', () => HttpResponse.json(ENV_OK)),
    http.get('http://127.0.0.1:8000/traffic/check', () =>
      HttpResponse.json({
        ok: false,
        device_id: '<redacted>',
        captured_success: false,
        captured_request_count: 0,
        flow_file_size: null,
        possible_reasons: [],
        mitm_status: { has_last_session: false, running: false, owned_by_session: false, pid: null, port: 8080, port_listening: false, traffic_dir: null },
        sample_requests: [],
      } as TrafficCheckResponse),
    ),
  )
})

describe('Environment 页 — 检测项四态展示', () => {
  it('Frida 异常时该项展示「异常」,ADB 正常时展示「正常」', async () => {
    renderWithProviders(<Environment />)
    // 等 env 加载完成
    expect(await screen.findByText('在线设备 1 台。')).toBeInTheDocument()
    // Frida 连接:check=false ⇒ 「异常」(detail「连接失败」唯一指向状态卡片行)
    const fridaRow = screen.getByText('连接失败').closest('div.flex') as HTMLElement
    expect(fridaRow).toHaveTextContent('异常')
    // ADB:check=true ⇒ 「正常」(detail「可用」唯一指向 ADB 状态卡片行)
    const adbRow = screen.getByText('可用').closest('div.flex') as HTMLElement
    expect(adbRow).toHaveTextContent('正常')
  })

  it('未提供项(apktool)始终显示「未提供」,不会被美化成「正常」', async () => {
    renderWithProviders(<Environment />)
    expect(await screen.findByText('在线设备 1 台。')).toBeInTheDocument()
    const apktoolRow = screen.getByText('apktool').closest('div.flex') as HTMLElement
    expect(apktoolRow).toHaveTextContent('未提供')
    expect(apktoolRow).not.toHaveTextContent('正常')
  })

  it('后端整体为 false 时,mitm/output 异常项展示「异常」,不被美化成「正常」', async () => {
    server.use(
      http.get('http://127.0.0.1:8000/env/check', () => HttpResponse.json(ENV_FAIL)),
    )
    renderWithProviders(<Environment />)
    // online_count=0 时 DeviceSelector 展示「当前未检测到在线设备」
    expect(await screen.findByText(/当前未检测到在线设备/)).toBeInTheDocument()
    const mitmRow = screen.getByText('mitmproxy / mitmdump 8080').closest('div.flex') as HTMLElement
    expect(mitmRow).toHaveTextContent('异常')
    expect(mitmRow).not.toHaveTextContent('正常')
  })

  it('点击「刷新」按钮触发 /env/check 重新请求', async () => {
    let calls = 0
    server.use(
      http.get('http://127.0.0.1:8000/env/check', () => {
        calls += 1
        return HttpResponse.json(ENV_OK)
      }),
    )
    const user = userEvent.setup()
    renderWithProviders(<Environment />)
    await screen.findByText('在线设备 1 台。')
    const firstCount = calls
    await user.click(screen.getByRole('button', { name: /刷新/ }))
    // 等待重取完成(refetch 后再次出现文案或 spin)
    await screen.findByText('在线设备 1 台。')
    expect(calls).toBeGreaterThan(firstCount)
    expect(calls).toBeGreaterThanOrEqual(2)
  })
})

describe('Environment 页 — 流量自检按需触发', () => {
  it('未点击前流量自检展示「尚未检测」,且不发起 /traffic/check', async () => {
    let trafficCalls = 0
    server.use(
      http.get('http://127.0.0.1:8000/traffic/check', () => {
        trafficCalls += 1
        return HttpResponse.json({
          ok: false,
          device_id: '<redacted>',
          captured_success: false,
          captured_request_count: 0,
          flow_file_size: null,
          possible_reasons: [],
          mitm_status: { has_last_session: false, running: false, owned_by_session: false, pid: null, port: 8080, port_listening: false, traffic_dir: null },
          sample_requests: [],
        } as TrafficCheckResponse)
      }),
    )
    renderWithProviders(<Environment />)
    await screen.findByText('在线设备 1 台。')
    const trafficRow = screen.getByText('流量捕获自检').closest('div.flex') as HTMLElement
    expect(trafficRow).toHaveTextContent('尚未检测')
    expect(trafficRow).not.toHaveTextContent('未提供')
    expect(trafficCalls).toBe(0)
  })

  it('点击「流量自检」后发起 /traffic/check 并展示结果', async () => {
    let trafficCalls = 0
    server.use(
      http.get('http://127.0.0.1:8000/traffic/check', () => {
        trafficCalls += 1
        return HttpResponse.json({
          ok: true,
          device_id: '<redacted>',
          captured_success: true,
          captured_request_count: 3,
          flow_file_size: 512,
          possible_reasons: [],
          mitm_status: { has_last_session: true, running: true, owned_by_session: true, pid: 1, port: 8080, port_listening: true, traffic_dir: '/out' },
          sample_requests: [],
        } as TrafficCheckResponse)
      }),
    )
    const user = userEvent.setup()
    renderWithProviders(<Environment />)
    await screen.findByText('在线设备 1 台。')
    // 「流量自检」按钮在 deviceId 为空时禁用;Environment 页面用 DeviceSelector,
    // 这里先输入一个设备序列号占位串(后端脱敏回显)再点击。
    const input = screen.getByPlaceholderText(/手动输入设备序列号|手动输入设备序列号·/)
    await user.type(input, 'emulator-5554')
    const button = screen.getByRole('button', { name: /流量自检/ })
    await user.click(button)
    expect(await screen.findByText('流量自检结果')).toBeInTheDocument()
    expect(trafficCalls).toBeGreaterThanOrEqual(1)
    const trafficRow = screen.getByText('流量捕获自检').closest('div.flex') as HTMLElement
    expect(trafficRow).toHaveTextContent('正常')
  })
})
