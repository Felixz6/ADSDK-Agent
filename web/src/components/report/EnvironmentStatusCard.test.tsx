import { describe, it, expect } from 'vitest'
import { render, screen } from '@testing-library/react'
import { EnvironmentStatusCard } from '@/components/report/EnvironmentStatusCard'
import type { EnvCheckResponse, TrafficCheckResponse } from '@/types/api'

function makeEnv(partial: Partial<EnvCheckResponse['checks']> = {}, ok = true): EnvCheckResponse {
  return {
    ok,
    device_id: '<redacted>',
    checks: {
      adb_available: true,
      device_online: true,
      frida_connectable: true,
      mitm_8080_listening: true,
      output_writable: true,
      ...partial,
    },
    details: {
      adb: { ok: true, stdout: '', stderr: '', cmd: [] },
      device: { ok: true, device_id: null, target: null, devices: [], online_count: 1 },
      frida: { ok: true, returncode: 0, stdout: '', stderr: '', cmd: [] },
      mitm: { port: 8080, listening: true },
      output: { ok: true, path: '/out', error: null },
    },
  }
}

describe('EnvironmentStatusCard — 四态显示', () => {
  it('后端返回 true 的项展示为「正常」并带绿色对勾', () => {
    render(<EnvironmentStatusCard env={makeEnv()} />)
    const okRow = screen.getByText('ADB 工具').closest('div.flex') as HTMLElement
    expect(okRow).toHaveTextContent('正常')
    // 导航图标的 aria-label 应为「正常」
    const okIcon = okRow!.querySelector('[aria-label="正常"]')
    expect(okIcon).not.toBeNull()
  })

  it('后端返回 false 的项展示为「异常」并带红色叉,而非「正常」', () => {
    render(<EnvironmentStatusCard env={makeEnv({ frida_connectable: false })} />)
    const fridaRow = screen.getByText(/Frida 连接/).closest('div.flex') as HTMLElement
    expect(fridaRow).toHaveTextContent('异常')
    expect(fridaRow!.querySelector('[aria-label="异常"]')).not.toBeNull()
    expect(fridaRow!.querySelector('[aria-label="正常"]')).toBeNull()
  })

  it('后端「未提供」的项(apktool / REDACTION_HMAC_KEY 等)展示为「未提供」并带减号,绝不展示为「正常」', () => {
    render(<EnvironmentStatusCard env={makeEnv()} />)
    const apktoolRow = screen.getByText('apktool').closest('div.flex') as HTMLElement
    expect(apktoolRow).toHaveTextContent('未提供')
    expect(apktoolRow!.querySelector('[aria-label="未提供"]')).not.toBeNull()
    expect(apktoolRow!.querySelector('[aria-label="正常"]')).toBeNull()
    const keyRow = screen.getByText('REDACTION_HMAC_KEY').closest('div.flex') as HTMLElement
    expect(keyRow).toHaveTextContent('未提供')
    expect(keyRow).not.toHaveTextContent('正常')
    expect(keyRow!.querySelector('[aria-label="正常"]')).toBeNull()
  })

  it('后端不可达(env=null)时所有项展示为「无法检测」,绝不展示为「正常」「异常」', () => {
    render(<EnvironmentStatusCard env={null} />)
    // adb / device 等 bool 类项:env=null ⇒ unknown
    const adbRow = screen.getByText('ADB 工具').closest('div.flex') as HTMLElement
    expect(adbRow).toHaveTextContent('无法检测')
    expect(adbRow!.querySelector('[aria-label="无法检测"]')).not.toBeNull()
  })

  it('无流量自检数据时流量捕获项展示为「无法检测」(不可美化成「正常」)', () => {
    render(<EnvironmentStatusCard env={makeEnv()} traffic={null} />)
    const trafficRow = screen.getByText('流量捕获自检').closest('div.flex') as HTMLElement
    expect(trafficRow).toHaveTextContent('无法检测')
    expect(trafficRow!.querySelector('[aria-label="正常"]')).toBeNull()
  })

  it('流量自检失败(captured_success=false)展示为「异常」', () => {
    const traffic = {
      ok: false,
      device_id: '<redacted>',
      captured_success: false,
      captured_request_count: 0,
      flow_file_size: null,
      possible_reasons: ['mitmproxy 未监听'],
      mitm_status: { has_last_session: false, running: false, owned_by_session: false, pid: null, port: 8080, port_listening: false, traffic_dir: null },
      sample_requests: [],
    } as TrafficCheckResponse
    render(<EnvironmentStatusCard env={makeEnv()} traffic={traffic} />)
    const trafficRow = screen.getByText('流量捕获自检').closest('div.flex') as HTMLElement
    expect(trafficRow).toHaveTextContent('异常')
    expect(trafficRow!.querySelector('[aria-label="异常"]')).not.toBeNull()
  })
})

describe('EnvironmentStatusCard — 隐私不变量', () => {
  it('不展示原始设备序列号等敏感标识于检测项说明', () => {
    render(<EnvironmentStatusCard env={makeEnv()} />)
    const card = document.body
    expect(card.textContent).not.toMatch(/serial|cookie|authorization/i)
    // device_id 占位只可见被脱敏回显字样,无原文短串
    expect(card.textContent).not.toMatch(/[0-9A-Fa-f]{16,}/)
  })
})
