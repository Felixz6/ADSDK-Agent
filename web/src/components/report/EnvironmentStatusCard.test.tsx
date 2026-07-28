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

const ROW = (matcher: RegExp | string) =>
  screen.getByText(matcher).closest('div.flex') as HTMLElement

describe('EnvironmentStatusCard — 五态显示', () => {
  it('后端返回 true 的项展示为「正常」并带绿色对勾', () => {
    render(<EnvironmentStatusCard env={makeEnv()} />)
    const okRow = ROW('ADB 工具')
    expect(okRow).toHaveTextContent('正常')
    expect(okRow!.querySelector('[aria-label="正常"]')).not.toBeNull()
  })

  it('后端返回 false 的项展示为「异常」并带红色叉,而非「正常」', () => {
    render(<EnvironmentStatusCard env={makeEnv({ frida_connectable: false })} />)
    const fridaRow = ROW(/Frida 连接/)
    expect(fridaRow).toHaveTextContent('异常')
    expect(fridaRow!.querySelector('[aria-label="异常"]')).not.toBeNull()
    expect(fridaRow!.querySelector('[aria-label="正常"]')).toBeNull()
  })

  it('后端「未提供」的项(apktool / REDACTION_HMAC_KEY 等)展示为「未提供」并带减号,绝不展示为「正常」', () => {
    render(<EnvironmentStatusCard env={makeEnv()} />)
    const apktoolRow = ROW('apktool')
    expect(apktoolRow).toHaveTextContent('未提供')
    expect(apktoolRow!.querySelector('[aria-label="未提供"]')).not.toBeNull()
    expect(apktoolRow!.querySelector('[aria-label="正常"]')).toBeNull()
    const keyRow = ROW('REDACTION_HMAC_KEY')
    expect(keyRow).toHaveTextContent('未提供')
    expect(keyRow).not.toHaveTextContent('正常')
    expect(keyRow!.querySelector('[aria-label="正常"]')).toBeNull()
  })

  it('后端不可达(env=null)时所有项展示为「无法检测」,绝不展示为「正常」「异常」', () => {
    render(<EnvironmentStatusCard env={null} />)
    const adbRow = ROW('ADB 工具')
    expect(adbRow).toHaveTextContent('无法检测')
    expect(adbRow!.querySelector('[aria-label="无法检测"]')).not.toBeNull()
  })
})

describe('EnvironmentStatusCard — apktool / Frida Python / 配置项实状态', () => {
  it('apktool 未安装(missing)展示「未配置」,而非「异常」或「正常」', () => {
    const env = makeEnv(
      { apktool_available: false },
      false,
    )
    env.details.apktool = {
      apktool_available: false,
      apktool_version: null,
      apktool_path: null,
      apktool_error: 'apktool not found on PATH',
    }
    render(<EnvironmentStatusCard env={env} />)
    const row = ROW('apktool')
    expect(row).toHaveTextContent('未配置')
    expect(row).not.toHaveTextContent('正常')
    expect(row).not.toHaveTextContent('异常')
  })

  it('apktool 已安装且 --version 成功展示「正常」并带版本', () => {
    const env = makeEnv({ apktool_available: true }, true)
    env.details.apktool = {
      apktool_available: true,
      apktool_version: 'apktool 2.11.1',
      apktool_path: 'apktool.bat',
      apktool_error: null,
    }
    render(<EnvironmentStatusCard env={env} />)
    const row = ROW('apktool')
    expect(row).toHaveTextContent('正常')
    expect(row).toHaveTextContent('2.11.1')
  })

  it('apktool 在 PATH 但 --version 失败展示「无法检测」', () => {
    const env = makeEnv({}, false)
    env.details.apktool = {
      apktool_available: true,
      apktool_version: null,
      apktool_path: 'apktool',
      apktool_error: 'java not found',
    }
    render(<EnvironmentStatusCard env={env} />)
    const row = ROW('apktool')
    expect(row).toHaveTextContent('无法检测')
    expect(row).not.toHaveTextContent('正常')
  })

  it('Frida Python 包未安装展示「异常」,与 frida-server 连通性分离', () => {
    const env = makeEnv({ frida_connectable: true, frida_python_available: false }, false)
    env.details.frida_python = {
      frida_python_available: false,
      frida_python_version: null,
      frida_python_error: 'frida package not importable',
      frida_python_error_detail: "No module named 'frida'",
    }
    render(<EnvironmentStatusCard env={env} />)
    const pyRow = ROW('Frida Python 包')
    expect(pyRow).toHaveTextContent('异常')
    // frida-server 连通行仍由 frida_connectable=true ⇒ 正常,显示包与 server 是两态
    expect(pyRow).not.toHaveTextContent('正常')
  })

  it('Frida Python 包已安装展示「正常」并带版本', () => {
    const env = makeEnv({ frida_python_available: true }, true)
    env.details.frida_python = {
      frida_python_available: true,
      frida_python_version: '16.7.19',
      frida_python_error: null,
      frida_python_error_detail: null,
    }
    render(<EnvironmentStatusCard env={env} />)
    expect(ROW('Frida Python 包')).toHaveTextContent('正常')
    expect(ROW('Frida Python 包')).toHaveTextContent('16.7.19')
  })
})

describe('EnvironmentStatusCard — REDACTION_HMAC_KEY 隐私不变量', () => {
  const SECRET = 'a-very-long-private-random-secret-please-rotate-me-123'

  it('密钥安全配置(secure)展示「正常」,但绝不回显密钥原值', () => {
    const env = makeEnv({ redaction_hmac_key_secure: true }, true)
    env.details.redaction_hmac_key = {
      redaction_hmac_key_configured: true,
      redaction_hmac_key_uses_placeholder: false,
      redaction_hmac_key_security_status: 'secure',
    }
    const { container } = render(<EnvironmentStatusCard env={env} />)
    const row = ROW('REDACTION_HMAC_KEY')
    expect(row).toHaveTextContent('正常')
    // 即使后端在某处返回了原值,卡片也绝不能把它渲染出来。
    expect(container.textContent).not.toContain(SECRET)
  })

  it('密钥使用占位值(placeholder)展示「异常」,提示替换', () => {
    const env = makeEnv({ redaction_hmac_key_secure: false }, false)
    env.details.redaction_hmac_key = {
      redaction_hmac_key_configured: true,
      redaction_hmac_key_uses_placeholder: true,
      redaction_hmac_key_security_status: 'placeholder',
    }
    render(<EnvironmentStatusCard env={env} />)
    const row = ROW('REDACTION_HMAC_KEY')
    expect(row).toHaveTextContent('异常')
    expect(row).not.toHaveTextContent('正常')
  })

  it('密钥未配置(missing)展示「未配置」', () => {
    const env = makeEnv({}, false)
    env.details.redaction_hmac_key = {
      redaction_hmac_key_configured: false,
      redaction_hmac_key_uses_placeholder: true,
      redaction_hmac_key_security_status: 'missing',
    }
    render(<EnvironmentStatusCard env={env} />)
    expect(ROW('REDACTION_HMAC_KEY')).toHaveTextContent('未配置')
  })

  it('APK_ALLOWED_ROOTS 已配置展示「正常」并带根目录数目/路径', () => {
    const env = makeEnv({ apk_allowed_roots_configured: true }, true)
    env.details.apk_allowed_roots = ['/data/samples', '/data/apks']
    render(<EnvironmentStatusCard env={env} />)
    const row = ROW('APK_ALLOWED_ROOTS')
    expect(row).toHaveTextContent('正常')
    expect(row).toHaveTextContent('2 个允许根目录')
  })

  it('APK_ALLOWED_ROOTS 为空数组展示「未配置」', () => {
    const env = makeEnv({ apk_allowed_roots_configured: false }, false)
    env.details.apk_allowed_roots = []
    render(<EnvironmentStatusCard env={env} />)
    expect(ROW('APK_ALLOWED_ROOTS')).toHaveTextContent('未配置')
  })

  it('APK_ALLOWED_ROOTS 字段缺失展示「未提供」', () => {
    render(<EnvironmentStatusCard env={makeEnv()} />)
    expect(ROW('APK_ALLOWED_ROOTS')).toHaveTextContent('未提供')
  })
})

describe('EnvironmentStatusCard — 流量自检独立文案', () => {
  it('未发起自检(trafficTriggered=false)展示「尚未检测」,而非「无法检测」或「未提供」', () => {
    render(<EnvironmentStatusCard env={makeEnv()} trafficTriggered={false} />)
    const row = ROW('流量捕获自检')
    expect(row).toHaveTextContent('尚未检测')
    expect(row).not.toHaveTextContent('未提供')
  })

  it('旧用法不传 trafficTriggered 时也回退为「尚未检测」(向后兼容)', () => {
    render(<EnvironmentStatusCard env={makeEnv()} traffic={null} />)
    expect(ROW('流量捕获自检')).toHaveTextContent('尚未检测')
  })

  it('已发起但无数据(trafficTriggered + traffic=null 且 env 在)展示「无法检测」', () => {
    render(<EnvironmentStatusCard env={makeEnv()} traffic={null} trafficTriggered />)
    expect(ROW('流量捕获自检')).toHaveTextContent('无法检测')
  })

  it('流量自检失败(captured_success=false)展示「异常」', () => {
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
    render(<EnvironmentStatusCard env={makeEnv()} traffic={traffic} trafficTriggered />)
    const row = ROW('流量捕获自检')
    expect(row).toHaveTextContent('异常')
    expect(row!.querySelector('[aria-label="异常"]')).not.toBeNull()
  })

  it('流量自检成功展示「正常」', () => {
    const traffic = {
      ok: true,
      device_id: '<redacted>',
      captured_success: true,
      captured_request_count: 5,
      flow_file_size: 1024,
      possible_reasons: [],
      mitm_status: { has_last_session: true, running: true, owned_by_session: true, pid: 1, port: 8080, port_listening: true, traffic_dir: '/out' },
      sample_requests: [],
    } as TrafficCheckResponse
    render(<EnvironmentStatusCard env={makeEnv()} traffic={traffic} trafficTriggered />)
    expect(ROW('流量捕获自检')).toHaveTextContent('正常')
  })
})

describe('EnvironmentStatusCard — 隐私不变量', () => {
  it('不展示原始设备序列号等敏感标识于检测项说明', () => {
    render(<EnvironmentStatusCard env={makeEnv()} />)
    const card = document.body
    expect(card.textContent).not.toMatch(/serial|cookie|authorization/i)
    expect(card.textContent).not.toMatch(/[0-9A-Fa-f]{16,}/)
  })
})
