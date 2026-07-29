import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'
import { DynamicReliabilityCard } from './DynamicReliabilityCard'
import type { FridaDiagnosticsResponse } from '@/types/api'

function diagnostics(
  overall_status: FridaDiagnosticsResponse['overall_status'],
): FridaDiagnosticsResponse {
  const section = {
    status: overall_status === 'ready' ? 'pass' as const : overall_status === 'degraded' ? 'warning' as const : 'error' as const,
    checks: {},
  }
  return {
    schema_version: 'frida-diagnostics-v1',
    overall_status,
    recommended_mode: overall_status === 'ready' ? 'spawn_suspended' : overall_status === 'degraded' ? 'attach_existing' : 'none',
    host: section,
    device: section,
    server: section,
    transport: section,
    target: section,
    issues: overall_status === 'ready' ? [] : [{
      code: 'frida_server_transport_unreachable',
      severity: overall_status === 'degraded' ? 'warning' : 'blocking',
      summary: 'transport',
      detail: 'transport',
      remediation: '检查服务进程和版本',
      evidence_available: true,
    }],
    remediations: [],
    checked_at: '2026-07-29T00:00:00Z',
    duration_ms: 20,
    device_ref: 'redacted:abc',
    management_enabled: false,
  }
}

describe('DynamicReliabilityCard', () => {
  it.each([
    ['ready', '就绪'],
    ['degraded', '降级可用'],
    ['blocked', '阻塞'],
    ['error', '检测失败'],
  ] as const)('renders %s readiness as %s', (state, label) => {
    render(<DynamicReliabilityCard diagnostics={diagnostics(state)} />)
    expect(screen.getAllByText(label).length).toBeGreaterThan(0)
  })

  it('does not turn an absent legacy field into success', () => {
    render(<DynamicReliabilityCard />)
    expect(screen.getByText(/尚未检测/)).toBeInTheDocument()
    expect(screen.queryByText('就绪')).not.toBeInTheDocument()
  })

  it('shows fallback attempts and evidence limitations', () => {
    render(
      <DynamicReliabilityCard
        execution={{
          policy: 'balanced',
          selected_mode: 'attach_existing',
          fallback_path: ['attach_existing'],
          attempts: [
            { mode: 'spawn_suspended', status: 'failed', reason_code: 'spawn_failed', message: 'failed' },
            { mode: 'attach_existing', status: 'success', message: 'ok' },
          ],
        }}
        evidence={{
          schema_version: 'dynamic-evidence-quality-v1',
          level: 'C',
          mode: 'attach_existing',
          coverage: ['Hook 就绪后的事件'],
          limitations: ['无法证明应用启动阶段行为完整'],
          trusted_capabilities: ['结构化事件'],
          untrusted_capabilities: ['启动阶段'],
          reason_codes: ['spawn_failed'],
        }}
      />,
    )
    expect(screen.getByText('证据 C 级')).toBeInTheDocument()
    expect(screen.getByText(/启动前 Hook 模式执行失败/)).toBeInTheDocument()
    expect(screen.getByText('无法证明应用启动阶段行为完整')).toBeInTheDocument()
  })

  it('explains zero requests and only labels pinning as suspected', () => {
    render(
      <DynamicReliabilityCard
        traffic={{
          outcome: 'collector_success_zero_requests',
          proxy_status: 'restored',
          pinning_suspected: true,
          request_count: 0,
          limitations: [],
        }}
      />,
    )
    expect(screen.getByText(/零请求不代表应用没有网络行为/)).toBeInTheDocument()
    expect(screen.getByText(/疑似 Pinning/)).toBeInTheDocument()
    expect(screen.queryByText('检测到 Pinning')).not.toBeInTheDocument()
  })
})
