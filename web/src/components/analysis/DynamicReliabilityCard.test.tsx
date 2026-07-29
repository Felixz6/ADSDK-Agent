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
    capabilities: {
      transport_available: true,
      process_enumeration_available: true,
      attach_available: true,
      spawn_creation_available: true,
      spawn_resume_stable: false,
    },
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

const execution = {
  policy: 'balanced' as const,
  selected_mode: 'launch_then_attach' as const,
  fallback_path: ['launch_then_attach'],
  attempts: [
    {
      mode: 'spawn_suspended' as const,
      status: 'failed' as const,
      reason_code: 'spawn_runtime_failed',
      message: 'runtime crash',
      phase: 'post_resume_stability',
      process_result: 'process_crashed',
      post_resume_survival_ms: 980,
    },
    {
      mode: 'launch_then_attach' as const,
      status: 'success' as const,
      message: 'collecting',
      phase: 'collecting',
      process_result: 'running',
    },
  ],
  launch_timing: { startup_gap_ms: 120 },
}

const evidence = {
  schema_version: 'dynamic-evidence-quality-v1' as const,
  level: 'C' as const,
  mode: 'launch_then_attach' as const,
  coverage: ['Hook 就绪后的运行时事件'],
  limitations: ['正常启动到 Attach 完成之间存在启动覆盖间隙'],
  trusted_capabilities: ['结构化事件'],
  untrusted_capabilities: ['最早启动阶段'],
  reason_codes: ['spawn_runtime_failed'],
}

const nativeCrash = {
  status: 'process_crashed',
  duration_ms: 980,
  most_likely_cause: '应用在 suspended spawn 恢复后发生原生崩溃，崩溃栈涉及 MuMu Native Bridge 与 MMKV。',
  reason_code: 'native_bridge_compatibility_suspected',
  crash_type: 'native_sigsegv',
  signal: 'SIGSEGV',
  signal_code: 'SEGV_ACCERR',
  summary: 'trying to execute non-executable memory',
  suspected_components: ['libhoudini.so', 'libhp15_x86_64.so', 'MMKV'],
  native_frames: ['#00 pc 00 libhoudini.so', '#01 pc 01 libhp15_x86_64.so'],
  confidence: 'high' as const,
}

describe('DynamicReliabilityCard', () => {
  it('separates environment capabilities from task result', () => {
    render(
      <DynamicReliabilityCard
        diagnostics={diagnostics('ready')}
        execution={execution}
        process={nativeCrash}
      />,
    )
    expect(screen.getByRole('region', { name: '环境能力' })).toBeInTheDocument()
    expect(screen.getByRole('region', { name: '本次采集结果' })).toBeInTheDocument()
    expect(screen.getByText('通信就绪')).toBeInTheDocument()
    expect(screen.getByText('当前样本不兼容')).toBeInTheDocument()
  })

  it('shows structured native crash summary and components', () => {
    render(<DynamicReliabilityCard process={nativeCrash} />)
    expect(screen.getByText('Native 崩溃摘要')).toBeInTheDocument()
    expect(screen.getByText('SIGSEGV / SEGV_ACCERR')).toBeInTheDocument()
    expect(screen.getByText('libhoudini.so, libhp15_x86_64.so, MMKV')).toBeInTheDocument()
  })

  it('shows suspended spawn failure at post-resume stability phase', () => {
    render(<DynamicReliabilityCard execution={execution} />)
    expect(screen.getByText(/恢复稳定窗口/)).toBeInTheDocument()
    expect(screen.getByText(/恢复后存活 980 ms/)).toBeInTheDocument()
  })

  it('keeps the complete balanced attempt chain', () => {
    render(<DynamicReliabilityCard execution={execution} />)
    expect(screen.getByText(/spawn_suspended/)).toBeInTheDocument()
    expect(screen.getAllByText(/launch_then_attach/).length).toBeGreaterThan(0)
    expect(screen.getByText(/正常启动至附加完成间隙：120 ms/)).toBeInTheDocument()
  })

  it('shows attach or launch-attach grade C limitations', () => {
    render(<DynamicReliabilityCard execution={execution} evidence={evidence} />)
    expect(screen.getByText('证据 C 级')).toBeInTheDocument()
    expect(screen.getByText('正常启动到 Attach 完成之间存在启动覆盖间隙')).toBeInTheDocument()
  })

  it('treats application-requested detach as normal cleanup', () => {
    render(
      <DynamicReliabilityCard
        process={{
          status: 'normal_cleanup',
          detached_reason: 'application-requested',
          most_likely_cause: '会话由采集流程主动分离，属于正常清理',
        }}
      />,
    )
    expect(screen.queryByText('Native 崩溃摘要')).not.toBeInTheDocument()
    expect(screen.queryByText(/进程：/)).not.toBeInTheDocument()
  })

  it('collapses the full backtrace by default', () => {
    render(<DynamicReliabilityCard process={nativeCrash} />)
    const summary = screen.getByText(/完整 Native backtrace/)
    expect(summary.closest('details')).not.toHaveAttribute('open')
    expect(screen.getByText('#00 pc 00 libhoudini.so', { exact: false })).toBeInTheDocument()
  })

  it('uses the bounded Chinese compatibility diagnosis', () => {
    render(<DynamicReliabilityCard process={nativeCrash} />)
    expect(screen.getByText(/MuMu Native Bridge 与 MMKV/)).toBeInTheDocument()
    expect(screen.getByText('native_bridge_compatibility_suspected')).toBeInTheDocument()
  })

  it('keeps old reports with absent reliability fields neutral', () => {
    render(<DynamicReliabilityCard />)
    expect(screen.getByText(/尚未检查/)).toBeInTheDocument()
    expect(screen.queryByText('通信就绪')).not.toBeInTheDocument()
  })

  it('does not describe a task crash as an unavailable Frida environment', () => {
    render(
      <DynamicReliabilityCard
        diagnostics={diagnostics('ready')}
        process={nativeCrash}
      />,
    )
    expect(screen.getByText('通信就绪')).toBeInTheDocument()
    expect(screen.queryByText('Frida 服务不可用')).not.toBeInTheDocument()
  })
})
