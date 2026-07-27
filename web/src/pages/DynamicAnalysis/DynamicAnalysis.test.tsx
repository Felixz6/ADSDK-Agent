import { describe, it, expect, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import DynamicAnalysis from './DynamicAnalysis'
import { renderWithProviders } from '@/test/render'
import { useAnalysisStore } from '@/stores/analysisStore'
import type { AnalyzeResponse } from '@/types/api'
import type { LocalTaskRecord } from '@/api/tasks'

beforeEach(() => {
  useAnalysisStore.getState().clear()
})

const taskStub: LocalTaskRecord = {
  local_id: 'local-dynamic-1',
  run_id: 'r-dynamic-1',
  kind: 'dynamic',
  apk_path: 'D:/authorized/demo.apk',
  package_name: 'com.example.demo',
  created_at: '2026-01-01T00:00:00Z',
  status: 'success',
  sdk_count: 0,
  has_report: true,
  report_md_path: null,
  artifacts_count: 0,
  error: null,
  error_code: null,
  summary: null,
}

function seedDynamic(resp: Partial<AnalyzeResponse> = {}) {
  const base: AnalyzeResponse = {
    ok: true,
    apk_path: 'D:/authorized/demo.apk',
    schema_version: '1.0',
    run_id: 'r-dynamic-1',
    apk_sha256: null,
    apk_snapshot: null,
    normalized_apk_name: 'demo',
    analysis_started_at: '2026-01-01T00:00:00Z',
    status: 'success',
    steps: [],
    warnings: [],
    device: null,
    artifacts: [],
    app_info: { package_name: 'com.example.demo' } as AnalyzeResponse['app_info'],
    sdk_count: 0,
    sdks: [],
    output_dir: '/out',
    hook_log: null,
    events_json: null,
    events_raw_jsonl: null,
    consent_time: null,
    traffic_dir: null,
    traffic_summary_json: null,
    traffic_jsonl: null,
    sessions_json: null,
    report_json: null,
    report_md: '# demo',
    dynamic_events: [],
    dynamic_findings: null,
    strict_dynamic_findings: null,
    traffic_summary: null,
    pre_consent_seconds: 10,
    post_consent_seconds: 10,
    enable_traffic: true,
    enable_ui_stimulation: false,
    collection_timeout_seconds: 300,
    collection_status: 'success',
    traffic_coverage: 'observed',
    dynamic_timeline: null,
    error: null,
    error_code: null,
    limitations: [],
  }
  const merged = { ...base, ...resp } as AnalyzeResponse
  useAnalysisStore.getState().setActive(merged, taskStub, 'dynamic')
  return merged
}

describe('DynamicAnalysis — 无活跃结果空态', () => {
  it('无结果时显示「尚未进行动态分析」与「新建分析」/「查看历史」入口', () => {
    renderWithProviders(<DynamicAnalysis />)
    expect(screen.getByText(/尚未进行动态分析/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /新建分析/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /查看历史/ })).toBeInTheDocument()
  })

  it('点击「新建分析」导航至 /analysis/new', async () => {
    const user = userEvent.setup()
    const { router } = renderWithProviders(<DynamicAnalysis />)
    await user.click(screen.getByRole('button', { name: /新建分析/ }))
    expect(router.state.location.pathname).toBe('/analysis/new')
  })
})

describe('DynamicAnalysis — 有结果时正确渲染,缺失后端字段以占位而非「正常」', () => {
  it('事件总数/同意前/同意后/时间不明 卡片计数正确', () => {
    seedDynamic({
      dynamic_events: [
        {
          type: 'event',
          event_id: 'e1',
          run_id: 'r-dynamic-1',
          session_id: 's1',
          timestamp_utc: '2026-01-01T00:00:01Z',
          monotonic_ms: 1000,
          pid: 1,
          process_name: 'demo',
          thread_id: 1,
          thread_name: 'main',
          category: 'privacy',
          api: 'getDeviceId',
          action: 'call',
          stack: [],
          metadata: {},
          consent_state: 'pre_consent',
          legacy_format: false,
          raw_retained: false as const,
          timing_reliable: true,
          protocol_version: '1',
          schema_version: '1',
        },
        {
          type: 'event',
          event_id: 'e2',
          run_id: 'r-dynamic-1',
          session_id: 's1',
          timestamp_utc: '2026-01-01T00:00:30Z',
          monotonic_ms: 30000,
          pid: 1,
          process_name: 'demo',
          thread_id: 1,
          thread_name: 'main',
          category: 'privacy',
          api: 'getString',
          action: 'call',
          stack: [],
          metadata: {},
          consent_state: 'post_consent',
          legacy_format: false,
          raw_retained: false as const,
          timing_reliable: true,
          protocol_version: '1',
          schema_version: '1',
        },
      ] as AnalyzeResponse['dynamic_events'],
    })
    renderWithProviders(<DynamicAnalysis />)
    expect(screen.getByText('事件总数')).toBeInTheDocument()
    // 事件总数 = 2(同意前 1 + 同意后 1)
    expect(screen.getAllByText('2').length).toBeGreaterThan(0)
  })

  it('后端缺失采集状态/流量覆盖度时以「—」占位,绝不显示为「正常」', () => {
    seedDynamic({
      collection_status: null,
      traffic_coverage: null,
      enable_traffic: null,
      enable_ui_stimulation: null,
      collection_timeout_seconds: null,
      dynamic_timeline: null,
      device: null,
    })
    const { container } = renderWithProviders(<DynamicAnalysis />)
    // 缺失字段以 em-dash 占位
    expect(container.textContent ?? '').toContain('—')
    // 任务 4.5:缺失后端数据不得显示为「正常」
    expect(screen.queryByText('正常')).toBeNull()
    // 「启用流量采集」缺失(enableTraffic=null)→「否」而非「正常」
    expect(container.textContent ?? '').toContain('否')
  })

  it('动态事件列表提供 全部/同意前/同意后/时间不明 筛选按钮', () => {
    seedDynamic()
    renderWithProviders(<DynamicAnalysis />)
    expect(screen.getByRole('button', { name: '全部' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '同意前' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '同意后' })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: '时间不明' })).toBeInTheDocument()
  })

  it('无事件时事件区域提示「该筛选下无事件。」', async () => {
    seedDynamic({ dynamic_events: [] })
    renderWithProviders(<DynamicAnalysis />)
    // 默认筛选「全部」,0 条事件 → 空提示
    expect(await screen.findByText(/该筛选下无事件/)).toBeInTheDocument()
  })
})

describe('DynamicAnalysis — 设备序列号脱敏回归', () => {
  it('device.serial 渲染为脱敏令牌,绝不为原始 IP 形 127.0.0.1:16417', () => {
    // 后端 DeviceContext.to_public_dict() 经 Redactor HMAC 脱敏(raw_retained=false),
    // 返回脱敏令牌而非原始 TCP 形 serial。这里以典型的脱敏令牌形态固化该契约。
    seedDynamic({
      device: {
        serial: 'redacted:a1b2c3d4e5f60718' as unknown as string,
        serial_token: 'redacted:a1b2c3d4e5f60718',
        raw_retained: false as const,
      },
    })
    const { container } = renderWithProviders(<DynamicAnalysis />)
    const text = container.textContent ?? ''
    // 脱敏令牌可见
    expect(text).toContain('redacted:')
    // 原始 IP:port 形态绝不在页面中出现
    expect(text).not.toMatch(/127\.0\.0\.1:16417/)
    // 标签「设备序列号(脱敏)」确认其为脱敏呈现
    expect(text).toContain('设备序列号(脱敏)')
  })
})
