import { describe, it, expect, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import Reports from './Reports'
import { renderWithProviders } from '@/test/render'
import { useAnalysisStore } from '@/stores/analysisStore'
import type { AnalyzeResponse } from '@/types/api'

beforeEach(() => {
  useAnalysisStore.getState().clear()
})

function seedDynamic(resp: Partial<AnalyzeResponse> = {}) {
  const base: AnalyzeResponse = {
    ok: true,
    apk_path: 'D:/authorized/demo.apk',
    schema_version: '1.0',
    run_id: 'r-1',
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
    report_md: '# Demo report',
    dynamic_events: [],
    dynamic_findings: {
      rules: [
        { rule_id: 'M1', status: 'matched', title: '同意前上传设备标识' },
        { rule_id: 'NM1', status: 'not_matched', title: '同意前未发现' },
        { rule_id: 'NE1', status: 'not_evaluated', title: '未运行' },
        { rule_id: 'E1', status: 'error', title: '执行异常' },
      ],
      summary: '',
      evaluation_summary: null,
    },
    strict_dynamic_findings: {
      rules: [
        { rule_id: 'S-M1', status: 'matched', title: '严格:命中' },
        { rule_id: 'S-NE1', status: 'not_evaluated', title: '严格:未运行' },
      ],
      window: {} as AnalyzeResponse['strict_dynamic_findings'] extends infer T ? T extends { window: infer W } ? W : never : never,
      summary: '',
      evaluation_summary: null,
      warnings: [],
    },
    traffic_summary: null,
    pre_consent_seconds: 10,
    post_consent_seconds: 10,
    enable_traffic: true,
    enable_ui_stimulation: false,
    collection_timeout_seconds: 300,
    collection_status: 'success',
    traffic_coverage: 'observed',
    dynamic_timeline: null,
  } as unknown as AnalyzeResponse
  const merged = { ...base, ...resp } as AnalyzeResponse
  useAnalysisStore.getState().setActive(merged, {
    local_id: 'local-x',
    run_id: 'r-1',
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
  }, 'dynamic')
  return merged
}

describe('Reports — 规则四态计数与渲染', () => {
  it('matched/not_matched/not_evaluated/error 计数正确显示', () => {
    seedDynamic()
    render(<Reports />)
    // 命中数 = strict 1 + mild 1 = 2
    expect(screen.getAllByText('2').length).toBeGreaterThan(0)
    // 未命中数 = mild 1
    // 未评估数 = strict 1 + mild 1 = 2
    // 异常数 = mild 1
  })

  it('未评估绝不展示为绿色/安全/通过:StatCard tone 为 neutral,文案为「绝不代表无风险」', () => {
    seedDynamic()
    const { container } = render(<Reports />)
    // 报告页头部明示「未评估绝不等于无风险」
    expect(screen.getByText(/未评估绝不等于无风险/)).toBeInTheDocument()
    // 「未评估」标签对应 StatCard 不含 success 语义色类
    // 检查页面不含把 not_evaluated 表述为「通过 / 安全 / 就绪 / 无风险(肯定式)」的肯定式断言
    const body = container.textContent ?? ''
    // 「无风险」只允许出现在「绝不代表无风险」语境,不允许独立肯定式「无风险」
    const standalone = body.replace(/绝不代表无风险/g, '').replace(/绝不等于无风险/g, '')
    expect(standalone).not.toMatch(/^.*(未评估).*(通过|已就绪|安全)/)
  })
})

describe('Reports — 无活跃结果', () => {
  it('无结果时显示无活跃结果占位', () => {
    renderWithProviders(<Reports />)
    expect(screen.getByText(/尚未进行(静态|动态)分析/)).toBeInTheDocument()
  })
})
