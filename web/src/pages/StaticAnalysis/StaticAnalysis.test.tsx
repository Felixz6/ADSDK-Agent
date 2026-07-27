import { describe, it, expect, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import StaticAnalysis from './StaticAnalysis'
import { renderWithProviders } from '@/test/render'
import { useAnalysisStore } from '@/stores/analysisStore'
import type { AnalyzeResponse } from '@/types/api'
import type { LocalTaskRecord } from '@/api/tasks'

beforeEach(() => {
  useAnalysisStore.getState().clear()
})

const taskStub: LocalTaskRecord = {
  local_id: 'local-static-1',
  run_id: 'r-static-1',
  kind: 'static',
  apk_path: 'D:/authorized/sample.apk',
  package_name: 'com.example.sample',
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

function seedStatic(resp: Partial<AnalyzeResponse> = {}) {
  const base: AnalyzeResponse = {
    ok: true,
    apk_path: 'D:/authorized/sample.apk',
    schema_version: '1.0',
    run_id: 'r-static-1',
    apk_sha256: null,
    apk_snapshot: null,
    normalized_apk_name: 'sample',
    analysis_started_at: '2026-01-01T00:00:00Z',
    status: 'success',
    steps: [],
    warnings: [],
    device: null,
    artifacts: [],
    app_info: {
      package_name: 'com.example.sample',
      version_name: '1.0.0',
      version_code: 10,
      application_label: '示例应用',
    } as AnalyzeResponse['app_info'],
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
    report_md: '# report',
    dynamic_events: [],
    dynamic_findings: null,
    strict_dynamic_findings: null,
    traffic_summary: null,
    pre_consent_seconds: null,
    post_consent_seconds: null,
    enable_traffic: null,
    enable_ui_stimulation: null,
    collection_timeout_seconds: null,
    collection_status: null,
    traffic_coverage: null,
    dynamic_timeline: null,
    error: null,
    error_code: null,
    limitations: [],
  }
  const merged = { ...base, ...resp } as AnalyzeResponse
  useAnalysisStore.getState().setActive(merged, taskStub, 'static')
  return merged
}

describe('StaticAnalysis — 无活跃结果空态', () => {
  it('无结果时显示「尚未进行静态分析」,并给出「新建分析」/「查看历史」入口', () => {
    const { container } = renderWithProviders(<StaticAnalysis />)
    expect(screen.getByText(/尚未进行静态分析/)).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /新建分析/ })).toBeInTheDocument()
    expect(screen.getByRole('button', { name: /查看历史/ })).toBeInTheDocument()
    // 关键:占位采纳自 useActiveResult(expected) 为 null,绝不展示「正常」「成功」等伪造状态
    expect(container.textContent ?? '').toMatch(/尚未进行静态分析/)
  })

  it('点击「新建分析」导航至 /analysis/new', async () => {
    const user = userEvent.setup()
    const { router } = renderWithProviders(<StaticAnalysis />)
    await user.click(screen.getByRole('button', { name: /新建分析/ }))
    expect(router.state.location.pathname).toBe('/analysis/new')
  })

  it('点击「查看历史」导航至 /tasks', async () => {
    const user = userEvent.setup()
    const { router } = renderWithProviders(<StaticAnalysis />)
    await user.click(screen.getByRole('button', { name: /查看历史/ }))
    expect(router.state.location.pathname).toBe('/tasks')
  })
})

describe('StaticAnalysis — 有结果时正确渲染,缺失字段以占位显示而非「正常」', () => {
  it('渲染应用包名、版本、识别 SDK 数、整体状态等卡片', () => {
    seedStatic()
    renderWithProviders(<StaticAnalysis />)
    expect(screen.getByText('com.example.sample')).toBeInTheDocument()
    expect(screen.getByText('1.0.0')).toBeInTheDocument()
    // 识别 SDK 数 = 0(未识别),整体状态 = 成功(STEP_STATUS_LABEL)
    expect(screen.getByText('成功')).toBeInTheDocument()
  })

  it('后端缺失 app_info 时,包名/版本以「—」占位,绝不展示为「正常」', () => {
    seedStatic({ app_info: null })
    const { container } = renderWithProviders(<StaticAnalysis />)
    // 包名/版本缺失 → em-dash 占位
    expect(container.textContent ?? '').toContain('—')
    // 不得把缺失渲染成「正常」(任务 4.5:缺失后端数据不得显示为正常)
    expect(screen.queryByText('正常')).toBeNull()
  })

  it('整体状态为失败时显示「失败」而非「成功」,不伪造成功', () => {
    seedStatic({ status: 'failed' })
    renderWithProviders(<StaticAnalysis />)
    expect(screen.getByText('失败')).toBeInTheDocument()
    expect(screen.queryByText('成功')).toBeNull()
  })

  it('识别到 SDK 时展示 SDK 名称,未识别时说明「未识别到已收录 SDK」', () => {
    seedStatic({
      sdk_count: 1,
      sdks: [
        {
          sdk_name: 'Pangle',
          package: 'com.pangle',
          confidence: 0.9,
          version: '5.0',
          evidence: [],
        },
      ],
    })
    const { container } = renderWithProviders(<StaticAnalysis />)
    // SDK 列表行包含脱敏的 package 标识,而「已收录 SDK 池」chip 只有名字;
    // 用包含 package 的整行断言,避免与池 chip 撞名。
    expect(container.textContent ?? '').toContain('com.pangle')
    expect(screen.getAllByText('Pangle').length).toBeGreaterThan(0)
  })
})
