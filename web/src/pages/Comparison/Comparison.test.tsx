import { describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Comparison from './Comparison'
import { renderWithProviders } from '@/test/render'
import { server } from '@/test/msw-server'
import type { ComparisonResult, TaskRecord } from '@/types/tasks'

const API = 'http://127.0.0.1:8000'

const emptyDiff = { added: [], removed: [], unchanged: [], unavailable: false }

function completed(id: string, version: string): TaskRecord {
  return {
    id,
    task_type: 'static',
    status: 'completed',
    apk_path: `D:/samples/${id}.apk`,
    apk_snapshot_path: null,
    apk_sha256: id.repeat(32).slice(0, 64),
    package_name: 'com.example.compare',
    app_name: 'Compare App',
    version_name: version,
    version_code: version,
    device_id: null,
    enable_traffic: false,
    enable_ui_stimulation: false,
    progress_percent: 100,
    current_stage: 'completed',
    cancelled_at_stage: null,
    error_code: null,
    error_message: null,
    report_json_path: `D:/output/${id}.json`,
    report_markdown_path: null,
    report_html_path: null,
    risk_score: 10,
    risk_level: 'low',
    request_payload: {},
    created_at: '2026-07-29T01:00:00Z',
    started_at: null,
    completed_at: '2026-07-29T01:01:00Z',
    updated_at: '2026-07-29T01:01:00Z',
    steps: [],
  }
}

const result: ComparisonResult = {
  schema_version: 'comparison-v1',
  id: 'comparison-1',
  task_id: 'comparison-task-1',
  base_task_id: 'base',
  target_task_id: 'target',
  created_at: '2026-07-29T02:00:00Z',
  base_summary: { app_name: 'Compare App', package_name: 'com.example.compare', version_name: '1.0', version_code: '100', risk_score: 10 },
  target_summary: { app_name: 'Compare App', package_name: 'com.example.compare', version_name: '2.0', version_code: '200', risk_score: 18 },
  risk_score_delta: 8,
  permissions: { added: ['android.permission.CAMERA'], removed: [], unchanged: ['android.permission.INTERNET'], unavailable: false },
  high_risk_permissions: emptyDiff,
  sdks: { added: ['NewAdSDK'], removed: ['OldAdSDK'], unchanged: [], unavailable: false },
  sdk_vendors: emptyDiff,
  sdk_categories: emptyDiff,
  rules: { added: ['RULE_NEW:matched'], removed: [], unchanged: [], unavailable: false },
  domains: emptyDiff,
  dynamic_behaviors: { ...emptyDiff, unavailable: true },
  evidence_complete: false,
  highlights: ['新增 1 项权限'],
  warnings: ['动态证据不足，相关维度标记为不可比较'],
}

describe('Comparison — 版本差异', () => {
  it('至少需要两个已完成且有报告的任务', async () => {
    server.use(http.get(`${API}/tasks`, () => HttpResponse.json({ items: [completed('base', '1.0')], total: 1, page: 1, page_size: 100, pages: 1 })))
    renderWithProviders(<Comparison />)
    expect(await screen.findByText('至少需要两个带有效报告的静态或动态任务。')).toBeInTheDocument()
    expect(screen.getByText('选择两个版本，建立清晰的变化视图')).toBeInTheDocument()
    expect(screen.getByText('证据覆盖率')).toBeInTheDocument()
    expect(screen.getByText('还没有历史对比')).toBeInTheDocument()
  })

  it('提交两个版本并展示权限、SDK、规则和证据不足语义', async () => {
    const tasks = [completed('base', '1.0'), completed('target', '2.0')]
    let body: Record<string, unknown> | undefined
    server.use(
      http.get(`${API}/tasks`, () => HttpResponse.json({ items: tasks, total: 2, page: 1, page_size: 100, pages: 1 })),
      http.post(`${API}/comparisons`, async ({ request }) => {
        body = await request.json() as Record<string, unknown>
        return HttpResponse.json(result, { status: 201 })
      }),
    )
    const user = userEvent.setup()
    renderWithProviders(<Comparison />)
    const selects = await screen.findAllByRole('combobox')
    await user.selectOptions(selects[0], 'base')
    await user.selectOptions(selects[1], 'target')
    await user.click(screen.getByRole('button', { name: /生成差异报告/ }))

    await vi.waitFor(() => expect(body).toMatchObject({ base_task_id: 'base', target_task_id: 'target', allow_cross_app: false }))
    expect(await screen.findByText('android.permission.CAMERA')).toBeInTheDocument()
    expect(screen.getByText('NewAdSDK')).toBeInTheDocument()
    expect(screen.getByText('RULE_NEW:matched')).toBeInTheDocument()
    expect(screen.getByText('动态证据不足，相关维度标记为不可比较')).toBeInTheDocument()
    expect(screen.queryByText('comparison-v1')).not.toBeInTheDocument()
    expect(screen.getByText('差异报告')).toBeInTheDocument()
    expect(screen.getByText('未评估')).toBeInTheDocument()
  })

  it('最近对比使用应用名称并可直接打开已有结果', async () => {
    server.use(
      http.get(`${API}/tasks`, () => HttpResponse.json({ items: [completed('base', '1.0'), completed('target', '2.0')], total: 2, page: 1, page_size: 100, pages: 1 })),
      http.get(`${API}/comparisons`, () => HttpResponse.json([result])),
    )
    const user = userEvent.setup()
    renderWithProviders(<Comparison />)

    const recent = await screen.findByRole('button', { name: /Compare App · 版本对比/ })
    expect(recent).toHaveAttribute('title', '对比 ID：comparison-1')
    await user.click(recent)
    expect(await screen.findByTestId('comparison-result')).toBeInTheDocument()
    expect(screen.getByText('android.permission.CAMERA')).toBeInTheDocument()
  })
})
