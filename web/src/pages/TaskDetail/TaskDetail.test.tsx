import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import TaskDetail from './TaskDetail'
import { renderWithProviders } from '@/test/render'
import { server } from '@/test/msw-server'
import type { TaskRecord } from '@/types/tasks'

const API = 'http://127.0.0.1:8000'
const originalWebSocket = globalThis.WebSocket

beforeEach(() => {
  Object.defineProperty(globalThis, 'WebSocket', { configurable: true, writable: true, value: undefined })
})
afterEach(() => {
  Object.defineProperty(globalThis, 'WebSocket', { configurable: true, writable: true, value: originalWebSocket })
})

function task(overrides: Partial<TaskRecord> = {}): TaskRecord {
  return {
    id: 'detail-1',
    task_type: 'dynamic',
    status: 'completed',
    apk_path: 'D:/samples/app.apk',
    apk_snapshot_path: 'runs/detail-1/input/app.apk',
    apk_sha256: 'b'.repeat(64),
    package_name: 'com.example.detail',
    app_name: 'Detail App',
    version_name: '2.0',
    version_code: '20',
    device_id: 'device_serial:abcd1234',
    enable_traffic: true,
    enable_ui_stimulation: false,
    progress_percent: 100,
    current_stage: 'completed',
    error_code: null,
    error_message: null,
    report_json_path: 'D:/output/report.json',
    report_markdown_path: 'D:/output/report.md',
    report_html_path: 'D:/output/report.html',
    risk_score: 31,
    risk_level: 'medium',
    request_payload: { task_type: 'dynamic', device_id: 'device_serial:abcd1234' },
    created_at: '2026-07-29T01:00:00Z',
    started_at: '2026-07-29T01:00:01Z',
    completed_at: '2026-07-29T01:00:05Z',
    updated_at: '2026-07-29T01:00:05Z',
    steps: [{
      id: 1,
      task_id: 'detail-1',
      step_key: 'apk_validation',
      step_name: 'apk_validation',
      status: 'success',
      progress_percent: 8,
      message: 'APK 输入已校验',
      started_at: '2026-07-29T01:00:01Z',
      completed_at: '2026-07-29T01:00:02Z',
      updated_at: '2026-07-29T01:00:02Z',
    }],
    ...overrides,
  }
}

function renderDetail(record: TaskRecord, routePath = '/tasks/:id') {
  server.use(http.get(`${API}/tasks/${record.id}`, () => HttpResponse.json(record)))
  return renderWithProviders(<div />, {
    initialEntries: [`/tasks/${record.id}`],
    extraRoutes: [{ path: routePath, element: <TaskDetail /> }],
  })
}

describe('TaskDetail — 实时生命周期', () => {
  it('终态任务展示步骤、脱敏设备和报告入口', async () => {
    renderDetail(task())
    expect((await screen.findAllByText('Detail App')).length).toBeGreaterThan(0)
    expect(screen.getAllByText('APK 输入已校验').length).toBeGreaterThan(0)
    expect(screen.getByText('device_serial:abcd1234')).toBeInTheDocument()
    expect(screen.queryByText('127.0.0.1:16416')).not.toBeInTheDocument()
    expect(screen.getByRole('button', { name: /专业报告/ })).toBeInTheDocument()
  })

  it('WebSocket 不可用时明确使用 HTTP 轮询', async () => {
    renderDetail(task({
      status: 'running',
      progress_percent: 42,
      current_stage: 'dynamic_collection',
      completed_at: null,
      report_json_path: null,
      report_markdown_path: null,
      report_html_path: null,
    }))
    expect(await screen.findByText('HTTP 轮询')).toBeInTheDocument()
  })


  it('uses friendly timeline copy and keeps raw error enums in collapsed technical details', async () => {
    const record = task({
      current_stage: 'dynamic_collection',
      steps: [{
        id: 2,
        task_id: 'detail-1',
        step_key: 'frida_spawn',
        step_name: 'frida_spawn',
        status: 'partial',
        progress_percent: 63,
        message: 'frida_server_unavailable: Frida could not spawn the target package',
        started_at: '2026-07-29T01:00:02Z',
        completed_at: '2026-07-29T01:00:03Z',
        updated_at: '2026-07-29T01:00:03Z',
      }],
    })

    renderDetail(record)

    expect(await screen.findByText('Frida \u4f1a\u8bdd\u672a\u5c31\u7eea\uff0c\u5df2\u4fdd\u7559\u7f51\u7edc\u4fa7\u91c7\u96c6\u7ed3\u679c\u3002')).toBeInTheDocument()
    expect(screen.getByText('\u52a8\u6001\u884c\u4e3a\u91c7\u96c6')).toBeInTheDocument()
    const technicalValue = screen.getByText('frida_server_unavailable: Frida could not spawn the target package')
    expect(technicalValue.closest('details')).not.toHaveAttribute('open')
  })

})
