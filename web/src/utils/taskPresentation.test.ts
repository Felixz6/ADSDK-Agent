import { describe, expect, it } from 'vitest'
import {
  riskLevelLabel,
  safeApplicationName,
  shortDeviceLabel,
  taskTitle,
} from './taskPresentation'
import type { TaskRecord } from '@/types/tasks'

const comparison = {
  id: '11111111-2222-4333-8444-555555555555',
  task_type: 'comparison',
  status: 'completed',
  apk_path: null,
  apk_snapshot_path: null,
  apk_sha256: null,
  package_name: 'com.example.app',
  app_name: '示例应用',
  version_name: null,
  version_code: null,
  device_id: null,
  enable_traffic: false,
  enable_ui_stimulation: false,
  progress_percent: 100,
  current_stage: 'completed',
  cancelled_at_stage: null,
  error_code: null,
  error_message: null,
  report_json_path: null,
  report_markdown_path: null,
  report_html_path: null,
  risk_score: null,
  risk_level: null,
  request_payload: {},
  created_at: '2026-07-29T01:00:00Z',
  started_at: null,
  completed_at: '2026-07-29T01:01:00Z',
  updated_at: '2026-07-29T01:01:00Z',
  steps: [],
} satisfies TaskRecord

describe('taskPresentation', () => {
  it('应用名称按 APK 文件名、包名和未知应用稳定回退', () => {
    expect(safeApplicationName({ appName: '@string/app_name', apkPath: 'D:/samples/demo.apk', packageName: 'com.demo' })).toBe('demo.apk')
    expect(safeApplicationName({ appName: '?attr/appLabel', packageName: 'com.demo' })).toBe('com.demo')
    expect(safeApplicationName({ appName: '@string/app_name' })).toBe('未知应用')
  })

  it('风险原始值转换为中文展示', () => {
    expect(riskLevelLabel('low')).toBe('低风险')
    expect(riskLevelLabel('medium')).toBe('中风险')
    expect(riskLevelLabel('high')).toBe('高风险')
    expect(riskLevelLabel('critical')).toBe('严重风险')
    expect(riskLevelLabel(null)).toBe('未评估')
  })

  it('对比标题友好且设备标识仅展示短值', () => {
    expect(taskTitle(comparison)).toBe('示例应用 · 版本对比')
    expect(shortDeviceLabel('redacted:80a563aa99887766')).toBe('设备 80a563aa')
  })
})
