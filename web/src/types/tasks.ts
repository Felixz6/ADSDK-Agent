import type { AnalyzeResponse } from './api'

export type TaskType = 'static' | 'dynamic' | 'comparison'
export type TaskStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
export type TaskStepStatus = 'success' | 'partial' | 'failed' | 'skipped' | 'running'

export interface TaskCreateRequest {
  task_type: 'static' | 'dynamic'
  apk_path: string
  package_name?: string
  device_id?: string
  enable_traffic?: boolean
  enable_ui_stimulation?: boolean
  consent_after_seconds?: number | null
  pre_consent_seconds?: number
  post_consent_seconds?: number
  collection_timeout_seconds?: number
  dynamic_mode_policy?: 'strict' | 'balanced' | 'attach_only'
}

export interface TaskStep {
  id: number
  task_id: string
  step_key: string
  step_name: string
  status: TaskStepStatus
  progress_percent: number
  message: string | null
  started_at: string | null
  completed_at: string | null
  updated_at: string
}

export interface TaskRecord {
  id: string
  task_type: TaskType
  status: TaskStatus
  apk_path: string | null
  apk_snapshot_path: string | null
  apk_sha256: string | null
  package_name: string | null
  app_name: string | null
  version_name: string | null
  version_code: string | null
  device_id: string | null
  enable_traffic: boolean
  enable_ui_stimulation: boolean
  progress_percent: number
  current_stage: string | null
  cancelled_at_stage?: string | null
  error_code: string | null
  error_message: string | null
  report_json_path: string | null
  report_markdown_path: string | null
  report_html_path: string | null
  risk_score: number | null
  risk_level: string | null
  request_payload: Record<string, unknown>
  created_at: string
  started_at: string | null
  completed_at: string | null
  updated_at: string
  steps: TaskStep[]
}

export interface TaskListResponse {
  items: TaskRecord[]
  total: number
  page: number
  page_size: number
  pages: number
}

export interface TaskActionResponse {
  task: TaskRecord
  message: string
}

export interface TaskReportResponse {
  task_id: string
  status: TaskStatus
  report: AnalyzeResponse | null
  json_url: string | null
  markdown_url: string | null
  html_url: string | null
}

export interface TaskFilters {
  status?: TaskStatus | ''
  task_type?: TaskType | ''
  keyword?: string
  page?: number
  page_size?: number
  sort?: '-created_at' | 'created_at' | '-updated_at' | 'updated_at'
}

export interface TaskSystemStatus {
  database_ok: boolean
  database_path: string
  running_tasks: number
  queued_tasks: number
  occupied_devices: string[]
}

export interface DifferenceSet {
  added: string[]
  removed: string[]
  unchanged: string[]
  unavailable: boolean
}

export interface ComparisonCreateRequest {
  base_task_id: string
  target_task_id: string
  allow_cross_app?: boolean
}

export interface ComparisonResult {
  schema_version: 'comparison-v1'
  id: string
  task_id: string
  base_task_id: string
  target_task_id: string
  created_at?: string | null
  base_summary: Record<string, unknown>
  target_summary: Record<string, unknown>
  risk_score_delta: number | null
  permissions: DifferenceSet
  high_risk_permissions: DifferenceSet
  sdks: DifferenceSet
  sdk_vendors: DifferenceSet
  sdk_categories: DifferenceSet
  rules: DifferenceSet
  domains: DifferenceSet
  dynamic_behaviors: DifferenceSet
  evidence_complete: boolean
  highlights: string[]
  warnings: string[]
}
