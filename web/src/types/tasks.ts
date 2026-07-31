import type { AnalyzeResponse } from './api'

export type TaskType = 'static' | 'dynamic' | 'comparison' | 'ai_orchestrated'
export type TaskStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
export type TaskStepStatus = 'success' | 'partial' | 'failed' | 'skipped' | 'running'
export type AnalysisScope = 'static_only' | 'dynamic_only' | 'full_analysis' | 'report_only'

export interface TaskCreateRequest {
  task_type: 'static' | 'dynamic' | 'ai_orchestrated'
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
  /** AI 编排分析(task_type='ai_orchestrated')专用字段 */
  objective?: string
  analysis_scope?: AnalysisScope
  allow_dynamic?: boolean
  allow_network?: boolean
  ai_enabled?: boolean
  token_budget?: number
  report_language?: string
  confirmed_tools?: string[]
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

// --- AI 编排(M6A)-----------------------------------------------------------
export type AISynthesisStatus =
  | 'completed'
  | 'partial'
  | 'failed'
  | 'budget_exhausted'
  | 'disabled'

export type AIToolStatus =
  | 'success'
  | 'partial'
  | 'failed'
  | 'not_run'
  | 'blocked_confirmation_required'

/** GET /ai/status —— 绝不包含 API Key */
export interface AIStatusResponse {
  enabled: boolean
  provider: string
  model: string
  configured: boolean
  /** null 表示「未按需探测」,不是「不可达」 */
  reachable: boolean | null
  last_error_code: string | null
  default_token_budget: number
  max_rounds: number
  max_tool_calls: number
  report_language: string
  allow_dynamic_tools: boolean
}

export interface AIPlanStep {
  step_id: string
  tool_name: string
  reason: string
  arguments: Record<string, unknown>
  depends_on: string[]
  requires_confirmation: boolean
}

export interface AIPlan {
  schema_version: 'ai-plan-v1'
  objective: string
  strategy: AnalysisScope
  steps: AIPlanStep[]
  expected_outputs: string[]
  stop_conditions: string[]
  limitations: string[]
  generated_by: 'ai' | 'default'
}

export interface AIKeyFinding {
  title: string
  severity: 'high' | 'medium' | 'low' | 'info'
  confidence: 'high' | 'medium' | 'low'
  summary: string
  evidence_refs: string[]
}

export interface AIReport {
  schema_version: 'ai-report-v1'
  status: AISynthesisStatus
  executive_summary: string
  key_findings: AIKeyFinding[]
  evidence_gaps: string[]
  risk_priorities: string[]
  recommended_actions: string[]
  evidence_refs: string[]
  limitations: string[]
  disclaimer: string
  usage: Record<string, unknown>
}

export interface AITokenUsage {
  input_tokens: number
  output_tokens: number
  cached_tokens: number
  estimated_tokens: number
  tool_call_count: number
  model_round_count: number
  latency_ms: number
  cache_hit: boolean
  budget_exhausted: boolean
  usage_is_estimate: boolean
}

export interface AIToolTraceStep {
  step_id: string
  tool_name: string
  started_at: string | null
  ended_at: string | null
  status: AIToolStatus
  safe_summary: string
  artifact_refs: string[]
  reused: boolean
  confirmation_required: boolean
  decision_summary: string | null
}

export interface AIToolTrace {
  trace_id: string
  steps: AIToolTraceStep[]
  model_round_count: number
  cache_hit: boolean
  budget_exhausted: boolean
}

/** report.json 中的 ai_orchestration 段(旧报告没有该字段) */
export interface AIOrchestrationSection {
  schema_version: 'ai-report-v1'
  status: AISynthesisStatus
  plan: AIPlan
  report: AIReport
  usage: AITokenUsage
  trace: AIToolTrace
  evidence_digest_hash: string
  error_code: string | null
  unavailable_reason: string | null
}

export interface TaskAIArtifactResponse {
  task_id: string
  status: TaskStatus
  available: boolean
  payload: Record<string, unknown> | null
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
