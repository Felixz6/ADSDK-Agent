import type { AnalyzeResponse } from './api'

export type TaskType = 'static' | 'dynamic' | 'comparison' | 'ai_orchestrated'
export type TaskStatus = 'queued' | 'running' | 'completed' | 'failed' | 'cancelled'
export type TaskStepStatus = 'success' | 'partial' | 'failed' | 'skipped' | 'running'
export type AnalysisScope = 'static_only' | 'dynamic_only' | 'full_analysis' | 'report_only'

/**
 * M7A — Consent 手动检查点。
 *
 * 操作员在真机上人工完成 Consent 动作后回报结论。AI 不得自动确认,
 * 任何超时都不会产生 `confirmed`;看门狗只能 `cancelled`(退出等待并进入清理)。
 */
export type ConsentCheckpointAction = 'confirmed' | 'not_found' | 'skipped'
export type ConsentCheckpointStatus =
  | ConsentCheckpointAction
  | 'awaiting'
  | 'cancelled'
  | 'expired'

export interface ConsentCheckpointState {
  task_id: string
  run_id: string
  status: ConsentCheckpointStatus
  entered_at: string
  resolved_at: string | null
  resolved_by_action: ConsentCheckpointAction | null
  last_heartbeat_at: string | null
  note: string
}

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
  /** M6C — token 来源(provider 真实 / estimated 本地估算 / unavailable 未知)。 */
  usage_source: TokenUsageSource
  /** 仅记录模型是否返回 reasoning_content 字段,绝不包含其内容。 */
  reasoning_content_present: boolean
  /** 真实 provider usage 中的 token 子集(无 provider 时为 0)。 */
  real_tokens: number
  /** 本地估算合计 token(无估算时为 0)。 */
  estimated_total_tokens: number
  /** 每轮模型的 token 来源明细。 */
  rounds: AIPerRoundUsage[]
}

/** token 来源:provider=真实返回 / estimated=本地估算 / unavailable=未知。 */
export type TokenUsageSource = 'provider' | 'estimated' | 'unavailable'

/** 模型编排阶段:plan=规划 / report=报告 / repair=修复。 */
export type AIRoundType = 'plan' | 'report' | 'repair'

/** 统一错误分类(provider 层产出)。仅含分类标签,无错误体/头部/URL。 */
export type AIErrorCode =
  | 'ai_not_configured'
  | 'ai_provider_timeout'
  | 'ai_provider_unreachable'
  | 'ai_provider_authentication_failed'
  | 'ai_provider_model_not_found'
  | 'ai_provider_rate_limited'
  | 'ai_provider_error'
  | 'ai_provider_invalid_json'
  | 'ai_provider_invalid_response'

/** 单轮 token 来源明细。reasoning_content_present 仅记录是否存在,不含内容。 */
export interface AIPerRoundUsage {
  round_index: number
  round_type: AIRoundType
  usage_source: TokenUsageSource
  input_tokens: number
  output_tokens: number
  cached_tokens: number
  latency_ms: number
  finish_reason: string | null
  reasoning_content_present: boolean
  retry_count: number
  cache_hit: boolean
}

/** 一次被分类的错误(瞬时重试或最终失败)。无错误体/头部/URL,仅标签+时序。 */
export interface AIErrorObservation {
  code: AIErrorCode
  retryable: boolean
  attempt: number
  retry_count: number
  stage: AIRoundType | null
  http_status: number | null
  latency_ms: number
  finalized: boolean
}

/**
 * ai-runtime-diagnostics-v1 运行时诊断(仅可观事实,绝不包含秘密/完整 prompt/
 * 完整模型响应/reasoning_content 内容——每轮仅记录是否存在 presence 布尔)。
 */
export interface AIRuntimeDiagnostic {
  schema_version: 'ai-runtime-diagnostics-v1'
  task_id: string
  model: string
  provider_profile: string
  thinking_mode: string
  enabled: boolean
  usage: AITokenUsage
  rounds: AIPerRoundUsage[]
  errors: AIErrorObservation[]
  total_rounds: number
  total_retries: number
  cache_hit: boolean
  cache_enabled: boolean
  deterministic_fallback: boolean
  outcome: 'ok' | 'degraded' | 'failed' | 'disabled'
  generated_at: string
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
  /** M6C — 运行时诊断(仅可观事实)。旧报告无此字段。 */
  diagnostic: AIRuntimeDiagnostic | null
}

export interface TaskAIArtifactResponse {
  task_id: string
  status: TaskStatus
  available: boolean
  payload: Record<string, unknown> | null
}

/** POST /tasks/{id}/ai-report/regenerate 返回的精简摘要(无秘密/无模型文本)。 */
export interface TaskAIArtifactSummary {
  task_id: string
  status: TaskStatus
  ai_status: string
  ai_section: Record<string, unknown>
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
