import type { AnalyzeResponse } from './api'
import type { components } from './openapi'

type Schemas = components['schemas']
type OptionalKeys<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>
type RequiredKeys<T, K extends keyof T> = Omit<T, K> & Required<Pick<T, K>>

export type TaskType = Schemas['TaskRecord']['task_type']
export type TaskStatus = Schemas['TaskRecord']['status']
export type TaskStepStatus = Schemas['TaskStepRecord']['status']
export type AnalysisScope = Schemas['TaskCreateRequest']['analysis_scope']

/**
 * M7A — Consent 手动检查点。
 *
 * 操作员在真机上人工完成 Consent 动作后回报结论。AI 不得自动确认,
 * 任何超时都不会产生 `confirmed`;看门狗只能 `cancelled`(退出等待并进入清理)。
 */
export type ConsentCheckpointAction = Schemas['ConsentCheckpointRequest']['action']
export type ConsentCheckpointStatus = Schemas['ConsentCheckpointState']['status']
export type ConsentCheckpointRequest = OptionalKeys<Schemas['ConsentCheckpointRequest'], 'note'>

export type ConsentCheckpointState = RequiredKeys<
  Schemas['ConsentCheckpointState'],
  'resolved_at' | 'resolved_by_action' | 'last_heartbeat_at'
>

export type TaskCreateRequest = OptionalKeys<
  Schemas['TaskCreateRequest'],
  | 'enable_traffic'
  | 'enable_ui_stimulation'
  | 'pre_consent_seconds'
  | 'post_consent_seconds'
  | 'collection_timeout_seconds'
  | 'dynamic_mode_policy'
  | 'analysis_scope'
  | 'allow_dynamic'
  | 'allow_network'
  | 'ai_enabled'
  | 'token_budget'
  | 'report_language'
>

export type TaskStep = RequiredKeys<
  Schemas['TaskStepRecord'],
  'message' | 'started_at' | 'completed_at'
>

export type TaskRecord = Required<
  Omit<Schemas['TaskRecord'], 'cancelled_at_stage' | 'steps' | 'request_payload'>
> & {
  cancelled_at_stage?: Schemas['TaskRecord']['cancelled_at_stage']
  steps: TaskStep[]
  request_payload: Record<string, unknown>
}

export type TaskListResponse = Omit<Schemas['TaskListResponse'], 'items'> & {
  items: TaskRecord[]
}

export type TaskActionResponse = Omit<Schemas['TaskActionResponse'], 'task'> & {
  task: TaskRecord
}

export type TaskReportResponse = Omit<Required<Schemas['TaskReportResponse']>, 'report'> & {
  report: AnalyzeResponse | null
}

export interface TaskFilters {
  status?: TaskStatus | ''
  task_type?: TaskType | ''
  keyword?: string
  page?: number
  page_size?: number
  sort?: '-created_at' | 'created_at' | '-updated_at' | 'updated_at'
}

export type TaskSystemStatus = RequiredKeys<Schemas['TaskSystemStatus'], 'occupied_devices'>

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
export type AIStatusResponse = RequiredKeys<
  Schemas['AIStatusResponse'],
  'reachable' | 'last_error_code'
>

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
  /** M7B — plan parsing / repair / strategy normalization diagnostics. */
  plan_source?: 'ai' | 'repaired' | 'deterministic'
  planning_failed?: boolean
  deterministic_plan_fallback?: boolean
  requested_strategy?: string
  effective_strategy?: string
  repair_attempted?: boolean
  repair_succeeded?: boolean
  fallback_used?: boolean
  validation_error_code?: string | null
  validation_json_path?: string | null
  normalized?: boolean
  normalization_reason?: string | null
  target_running?: boolean
  preflight_changed?: boolean
  report_source?: 'ai_validated' | 'ai_repaired' | 'deterministic_fallback'
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

export type TaskAIArtifactResponse = RequiredKeys<Schemas['TaskAIArtifactResponse'], 'payload'>

/** POST /tasks/{id}/ai-report/regenerate 返回的精简摘要(无秘密/无模型文本)。 */
export type TaskAIArtifactSummary = Schemas['TaskAIArtifactSummary']

export type DifferenceSet = RequiredKeys<
  Schemas['DifferenceSet'],
  'added' | 'removed' | 'unchanged'
>

export type ComparisonCreateRequest = OptionalKeys<
  Schemas['ComparisonCreateRequest'],
  'allow_cross_app'
>

export type ComparisonResult = Omit<
  RequiredKeys<Schemas['ComparisonResult'], 'risk_score_delta' | 'highlights' | 'warnings'>,
  | 'permissions'
  | 'high_risk_permissions'
  | 'sdks'
  | 'sdk_vendors'
  | 'sdk_categories'
  | 'rules'
  | 'domains'
  | 'dynamic_behaviors'
> & {
  permissions: DifferenceSet
  high_risk_permissions: DifferenceSet
  sdks: DifferenceSet
  sdk_vendors: DifferenceSet
  sdk_categories: DifferenceSet
  rules: DifferenceSet
  domains: DifferenceSet
  dynamic_behaviors: DifferenceSet
}
