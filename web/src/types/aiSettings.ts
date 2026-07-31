/**
 * M6B —— 前端 AI 配置中心类型。
 *
 * 严格依据后端 Pydantic 模型 `AISettingsResponse` / `AISettingsSaveRequest` /
 * `AISettingsTestRequest` / `AISettingsTestResponse` / `AISettingsDeleteKeyResponse`
 * (app/tasks/models.py)。字段名、取值与可空性与后端保持一致,前端不臆造。
 *
 * 安全约束(类型层强制):
 * - 任何「读取」响应都**不含** `api_key` 字段。只有 `api_key_configured`(布尔)
 *   与 `api_key_source` 会暴露配置状态,绝不暴露密钥原值。
 * - 保存请求中的 `api_key` 为「只写」字段:不在响应中回显,也不回填到输入框。
 */

/** API Key 的来源,只有这三个值。`none` 表示尚未配置任何密钥。 */
export type AISettingsApiKeySource = 'none' | 'environment' | 'local_store'

/** 单个可编辑字段的配置来源。决定前端是否锁定该输入。 */
export type AISettingsFieldSource = 'default' | 'environment' | 'local_store'

/** GET /ai/settings —— 脱敏后的有效配置。绝不包含 API Key。 */
export interface AISettingsResponse {
  schema_version: 'ai-settings-v1'
  enabled: boolean
  provider: string
  base_url: string
  model: string
  /** 是否已配置 Key(布尔);不暴露原始密钥、长度或任何派生值。 */
  api_key_configured: boolean
  api_key_source: AISettingsApiKeySource
  default_token_budget: number
  max_rounds: number
  max_tool_calls: number
  timeout_seconds: number
  max_input_tokens: number
  max_output_tokens: number
  cache_enabled: boolean
  cache_ttl_seconds: number
  allow_dynamic_tools: boolean
  report_language: 'zh-CN' | 'en-US'
  /** 各可编辑字段的有效值来源(环境变量>本地保存>默认)。 */
  field_sources: Record<string, AISettingsFieldSource>
  /** 被环境变量锁定的字段名;前端必须禁用并提示「由环境变量管理」。 */
  locked_fields: string[]
}

/** PUT /ai/settings —— 可编辑字段 + 可选只写 API Key。 */
export interface AISettingsSaveRequest {
  enabled?: boolean
  provider?: string
  base_url?: string
  model?: string
  /** 只写:省略或空字符串表示保持现有 Key;非空表示替换。删除须用独立接口。 */
  api_key?: string
  default_token_budget?: number
  max_rounds?: number
  max_tool_calls?: number
  timeout_seconds?: number
  max_input_tokens?: number
  max_output_tokens?: number
  cache_enabled?: boolean
  cache_ttl_seconds?: number
  allow_dynamic_tools?: boolean
  report_language?: 'zh-CN' | 'en-US'
}

/** POST /ai/settings/test —— 可选临时配置(含临时 Key,绝不持久化)。 */
export interface AISettingsTestRequest {
  enabled?: boolean
  provider?: string
  base_url?: string
  model?: string
  /** 临时 Key:仅在本次请求内存,不保存、不缓存、不写库、不写日志。 */
  api_key?: string
  timeout_seconds?: number
}

/** 连接测试状态。 */
export type AISettingsTestStatus =
  | 'reachable'
  | 'unreachable'
  | 'invalid_configuration'
  | 'authentication_failed'
  | 'timeout'

/** POST /ai/settings/test —— 测试结果。无 Key、无主机回显。 */
export interface AISettingsTestResponse {
  status: AISettingsTestStatus
  provider: string
  model: string
  latency_ms: number
  safe_message: string
  models_endpoint_supported: boolean
}

/** DELETE /ai/settings/api-key —— 删除本地保存的 Key(环境变量 Key 不受影响)。 */
export interface AISettingsDeleteKeyResponse {
  deleted: boolean
  api_key_source: AISettingsApiKeySource
  api_key_configured: boolean
}
