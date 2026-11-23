/**
 * M6B —— 前端 AI 配置中心类型。
 *
 * 直接从自动生成的 OpenAPI 契约 (`./openapi`) 派生，字段名、取值与可空性与后端
 * Pydantic 模型 (`app/tasks/models.py`) 保持编译期同步，前端不独立手写漂移副本。
 *
 * 安全约束(类型层强制):
 * - 任何「读取」响应都**不含** `api_key` 字段。只有 `api_key_configured`(布尔)
 *   与 `api_key_source` 会暴露配置状态,绝不暴露密钥原值。
 * - 保存请求中的 `api_key` 为「只写」字段:不在响应中回显,也不回填到输入框。
 */
import type { components } from './openapi'

type AISettingsResponseSchema = components['schemas']['AISettingsResponse']

/** API Key 的来源,只有这三个值。`none` 表示尚未配置任何密钥。 */
export type AISettingsApiKeySource = AISettingsResponseSchema['api_key_source']

/** 单个可编辑字段的配置来源。决定前端是否锁定该输入。 */
export type AISettingsFieldSource = AISettingsResponseSchema['field_sources'][string]

/** GET /ai/settings —— 脱敏后的有效配置。绝不包含 API Key。 */
export type AISettingsResponse = Omit<
  AISettingsResponseSchema,
  'schema_version' | 'report_language'
> & {
  schema_version: 'ai-settings-v1'
  report_language: 'zh-CN' | 'en-US'
}

/** PUT /ai/settings —— 可编辑字段 + 可选只写 API Key。 */
export type AISettingsSaveRequest = Omit<
  components['schemas']['AISettingsSaveRequest'],
  'report_language'
> & {
  report_language?: 'zh-CN' | 'en-US' | null
}

/** POST /ai/settings/test —— 可选临时配置(含临时 Key,绝不持久化)。 */
export type AISettingsTestRequest = components['schemas']['AISettingsTestRequest']

/** POST /ai/settings/test —— 测试结果。无 Key、无主机回显。 */
export type AISettingsTestResponse = components['schemas']['AISettingsTestResponse']

/** 连接测试状态。 */
export type AISettingsTestStatus = AISettingsTestResponse['status']

/** DELETE /ai/settings/api-key —— 删除本地保存的 Key(环境变量 Key 不受影响)。 */
export type AISettingsDeleteKeyResponse = components['schemas']['AISettingsDeleteKeyResponse']
