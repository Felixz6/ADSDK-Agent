/**
 * M6B —— 前端 AI 配置中心 API 封装。
 *
 * 安全边界:
 * - 这些接口的请求体可能包含 `api_key`。本项目统一的 axios 拦截器
 *   (src/api/client.ts)在开发期仅打印 `[api] -> METHOD url`,**从不打印 body**,
 *   因此密钥不会进入浏览器控制台日志或任何前端持久化。
 * - 不将 `api_key` 写入 localStorage / sessionStorage / IndexedDB / URL 查询参数。
 *   组件层负责在卸载时清除本地输入态。
 * - 保存/测试/删除均为敏感本机写接口;后端 `_AILocalOnlyMiddleware` 强制
 *   loopback + 合法 Origin,远程写请求会被 403 拒绝。
 */
import api from './client'
import type {
  AISettingsDeleteKeyResponse,
  AISettingsResponse,
  AISettingsSaveRequest,
  AISettingsTestRequest,
  AISettingsTestResponse,
} from '@/types/aiSettings'

/** GET /ai/settings —— 读取脱敏后的有效配置(绝不返回 Key)。 */
export async function getAISettings(signal?: AbortSignal): Promise<AISettingsResponse> {
  const { data } = await api.get<AISettingsResponse>('/ai/settings', { signal })
  return data
}

/** PUT /ai/settings —— 保存可编辑配置 + 可选新 Key。请求体不记日志、不回显。 */
export async function updateAISettings(
  req: AISettingsSaveRequest,
  signal?: AbortSignal,
): Promise<AISettingsResponse> {
  const { data } = await api.put<AISettingsResponse>('/ai/settings', req, { signal })
  return data
}

/** POST /ai/settings/test —— 测试当前或临时配置。临时 Key 不保存、不缓存、不写库。 */
export async function testAISettings(
  req: AISettingsTestRequest,
  signal?: AbortSignal,
): Promise<AISettingsTestResponse> {
  const { data } = await api.post<AISettingsTestResponse>('/ai/settings/test', req, {
    signal,
  })
  return data
}

/** DELETE /ai/settings/api-key —— 删除本地保存的 Key(环境变量 Key 不受影响)。 */
export async function deleteLocalAIKey(
  signal?: AbortSignal,
): Promise<AISettingsDeleteKeyResponse> {
  const { data } = await api.delete<AISettingsDeleteKeyResponse>(
    '/ai/settings/api-key',
    { signal },
  )
  return data
}
