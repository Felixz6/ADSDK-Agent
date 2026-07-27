/**
 * 系统类接口:根健康检查、环境自检、流量捕获自检
 */
import api, { DEFAULT_TIMEOUT_MS } from './client'
import type {
  ServiceHealth,
  EnvCheckResponse,
  TrafficCheckResponse,
} from '@/types/api'

/** GET /  服务健康 */
export async function getServiceHealth(signal?: AbortSignal): Promise<ServiceHealth> {
  const { data } = await api.get<ServiceHealth>('/', { signal })
  return data
}

/**
 * GET /env/check
 * @param deviceId 可选目标设备序列号(透传,后端会脱敏回显)
 */
export async function getEnvCheck(deviceId?: string, signal?: AbortSignal): Promise<EnvCheckResponse> {
  const { data } = await api.get<EnvCheckResponse>('/env/check', {
    params: deviceId ? { device_id: deviceId } : undefined,
    signal,
  })
  return data
}

/**
 * GET /traffic/check  需要指定设备
 */
export async function getTrafficCheck(
  deviceId: string,
  signal?: AbortSignal,
): Promise<TrafficCheckResponse> {
  const { data } = await api.get<TrafficCheckResponse>('/traffic/check', {
    params: { device_id: deviceId },
    signal,
    // /traffic/check 是一次轻量自检(默认端口探测),用 15s 够用;
    // 实际长耗时抓包在 /dynamic/analyze 内完成,由动态分析超时覆盖。
    timeout: DEFAULT_TIMEOUT_MS,
  })
  return data
}

export type EnvCheckQueryKey = ['env', 'check'] | ['env', 'check', string | undefined]
export type TrafficCheckQueryKey = ['traffic', 'check', string]
