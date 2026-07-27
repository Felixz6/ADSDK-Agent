/**
 * TanStack Query hooks:统一封装查询与变更,页面不直接调用 axios/api。
 */
import { useMutation, useQuery, type UseQueryOptions } from '@tanstack/react-query'
import { getServiceHealth, getEnvCheck, getTrafficCheck } from '@/api/system'
import { submitStaticAnalysis, submitDynamicAnalysis } from '@/api/analysis'
import type { ApiError } from '@/api/client'
import type {
  AnalyzeRequest,
  DynamicAnalyzeRequest,
  AnalyzeResponse,
  EnvCheckResponse,
  ServiceHealth,
  TrafficCheckResponse,
} from '@/types/api'

/* -------- 健康检查 -------- */
export function useServiceHealth(
  options?: Omit<UseQueryOptions<ServiceHealth, ApiError>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<ServiceHealth, ApiError>({
    queryKey: ['service', 'health'],
    queryFn: ({ signal }) => getServiceHealth(signal),
    refetchInterval: 30_000,
    ...options,
  })
}

/* -------- 环境自检 -------- */
export function useEnvCheck(
  deviceId?: string,
  options?: Omit<UseQueryOptions<EnvCheckResponse, ApiError>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<EnvCheckResponse, ApiError>({
    queryKey: ['env', 'check', deviceId],
    queryFn: ({ signal }) => getEnvCheck(deviceId, signal),
    refetchInterval: 60_000,
    ...options,
  })
}

/* -------- 流量捕获自检 -------- */
export function useTrafficCheck(
  deviceId: string,
  enabled: boolean,
  options?: Omit<UseQueryOptions<TrafficCheckResponse, ApiError>, 'queryKey' | 'queryFn'>,
) {
  return useQuery<TrafficCheckResponse, ApiError>({
    queryKey: ['traffic', 'check', deviceId],
    queryFn: ({ signal }) => getTrafficCheck(deviceId, signal),
    enabled: enabled && Boolean(deviceId),
    refetchInterval: false,
    ...options,
  })
}

/* -------- 提交静态分析(变更) -------- */
export function useSubmitStaticAnalysis() {
  return useMutation<AnalyzeResponse, ApiError, AnalyzeRequest>({
    mutationFn: submitStaticAnalysis,
  })
}

/* -------- 提交动态分析(变更) -------- */
export function useSubmitDynamicAnalysis() {
  return useMutation<AnalyzeResponse, ApiError, DynamicAnalyzeRequest>({
    mutationFn: submitDynamicAnalysis,
  })
}
