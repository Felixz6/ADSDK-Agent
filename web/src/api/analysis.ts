/**
 * 分析类接口:静态分析 /analyze、动态分析 /dynamic/analyze
 */
import api, { STATIC_SUBMIT_CONFIG, dynamicSubmitConfig } from './client'
import type {
  AnalyzeRequest,
  DynamicAnalyzeRequest,
  AnalyzeResponse,
} from '@/types/api'

/**
 * POST /analyze  提交静态分析(长耗时同步,超时 120 秒)
 */
export async function submitStaticAnalysis(req: AnalyzeRequest): Promise<AnalyzeResponse> {
  const { data } = await api.post<AnalyzeResponse>('/analyze', req, STATIC_SUBMIT_CONFIG)
  return data
}

/**
 * POST /dynamic/analyze  提交动态分析(长耗时同步)
 *
 * 总超时 = max(600s, collection_timeout_seconds * 1000 + 90s 清理余量),
 * 单位毫秒;保证后端仍在采集/清理时前端不会过早超时。
 */
export async function submitDynamicAnalysis(req: DynamicAnalyzeRequest): Promise<AnalyzeResponse> {
  const { data } = await api.post<AnalyzeResponse>(
    '/dynamic/analyze',
    req,
    dynamicSubmitConfig(req.collection_timeout_seconds),
  )
  return data
}
