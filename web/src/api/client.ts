/**
 * AdSDK Agent 统一 API Client
 *
 * 设计目标:
 * 1. 全仓唯一 axios 实例,其余模块一律通过 src/api 下的封装函数访问后端,
 *    不直接 import axios —— 满足「API 层集中化」要求。
 * 2. 统一超时、错误归一化、开发环境日志,且区分「可络·无响应(后端未启动)」
 *    与「业务错误」,使前端在后端下线时给出友好提示。
 * 3. 仅在开发期(VITE_USE_MOCK==='true')启用本地 Mock 拦截,生产构建
 *    始终走真实接口,绝不替换真实 API。
 */
import axios, { AxiosError, type AxiosInstance } from 'axios'

/** API 根地址:优先使用环境配置,缺省指向本地 FastAPI */
export const API_BASE_URL: string =
  import.meta.env.VITE_API_BASE_URL?.replace(/\/$/, '') ?? 'http://127.0.0.1:8000'

/** 是否启用开发期 Mock(仅 dev,见 src/api/mock.ts) */
export const USE_MOCK: boolean = import.meta.env.VITE_USE_MOCK === 'true'

/** 统一 API 错误形态 */
export interface ApiError {
  /** 是否为后端无法连接(网络层 / 超时 / 5xx 后可能仍 false) */
  unreachable: boolean
  /** HTTP 状态码,无响应时为 null */
  status: number | null
  /** 错误代号,优先取后端的 error_code */
  code: string | null
  /** 面向用户的中文消息(绝不包含原始敏感字段) */
  message: string
  /** 原始错误对象(仅开发期用于排查) */
  raw?: unknown
}

/**
 * 超时分层(单位:毫秒)。
 *
 * - 默认轻量接口(/、/env/check、/traffic/check):15 秒。这些接口只做
 *   本地环境探测,正常应在亚秒级返回;15 秒足以覆盖慢启动,但不会让用户
 *   长时间挂着等待。
 * - 静态分析(POST /analyze):120 秒。解包 + Manifest 解析 + SDK 规则
 *   识别为同步耗时操作,需要更长的窗口。
 * - 动态分析(POST /dynamic/analyze):基础 600 秒(= 10 分钟),并按后端
 *   DynamicAnalyzeRequest.collection_timeout_seconds 额外增加清理余量,
 *   避免后端仍在采集时前端先超时。注意:600_000 是 600 秒(毫秒),不是
 *   600 毫秒 —— 与 collection_timeout_seconds(秒)联动时务必乘以 1000。
 */
export const DEFAULT_TIMEOUT_MS = 15_000
export const STATIC_ANALYSIS_TIMEOUT_MS = 120_000
export const DYNAMIC_ANALYSIS_BASE_TIMEOUT_MS = 600_000
/** 动态分析请求超时之外,额外预留的清理余量(毫秒)。 */
export const DYNAMIC_ANALYSIS_CLEANUP_MARGIN_MS = 90_000

/** 动态分析接口超时(根据 collection_timeout_seconds 动态计算,单位毫秒)。 */
export function dynamicAnalysisTimeoutMs(
  collectionTimeoutSeconds: number | null | undefined,
): number {
  const seconds = Number.isFinite(collectionTimeoutSeconds as number)
    ? Number(collectionTimeoutSeconds)
    : 0
  const base = Math.max(0, seconds) * 1000
  // 取「固定基础 600s」与「collection_timeout + 清理余量」二者较大值,
  // 保证即便 collection_timeout_seconds 较小也不会过早就绪断开。
  return Math.max(
    DYNAMIC_ANALYSIS_BASE_TIMEOUT_MS,
    base + DYNAMIC_ANALYSIS_CLEANUP_MARGIN_MS,
  )
}

const instance: AxiosInstance = axios.create({
  baseURL: API_BASE_URL,
  timeout: DEFAULT_TIMEOUT_MS,
  headers: { Accept: 'application/json' },
})

instance.interceptors.request.use((config) => {
  if (import.meta.env.DEV) {
    // eslint-disable-next-line no-console
    console.debug('[api] ->', config.method?.toUpperCase(), config.url)
  }
  return config
})

instance.interceptors.response.use(
  (resp) => resp,
  (error: AxiosError<unknown>) => {
    const apiError = toApiError(error)
    if (import.meta.env.DEV) {
      // eslint-disable-next-line no-console
      console.warn('[api] error', {
        url: error.config?.url,
        status: apiError.status,
        code: apiError.code,
        unreachable: apiError.unreachable,
      })
    }
    return Promise.reject(apiError)
  },
)

/** 将任意 axios 错误归一化为 ApiError */
export function toApiError(error: unknown): ApiError {
  if (axios.isAxiosError(error)) {
    const status = error.response?.status ?? null
    const unreachable =
      !error.response &&
      (error.code === 'ERR_NETWORK' ||
        error.code === 'ECONNABORTED' ||
        error.code === 'ETIMEDOUT' ||
        error.message?.toLowerCase().includes('network error') ||
        false)

    // 优先采用后端返回的结构化错误
    const payload = error.response?.data
    let code: string | null = null
    let message = ''
    if (payload && typeof payload === 'object') {
      const p = payload as Record<string, unknown>
      code = (typeof p.error_code === 'string' && p.error_code) || null
      message =
        (typeof p.detail === 'string' && p.detail) ||
        (typeof p.message === 'string' && p.message) ||
        ''
    }
    if (!message) {
      if (unreachable) {
        message = '无法连接到 AdSDK Agent 后端(127.0.0.1:8000),请确认服务已启动。'
      } else if (error.code === 'ECONNABORTED') {
        message = '请求超时,后端响应时间过长(分析任务可能仍在进行)。'
      } else if (status === 404) {
        message = '请求的接口不存在(404)。'
      } else if (status === 422) {
        message = '请求参数校验未通过(422),请检查输入字段。'
      } else if (status && status >= 500) {
        message = `后端服务异常(${status}),请稍后重试或查看服务日志。`
      } else if (status) {
        message = `请求失败(HTTP ${status})。`
      } else {
        message = '请求失败,请稍后重试。'
      }
    }
    return { unreachable: unreachable && !error.response, status, code, message, raw: error }
  }
  return {
    unreachable: true,
    status: null,
    code: null,
    message: '发生未知错误。',
    raw: error,
  }
}

/** 判断是否为「后端不可达」类错误,UI 据此展示引导 */
export function isUnreachable(err: unknown): err is ApiError {
  return Boolean(err && typeof err === 'object' && 'unreachable' in err && (err as ApiError).unreachable)
}

/** 静态分析(POST /analyze)请求配置:120 秒超时。 */
export const STATIC_SUBMIT_CONFIG = { timeout: STATIC_ANALYSIS_TIMEOUT_MS } as const

/**
 * 动态分析(POST /dynamic/analyze)请求配置:根据 collection_timeout_seconds
 * 动态计算总超时(基础 600s + 清理余量),单位毫秒。
 */
export function dynamicSubmitConfig(collectionTimeoutSeconds: number | null | undefined) {
  return { timeout: dynamicAnalysisTimeoutMs(collectionTimeoutSeconds) } as const
}

/**
 * @deprecated 历史导出,语义为「静态分析超时」。新代码请直接使用
 * STATIC_SUBMIT_CONFIG 或 dynamicSubmitConfig(...),以便按接口分层。
 */
export const SUBMIT_CONFIG = STATIC_SUBMIT_CONFIG

export default instance
