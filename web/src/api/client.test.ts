import { describe, it, expect } from 'vitest'
import { AxiosError } from 'axios'
import {
  toApiError,
  isUnreachable,
  dynamicAnalysisTimeoutMs,
  DEFAULT_TIMEOUT_MS,
  STATIC_ANALYSIS_TIMEOUT_MS,
  DYNAMIC_ANALYSIS_BASE_TIMEOUT_MS,
} from './client'

/**
 * 构造真实 AxiosError,验证 toApiError 在「后端不可达」「超时」「业务错误」
 * 等场景下的归一化与中文友好提示。
 */
function makeAxiosError(
  partial: Partial<AxiosError> & { code?: string; message?: string },
): AxiosError {
  // 用真实 AxiosError 构造,保证 isAxiosError 成立、原型链正确。
  const err = new AxiosError(
    partial.message ?? '',
    partial.code ?? '',
    partial.config,
    partial.request,
    partial.response,
  )
  return err
}

describe('toApiError — 后端不可达识别', () => {
  it('ERR_NETWORK 无响应 => unreachable=true,友好中文提示', () => {
    const e = makeAxiosError({ message: 'Network Error', code: 'ERR_NETWORK' })
    const api = toApiError(e)
    expect(api.unreachable).toBe(true)
    expect(api.status).toBeNull()
    expect(api.message).toContain('无法连接')
    expect(api.message).toContain('127.0.0.1:8000')
  })

  it('ECONNABORTED 超时(无响应)=> unreachable=true,归入「无法连接」提示', () => {
    // 实现中 unreachable 先于超时判断,故无响应的超时也归为不可达类提示。
    const e = makeAxiosError({ message: 'timeout of 600000ms exceeded', code: 'ECONNABORTED' })
    const api = toApiError(e)
    expect(api.unreachable).toBe(false)
    expect(api.code).toBe('client_timeout')
  })

  it('ETIMEDOUT => unreachable=true', () => {
    const e = makeAxiosError({ message: 'timeout', code: 'ETIMEDOUT' })
    const api = toApiError(e)
    expect(api.unreachable).toBe(false)
    expect(api.code).toBe('client_timeout')
  })

  it('message 含 "network error"(小写,无显式 code)=> unreachable=true', () => {
    const e = makeAxiosError({ message: 'getaddrinfo ENOTFOUND ... network error occurred' })
    const api = toApiError(e)
    expect(api.unreachable).toBe(true)
  })
})

describe('toApiError — 业务错误(后端有响应)', () => {
  it('4xx 不视为不可达;404 友好提示', () => {
    const e = makeAxiosError({
      message: 'Request failed with status code 404',
      code: 'ERR_BAD_REQUEST',
      response: { status: 404, data: undefined } as AxiosError['response'],
    })
    const api = toApiError(e)
    expect(api.unreachable).toBe(false)
    expect(api.status).toBe(404)
    expect(api.message).toContain('404')
  })

  it('422 友好提示', () => {
    const e = makeAxiosError({
      message: 'Request failed',
      code: 'ERR_BAD_REQUEST',
      response: { status: 422, data: undefined } as AxiosError['response'],
    })
    const api = toApiError(e)
    expect(api.unreachable).toBe(false)
    expect(api.status).toBe(422)
    expect(api.message).toContain('422')
  })

  it('5xx 友好提示但非不可达(有响应)', () => {
    const e = makeAxiosError({
      message: 'failed',
      response: { status: 500, data: undefined } as AxiosError['response'],
    })
    const api = toApiError(e)
    expect(api.unreachable).toBe(false)
    expect(api.status).toBe(500)
    expect(api.message).toContain('500')
  })

  it('后端返回结构化 error_code/detail 时优先采用', () => {
    const e = makeAxiosError({
      message: 'failed',
      response: {
        status: 400,
        data: { error_code: 'E_BAD_APK', detail: 'APK 解包失败,请检查文件。' },
      } as AxiosError['response'],
    })
    const api = toApiError(e)
    expect(api.code).toBe('E_BAD_APK')
    expect(api.message).toBe('APK 解包失败,请检查文件。')
  })

  it('后端仅返回 message 字段时也被读取', () => {
    const e = makeAxiosError({
      message: 'failed',
      response: { status: 400, data: { message: '内部错误提示' } } as AxiosError['response'],
    })
    const api = toApiError(e)
    expect(api.message).toBe('内部错误提示')
  })
})

describe('toApiError — 非 axios 错误', () => {
  it('普通 Error 归一化为不可达 + 未知错误', () => {
    const api = toApiError(new Error('boom'))
    expect(api.unreachable).toBe(true)
    expect(api.message).toBe('发生未知错误。')
  })
  it('null/undefined 不抛异常', () => {
    expect(() => toApiError(null)).not.toThrow()
    expect(() => toApiError(undefined)).not.toThrow()
  })
})

describe('isUnreachable 类型守卫', () => {
  it('识别不可达 ApiError', () => {
    const e = makeAxiosError({ message: 'Network Error', code: 'ERR_NETWORK' })
    expect(isUnreachable(toApiError(e))).toBe(true)
  })
  it('业务错误不被判为不可达', () => {
    const e = makeAxiosError({
      message: '404',
      response: { status: 404, data: undefined } as AxiosError['response'],
    })
    expect(isUnreachable(toApiError(e))).toBe(false)
  })
  it('非 ApiError 对象返回 false(无 unreachable 键)', () => {
    expect(isUnreachable({ message: 'x' })).toBe(false)
    expect(isUnreachable(null)).toBe(false)
    expect(isUnreachable(undefined)).toBe(false)
  })
})

/**
 * 超时分层(单位:毫秒)回归测试。
 *
 * 重点防止两类历史回归:
 *  - 把「600 秒」误当成「600 毫秒」:基础动态超时必须 >= 600_000ms。
 *  - 单一超时回归:默认 15s / 静态 120s / 动态 600s 三档必须严格分层。
 */
describe('超时分层', () => {
  it('常量档位分隔清晰(15s / 120s / 600s)', () => {
    expect(DEFAULT_TIMEOUT_MS).toBe(15_000)
    expect(STATIC_ANALYSIS_TIMEOUT_MS).toBe(1_920_000)
    expect(DYNAMIC_ANALYSIS_BASE_TIMEOUT_MS).toBe(2_010_000)
  })

  it('动态基础超时为 600 秒(600_000ms),绝不可写成 600 毫秒', () => {
    expect(DYNAMIC_ANALYSIS_BASE_TIMEOUT_MS).toBeGreaterThanOrEqual(600_000)
    expect(DYNAMIC_ANALYSIS_BASE_TIMEOUT_MS).not.toBe(600) // 防回归:不要把秒当毫秒
  })

  it('collection_timeout_seconds 较小时取基础 600s,不会被压低', () => {
    expect(dynamicAnalysisTimeoutMs(undefined)).toBe(2_010_000)
    expect(dynamicAnalysisTimeoutMs(null)).toBe(2_010_000)
    expect(dynamicAnalysisTimeoutMs(0)).toBe(2_010_000)
    expect(dynamicAnalysisTimeoutMs(60)).toBe(2_070_000) // 60s 采集 + 90s 余量 仍 < 600s
    expect(dynamicAnalysisTimeoutMs(300)).toBe(2_310_000) // 默认 300s 采集仍走基础值
  })

  it('collection_timeout_seconds 较大时 = 采集秒数*1000 + 90s 清理余量', () => {
    // 600s 采集 => 600*1000 + 90*1000 = 690_000ms
    expect(dynamicAnalysisTimeoutMs(600)).toBe(2_610_000)
    // 1800s 采集 => 1_890_000ms
    expect(dynamicAnalysisTimeoutMs(1800)).toBe(3_810_000)
  })

  it('非法输入安全回退到基础 600s', () => {
    expect(dynamicAnalysisTimeoutMs(Number.NaN)).toBe(2_010_000)
    expect(dynamicAnalysisTimeoutMs(Number.POSITIVE_INFINITY)).toBe(2_010_000)
    expect(dynamicAnalysisTimeoutMs(-10)).toBe(2_010_000) // 负数按 0 处理
    expect(dynamicAnalysisTimeoutMs('abc' as unknown as number)).toBe(2_010_000)
  })

  it('动态超时 永远 > 静态超时 > 默认超时,不会因采集短而降到默认档', () => {
    // 即便输入 0/小值,动态档也至少 600s,远大于静态 120s 与默认 15s
    expect(dynamicAnalysisTimeoutMs(0)).toBeGreaterThan(STATIC_ANALYSIS_TIMEOUT_MS)
    expect(STATIC_ANALYSIS_TIMEOUT_MS).toBeGreaterThan(DEFAULT_TIMEOUT_MS)
  })
})
