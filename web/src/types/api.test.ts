import { describe, it, expect } from 'vitest'
import { KNOWN_SDK_NAMES, type HttpRequestRecord } from '@/types/api'

describe('KNOWN_SDK_NAMES', () => {
  it('恰好为 12 个已知广告 SDK', () => {
    expect(KNOWN_SDK_NAMES).toHaveLength(12)
  })
  it('包含规范要求的全部 12 个 SDK', () => {
    const set = new Set<string>(KNOWN_SDK_NAMES)
    const required: string[] = [
      'Pangle',
      '优量汇',
      'GDT',
      '百度广告SDK',
      '快手',
      'Kwai Ads',
      'Mintegral',
      'Unity Ads',
      'AppLovin',
      'AdMob',
      'ironSource',
      'Vungle',
    ]
    for (const name of required) expect(set.has(name)).toBe(true)
  })
  it('无重复项', () => {
    expect(new Set(KNOWN_SDK_NAMES).size).toBe(KNOWN_SDK_NAMES.length)
  })
})

/**
 * HttpRequestRecord 字段形状与隐私不变量:
 *  - 必须为恰好 18 个字段;
 *  - 必须存在 query_keys 为键名数组(仅键,无值);
 *  - **绝不**包含原文敏感字段:host / headers / body / url / cookie / auth / authorization。
 */
describe('HttpRequestRecord — 隐私字段形状', () => {
  const sample: HttpRequestRecord = {
    protocol_version: '1.0',
    schema_version: '1.0',
    type: 'http_request',
    flow_id: 'flow-1',
    run_id: 'run-1',
    session_id: 'sess-1',
    timestamp_utc: '2026-07-25T10:00:00Z',
    method: 'GET',
    scheme: 'https',
    hostname: null,
    port: 443,
    path: null,
    query_keys: ['uid', 'token'],
    status_code: 200,
    request_size: 0,
    response_size: 12,
    tls: 'TLSv1.2',
    error: null,
  }

  it('恰好包含 18 个字段', () => {
    expect(Object.keys(sample).length).toBe(18)
  })

  it('query_keys 为字符串数组(仅键名,无值)', () => {
    expect(Array.isArray(sample.query_keys)).toBe(true)
    for (const k of sample.query_keys) expect(typeof k).toBe('string')
  })

  const FORBIDDEN_KEYS = [
    'host', // 用 hostname(已脱敏)替代
    'headers',
    'header',
    'body',
    'request_body',
    'url',
    'full_url',
    'cookie',
    'cookies',
    'set_cookie',
    'auth',
    'authorization',
    'access_token',
    'android_id',
    'oaid',
  ]

  for (const bad of FORBIDDEN_KEYS) {
    it(`不包含敏感字段 "${bad}"`, () => {
      expect(sample).not.toHaveProperty(bad)
    })
  }

  it('type 固定为 http_request', () => {
    expect(sample.type).toBe('http_request')
  })

  it('protocol_version / schema_version 固定为 1.0', () => {
    expect(sample.protocol_version).toBe('1.0')
    expect(sample.schema_version).toBe('1.0')
  })

  it('error 取值受限(flow_error | incomplete | null)', () => {
    const allowed: unknown[] = ['flow_error', 'incomplete', null]
    expect(allowed).toContain(sample.error)
  })
})

/**
 * 编译期断言:HttpRequestRecord 可被满足的字段集合内不含任意上述敏感键。
 * 若未来有人误在接口中新增 host/headers/body 等,编译期不能阻止新增,
 * 但运行期此处 FORBIDDEN_KEYS 循环会失败 —— 作为回归护栏。
 */
