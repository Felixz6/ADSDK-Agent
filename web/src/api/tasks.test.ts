import { describe, it, expect, beforeEach, vi } from 'vitest'
import type { AnalyzeResponse } from '@/types/api'
import {
  listLocalTasks,
  recordTask,
  deleteLocalTask,
  clearLocalTasks,
} from './tasks'

/* 模拟 localStorage(tasks.ts 依赖浏览器持久层) */
const store = new Map<string, string>()
beforeEach(() => {
  store.clear()
  Object.defineProperty(globalThis, 'localStorage', {
    configurable: true,
    value: {
      getItem: (k: string) => store.get(k) ?? null,
      setItem: (k: string, v: string) => void store.set(k, v),
      removeItem: (k: string) => void store.delete(k),
      clear: () => store.clear(),
      key: (i: number) => Array.from(store.keys())[i] ?? null,
      length: 0,
    },
  })
  // 重置 spy 计数器
  vi.clearAllMocks()
})

describe('recordTask — 成功路径规则统计', () => {
  it('入库时填充 summary(规则状态计数),不含原文敏感标识', () => {
    const resp: Partial<AnalyzeResponse> = {
      run_id: 'run-1',
      status: 'success',
      dynamic_findings: {
        rules: [
          { rule_id: 'R1', status: 'matched' },
          { rule_id: 'R2', status: 'not_matched' },
          { rule_id: 'R3', status: 'not_evaluated' },
        ],
      } as AnalyzeResponse['dynamic_findings'],
      strict_dynamic_findings: {
        rules: [
          { rule_id: 'S1', status: 'matched' },
          { rule_id: 'S2', status: 'error' },
        ],
      } as unknown as AnalyzeResponse['strict_dynamic_findings'],
    }
    const rec = recordTask('dynamic', { apk_path: '/x/a.apk' }, resp as AnalyzeResponse)
    expect(rec.summary).toEqual({
      matched: 2,
      not_matched: 1,
      not_evaluated: 1,
      errored: 1,
    })
  })

  it('无任何规则时 summary 为 null', () => {
    const resp: Partial<AnalyzeResponse> = { run_id: 'r2', status: 'success' }
    const rec = recordTask('static', { apk_path: '/x/b.apk' }, resp as AnalyzeResponse)
    expect(rec.summary).toBeNull()
  })

  it('package_name 优先用 input,回退到 result.app_info.package_name', () => {
    const resp: Partial<AnalyzeResponse> = {
      run_id: 'r3',
      status: 'success',
      app_info: { package_name: 'com.backend.pkg' } as AnalyzeResponse['app_info'],
    }
    const byInput = recordTask('static', { apk_path: '/x/c.apk', package_name: 'com.input.pkg' }, resp as AnalyzeResponse)
    expect(byInput.package_name).toBe('com.input.pkg')
    const byFallback = recordTask('static', { apk_path: '/x/d.apk' }, resp as AnalyzeResponse)
    expect(byFallback.package_name).toBe('com.backend.pkg')
    const bothNull = recordTask('static', { apk_path: '/x/e.apk' }, { run_id: 'r4', status: 'success' } as AnalyzeResponse)
    expect(bothNull.package_name).toBeNull()
  })

  it('has_report 在 report_md 或 report_json 存在时为 true', () => {
    const withMd = recordTask('static', { apk_path: '/x/f.apk' }, { report_md: '/tmp/r.md' } as AnalyzeResponse)
    expect(withMd.has_report).toBe(true)
    const withJson = recordTask('static', { apk_path: '/x/g.apk' }, { report_json: '/tmp/r.json' } as AnalyzeResponse)
    expect(withJson.has_report).toBe(true)
    const none = recordTask('static', { apk_path: '/x/h.apk' }, {} as AnalyzeResponse)
    expect(none.has_report).toBe(false)
  })

  it('artifacts_count 取 result.artifacts.length,缺省为 0', () => {
    const withArts = recordTask('static', { apk_path: '/x/i.apk' }, { artifacts: [{}, {}, {}] } as unknown as AnalyzeResponse)
    expect(withArts.artifacts_count).toBe(3)
    const none = recordTask('static', { apk_path: '/x/j.apk' }, {} as AnalyzeResponse)
    expect(none.artifacts_count).toBe(0)
  })

  it('不向后端发请求(repo 仅写 localStorage);列表含全部已登记项', () => {
    const fetchSpy = vi.spyOn(globalThis, 'fetch').mockImplementation(() => Promise.resolve(new Response('')))
    recordTask('static', { apk_path: '/x/k.apk' }, { run_id: 'r-k', status: 'success' } as AnalyzeResponse)
    recordTask('static', { apk_path: '/x/l.apk' }, { run_id: 'r-l', status: 'success' } as AnalyzeResponse)
    expect(fetchSpy).not.toHaveBeenCalled()
    const list = listLocalTasks()
    expect(list).toHaveLength(2)
    const paths = list.map((t) => t.apk_path).sort()
    expect(paths).toEqual(['/x/k.apk', '/x/l.apk'])
    fetchSpy.mockRestore()
  })
})

describe('recordTask — 失败路径', () => {
  it('无 result(failure)时 status="failed",summary=null', () => {
    const rec = recordTask('static', { apk_path: '/x/fail.apk' }, null, {
      error: '连接超时',
      error_code: 'E_TIMEOUT',
    })
    expect(rec.status).toBe('failed')
    expect(rec.summary).toBeNull()
    expect(rec.error).toBe('连接超时')
    expect(rec.error_code).toBe('E_TIMEOUT')
    expect(rec.run_id).toBeNull()
  })

  it('失败时仍有 has_report=false 与 artifacts_count=0', () => {
    const rec = recordTask('dynamic', { apk_path: '/x/f2.apk' }, null, { error: 'x', error_code: 'E' })
    expect(rec.has_report).toBe(false)
    expect(rec.artifacts_count).toBe(0)
  })
})

describe('listLocalTasks / getLocalTask / deleteLocalTask / clearLocalTasks', () => {
  it('空 localStorage 返回空数组', () => {
    expect(listLocalTasks()).toEqual([])
  })

  it('删除某条记录后,列表不再含该记录', () => {
    recordTask('static', { apk_path: '/x/d1.apk' }, { run_id: 'r1', status: 'success' } as AnalyzeResponse)
    const r2 = recordTask('static', { apk_path: '/x/d2.apk' }, { run_id: 'r2', status: 'success' } as AnalyzeResponse)
    deleteLocalTask(r2.local_id)
    const list = listLocalTasks()
    const paths = list.map((t) => t.apk_path)
    expect(paths).not.toContain('/x/d2.apk')
  })

  it('清空历史后列表为空', () => {
    recordTask('static', { apk_path: '/x/c1.apk' }, { run_id: 'r', status: 'success' } as AnalyzeResponse)
    clearLocalTasks()
    expect(listLocalTasks()).toEqual([])
  })

  it('MAX_RECORDS 上限裁剪(只保留最近 100 条)', async () => {
    for (let i = 0; i < 105; i++) {
      recordTask('static', { apk_path: `/x/m${i}.apk` }, { run_id: `r${i}`, status: 'success' } as AnalyzeResponse)
    }
    expect(listLocalTasks().length).toBeLessThanOrEqual(100)
  })
})
