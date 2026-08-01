import { describe, it, expect } from 'vitest'
import { http, HttpResponse } from 'msw'
import type { JsonBodyType } from 'msw'
import {
  getTaskAIPlan,
  getTaskAIReport,
  getTaskAIRuntimeDiagnostics,
  regenerateTaskAIReport,
} from './taskCenter'
import { server } from '@/test/msw-server'
import type {
  TaskAIArtifactResponse,
  TaskAIArtifactSummary,
} from '@/types/tasks'

const API = 'http://127.0.0.1:8000'

/** 捕获请求的方法/URL/查询参数,用于断言按约定构造。 */
function capture() {
  const seen: Array<{ method: string; url: URL; body: unknown }> = []
  const handlers = {
    get: (path: string, status = 200, payload: JsonBodyType = {}) =>
      http.get(`${API}${path}`, ({ request }) => {
        seen.push({ method: 'GET', url: new URL(request.url), body: null })
        return HttpResponse.json(payload, { status })
      }),
    post: (path: string, status = 200, payload: JsonBodyType = {}) =>
      http.post(`${API}${path}`, async ({ request }) => {
        let body: unknown = null
        try {
          body = await request.text()
        } catch {
          body = null
        }
        seen.push({ method: 'POST', url: new URL(request.url), body })
        return HttpResponse.json(payload, { status })
      }),
  }
  return { seen, ...handlers }
}

const artifactResp: TaskAIArtifactResponse = {
  task_id: 't-ai-1',
  status: 'completed',
  available: true,
  payload: { schema_version: 'ai-runtime-diagnostics-v1' },
}

const summaryResp: TaskAIArtifactSummary = {
  task_id: 't-ai-1',
  status: 'completed',
  ai_status: 'completed',
  ai_section: { status: 'completed' },
}

describe('getTaskAIRuntimeDiagnostics / getTaskAIPlan / getTaskAIReport — artifact 路由', () => {
  it('runtime-diagnostics GET 命中 /tasks/{id}/ai-runtime-diagnostics 并回传 payload', async () => {
    const c = capture()
    server.use(c.get('/tasks/t-ai-1/ai-runtime-diagnostics', 200, artifactResp))
    const data = await getTaskAIRuntimeDiagnostics('t-ai-1')
    expect(data.task_id).toBe('t-ai-1')
    expect(data.available).toBe(true)
    expect(data.payload?.schema_version).toBe('ai-runtime-diagnostics-v1')
    expect(c.seen).toHaveLength(1)
    expect(c.seen[0].method).toBe('GET')
    expect(c.seen[0].url.pathname).toBe('/tasks/t-ai-1/ai-runtime-diagnostics')
  })

  it('taskId 含特殊字符会被 encodeURIComponent 转义(不破坏路由)', async () => {
    const c = capture()
    server.use(c.get('/tasks/a%20b%2FC/ai-plan', 200, artifactResp))
    const data = await getTaskAIPlan('a b/C')
    expect(data.task_id).toBe('t-ai-1')
    expect(c.seen[0].url.pathname).toBe('/tasks/a%20b%2FC/ai-plan')
  })

  it('ai-report GET 命中 /tasks/{id}/ai-report', async () => {
    const c = capture()
    server.use(c.get('/tasks/t-ai-1/ai-report', 200, artifactResp))
    const data = await getTaskAIReport('t-ai-1')
    expect(data.available).toBe(true)
    expect(c.seen[0].url.pathname).toBe('/tasks/t-ai-1/ai-report')
  })
})

describe('regenerateTaskAIReport — use_cache 查询参数', () => {
  it('未传 useCache 时不附加查询参数(沿用后端保存的缓存设置)', async () => {
    const c = capture()
    server.use(c.post('/tasks/t-ai-1/ai-report/regenerate', 200, summaryResp))
    const data = await regenerateTaskAIReport('t-ai-1')
    expect(data.ai_status).toBe('completed')
    expect(c.seen).toHaveLength(1)
    expect(c.seen[0].method).toBe('POST')
    expect(c.seen[0].url.pathname).toBe('/tasks/t-ai-1/ai-report/regenerate')
    expect(c.seen[0].url.search).toBe('')
  })

  it('useCache=true 附加 ?use_cache=true(强制走缓存 → 命中后零真实模型调用)', async () => {
    const c = capture()
    server.use(c.post('/tasks/t-ai-1/ai-report/regenerate', 200, summaryResp))
    await regenerateTaskAIReport('t-ai-1', true)
    expect(c.seen[0].url.searchParams.get('use_cache')).toBe('true')
  })

  it('useCache=false 附加 ?use_cache=false(强制真实调用)', async () => {
    const c = capture()
    server.use(c.post('/tasks/t-ai-1/ai-report/regenerate', 200, summaryResp))
    await regenerateTaskAIReport('t-ai-1', false)
    expect(c.seen[0].url.searchParams.get('use_cache')).toBe('false')
  })

  it('409(无确定性产物可复用)时向上抛出结构化错误', async () => {
    const c = capture()
    server.use(
      c.post('/tasks/t-ai-1/ai-report/regenerate', 409, {
        detail: 'ai_regenerate_no_report',
      }),
    )
    await expect(regenerateTaskAIReport('t-ai-1', false)).rejects.toThrow()
    expect(c.seen).toHaveLength(1)
  })

  it('请求体为空(不携带任何 payload,后端从磁盘读取产物)', async () => {
    const c = capture()
    server.use(c.post('/tasks/t-ai-1/ai-report/regenerate', 200, summaryResp))
    await regenerateTaskAIReport('t-ai-1')
    // 后端 POST 路由 body 可空;此处断言未发送 JSON 文本。
    expect(c.seen[0].body === '' || c.seen[0].body === null).toBe(true)
  })
})
