import { describe, it, expect } from 'vitest'
import { http, HttpResponse } from 'msw'
import type { JsonBodyType } from 'msw'
import { getConsentCheckpoint, resolveConsentCheckpoint } from './taskCenter'
import { server } from '@/test/msw-server'
import type { ConsentCheckpointState } from '@/types/tasks'

const API = 'http://127.0.0.1:8000'

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
          body = JSON.parse(await request.text())
        } catch {
          body = null
        }
        seen.push({ method: 'POST', url: new URL(request.url), body })
        return HttpResponse.json(payload, { status })
      }),
  }
  return { seen, ...handlers }
}

const awaiting: ConsentCheckpointState = {
  task_id: 't-1',
  run_id: 'run-1',
  status: 'awaiting',
  entered_at: '2026-08-02T00:00:01Z',
  resolved_at: null,
  resolved_by_action: null,
  last_heartbeat_at: '2026-08-02T00:00:02Z',
  note: '',
}

describe('M7A — Consent 检查点 API', () => {
  it('GET 返回等待中的检查点状态', async () => {
    const cap = capture()
    server.use(cap.get('/tasks/t-1/consent-checkpoint', 200, awaiting))
    const state = await getConsentCheckpoint('t-1')
    expect(state?.status).toBe('awaiting')
    expect(cap.seen[0].url.pathname).toBe('/tasks/t-1/consent-checkpoint')
  })

  it('GET 在没有等待中的检查点时把 404 转成 null 而非抛错', async () => {
    const cap = capture()
    server.use(
      cap.get('/tasks/t-1/consent-checkpoint', 404, {
        detail: { code: 'checkpoint_not_found', message: '无等待中的检查点' },
      }),
    )
    await expect(getConsentCheckpoint('t-1')).resolves.toBeNull()
  })

  it('GET 对非 404 错误仍然抛出', async () => {
    const cap = capture()
    server.use(cap.get('/tasks/t-1/consent-checkpoint', 500, {}))
    await expect(getConsentCheckpoint('t-1')).rejects.toBeTruthy()
  })

  it.each(['confirmed', 'not_found', 'skipped'] as const)(
    'POST 提交 %s 动作并回传服务端状态',
    async (action) => {
      const cap = capture()
      server.use(
        cap.post('/tasks/t-1/consent-checkpoint', 200, {
          ...awaiting,
          status: action,
          resolved_by_action: action,
          resolved_at: '2026-08-02T00:01:00Z',
        }),
      )
      const state = await resolveConsentCheckpoint('t-1', action)
      expect(state.status).toBe(action)
      expect(cap.seen[0].method).toBe('POST')
      expect(cap.seen[0].body).toMatchObject({ action })
    },
  )

  it('POST 携带备注', async () => {
    const cap = capture()
    server.use(
      cap.post('/tasks/t-1/consent-checkpoint', 200, {
        ...awaiting,
        status: 'confirmed',
        resolved_by_action: 'confirmed',
        note: '首页弹窗',
      }),
    )
    await resolveConsentCheckpoint('t-1', 'confirmed', '首页弹窗')
    expect(cap.seen[0].body).toMatchObject({
      action: 'confirmed',
      note: '首页弹窗',
    })
  })

  it('POST 在状态冲突时抛出 409', async () => {
    const cap = capture()
    server.use(
      cap.post('/tasks/t-1/consent-checkpoint', 409, {
        detail: {
          code: 'checkpoint_already_resolved',
          message: '检查点已以不同动作结束',
        },
      }),
    )
    await expect(
      resolveConsentCheckpoint('t-1', 'skipped'),
    ).rejects.toBeTruthy()
  })

  it('任务 ID 被正确 URL 编码', async () => {
    const cap = capture()
    server.use(
      cap.get('/tasks/:taskId/consent-checkpoint', 200, awaiting),
    )
    await getConsentCheckpoint('a b/c')
    expect(cap.seen[0].url.pathname).toContain('a%20b%2Fc')
  })

  it('请求体只包含 action 与 note，不含任何密钥字段', async () => {
    const cap = capture()
    server.use(
      cap.post('/tasks/t-1/consent-checkpoint', 200, {
        ...awaiting,
        status: 'confirmed',
        resolved_by_action: 'confirmed',
      }),
    )
    await resolveConsentCheckpoint('t-1', 'confirmed', 'note')
    const body = cap.seen[0].body as Record<string, unknown>
    expect(Object.keys(body).sort()).toEqual(['action', 'note'])
    expect(JSON.stringify(body)).not.toContain('api_key')
  })
})
