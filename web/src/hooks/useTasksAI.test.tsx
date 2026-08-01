import { describe, it, expect, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { renderHook, waitFor } from '@testing-library/react'
import {
  useTaskAIRuntimeDiagnostics,
  useRegenerateTaskAIReport,
} from './useTasks'
import { server } from '@/test/msw-server'
import { makeTestQueryClient } from '@/test/render'
import { QueryClientProvider } from '@tanstack/react-query'

const API = 'http://127.0.0.1:8000'

/** 用独立 QueryClient 包裹 hook,避免污染其它用例的缓存。 */
function wrapper(queryClient = makeTestQueryClient()) {
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('useTaskAIRuntimeDiagnostics', () => {
  it('查询 /tasks/{id}/ai-runtime-diagnostics 并返回 payload', async () => {
    server.use(
      http.get(`${API}/tasks/t-dx/ai-runtime-diagnostics`, () =>
        HttpResponse.json({
          task_id: 't-dx',
          status: 'completed',
          available: true,
          payload: { outcome: 'ok', total_rounds: 2 },
        }),
      ),
    )
    const { result } = renderHook(
      () => useTaskAIRuntimeDiagnostics('t-dx'),
      { wrapper: wrapper() },
    )
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(result.current.data?.task_id).toBe('t-dx')
    expect(result.current.data?.payload?.total_rounds).toBe(2)
  })

  it('taskId 为 undefined 时禁用查询(不发请求)', async () => {
    const { result } = renderHook(
      () => useTaskAIRuntimeDiagnostics(undefined),
      { wrapper: wrapper() },
    )
    expect(result.current.isPending).toBe(true)
    expect(result.current.fetchStatus).toBe('idle')
  })
})

describe('useRegenerateTaskAIReport', () => {
  it('useCache 透传到查询参数且成功返回摘要', async () => {
    let postedUrl = ''
    server.use(
      http.post(`${API}/tasks/t-r/ai-report/regenerate`, ({ request }) => {
        postedUrl = request.url
        return HttpResponse.json({
          task_id: 't-r',
          status: 'completed',
          ai_status: 'completed',
          ai_section: { status: 'completed' },
        })
      }),
    )
    const queryClient = makeTestQueryClient()
    const invalidateSpy = vi.spyOn(queryClient, 'invalidateQueries')
    const { result } = renderHook(
      () => useRegenerateTaskAIReport('t-r', 'ai-report' as const),
      { wrapper: wrapper(queryClient) },
    )
    result.current.mutateAsync(true)
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(new URL(postedUrl).searchParams.get('use_cache')).toBe('true')
    expect(result.current.data?.ai_status).toBe('completed')
    // 成功后失效 ai-report 与 ai-runtime-diagnostics 查询,使前端拉新产物。
    expect(invalidateSpy).toHaveBeenCalled()
  })

  it('空 useCache 不附加查询参数(沿用后端缓存设置)', async () => {
    let postedUrl = ''
    server.use(
      http.post(`${API}/tasks/t-r/ai-report/regenerate`, ({ request }) => {
        postedUrl = request.url
        return HttpResponse.json({
          task_id: 't-r',
          status: 'completed',
          ai_status: 'completed',
          ai_section: {},
        })
      }),
    )
    const { result } = renderHook(
      () => useRegenerateTaskAIReport('t-r', 'ai-report' as const),
      { wrapper: wrapper() },
    )
    await result.current.mutateAsync(undefined)
    await waitFor(() => expect(result.current.isSuccess).toBe(true))
    expect(new URL(postedUrl).search).toBe('')
  })
})
