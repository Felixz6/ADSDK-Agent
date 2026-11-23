import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { act, renderHook, waitFor } from '@testing-library/react'
import { QueryClientProvider } from '@tanstack/react-query'
import { useLiveTask } from './useTasks'
import { server } from '@/test/msw-server'
import { makeTestQueryClient } from '@/test/render'
import type { TaskRecord } from '@/types/tasks'

const API = 'http://127.0.0.1:8000'

function makeTask(overrides: Partial<TaskRecord> = {}): TaskRecord {
  return {
    id: 't-live',
    task_type: 'static',
    status: 'queued',
    apk_path: 'D:/samples/app.apk',
    apk_snapshot_path: null,
    apk_sha256: null,
    package_name: null,
    app_name: null,
    version_name: null,
    version_code: null,
    device_id: null,
    enable_traffic: false,
    enable_ui_stimulation: false,
    progress_percent: 0,
    current_stage: null,
    cancelled_at_stage: null,
    error_code: null,
    error_message: null,
    report_json_path: null,
    report_markdown_path: null,
    report_html_path: null,
    risk_score: null,
    risk_level: null,
    request_payload: {},
    created_at: '2026-11-23T00:00:00Z',
    started_at: null,
    completed_at: null,
    updated_at: '2026-11-23T00:00:00Z',
    steps: [],
    ...overrides,
  }
}

class FakeWebSocket {
  static instances: FakeWebSocket[] = []

  readonly url: string
  onopen: ((ev: Event) => void) | null = null
  onmessage: ((ev: MessageEvent) => void) | null = null
  onerror: ((ev: Event) => void) | null = null
  onclose: ((ev: CloseEvent) => void) | null = null
  close = vi.fn(() => {
    this.onclose?.(new CloseEvent('close', { code: 1000 }))
  })

  constructor(url: string) {
    this.url = url
    FakeWebSocket.instances.push(this)
  }

  emitOpen() {
    this.onopen?.(new Event('open'))
  }

  emitMessage(payload: TaskRecord) {
    this.onmessage?.(new MessageEvent('message', { data: JSON.stringify(payload) }))
  }

  emitClose(code = 1006) {
    this.onclose?.(new CloseEvent('close', { code }))
  }
}

function wrapper(queryClient = makeTestQueryClient()) {
  return ({ children }: { children: React.ReactNode }) => (
    <QueryClientProvider client={queryClient}>{children}</QueryClientProvider>
  )
}

describe('useLiveTask', () => {
  beforeEach(() => {
    FakeWebSocket.instances = []
    vi.stubGlobal('WebSocket', FakeWebSocket)
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('keeps one WebSocket open across queued -> running transition', async () => {
    server.use(http.get(`${API}/tasks/t-live`, () => HttpResponse.json(makeTask({ status: 'queued' }))))

    const { result } = renderHook(() => useLiveTask('t-live'), { wrapper: wrapper() })

    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const ws = FakeWebSocket.instances[0]

    act(() => {
      ws.emitOpen()
    })
    expect(result.current.socketConnected).toBe(true)

    act(() => {
      ws.emitMessage(
        makeTask({
          status: 'running',
          progress_percent: 48,
          current_stage: 'apk_unpack',
          updated_at: '2026-11-23T00:00:01Z',
        }),
      )
    })

    await waitFor(() => expect(result.current.data?.status).toBe('running'))
    expect(result.current.data?.progress_percent).toBe(48)
    expect(FakeWebSocket.instances).toHaveLength(1)
    expect(ws.close).not.toHaveBeenCalled()
  })

  it('reconnects with exponential backoff after unexpected close and stops at terminal status', async () => {
    vi.useFakeTimers({ shouldAdvanceTime: true })
    server.use(http.get(`${API}/tasks/t-live`, () => HttpResponse.json(makeTask({ status: 'running' }))))

    const { result } = renderHook(() => useLiveTask('t-live'), { wrapper: wrapper() })

    await waitFor(() => expect(FakeWebSocket.instances).toHaveLength(1))
    const first = FakeWebSocket.instances[0]
    act(() => {
      first.emitOpen()
    })
    expect(result.current.socketConnected).toBe(true)

    // Unexpected close triggers 1000ms backoff reconnect
    act(() => {
      first.emitClose(1006)
    })
    expect(result.current.socketConnected).toBe(false)
    expect(FakeWebSocket.instances).toHaveLength(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(999)
    })
    expect(FakeWebSocket.instances).toHaveLength(1)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1)
    })
    expect(FakeWebSocket.instances).toHaveLength(2)

    // Second socket closes without opening -> backoff doubles to 2000ms
    const second = FakeWebSocket.instances[1]
    act(() => {
      second.emitClose(1006)
    })
    await act(async () => {
      await vi.advanceTimersByTimeAsync(1_999)
    })
    expect(FakeWebSocket.instances).toHaveLength(2)

    await act(async () => {
      await vi.advanceTimersByTimeAsync(1)
    })
    expect(FakeWebSocket.instances).toHaveLength(3)

    // Third socket delivers terminal status -> stops reconnecting permanently
    const third = FakeWebSocket.instances[2]
    act(() => {
      third.emitOpen()
      third.emitMessage(
        makeTask({
          status: 'completed',
          progress_percent: 100,
          current_stage: 'completed',
          updated_at: '2026-11-23T00:00:05Z',
        }),
      )
    })
    await waitFor(() => expect(result.current.data?.status).toBe('completed'))

    await act(async () => {
      await vi.advanceTimersByTimeAsync(30_000)
    })
    expect(FakeWebSocket.instances).toHaveLength(3)
  })
})
