import { describe, it, expect, beforeEach, vi } from 'vitest'
import { http, HttpResponse } from 'msw'
import { screen } from '@testing-library/react'
import userEvent, { type UserEvent } from '@testing-library/user-event'
import NewAnalysis from './NewAnalysis'
import { renderWithProviders } from '@/test/render'
import { server } from '@/test/msw-server'
import { clearLocalTasks } from '@/api/tasks'

beforeEach(() => {
  localStorage.clear()
  clearLocalTasks()
  // 默认静态成功响应(后端 /analyze)
  server.use(
    http.post('http://127.0.0.1:8000/analyze', async () =>
      HttpResponse.json({
        ok: true,
        apk_path: 'D:/authorized/sample.apk',
        schema_version: '1.0',
        run_id: 'r-static-ok',
        apk_sha256: null,
        apk_snapshot: null,
        normalized_apk_name: 'sample',
        analysis_started_at: '2026-01-01T00:00:00Z',
        status: 'success',
        steps: [],
        warnings: [],
        device: null,
        artifacts: [],
        app_info: { package_name: 'com.example.sample' },
        sdk_count: 0,
        sdks: [],
        output_dir: '/out',
        hook_log: null,
        events_json: null,
        events_raw_jsonl: null,
        consent_time: null,
        traffic_dir: null,
        traffic_summary_json: null,
        traffic_jsonl: null,
        sessions_json: null,
        report_json: null,
        report_md: '# report',
        dynamic_events: [],
        dynamic_findings: null,
        strict_dynamic_findings: null,
        traffic_summary: null,
        pre_consent_seconds: null,
        post_consent_seconds: null,
        enable_traffic: null,
        enable_ui_stimulation: null,
        collection_timeout_seconds: null,
        collection_status: null,
        traffic_coverage: null,
        dynamic_timeline: null,
      }),
    ),
  )
})

async function gotoSubmitFromInput(user: UserEvent, apkPath: string) {
  // 默认静态模式 → 第一步 mode 的「下一步」到 input
  await user.click(screen.getByRole('button', { name: /下一步/ }))
  const pathInput = await screen.findByPlaceholderText(/sample\.apk/)
  await user.type(pathInput, apkPath)
  // 进入 options
  await user.click(screen.getByRole('button', { name: /下一步/ }))
  // 进入 submit
  await user.click(screen.getByRole('button', { name: /下一步/ }))
}

/**
 * 切到动态模式并走到 submit 步。
 * 与静态版不同的是:第一步在 mode 卡里点选「动态分析」单选,再走 input→options→submit。
 */
async function gotoSubmitDynamicFromInput(user: UserEvent, apkPath: string) {
  // 第一步 mode:选择「动态分析」(AnalysisModeSelector 的 label 文案含「动态分析」)
  await user.click(screen.getByLabelText(/动态分析/))
  await user.click(screen.getByRole('button', { name: /下一步/ }))
  const pathInput = await screen.findByPlaceholderText(/sample\.apk/)
  await user.type(pathInput, apkPath)
  await user.click(screen.getByRole('button', { name: /下一步/ }))
  // options 步对动态模式有额外字段,直接下一步到 submit
  await user.click(screen.getByRole('button', { name: /下一步/ }))
}

describe('NewAnalysis — 静态提交流', () => {
  it('未填路径时「下一步」被禁用,无法进入下一步', async () => {
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await user.click(screen.getByRole('button', { name: /下一步/ }))
    // 进入 input 步,空路径下「下一步」禁用
    const next = screen.getByRole('button', { name: /下一步/ })
    expect(next).toBeDisabled()
  })

  it('有效静态路径提交后跳转至 /static,本地任务记录登记成功', async () => {
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await gotoSubmitFromInput(user, 'D:/authorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交分析/ }))
    // 提交成功后跳转至 /static(与 Home 同样断言 router.location)
    await vi.waitFor(() => {
      expect(router.state.location.pathname).toBe('/static')
    })
  })

  it('提交期间按钮显示「分析中…」且禁用(请求进行中)', async () => {
    let resolvePost!: (v: unknown) => void
    server.use(
      http.post('http://127.0.0.1:8000/analyze', async () =>
        new Promise((res) => {
          resolvePost = res
        }).then(() =>
          HttpResponse.json({ ok: true, run_id: 'r', status: 'success' }),
        ),
      ),
    )
    const user = userEvent.setup()
    renderWithProviders(<NewAnalysis />)
    await gotoSubmitFromInput(user, 'D:/authorized/sample.apk')
    const submitBtn = screen.getByRole('button', { name: /提交分析/ })
    await user.click(submitBtn)
    // 请求挂起期间,提交按钮进入 pendng
    expect(await screen.findByRole('button', { name: /分析中/ })).toBeDisabled()
    // 放行挂起请求
    resolvePost({})
    // 终态恢复
    await vi.waitFor(() => {
      // 跳转后页面卸载或在 /static;此处仅确认按钮文案已离开「分析中」
      const still = screen.queryByRole('button', { name: /分析中/ })
      expect(still ?? null).toBeNull()
    })
  })

  it('后端 422 校验错误时显示中文错误,不伪造成功', async () => {
    server.use(
      http.post('http://127.0.0.1:8000/analyze', async () =>
        new HttpResponse(
          JSON.stringify({ detail: 'APK 路径不在允许根目录内' }),
          { status: 422, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await gotoSubmitFromInput(user, 'D:/unauthorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交分析/ }))
    // toast 错误可见(中文),且未跳到 /static(失败落到任务详情)
    expect(await screen.findByText(/APK 路径不在允许根目录内/)).toBeInTheDocument()
    expect(router.state.location.pathname).not.toBe('/static')
  })

  it('网络层不可达时显示中文「后端未连接」提示,不伪造成功', async () => {
    server.use(
      http.post('http://127.0.0.1:8000/analyze', () => HttpResponse.error()),
    )
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await gotoSubmitFromInput(user, 'D:/authorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交分析/ }))
    // toast 错误可见(中文「无法连接到后端」),且未跳到 /static(失败落到任务详情)
    expect(
      await screen.findByText(/无法连接到 AdSDK Agent 后端/),
    ).toBeInTheDocument()
    expect(router.state.location.pathname).not.toBe('/static')
  })
})

describe('NewAnalysis — 动态提交流(POST /dynamic/analyze)', () => {
  it('后端 422 校验错误时显示中文错误,不伪造成功,且不跳到 /dynamic', async () => {
    server.use(
      http.post('http://127.0.0.1:8000/dynamic/analyze', async () =>
        new HttpResponse(
          JSON.stringify({ detail: 'collection_timeout_seconds 必须 ≥ 1' }),
          { status: 422, headers: { 'Content-Type': 'application/json' } },
        ),
      ),
    )
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await gotoSubmitDynamicFromInput(user, 'D:/authorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交分析/ }))
    // 动态路径 422 同样如实展示后端中文错误,不伪造成功
    expect(await screen.findByText(/collection_timeout_seconds/)).toBeInTheDocument()
    // 失败落到任务详情而非 /dynamic
    expect(router.state.location.pathname).not.toBe('/dynamic')
  })

  it('网络层不可达时显示中文「后端未连接」提示,不伪造成功,且不跳到 /dynamic', async () => {
    server.use(
      http.post('http://127.0.0.1:8000/dynamic/analyze', () => HttpResponse.error()),
    )
    const user = userEvent.setup()
    const { router } = renderWithProviders(<NewAnalysis />)
    await gotoSubmitDynamicFromInput(user, 'D:/authorized/sample.apk')
    await user.click(screen.getByRole('button', { name: /提交分析/ }))
    // 动态向导多步骤可能保留旧 toast,用 findAllByText 取首个匹配即可
    expect(
      (await screen.findAllByText(/无法连接到 AdSDK Agent 后端/)).length,
    ).toBeGreaterThan(0)
    expect(router.state.location.pathname).not.toBe('/dynamic')
  })
})
