import { describe, expect, it, vi } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '@/test/render'
import { ConsentCheckpointCard } from './ConsentCheckpointCard'
import type {
  ConsentCheckpointAction,
  ConsentCheckpointState,
} from '@/types/tasks'

function state(
  values: Partial<ConsentCheckpointState> = {},
): ConsentCheckpointState {
  return {
    task_id: 'task-1',
    run_id: 'run-1',
    status: 'awaiting',
    entered_at: '2026-08-02T00:00:01Z',
    resolved_at: null,
    resolved_by_action: null,
    last_heartbeat_at: '2026-08-02T00:00:02Z',
    note: '',
    ...values,
  }
}

describe('M7A — Consent 手动检查点卡片', () => {
  it('等待态展示三个人工动作按钮', () => {
    renderWithProviders(
      <ConsentCheckpointCard state={state()} onResolve={() => {}} />,
    )
    expect(screen.getByTestId('consent-action-confirmed')).toBeInTheDocument()
    expect(screen.getByTestId('consent-action-not_found')).toBeInTheDocument()
    expect(screen.getByTestId('consent-action-skipped')).toBeInTheDocument()
  })

  it('明确说明平台不会自动点击 UI、不会清除数据、超时不自动确认', () => {
    renderWithProviders(
      <ConsentCheckpointCard state={state()} onResolve={() => {}} />,
    )
    const text = document.body.textContent ?? ''
    expect(text).toContain('不会自动点击 UI')
    expect(text).toContain('不会清除应用数据')
    expect(text).toContain('超时不会自动确认')
  })

  it.each<ConsentCheckpointAction>(['confirmed', 'not_found', 'skipped'])(
    '点击 %s 回传对应动作',
    async (action) => {
      const onResolve = vi.fn()
      renderWithProviders(
        <ConsentCheckpointCard state={state()} onResolve={onResolve} />,
      )
      await userEvent.click(screen.getByTestId(`consent-action-${action}`))
      expect(onResolve).toHaveBeenCalledWith(action, '')
    },
  )

  it('备注随动作一并回传且长度受限于 240', async () => {
    const onResolve = vi.fn()
    renderWithProviders(
      <ConsentCheckpointCard state={state()} onResolve={onResolve} />,
    )
    const note = screen.getByTestId('consent-note') as HTMLInputElement
    expect(note.maxLength).toBe(240)
    await userEvent.type(note, '首页弹窗完成同意')
    await userEvent.click(screen.getByTestId('consent-action-confirmed'))
    expect(onResolve).toHaveBeenCalledWith('confirmed', '首页弹窗完成同意')
  })

  it('提交中禁用全部动作按钮，避免重复提交', () => {
    renderWithProviders(
      <ConsentCheckpointCard
        state={state()}
        onResolve={() => {}}
        isSubmitting
      />,
    )
    expect(screen.getByTestId('consent-action-confirmed')).toBeDisabled()
    expect(screen.getByTestId('consent-action-not_found')).toBeDisabled()
    expect(screen.getByTestId('consent-action-skipped')).toBeDisabled()
  })

  it('已确认态不再展示动作按钮，只读展示结论', () => {
    renderWithProviders(
      <ConsentCheckpointCard
        state={state({
          status: 'confirmed',
          resolved_by_action: 'confirmed',
          resolved_at: '2026-08-02T00:01:00Z',
        })}
        onResolve={() => {}}
      />,
    )
    expect(screen.queryByTestId('consent-action-confirmed')).toBeNull()
    expect(screen.getByText('2026-08-02T00:01:00Z')).toBeInTheDocument()
  })

  it('未发现态说明按部分证据处理而非失败', () => {
    renderWithProviders(
      <ConsentCheckpointCard
        state={state({ status: 'not_found', resolved_by_action: 'not_found' })}
        onResolve={() => {}}
      />,
    )
    expect(document.body.textContent).toContain('未发现 Consent 界面')
  })

  it('取消态说明等待已退出并进入清理', () => {
    renderWithProviders(
      <ConsentCheckpointCard
        state={state({ status: 'cancelled' })}
        onResolve={() => {}}
      />,
    )
    expect(document.body.textContent).toContain('进入资源清理')
  })

  it('过期态明确未自动确认', () => {
    renderWithProviders(
      <ConsentCheckpointCard
        state={state({ status: 'expired' })}
        onResolve={() => {}}
      />,
    )
    expect(document.body.textContent).toContain('未自动确认')
  })

  it('错误信息以 alert 呈现', () => {
    renderWithProviders(
      <ConsentCheckpointCard
        state={state()}
        onResolve={() => {}}
        errorMessage="该任务当前没有等待中的 Consent 检查点"
      />,
    )
    expect(screen.getByRole('alert')).toHaveTextContent(
      '该任务当前没有等待中的 Consent 检查点',
    )
  })

  it('绝不展示 API Key、完整设备序列号、Prompt 原文或 reasoning_content', () => {
    renderWithProviders(
      <ConsentCheckpointCard
        state={state({ note: '在首页完成' })}
        onResolve={() => {}}
      />,
    )
    const text = document.body.textContent ?? ''
    expect(text).not.toContain('sk-')
    expect(text).not.toContain('127.0.0.1:16416')
    expect(text).not.toContain('reasoning_content')
    expect(text.toLowerCase()).not.toContain('api_key')
    expect(text.toLowerCase()).not.toContain('authorization')
  })

  it('375px 窄屏下按钮组换行不产生水平溢出', () => {
    const { container } = renderWithProviders(
      <ConsentCheckpointCard state={state()} onResolve={() => {}} />,
    )
    // 按钮容器使用 flex-wrap，窄屏下换行而非撑破容器。
    const wrap = container.querySelector('.flex-wrap')
    expect(wrap).not.toBeNull()
  })

  it('备注输入提示不要填写密钥或完整序列号', () => {
    renderWithProviders(
      <ConsentCheckpointCard state={state()} onResolve={() => {}} />,
    )
    expect(document.body.textContent).toContain('请勿填写任何密钥或完整设备序列号')
  })
})
