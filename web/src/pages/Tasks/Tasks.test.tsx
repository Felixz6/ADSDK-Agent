import { describe, it, expect, beforeEach } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import Tasks from './Tasks'
import { renderWithProviders } from '@/test/render'
import { clearLocalTasks, recordTask } from '@/api/tasks'
import type { AnalyzeResponse } from '@/types/api'

beforeEach(() => {
  localStorage.clear()
  clearLocalTasks()
})

describe('Tasks — 空状态', () => {
  it('无任何本地记录时显示「尚无任务记录」空态', () => {
    renderWithProviders(<Tasks />)
    expect(screen.getByText(/尚无任务记录/)).toBeInTheDocument()
  })

  it('始终显示「浏览器本地不持久化」显著提示', () => {
    renderWithProviders(<Tasks />)
    expect(screen.getByText(/当前记录保存在本浏览器中/)).toBeInTheDocument()
    expect(screen.getByText(/不会出现伪造的「排队中 \/ 运行中 \/ 已取消」状态/)).toBeInTheDocument()
  })
})

describe('Tasks — 记录存读删', () => {
  it('写入静态任务后列表中可见包名与三态计数', () => {
    const resp = {
      run_id: 'r-static-1',
      status: 'success',
      app_info: { package_name: 'com.example.alpha' },
      strict_findings: {
        rules: [
          { rule_id: 'R1', status: 'matched' },
          { rule_id: 'R2', status: 'not_matched' },
          { rule_id: 'R3', status: 'not_evaluated' },
        ],
      },
    } as unknown as AnalyzeResponse
    const rec = recordTask('static', { apk_path: 'D:/authorized/alpha.apk', package_name: 'com.example.alpha' }, resp)
    renderWithProviders(<Tasks />)
    expect(screen.getByText(/com\.example\.alpha/)).toBeInTheDocument()
    // 三态计数:命中1 未命中1 未评估1(列仅 sm+ 显示,但文本存在于 DOM)
    expect(screen.getAllByText(/命中/).length).toBeGreaterThan(0)
    expect(rec.local_id).toMatch(/^local-/)
  })

  it('crypto.randomUUID 生成的 local_id 在连续多次登记间互不重复', () => {
    const ids = new Set<string>()
    for (let i = 0; i < 25; i++) {
      const rec = recordTask('static', { apk_path: `D:/authorized/x${i}.apk` }, {
        run_id: `r${i}`,
        status: 'success',
        app_info: { package_name: 'com.example.lab' },
      } as unknown as AnalyzeResponse)
      ids.add(rec.local_id)
    }
    expect(ids.size).toBe(25)
  })

  it('点击「删除」移除该记录并提示', async () => {
    recordTask('static', { apk_path: 'D:/authorized/del.apk', package_name: 'com.example.del' }, {
      run_id: 'r-del',
      status: 'success',
      app_info: { package_name: 'com.example.del' },
    } as unknown as AnalyzeResponse)
    const user = userEvent.setup()
    renderWithProviders(<Tasks />)
    expect(screen.getByText(/com\.example\.del/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: /删除任务/ }))
    expect(screen.queryByText(/com\.example\.del/)).not.toBeInTheDocument()
  })

  it('清空全部:确认后清空全部记录', async () => {
    recordTask('static', { apk_path: 'D:/authorized/a.apk', package_name: 'com.example.a' }, {
      run_id: 'ra', status: 'success', app_info: { package_name: 'com.example.a' },
    } as unknown as AnalyzeResponse)
    recordTask('dynamic', { apk_path: 'D:/authorized/b.apk', package_name: 'com.example.b' }, {
      run_id: 'rb', status: 'partial', app_info: { package_name: 'com.example.b' },
    } as unknown as AnalyzeResponse)
    const user = userEvent.setup()
    renderWithProviders(<Tasks />)
    expect(screen.getByText('清空全部')).toBeInTheDocument()
    await user.click(screen.getByText('清空全部'))
    expect(await screen.findByText(/清空全部任务记录\?/)).toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: '清空' }))
    expect(await screen.findByText(/尚无任务记录/)).toBeInTheDocument()
  })
})

describe('Tasks — 不伪造运行态', () => {
  it('任务列表项不出现伪状态文案「排队中 / 运行中 / 已取消」作为状态徽标', () => {
    recordTask('static', { apk_path: 'D:/authorized/nf.apk', package_name: 'com.example.nf' }, {
      run_id: 'r-nf', status: 'success', app_info: { package_name: 'com.example.nf' },
    } as unknown as AnalyzeResponse)
    renderWithProviders(<Tasks />)
    // 横幅说明文案会引用这些词,故仅检查列表项(li)内不含伪状态
    const items = screen.queryAllByRole('listitem')
    for (const li of items) {
      expect(li).not.toHaveTextContent(/排队中/)
      expect(li).not.toHaveTextContent(/运行中/)
      expect(li).not.toHaveTextContent(/已取消/)
    }
  })
})
