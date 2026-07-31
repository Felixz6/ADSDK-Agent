import { describe, expect, it } from 'vitest'
import { screen, within } from '@testing-library/react'
import { AIOrchestrationCard } from './AIOrchestrationCard'
import { AISynthesisCard } from './AISynthesisCard'
import { renderWithProviders } from '@/test/render'
import type { AIOrchestrationSection } from '@/types/tasks'

function makeSection(overrides: Partial<AIOrchestrationSection> = {}): AIOrchestrationSection {
  return {
    schema_version: 'ai-report-v1',
    status: 'completed',
    evidence_digest_hash: 'abc123',
    error_code: null,
    unavailable_reason: null,
    plan: {
      schema_version: 'ai-plan-v1',
      objective: '静态隐私检查',
      strategy: 'static_only',
      generated_by: 'ai',
      steps: [
        {
          step_id: 's1',
          tool_name: 'static_analysis',
          reason: '识别 SDK 与权限',
          arguments: {},
          depends_on: [],
          requires_confirmation: false,
        },
        {
          step_id: 's2',
          tool_name: 'dynamic_analysis',
          reason: '采集运行时行为',
          arguments: {},
          depends_on: ['s1'],
          requires_confirmation: true,
        },
      ],
      expected_outputs: [],
      stop_conditions: [],
      limitations: [],
    },
    report: {
      schema_version: 'ai-report-v1',
      status: 'completed',
      executive_summary: '本次共识别 2 个 SDK。',
      key_findings: [
        {
          title: 'Consent 前网络请求',
          severity: 'medium',
          confidence: 'medium',
          summary: '在同意前观察到请求。',
          evidence_refs: ['ev-1', 'ev-2'],
        },
      ],
      evidence_gaps: ['本次没有可信的动态事件证据'],
      risk_priorities: ['[medium] Consent 前网络请求'],
      recommended_actions: ['补充一次可信动态采集'],
      evidence_refs: ['ev-1'],
      limitations: ['结论仅覆盖本次采集窗口'],
      disclaimer:
        'AI 综合研判基于本次任务中已有的结构化技术证据生成。AI 不直接读取或验证原始敏感数据，本结果不构成法律合规结论。未观察到某项行为不代表该行为不会在其他设备、时间、账号或操作路径下发生。',
      usage: {},
    },
    usage: {
      input_tokens: 1200,
      output_tokens: 400,
      cached_tokens: 0,
      estimated_tokens: 0,
      tool_call_count: 2,
      model_round_count: 2,
      latency_ms: 900,
      cache_hit: false,
      budget_exhausted: false,
      usage_is_estimate: false,
    },
    trace: {
      trace_id: 't1',
      model_round_count: 2,
      cache_hit: false,
      budget_exhausted: false,
      steps: [
        {
          step_id: 's1',
          tool_name: 'static_analysis',
          started_at: null,
          ended_at: null,
          status: 'success',
          safe_summary: '静态分析完成',
          artifact_refs: ['report.json'],
          reused: true,
          confirmation_required: false,
          decision_summary: null,
        },
        {
          step_id: 's2',
          tool_name: 'dynamic_analysis',
          started_at: null,
          ended_at: null,
          status: 'blocked_confirmation_required',
          safe_summary: '需要确认，未执行',
          artifact_refs: [],
          reused: false,
          confirmation_required: true,
          decision_summary: null,
        },
      ],
    },
    ...overrides,
  }
}

describe('AIOrchestrationCard — 计划与工具状态', () => {
  it('展示计划步骤、工具状态与已复用标记', () => {
    renderWithProviders(<AIOrchestrationCard section={makeSection()} />)

    const card = screen.getByTestId('ai-orchestration-card')
    expect(within(card).getByText('静态分析')).toBeInTheDocument()
    expect(within(card).getByText('识别 SDK 与权限')).toBeInTheDocument()
    expect(within(card).getByText('已复用')).toBeInTheDocument()
    expect(within(card).getByText('成功')).toBeInTheDocument()
  })

  it('展示 Token 使用与模型调用轮数', () => {
    renderWithProviders(<AIOrchestrationCard section={makeSection()} />)

    const card = screen.getByTestId('ai-orchestration-card')
    expect(within(card).getByText('Token(实际)')).toBeInTheDocument()
    expect(within(card).getByText('1600')).toBeInTheDocument()
    // 定位到「模型调用轮数」这一格,避免与其它同值指标混淆。
    const roundsValue = within(card).getByText('模型调用轮数').closest('dt')?.nextElementSibling
    expect(roundsValue).toHaveTextContent('2')
  })

  it('估算 Token 明确标注为估算值', () => {
    const section = makeSection()
    section.usage = { ...section.usage, usage_is_estimate: true, estimated_tokens: 500 }
    renderWithProviders(<AIOrchestrationCard section={section} />)

    const card = screen.getByTestId('ai-orchestration-card')
    expect(within(card).getByText('Token(估算)')).toBeInTheDocument()
    expect(within(card).getByText(/明确标注的估算值/)).toBeInTheDocument()
  })

  it('命中缓存时展示缓存标记', () => {
    const section = makeSection()
    section.usage = { ...section.usage, cache_hit: true }
    renderWithProviders(<AIOrchestrationCard section={section} />)

    expect(within(screen.getByTestId('ai-orchestration-card')).getByText('命中缓存')).toBeInTheDocument()
  })

  it('触及预算时展示 budget_exhausted 状态', () => {
    const section = makeSection({ status: 'budget_exhausted' })
    section.usage = { ...section.usage, budget_exhausted: true }
    renderWithProviders(<AIOrchestrationCard section={section} />)

    const card = screen.getByTestId('ai-orchestration-card')
    expect(within(card).getByText('已触及预算上限')).toBeInTheDocument()
    expect(within(card).getByText('预算已用尽')).toBeInTheDocument()
  })

  it('展示 confirmation_required 阻塞项且不声称已执行', () => {
    renderWithProviders(<AIOrchestrationCard section={makeSection()} />)

    const blocked = screen.getByTestId('ai-blocked-confirmations')
    expect(within(blocked).getByText(/待确认项（1）/)).toBeInTheDocument()
    expect(within(blocked).getByText(/需显式确认后才会改变设备状态/)).toBeInTheDocument()
  })

  it('旧任务没有 AI 字段时给出中性提示', () => {
    renderWithProviders(<AIOrchestrationCard section={null} />)

    const card = screen.getByTestId('ai-orchestration-card')
    expect(within(card).getByText(/本任务未使用 AI 编排/)).toBeInTheDocument()
    expect(within(card).getByText(/确定性分析与报告不受影响/)).toBeInTheDocument()
  })

  it('使用确定性默认计划时明确标注', () => {
    const section = makeSection()
    section.plan = { ...section.plan, generated_by: 'default' }
    renderWithProviders(<AIOrchestrationCard section={section} />)

    expect(within(screen.getByTestId('ai-orchestration-card')).getByText('确定性默认计划')).toBeInTheDocument()
  })
})

describe('AISynthesisCard — AI 综合研判', () => {
  it('展示执行摘要、风险优先级、关键发现与建议动作', () => {
    renderWithProviders(<AISynthesisCard section={makeSection()} />)

    const card = screen.getByTestId('ai-synthesis-card')
    expect(within(card).getByText('本次共识别 2 个 SDK。')).toBeInTheDocument()
    expect(within(card).getByText('[medium] Consent 前网络请求')).toBeInTheDocument()
    expect(within(card).getByText('Consent 前网络请求')).toBeInTheDocument()
    expect(within(card).getByText('补充一次可信动态采集')).toBeInTheDocument()
    expect(within(card).getByText('本次没有可信的动态事件证据')).toBeInTheDocument()
  })

  it('展示 Evidence refs', () => {
    renderWithProviders(<AISynthesisCard section={makeSection()} />)

    const card = screen.getByTestId('ai-synthesis-card')
    expect(within(card).getByText(/证据引用：ev-1、ev-2/)).toBeInTheDocument()
    expect(within(card).getByText('Evidence refs')).toBeInTheDocument()
  })

  it('始终展示固定免责声明', () => {
    renderWithProviders(<AISynthesisCard section={makeSection()} />)

    const disclaimer = screen.getByTestId('ai-disclaimer')
    expect(disclaimer).toHaveTextContent('不构成法律合规结论')
    expect(disclaimer).toHaveTextContent('未观察到某项行为不代表该行为不会在其他设备')
  })

  it('无证据引用的发现标注为已降级', () => {
    const section = makeSection()
    section.report = {
      ...section.report,
      key_findings: [
        {
          title: '无证据结论',
          severity: 'low',
          confidence: 'low',
          summary: '提示性描述',
          evidence_refs: [],
        },
      ],
    }
    renderWithProviders(<AISynthesisCard section={section} />)

    expect(within(screen.getByTestId('ai-synthesis-card')).getByText(/无直接证据引用（已降级为提示）/)).toBeInTheDocument()
  })

  it('AI 未启用时展示中性说明且不伪造结论', () => {
    const section = makeSection({ status: 'disabled' })
    section.report = { ...section.report, executive_summary: '', key_findings: [] }
    renderWithProviders(<AISynthesisCard section={section} />)

    const card = screen.getByTestId('ai-synthesis-card')
    expect(within(card).getByText(/本次任务未启用 AI 综合研判/)).toBeInTheDocument()
    expect(within(card).getByText(/确定性证据与报告已完整生成/)).toBeInTheDocument()
  })

  it('旧报告没有 AI 字段时整个区块不渲染', () => {
    renderWithProviders(<AISynthesisCard section={null} />)

    expect(screen.queryByTestId('ai-synthesis-card')).not.toBeInTheDocument()
  })

  it('窄屏下关键容器不产生水平溢出', () => {
    renderWithProviders(<AISynthesisCard section={makeSection()} />)
    const card = screen.getByTestId('ai-synthesis-card')

    expect(card.className).toContain('min-w-0')
    expect(card.className).toContain('overflow-hidden')
    // 长文本必须允许折行,避免窄屏横向滚动。
    expect(card.querySelector('.break-words')).not.toBeNull()
  })
})
