import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import { renderWithProviders } from '@/test/render'
import { EvidenceCorrelationCard } from './EvidenceCorrelationCard'
import type { EvidenceCorrelation } from '@/types/api'

function correlation(
  values: Partial<EvidenceCorrelation> = {},
): EvidenceCorrelation {
  return {
    schema_version: 'correlation-v1',
    status: 'evaluated',
    window_ms: 2500,
    items: [{
      correlation_id: 'corr-1',
      dynamic_event_id: 'evt-1',
      network_request_id: 'req-1',
      event_type: 'identifier',
      request_host: 'api.example.test',
      request_method: 'POST',
      delta_ms: 238,
      consent_state: 'post_consent',
      confidence: 'high',
      reason_codes: ['monotonic_near', 'same_consent_state'],
      summary: '时间上接近，可能相关；不表示因果关系',
    }],
    summary: {
      dynamic_event_count: 1,
      network_request_count: 1,
      correlated_pair_count: 1,
      high_confidence_count: 1,
      medium_confidence_count: 0,
      low_confidence_count: 0,
    },
    limitations: ['关联仅表示时间接近，不证明因果关系'],
    ...values,
  }
}

describe('EvidenceCorrelationCard', () => {
  it('展示 evaluated 状态、计数和窗口', () => {
    renderWithProviders(<EvidenceCorrelationCard correlation={correlation()} />)
    expect(screen.getByText('evaluated')).toBeInTheDocument()
    expect(screen.getByText('时间窗口 2500 ms')).toBeInTheDocument()
    expect(screen.getByText('关联数量')).toBeInTheDocument()
  })

  it('展示 no_observations 空态', () => {
    renderWithProviders(
      <EvidenceCorrelationCard correlation={correlation({
        status: 'no_observations',
        items: [],
      })} />,
    )
    expect(screen.getAllByText(/没有形成可供关联的观察记录/).length).toBeGreaterThan(0)
  })

  it('展示 not_evaluated 空态', () => {
    renderWithProviders(
      <EvidenceCorrelationCard correlation={correlation({
        status: 'not_evaluated',
        items: [],
      })} />,
    )
    expect(screen.getAllByText(/时间信息不足/).length).toBeGreaterThan(0)
  })

  it('展示高、中、低置信徽标', () => {
    const base = correlation().items[0]
    renderWithProviders(
      <EvidenceCorrelationCard correlation={correlation({
        items: [
          base,
          { ...base, correlation_id: 'corr-2', confidence: 'medium' },
          { ...base, correlation_id: 'corr-3', confidence: 'low' },
        ],
      })} />,
    )
    expect(screen.getAllByText('高置信').length).toBeGreaterThan(0)
    expect(screen.getAllByText('中置信').length).toBeGreaterThan(0)
    expect(screen.getAllByText('低置信').length).toBeGreaterThan(0)
  })

  it('展示有符号时间差', () => {
    renderWithProviders(<EvidenceCorrelationCard correlation={correlation()} />)
    expect(screen.getByText(/时间差 238 ms/)).toBeInTheDocument()
  })

  it('将 Consent 状态显示为中文', () => {
    renderWithProviders(<EvidenceCorrelationCard correlation={correlation()} />)
    expect(screen.getByText(/Consent 后/)).toBeInTheDocument()
  })

  it('兼容旧报告缺失字段', () => {
    renderWithProviders(<EvidenceCorrelationCard />)
    expect(screen.getByText(/旧版本报告未生成事件—网络关联结果/)).toBeInTheDocument()
  })

  it('提供折叠技术详情', () => {
    renderWithProviders(<EvidenceCorrelationCard correlation={correlation()} />)
    expect(screen.getByText('技术详情').closest('details')).toBeInTheDocument()
  })

  it('窄屏容器使用 min-w-0 且技术内容可滚动', () => {
    const { container } = renderWithProviders(
      <EvidenceCorrelationCard correlation={correlation()} />,
    )
    expect(container.querySelector('.min-w-0')).toBeInTheDocument()
    expect(container.querySelector('pre.overflow-auto')).toBeInTheDocument()
  })
})
