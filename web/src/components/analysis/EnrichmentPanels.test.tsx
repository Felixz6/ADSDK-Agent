import { describe, expect, it } from 'vitest'
import { fireEvent, render, screen } from '@testing-library/react'
import { RiskSummaryCard } from './RiskSummaryCard'
import { BehaviorTimeline } from './BehaviorTimeline'
import { SdkIntelligencePanel } from './SdkIntelligencePanel'
import { ComplianceInsight } from '@/components/report/ComplianceInsight'
import type { BehaviorTimelineData, RiskLevel, RiskSummary } from '@/types/api'

function risk(level: RiskLevel): RiskSummary {
  return {
    score: level === 'critical' ? 90 : level === 'high' ? 70 : level === 'medium' ? 40 : 10,
    level,
    confidence: 'medium',
    evaluated_rule_count: 2,
    unevaluated_rule_count: 1,
    category_scores: [],
    top_risks: [],
    confidence_reasons: ['1 条规则证据不足'],
    calculation_version: 'risk-v1',
  }
}

describe('RiskSummaryCard', () => {
  it.each([
    ['low', '低风险'],
    ['medium', '中风险'],
    ['high', '高风险'],
    ['critical', '严重风险'],
  ] as const)('renders %s level', (level, label) => {
    render(<RiskSummaryCard summary={risk(level)} />)
    expect(screen.getByText(label)).toBeInTheDocument()
  })

  it('keeps old reports readable', () => {
    render(<RiskSummaryCard summary={null} />)
    expect(screen.getByText(/旧版报告未包含/)).toBeInTheDocument()
  })
})

const timeline: BehaviorTimelineData = {
  start_monotonic: 1000,
  consent_monotonic: 1200,
  timing_reliable: true,
  warnings: [],
  timeline_version: 'timeline-v1',
  events: [
    {
      id: 'pre',
      relative_ms: 100,
      timestamp_utc: null,
      source: 'frida',
      category: 'identifier',
      title: '读取 Android ID',
      description: '调用标识符 API',
      consent_state: 'pre_consent',
      severity: 'high',
      evidence_ref: 'events.raw.jsonl#1',
    },
    {
      id: 'unknown',
      relative_ms: null,
      timestamp_utc: null,
      source: 'network',
      category: 'network',
      title: '网络请求',
      description: '时间缺失',
      consent_state: 'unknown',
      severity: 'medium',
      evidence_ref: 'traffic/requests.jsonl#1',
    },
    {
      id: 'post',
      relative_ms: 250,
      timestamp_utc: null,
      source: 'control',
      category: 'consent',
      title: 'Consent 已确认',
      description: '边界事件',
      consent_state: 'post_consent',
      severity: 'medium',
      evidence_ref: 'sessions.json#timeline',
    },
  ],
}

describe('BehaviorTimeline', () => {
  it('renders consent boundary states and filters', () => {
    render(<BehaviorTimeline timeline={timeline} />)
    expect(screen.getAllByText('同意前').length).toBeGreaterThan(0)
    expect(screen.getAllByText('时间不明').length).toBeGreaterThan(0)
    expect(screen.getByText('Consent 边界')).toBeInTheDocument()
    fireEvent.change(screen.getByLabelText('Consent 筛选'), { target: { value: 'unknown' } })
    expect(screen.queryByText('读取 Android ID')).not.toBeInTheDocument()
    expect(screen.getByText('网络请求')).toBeInTheDocument()
  })
})

describe('SdkIntelligencePanel', () => {
  it('separates static recognition from dynamic correlation and expands evidence', () => {
    render(<SdkIntelligencePanel sdks={[{
      id: 'appsflyer',
      sdk_name: 'AppsFlyer',
      package: 'com.appsflyer',
      vendor: 'AppsFlyer',
      category: 'attribution',
      risk_level: 'medium',
      confidence: 0.9,
      version: null,
      capabilities: ['广告归因'],
      static_only: true,
      dynamic_correlated: false,
      evidence: [{ source_type: 'domain', relative_path: 'smali/A.smali', detector: 'domain_literal', description: '命中域名' }],
    }]} />)
    expect(screen.getByText(/仅静态识别/)).toBeInTheDocument()
    fireEvent.click(screen.getByText('AppsFlyer'))
    expect(screen.getByText(/smali\/A.smali/)).toBeInTheDocument()
  })
})

describe('ComplianceInsight', () => {
  it('renders evidence limitations', () => {
    render(<ComplianceInsight insight={{
      overall_assessment: '基于当前结构化证据。',
      key_findings: [],
      priority_actions: [],
      limitations: ['SSL Pinning 可能降低流量覆盖'],
      generator_version: 'insight-v1',
    }} />)
    expect(screen.getByText(/证据限制/)).toHaveTextContent('SSL Pinning')
  })
})
