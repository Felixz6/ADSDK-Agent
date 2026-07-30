import { describe, expect, it } from 'vitest'
import { screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { renderWithProviders } from '@/test/render'
import { PrivacyFindingsCard } from './PrivacyFindingsCard'
import type { PrivacyFinding, PrivacyFindings } from '@/types/api'

const DISCLAIMER =
  '本结果是基于当前观察窗口和技术证据形成的风险提示，不构成法律合规结论。'
  + '未观察到某项行为不代表该行为不会在其他设备、时间、账号或操作路径下发生。'

function finding(values: Partial<PrivacyFinding> = {}): PrivacyFinding {
  return {
    finding_id: 'pf-1',
    rule_id: 'PF-PRECONSENT-SENSITIVE-EVENT',
    title: 'Consent 前存在敏感 API 调用观察',
    category: 'privacy_sensitive_access',
    severity: 'high',
    confidence: 'high',
    finding_type: 'observed',
    consent_state: 'pre_consent',
    summary: '在 Consent 之前观察到 2 条敏感 API 调用记录。',
    explanation: '本次采集在可信 Consent 边界之前记录到敏感 API 调用。',
    reason_codes: ['pre_consent_sensitive_api_observed', 'observation_window_limited'],
    evidence_refs: [
      {
        evidence_type: 'dynamic_event',
        evidence_id: 'evt-1',
        artifact: 'events.json',
        label: 'identifier · Settings.Secure.getString',
      },
      {
        evidence_type: 'network_request',
        evidence_id: 'req-1',
        artifact: 'traffic/requests.jsonl',
        label: 'POST api.example.test/v1/track',
      },
    ],
    limitations: ['调用发生不等同于数据外发'],
    ...values,
  }
}

function findings(values: Partial<PrivacyFindings> = {}): PrivacyFindings {
  const items = values.findings ?? [finding()]
  return {
    schema_version: 'privacy-findings-v2',
    status: 'evaluated',
    disclaimer: DISCLAIMER,
    findings: items,
    rule_results: [
      {
        rule_id: 'PF-PRECONSENT-SENSITIVE-EVENT',
        status: 'matched',
        reason_codes: ['pre_consent_sensitive_api_observed'],
        evidence_refs: [],
        limitations: [],
      },
      {
        rule_id: 'PF-PRECONSENT-CORRELATED-ACTIVITY',
        status: 'not_evaluated',
        reason_codes: ['correlation_not_available'],
        evidence_refs: [],
        limitations: [],
      },
    ],
    summary: {
      finding_count: items.length,
      high_severity_count: 1,
      medium_severity_count: 0,
      low_severity_count: 0,
      info_severity_count: 0,
      confirmed_observation_count: 1,
      suspected_risk_count: 0,
      evidence_gap_count: 0,
      matched_rule_count: 1,
      not_matched_rule_count: 0,
      not_evaluated_rule_count: 1,
      error_rule_count: 0,
    },
    limitations: [DISCLAIMER],
    ...values,
  }
}

describe('PrivacyFindingsCard', () => {
  it('展示 evaluated 状态与统计口径', () => {
    renderWithProviders(<PrivacyFindingsCard findings={findings()} />)
    expect(screen.getByText('evaluated')).toBeInTheDocument()
    expect(screen.getByText('发现数量')).toBeInTheDocument()
    expect(screen.getAllByText('已观察事实').length).toBeGreaterThan(0)
    expect(screen.getAllByText('疑似风险提示').length).toBeGreaterThan(0)
    expect(screen.getAllByText('证据缺口').length).toBeGreaterThan(0)
    expect(screen.getByText('未评估规则')).toBeInTheDocument()
  })

  it('固定展示不构成法律合规结论的免责声明', () => {
    const { container } = renderWithProviders(
      <PrivacyFindingsCard findings={findings()} />,
    )
    const text = container.textContent ?? ''
    expect(text).toContain('不构成法律合规结论')
    expect(text).toContain('未观察到某项行为不代表该行为不会在其他设备')
  })

  it('展示标题、严重性、置信度与 Consent 阶段', () => {
    renderWithProviders(<PrivacyFindingsCard findings={findings()} />)
    expect(screen.getByText('Consent 前存在敏感 API 调用观察')).toBeInTheDocument()
    expect(screen.getByText('高关注')).toBeInTheDocument()
    expect(screen.getByText('高置信')).toBeInTheDocument()
    expect(screen.getByText(/Consent 前 · 证据 2 条/)).toBeInTheDocument()
  })

  it('区分已观察事实、疑似风险提示与证据缺口标签', () => {
    renderWithProviders(
      <PrivacyFindingsCard
        findings={findings({
          findings: [
            finding(),
            finding({
              finding_id: 'pf-2',
              rule_id: 'PF-PRECONSENT-CORRELATED-ACTIVITY',
              finding_type: 'suspected',
              severity: 'medium',
              confidence: 'medium',
            }),
            finding({
              finding_id: 'pf-3',
              rule_id: 'PF-DYNAMIC-EVIDENCE-GAP',
              finding_type: 'evidence_gap',
              severity: 'info',
              confidence: 'low',
            }),
          ],
        })}
      />,
    )
    expect(screen.getAllByText('已观察事实').length).toBeGreaterThan(0)
    expect(screen.getAllByText('疑似风险提示').length).toBeGreaterThan(0)
    expect(screen.getAllByText('证据缺口').length).toBeGreaterThan(0)
  })

  it('将 reason_codes 渲染为中文解释', () => {
    renderWithProviders(<PrivacyFindingsCard findings={findings()} />)
    expect(
      screen.getByText(/在 Consent 之前观察到敏感 API 调用记录/),
    ).toBeInTheDocument()
    expect(screen.getByText(/结论仅覆盖本次采集窗口/)).toBeInTheDocument()
  })

  it('未知 reason_code 原样展示且不报错', () => {
    renderWithProviders(
      <PrivacyFindingsCard
        findings={findings({ findings: [finding({ reason_codes: ['future_code'] })] })}
      />,
    )
    expect(screen.getByText(/future_code/)).toBeInTheDocument()
  })

  it('证据链默认折叠，展开后按环节展示且不伪造缺失环节', async () => {
    renderWithProviders(<PrivacyFindingsCard findings={findings()} />)
    const toggle = screen.getByRole('button', { name: /证据链/ })
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    expect(screen.queryByText('动态事件')).not.toBeInTheDocument()

    await userEvent.click(toggle)

    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    expect(screen.getByText('动态事件')).toBeInTheDocument()
    expect(screen.getByText('网络请求')).toBeInTheDocument()
    expect(screen.queryByText('Manifest')).not.toBeInTheDocument()
    expect(screen.queryByText('关联')).not.toBeInTheDocument()
  })

  it('展开后展示解释与单条发现的证据限制', async () => {
    renderWithProviders(<PrivacyFindingsCard findings={findings()} />)
    await userEvent.click(screen.getByRole('button', { name: /证据链/ }))
    expect(
      screen.getByText(/本次采集在可信 Consent 边界之前记录到敏感 API 调用/),
    ).toBeInTheDocument()
    expect(screen.getByText('调用发生不等同于数据外发')).toBeInTheDocument()
  })

  it('展示空态文案而非零风险结论', () => {
    renderWithProviders(
      <PrivacyFindingsCard
        findings={findings({
          findings: [],
          status: 'no_observations',
          summary: { ...findings().summary, finding_count: 0 },
        })}
      />,
    )
    expect(screen.getByText('本次观察中没有形成可展示的隐私发现。')).toBeInTheDocument()
    expect(screen.queryByText(/零风险/)).not.toBeInTheDocument()
    expect(screen.queryByText(/应用安全/)).not.toBeInTheDocument()
  })

  it('展示 partially_evaluated 时说明未评估不代表安全', () => {
    renderWithProviders(
      <PrivacyFindingsCard findings={findings({ status: 'partially_evaluated' })} />,
    )
    expect(screen.getByText(/未评估不代表安全或合规/)).toBeInTheDocument()
  })

  it('展示 error 状态时说明主报告仍可查看', () => {
    renderWithProviders(<PrivacyFindingsCard findings={findings({ status: 'error' })} />)
    expect(screen.getByText('error')).toBeInTheDocument()
    expect(screen.getByText(/主报告与原始证据仍可查看/)).toBeInTheDocument()
  })

  it('展示 not_evaluated 状态文案', () => {
    renderWithProviders(
      <PrivacyFindingsCard findings={findings({ status: 'not_evaluated' })} />,
    )
    expect(screen.getByText(/本次证据不足，未形成可判定的隐私发现结果/)).toBeInTheDocument()
  })

  it('展示规则评估明细含 not_evaluated 规则', () => {
    renderWithProviders(<PrivacyFindingsCard findings={findings()} />)
    expect(screen.getByText('PF-PRECONSENT-CORRELATED-ACTIVITY')).toBeInTheDocument()
    expect(screen.getByText('not_evaluated')).toBeInTheDocument()
  })

  it('兼容旧报告缺失 privacy_findings 字段', () => {
    renderWithProviders(<PrivacyFindingsCard />)
    expect(screen.getByText('旧版报告未生成可解释隐私发现结果。')).toBeInTheDocument()
    expect(screen.queryByText(/error/)).not.toBeInTheDocument()
  })

  it('窄屏不产生横向溢出：容器使用 min-w-0 与 break-words', () => {
    const { container } = renderWithProviders(
      <PrivacyFindingsCard findings={findings()} />,
    )
    expect(container.querySelector('.min-w-0')).toBeInTheDocument()
    expect(container.querySelector('.break-words')).toBeInTheDocument()
  })

  it('不展示 Cookie、Token 等敏感字段', () => {
    const { container } = renderWithProviders(
      <PrivacyFindingsCard findings={findings()} />,
    )
    const text = container.textContent ?? ''
    for (const forbidden of ['Cookie', 'Authorization', 'Bearer', 'set-cookie']) {
      expect(text).not.toContain(forbidden)
    }
  })
})
