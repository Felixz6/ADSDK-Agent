import { render, screen } from '@testing-library/react'
import { describe, expect, it } from 'vitest'

import { ReportRuleCard } from './ReportRuleCard'

describe('ReportRuleCard', () => {
  it('安全展示后端对象摘要而不把对象直接作为 React 子节点', () => {
    render(
      <ReportRuleCard
        findings={{
          rules: [
            {
              rule_id: 'pre_consent_sensitive_access',
              status: 'not_evaluated',
              legacy_status: null,
              secure_getstring_count: 0,
              android_id_count: 0,
            },
          ],
          summary: {
            pre_consent_sensitive_access: 0,
            high_frequency_sensitive_access: 0,
          } as unknown as string,
          evaluation_summary: null,
        }}
      />,
    )

    expect(
      screen.getByText(
        '{"pre_consent_sensitive_access":0,"high_frequency_sensitive_access":0}',
      ),
    ).toBeInTheDocument()
    expect(screen.getByText('未评估')).toBeInTheDocument()
  })
})
