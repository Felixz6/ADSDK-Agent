import { describe, expect, it } from 'vitest'
import { normalizeAnalyzeResponse } from './analysis'
import type { AnalyzeResponse } from '@/types/api'

describe('normalizeAnalyzeResponse', () => {
  it('adds compatible defaults for old reports', () => {
    const old = {
      ok: true,
      apk_path: 'sample.apk',
      sdks: undefined,
      dynamic_events: undefined,
      warnings: undefined,
      limitations: undefined,
    } as unknown as AnalyzeResponse
    const normalized = normalizeAnalyzeResponse(old)
    expect(normalized.sdks).toEqual([])
    expect(normalized.dynamic_events).toEqual([])
    expect(normalized.risk_summary).toBeNull()
    expect(normalized.timeline).toBeNull()
    expect(normalized.compliance_insight).toBeNull()
  })
})
