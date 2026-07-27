import { describe, it, expect } from 'vitest'
import { deriveRiskLevel, type RiskLevel } from './RiskBadge'

/**
 * 隐私合规关键不变量:**未评估(not_evaluated) 绝不应被展示为「安全/低风险」**。
 * deriveRiskLevel 必须将 not_evaluated>0 归类为 unknown,而非 low。
 * 不匹配 0 + 未评估 0 + 错误 0 才可判为 low。
 */
describe('deriveRiskLevel — 隐私不变量', () => {
  it('命中(matched>0)一律为高风险', () => {
    expect(deriveRiskLevel({ matched: 1, not_evaluated: 0, errored: 0 })).toBe<RiskLevel>('high')
    expect(deriveRiskLevel({ matched: 5, not_evaluated: 3, errored: 2 })).toBe<RiskLevel>('high')
    expect(deriveRiskLevel({ matched: 1, not_evaluated: 0, errored: 0 })).not.toBe('low')
  })

  it('错误(errored>0)归为未知,而非低风险', () => {
    expect(deriveRiskLevel({ matched: 0, not_evaluated: 0, errored: 1 })).toBe<RiskLevel>('unknown')
    expect(deriveRiskLevel({ matched: 0, not_evaluated: 0, errored: 1 })).not.toBe('low')
  })

  it('未评估(not_evaluated>0)归为未知,【绝不】展示为低风险/安全', () => {
    // 这是核心安全断言:未能评估的项目不可声称「安全」。
    expect(deriveRiskLevel({ matched: 0, not_evaluated: 1, errored: 0 })).toBe<RiskLevel>('unknown')
    expect(deriveRiskLevel({ matched: 0, not_evaluated: 10, errored: 0 })).not.toBe('low')
    expect(deriveRiskLevel({ matched: 0, not_evaluated: 10, errored: 0 })).not.toBe('high')
  })

  it('全为零时方为低风险', () => {
    expect(deriveRiskLevel({ matched: 0, not_evaluated: 0, errored: 0 })).toBe<RiskLevel>('low')
  })

  it('优先级:matched > errored > not_evaluated > low', () => {
    // matched 命中优先级最高,即便有 errored 与 not_evaluated 也判 high
    expect(deriveRiskLevel({ matched: 1, not_evaluated: 1, errored: 1 })).toBe<RiskLevel>('high')
    // 无 matched 时,errored 优先于 not_evaluated
    expect(deriveRiskLevel({ matched: 0, not_evaluated: 1, errored: 1 })).toBe<RiskLevel>('unknown')
  })

  it('不产生 medium(本推导函数只产出 high/unknown/low)', () => {
    const outcomes: RiskLevel[] = [
      deriveRiskLevel({ matched: 2, not_evaluated: 0, errored: 0 }),
      deriveRiskLevel({ matched: 0, not_evaluated: 0, errored: 1 }),
      deriveRiskLevel({ matched: 0, not_evaluated: 1, errored: 0 }),
      deriveRiskLevel({ matched: 0, not_evaluated: 0, errored: 0 }),
    ]
    for (const o of outcomes) expect(o).not.toBe('medium')
  })
})
