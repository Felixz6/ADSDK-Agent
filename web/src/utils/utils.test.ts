import { describe, it, expect } from 'vitest'
import { cn, formatBytes, formatDuration, makeLocalRunId, safePick } from '@/utils'

describe('cn', () => {
  it('合并多个类名', () => {
    expect(cn('a', 'b')).toBe('a b')
  })
  it('过滤假值', () => {
    expect(cn('a', false, null, undefined, 'b')).toBe('a b')
  })
  it('支持对象条件', () => {
    expect(cn('a', { 'b': true, 'c': false })).toBe('a b')
  })
  it('支持数组', () => {
    expect(cn('a', ['b', { 'c': true }])).toBe('a b c')
  })
  it('后值覆盖前值(clsx 行为)', () => {
    expect(cn('px-2', 'px-4')).toBe('px-2 px-4')
  })
})

describe('formatDuration', () => {
  it('null/NaN 返回占位', () => {
    expect(formatDuration(null)).toBe('—')
    expect(formatDuration(Number.NaN)).toBe('—')
  })
  it('小于 1 秒按毫秒', () => {
    expect(formatDuration(500)).toBe('500ms')
    expect(formatDuration(999)).toBe('999ms')
  })
  it('秒级保留一位小数(<10s)', () => {
    expect(formatDuration(1500)).toBe('1.5s')
  })
  it('秒级 >=10s 取整', () => {
    expect(formatDuration(12000)).toBe('12s')
  })
  it('分钟级', () => {
    expect(formatDuration(75400)).toBe('1分15秒')
  })
  it('小时级', () => {
    expect(formatDuration(3 * 60 * 60 * 1000 + 30 * 60 * 1000)).toBe('3时30分')
  })
})

describe('formatBytes', () => {
  it('null/NaN 返回占位', () => {
    expect(formatBytes(null)).toBe('—')
    expect(formatBytes(Number.NaN)).toBe('—')
  })
  it('字节级原样', () => {
    expect(formatBytes(512)).toBe('512 B')
  })
  it('KB 两位小数(<10MB)', () => {
    expect(formatBytes(2048)).toBe('2.00 KB')
  })
  it('MB 一位小数', () => {
    expect(formatBytes(10 * 1024 * 1024)).toBe('10.0 MB')
  })
  it('GB 级(<10GB 保留两位小数)', () => {
    expect(formatBytes(2 * 1024 * 1024 * 1024)).toBe('2.00 GB')
  })
})

describe('makeLocalRunId', () => {
  it('以 local- 前缀开头', () => {
    expect(makeLocalRunId().startsWith('local-')).toBe(true)
  })

  it('同毫秒内连续生成多个 ID 不重复(随机/单调保证唯一)', () => {
    // 同步循环:尽可能落在同一毫秒内执行
    const ids = new Set<string>()
    const N = 2000
    for (let i = 0; i < N; i++) {
      ids.add(makeLocalRunId())
    }
    // 2 个/毫秒计 2000 个,若唯一性失效会出现重复
    expect(ids.size).toBe(N)
  })

  it('分布式跨请求生成 10000 个仍全部唯一', () => {
    const ids = new Set<string>()
    for (let i = 0; i < 10000; i++) ids.add(makeLocalRunId())
    expect(ids.size).toBe(10000)
  })
})

describe('safePick', () => {
  it('键存在返回值', () => {
    expect(safePick({ a: 1 }, 'a', 0)).toBe(1)
  })
  it('对象为空返回回退值', () => {
    expect(safePick<Record<string, number>, 'a'>(null, 'a', 9)).toBe(9)
    expect(safePick<Record<string, number>, 'a'>(undefined, 'a', 9)).toBe(9)
  })
  it('键缺失返回回退值', () => {
    expect(safePick<Record<string, number>, 'a'>({}, 'a', 7)).toBe(7)
  })
  it('值为 null 时回退', () => {
    expect(safePick<Record<string, string | null>, 'a'>({ a: null }, 'a', 'x')).toBe('x')
  })
})
