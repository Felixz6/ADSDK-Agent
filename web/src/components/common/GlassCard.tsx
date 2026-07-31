import { type ReactNode } from 'react'
import { cn } from '@/utils'

/**
 * GlassCard — 玻璃拟态卡片容器。
 * 通过 CSS 变量取色,绝不在组件里硬编码十六进制值。
 */
export interface GlassCardProps {
  className?: string
  /** 加强背景(用于关键面板) */
  strong?: boolean
  /** 顶部高光线 */
  highlight?: boolean
  /** 内边距 */
  padding?: 'none' | 'sm' | 'md' | 'lg'
  children: ReactNode
  /** 语义化交互用法时允许点击穿透关闭外的默认背景指针事件 */
  as?: 'div' | 'section' | 'aside' | 'article'
  /** 测试选择器透传(仅用于稳定定位,不影响样式) */
  'data-testid'?: string
}

const paddingMap: Record<NonNullable<GlassCardProps['padding']>, string> = {
  none: '',
  sm: 'p-3',
  md: 'p-5',
  lg: 'p-6 sm:p-8',
}

export function GlassCard({
  className,
  strong = false,
  highlight = false,
  padding = 'md',
  as: Tag = 'div',
  children,
  'data-testid': testId,
}: GlassCardProps) {
  const base = strong ? 'glass-strong' : 'glass'
  return (
    <Tag
      data-testid={testId}
      className={cn(
        base,
        highlight && 'glass-highlight',
        'relative overflow-hidden',
        paddingMap[padding],
        className,
      )}
    >
      {children}
    </Tag>
  )
}

export default GlassCard
