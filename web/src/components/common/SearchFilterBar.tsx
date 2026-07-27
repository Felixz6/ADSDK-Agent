import { type ReactNode } from 'react'
import { cn } from '@/utils'

export interface SearchFilterBarProps {
  /** 搜索框值 */
  value: string
  onValueChange: (v: string) => void
  placeholder?: string
  /** 右侧附加控件(选择器、按钮等) */
  extra?: ReactNode
  className?: string
}

export function SearchFilterBar({
  value,
  onValueChange,
  placeholder = '搜索…',
  extra,
  className,
}: SearchFilterBarProps) {
  return (
    <div
      className={cn(
        'flex flex-col gap-2 sm:flex-row sm:items-center sm:justify-between',
        className,
      )}
    >
      <label className="flex items-center gap-2 glass rounded-[10px] px-3 py-1.5 w-full sm:w-72 focus-within:border-[var(--border-active)]">
        <span className="sr-only">搜索</span>
        <SearchIcon />
        <input
          type="text"
          value={value}
          onChange={(e) => onValueChange(e.target.value)}
          placeholder={placeholder}
          className="bg-transparent outline-none text-sm text-[var(--text-primary)] w-full placeholder:text-[var(--text-tertiary)]"
        />
      </label>
      {extra && <div className="flex items-center gap-2 flex-wrap">{extra}</div>}
    </div>
  )
}

function SearchIcon() {
  return (
    <svg
      width="16"
      height="16"
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2"
      className="text-[var(--text-tertiary)] shrink-0"
      aria-hidden
    >
      <circle cx="11" cy="11" r="8" />
      <path d="m21 21-4.3-4.3" strokeLinecap="round" />
    </svg>
  )
}

export default SearchFilterBar
