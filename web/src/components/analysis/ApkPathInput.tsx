import { useId, useState } from 'react'
import { FolderOpen, Check, AlertCircle } from 'lucide-react'
import { cn } from '@/utils'

export interface ApkPathInputProps {
  id?: string
  value: string
  onChange: (v: string) => void
  disabled?: boolean
  /** 是否在失焦时做基本格式校验 */
  required?: boolean
}

/** APK 本地路径输入(只接受路径字符串,不做文件上传) */
export function ApkPathInput({ id, value, onChange, disabled, required }: ApkPathInputProps) {
  const generated = useId()
  const inputId = id ?? generated
  const [touched, setTouched] = useState(false)

  const trimmed = value.trim()
  const looksValid = trimmed.toLowerCase().endsWith('.apk')
  const showError = touched && required && trimmed.length > 0 && !looksValid

  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={inputId} className="text-sm font-medium text-[var(--text-secondary)]">
        APK 路径<span className="text-[var(--accent-pink)]"> *</span>
      </label>
      <div
        className={cn(
          'flex items-center gap-2 glass rounded-[12px] px-3 py-2 transition-colors',
          'focus-within:border-[var(--border-active)]',
          showError && 'border-[rgba(242,139,155,0.5)]',
        )}
      >
        <FolderOpen size={18} className={cn('shrink-0', showError ? 'text-[var(--danger)]' : 'text-[var(--accent-blue)]')} />
        <input
          id={inputId}
          type="text"
          value={value}
          disabled={disabled}
          required={required}
          spellCheck={false}
          placeholder="例如 D:\\downloads\\sample.apk 或 /data/app/sample.apk"
          onBlur={() => setTouched(true)}
          onChange={(e) => onChange(e.target.value)}
          className="bg-transparent outline-none text-sm text-[var(--text-primary)] w-full placeholder:text-[var(--text-tertiary)] disabled:opacity-60"
        />
        {!showError && trimmed.length > 0 && looksValid && (
          <Check size={16} className="shrink-0 text-[var(--success)]" aria-label="格式正确" />
        )}
        {showError && <AlertCircle size={16} className="shrink-0 text-[var(--danger)]" />}
      </div>
      {showError && (
        <p className="text-xs text-[var(--danger)]">路径应以 <code>.apk</code> 结尾。</p>
      )}
      <p className="text-xs text-[var(--text-tertiary)]">仅接受设备/主机上 APK 文件的绝对路径;不会上传文件到浏览器。</p>
    </div>
  )
}

export default ApkPathInput
