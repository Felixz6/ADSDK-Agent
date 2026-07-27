import { useEnvCheck } from '@/hooks/useApi'
import { Smartphone, CheckCircle2, AlertTriangle, Loader2 } from 'lucide-react'
import { cn } from '@/utils'

export interface DeviceSelectorProps {
  value: string
  onChange: (v: string) => void
  disabled?: boolean
  /** 允许手动输入任意串(后端会脱敏回显) */
  allowManual?: boolean
}

/**
 * 设备选择器:基于 /env/check 返回的已识别设备列表。
 * 注意:列表中所有 device_id 已脱敏,前端始终原样回显,不做反向推断。
 */
export function DeviceSelector({ value, onChange, disabled, allowManual = true }: DeviceSelectorProps) {
  const env = useEnvCheck()
  const loading = env.isLoading
  const devices = env.data?.details?.device?.devices ?? []
  const onlineCount = env.data?.details?.device?.online_count ?? 0

  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor="device-select" className="text-sm font-medium text-[var(--text-secondary)]">
        目标设备 <span className="text-[var(--text-tertiary)]">(可选 · 已脱敏)</span>
      </label>

      <div className="flex items-center gap-2">
        <div className={cn('flex items-center gap-2 glass rounded-[12px] px-3 py-2 flex-1', 'focus-within:border-[var(--border-active)]')}>
          <Smartphone size={18} className="shrink-0 text-[var(--accent-blue)]" />
          {devices.length > 0 ? (
            <select
              id="device-select"
              value={value}
              disabled={disabled}
              onChange={(e) => onChange(e.target.value)}
              className="bg-transparent outline-none text-sm text-[var(--text-primary)] w-full disabled:opacity-60"
            >
              <option value="">使用默认设备</option>
              {devices.map((d) => (
                <option key={d.device_id} value={d.device_id} className="bg-[#0a1630]">
                  {d.device_id}（{d.status}）
                </option>
              ))}
            </select>
          ) : (
            <input
              id="device-select"
              type="text"
              value={value}
              disabled={disabled}
              spellCheck={false}
              placeholder={loading ? '正在检测设备…' : '手动输入设备序列号(已脱敏回显)'}
              onChange={(e) => onChange(e.target.value)}
              className="bg-transparent outline-none text-sm text-[var(--text-primary)] w-full placeholder:text-[var(--text-tertiary)] disabled:opacity-60"
            />
          )}
        </div>
      </div>

      {loading && (
        <p className="text-xs text-[var(--text-tertiary)] flex items-center gap-1.5">
          <Loader2 size={13} className="animate-spin" /> 环境检测中…
        </p>
      )}
      {!loading && env.isError && (
        <p className="text-xs text-[var(--warning)] flex items-center gap-1.5">
          <AlertTriangle size={13} /> 无法获取设备列表,可手动输入。
        </p>
      )}
      {!loading && !env.isError && onlineCount > 0 && (
        <p className="text-xs text-[var(--success)] flex items-center gap-1.5">
          <CheckCircle2 size={13} /> 在线设备 {onlineCount} 台。
        </p>
      )}
      {!loading && !env.isError && onlineCount === 0 && allowManual && (
        <p className="text-xs text-[var(--text-tertiary)]">当前未检测到在线设备,可手动输入序列号。</p>
      )}
    </div>
  )
}

export default DeviceSelector
