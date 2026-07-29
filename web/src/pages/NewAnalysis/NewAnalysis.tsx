import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { motion, AnimatePresence } from 'framer-motion'
import {
  FileSearch,
  Activity,
  Network,
  ArrowRight,
  ArrowLeft,
  Loader2,
  Play,
  ChevronRight,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { ApkPathInput } from '@/components/analysis/ApkPathInput'
import { AnalysisModeSelector, type AnalysisMode } from '@/components/analysis/AnalysisModeSelector'
import { DeviceSelector } from '@/components/analysis/DeviceSelector'
import { useCreateTask } from '@/hooks/useTasks'
import { useUIStore } from '@/stores/uiStore'
import { cn } from '@/utils'

const RECENT_APK_KEY = 'adsdk-agent:recent-apk-path'

const STEPS = [
  { key: 'mode', title: '选择模式' },
  { key: 'input', title: '提交输入' },
  { key: 'options', title: '配置参数' },
  { key: 'submit', title: '确认提交' },
] as const

type StepKey = (typeof STEPS)[number]['key']

export default function NewAnalysis() {
  const navigate = useNavigate()
  const pushToast = useUIStore((s) => s.pushToast)

  const [step, setStep] = useState<StepKey>('mode')
  const [mode, setMode] = useState<AnalysisMode>('static')
  const [apkPath, setApkPath] = useState(() =>
    import.meta.env.DEV ? localStorage.getItem(RECENT_APK_KEY) ?? '' : '',
  )
  const [packageName, setPackageName] = useState('')
  const [deviceId, setDeviceId] = useState('')
  const [consentAfter, setConsentAfter] = useState<number>(20)
  const [preSeconds, setPreSeconds] = useState<number>(10)
  const [postSeconds, setPostSeconds] = useState<number>(10)
  const [enableTraffic, setEnableTraffic] = useState(true)
  const [enableUiStim, setEnableUiStim] = useState(false)
  const [timeoutSec, setTimeoutSec] = useState(300)

  const createMut = useCreateTask()
  const submitting = createMut.isPending

  const stepIndex = STEPS.findIndex((s) => s.key === step)
  const isDynamic = mode === 'dynamic' || mode === 'traffic'
  const canFromInput = apkPath.trim().toLowerCase().endsWith('.apk')

  function goNext() {
    const i = Math.min(stepIndex + 1, STEPS.length - 1)
    setStep(STEPS[i].key)
  }
  function goPrev() {
    const i = Math.max(stepIndex - 1, 0)
    setStep(STEPS[i].key)
  }

  async function handleSubmit() {
    if (!canFromInput) {
      pushToast({ kind: 'warning', message: '请填写有效的 APK 路径。', duration: 3500 })
      return
    }
    const kind = isDynamic ? 'dynamic' : 'static'
    if (kind === 'dynamic' && !deviceId.trim()) {
      pushToast({ kind: 'warning', message: '动态任务必须显式选择在线设备。', duration: 4000 })
      return
    }
    try {
      const task = await createMut.mutateAsync(
        kind === 'static'
          ? { task_type: 'static', apk_path: apkPath.trim() }
          : {
          task_type: 'dynamic',
          apk_path: apkPath.trim(),
          package_name: packageName.trim() || undefined,
          device_id: deviceId.trim(),
          consent_after_seconds: consentAfter,
          pre_consent_seconds: preSeconds,
          post_consent_seconds: postSeconds,
          enable_traffic: enableTraffic,
          enable_ui_stimulation: enableUiStim,
          collection_timeout_seconds: timeoutSec,
        },
      )
      if (import.meta.env.DEV) localStorage.setItem(RECENT_APK_KEY, apkPath.trim())
      pushToast({ kind: 'success', message: '任务已进入后台队列。', duration: 3500 })
      navigate(`/tasks/${task.id}`)
    } catch (err) {
      const e = err as { message?: string; code?: string | null; unreachable?: boolean }
      pushToast({
        kind: 'error',
        message: e.message ?? '提交失败',
        duration: 6000,
      })
    }
  }

  return (
    <div className="flex flex-col gap-5">
      <PageHeader
        title="新建分析"
        description="四步引导式提交:选择模式 → 填写 APK 路径 → 配置参数 → 确认提交。"
        eyebrow="分析 · 向导"
      />

      <Stepper current={stepIndex} />

      <AnimatePresence mode="wait">
        <motion.div
          key={step}
          initial={{ opacity: 0, x: 16 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -16 }}
          transition={{ duration: 0.2 }}
        >
          {step === 'mode' && (
            <GlassCard padding="lg" highlight>
              <div className="flex items-center gap-2 mb-1 text-[var(--accent-blue)]">
                <FileSearch size={18} />
                <h2 className="text-base font-semibold text-[var(--text-primary)]">选择分析模式</h2>
              </div>
              <p className="text-xs text-[var(--text-tertiary)] mb-4">
                静态分析仅解包识别;动态分析会在同意前后采集行为并可选记录流量。
              </p>
              <AnalysisModeSelector value={mode} onChange={setMode} disabled={submitting} />
            </GlassCard>
          )}

          {step === 'input' && (
            <GlassCard padding="lg" highlight className="flex flex-col gap-4">
              <div className="flex items-center gap-2 text-[var(--accent-blue)]">
                <FileSearch size={18} />
                <h2 className="text-base font-semibold text-[var(--text-primary)]">提交输入</h2>
              </div>
              <ApkPathInput value={apkPath} onChange={setApkPath} disabled={submitting} required />
              {isDynamic && (
                <div className="flex flex-col gap-1.5">
                  <label htmlFor="pkg" className="text-sm font-medium text-[var(--text-secondary)]">
                    包名 <span className="text-[var(--text-tertiary)]">(可选 · 用于精确定位)</span>
                  </label>
                  <input
                    id="pkg"
                    value={packageName}
                    onChange={(e) => setPackageName(e.target.value)}
                    disabled={submitting}
                    placeholder="com.example.app"
                    spellCheck={false}
                    className="glass rounded-[12px] px-3 py-2 text-sm text-[var(--text-primary)] outline-none focus:border-[var(--border-active)]"
                  />
                </div>
              )}
              {!canFromInput && apkPath.length > 0 && (
                <p className="text-xs text-[var(--warning)]">APK 路径应以 .apk 结尾。</p>
              )}
            </GlassCard>
          )}

          {step === 'options' && (
            <GlassCard padding="lg" highlight className="flex flex-col gap-4">
              <div className="flex items-center gap-2 text-[var(--accent-blue)]">
                {isDynamic ? <Activity size={18} /> : <Network size={18} />}
                <h2 className="text-base font-semibold text-[var(--text-primary)]">配置参数</h2>
              </div>

              {!isDynamic ? (
                <p className="text-sm text-[var(--text-tertiary)]">静态分析无需额外参数。</p>
              ) : (
                <>
                  <DeviceSelector value={deviceId} onChange={setDeviceId} disabled={submitting} />
                  <NumberField id="consentAfter" label="同意发生时长(秒)" hint="0-86400,用于划分同意前/后窗口" value={consentAfter} min={0} max={86400} onChange={setConsentAfter} disabled={submitting} />
                  <div className="grid grid-cols-2 gap-3">
                    <NumberField id="pre" label="同意前窗口(秒)" hint="0-3600" value={preSeconds} min={0} max={3600} onChange={setPreSeconds} disabled={submitting} />
                    <NumberField id="post" label="同意后窗口(秒)" hint="0-3600" value={postSeconds} min={0} max={3600} onChange={setPostSeconds} disabled={submitting} />
                  </div>
                  <ToggleField id="traffic" label="采集网络流量" value={enableTraffic} onChange={setEnableTraffic} disabled={submitting} />
                  <ToggleField id="uistim" label="启用 UI 刺激(模拟点击)" value={enableUiStim} onChange={setEnableUiStim} disabled={submitting} />
                  <NumberField id="timeout" label="采集超时(秒)" hint="1-86400" value={timeoutSec} min={1} max={86400} onChange={setTimeoutSec} disabled={submitting} />
                </>
              )}
            </GlassCard>
          )}

          {step === 'submit' && (
            <GlassCard padding="lg" highlight className="flex flex-col gap-3">
              <div className="flex items-center gap-2 text-[var(--accent-blue)]">
                <Play size={18} />
                <h2 className="text-base font-semibold text-[var(--text-primary)]">确认并提交</h2>
              </div>
              <SummaryTable
                rows={[
                  ['分析模式', mode === 'static' ? '静态分析' : mode === 'dynamic' ? '动态分析' : '流量观测'],
                  ['APK 路径', apkPath || '—'],
                  ...(isDynamic
                    ? ([
                        ['目标设备', deviceId || '默认'],
                        ['包名', packageName || '—'],
                        ['同意发生时长', `${consentAfter} 秒`],
                        ['同意前/后窗口', `${preSeconds} / ${postSeconds} 秒`],
                        ['采集流量', enableTraffic ? '是' : '否'],
                        ['UI 刺激', enableUiStim ? '是' : '否'],
                        ['采集超时', `${timeoutSec} 秒`],
                      ] as [string, string][])
                    : ([] as [string, string][])),
                ]}
              />
              <div className="rounded-[10px] border border-[var(--border-soft)] bg-[rgba(120,216,255,0.06)] px-3 py-2 text-xs text-[var(--text-secondary)] leading-relaxed">
                提交后将进入任务详情页；任务在后台运行，可实时查看真实步骤。
                动态任务会独占所选设备，离开页面不会中断分析。
              </div>
            </GlassCard>
          )}
        </motion.div>
      </AnimatePresence>

      <div className="flex items-center justify-between sticky bottom-4">
        <button
          type="button"
          onClick={goPrev}
          disabled={stepIndex === 0 || submitting}
          className={cn(
            'inline-flex items-center gap-1.5 px-4 py-2 rounded-[12px] text-sm font-medium transition-colors',
            'glass border-[var(--border-soft)] text-[var(--text-secondary)] hover:text-[var(--text-primary)]',
            (stepIndex === 0 || submitting) && 'opacity-50 cursor-not-allowed',
          )}
        >
          <ArrowLeft size={16} /> 上一步
        </button>

        {stepIndex < STEPS.length - 1 ? (
          <button
            type="button"
            onClick={goNext}
            disabled={(step === 'input' && !canFromInput) || submitting}
            className={cn(
              'inline-flex items-center gap-1.5 px-4 py-2 rounded-[12px] text-sm font-medium transition-all',
              'bg-[var(--accent-blue)] text-[var(--text-on-accent)] hover:brightness-110 shadow-[var(--shadow-glow)]',
              ((step === 'input' && !canFromInput) || submitting) && 'opacity-60 cursor-not-allowed',
            )}
          >
            下一步 <ArrowRight size={16} />
          </button>
        ) : (
          <button
            type="button"
            onClick={handleSubmit}
            disabled={!canFromInput || submitting}
            className={cn(
              'inline-flex items-center gap-1.5 px-5 py-2 rounded-[12px] text-sm font-semibold transition-all',
              'bg-[var(--accent-blue)] text-[var(--text-on-accent)] hover:brightness-110 shadow-[var(--shadow-glow)]',
              (!canFromInput || submitting) && 'opacity-70 cursor-progress',
            )}
          >
            {submitting ? <Loader2 size={16} className="animate-spin" /> : <Play size={16} />}
            {submitting ? '正在创建任务…' : '提交后台任务'}
          </button>
        )}
      </div>
    </div>
  )
}

function Stepper({ current }: { current: number }) {
  return (
    <ol className="flex items-center gap-1 sm:gap-2">
      {STEPS.map((s, i) => (
        <li key={s.key} className="flex items-center gap-1 sm:gap-2 flex-1">
          <div
            className={cn(
              'flex items-center gap-2 px-3 py-1.5 rounded-[10px] text-xs flex-1',
              i === current ? 'glass-strong border-[var(--border-active)] text-[var(--text-primary)]' : i < current ? 'text-[var(--success)]' : 'text-[var(--text-tertiary)]',
            )}
          >
            <span className={cn('w-5 h-5 rounded-full flex items-center justify-center text-[11px] font-semibold', i === current ? 'bg-[var(--accent-blue)] text-[var(--text-on-accent)]' : i < current ? 'bg-[rgba(121,224,195,0.18)] text-[var(--success)]' : 'bg-[rgba(127,147,186,0.16)] text-[var(--text-tertiary)]')}>
              {i + 1}
            </span>
            <span className="truncate">{s.title}</span>
          </div>
          {i < STEPS.length - 1 && <ChevronRight size={14} className="text-[var(--text-tertiary)] shrink-0" />}
        </li>
      ))}
    </ol>
  )
}

function NumberField({
  id, label, hint, value, min, max, onChange, disabled,
}: { id: string; label: string; hint?: string; value: number; min: number; max: number; onChange: (v: number) => void; disabled?: boolean }) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-[var(--text-secondary)]">{label}</label>
      <input
        id={id}
        type="number"
        value={value}
        min={min}
        max={max}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
        className="glass rounded-[12px] px-3 py-2 text-sm text-[var(--text-primary)] outline-none focus:border-[var(--border-active)] w-full disabled:opacity-60"
      />
      {hint && <p className="text-[11px] text-[var(--text-tertiary)]">{hint}</p>}
    </div>
  )
}

function ToggleField({ id, label, value, onChange, disabled }: { id: string; label: string; value: boolean; onChange: (v: boolean) => void; disabled?: boolean }) {
  return (
    <label htmlFor={id} className="flex items-center justify-between gap-3 glass rounded-[12px] px-3 py-2.5 cursor-pointer">
      <span className="text-sm text-[var(--text-secondary)]">{label}</span>
      <button
        type="button"
        id={id}
        role="switch"
        aria-checked={value}
        disabled={disabled}
        onClick={() => onChange(!value)}
        className={cn(
          'relative w-10 h-6 rounded-full transition-colors',
          value ? 'bg-[var(--accent-blue)]' : 'bg-[rgba(127,147,186,0.3)]',
        )}
      >
        <span className={cn('absolute top-0.5 left-0.5 w-5 h-5 rounded-full bg-white transition-transform', value && 'translate-x-4')} />
      </button>
    </label>
  )
}

function SummaryTable({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="grid grid-cols-1 gap-1">
      {rows.map(([k, v]) => (
        <div key={k} className="flex items-start justify-between gap-3 py-1.5 border-b border-[var(--border-soft)]/40">
          <dt className="text-xs text-[var(--text-tertiary)] uppercase tracking-wide">{k}</dt>
          <dd className="text-sm text-[var(--text-primary)] text-right break-all">{v}</dd>
        </div>
      ))}
    </dl>
  )
}
