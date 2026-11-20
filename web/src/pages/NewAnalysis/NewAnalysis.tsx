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
  Check,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { PageHeader } from '@/components/common/PageHeader'
import { ApkPathInput } from '@/components/analysis/ApkPathInput'
import { AnalysisModeSelector, type AnalysisMode } from '@/components/analysis/AnalysisModeSelector'
import { DeviceSelector } from '@/components/analysis/DeviceSelector'
import { DynamicReliabilityCard } from '@/components/analysis/DynamicReliabilityCard'
import { useCreateTask, useAIStatus } from '@/hooks/useTasks'
import { useFridaDiagnostics } from '@/hooks/useApi'
import { useUIStore } from '@/stores/uiStore'
import { cn } from '@/utils'
import { MODE_COPY } from '@/utils/dynamicReliability'
import type { DynamicModePolicy } from '@/types/api'
import type { AnalysisScope } from '@/types/tasks'

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
  const [dynamicPolicy, setDynamicPolicy] = useState<DynamicModePolicy>('balanced')
  // AI 编排分析(M6A)
  const [objective, setObjective] = useState('')
  const [analysisScope, setAnalysisScope] = useState<AnalysisScope>('static_only')
  const [allowDynamic, setAllowDynamic] = useState(false)
  const [allowNetwork, setAllowNetwork] = useState(false)
  const [tokenBudget, setTokenBudget] = useState<number | null>(null)

  const createMut = useCreateTask()
  const diagnostics = useFridaDiagnostics()
  const aiStatus = useAIStatus()
  const submitting = createMut.isPending

  const stepIndex = STEPS.findIndex((s) => s.key === step)
  const isAI = mode === 'ai'
  const isDynamic = !isAI && (mode === 'dynamic' || mode === 'traffic')
  const canFromInput = apkPath.trim().toLowerCase().endsWith('.apk')
  // 默认预算来自后端配置,不允许无限值。
  const effectiveTokenBudget = tokenBudget ?? aiStatus.data?.default_token_budget ?? 6000
  const aiAvailable = Boolean(aiStatus.data?.enabled && aiStatus.data?.configured)

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
    const kind = isAI ? 'ai_orchestrated' : isDynamic ? 'dynamic' : 'static'
    if (kind === 'dynamic' && !deviceId.trim()) {
      pushToast({ kind: 'warning', message: '动态任务必须显式选择在线设备。', duration: 4000 })
      return
    }
    if (kind === 'dynamic' && diagnostics.data?.overall_status === 'blocked') {
      pushToast({
        kind: 'warning',
        message: 'Frida 预检存在阻塞项，请先进入环境检测查看修复建议。',
        duration: 5000,
      })
      return
    }
    if (kind === 'ai_orchestrated' && allowDynamic && !deviceId.trim()) {
      pushToast({ kind: 'warning', message: '允许动态分析时必须显式选择在线设备。', duration: 4000 })
      return
    }
    try {
      const task = await createMut.mutateAsync(
        kind === 'static'
          ? { task_type: 'static', apk_path: apkPath.trim() }
          : kind === 'ai_orchestrated'
            ? {
                task_type: 'ai_orchestrated',
                apk_path: apkPath.trim(),
                package_name: packageName.trim() || undefined,
                device_id: allowDynamic ? deviceId.trim() : undefined,
                objective: objective.trim() || undefined,
                analysis_scope: analysisScope,
                allow_dynamic: allowDynamic,
                allow_network: allowNetwork,
                token_budget: effectiveTokenBudget,
                // 允许动态时显式确认设备状态变更类工具,否则后端会阻塞该工具。
                confirmed_tools: allowDynamic ? ['dynamic_analysis'] : [],
              }
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
                dynamic_mode_policy: dynamicPolicy,
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
        description="四步引导式提交：选择模式 → 填写 APK 路径 → 配置参数 → 确认提交。"
        eyebrow="分析 · 向导"
      />

      <Stepper current={stepIndex} />

      <AnimatePresence mode="wait">
        <motion.div
          key={step}
          initial={{ opacity: 0, y: 6 }}
          animate={{ opacity: 1, y: 0 }}
          exit={{ opacity: 0, y: -6 }}
          transition={{ duration: 0.18 }}
        >
          {step === 'mode' && (
            <GlassCard padding="lg" highlight>
              <div className="flex items-center gap-2 mb-1 text-[var(--text-primary)]">
                <FileSearch size={17} />
                <h2 className="text-base font-semibold">选择分析模式</h2>
              </div>
              <p className="text-xs text-[var(--text-tertiary)] mb-4">
                静态分析仅解包识别；动态分析会在同意前后采集行为并可选记录流量。
              </p>
              <AnalysisModeSelector value={mode} onChange={setMode} disabled={submitting} />
            </GlassCard>
          )}

          {step === 'input' && (
            <GlassCard padding="lg" highlight className="flex flex-col gap-4">
              <div className="flex items-center gap-2 text-[var(--text-primary)]">
                <FileSearch size={17} />
                <h2 className="text-base font-semibold">提交输入</h2>
              </div>
              <ApkPathInput value={apkPath} onChange={setApkPath} disabled={submitting} required />
              {isDynamic && (
                <div className="flex flex-col gap-1.5">
                  <label htmlFor="pkg" className="text-sm font-medium text-[var(--text-secondary)]">
                    包名 <span className="text-[var(--text-tertiary)] font-normal">(可选 · 用于精确定位)</span>
                  </label>
                  <input
                    id="pkg"
                    value={packageName}
                    onChange={(e) => setPackageName(e.target.value)}
                    disabled={submitting}
                    placeholder="com.example.app"
                    spellCheck={false}
                    className="control-input font-mono"
                  />
                </div>
              )}
              {!canFromInput && apkPath.length > 0 && (
                <p className="text-xs text-[var(--warning)]">APK 路径应以 .apk 结尾。</p>
              )}
            </GlassCard>
          )}

          {step === 'options' && (
            <GlassCard padding="lg" highlight className="flex flex-col gap-5">
              <div className="flex items-center gap-2 text-[var(--text-primary)]">
                {isDynamic ? <Activity size={17} /> : <Network size={17} />}
                <h2 className="text-base font-semibold">配置参数</h2>
              </div>

              {!isDynamic && !isAI ? (
                <p className="text-sm text-[var(--text-tertiary)]">静态分析无需额外参数。</p>
              ) : isAI ? (
                <>
                  {!aiAvailable && (
                    <div
                      className="rounded-[10px] border border-[var(--hairline)] bg-[var(--bg-soft)] px-3.5 py-2.5 text-xs leading-relaxed text-[var(--text-secondary)]"
                      data-testid="ai-disabled-notice"
                    >
                      {aiStatus.data?.enabled === false
                        ? 'AI 功能当前未启用。仍可提交任务：系统会执行确定性默认计划并生成确定性报告，不会生成 AI 叙述。'
                        : 'AI Provider / Model 尚未配置完成。仍可提交任务：系统会执行确定性默认计划并生成确定性报告。'}
                    </div>
                  )}
                  <div className="flex flex-col gap-1.5">
                    <label htmlFor="objective" className="text-sm font-medium text-[var(--text-secondary)]">
                      分析目标 <span className="text-[var(--text-tertiary)] font-normal">(可选 · 用于编排工具顺序)</span>
                    </label>
                    <textarea
                      id="objective"
                      value={objective}
                      onChange={(e) => setObjective(e.target.value)}
                      disabled={submitting}
                      rows={2}
                      maxLength={2000}
                      placeholder="例如：只做静态隐私检查，重点关注广告 SDK 与敏感权限"
                      className="control-input min-h-[72px] resize-y"
                    />
                    <p className="text-xs text-[var(--text-tertiary)]">
                      分析目标仅作为调度输入；AI 不会据此改变系统策略或获得额外权限。
                    </p>
                  </div>

                  <div className="flex flex-col gap-2">
                    <span className="text-sm font-medium text-[var(--text-secondary)]">分析范围</span>
                    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-2">
                      {(
                        [
                          ['static_only', '仅静态', '只执行静态分析与隐私规则'],
                          ['dynamic_only', '仅动态', '需要设备与显式确认'],
                          ['full_analysis', '完整分析', '静态 + 动态 + 网络 + 关联'],
                          ['report_only', '仅出报告', '复用已有产物，不重新采集'],
                        ] as [AnalysisScope, string, string][]
                      ).map(([value, label, detail]) => (
                        <button
                          key={value}
                          type="button"
                          onClick={() => setAnalysisScope(value)}
                          aria-pressed={analysisScope === value}
                          className={cn(
                            'min-w-0 rounded-[12px] border p-3 text-left transition-colors',
                            analysisScope === value
                              ? 'border-[var(--border-active)] bg-[var(--accent-soft)]'
                              : 'border-[var(--hairline)] hover:bg-[var(--fill-hover)]',
                          )}
                        >
                          <span className="text-sm font-medium text-[var(--text-primary)]">{label}</span>
                          <span className="mt-1 block text-xs leading-relaxed text-[var(--text-tertiary)]">
                            {detail}
                          </span>
                        </button>
                      ))}
                    </div>
                  </div>

                  <div className="flex flex-col gap-2.5">
                    <ToggleField
                      id="allowDynamic"
                      label="允许动态分析(会改变设备状态，需确认)"
                      value={allowDynamic}
                      onChange={setAllowDynamic}
                      disabled={submitting}
                    />
                    <ToggleField
                      id="allowNetwork"
                      label="允许网络采集"
                      value={allowNetwork}
                      onChange={setAllowNetwork}
                      disabled={submitting}
                    />
                  </div>

                  {allowDynamic && (
                    <DeviceSelector value={deviceId} onChange={setDeviceId} disabled={submitting} />
                  )}
                  {allowDynamic && (
                    <div
                      data-testid="device-change-checklist"
                      className="rounded-[12px] border border-[var(--warning-line)] bg-[var(--warning-soft)] p-3.5 text-xs leading-relaxed"
                    >
                      <p className="font-semibold text-[var(--warning)]">
                        本次运行将改变设备状态，请确认以下范围
                      </p>
                      <ul className="mt-2 list-disc space-y-1 pl-4 text-[var(--text-secondary)]">
                        <li>安装/覆盖安装目标 APK（不会删除你原有的数据）</li>
                        <li>启动目标应用并附加 Frida 采集</li>
                        <li>按需设置设备 HTTP 代理，并在结束时恢复为初始值</li>
                        <li>启动本轮独占的抓包进程，结束时关闭</li>
                        <li>在 Consent 前后各采集一个观察窗口</li>
                      </ul>
                      <p className="mt-2.5 font-semibold text-[var(--text-primary)]">
                        平台不会执行的操作
                      </p>
                      <ul className="mt-1 list-disc space-y-1 pl-4 text-[var(--text-secondary)]">
                        <li>不清除应用数据、不卸载应用、不修改其他应用</li>
                        <li>不自动点击 UI、不自动确认 Consent、不重启设备</li>
                        <li>不停止非本轮启动的外部 frida-server</li>
                        <li>不绕过 SSL Pinning</li>
                      </ul>
                      <p className="mt-2 text-[var(--text-tertiary)]">
                        Consent 需要你在真机上人工完成，随后在任务详情页回报结论；
                        超时不会自动确认。
                      </p>
                    </div>
                  )}
                  <NumberField
                    id="tokenBudget"
                    label="Token 预算"
                    hint={`默认取后端配置(${aiStatus.data?.default_token_budget ?? 6000})；不允许无限值`}
                    value={effectiveTokenBudget}
                    min={256}
                    max={200000}
                    onChange={setTokenBudget}
                    disabled={submitting}
                  />
                </>
              ) : (
                <>
                  <DeviceSelector value={deviceId} onChange={setDeviceId} disabled={submitting} />

                  <div className="flex flex-col gap-2">
                    <span className="text-sm font-medium text-[var(--text-secondary)]">执行策略</span>
                    <div className="grid grid-cols-1 gap-2.5 sm:grid-cols-3">
                      {(Object.entries(MODE_COPY) as [DynamicModePolicy, { label: string; detail: string }][]).map(
                        ([value, copy]) => (
                          <button
                            key={value}
                            type="button"
                            onClick={() => setDynamicPolicy(value)}
                            aria-pressed={dynamicPolicy === value}
                            className={cn(
                              'min-w-0 rounded-[12px] border p-3 text-left transition-colors',
                              dynamicPolicy === value
                                ? 'border-[var(--border-active)] bg-[var(--accent-soft)]'
                                : 'border-[var(--hairline)] hover:bg-[var(--fill-hover)]',
                            )}
                          >
                            <span className="text-sm font-medium text-[var(--text-primary)]">{copy.label}</span>
                            <span className="mt-1 block text-xs leading-relaxed text-[var(--text-tertiary)]">
                              {copy.detail}
                            </span>
                          </button>
                        ),
                      )}
                    </div>
                  </div>

                  <div className="flex flex-wrap items-center gap-2.5">
                    <button
                      type="button"
                      disabled={!deviceId.trim() || diagnostics.isPending}
                      onClick={() =>
                        diagnostics.mutate({
                          deviceId: deviceId.trim(),
                          packageName: packageName.trim() || undefined,
                        })
                      }
                      className="control-button"
                    >
                      {diagnostics.isPending ? '正在预检…' : '运行 Frida 预检'}
                    </button>
                    <span className="text-xs text-[var(--text-tertiary)]">
                      预检按需执行；不会部署或启动服务。
                    </span>
                  </div>

                  <DynamicReliabilityCard
                    diagnostics={diagnostics.data}
                    loading={diagnostics.isPending}
                    onRefresh={
                      deviceId.trim()
                        ? () =>
                            diagnostics.mutate({
                              deviceId: deviceId.trim(),
                              packageName: packageName.trim() || undefined,
                            })
                        : undefined
                    }
                  />

                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3.5 pt-3 border-t border-[var(--hairline)]">
                    <NumberField
                      id="consentAfter"
                      label="同意发生时长(秒)"
                      hint="0-86400,用于划分同意前/后窗口"
                      value={consentAfter}
                      min={0}
                      max={86400}
                      onChange={setConsentAfter}
                      disabled={submitting}
                    />
                    <NumberField
                      id="timeout"
                      label="采集超时(秒)"
                      hint="1-86400"
                      value={timeoutSec}
                      min={1}
                      max={86400}
                      onChange={setTimeoutSec}
                      disabled={submitting}
                    />
                    <NumberField
                      id="pre"
                      label="同意前窗口(秒)"
                      hint="0-3600"
                      value={preSeconds}
                      min={0}
                      max={3600}
                      onChange={setPreSeconds}
                      disabled={submitting}
                    />
                    <NumberField
                      id="post"
                      label="同意后窗口(秒)"
                      hint="0-3600"
                      value={postSeconds}
                      min={0}
                      max={3600}
                      onChange={setPostSeconds}
                      disabled={submitting}
                    />
                  </div>

                  <div className="flex flex-col gap-2.5">
                    <ToggleField
                      id="traffic"
                      label="采集网络流量"
                      value={enableTraffic}
                      onChange={setEnableTraffic}
                      disabled={submitting}
                    />
                    <ToggleField
                      id="uistim"
                      label="启用 UI 刺激(模拟点击)"
                      value={enableUiStim}
                      onChange={setEnableUiStim}
                      disabled={submitting}
                    />
                  </div>
                </>
              )}
            </GlassCard>
          )}

          {step === 'submit' && (
            <GlassCard padding="lg" highlight className="flex flex-col gap-4">
              <div className="flex items-center gap-2 text-[var(--text-primary)]">
                <Play size={17} />
                <h2 className="text-base font-semibold">确认并提交</h2>
              </div>
              <SummaryTable
                rows={[
                  [
                    '分析模式',
                    mode === 'static'
                      ? '静态分析'
                      : mode === 'dynamic'
                        ? '动态分析'
                        : mode === 'ai'
                          ? 'AI 编排分析'
                          : '流量观测',
                  ],
                  ['APK 路径', apkPath || '—'],
                  ...(isAI
                    ? ([
                        ['分析目标', objective || '（未填写，使用默认目标）'],
                        ['分析范围', analysisScope],
                        ['允许动态分析', allowDynamic ? '是（已确认设备状态变更）' : '否'],
                        ['允许网络采集', allowNetwork ? '是' : '否'],
                        ['Token 预算', String(effectiveTokenBudget)],
                        [
                          'AI 可用性',
                          aiAvailable
                            ? '已启用并已配置'
                            : '未启用或未配置（将使用确定性默认计划）',
                        ],
                      ] as [string, string][])
                    : []),
                  ...(isDynamic
                    ? ([
                        ['目标设备', deviceId || '默认'],
                        ['包名', packageName || '—'],
                        ['执行策略', MODE_COPY[dynamicPolicy].label],
                        ['同意发生时长', `${consentAfter} 秒`],
                        ['同意前/后窗口', `${preSeconds} / ${postSeconds} 秒`],
                        ['采集流量', enableTraffic ? '是' : '否'],
                        ['UI 刺激', enableUiStim ? '是' : '否'],
                        ['采集超时', `${timeoutSec} 秒`],
                      ] as [string, string][])
                    : ([] as [string, string][])),
                ]}
              />
              <div className="rounded-[10px] border border-[var(--hairline)] bg-[var(--bg-soft)] px-3.5 py-2.5 text-xs text-[var(--text-secondary)] leading-relaxed">
                提交后将进入任务详情页；任务在后台运行，可实时查看真实步骤。
                动态任务会独占所选设备，离开页面不会中断分析。
              </div>
            </GlassCard>
          )}
        </motion.div>
      </AnimatePresence>

      {/* 吸顶底部操作条 */}
      <div className="sticky bottom-4 z-20 flex items-center justify-between gap-3 rounded-[var(--radius-glass)] border border-[var(--hairline)] bg-[var(--bg-panel)]/95 backdrop-blur-md px-4 py-3 shadow-sm">
        <button
          type="button"
          onClick={goPrev}
          disabled={stepIndex === 0 || submitting}
          className="control-button"
        >
          <ArrowLeft size={15} /> 上一步
        </button>

        <span className="hidden sm:inline text-xs text-[var(--text-tertiary)] tabular-nums">
          第 {stepIndex + 1} / {STEPS.length} 步 · {STEPS[stepIndex].title}
        </span>

        {stepIndex < STEPS.length - 1 ? (
          <button
            type="button"
            onClick={goNext}
            disabled={(step === 'input' && !canFromInput) || submitting}
            className="control-primary"
          >
            下一步 <ArrowRight size={15} />
          </button>
        ) : (
          <button
            type="button"
            onClick={handleSubmit}
            disabled={!canFromInput || submitting}
            className="control-primary"
          >
            {submitting ? <Loader2 size={15} className="animate-spin" /> : <Play size={15} />}
            {submitting ? '正在创建任务…' : '提交后台任务'}
          </button>
        )}
      </div>
    </div>
  )
}

function Stepper({ current }: { current: number }) {
  return (
    <ol className="grid grid-cols-2 sm:grid-cols-4 divide-y sm:divide-y-0 sm:divide-x divide-[var(--hairline)] rounded-[var(--radius-glass)] border border-[var(--hairline)] bg-[var(--bg-panel)] overflow-hidden">
      {STEPS.map((s, i) => {
        const done = i < current
        const active = i === current
        return (
          <li
            key={s.key}
            className={cn(
              'flex items-center gap-2.5 px-3.5 py-2.5 text-xs transition-colors',
              active && 'bg-[var(--bg-soft)] font-semibold text-[var(--text-primary)]',
              done && 'text-[var(--text-secondary)]',
              !active && !done && 'text-[var(--text-tertiary)]',
            )}
          >
            <span
              className={cn(
                'w-5 h-5 shrink-0 rounded-full flex items-center justify-center text-[11px] font-semibold tabular-nums',
                active
                  ? 'bg-[var(--accent-blue)] text-[var(--text-on-accent)]'
                  : done
                    ? 'bg-[var(--success-soft)] text-[var(--success)]'
                    : 'bg-[var(--fill-quiet)] text-[var(--text-tertiary)]',
              )}
            >
              {done ? <Check size={12} strokeWidth={2.5} /> : i + 1}
            </span>
            <span className="truncate">{s.title}</span>
          </li>
        )
      })}
    </ol>
  )
}

function NumberField({
  id,
  label,
  hint,
  value,
  min,
  max,
  onChange,
  disabled,
}: {
  id: string
  label: string
  hint?: string
  value: number
  min: number
  max: number
  onChange: (v: number) => void
  disabled?: boolean
}) {
  return (
    <div className="flex flex-col gap-1.5">
      <label htmlFor={id} className="text-sm font-medium text-[var(--text-secondary)]">
        {label}
      </label>
      <input
        id={id}
        type="number"
        value={value}
        min={min}
        max={max}
        disabled={disabled}
        onChange={(e) => onChange(Number(e.target.value))}
        className="control-input tabular-nums"
      />
      {hint && <p className="text-xs text-[var(--text-tertiary)]">{hint}</p>}
    </div>
  )
}

function ToggleField({
  id,
  label,
  value,
  onChange,
  disabled,
}: {
  id: string
  label: string
  value: boolean
  onChange: (v: boolean) => void
  disabled?: boolean
}) {
  return (
    <label
      htmlFor={id}
      className="flex items-center justify-between gap-3 rounded-[12px] border border-[var(--hairline)] bg-[var(--bg-soft)] px-3.5 py-2.5 cursor-pointer hover:border-[var(--border-active)]/40 transition-colors"
    >
      <span className="text-sm text-[var(--text-primary)]">{label}</span>
      <button
        type="button"
        id={id}
        role="switch"
        aria-checked={value}
        disabled={disabled}
        onClick={() => onChange(!value)}
        className={cn(
          'relative w-10 h-6 shrink-0 rounded-full transition-colors',
          value ? 'bg-[var(--accent-blue)]' : 'bg-[var(--hairline)]',
          disabled && 'opacity-50 cursor-not-allowed',
        )}
      >
        <span
          className={cn(
            'absolute top-0.5 left-0.5 w-5 h-5 rounded-full transition-transform shadow-sm',
            value
              ? 'translate-x-4 bg-[var(--text-on-accent)]'
              : 'translate-x-0 bg-[var(--bg-panel)]',
          )}
        />
      </button>
    </label>
  )
}

function SummaryTable({ rows }: { rows: [string, string][] }) {
  return (
    <dl className="divide-y divide-[var(--hairline)] border-t border-b border-[var(--hairline)]">
      {rows.map(([k, v]) => (
        <div key={k} className="flex items-start justify-between gap-4 py-2.5">
          <dt className="text-xs font-medium text-[var(--text-tertiary)] shrink-0 pt-0.5">{k}</dt>
          <dd className="text-sm text-[var(--text-primary)] text-right break-all tabular-nums">{v}</dd>
        </div>
      ))}
    </dl>
  )
}