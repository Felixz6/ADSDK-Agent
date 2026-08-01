/**
 * M6B —— AI 配置表单(Settings 页面内的可编辑卡片)。
 *
 * 安全设计(与后端契约一致):
 * - API Key **只提交、不回读**。输入框初始为空,永不回填已保存的 Key;
 *   保存成功后立即清空本地输入态;组件卸载时也清空。
 * - Key 不写入 localStorage / sessionStorage / IndexedDB / URL / 全局 Store。
 *   它只存在于本组件的 `useState` 中,随组件生命周期结束而消失。
 * - 环境变量管理的字段由后端 `locked_fields` 标记,前端一律禁用并提示,
 *   不允许本地保存覆盖环境变量。
 * - 删除已保存 Key 是独立操作(带二次确认),普通保存的空 Key 不会误删。
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Bot, Eye, EyeOff, Loader2, Lock, Plug, Save, RotateCcw, Trash2 } from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { ConfirmDialog } from '@/components/common/ConfirmDialog'
import { useUIStore } from '@/stores/uiStore'
import {
  deleteLocalAIKey,
  getAISettings,
  testAISettings,
  updateAISettings,
} from '@/api/aiSettings'
import type {
  AISettingsResponse,
  AISettingsSaveRequest,
  AISettingsTestResponse,
} from '@/types/aiSettings'
import type { ApiError } from '@/api/client'
import { cn } from '@/utils'

/** 表单本地可编辑态(不含 API Key —— Key 单独管理,绝不与配置同存)。 */
interface FormState {
  enabled: boolean
  provider: string
  base_url: string
  model: string
  default_token_budget: number
  max_rounds: number
  max_tool_calls: number
  timeout_seconds: number
  max_input_tokens: number
  max_output_tokens: number
  cache_enabled: boolean
  cache_ttl_seconds: number
  allow_dynamic_tools: boolean
  report_language: 'zh-CN' | 'en-US'
}

type Phase =
  | 'loading'
  | 'idle'
  | 'saving'
  | 'saved'
  | 'testing'
  | 'deleting_key'
  | 'error'

function toFormState(s: AISettingsResponse): FormState {
  return {
    enabled: s.enabled,
    provider: s.provider,
    base_url: s.base_url,
    model: s.model,
    default_token_budget: s.default_token_budget,
    max_rounds: s.max_rounds,
    max_tool_calls: s.max_tool_calls,
    timeout_seconds: s.timeout_seconds,
    max_input_tokens: s.max_input_tokens,
    max_output_tokens: s.max_output_tokens,
    cache_enabled: s.cache_enabled,
    cache_ttl_seconds: s.cache_ttl_seconds,
    allow_dynamic_tools: s.allow_dynamic_tools,
    report_language: s.report_language,
  }
}

/** 数值字段的合法区间,与后端 `_RANGES` 完全一致(前端先行校验,后端仍是权威)。 */
const RANGES: Record<string, [number, number]> = {
  default_token_budget: [100, 100000],
  max_rounds: [1, 3],
  max_tool_calls: [1, 10],
  timeout_seconds: [5, 300],
  max_input_tokens: [500, 100000],
  max_output_tokens: [100, 10000],
  cache_ttl_seconds: [60, 604800],
}

function validate(form: FormState): Record<string, string> {
  const errors: Record<string, string> = {}
  for (const [key, [low, high]] of Object.entries(RANGES)) {
    const value = form[key as keyof FormState] as number
    if (!Number.isFinite(value) || value < low || value > high) {
      errors[key] = `应在 ${low}–${high} 之间`
    }
  }
  if (form.base_url) {
    const lowered = form.base_url.toLowerCase()
    if (!lowered.startsWith('http://') && !lowered.startsWith('https://')) {
      errors.base_url = '必须为 http 或 https'
    }
  }
  if (form.model && (form.model.length > 200 || /[\n\r]/.test(form.model))) {
    errors.model = '长度 1–200 且不得换行'
  }
  return errors
}

/** 测试结果的中文友好文案(技术错误码单独折叠展示)。 */
const TEST_MESSAGES: Record<AISettingsTestResponse['status'], string> = {
  reachable: '连接正常',
  unreachable: '无法连接到该服务地址',
  invalid_configuration: '配置不完整或被网关拒绝',
  authentication_failed: 'API Key 鉴权失败',
  timeout: '连接超时',
}

const TEST_TONES: Record<AISettingsTestResponse['status'], 'success' | 'danger' | 'warning'> = {
  reachable: 'success',
  unreachable: 'danger',
  invalid_configuration: 'warning',
  authentication_failed: 'danger',
  timeout: 'warning',
}

export function AISettingsCard() {
  const pushToast = useUIStore((s) => s.pushToast)
  const [server, setServer] = useState<AISettingsResponse | null>(null)
  const [form, setForm] = useState<FormState | null>(null)
  const [phase, setPhase] = useState<Phase>('loading')
  const [loadError, setLoadError] = useState<string | null>(null)
  const [errorCode, setErrorCode] = useState<string | null>(null)
  const [testResult, setTestResult] = useState<AISettingsTestResponse | null>(null)
  const [confirmDelete, setConfirmDelete] = useState(false)

  // API Key 只存在于本地 state —— 不进任何持久化,不回填,卸载即清除。
  const [apiKeyInput, setApiKeyInput] = useState('')
  const [showKey, setShowKey] = useState(false)

  const mounted = useRef(true)

  const load = useCallback(async (signal?: AbortSignal) => {
    try {
      const data = await getAISettings(signal)
      if (!mounted.current) return
      setServer(data)
      setForm(toFormState(data))
      setPhase('idle')
      setLoadError(null)
    } catch (err) {
      if (!mounted.current) return
      const apiErr = err as ApiError
      setPhase('error')
      setLoadError(apiErr.message ?? '读取 AI 配置失败。')
      setErrorCode(apiErr.code ?? null)
    }
  }, [])

  useEffect(() => {
    mounted.current = true
    const controller = new AbortController()
    void load(controller.signal)
    return () => {
      mounted.current = false
      controller.abort()
      // 卸载时清除 Key 输入态,确保密钥不会在内存中残留于任何全局位置。
      setApiKeyInput('')
      setShowKey(false)
    }
  }, [load])

  const locked = useMemo(
    () => new Set(server?.locked_fields ?? []),
    [server],
  )
  const envKeyManaged = server?.api_key_source === 'environment'

  const errors = useMemo(() => (form ? validate(form) : {}), [form])
  const hasErrors = Object.keys(errors).length > 0

  const dirty = useMemo(() => {
    if (!server || !form) return false
    const base = toFormState(server)
    const changedFields = (Object.keys(base) as (keyof FormState)[]).some(
      (k) => base[k] !== form[k],
    )
    return changedFields || apiKeyInput.length > 0
  }, [server, form, apiKeyInput])

  const busy = phase === 'saving' || phase === 'testing' || phase === 'deleting_key'

  function update<K extends keyof FormState>(key: K, value: FormState[K]) {
    setForm((prev) => (prev ? { ...prev, [key]: value } : prev))
    setPhase((p) => (p === 'saved' ? 'idle' : p))
  }

  async function handleSave() {
    if (!form || busy || hasErrors || !dirty) return
    setPhase('saving')
    setErrorCode(null)
    try {
      // 仅提交未被环境变量锁定的字段;锁定字段由后端忽略,这里也不发送,
      // 避免给用户「本地能覆盖环境变量」的错觉。
      const payload: AISettingsSaveRequest = {}
      const entries = Object.entries(form) as [keyof FormState, unknown][]
      for (const [key, value] of entries) {
        if (locked.has(key)) continue
        ;(payload as Record<string, unknown>)[key] = value
      }
      // 空字符串表示「保持不变」,后端不会据此删除 Key;仅在用户实际输入时提交。
      if (apiKeyInput) payload.api_key = apiKeyInput
      const saved = await updateAISettings(payload)
      if (!mounted.current) return
      setServer(saved)
      setForm(toFormState(saved))
      // 保存成功后立刻清空 Key 输入,避免密钥停留在 DOM/内存中。
      setApiKeyInput('')
      setShowKey(false)
      setPhase('saved')
      pushToast({ kind: 'success', message: 'AI 配置已保存到本机后端。', duration: 2500 })
    } catch (err) {
      if (!mounted.current) return
      const apiErr = err as ApiError
      setPhase('error')
      setLoadError(apiErr.message ?? '保存失败。')
      setErrorCode(apiErr.code ?? null)
      pushToast({ kind: 'error', message: apiErr.message ?? 'AI 配置保存失败。', duration: 3500 })
    }
  }

  async function handleTest() {
    if (!form || busy) return
    setPhase('testing')
    setTestResult(null)
    setErrorCode(null)
    try {
      const result = await testAISettings({
        provider: form.provider,
        base_url: form.base_url,
        model: form.model,
        timeout_seconds: form.timeout_seconds,
        // 临时 Key 仅本次请求使用,后端不保存、不缓存、不写日志。
        ...(apiKeyInput ? { api_key: apiKeyInput } : {}),
      })
      if (!mounted.current) return
      setTestResult(result)
      setPhase('idle')
    } catch (err) {
      if (!mounted.current) return
      const apiErr = err as ApiError
      setPhase('error')
      setLoadError(apiErr.message ?? '测试连接失败。')
      setErrorCode(apiErr.code ?? null)
    }
  }

  async function handleDeleteKey() {
    setConfirmDelete(false)
    if (busy) return
    setPhase('deleting_key')
    try {
      const result = await deleteLocalAIKey()
      if (!mounted.current) return
      setServer((prev) =>
        prev
          ? {
              ...prev,
              api_key_configured: result.api_key_configured,
              api_key_source: result.api_key_source,
            }
          : prev,
      )
      setApiKeyInput('')
      setPhase('idle')
      pushToast({ kind: 'success', message: '已删除本机保存的 API Key。', duration: 2500 })
    } catch (err) {
      if (!mounted.current) return
      const apiErr = err as ApiError
      setPhase('error')
      setLoadError(apiErr.message ?? '删除失败。')
      setErrorCode(apiErr.code ?? null)
    }
  }

  function handleReset() {
    if (!server) return
    setForm(toFormState(server))
    setApiKeyInput('')
    setShowKey(false)
    setTestResult(null)
    setPhase('idle')
  }

  if (phase === 'loading' || !form || !server) {
    return (
      <GlassCard padding="md" highlight>
        <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-1.5">
          <Bot size={15} /> AI 编排
        </h3>
        {phase === 'error' ? (
          <p className="text-xs text-[var(--danger)]" data-testid="ai-settings-load-error">
            {loadError ?? '读取 AI 配置失败。'}
          </p>
        ) : (
          <p className="text-xs text-[var(--text-tertiary)]" data-testid="ai-settings-loading">
            正在读取 AI 配置…
          </p>
        )}
      </GlassCard>
    )
  }

  return (
    <GlassCard padding="md" highlight>
      <h3 className="text-sm font-semibold text-[var(--text-primary)] mb-3 flex items-center gap-1.5">
        <Bot size={15} /> AI 编排
      </h3>

      {/* ---- 状态摘要 ---- */}
      <div className="flex flex-wrap items-center gap-2 mb-3" data-testid="ai-settings-summary">
        <StatusBadge
          tone={server.enabled ? 'success' : 'neutral'}
          label={server.enabled ? 'AI 已启用' : 'AI 未启用'}
        />
        <StatusBadge
          tone={server.api_key_configured ? 'success' : 'warning'}
          label={server.api_key_configured ? 'Key 已配置' : 'Key 未配置'}
        />
        <StatusBadge
          tone="info"
          label={`Key 来源:${
            server.api_key_source === 'environment'
              ? '环境变量'
              : server.api_key_source === 'local_store'
                ? '本机加密存储'
                : '未配置'
          }`}
        />
        {server.locked_fields.length > 0 && (
          <StatusBadge tone="accent" label={`环境变量锁定 ${server.locked_fields.length} 项`} />
        )}
      </div>

      {testResult && (
        <div className="mb-3" data-testid="ai-settings-test-result">
          <StatusBadge
            tone={TEST_TONES[testResult.status]}
            label={`${TEST_MESSAGES[testResult.status]}(${testResult.latency_ms} ms)`}
          />
          <details className="mt-1">
            <summary className="text-[11px] text-[var(--text-tertiary)] cursor-pointer">
              技术详情
            </summary>
            <p className="text-[11px] text-[var(--text-tertiary)] mt-1 break-all">
              status={testResult.status} · provider={testResult.provider} · model=
              {testResult.model || '—'} · models_endpoint_supported=
              {String(testResult.models_endpoint_supported)}
              {testResult.safe_message ? ` · ${testResult.safe_message}` : ''}
            </p>
          </details>
        </div>
      )}

      {phase === 'error' && loadError && (
        <div className="mb-3" data-testid="ai-settings-error">
          <p className="text-xs text-[var(--danger)]">{loadError}</p>
          {errorCode && (
            <details className="mt-1">
              <summary className="text-[11px] text-[var(--text-tertiary)] cursor-pointer">
                技术错误码
              </summary>
              <p className="text-[11px] text-[var(--text-tertiary)] mt-1 break-all">{errorCode}</p>
            </details>
          )}
        </div>
      )}

      {/* ---- 可编辑表单 ---- */}
      <div className="flex flex-col gap-3 min-w-0">
        <CheckboxField
          id="ai-enabled"
          label="启用 AI 编排"
          checked={form.enabled}
          locked={locked.has('enabled')}
          onChange={(v) => update('enabled', v)}
        />

        <TextField
          id="ai-provider"
          label="Provider"
          value={form.provider}
          locked={locked.has('provider')}
          onChange={(v) => update('provider', v)}
          hint="当前仅支持 openai_compatible"
        />

        <TextField
          id="ai-base-url"
          label="Base URL"
          value={form.base_url}
          locked={locked.has('base_url')}
          error={errors.base_url}
          placeholder="https://example.com/v1"
          onChange={(v) => update('base_url', v)}
        />

        <TextField
          id="ai-model"
          label="Model"
          value={form.model}
          locked={locked.has('model')}
          error={errors.model}
          onChange={(v) => update('model', v)}
        />

        {/* ---- API Key(只提交,不回读) ---- */}
        <div className="flex flex-col gap-1 min-w-0">
          <label htmlFor="ai-api-key" className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide">
            API Key
            {envKeyManaged && (
              <span className="ml-1 inline-flex items-center gap-0.5 text-[var(--accent-purple)] normal-case tracking-normal">
                <Lock size={10} /> 由环境变量管理
              </span>
            )}
          </label>
          <div className="flex items-center gap-2 min-w-0">
            <input
              id="ai-api-key"
              type={showKey ? 'text' : 'password'}
              value={apiKeyInput}
              disabled={envKeyManaged}
              autoComplete="off"
              spellCheck={false}
              onChange={(e) => setApiKeyInput(e.target.value)}
              placeholder={
                envKeyManaged
                  ? '由环境变量 AI_API_KEY 管理'
                  : server.api_key_configured
                    ? '已配置,留空表示保持不变'
                    : '请输入 API Key'
              }
              className={cn(
                'flex-1 min-w-0 px-2.5 py-1.5 rounded-[10px] text-sm bg-transparent border',
                'border-[var(--border-soft)] text-[var(--text-primary)]',
                envKeyManaged && 'opacity-50 cursor-not-allowed',
              )}
            />
            <button
              type="button"
              aria-label={showKey ? '隐藏输入' : '显示输入'}
              disabled={envKeyManaged}
              onClick={() => setShowKey((v) => !v)}
              className="shrink-0 p-1.5 rounded-[8px] border border-[var(--border-soft)] text-[var(--text-tertiary)] hover:text-[var(--text-primary)] disabled:opacity-40"
            >
              {showKey ? <EyeOff size={14} /> : <Eye size={14} />}
            </button>
          </div>
          <p className="text-[11px] text-[var(--text-tertiary)]">
            API Key 仅提交到本机后端,并使用 Windows 用户级加密保存。页面不会读取或显示已保存的完整密钥。
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 min-w-0">
          <NumberField
            id="ai-token-budget"
            label="默认 Token 预算"
            value={form.default_token_budget}
            locked={locked.has('default_token_budget')}
            error={errors.default_token_budget}
            onChange={(v) => update('default_token_budget', v)}
          />
          <NumberField
            id="ai-max-rounds"
            label="最大模型轮数"
            value={form.max_rounds}
            locked={locked.has('max_rounds')}
            error={errors.max_rounds}
            onChange={(v) => update('max_rounds', v)}
          />
          <NumberField
            id="ai-max-tool-calls"
            label="最大工具调用数"
            value={form.max_tool_calls}
            locked={locked.has('max_tool_calls')}
            error={errors.max_tool_calls}
            onChange={(v) => update('max_tool_calls', v)}
          />
          <NumberField
            id="ai-timeout"
            label="请求超时(秒)"
            value={form.timeout_seconds}
            locked={locked.has('timeout_seconds')}
            error={errors.timeout_seconds}
            onChange={(v) => update('timeout_seconds', v)}
          />
          <NumberField
            id="ai-max-input"
            label="最大输入 Token"
            value={form.max_input_tokens}
            locked={locked.has('max_input_tokens')}
            error={errors.max_input_tokens}
            onChange={(v) => update('max_input_tokens', v)}
          />
          <NumberField
            id="ai-max-output"
            label="最大输出 Token"
            value={form.max_output_tokens}
            locked={locked.has('max_output_tokens')}
            error={errors.max_output_tokens}
            onChange={(v) => update('max_output_tokens', v)}
          />
          <NumberField
            id="ai-cache-ttl"
            label="缓存 TTL(秒)"
            value={form.cache_ttl_seconds}
            locked={locked.has('cache_ttl_seconds')}
            error={errors.cache_ttl_seconds}
            onChange={(v) => update('cache_ttl_seconds', v)}
          />
          <SelectField
            id="ai-report-language"
            label="报告语言"
            value={form.report_language}
            locked={locked.has('report_language')}
            options={[
              { value: 'zh-CN', label: '简体中文 (zh-CN)' },
              { value: 'en-US', label: 'English (en-US)' },
            ]}
            onChange={(v) => update('report_language', v as 'zh-CN' | 'en-US')}
          />
        </div>

        <CheckboxField
          id="ai-cache-enabled"
          label="启用结果缓存"
          checked={form.cache_enabled}
          locked={locked.has('cache_enabled')}
          onChange={(v) => update('cache_enabled', v)}
        />
        <CheckboxField
          id="ai-allow-dynamic"
          label="允许动态工具(设备状态变更类)"
          checked={form.allow_dynamic_tools}
          locked={locked.has('allow_dynamic_tools')}
          onChange={(v) => update('allow_dynamic_tools', v)}
        />
      </div>

      {/* ---- 操作按钮 ---- */}
      <div className="flex flex-wrap items-center gap-2 mt-4">
        <button
          type="button"
          onClick={handleTest}
          disabled={busy}
          data-testid="ai-settings-test"
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm border border-[var(--border-soft)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {phase === 'testing' ? <Loader2 size={14} className="animate-spin" /> : <Plug size={14} />}
          测试连接
        </button>
        <button
          type="button"
          onClick={handleSave}
          disabled={busy || hasErrors || !dirty}
          data-testid="ai-settings-save"
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm border border-[var(--border-active)] text-[var(--text-primary)] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {phase === 'saving' ? <Loader2 size={14} className="animate-spin" /> : <Save size={14} />}
          保存配置
        </button>
        <button
          type="button"
          onClick={handleReset}
          disabled={busy || !dirty}
          data-testid="ai-settings-reset"
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm border border-[var(--border-soft)] text-[var(--text-secondary)] hover:text-[var(--text-primary)] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          <RotateCcw size={14} /> 重置未保存修改
        </button>
        <button
          type="button"
          onClick={() => setConfirmDelete(true)}
          disabled={busy || envKeyManaged || !server.api_key_configured}
          data-testid="ai-settings-delete-key"
          className="inline-flex items-center gap-1.5 px-3.5 py-1.5 rounded-[10px] text-sm border border-[var(--border-soft)] text-[var(--danger)] hover:bg-[rgba(255,107,138,0.08)] disabled:opacity-50 disabled:cursor-not-allowed"
        >
          {phase === 'deleting_key' ? (
            <Loader2 size={14} className="animate-spin" />
          ) : (
            <Trash2 size={14} />
          )}
          删除已保存 API Key
        </button>
        {phase === 'saved' && (
          <span className="text-[11px] text-[var(--success)]" data-testid="ai-settings-saved">
            已保存
          </span>
        )}
      </div>

      <p className="text-[11px] text-[var(--text-tertiary)] mt-2">
        配置优先级:环境变量 &gt; 本机保存 &gt; 代码默认值。被环境变量管理的字段在此页面只读。
        AI 不可用时,确定性分析与报告仍照常生成。
      </p>

      <ConfirmDialog
        open={confirmDelete}
        title="删除已保存的 API Key?"
        description="此操作会删除本机加密保存的 API Key,无法恢复。环境变量配置的 Key 不受影响。"
        confirmLabel="删除"
        tone="danger"
        onConfirm={handleDeleteKey}
        onCancel={() => setConfirmDelete(false)}
      />
    </GlassCard>
  )
}

/* -------------------------------------------------------------------------
 * 受控字段(锁定字段统一禁用 + 提示,保证「不得让本地保存覆盖环境变量」)
 * ------------------------------------------------------------------------- */
function LockHint() {
  return (
    <span className="ml-1 inline-flex items-center gap-0.5 text-[var(--accent-purple)] normal-case tracking-normal">
      <Lock size={10} /> 该字段由环境变量管理
    </span>
  )
}

function TextField({
  id,
  label,
  value,
  locked,
  error,
  hint,
  placeholder,
  onChange,
}: {
  id: string
  label: string
  value: string
  locked?: boolean
  error?: string
  hint?: string
  placeholder?: string
  onChange: (v: string) => void
}) {
  return (
    <div className="flex flex-col gap-1 min-w-0">
      <label htmlFor={id} className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide">
        {label}
        {locked && <LockHint />}
      </label>
      <input
        id={id}
        type="text"
        value={value}
        disabled={locked}
        placeholder={placeholder}
        spellCheck={false}
        onChange={(e) => onChange(e.target.value)}
        className={cn(
          'w-full min-w-0 px-2.5 py-1.5 rounded-[10px] text-sm bg-transparent border text-[var(--text-primary)]',
          error ? 'border-[var(--danger)]' : 'border-[var(--border-soft)]',
          locked && 'opacity-50 cursor-not-allowed',
        )}
      />
      {error && <span className="text-[11px] text-[var(--danger)]">{error}</span>}
      {hint && !error && <span className="text-[11px] text-[var(--text-tertiary)]">{hint}</span>}
    </div>
  )
}

function NumberField({
  id,
  label,
  value,
  locked,
  error,
  onChange,
}: {
  id: string
  label: string
  value: number
  locked?: boolean
  error?: string
  onChange: (v: number) => void
}) {
  return (
    <div className="flex flex-col gap-1 min-w-0">
      <label htmlFor={id} className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide">
        {label}
        {locked && <LockHint />}
      </label>
      <input
        id={id}
        type="number"
        value={Number.isFinite(value) ? value : ''}
        disabled={locked}
        onChange={(e) => onChange(Number(e.target.value))}
        className={cn(
          'w-full min-w-0 px-2.5 py-1.5 rounded-[10px] text-sm bg-transparent border text-[var(--text-primary)]',
          error ? 'border-[var(--danger)]' : 'border-[var(--border-soft)]',
          locked && 'opacity-50 cursor-not-allowed',
        )}
      />
      {error && <span className="text-[11px] text-[var(--danger)]">{error}</span>}
    </div>
  )
}

function SelectField({
  id,
  label,
  value,
  locked,
  options,
  onChange,
}: {
  id: string
  label: string
  value: string
  locked?: boolean
  options: { value: string; label: string }[]
  onChange: (v: string) => void
}) {
  return (
    <div className="flex flex-col gap-1 min-w-0">
      <label htmlFor={id} className="text-[11px] text-[var(--text-tertiary)] uppercase tracking-wide">
        {label}
        {locked && <LockHint />}
      </label>
      <select
        id={id}
        value={value}
        disabled={locked}
        onChange={(e) => onChange(e.target.value)}
        className={cn(
          'w-full min-w-0 px-2.5 py-1.5 rounded-[10px] text-sm bg-transparent border border-[var(--border-soft)] text-[var(--text-primary)]',
          locked && 'opacity-50 cursor-not-allowed',
        )}
      >
        {options.map((opt) => (
          <option key={opt.value} value={opt.value} className="bg-[var(--bg-elevated)]">
            {opt.label}
          </option>
        ))}
      </select>
    </div>
  )
}

function CheckboxField({
  id,
  label,
  checked,
  locked,
  onChange,
}: {
  id: string
  label: string
  checked: boolean
  locked?: boolean
  onChange: (v: boolean) => void
}) {
  return (
    <div className="flex items-center gap-2 min-w-0">
      <input
        id={id}
        type="checkbox"
        checked={checked}
        disabled={locked}
        onChange={(e) => onChange(e.target.checked)}
        className={cn('shrink-0', locked && 'opacity-50 cursor-not-allowed')}
      />
      <label htmlFor={id} className="text-sm text-[var(--text-secondary)] min-w-0">
        {label}
        {locked && <LockHint />}
      </label>
    </div>
  )
}
