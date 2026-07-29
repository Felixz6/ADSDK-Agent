import { useNavigate } from 'react-router-dom'
import { motion } from 'framer-motion'
import {
  ShieldCheck,
  PlusCircle,
  Cpu,
  Activity,
  Network,
  ArrowRight,
  Sparkles,
  ListChecks,
  GitCompareArrows,
  FileText,
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { useServiceHealth } from '@/hooks/useApi'
import { useTasks } from '@/hooks/useTasks'
import { listLocalTasks } from '@/api/tasks'
import { StatCard } from '@/components/common/StatCard'
import { StatusBadge } from '@/components/common/StatusBadge'
import { RiskBadge } from '@/components/common/RiskBadge'
import { formatDateTime } from '@/utils'
import {
  riskBadgeLevel,
  riskLevelLabel,
  taskSubtitle,
  taskTitle,
  taskTypeLongLabel,
} from '@/utils/taskPresentation'

const FEATURES = [
  { icon: Cpu, title: '静态分析', desc: '解包识别 AndroidManifest 与广告 SDK 指纹', to: '/static' },
  { icon: Activity, title: '动态分析', desc: '同意前/同意后敏感 API 行为取证与红脱敏', to: '/dynamic' },
  { icon: Network, title: '流量观测', desc: '记录网络外发请求样本,键值脱敏不留痕', to: '/traffic' },
]

export default function Home() {
  const navigate = useNavigate()
  const health = useServiceHealth()
  const taskQuery = useTasks({ page: 1, page_size: 5 })
  const runningQuery = useTasks({ status: 'running', page: 1, page_size: 1 })
  const staticQuery = useTasks({ task_type: 'static', page: 1, page_size: 1 })
  const dynamicQuery = useTasks({ task_type: 'dynamic', page: 1, page_size: 1 })
  const comparisonQuery = useTasks({ task_type: 'comparison', page: 1, page_size: 1 })
  const recent = taskQuery.data?.items ?? []
  const legacyRecent = listLocalTasks().slice(0, 3)
  const reachable = Boolean(health.data?.ok)

  return (
    <div className="flex flex-col gap-6">
      {/* Hero */}
      <GlassCard strong highlight padding="lg" className="flex flex-col gap-4 min-h-[340px] justify-center">
        <motion.div
          initial={{ opacity: 0, y: 12 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.4 }}
          className="flex flex-col gap-3 max-w-2xl"
        >
          <span className="inline-flex items-center gap-1.5 text-xs text-[var(--accent-blue)] tracking-wider">
            <Sparkles size={14} /> AdSDK Agent · 隐私合规取证控制台
          </span>
          <h1 className="text-3xl sm:text-4xl font-semibold text-[var(--text-primary)] tracking-tight leading-tight">
            星穹之下的守望
            <br className="hidden sm:block" />
            <span className="text-[var(--accent-blue)]"> 安全分析控制台</span>
          </h1>
          <p className="text-sm sm:text-base text-[var(--text-secondary)] leading-relaxed">
            面向安卓广告 SDK 的隐私合规取证工具。对 APK 进行静态清单与 SDK 识别、动态同意前后行为采集、
            网络外发观测与严格规则判定。所有原始敏感标识一律 HMAC 脱敏,可在本地合规留存证据。
          </p>
          <div className="flex items-center gap-3 flex-wrap mt-1">
            <button
              type="button"
              onClick={() => navigate('/analysis/new')}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-[12px] font-medium text-[var(--text-on-accent)] bg-[var(--accent-blue)] hover:brightness-110 transition-all shadow-[var(--shadow-glow)]"
            >
              <PlusCircle size={18} /> 新建分析
            </button>
            <button
              type="button"
              onClick={() => navigate('/dashboard')}
              className="inline-flex items-center gap-2 px-4 py-2.5 rounded-[12px] font-medium text-[var(--text-primary)] glass border-[var(--border-soft)] hover:border-[var(--border-active)] transition-colors"
            >
              查看仪表盘 <ArrowRight size={16} />
            </button>
            <button type="button" onClick={() => navigate('/tasks')} className="control-button">
              <ListChecks size={16} /> 任务中心
            </button>
            <button type="button" onClick={() => navigate('/comparisons')} className="control-button">
              <GitCompareArrows size={16} /> 版本对比
            </button>
          </div>
        </motion.div>
      </GlassCard>

      <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
        <StatCard label="静态分析" value={staticQuery.data?.total ?? '—'} tone="success" icon={<Cpu size={18} />} />
        <StatCard label="动态分析" value={dynamicQuery.data?.total ?? '—'} tone="warning" icon={<Network size={18} />} />
        <StatCard label="版本对比" value={comparisonQuery.data?.total ?? '—'} tone="default" icon={<GitCompareArrows size={18} />} />
        <StatCard label="运行中任务" value={runningQuery.data?.total ?? '—'} tone="accent" icon={<Activity size={18} />} />
      </div>

      {/* Backend status banner */}
      <GlassCard padding="md" className="flex items-center gap-3">
        <ShieldCheck
          size={20}
          className={reachable ? 'text-[var(--success)]' : 'text-[var(--danger)]'}
        />
        <div className="flex-1 min-w-0">
          <p className="text-sm text-[var(--text-primary)] font-medium">
            {reachable ? '已连接 AdSDK Agent 后端' : '后端未连接 · 部分功能不可用'}
          </p>
          <p className="text-xs text-[var(--text-tertiary)] truncate">
            {reachable
              ? `服务运行中 · 健康检查于 ${fmtMs(health.dataUpdatedAt)}`
              : '请启动本地 FastAPI(127.0.0.1:8000)后再提交分析任务。'}
          </p>
        </div>
        <button
          type="button"
          onClick={() => navigate('/environment')}
          className="text-xs px-3 py-1.5 rounded-[10px] border border-[var(--border-soft)] text-[var(--text-secondary)] hover:bg-[rgba(157,192,255,0.08)]"
        >
          环境检测
        </button>
      </GlassCard>

      {/* Feature cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
        {FEATURES.map((f, i) => {
          const Icon = f.icon
          return (
            <motion.button
              key={f.to}
              type="button"
              onClick={() => navigate(f.to)}
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ delay: 0.1 + i * 0.08, duration: 0.3 }}
              className="text-left focus:outline-none"
            >
              <GlassCard padding="md" highlight className="h-full hover:border-[var(--border-active)] transition-colors">
                <div className="flex items-center gap-2.5 mb-2">
                  <span className="flex items-center justify-center w-10 h-10 rounded-[10px] bg-[rgba(120,216,255,0.10)] text-[var(--accent-blue)] border border-[var(--border-soft)]">
                    <Icon size={20} />
                  </span>
                  <span className="text-sm font-semibold text-[var(--text-primary)]">{f.title}</span>
                </div>
                <p className="text-xs text-[var(--text-secondary)] leading-relaxed">{f.desc}</p>
                <span className="inline-flex items-center gap-1 text-xs text-[var(--accent-blue)] mt-3">
                  进入 <ArrowRight size={13} />
                </span>
              </GlassCard>
            </motion.button>
          )
        })}
      </div>

      {/* Recent tasks */}
      <GlassCard padding="md">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-sm font-semibold text-[var(--text-primary)]">最近提交</h2>
          <button
            type="button"
            onClick={() => navigate('/tasks')}
            className="text-xs text-[var(--text-secondary)] hover:text-[var(--accent-blue)]"
          >
            查看全部
          </button>
        </div>
        {recent.length === 0 && legacyRecent.length === 0 ? (
          <p className="text-sm text-[var(--text-tertiary)] py-6 text-center">尚无持久化任务。点击「新建分析」开始。</p>
        ) : (
          <ul className="flex flex-col divide-y divide-[rgba(157,192,255,0.07)]">
            {recent.map((t) => (
              <li key={t.id} className="flex min-w-0 items-center gap-2 rounded-[10px] px-2 py-3 transition-colors hover:bg-[rgba(157,192,255,0.045)]">
                <button
                  type="button"
                  onClick={() => navigate(`/tasks/${t.id}`)}
                  className="flex min-w-0 flex-1 items-center gap-3 text-left"
                  title={`任务 ID：${t.id}`}
                >
                  <StatusBadge
                    className="hidden min-w-[68px] justify-center sm:inline-flex"
                    tone={t.status === 'completed' ? 'success' : t.status === 'failed' ? 'danger' : t.status === 'running' ? 'info' : t.status === 'cancelled' ? 'neutral' : 'warning'}
                    label={t.status === 'completed' ? '已完成' : t.status === 'failed' ? '失败' : t.status === 'running' ? '分析中' : t.status === 'cancelled' ? '已取消' : '排队中'}
                  />
                  <span className="min-w-0 flex-1">
                    <span className="block truncate text-sm font-medium text-[var(--text-primary)]">{taskTitle(t)}</span>
                    <span className="mt-1 block truncate text-[11px] text-[var(--text-tertiary)]">{taskSubtitle(t)}</span>
                  </span>
                </button>
                <div className="hidden shrink-0 items-center gap-2 md:flex">
                  <StatusBadge tone="info" label={taskTypeLongLabel(t.task_type)} dot={false} />
                  <RiskBadge level={riskBadgeLevel(t.risk_level)} label={riskLevelLabel(t.risk_level)} />
                </div>
                <div className="hidden shrink-0 text-right text-[11px] text-[var(--text-tertiary)] lg:block">
                  <p>{t.completed_at ? '完成于' : '提交于'}</p>
                  <p className="mt-0.5">{formatDateTime(t.completed_at || t.created_at)}</p>
                </div>
                {t.report_json_path && (
                  <button
                    type="button"
                    aria-label="查看报告"
                    title="查看报告"
                    onClick={() => navigate(`/reports?task_id=${t.id}`)}
                    className="control-icon shrink-0"
                  >
                    <FileText size={14} />
                  </button>
                )}
              </li>
            ))}
            {recent.length === 0 && legacyRecent.map((t) => (
              <li key={t.local_id} className="rounded-[10px] px-3 py-2 border border-[var(--border-soft)]">
                <p className="text-sm text-[var(--text-primary)] truncate">{t.apk_path}</p>
                <p className="text-[11px] text-[var(--text-tertiary)]">浏览器旧记录 · {formatDateTime(t.created_at)}</p>
              </li>
            ))}
          </ul>
        )}
      </GlassCard>
    </div>
  )
}

/** 毫秒时间戳 -> "2026-07-25 16:30:09" 本地时间,dataUpdatedAt 为数字 */
function fmtMs(ms: number | undefined): string {
  if (!ms || Number.isNaN(ms)) return '—'
  const d = new Date(ms)
  if (Number.isNaN(d.getTime())) return '—'
  const p = (n: number) => String(n).padStart(2, '0')
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
}
