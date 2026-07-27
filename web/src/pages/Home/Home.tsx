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
} from 'lucide-react'
import { GlassCard } from '@/components/common/GlassCard'
import { useServiceHealth } from '@/hooks/useApi'
import { listLocalTasks } from '@/api/tasks'
import { formatDateTime } from '@/utils'

const FEATURES = [
  { icon: Cpu, title: '静态分析', desc: '解包识别 AndroidManifest 与广告 SDK 指纹', to: '/static' },
  { icon: Activity, title: '动态分析', desc: '同意前/同意后敏感 API 行为取证与红脱敏', to: '/dynamic' },
  { icon: Network, title: '流量观测', desc: '记录网络外发请求样本,键值脱敏不留痕', to: '/traffic' },
]

export default function Home() {
  const navigate = useNavigate()
  const health = useServiceHealth()
  const recent = listLocalTasks().slice(0, 3)
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
          </div>
        </motion.div>
      </GlassCard>

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
        {recent.length === 0 ? (
          <p className="text-sm text-[var(--text-tertiary)] py-6 text-center">尚无分析记录。点击「新建分析」开始。</p>
        ) : (
          <ul className="flex flex-col gap-2">
            {recent.map((t) => (
              <li key={t.local_id}>
                <button
                  type="button"
                  onClick={() => navigate(`/tasks/${t.local_id}`)}
                  className="w-full text-left flex items-center gap-3 rounded-[10px] px-3 py-2 hover:bg-[rgba(157,192,255,0.08)] transition-colors"
                >
                  <span className="text-xs px-2 py-0.5 rounded-md border border-[var(--border-soft)] text-[var(--text-tertiary)]">
                    {t.kind === 'dynamic' ? '动态' : '静态'}
                  </span>
                  <span className="text-sm text-[var(--text-primary)] truncate flex-1">{t.apk_path}</span>
                  <span className="text-[11px] text-[var(--text-tertiary)] shrink-0">{formatDateTime(t.created_at)}</span>
                </button>
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
