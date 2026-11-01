import { useNavigate } from 'react-router-dom'
import { useServiceHealth } from '@/hooks/useApi'
import { useTasks } from '@/hooks/useTasks'
import { listLocalTasks } from '@/api/tasks'
import { StatusBadge } from '@/components/common/StatusBadge'
import { RiskBadge } from '@/components/common/RiskBadge'
import { HeroConsole } from '@/components/home/HeroConsole'
import { formatDateTime } from '@/utils'
import {
  riskBadgeLevel,
  riskLevelLabel,
  taskSubtitle,
  taskTitle,
  taskTypeLongLabel,
} from '@/utils/taskPresentation'

const STAGES = [
  { n: '01', title: '环境检查', body: '确认 ADB、Frida、mitmproxy 与输出目录是否就绪。', to: '/environment', go: '环境' },
  { n: '02', title: '静态分析', body: '校验 APK、解析 Manifest 与权限，识别 SDK 指纹。', to: '/static', go: '静态' },
  { n: '03', title: '动态分析', body: '用单调时钟划分同意前、同意后与时间不明。', to: '/dynamic', go: '动态' },
  { n: '04', title: '网络流量', body: '记录请求元数据。不保存认证头、Cookie 与正文。', to: '/traffic', go: '流量' },
  { n: '05', title: '报告', body: '规则给出观察、疑似与证据缺口。AI 只整理叙述。', to: '/reports', go: '报告' },
]

const SPECS = [
  ['包名与版本', '应用信息、versionName 与 versionCode'],
  ['权限与组件', 'Manifest 中声明的权限、活动与服务'],
  ['SDK 指纹', '广告、统计、推送、归因、定位与社交'],
  ['完整性', '路径校验、ZIP 与 SHA-256 快照'],
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
    <>
      <section className="hero">
        <div className="hero-copy">
          <p className="kicker">AdSDK Agent</p>
          <h1 className="display">
            隐私审计，
            <br />
            留在本机。
          </h1>
          <p className="lede">
            面向已授权的 Android APK。静态清单、动态行为、网络流量与证据关联都在这台电脑上完成。事实由确定性工具产生。
          </p>
          <div className="hero-actions">
            <button type="button" className="pill pill-lg" onClick={() => navigate('/analysis/new')}>
              新建分析
            </button>
            <button type="button" className="pill-quiet pill-lg" onClick={() => navigate('/tasks')}>
              查看任务
            </button>
          </div>
        </div>
        <HeroConsole />
      </section>

      <section className="chapter chapter-ink" aria-labelledby="pipeline-title">
        <div className="chapter-inner">
          <h2 id="pipeline-title">证据先于叙述。</h2>
          <p className="lede">一次任务按固定顺序取证。模型不能改写其中的计数、风险或证据。</p>
          <ol className="stage-list">
            {STAGES.map((stage) => (
              <li key={stage.n}>
                <a href={stage.to} onClick={(event) => { event.preventDefault(); navigate(stage.to) }}>
                  <span className="num">{stage.n}</span>
                  <span>
                    <strong>{stage.title}</strong>
                    <span className="stage-body">{stage.body}</span>
                  </span>
                  <span className="go">{stage.go}</span>
                </a>
              </li>
            ))}
          </ol>
        </div>
      </section>

      <section className="chapter" aria-labelledby="static-title">
        <div className="chapter-inner split">
          <div>
            <h2 id="static-title">先读清单。</h2>
            <p>
              在设备被改动之前，先确认包里有什么。解包按 SHA-256 缓存。某一维证据失败时，其余部分仍然保留。
            </p>
            <div className="hero-actions">
              <button type="button" className="pill" onClick={() => navigate('/static')}>
                静态分析
              </button>
            </div>
          </div>
          <dl className="spec">
            {SPECS.map(([term, detail]) => (
              <div key={term}>
                <dt>{term}</dt>
                <dd>{detail}</dd>
              </div>
            ))}
          </dl>
        </div>
      </section>

      <section className="chapter chapter-soft" aria-labelledby="consent-title">
        <div className="chapter-inner">
          <h2 id="consent-title">同意，用时间划分。</h2>
          <p className="prose">不靠文案顺序猜测用户是否已经同意。只比较事件与人工检查点的单调时钟。</p>
          <div className="trio">
            <article>
              <h3>同意前</h3>
              <p>事件早于确认点。</p>
            </article>
            <article>
              <h3>同意后</h3>
              <p>事件不早于确认点。</p>
            </article>
            <article>
              <h3>时间不明</h3>
              <p>缺少可信时间。相关规则记为未评估。</p>
            </article>
          </div>
          <div className="hero-actions">
            <button type="button" className="pill" onClick={() => navigate('/dynamic')}>
              动态分析
            </button>
          </div>
        </div>
      </section>

      <section className="chapter" aria-labelledby="traffic-title">
        <div className="chapter-inner">
          <h2 id="traffic-title">看见请求，不留下秘密。</h2>
          <div className="pair">
            <div>
              <h3>会留下</h3>
              <ul>
                <li>主机与路径形态</li>
                <li>时间与观察窗口</li>
                <li>零请求也是一种结果</li>
              </ul>
            </div>
            <div>
              <h3>不会留下</h3>
              <ul>
                <li>认证头与 Cookie</li>
                <li>请求和响应正文</li>
                <li>完整的 query 值</li>
              </ul>
            </div>
          </div>
          <div className="hero-actions">
            <button type="button" className="pill" onClick={() => navigate('/traffic')}>
              流量观测
            </button>
          </div>
        </div>
      </section>

      <section className="chapter chapter-ink" aria-labelledby="limit-title">
        <div className="chapter-inner">
          <h2 id="limit-title" className="quote-block">未观察到，不是安全。</h2>
          <p className="quote-follow">时间接近，不是因果。</p>
          <div className="hero-actions">
            <button type="button" className="pill" onClick={() => navigate('/reports')}>
              打开报告
            </button>
          </div>
        </div>
      </section>

      <section className="chapter chapter-soft" aria-labelledby="recent-title">
        <div className="chapter-inner">
          <div className="workbench-head">
            <h2 id="recent-title">最近提交</h2>
            <button type="button" className="pill-quiet" onClick={() => navigate('/dashboard')}>
              查看仪表盘
            </button>
          </div>
          <div className="status-row">
            <p className="status-line" role="status">
              {reachable ? '已连接 AdSDK Agent 后端' : '后端未连接 · 部分功能不可用'}
              {reachable
                ? ` · 健康检查于 ${fmtMs(health.dataUpdatedAt)}`
                : '。请启动本地 FastAPI(127.0.0.1:8000)后再提交分析任务。'}
            </p>
            <button type="button" className="pill-quiet" onClick={() => navigate('/environment')}>
              环境检测
            </button>
          </div>
          <dl className="stats">
            <div>
              <dt>静态分析</dt>
              <dd className={staticQuery.data ? undefined : 'stat-empty'}>{staticQuery.data?.total ?? '—'}</dd>
            </div>
            <div>
              <dt>动态分析</dt>
              <dd className={dynamicQuery.data ? undefined : 'stat-empty'}>{dynamicQuery.data?.total ?? '—'}</dd>
            </div>
            <div>
              <dt>版本对比</dt>
              <dd className={comparisonQuery.data ? undefined : 'stat-empty'}>{comparisonQuery.data?.total ?? '—'}</dd>
            </div>
            <div>
              <dt>运行中任务</dt>
              <dd className={runningQuery.data ? undefined : 'stat-empty'}>{runningQuery.data?.total ?? '—'}</dd>
            </div>
          </dl>
          {recent.length === 0 && legacyRecent.length === 0 ? (
            <p className="prose">尚无持久化任务。点击「新建分析」开始。</p>
          ) : (
            <ul className="recent">
              {recent.map((task) => (
                <li key={task.id}>
                  <button type="button" className="linkish" onClick={() => navigate(`/tasks/${task.id}`)} title={`任务 ID：${task.id}`}>
                    <StatusBadge
                      className="hidden min-w-[68px] justify-center sm:inline-flex"
                      tone={task.status === 'completed' ? 'success' : task.status === 'failed' ? 'danger' : task.status === 'running' ? 'info' : task.status === 'cancelled' ? 'neutral' : 'warning'}
                      label={task.status === 'completed' ? '已完成' : task.status === 'failed' ? '失败' : task.status === 'running' ? '分析中' : task.status === 'cancelled' ? '已取消' : '排队中'}
                    />
                    <span className="min-w-0">
                      <span className="title">{taskTitle(task)}</span>
                      <span className="meta">{taskSubtitle(task)}</span>
                    </span>
                  </button>
                  <span className="meta when">{taskTypeLongLabel(task.task_type)}</span>
                  <RiskBadge level={riskBadgeLevel(task.risk_level)} label={riskLevelLabel(task.risk_level)} />
                  <span className="meta when">
                    <span>{task.completed_at ? '完成于' : '提交于'}</span>
                    <span>{formatDateTime(task.completed_at || task.created_at)}</span>
                  </span>
                  {task.report_json_path && (
                    <button
                      type="button"
                      aria-label="查看报告"
                      title="查看报告"
                      className="control-icon"
                      onClick={() => navigate(`/reports?task_id=${task.id}`)}
                    >
                      <span aria-hidden>→</span>
                    </button>
                  )}
                </li>
              ))}
              {recent.length === 0 && legacyRecent.map((task) => (
                <li key={task.local_id}>
                  <span className="min-w-0">
                    <span className="title">{task.apk_path}</span>
                    <span className="meta">浏览器旧记录 · {formatDateTime(task.created_at)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </section>
    </>
  )
}

function fmtMs(ms: number | undefined): string {
  if (!ms || Number.isNaN(ms)) return '—'
  const date = new Date(ms)
  if (Number.isNaN(date.getTime())) return '—'
  const pad = (value: number) => String(value).padStart(2, '0')
  return `${date.getFullYear()}-${pad(date.getMonth() + 1)}-${pad(date.getDate())} ${pad(date.getHours())}:${pad(date.getMinutes())}:${pad(date.getSeconds())}`
}
