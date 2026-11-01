import { useState, useId } from 'react'
import {
  ShieldCheck,
  Clock,
  EyeOff,
  CheckCircle2,
  Terminal,
  FileCode2,
  Radio,
  Lock,
} from 'lucide-react'

export type ConsoleTab = 'static' | 'dynamic' | 'traffic'

export function HeroConsole() {
  const [tab, setTab] = useState<ConsoleTab>('static')
  const tabListId = useId()

  return (
    <div className="hero-console" role="region" aria-label="本地审计引擎交互演示">
      {/* 顶部控制台标题栏（Apple 风格） */}
      <div className="hero-console-bar">
        <div className="hero-console-dots" aria-hidden>
          <span className="dot dot-red" />
          <span className="dot dot-yellow" />
          <span className="dot dot-green" />
        </div>
        <div className="hero-console-target">
          <Terminal size={12} className="text-[var(--text-tertiary)]" />
          <span className="font-mono text-xs">com.example.reader_v8.apk</span>
          <span className="badge-mono">SHA-256 校验完毕</span>
        </div>
        <div className="hero-console-status">
          <span className="status-dot-live" aria-hidden />
          <span className="text-[11px] text-[var(--success)] font-medium">本机隔离环境</span>
        </div>
      </div>

      {/* Apple 风格分段选择器 (Segmented Control) */}
      <div className="hero-console-tabs" role="tablist" id={tabListId}>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'static'}
          aria-controls={`${tabListId}-panel-static`}
          className="console-tab-btn"
          data-active={tab === 'static' ? 'true' : 'false'}
          onClick={() => setTab('static')}
        >
          <FileCode2 size={14} />
          <span>静态清单 (Static)</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'dynamic'}
          aria-controls={`${tabListId}-panel-dynamic`}
          className="console-tab-btn"
          data-active={tab === 'dynamic' ? 'true' : 'false'}
          onClick={() => setTab('dynamic')}
        >
          <Clock size={14} />
          <span>单调时钟 (Timeline)</span>
        </button>
        <button
          type="button"
          role="tab"
          aria-selected={tab === 'traffic'}
          aria-controls={`${tabListId}-panel-traffic`}
          className="console-tab-btn"
          data-active={tab === 'traffic' ? 'true' : 'false'}
          onClick={() => setTab('traffic')}
        >
          <EyeOff size={14} />
          <span>流量脱敏 (Zero-Leak)</span>
        </button>
      </div>

      {/* 选项卡内容区 */}
      <div className="hero-console-body">
        {tab === 'static' && (
          <div
            id={`${tabListId}-panel-static`}
            role="tabpanel"
            className="console-panel"
            aria-label="静态清单分析演示"
          >
            <div className="console-grid">
              <div className="console-item">
                <div className="console-item-header">
                  <span className="label">权限声明与组件</span>
                  <span className="tag-ok">18 项已声明</span>
                </div>
                <p className="desc">
                  Manifest 解析与导出组件审计。检测到 4 项高危权限声明，导出组件均附带签名权限保护。
                </p>
                <div className="code-pill font-mono">
                  READ_PHONE_STATE · ACCESS_FINE_LOCATION · CAMERA
                </div>
              </div>

              <div className="console-item">
                <div className="console-item-header">
                  <span className="label">第三方 SDK 指纹识别</span>
                  <span className="tag-info">3 个商业 SDK</span>
                </div>
                <p className="desc">
                  基于确定性特征库匹配广告与统计 SDK。指纹直接对应代码包名与 DEX 类结构。
                </p>
                <div className="code-pill font-mono">
                  Pangle SDK v5.9 · Tencent Bugly v4.1 · Umeng Analytics
                </div>
              </div>
            </div>

            <div className="console-footer-note">
              <ShieldCheck size={14} className="text-[var(--text-secondary)] shrink-0" />
              <span>解包结果完全存入本地临时沙箱，按 SHA-256 内容寻址缓存，不产生任何远程上传。</span>
            </div>
          </div>
        )}

        {tab === 'dynamic' && (
          <div
            id={`${tabListId}-panel-dynamic`}
            role="tabpanel"
            className="console-panel"
            aria-label="单调时钟分析演示"
          >
            <div className="timeline-visual">
              <div className="timeline-step">
                <div className="timeline-node" data-state="ok">T₀</div>
                <div className="timeline-info">
                  <strong className="time font-mono">0.00s 进程启动</strong>
                  <span className="detail">未同意隐私政策前。Frida 探针监控敏感 API 访问。</span>
                  <span className="badge-subtle text-[var(--success)]">无越界调用拦截</span>
                </div>
              </div>

              <div className="timeline-connector" aria-hidden />

              <div className="timeline-step">
                <div className="timeline-node node-checkpoint" data-state="checkpoint">T_c</div>
                <div className="timeline-info">
                  <strong className="time font-mono">3.42s 人工确认点</strong>
                  <span className="detail">用户在设备屏幕真实点击「同意并继续」，单调时钟锁定。</span>
                  <span className="badge-subtle text-[var(--warning)]">记录可信时间戳</span>
                </div>
              </div>

              <div className="timeline-connector" aria-hidden />

              <div className="timeline-step">
                <div className="timeline-node" data-state="ok">T₁</div>
                <div className="timeline-info">
                  <strong className="time font-mono">3.48s 首次合法调用</strong>
                  <span className="detail">广告 SDK 初始化并发起首次广播，时序严格位于同意点之后。</span>
                  <span className="badge-subtle text-[var(--success)]">符合合规要求</span>
                </div>
              </div>
            </div>

            <div className="console-footer-note">
              <CheckCircle2 size={14} className="text-[var(--success)] shrink-0" />
              <span>不靠文案顺序猜测用户是否已经同意。只依据单调时钟与人工检查点划分时序。</span>
            </div>
          </div>
        )}

        {tab === 'traffic' && (
          <div
            id={`${tabListId}-panel-traffic`}
            role="tabpanel"
            className="console-panel"
            aria-label="流量脱敏分析演示"
          >
            <div className="traffic-mock-table">
              <div className="traffic-row">
                <span className="traffic-method">POST</span>
                <span className="traffic-url font-mono">https://ad-network.example.com/api/v2/track</span>
                <span className="traffic-status">200 OK</span>
              </div>
              <div className="traffic-redacted-box">
                <div className="redacted-line">
                  <Lock size={12} className="text-[var(--text-tertiary)]" />
                  <span className="font-mono text-xs">Authorization: [REDACTED · 内存脱敏，绝不落盘]</span>
                </div>
                <div className="redacted-line">
                  <EyeOff size={12} className="text-[var(--text-tertiary)]" />
                  <span className="font-mono text-xs">Cookie: [STRIPPED · 套接字边界直接剔除]</span>
                </div>
                <div className="redacted-line">
                  <Radio size={12} className="text-[var(--text-tertiary)]" />
                  <span className="font-mono text-xs">Body: [DISCARDED · 不保存请求与响应正文]</span>
                </div>
              </div>
            </div>

            <div className="console-footer-note">
              <Lock size={14} className="text-[var(--text-secondary)] shrink-0" />
              <span>网络流量只留存域名、路径拓扑与时间窗口。零请求也是确凿证据，杜绝凭据泄露。</span>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

export default HeroConsole
